from __future__ import annotations

import os
import socket
import subprocess
import tempfile
from collections.abc import Mapping, Sequence
from pathlib import Path

import pytest

from localize.guardian.deadline import PollDeadline, PollDeadlineExceeded
from localize.guardian.models import SigningFormat
from localize.guardian.signing import SSHSigningMaterial
from localize.guardian.workspace import (
    CommitResult,
    ExactRevision,
    GuardianWorkspace,
    HistoricalRevision,
    HistoricalWorkspace,
    PreventionPublicationResult,
    PublicationResult,
    WorkspaceError,
    materialize_exact_checkout,
    materialize_historical_checkout,
)


def _git(repo: Path, *args: str, check: bool = True) -> str:
    completed = subprocess.run(
        ["git", "-C", str(repo), *args],
        check=False,
        capture_output=True,
        text=True,
    )
    if check and completed.returncode != 0:
        raise AssertionError(completed.stderr)
    return completed.stdout.strip()


def _create_remote(tmp_path: Path) -> tuple[Path, str, str]:
    source = tmp_path / "source"
    source.mkdir()
    _git(source, "init", "--initial-branch=main")
    _git(source, "config", "user.name", "Test User")
    _git(source, "config", "user.email", "test@example.com")
    _git(source, "config", "commit.gpgsign", "false")
    translations = source / "i18n"
    translations.mkdir()
    (translations / "messages.properties").write_text("hello=Hello\n", encoding="utf-8")
    (translations / "messages_ru.properties").write_text(
        "hello=Privet\n", encoding="utf-8"
    )
    (source / "README.md").write_text("example\n", encoding="utf-8")
    _git(source, "add", ".")
    _git(source, "commit", "-m", "Create base")
    base_sha = _git(source, "rev-parse", "HEAD")

    _git(source, "checkout", "-b", "translation-review")
    (translations / "messages_ru.properties").write_text(
        "hello=Привет\n", encoding="utf-8"
    )
    _git(source, "add", "i18n/messages_ru.properties")
    _git(source, "commit", "-m", "Translate greeting")
    head_sha = _git(source, "rev-parse", "HEAD")

    remote_parent = tmp_path / "acme"
    remote_parent.mkdir()
    remote = remote_parent / "project.git"
    completed = subprocess.run(
        ["git", "clone", "--bare", str(source), str(remote)],
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stderr
    return remote, base_sha, head_sha


def _revision(*, ref: str, sha: str) -> ExactRevision:
    return ExactRevision(
        host="github.example.com",
        owner="acme",
        repository="project",
        ref=ref,
        sha=sha,
    )


def _historical_revision(*, sha: str, pull_number: int | None = None) -> HistoricalRevision:
    return HistoricalRevision(
        host="github.example.com",
        owner="acme",
        repository="project",
        sha=sha,
        pull_number=pull_number,
    )


@pytest.mark.parametrize("pull_number", [0, -1, True, "7"])
def test_historical_revision_rejects_invalid_pull_numbers(pull_number):
    """Historical refs must be exact positive numeric GitHub PR identities."""

    with pytest.raises((TypeError, ValueError)):
        _historical_revision(sha="a" * 40, pull_number=pull_number)


def test_historical_checkout_fetches_an_exact_old_commit_without_a_live_branch(
    tmp_path,
):
    """An old base SHA remains reconstructible after its branch advances."""

    remote, base_sha, head_sha = _create_remote(tmp_path)
    assert _git(remote, "rev-parse", "refs/heads/translation-review") == head_sha

    with materialize_historical_checkout(
        _historical_revision(sha=base_sha),
        remote_url=remote.as_uri(),
        allow_file_remote=True,
    ) as workspace:
        assert isinstance(workspace, HistoricalWorkspace)
        assert _git(workspace.path, "rev-parse", "HEAD") == base_sha
        assert _git(workspace.path, "symbolic-ref", "-q", "HEAD", check=False) == ""
        assert not hasattr(workspace, "commit_validated_changes")
        assert not hasattr(workspace, "publish_commit")


def test_historical_checkout_fetches_the_immutable_pull_head_ref(tmp_path):
    """A closed PR head is read from the upstream pull ref, not a fork branch."""

    remote, _base_sha, head_sha = _create_remote(tmp_path)
    _git(remote, "update-ref", "refs/pull/7/head", head_sha)
    _git(remote, "update-ref", "-d", "refs/heads/translation-review")

    with materialize_historical_checkout(
        _historical_revision(sha=head_sha, pull_number=7),
        remote_url=remote.as_uri(),
        allow_file_remote=True,
    ) as workspace:
        assert _git(workspace.path, "rev-parse", "HEAD") == head_sha
        assert workspace.revision.fetch_target == "refs/pull/7/head"


def test_historical_checkout_rejects_a_pull_ref_at_the_wrong_sha(tmp_path):
    """GitHub pull-ref movement cannot substitute a different historical head."""

    remote, base_sha, head_sha = _create_remote(tmp_path)
    _git(remote, "update-ref", "refs/pull/7/head", head_sha)

    with pytest.raises(WorkspaceError, match="exact expected SHA"):
        with materialize_historical_checkout(
            _historical_revision(sha=base_sha, pull_number=7),
            remote_url=remote.as_uri(),
            allow_file_remote=True,
        ):
            pytest.fail("a mismatched historical pull ref must not be yielded")


@pytest.mark.parametrize(
    "kwargs",
    [
        {"host": "https://github.com"},
        {"host": "github.com/evil"},
        {"owner": "../acme"},
        {"owner": "acme\nattacker"},
        {"repository": "project/other"},
        {"repository": ".."},
        {"ref": "translation-review"},
        {"ref": "refs/heads/../main"},
        {"ref": "refs/tags/main"},
        {"sha": "abc123"},
        {"sha": "G" * 40},
    ],
)
def test_exact_revision_rejects_hostile_or_ambiguous_identity(kwargs):
    values = {
        "host": "github.com",
        "owner": "acme",
        "repository": "project",
        "ref": "refs/heads/main",
        "sha": "a" * 40,
    }
    values.update(kwargs)

    with pytest.raises(ValueError):
        ExactRevision(**values)


def test_materializes_base_and_head_as_detached_exact_sha_checkouts(tmp_path):
    remote, base_sha, head_sha = _create_remote(tmp_path)
    checkout_root = tmp_path / "checkouts"
    checkout_root.mkdir()

    with materialize_exact_checkout(
        _revision(ref="refs/heads/main", sha=base_sha),
        remote_url=remote.as_uri(),
        allow_file_remote=True,
        temporary_root=checkout_root,
    ) as base:
        assert isinstance(base, GuardianWorkspace)
        assert base.original_sha == base_sha
        assert _git(base.path, "rev-parse", "HEAD") == base_sha
        assert _git(base.path, "symbolic-ref", "-q", "HEAD", check=False) == ""
        base_path = base.path

    assert not base_path.exists()

    with materialize_exact_checkout(
        _revision(ref="refs/heads/translation-review", sha=head_sha),
        remote_url=remote.as_uri(),
        allow_file_remote=True,
        temporary_root=checkout_root,
    ) as head:
        assert head.original_sha == head_sha
        assert _git(head.path, "rev-parse", "HEAD") == head_sha


@pytest.mark.parametrize("historical", [False, True])
def test_checkout_preserves_blobs_despite_later_line_ending_attributes(tmp_path, historical):
    """Adding text attributes without renormalizing must not dirty a checkout."""
    remote, _, _ = _create_remote(tmp_path)
    source = tmp_path / "source"
    original = b"@echo off\r\necho wrapper\r\n"
    (source / "gradlew.bat").write_bytes(original)
    _git(source, "-c", "core.autocrlf=false", "add", "gradlew.bat")
    _git(source, "commit", "-m", "Add CRLF wrapper")
    (source / ".gitattributes").write_text("gradlew.bat text eol=crlf\n", encoding="utf-8")
    _git(source, "add", ".gitattributes")
    _git(source, "commit", "-m", "Set attributes without renormalizing old blobs")
    sha = _git(source, "rev-parse", "HEAD")
    _git(source, "push", str(remote), "HEAD:refs/heads/translation-review")
    materialize = materialize_historical_checkout if historical else materialize_exact_checkout
    revision = (
        _historical_revision(sha=sha)
        if historical else _revision(ref="refs/heads/translation-review", sha=sha)
    )
    with materialize(revision, remote_url=remote.as_uri(), allow_file_remote=True) as workspace:
        assert (workspace.path / "gradlew.bat").read_bytes() == original
        assert _git(workspace.path, "status", "--porcelain") == ""
        assert _git(workspace.path, "rev-parse", "HEAD") == sha


def test_materialization_fails_closed_when_ref_does_not_resolve_to_expected_sha(
    tmp_path,
):
    remote, base_sha, _head_sha = _create_remote(tmp_path)

    with pytest.raises(WorkspaceError, match="exact expected SHA"):
        with materialize_exact_checkout(
            _revision(ref="refs/heads/translation-review", sha=base_sha),
            remote_url=remote.as_uri(),
            allow_file_remote=True,
        ):
            pytest.fail("a stale checkout must not be yielded")


@pytest.mark.parametrize(
    "remote_url",
    [
        "https://secret@github.example.com/acme/project.git",
        "https://github.example.com/other/project.git",
        "https://github.example.com/acme/other.git",
        "https://github.example.com/acme/project.git?token=secret",
        "ssh://git@github.example.com/acme/project.git",
        "file:///tmp/acme/project.git",
    ],
)
def test_remote_must_be_credential_free_identity_bound_https_by_default(remote_url):
    with pytest.raises(ValueError):
        with materialize_exact_checkout(
            _revision(ref="refs/heads/main", sha="a" * 40),
            remote_url=remote_url,
        ):
            pytest.fail("invalid remote must not be used")


def test_checkout_stops_before_starting_git_after_the_poll_deadline(tmp_path):
    now = [10.0]
    calls: list[float] = []

    def expire_after_first_call(args, **kwargs):
        calls.append(kwargs["timeout"])
        now[0] = 13.0
        return subprocess.CompletedProcess(args, 0, stdout="", stderr="")

    with pytest.raises(PollDeadlineExceeded, match="deadline"):
        with materialize_exact_checkout(
            _revision(ref="refs/heads/main", sha="a" * 40),
            temporary_root=tmp_path,
            timeout_seconds=37,
            deadline=PollDeadline(3, clock=lambda: now[0]),
            _process_runner=expire_after_first_call,
        ):
            pytest.fail("an expired checkout must not be yielded")

    assert calls == [3]


def test_checkout_promotes_a_deadline_bound_git_timeout(tmp_path):
    calls: list[float] = []

    def timed_out_git(args, **kwargs):
        calls.append(kwargs["timeout"])
        raise subprocess.TimeoutExpired(args, kwargs["timeout"])

    with pytest.raises(PollDeadlineExceeded, match="deadline"):
        with materialize_exact_checkout(
            _revision(ref="refs/heads/main", sha="a" * 40),
            temporary_root=tmp_path,
            timeout_seconds=37,
            deadline=PollDeadline(3, clock=lambda: 10.0),
            _process_runner=timed_out_git,
        ):
            pytest.fail("a deadline-bound git timeout must not yield a checkout")

    assert calls == [3]


def test_credentials_are_fetch_only_and_never_placed_in_argv(tmp_path):
    remote, _base_sha, head_sha = _create_remote(tmp_path)
    secret = "guardian-secret-value"
    calls: list[tuple[tuple[str, ...], Mapping[str, str]]] = []
    original_run = subprocess.run

    def recording_run(args: Sequence[str], **kwargs):
        calls.append((tuple(args), dict(kwargs["env"])))
        return original_run(args, **kwargs)

    with materialize_exact_checkout(
        _revision(ref="refs/heads/translation-review", sha=head_sha),
        remote_url=remote.as_uri(),
        allow_file_remote=True,
        credential_environment=lambda: {
            "GIT_ASKPASS": "/usr/bin/false",
            "LOCALIZE_GUARDIAN_GIT_TOKEN": secret,
        },
        _process_runner=recording_run,
    ):
        pass

    assert calls
    assert all(secret not in "\0".join(arguments) for arguments, _environment in calls)
    calls_with_secret = [
        arguments for arguments, environment in calls if secret in environment.values()
    ]
    assert len(calls_with_secret) == 1
    assert "fetch" in calls_with_secret[0]
    assert all(
        "OPENAI_API_KEY" not in environment and "GITHUB_TOKEN" not in environment
        for _arguments, environment in calls
    )


@pytest.mark.parametrize(
    "unsafe_environment",
    [
        {"GIT_CONFIG_GLOBAL": "/tmp/attacker-config"},
        {"GIT_CONFIG_COUNT": "1"},
        {"LD_PRELOAD": "/tmp/attacker-library"},
        {"GIT_ASKPASS": "relative-helper"},
    ],
)
def test_credential_environment_cannot_override_git_security_controls(
    tmp_path,
    unsafe_environment,
):
    remote, _base_sha, head_sha = _create_remote(tmp_path)

    with pytest.raises(WorkspaceError, match="credential environment"):
        with materialize_exact_checkout(
            _revision(ref="refs/heads/translation-review", sha=head_sha),
            remote_url=remote.as_uri(),
            allow_file_remote=True,
            credential_environment=lambda: unsafe_environment,
        ):
            pytest.fail("an unsafe credential environment must not be used")


def test_credential_provider_failure_does_not_echo_secret_exception_text(tmp_path):
    remote, _base_sha, head_sha = _create_remote(tmp_path)
    secret = "provider accidentally included a secret"

    def failing_provider():
        raise RuntimeError(secret)

    with pytest.raises(WorkspaceError, match="provider failed") as failure:
        with materialize_exact_checkout(
            _revision(ref="refs/heads/translation-review", sha=head_sha),
            remote_url=remote.as_uri(),
            allow_file_remote=True,
            credential_environment=failing_provider,
        ):
            pytest.fail("a failed credential provider must not yield a checkout")

    assert secret not in str(failure.value)
    assert failure.value.__cause__ is None


def test_credential_provider_preserves_poll_deadline_expiry(tmp_path):
    remote, _base_sha, head_sha = _create_remote(tmp_path)

    def expired_provider():
        raise PollDeadlineExceeded("Guardian poll deadline was exceeded.")

    with pytest.raises(PollDeadlineExceeded, match="deadline"):
        with materialize_exact_checkout(
            _revision(ref="refs/heads/translation-review", sha=head_sha),
            remote_url=remote.as_uri(),
            allow_file_remote=True,
            credential_environment=expired_provider,
        ):
            pytest.fail("an expired credential provider must not yield a checkout")


def test_commits_only_exact_translation_paths_and_links_feedback(tmp_path):
    remote, _base_sha, head_sha = _create_remote(tmp_path)

    with materialize_exact_checkout(
        _revision(ref="refs/heads/translation-review", sha=head_sha),
        remote_url=remote.as_uri(),
        allow_file_remote=True,
    ) as workspace:
        target = workspace.path / "i18n/messages_ru.properties"
        target.write_text("hello=Здравствуйте\n", encoding="utf-8")
        result = workspace.commit_validated_changes(
            expected_paths=("i18n/messages_ru.properties",),
            pull_number=7,
            feedback_urls=(
                "https://github.example.com/acme/project/pull/7#discussion_r123",
                "https://github.example.com/acme/project/issues/7#issuecomment-456",
            ),
            sign=False,
        )

        assert isinstance(result, CommitResult)
        assert result.parent_sha == head_sha
        assert result.changed_paths == ("i18n/messages_ru.properties",)
        assert result.signature_verified is False
        assert (
            _git(workspace.path, "status", "--porcelain", "--untracked-files=all") == ""
        )
        assert _git(workspace.path, "rev-parse", "HEAD") == result.commit_sha
        assert _git(workspace.path, "rev-parse", "HEAD^") == head_sha
        assert _git(workspace.path, "show", "--format=%s", "--no-patch", "HEAD") == (
            "[localize-guardian] Apply review feedback"
        )
        body = _git(workspace.path, "show", "--format=%B", "--no-patch", "HEAD")
        assert "Created by the Localize Guardian bot." in body
        assert "pull/7#discussion_r123" in body
        assert "issues/7#issuecomment-456" in body

    assert _git(remote, "rev-parse", "refs/heads/translation-review") == head_sha


def test_fork_commit_links_feedback_in_the_base_repository(tmp_path):
    remote, _base_sha, head_sha = _create_remote(tmp_path)
    with materialize_exact_checkout(
        _revision(ref="refs/heads/translation-review", sha=head_sha),
        remote_url=remote.as_uri(),
        allow_file_remote=True,
    ) as workspace:
        (workspace.path / "i18n/messages_ru.properties").write_text(
            "hello=Здравствуйте\n",
            encoding="utf-8",
        )
        result = workspace.commit_validated_changes(
            expected_paths=("i18n/messages_ru.properties",),
            pull_number=7,
            feedback_repository="upstream/project",
            feedback_urls=(
                "https://github.example.com/upstream/project/pull/7#discussion_r123",
            ),
            sign=False,
        )

        assert result.parent_sha == head_sha
        assert "upstream/project/pull/7" in _git(
            workspace.path, "show", "--format=%B", "--no-patch", "HEAD"
        )


def test_publishes_exact_descendant_with_expected_old_ref_and_confirms_ref(tmp_path):
    remote, _base_sha, head_sha = _create_remote(tmp_path)
    calls = []
    publication_sequence: list[str] = []
    original_run = subprocess.run

    def recording_run(args, **kwargs):
        calls.append((tuple(args), dict(kwargs["env"])))
        for command in ("fetch", "push", "ls-remote"):
            if command in args:
                publication_sequence.append(command)
                break
        return original_run(args, **kwargs)

    with materialize_exact_checkout(
        _revision(ref="refs/heads/translation-review", sha=head_sha),
        remote_url=remote.as_uri(),
        allow_file_remote=True,
        _process_runner=recording_run,
    ) as workspace:
        (workspace.path / "i18n/messages_ru.properties").write_text(
            "hello=Здравствуйте\n",
            encoding="utf-8",
        )
        commit = workspace.commit_validated_changes(
            expected_paths=("i18n/messages_ru.properties",),
            pull_number=7,
            feedback_urls=(
                "https://github.example.com/acme/project/pull/7#discussion_r123",
            ),
            sign=False,
        )
        publication_sequence.clear()
        published = workspace.publish_commit(
            commit,
            credential_environment=lambda: {
                "GIT_ASKPASS": "/usr/bin/false",
                "LOCALIZE_GUARDIAN_GIT_TOKEN": "publish-secret",
            },
            require_signature=False,
            before_push=lambda: publication_sequence.append("lease-check"),
        )

    assert published == PublicationResult(
        ref="refs/heads/translation-review",
        previous_sha=head_sha,
        commit_sha=commit.commit_sha,
    )
    assert (
        _git(remote, "rev-parse", "refs/heads/translation-review") == commit.commit_sha
    )
    network_calls = [
        (argv, environment)
        for argv, environment in calls
        if any(command in argv for command in ("fetch", "push", "ls-remote"))
        and "publish-secret" in environment.values()
    ]
    assert {
        next(command for command in ("fetch", "push", "ls-remote") if command in argv)
        for argv, _ in network_calls
    } == {
        "fetch",
        "push",
        "ls-remote",
    }
    assert all("publish-secret" not in "\0".join(argv) for argv, _ in network_calls)
    push_argv = next(argv for argv, _ in network_calls if "push" in argv)
    assert "--force" not in push_argv
    assert "--atomic" in push_argv
    assert (
        f"--force-with-lease=refs/heads/translation-review:{head_sha}" in push_argv
    )
    assert publication_sequence == ["fetch", "lease-check", "push", "ls-remote"]


def test_publish_callback_failure_prevents_the_remote_mutation(tmp_path):
    remote, _base_sha, head_sha = _create_remote(tmp_path)
    with materialize_exact_checkout(
        _revision(ref="refs/heads/translation-review", sha=head_sha),
        remote_url=remote.as_uri(),
        allow_file_remote=True,
    ) as workspace:
        (workspace.path / "i18n/messages_ru.properties").write_text(
            "hello=Здравствуйте\n",
            encoding="utf-8",
        )
        commit = workspace.commit_validated_changes(
            expected_paths=("i18n/messages_ru.properties",),
            pull_number=7,
            feedback_urls=(
                "https://github.example.com/acme/project/pull/7#discussion_r123",
            ),
            sign=False,
        )

        def lost_lease() -> None:
            raise RuntimeError("lease lost")

        with pytest.raises(RuntimeError, match="lease lost"):
            workspace.publish_commit(
                commit,
                require_signature=False,
                before_push=lost_lease,
            )

    assert _git(remote, "rev-parse", "refs/heads/translation-review") == head_sha


def test_publish_exact_lease_rejects_remote_rewind_during_callback(tmp_path):
    """A force-rewind cannot be overwritten by our otherwise fast-forward commit."""

    remote, base_sha, head_sha = _create_remote(tmp_path)
    with materialize_exact_checkout(
        _revision(ref="refs/heads/translation-review", sha=head_sha),
        remote_url=remote.as_uri(),
        allow_file_remote=True,
    ) as workspace:
        (workspace.path / "i18n/messages_ru.properties").write_text(
            "hello=Здравствуйте\n",
            encoding="utf-8",
        )
        commit = workspace.commit_validated_changes(
            expected_paths=("i18n/messages_ru.properties",),
            pull_number=7,
            feedback_urls=(
                "https://github.example.com/acme/project/pull/7#discussion_r123",
            ),
            sign=False,
        )

        def rewind_remote() -> None:
            _git(
                remote,
                "update-ref",
                "refs/heads/translation-review",
                base_sha,
                head_sha,
            )

        with pytest.raises(WorkspaceError, match="git push failed"):
            workspace.publish_commit(
                commit,
                require_signature=False,
                before_push=rewind_remote,
            )

    assert _git(remote, "rev-parse", "refs/heads/translation-review") == base_sha


def test_publish_rechecks_authority_after_final_signature_verification(tmp_path):
    remote, _base_sha, head_sha = _create_remote(tmp_path)
    original_run = subprocess.run
    authority_current = True
    verify_calls = 0
    push_calls = 0

    def signing_spy(args: Sequence[str], **kwargs):
        nonlocal authority_current, push_calls, verify_calls
        arguments = tuple(args)
        if "commit" in arguments and "-S" in arguments:
            arguments = tuple(
                "--no-gpg-sign" if value == "-S" else value for value in arguments
            )
        if "verify-commit" in arguments:
            verify_calls += 1
            if verify_calls == 3:
                authority_current = False
            return subprocess.CompletedProcess(arguments, 0, "", "")
        if "push" in arguments:
            push_calls += 1
        return original_run(arguments, **kwargs)

    with materialize_exact_checkout(
        _revision(ref="refs/heads/translation-review", sha=head_sha),
        remote_url=remote.as_uri(),
        allow_file_remote=True,
        _process_runner=signing_spy,
    ) as workspace:
        (workspace.path / "i18n/messages_ru.properties").write_text(
            "hello=Здравствуйте\n",
            encoding="utf-8",
        )
        commit = workspace.commit_validated_changes(
            expected_paths=("i18n/messages_ru.properties",),
            pull_number=7,
            feedback_urls=(
                "https://github.example.com/acme/project/pull/7#discussion_r123",
            ),
        )

        def require_current_authority() -> None:
            if not authority_current:
                raise RuntimeError("authority lost")

        with pytest.raises(RuntimeError, match="authority lost"):
            workspace.publish_commit(commit, before_push=require_current_authority)

    assert verify_calls == 3
    assert push_calls == 0
    assert _git(remote, "rev-parse", "refs/heads/translation-review") == head_sha


def test_publish_rejects_unsigned_or_stale_remote_without_moving_ref(tmp_path):
    remote, _base_sha, head_sha = _create_remote(tmp_path)
    with materialize_exact_checkout(
        _revision(ref="refs/heads/translation-review", sha=head_sha),
        remote_url=remote.as_uri(),
        allow_file_remote=True,
    ) as workspace:
        (workspace.path / "i18n/messages_ru.properties").write_text(
            "hello=Здравствуйте\n",
            encoding="utf-8",
        )
        commit = workspace.commit_validated_changes(
            expected_paths=("i18n/messages_ru.properties",),
            pull_number=7,
            feedback_urls=(
                "https://github.example.com/acme/project/pull/7#discussion_r123",
            ),
            sign=False,
        )
        with pytest.raises(WorkspaceError, match="signed"):
            workspace.publish_commit(commit)

        other = tmp_path / "other"
        subprocess.run(
            ["git", "clone", remote.as_uri(), str(other)],
            check=True,
            capture_output=True,
            text=True,
        )
        _git(other, "config", "user.name", "Other")
        _git(other, "config", "user.email", "other@example.com")
        _git(other, "config", "commit.gpgsign", "false")
        _git(other, "checkout", "translation-review")
        _git(other, "commit", "--allow-empty", "-m", "Move remote")
        _git(other, "push", "origin", "translation-review")
        moved_sha = _git(remote, "rev-parse", "refs/heads/translation-review")

        with pytest.raises(WorkspaceError, match="changed since intake"):
            workspace.publish_commit(commit, require_signature=False)

    assert _git(remote, "rev-parse", "refs/heads/translation-review") == moved_sha


def test_default_commit_path_requests_and_verifies_signature(tmp_path):
    remote, _base_sha, head_sha = _create_remote(tmp_path)
    original_run = subprocess.run
    calls: list[tuple[str, ...]] = []

    def signing_spy(args: Sequence[str], **kwargs):
        arguments = tuple(args)
        calls.append(arguments)
        if "commit" in arguments and "-S" in arguments:
            unsigned = tuple(
                "--no-gpg-sign" if value == "-S" else value for value in arguments
            )
            return original_run(unsigned, **kwargs)
        if "verify-commit" in arguments:
            return subprocess.CompletedProcess(arguments, 0, "", "")
        return original_run(arguments, **kwargs)

    with materialize_exact_checkout(
        _revision(ref="refs/heads/translation-review", sha=head_sha),
        remote_url=remote.as_uri(),
        allow_file_remote=True,
        _process_runner=signing_spy,
    ) as workspace:
        (workspace.path / "i18n/messages_ru.properties").write_text(
            "hello=Здравствуйте\n",
            encoding="utf-8",
        )
        result = workspace.commit_validated_changes(
            expected_paths=("i18n/messages_ru.properties",),
            pull_number=7,
            feedback_urls=(
                "https://github.example.com/acme/project/pull/7#discussion_r123",
            ),
        )

    assert result.signature_verified is True
    assert any("commit" in call and "-S" in call for call in calls)
    assert any("verify-commit" in call for call in calls)
    assert all("push" not in call for call in calls)


def test_openpgp_profile_keeps_the_existing_git_flags_and_environment(tmp_path):
    remote, _base_sha, head_sha = _create_remote(tmp_path)
    fingerprint = "A" * 40
    gnupg_home = tmp_path / "gnupg"
    gnupg_home.mkdir(mode=0o700)
    calls: list[tuple[tuple[str, ...], dict[str, str]]] = []
    original_run = subprocess.run

    def signing_spy(args: Sequence[str], **kwargs):
        arguments = tuple(args)
        calls.append((arguments, dict(kwargs["env"])))
        if "commit" in arguments and f"-S{fingerprint}" in arguments:
            unsigned = tuple(
                "--no-gpg-sign" if value == f"-S{fingerprint}" else value
                for value in arguments
            )
            return original_run(unsigned, **kwargs)
        if "verify-commit" in arguments:
            return subprocess.CompletedProcess(
                arguments,
                0,
                "",
                f"[GNUPG:] VALIDSIG {fingerprint}\n",
            )
        return original_run(arguments, **kwargs)

    with materialize_exact_checkout(
        _revision(ref="refs/heads/translation-review", sha=head_sha),
        remote_url=remote.as_uri(),
        allow_file_remote=True,
        signing_program="/usr/bin/gpg",
        _process_runner=signing_spy,
    ) as workspace:
        (workspace.path / "i18n/messages_ru.properties").write_text(
            "hello=Здравствуйте\n",
            encoding="utf-8",
        )
        workspace.commit_validated_changes(
            expected_paths=("i18n/messages_ru.properties",),
            pull_number=7,
            feedback_urls=(
                "https://github.example.com/acme/project/pull/7#discussion_r123",
            ),
            signing_key=fingerprint,
            signing_environment={"GNUPGHOME": str(gnupg_home)},
        )

    signing_calls = [
        call for call in calls if "commit" in call[0] or "verify-commit" in call[0]
    ]
    assert len(signing_calls) == 2
    for arguments, environment in signing_calls:
        assert "gpg.program=/usr/bin/gpg" in arguments
        assert "gpg.format=ssh" not in arguments
        assert not any(
            argument.startswith("gpg.ssh.") for argument in arguments
        )
        assert environment["GNUPGHOME"] == str(gnupg_home.resolve())
        assert "SSH_AUTH_SOCK" not in environment


def test_openpgp_commit_rejects_an_untrusted_signing_home_before_staging(tmp_path):
    remote, _base_sha, head_sha = _create_remote(tmp_path)
    gnupg_home = tmp_path / "gnupg"
    gnupg_home.mkdir(mode=0o700)
    gnupg_home.chmod(0o777)

    with materialize_exact_checkout(
        _revision(ref="refs/heads/translation-review", sha=head_sha),
        remote_url=remote.as_uri(),
        allow_file_remote=True,
    ) as workspace:
        (workspace.path / "i18n/messages_ru.properties").write_text(
            "hello=Здравствуйте\n",
            encoding="utf-8",
        )
        with pytest.raises(ValueError, match="0700"):
            workspace.commit_validated_changes(
                expected_paths=("i18n/messages_ru.properties",),
                pull_number=7,
                feedback_urls=(
                    "https://github.example.com/acme/project/pull/7#discussion_r123",
                ),
                signing_environment={"GNUPGHOME": str(gnupg_home)},
            )

        assert _git(workspace.path, "diff", "--cached", "--name-only") == ""


def test_ssh_signing_uses_exact_snapshot_and_limits_agent_socket_to_commit(
    tmp_path,
):
    remote, _base_sha, head_sha = _create_remote(tmp_path)
    fingerprint = "SHA256:" + "A" * 43
    signing_root = tmp_path / "ssh-signing"
    signing_root.mkdir(mode=0o700)
    public_key = signing_root / "signing-key.pub"
    allowed_signers = signing_root / "allowed-signers"
    public_key.write_text("ssh-ed25519 AAAATest\n", encoding="ascii")
    allowed_signers.write_text(
        "localize-guardian ssh-ed25519 AAAATest\n",
        encoding="ascii",
    )
    public_key.chmod(0o600)
    allowed_signers.chmod(0o600)
    material = SSHSigningMaterial(
        root=signing_root,
        public_key=public_key,
        allowed_signers=allowed_signers,
        fingerprint=fingerprint,
    )
    socket_root = Path(
        tempfile.mkdtemp(prefix="lg-agent-", dir=str(Path("/tmp").resolve()))
    )
    socket_path = socket_root / "agent.sock"
    agent_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    agent_socket.bind(str(socket_path))
    calls: list[tuple[tuple[str, ...], dict[str, str]]] = []
    original_run = subprocess.run

    def signing_spy(args: Sequence[str], **kwargs):
        arguments = tuple(args)
        calls.append((arguments, dict(kwargs["env"])))
        if "commit" in arguments and any(
            argument.startswith("-S") for argument in arguments
        ):
            unsigned = tuple(
                "--no-gpg-sign" if value.startswith("-S") else value
                for value in arguments
            )
            return original_run(unsigned, **kwargs)
        if "verify-commit" in arguments:
            return subprocess.CompletedProcess(
                arguments,
                0,
                (
                    'Good "git" signature for localize-guardian with ED25519 key '
                    f"{fingerprint}\n"
                ),
                "",
            )
        return original_run(arguments, **kwargs)

    try:
        with materialize_exact_checkout(
            _revision(ref="refs/heads/translation-review", sha=head_sha),
            remote_url=remote.as_uri(),
            allow_file_remote=True,
            signing_format=SigningFormat.SSH,
            signing_program="/usr/bin/ssh-keygen",
            ssh_signing_material=material,
            _process_runner=signing_spy,
        ) as workspace:
            (workspace.path / "i18n/messages_ru.properties").write_text(
                "hello=Здравствуйте\n",
                encoding="utf-8",
            )
            commit = workspace.commit_validated_changes(
                expected_paths=("i18n/messages_ru.properties",),
                pull_number=7,
                feedback_urls=(
                    "https://github.example.com/acme/project/pull/7#discussion_r123",
                ),
                signing_key=fingerprint,
                signing_environment={"SSH_AUTH_SOCK": str(socket_path)},
            )
            workspace.publish_commit(
                commit,
                signing_key=fingerprint,
                signing_environment={"SSH_AUTH_SOCK": str(socket_path)},
            )
    finally:
        agent_socket.close()
        socket_path.unlink(missing_ok=True)
        socket_root.rmdir()

    commit_call = next(call for call in calls if "commit" in call[0])
    assert commit_call[1]["SSH_AUTH_SOCK"] == str(socket_path)
    assert f"-S{public_key}" in commit_call[0]
    assert all(
        "SSH_AUTH_SOCK" not in environment
        for arguments, environment in calls
        if "commit" not in arguments
    )
    verify_calls = [arguments for arguments, _environment in calls if "verify-commit" in arguments]
    assert len(verify_calls) == 3
    for arguments in verify_calls:
        assert "gpg.format=ssh" in arguments
        assert "gpg.ssh.program=/usr/bin/ssh-keygen" in arguments
        assert f"gpg.ssh.allowedSignersFile={allowed_signers}" in arguments
        assert "gpg.minTrustLevel=fully" in arguments
    push_index = next(index for index, call in enumerate(calls) if "push" in call[0])
    assert "verify-commit" in calls[push_index - 1][0]


def test_ssh_signing_rejects_wrong_fingerprint_or_non_socket_agent(tmp_path):
    remote, _base_sha, head_sha = _create_remote(tmp_path)
    fingerprint = "SHA256:" + "A" * 43
    signing_root = tmp_path / "ssh-signing"
    signing_root.mkdir(mode=0o700)
    public_key = signing_root / "signing-key.pub"
    allowed_signers = signing_root / "allowed-signers"
    public_key.write_text("ssh-ed25519 AAAATest\n", encoding="ascii")
    allowed_signers.write_text(
        "localize-guardian ssh-ed25519 AAAATest\n",
        encoding="ascii",
    )
    public_key.chmod(0o600)
    allowed_signers.chmod(0o600)
    material = SSHSigningMaterial(
        root=signing_root,
        public_key=public_key,
        allowed_signers=allowed_signers,
        fingerprint=fingerprint,
    )
    fake_socket = tmp_path / "not-a-socket"
    fake_socket.write_text("not a socket", encoding="ascii")

    with materialize_exact_checkout(
        _revision(ref="refs/heads/translation-review", sha=head_sha),
        remote_url=remote.as_uri(),
        allow_file_remote=True,
        signing_format=SigningFormat.SSH,
        signing_program="/usr/bin/ssh-keygen",
        ssh_signing_material=material,
    ) as workspace:
        target = workspace.path / "i18n/messages_ru.properties"
        target.write_text("hello=Здравствуйте\n", encoding="utf-8")
        with pytest.raises(ValueError, match="fingerprint"):
            workspace.commit_validated_changes(
                expected_paths=("i18n/messages_ru.properties",),
                pull_number=7,
                feedback_urls=(
                    "https://github.example.com/acme/project/pull/7#discussion_r123",
                ),
                signing_key="SHA256:" + "B" * 43,
                signing_environment={"SSH_AUTH_SOCK": str(fake_socket)},
            )
        with pytest.raises(ValueError, match="SSH_AUTH_SOCK"):
            workspace.commit_validated_changes(
                expected_paths=("i18n/messages_ru.properties",),
                pull_number=7,
                feedback_urls=(
                    "https://github.example.com/acme/project/pull/7#discussion_r123",
                ),
                signing_key=fingerprint,
                signing_environment={"SSH_AUTH_SOCK": str(fake_socket)},
            )


def test_git_runner_restricts_agent_socket_to_ssh_commit_subprocess(tmp_path):
    remote, _base_sha, head_sha = _create_remote(tmp_path)
    fingerprint = "SHA256:" + "A" * 43
    signing_root = tmp_path / "ssh-signing"
    signing_root.mkdir(mode=0o700)
    public_key = signing_root / "signing-key.pub"
    allowed_signers = signing_root / "allowed-signers"
    public_key.write_text("ssh-ed25519 AAAATest\n", encoding="ascii")
    allowed_signers.write_text(
        "localize-guardian ssh-ed25519 AAAATest\n",
        encoding="ascii",
    )
    public_key.chmod(0o600)
    allowed_signers.chmod(0o600)
    material = SSHSigningMaterial(
        root=signing_root,
        public_key=public_key,
        allowed_signers=allowed_signers,
        fingerprint=fingerprint,
    )

    with materialize_exact_checkout(
        _revision(ref="refs/heads/translation-review", sha=head_sha),
        remote_url=remote.as_uri(),
        allow_file_remote=True,
        signing_format=SigningFormat.SSH,
        signing_program="/usr/bin/ssh-keygen",
        ssh_signing_material=material,
    ) as workspace:
        workspace._runner.process_runner = lambda *args, **kwargs: subprocess.CompletedProcess(
            args[0],
            0,
            "",
            "",
        )
        for operation in ("fetch", "push", "verify-commit", "status"):
            with pytest.raises(WorkspaceError, match="SSH_AUTH_SOCK.*commit"):
                workspace._runner.run(
                    (operation,),
                    extra_environment={"SSH_AUTH_SOCK": "/private/agent.sock"},
                )


def test_ssh_checkout_rejects_untrusted_signing_program_at_public_boundary(tmp_path):
    remote, _base_sha, head_sha = _create_remote(tmp_path)
    fingerprint = "SHA256:" + "A" * 43
    signing_root = tmp_path / "ssh-signing"
    signing_root.mkdir(mode=0o700)
    public_key = signing_root / "signing-key.pub"
    allowed_signers = signing_root / "allowed-signers"
    public_key.write_text("ssh-ed25519 AAAATest\n", encoding="ascii")
    allowed_signers.write_text(
        "localize-guardian ssh-ed25519 AAAATest\n",
        encoding="ascii",
    )
    public_key.chmod(0o600)
    allowed_signers.chmod(0o600)
    material = SSHSigningMaterial(
        root=signing_root,
        public_key=public_key,
        allowed_signers=allowed_signers,
        fingerprint=fingerprint,
    )
    untrusted_program = tmp_path / "untrusted-ssh-keygen"
    untrusted_program.write_text("#!/bin/sh\nexit 0\n", encoding="ascii")
    untrusted_program.chmod(0o777)

    with pytest.raises(ValueError, match="trusted, non-symlinked executable"):
        with materialize_exact_checkout(
            _revision(ref="refs/heads/translation-review", sha=head_sha),
            remote_url=remote.as_uri(),
            allow_file_remote=True,
            signing_format=SigningFormat.SSH,
            signing_program=str(untrusted_program),
            ssh_signing_material=material,
        ):
            pytest.fail("an untrusted SSH verification program must fail closed")


def test_unsigned_openpgp_commit_still_rejects_malformed_supplied_key(tmp_path):
    remote, _base_sha, head_sha = _create_remote(tmp_path)

    with materialize_exact_checkout(
        _revision(ref="refs/heads/translation-review", sha=head_sha),
        remote_url=remote.as_uri(),
        allow_file_remote=True,
    ) as workspace:
        with pytest.raises(ValueError, match="OpenPGP fingerprint"):
            workspace.commit_validated_changes(
                expected_paths=("i18n/messages_ru.properties",),
                pull_number=7,
                feedback_urls=(
                    "https://github.example.com/acme/project/pull/7#discussion_r123",
                ),
                sign=False,
                signing_key="not-a-fingerprint",
            )


def test_signs_validated_prevention_modifications_and_new_tests_then_creates_branch(
    tmp_path,
):
    remote, _base_sha, head_sha = _create_remote(tmp_path)
    original_run = subprocess.run
    calls: list[tuple[tuple[str, ...], dict[str, str]]] = []

    def signing_spy(args: Sequence[str], **kwargs):
        arguments = tuple(args)
        calls.append((arguments, dict(kwargs["env"])))
        if "commit" in arguments and "-S" in arguments:
            unsigned = tuple(
                "--no-gpg-sign" if value == "-S" else value for value in arguments
            )
            return original_run(unsigned, **kwargs)
        if "verify-commit" in arguments:
            return subprocess.CompletedProcess(arguments, 0, "", "")
        return original_run(arguments, **kwargs)

    with materialize_exact_checkout(
        _revision(ref="refs/heads/translation-review", sha=head_sha),
        remote_url=remote.as_uri(),
        allow_file_remote=True,
        _process_runner=signing_spy,
    ) as workspace:
        (workspace.path / "README.md").write_text("prevention\n", encoding="utf-8")
        new_test = workspace.path / "tests/test_prevention.py"
        new_test.parent.mkdir()
        new_test.write_text("def test_guard():\n    assert True\n", encoding="utf-8")
        commit = workspace.commit_prevention_changes(
            expected_paths=("README.md", "tests/test_prevention.py"),
            evidence_hash="a" * 64,
        )
        lease_checks: list[str] = []

        def lost_lease() -> None:
            raise RuntimeError("lease lost")

        with pytest.raises(RuntimeError, match="lease lost"):
            workspace.publish_prevention_branch(
                commit,
                push_repository="acme/project",
                branch="guardian/prevention-abc",
                branch_prefix="guardian/prevention-",
                credential_environment=lambda: {
                    "GIT_ASKPASS": "/usr/bin/false",
                },
                before_push=lost_lease,
                remote_url=remote.as_uri(),
                allow_file_remote=True,
            )
        assert (
            _git(
                remote,
                "show-ref",
                "--verify",
                "refs/heads/guardian/prevention-abc",
                check=False,
            )
            == ""
        )

        published = workspace.publish_prevention_branch(
            commit,
            push_repository="acme/project",
            branch="guardian/prevention-abc",
            branch_prefix="guardian/prevention-",
            credential_environment=lambda: {
                "GIT_ASKPASS": "/usr/bin/false",
                "LOCALIZE_GUARDIAN_GIT_TOKEN": "prevention-secret",
            },
            before_push=lambda: lease_checks.append("checked"),
            remote_url=remote.as_uri(),
            allow_file_remote=True,
        )

    assert commit.parent_sha == head_sha
    assert commit.changed_paths == ("README.md", "tests/test_prevention.py")
    assert commit.signature_verified is True
    assert published == PreventionPublicationResult(
        repository="acme/project",
        ref="refs/heads/guardian/prevention-abc",
        commit_sha=commit.commit_sha,
        created=True,
    )
    assert _git(remote, "rev-parse", published.ref) == commit.commit_sha
    assert lease_checks == ["checked"]
    push_call = next(arguments for arguments, _env in calls if "push" in arguments)
    assert "--force-with-lease=refs/heads/guardian/prevention-abc:" in push_call
    push_index = next(index for index, call in enumerate(calls) if "push" in call[0])
    assert "verify-commit" in calls[push_index - 1][0]
    assert all(
        "prevention-secret" not in "\0".join(arguments)
        for arguments, _environment in calls
    )


def test_prevention_rechecks_authority_after_final_signature_verification(tmp_path):
    remote, _base_sha, head_sha = _create_remote(tmp_path)
    original_run = subprocess.run
    authority_current = True
    verify_calls = 0
    push_calls = 0

    def signing_spy(args: Sequence[str], **kwargs):
        nonlocal authority_current, push_calls, verify_calls
        arguments = tuple(args)
        if "commit" in arguments and "-S" in arguments:
            arguments = tuple(
                "--no-gpg-sign" if value == "-S" else value for value in arguments
            )
        if "verify-commit" in arguments:
            verify_calls += 1
            if verify_calls == 3:
                authority_current = False
            return subprocess.CompletedProcess(arguments, 0, "", "")
        if "push" in arguments:
            push_calls += 1
        return original_run(arguments, **kwargs)

    with materialize_exact_checkout(
        _revision(ref="refs/heads/translation-review", sha=head_sha),
        remote_url=remote.as_uri(),
        allow_file_remote=True,
        _process_runner=signing_spy,
    ) as workspace:
        (workspace.path / "README.md").write_text("prevention\n", encoding="utf-8")
        commit = workspace.commit_prevention_changes(
            expected_paths=("README.md",),
            evidence_hash="a" * 64,
        )

        def require_current_authority() -> None:
            if not authority_current:
                raise RuntimeError("authority lost")

        with pytest.raises(RuntimeError, match="authority lost"):
            workspace.publish_prevention_branch(
                commit,
                push_repository="acme/project",
                branch="guardian/prevention-authority-loss",
                branch_prefix="guardian/prevention-",
                credential_environment=lambda: {},
                before_push=require_current_authority,
                remote_url=remote.as_uri(),
                allow_file_remote=True,
            )

    assert verify_calls == 3
    assert push_calls == 0
    assert (
        _git(
            remote,
            "show-ref",
            "--verify",
            "refs/heads/guardian/prevention-authority-loss",
            check=False,
        )
        == ""
    )


def test_signs_value_only_historical_remediation_with_cross_pr_evidence(tmp_path):
    """A remediation commit may link several closed PRs but only tracked values."""

    remote, _base_sha, head_sha = _create_remote(tmp_path)
    original_run = subprocess.run

    def signing_spy(args: Sequence[str], **kwargs):
        arguments = tuple(args)
        if "commit" in arguments and "-S" in arguments:
            arguments = tuple(
                "--no-gpg-sign" if value == "-S" else value for value in arguments
            )
        if "verify-commit" in arguments:
            return subprocess.CompletedProcess(arguments, 0, "", "")
        return original_run(arguments, **kwargs)

    with materialize_exact_checkout(
        _revision(ref="refs/heads/translation-review", sha=head_sha),
        remote_url=remote.as_uri(),
        allow_file_remote=True,
        _process_runner=signing_spy,
    ) as workspace:
        (workspace.path / "i18n/messages_ru.properties").write_text(
            "hello=Здравствуйте\n",
            encoding="utf-8",
        )
        commit = workspace.commit_historical_remediation_changes(
            expected_paths=("i18n/messages_ru.properties",),
            feedback_repository="upstream/project",
            feedback_pull_numbers=(7, 11),
            feedback_urls=(
                "https://github.example.com/upstream/project/pull/7#discussion_r123",
                "https://github.example.com/upstream/project/issues/11#issuecomment-456",
            ),
            evidence_hash="b" * 64,
        )

        assert commit.parent_sha == head_sha
        assert commit.changed_paths == ("i18n/messages_ru.properties",)
        assert commit.signature_verified is True
        assert _git(workspace.path, "show", "--format=%s", "--no-patch", "HEAD") == (
            "[localize-guardian] Repair historical feedback"
        )
        body = _git(workspace.path, "show", "--format=%B", "--no-patch", "HEAD")
        assert "human review" in body
        assert "pull/7#discussion_r123" in body
        assert "issues/11#issuecomment-456" in body
        assert f"Historical evidence: {'b' * 64}" in body


def test_historical_remediation_rejects_new_files_and_wrong_pr_links(tmp_path):
    """Historical repair authority cannot add files or cite unrelated PRs."""

    remote, _base_sha, head_sha = _create_remote(tmp_path)
    original_run = subprocess.run

    def signing_spy(args: Sequence[str], **kwargs):
        arguments = tuple(args)
        if "commit" in arguments and "-S" in arguments:
            arguments = tuple(
                "--no-gpg-sign" if value == "-S" else value for value in arguments
            )
        if "verify-commit" in arguments:
            return subprocess.CompletedProcess(arguments, 0, "", "")
        return original_run(arguments, **kwargs)

    with materialize_exact_checkout(
        _revision(ref="refs/heads/translation-review", sha=head_sha),
        remote_url=remote.as_uri(),
        allow_file_remote=True,
        _process_runner=signing_spy,
    ) as workspace:
        new_file = workspace.path / "i18n/messages_de.properties"
        new_file.write_text("hello=Hallo\n", encoding="utf-8")
        with pytest.raises(WorkspaceError, match="tracked file"):
            workspace.commit_historical_remediation_changes(
                expected_paths=("i18n/messages_de.properties",),
                feedback_repository="upstream/project",
                feedback_pull_numbers=(7,),
                feedback_urls=(
                    "https://github.example.com/upstream/project/pull/7#discussion_r123",
                ),
                evidence_hash="c" * 64,
            )

    with materialize_exact_checkout(
        _revision(ref="refs/heads/translation-review", sha=head_sha),
        remote_url=remote.as_uri(),
        allow_file_remote=True,
        _process_runner=signing_spy,
    ) as workspace:
        (workspace.path / "i18n/messages_ru.properties").write_text(
            "hello=Здравствуйте\n",
            encoding="utf-8",
        )
        with pytest.raises(ValueError, match="historical feedback URL"):
            workspace.commit_historical_remediation_changes(
                expected_paths=("i18n/messages_ru.properties",),
                feedback_repository="upstream/project",
                feedback_pull_numbers=(7,),
                feedback_urls=(
                    "https://github.example.com/upstream/project/pull/8#discussion_r123",
                ),
                evidence_hash="d" * 64,
            )


def test_open_and_historical_commits_reject_hardlinked_tracked_files(tmp_path):
    remote, _base_sha, head_sha = _create_remote(tmp_path)
    original_run = subprocess.run

    def signing_spy(args: Sequence[str], **kwargs):
        arguments = tuple(args)
        if "commit" in arguments and "-S" in arguments:
            arguments = tuple(
                "--no-gpg-sign" if value == "-S" else value for value in arguments
            )
        if "verify-commit" in arguments:
            return subprocess.CompletedProcess(arguments, 0, "", "")
        return original_run(arguments, **kwargs)

    with materialize_exact_checkout(
        _revision(ref="refs/heads/translation-review", sha=head_sha),
        remote_url=remote.as_uri(),
        allow_file_remote=True,
    ) as workspace:
        outside = tmp_path / "open-hardlink-source.properties"
        outside.write_text("hello=Здравствуйте\n", encoding="utf-8")
        target = workspace.path / "i18n/messages_ru.properties"
        target.unlink()
        os.link(outside, target)

        with pytest.raises(WorkspaceError, match="hard-linked"):
            workspace.commit_validated_changes(
                expected_paths=("i18n/messages_ru.properties",),
                pull_number=7,
                feedback_urls=(
                    "https://github.example.com/acme/project/pull/7#discussion_r123",
                ),
                sign=False,
            )

    with materialize_exact_checkout(
        _revision(ref="refs/heads/translation-review", sha=head_sha),
        remote_url=remote.as_uri(),
        allow_file_remote=True,
        _process_runner=signing_spy,
    ) as workspace:
        outside = tmp_path / "remediation-hardlink-source.properties"
        outside.write_text("hello=Здравствуйте\n", encoding="utf-8")
        target = workspace.path / "i18n/messages_ru.properties"
        target.unlink()
        os.link(outside, target)

        with pytest.raises(WorkspaceError, match="hard-linked"):
            workspace.commit_historical_remediation_changes(
                expected_paths=("i18n/messages_ru.properties",),
                feedback_repository="upstream/project",
                feedback_pull_numbers=(7,),
                feedback_urls=(
                    "https://github.example.com/upstream/project/pull/7#discussion_r123",
                ),
                evidence_hash="e" * 64,
            )


def test_remediation_publication_uses_remediation_specific_diagnostics(tmp_path):
    remote, _base_sha, head_sha = _create_remote(tmp_path)
    with materialize_exact_checkout(
        _revision(ref="refs/heads/translation-review", sha=head_sha),
        remote_url=remote.as_uri(),
        allow_file_remote=True,
    ) as workspace:
        unsigned = CommitResult(
            commit_sha=head_sha,
            parent_sha=head_sha,
            changed_paths=("i18n/messages_ru.properties",),
            signature_verified=False,
        )

        with pytest.raises(WorkspaceError, match="unsigned remediation commit") as error:
            workspace.publish_remediation_branch(
                unsigned,
                push_repository="acme/project",
                branch="guardian/remediation-candidate",
                branch_prefix="guardian/remediation-",
                credential_environment=lambda: {},
                before_push=lambda: None,
                remote_url=remote.as_uri(),
                allow_file_remote=True,
            )

        assert "prevention" not in str(error.value)


def test_prevention_commit_rejects_unexpected_staged_deleted_or_hardlinked_paths(
    tmp_path,
):
    remote, _base_sha, head_sha = _create_remote(tmp_path)
    with materialize_exact_checkout(
        _revision(ref="refs/heads/translation-review", sha=head_sha),
        remote_url=remote.as_uri(),
        allow_file_remote=True,
    ) as workspace:
        target = workspace.path / "README.md"
        target.unlink()
        with pytest.raises(WorkspaceError, match="missing"):
            workspace.commit_prevention_changes(
                expected_paths=("README.md",),
                evidence_hash="a" * 64,
            )

    with materialize_exact_checkout(
        _revision(ref="refs/heads/translation-review", sha=head_sha),
        remote_url=remote.as_uri(),
        allow_file_remote=True,
    ) as workspace:
        outside = tmp_path / "outside.py"
        outside.write_text("assert True\n", encoding="utf-8")
        linked = workspace.path / "tests.py"
        os.link(outside, linked)
        with pytest.raises(WorkspaceError, match="hard-linked"):
            workspace.commit_prevention_changes(
                expected_paths=("tests.py",),
                evidence_hash="a" * 64,
            )


def test_rejects_unexpected_or_pre_staged_changes_without_committing(tmp_path):
    remote, _base_sha, head_sha = _create_remote(tmp_path)

    with materialize_exact_checkout(
        _revision(ref="refs/heads/translation-review", sha=head_sha),
        remote_url=remote.as_uri(),
        allow_file_remote=True,
    ) as workspace:
        target = workspace.path / "i18n/messages_ru.properties"
        target.write_text("hello=Здравствуйте\n", encoding="utf-8")
        (workspace.path / "README.md").write_text("unexpected\n", encoding="utf-8")

        with pytest.raises(WorkspaceError, match="unexpected working-tree changes"):
            workspace.commit_validated_changes(
                expected_paths=("i18n/messages_ru.properties",),
                pull_number=7,
                feedback_urls=(
                    "https://github.example.com/acme/project/pull/7#discussion_r123",
                ),
                sign=False,
            )

        assert _git(workspace.path, "rev-parse", "HEAD") == head_sha
        assert _git(workspace.path, "diff", "--cached", "--name-only") == ""

        (workspace.path / "README.md").write_text("example\n", encoding="utf-8")
        _git(workspace.path, "add", "i18n/messages_ru.properties")
        with pytest.raises(WorkspaceError, match="pre-staged"):
            workspace.commit_validated_changes(
                expected_paths=("i18n/messages_ru.properties",),
                pull_number=7,
                feedback_urls=(
                    "https://github.example.com/acme/project/pull/7#discussion_r123",
                ),
                sign=False,
            )


@pytest.mark.parametrize(
    "path",
    [
        "../messages_ru.properties",
        "/tmp/messages_ru.properties",
        "i18n/../../messages_ru.properties",
        "i18n\\messages_ru.properties",
        ".git/config",
        "i18n/messages_ru.properties\nREADME.md",
    ],
)
def test_commit_rejects_hostile_paths(tmp_path, path):
    remote, _base_sha, head_sha = _create_remote(tmp_path)

    with materialize_exact_checkout(
        _revision(ref="refs/heads/translation-review", sha=head_sha),
        remote_url=remote.as_uri(),
        allow_file_remote=True,
    ) as workspace:
        with pytest.raises((ValueError, WorkspaceError)):
            workspace.commit_validated_changes(
                expected_paths=(path,),
                pull_number=7,
                feedback_urls=(
                    "https://github.example.com/acme/project/pull/7#discussion_r123",
                ),
                sign=False,
            )


def test_commit_rejects_symlinked_expected_file(tmp_path):
    remote, _base_sha, head_sha = _create_remote(tmp_path)

    with materialize_exact_checkout(
        _revision(ref="refs/heads/translation-review", sha=head_sha),
        remote_url=remote.as_uri(),
        allow_file_remote=True,
    ) as workspace:
        target = workspace.path / "i18n/messages_ru.properties"
        target.unlink()
        target.symlink_to(workspace.path / "README.md")

        with pytest.raises(WorkspaceError, match="symbolic link"):
            workspace.commit_validated_changes(
                expected_paths=("i18n/messages_ru.properties",),
                pull_number=7,
                feedback_urls=(
                    "https://github.example.com/acme/project/pull/7#discussion_r123",
                ),
                sign=False,
            )


@pytest.mark.parametrize(
    "feedback_url",
    [
        "https://github.example.com/acme/other/pull/7#discussion_r123",
        "https://github.example.com/acme/project/pull/8#discussion_r123",
        "https://github.example.com/acme/project/pull/7",
        "https://token@github.example.com/acme/project/pull/7#discussion_r123",
        "https://github.example.com/acme/project/pull/7?token=secret#discussion_r123",
        "https://evil.example/acme/project/pull/7#discussion_r123",
    ],
)
def test_commit_rejects_unbound_or_ambiguous_feedback_links(tmp_path, feedback_url):
    remote, _base_sha, head_sha = _create_remote(tmp_path)

    with materialize_exact_checkout(
        _revision(ref="refs/heads/translation-review", sha=head_sha),
        remote_url=remote.as_uri(),
        allow_file_remote=True,
    ) as workspace:
        (workspace.path / "i18n/messages_ru.properties").write_text(
            "hello=Здравствуйте\n",
            encoding="utf-8",
        )
        with pytest.raises(ValueError, match="feedback"):
            workspace.commit_validated_changes(
                expected_paths=("i18n/messages_ru.properties",),
                pull_number=7,
                feedback_urls=(feedback_url,),
                sign=False,
            )


def test_commit_refuses_when_checkout_head_no_longer_matches_intake_sha(tmp_path):
    remote, _base_sha, head_sha = _create_remote(tmp_path)

    with materialize_exact_checkout(
        _revision(ref="refs/heads/translation-review", sha=head_sha),
        remote_url=remote.as_uri(),
        allow_file_remote=True,
    ) as workspace:
        _git(workspace.path, "config", "user.name", "Attacker")
        _git(workspace.path, "config", "user.email", "attacker@example.com")
        _git(workspace.path, "config", "commit.gpgsign", "false")
        _git(workspace.path, "commit", "--allow-empty", "-m", "Move HEAD")
        (workspace.path / "i18n/messages_ru.properties").write_text(
            "hello=Здравствуйте\n",
            encoding="utf-8",
        )
        with pytest.raises(WorkspaceError, match="original exact SHA"):
            workspace.commit_validated_changes(
                expected_paths=("i18n/messages_ru.properties",),
                pull_number=7,
                feedback_urls=(
                    "https://github.example.com/acme/project/pull/7#discussion_r123",
                ),
                sign=False,
            )
