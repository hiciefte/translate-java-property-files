from __future__ import annotations

from contextlib import contextmanager
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
from typing import Iterator, Sequence

import httpx
import pytest

from localize.guardian import prevention_runtime
from localize.guardian import state as guardian_state
from localize.guardian.codex import (
    CodexAuthenticationError,
    CodexCapacityError,
    CodexOutputError,
    CodexTimeoutError,
    CodexUsage,
)
from localize.guardian.credentials import (
    CredentialError,
    CredentialSnapshot,
    SecretCommand,
)
from localize.guardian.deadline import PollDeadline, PollDeadlineExceeded
from localize.guardian.github import GitHubAuthenticationError
from localize.guardian.models import (
    AllowedHeadRepository,
    CodexAuthMode,
    ExactRepository,
    FeedbackEvent,
    GuardianMode,
    HistoricalCheckScope,
    PreventionPolicy,
    RecurrenceCandidate,
    RepositoryPolicy,
    TrustedActor,
)
from localize.guardian.prevention import (
    PreventionPolicyError,
    TestCommandResult,
    TestOutcome,
)
from localize.guardian.prevention_runtime import (
    PreventionAuthorResult,
    PreventionBaseSnapshot,
    PreventionCodexAuthor,
    PreventionCoordinator,
    PreventionDraftResult,
    PreventionGitHubBroker,
    PreventionRemoteConflictError,
    PreventionRuntimeError,
    PreventionSourceAuthorityError,
    SandboxedTestRunner,
)
from localize.guardian.remediation import RemediationSourceAuthorityError
from localize.guardian.state import (
    GuardianState,
    HistoricalPullReference,
    OpenPullAuthorityReference,
)
from localize.guardian.workspace import (
    CommitResult,
    ExactRevision,
    PreventionPublicationResult,
)


UTC = timezone.utc
BASE_SHA = "a" * 40
CANDIDATE_SHA = "b" * 40
TOKEN = "github-token-never-log"
PUBLICATION_ACTOR = TrustedActor("guardian-publisher", 301, "User")
OPEN_SOURCE_REVISION_ID = 1


class _FakeClock:
    def __init__(self) -> None:
        self.value = 0.0

    def __call__(self) -> float:
        return self.value

    def advance(self, seconds: float) -> None:
        self.value += seconds


class _TickingClock(_FakeClock):
    def __init__(self, step: float) -> None:
        super().__init__()
        self.step = step

    def __call__(self) -> float:
        current = self.value
        self.value += self.step
        return current


def _authenticated_actor_payload(
    *,
    actor_id: int = PUBLICATION_ACTOR.id,
    actor_type: str = PUBLICATION_ACTOR.type,
    login: str = PUBLICATION_ACTOR.login,
) -> dict[str, object]:
    return {"id": actor_id, "type": actor_type, "login": login}


def _live_lease() -> None:
    return None


def _current_base() -> None:
    return None


def _open_source() -> OpenPullAuthorityReference:
    return OpenPullAuthorityReference(
        repository="acme/translations",
        repository_id=42,
        pull_id=500,
        pr_number=12,
        authority_digest="4" * 64,
        head_sha="c" * 40,
        base_sha="d" * 40,
    )


def _open_source_authority(
    _source: OpenPullAuthorityReference,
    _revision_ids: Sequence[int],
) -> None:
    return None


def _seed_open_source_event(state: GuardianState) -> int:
    source = _open_source()
    revision = state.record_feedback_event(
        FeedbackEvent(
            repository=source.repository,
            pr_number=source.pr_number,
            kind="review_comment",
            event_id="42",
            author="coderabbitai[bot]",
            author_id=202,
            author_type="Bot",
            body="Prevent this placeholder regression.",
            head_sha=source.head_sha,
            base_sha=source.base_sha,
            locale="ru",
            updated_at="2026-08-30T08:00:00Z",
            path="l10n/messages_ru.properties",
            line=17,
            html_url=("https://github.test/acme/translations/pull/12#discussion_r42"),
        ),
        observed_at=datetime(2026, 8, 30, 8, 0, tzinfo=UTC),
    )
    return revision.revision_id


def _open_source_kwargs() -> dict[str, object]:
    return {
        "open_source": _open_source(),
        "source_event_revision_ids": (OPEN_SOURCE_REVISION_ID,),
        "require_exact_open_source_authority": _open_source_authority,
    }


@pytest.fixture
def stub_network_canaries(monkeypatch: pytest.MonkeyPatch) -> None:
    @contextmanager
    def canaries() -> Iterator[tuple[str, int, str]]:
        yield "127.0.0.1", 43210, "/private/guardian-canary.sock"

    monkeypatch.setattr(prevention_runtime, "_network_canaries", canaries)


def _prevention_policy(
    *,
    private_target_opt_in: bool = False,
    target_repository: ExactRepository | None = None,
    push_repository: ExactRepository | None = None,
) -> PreventionPolicy:
    return PreventionPolicy(
        target_repository=target_repository
        or ExactRepository(full_name="guardian/pipeline", id=101),
        target_base_branch="main",
        push_repository=push_repository
        or ExactRepository(full_name="guardian/pipeline", id=101),
        push_branch_prefix="guardian/prevention-",
        publication_actor=PUBLICATION_ACTOR,
        allowed_code_path_globs=("localize/*.py",),
        allowed_test_path_globs=("tests/**/*.py",),
        focused_test_argv=(
            ("/opt/localize-guardian/bin/pytest", "tests/unit/test_rules.py", "-q"),
        ),
        sandbox_argv_prefix=("/usr/bin/guardian-sandbox-wrapper",),
        max_changed_files=4,
        max_changed_bytes=16_384,
        private_target_model_opt_in=private_target_opt_in,
    )


def test_prevention_broker_accepts_exactly_one_shared_credential_source() -> None:
    credential = CredentialSnapshot(SecretCommand(("credential-helper",)))

    broker = PreventionGitHubBroker(
        policy=_prevention_policy(),
        credential=credential,
    )

    assert broker._token is credential  # noqa: SLF001
    with pytest.raises(ValueError, match="exactly one"):
        PreventionGitHubBroker(policy=_prevention_policy())
    with pytest.raises(ValueError, match="exactly one"):
        PreventionGitHubBroker(
            policy=_prevention_policy(),
            token_command=("credential-helper",),
            credential=credential,
        )


def test_prevention_broker_bounds_github_response_bytes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/user"
        return httpx.Response(
            200,
            request=request,
            content=b'{"login":"guardian-bot"}',
        )

    monkeypatch.setattr(prevention_runtime, "_MAX_GITHUB_RESPONSE_BYTES", 16)
    monkeypatch.setattr(prevention_runtime.SecretCommand, "read", lambda _self: TOKEN)
    broker = PreventionGitHubBroker(
        policy=_prevention_policy(),
        token_command=("credential-helper",),
        base_url="https://api.github.test",
        transport=httpx.MockTransport(handler),
    )

    with pytest.raises(PreventionRuntimeError, match="byte limit"):
        broker.capture_base()


def test_prevention_broker_normalizes_recursive_json_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    deeply_nested = b"[" * 1200 + b"0" + b"]" * 1200

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/user"
        return httpx.Response(200, request=request, content=deeply_nested)

    monkeypatch.setattr(prevention_runtime.SecretCommand, "read", lambda _self: TOKEN)
    broker = PreventionGitHubBroker(
        policy=_prevention_policy(),
        token_command=("credential-helper",),
        base_url="https://api.github.test",
        transport=httpx.MockTransport(handler),
    )

    with pytest.raises(PreventionRuntimeError, match="invalid JSON"):
        broker.capture_base()


@pytest.mark.parametrize(
    "authenticated_actor",
    [
        _authenticated_actor_payload(actor_id=999),
        _authenticated_actor_payload(actor_type="Bot"),
    ],
    ids=("numeric-id", "type"),
)
def test_prevention_broker_binds_credential_to_publication_actor(
    authenticated_actor: dict[str, object],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/user":
            return _response(request, authenticated_actor)
        raise AssertionError("repository authority must not be read for a wrong actor")

    monkeypatch.setattr(prevention_runtime.SecretCommand, "read", lambda _self: TOKEN)
    broker = PreventionGitHubBroker(
        policy=_prevention_policy(),
        token_command=("credential-helper",),
        base_url="https://api.github.test",
        transport=httpx.MockTransport(handler),
    )

    with pytest.raises(GitHubAuthenticationError, match="actor.*policy"):
        broker.capture_base()


def test_prevention_broker_does_not_treat_mutable_actor_login_as_authority(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/user":
            return _response(
                request,
                _authenticated_actor_payload(login="renamed-guardian-bot"),
            )
        if request.url.path == "/repos/guardian/pipeline":
            return _response(request, _repo_payload())
        if request.url.path == "/repos/guardian/pipeline/branches/main":
            return _response(request, _branch_payload("main", BASE_SHA))
        raise AssertionError(request.url.path)

    monkeypatch.setattr(prevention_runtime.SecretCommand, "read", lambda _self: TOKEN)
    broker = PreventionGitHubBroker(
        policy=_prevention_policy(),
        token_command=("credential-helper",),
        base_url="https://api.github.test",
        transport=httpx.MockTransport(handler),
    )

    assert broker.capture_base().revision.sha == BASE_SHA


@pytest.mark.parametrize(
    ("target_private", "push_payload", "message"),
    [
        (
            False,
            {
                "id": 202,
                "full_name": "guardian-fork/pipeline",
                "private": False,
                "fork": False,
                "parent": None,
                "source": None,
            },
            "outside the target repository fork network",
        ),
        (
            True,
            {
                "id": 202,
                "full_name": "guardian-fork/pipeline",
                "private": False,
                "fork": True,
                "parent": {"id": 101},
                "source": {"id": 101, "fork": False},
            },
            "private repository content to a public",
        ),
    ],
)
def test_prevention_broker_rejects_unsafe_cross_repository_publication(
    target_private: bool,
    push_payload: dict[str, object],
    message: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = {**_repo_payload(), "private": target_private}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/user":
            return _response(request, _authenticated_actor_payload())
        if request.url.path == "/repos/guardian/pipeline":
            return _response(request, target)
        if request.url.path == "/repos/guardian-fork/pipeline":
            return _response(request, push_payload)
        raise AssertionError(request.url.path)

    monkeypatch.setattr(prevention_runtime.SecretCommand, "read", lambda _self: TOKEN)
    broker = PreventionGitHubBroker(
        policy=_prevention_policy(
            push_repository=ExactRepository(
                full_name="guardian-fork/pipeline",
                id=202,
            )
        ),
        token_command=("credential-helper",),
        base_url="https://api.github.test",
        transport=httpx.MockTransport(handler),
    )

    with pytest.raises(PreventionRuntimeError, match=message):
        broker.capture_base()


def test_prevention_broker_accepts_a_push_fork_in_the_same_network(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    push_payload = {
        "id": 202,
        "full_name": "guardian-fork/pipeline",
        "private": False,
        "fork": True,
        "parent": {"id": 101},
        "source": {"id": 101, "fork": False},
    }

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/user":
            return _response(request, _authenticated_actor_payload())
        if request.url.path == "/repos/guardian/pipeline":
            return _response(request, _repo_payload())
        if request.url.path == "/repos/guardian-fork/pipeline":
            return _response(request, push_payload)
        if request.url.path == "/repos/guardian/pipeline/branches/main":
            return _response(request, _branch_payload("main", BASE_SHA))
        raise AssertionError(request.url.path)

    monkeypatch.setattr(prevention_runtime.SecretCommand, "read", lambda _self: TOKEN)
    broker = PreventionGitHubBroker(
        policy=_prevention_policy(
            push_repository=ExactRepository(
                full_name="guardian-fork/pipeline",
                id=202,
            )
        ),
        token_command=("credential-helper",),
        base_url="https://api.github.test",
        transport=httpx.MockTransport(handler),
    )

    base = broker.capture_base()

    assert base.target_repository_id == 101
    assert base.push_repository_id == 202


def _repository_policy(
    *,
    private_opt_in: bool = False,
    private_target_opt_in: bool = False,
) -> RepositoryPolicy:
    actor = TrustedActor(login="translation-bot", id=7, type="User")
    owner = TrustedActor(login="translation-bot", id=8, type="Organization")
    return RepositoryPolicy(
        base_repo="acme/translations",
        base_repo_id=42,
        base_branch="main",
        allowed_pr_authors=(actor,),
        allowed_head_owners=(owner,),
        allowed_head_repositories=(
            AllowedHeadRepository(full_name="translation-bot/translations", id=84),
        ),
        allowed_branch_globs=("translation-*",),
        allowed_path_globs=("l10n/*.properties",),
        pipeline_config_path="config.yaml",
        source_locale="en",
        trusted_reviewers={"ru": (TrustedActor("reviewer", 9, "User"),)},
        trusted_bots={},
        publication_actor=PUBLICATION_ACTOR,
        private_repo_model_opt_in=private_opt_in,
        prevention=_prevention_policy(private_target_opt_in=private_target_opt_in),
    )


def _base_revision() -> ExactRevision:
    return ExactRevision(
        host="github.com",
        owner="guardian",
        repository="pipeline",
        ref="refs/heads/main",
        sha=BASE_SHA,
    )


def _repo_payload() -> dict[str, object]:
    return {
        "id": 101,
        "full_name": "guardian/pipeline",
        "private": False,
        "fork": False,
        "parent": None,
        "source": None,
    }


def _branch_payload(name: str, sha: str) -> dict[str, object]:
    return {"name": name, "commit": {"sha": sha}}


def _pull_payload(
    *,
    number: int,
    branch: str,
    body: str,
    draft: bool,
    title: str = "Prevent recurrence: placeholder parity",
    state: str = "open",
    merged_at: str | None = None,
    closed_at: str | None = None,
    actor_id: int = PUBLICATION_ACTOR.id,
    actor_type: str = PUBLICATION_ACTOR.type,
    maintainer_can_modify: bool = False,
    html_url: str | None = None,
) -> dict[str, object]:
    return {
        "number": number,
        "html_url": html_url or f"https://github.com/guardian/pipeline/pull/{number}",
        "title": title,
        "body": body,
        "state": state,
        "draft": draft,
        "merged_at": merged_at,
        "closed_at": closed_at,
        "maintainer_can_modify": maintainer_can_modify,
        "user": {
            "id": actor_id,
            "type": actor_type,
            "login": PUBLICATION_ACTOR.login,
        },
        "head": {
            "sha": CANDIDATE_SHA,
            "ref": branch,
            "repo": {"id": 101, "full_name": "guardian/pipeline"},
        },
        "base": {
            "sha": BASE_SHA,
            "ref": "main",
            "repo": {"id": 101, "full_name": "guardian/pipeline"},
        },
    }


def _issue_event(event_id: int, event: str) -> dict[str, object]:
    return {
        "id": event_id,
        "event": event,
        "actor": _authenticated_actor_payload(),
    }


def _response(
    request: httpx.Request, payload: object, status: int = 200
) -> httpx.Response:
    return httpx.Response(status, request=request, json=payload)


def _recovery_broker(
    monkeypatch: pytest.MonkeyPatch,
    *,
    branch: str,
    exact_pull: dict[str, object],
    event_pages: dict[int, list[object]] | None = None,
    listed_pull: dict[str, object] | None = None,
) -> PreventionGitHubBroker:
    pull_number = int((listed_pull or exact_pull)["number"])
    event_pages = event_pages or {1: []}

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/user":
            return _response(request, _authenticated_actor_payload())
        if path == "/repos/guardian/pipeline":
            return _response(request, _repo_payload())
        if path == "/repos/guardian/pipeline/branches/main":
            return _response(request, _branch_payload("main", BASE_SHA))
        if path == f"/repos/guardian/pipeline/branches/{branch}":
            return _response(request, _branch_payload(branch, CANDIDATE_SHA))
        if path == "/repos/guardian/pipeline/pulls":
            return _response(request, [listed_pull or exact_pull])
        if path == f"/repos/guardian/pipeline/pulls/{pull_number}":
            return _response(request, exact_pull)
        if path == f"/repos/guardian/pipeline/issues/{pull_number}/events":
            page = int(request.url.params.get("page", "1"))
            return _response(request, event_pages.get(page, []))
        raise AssertionError(f"unexpected {request.method} {request.url}")

    monkeypatch.setattr(prevention_runtime.SecretCommand, "read", lambda _self: TOKEN)
    return PreventionGitHubBroker(
        policy=_prevention_policy(),
        token_command=("credential-helper",),
        base_url="https://api.github.test",
        transport=httpx.MockTransport(handler),
    )


def test_prevention_author_uses_workspace_write_stdin_and_scrubs_write_credentials(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    observed: dict[str, object] = {}

    def fake_run(argv, **kwargs):
        observed["argv"] = list(argv)
        observed["kwargs"] = kwargs
        observed["launch_environment"] = dict(kwargs["env"])
        return subprocess.CompletedProcess(
            argv,
            0,
            stdout=json.dumps(
                {
                    "type": "turn.completed",
                    "usage": {"input_tokens": 12, "output_tokens": 3},
                    "cost_usd": 0.02,
                }
            ),
            stderr="",
        )

    monkeypatch.setattr(prevention_runtime, "run_bounded_process", fake_run)
    monkeypatch.setenv("GITHUB_TOKEN", "forbidden-github")
    monkeypatch.setenv("GH_TOKEN", "forbidden-gh")
    monkeypatch.setenv("GIT_ASKPASS", "/forbidden/askpass")
    monkeypatch.setenv("GNUPGHOME", "/forbidden/gnupg")
    monkeypatch.setenv("OPENAI_API_KEY", "inherited-model-key")
    author = PreventionCodexAuthor(
        model="gpt-5.6-sol",
        reasoning_effort="max",
        auth_mode=CodexAuthMode.API_KEY,
        timeout_seconds=17,
    )
    result = author.run(
        workspace=workspace,
        scope="pipeline_code",
        summary="Preserve indexed placeholders in the validator",
        evidence_feedback_ids=("review_comment:42:revision-7",),
        policy=_prevention_policy(),
        api_key="explicit-model-key",
    )

    argv = observed["argv"]
    assert isinstance(argv, list)
    assert "--sandbox" not in argv
    assert argv[1:3] == ["--ask-for-approval", "never"]
    assert 'default_permissions="guardian_prevention_author"' in argv
    assert (
        'permissions.guardian_prevention_author.filesystem={":minimal"="read",'
        '":workspace_roots"={"."="write"}}'
    ) in argv
    assert "--ignore-rules" in argv
    assert "--ignore-user-config" in argv
    assert argv[-1] == "-"
    kwargs = observed["kwargs"]
    assert kwargs["shell"] is False
    assert kwargs["input"].startswith("You are preparing")
    assert "Preserve indexed placeholders" in kwargs["input"]
    assert "Preserve indexed placeholders" not in argv
    assert kwargs["timeout"] == 17
    assert kwargs["limits"].require_linux_cgroup is True
    assert kwargs["limits"].max_file_size_bytes == 128 * 1024 * 1024
    launch_environment = observed["launch_environment"]
    assert isinstance(launch_environment, dict)
    assert launch_environment["CODEX_API_KEY"] == "explicit-model-key"
    assert "OPENAI_API_KEY" not in launch_environment
    assert "CODEX_API_KEY" not in kwargs["env"]
    for forbidden in (
        "GITHUB_TOKEN",
        "GH_TOKEN",
        "GIT_ASKPASS",
        "GNUPGHOME",
        "SSH_AUTH_SOCK",
    ):
        assert forbidden not in kwargs["env"]
    assert result.usage == CodexUsage(input_tokens=12, output_tokens=3, cost_usd=0.02)


def test_prevention_author_opens_auth_circuit_without_echoing_secret(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    def fake_run(argv, **_kwargs):
        return subprocess.CompletedProcess(
            argv,
            1,
            stdout="",
            stderr="401 Unauthorized explicit-secret-value",
        )

    monkeypatch.setattr(prevention_runtime, "run_bounded_process", fake_run)
    with pytest.raises(CodexAuthenticationError) as failure:
        PreventionCodexAuthor(
            model="gpt-5.6-sol",
            reasoning_effort="max",
            auth_mode=CodexAuthMode.API_KEY,
        ).run(
            workspace=workspace,
            scope="pipeline_code",
            summary="Regression",
            evidence_feedback_ids=("review:1:revision-1",),
            policy=_prevention_policy(),
            api_key="explicit-secret-value",
        )
    assert "explicit-secret-value" not in str(failure.value)


def test_prevention_author_rejects_and_clears_secret_from_success_diagnostics(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    secret = "sk-guardian-diagnostic-regression-secret"
    child_environment: dict[str, str] = {}

    def fake_run(argv, **kwargs):
        child_environment.update(kwargs["env"])
        # Keep the exact mapping so the assertion also proves the caller clears it.
        observed_mapping.append(kwargs["env"])
        return subprocess.CompletedProcess(
            argv,
            0,
            stdout=f"diagnostic accidentally repeated {secret}",
            stderr="",
        )

    observed_mapping: list[dict[str, str]] = []
    monkeypatch.setattr(prevention_runtime, "run_bounded_process", fake_run)

    with pytest.raises(CodexOutputError) as failure:
        PreventionCodexAuthor(
            model="gpt-5.6-sol",
            reasoning_effort="max",
            auth_mode=CodexAuthMode.API_KEY,
        ).run(
            workspace=workspace,
            scope="pipeline_code",
            summary="Regression",
            evidence_feedback_ids=("review:1:revision-1",),
            policy=_prevention_policy(),
            api_key=secret,
        )

    assert str(failure.value) == (
        "Prevention Codex output failed credential safety validation."
    )
    assert secret not in str(failure.value)
    assert child_environment["CODEX_API_KEY"] == secret
    assert "CODEX_API_KEY" not in observed_mapping[0]


def test_candidate_credential_scan_redacts_model_authored_filename(
    tmp_path: Path,
) -> None:
    secret = "sk-guardian-filename-regression-secret"
    base = tmp_path / "base"
    candidate = tmp_path / "candidate"
    (base / "localize").mkdir(parents=True)
    (candidate / "localize").mkdir(parents=True)
    (candidate / "localize" / f"diagnostic-{secret}.py").write_text(
        "SAFE = True\n",
        encoding="utf-8",
    )

    with pytest.raises(PreventionRuntimeError) as failure:
        prevention_runtime._reject_model_credential_in_candidate_delta(  # noqa: SLF001
            base_workspace=base,
            candidate_workspace=candidate,
            credential=secret,
            deadline=None,
        )

    assert str(failure.value) == (
        "Prevention candidate failed credential safety validation."
    )
    assert secret not in str(failure.value)


def test_prevention_author_never_inherits_a_host_model_credential(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    observed_environment: dict[str, str] = {}

    def fake_run(argv, **kwargs):
        observed_environment.update(kwargs["env"])
        return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

    monkeypatch.setattr(prevention_runtime, "run_bounded_process", fake_run)
    monkeypatch.setenv("CODEX_API_KEY", "inherited-codex-key")
    monkeypatch.setenv("OPENAI_API_KEY", "inherited-openai-key")
    codex_home = tmp_path / "codex-home"
    codex_home.mkdir(mode=0o700)

    PreventionCodexAuthor(
        model="gpt-5.6-sol",
        reasoning_effort="max",
        auth_mode=CodexAuthMode.CHATGPT,
        codex_home=codex_home,
    ).run(
        workspace=workspace,
        scope="pipeline_code",
        summary="Regression",
        evidence_feedback_ids=("review:1:revision-1",),
        policy=_prevention_policy(),
        api_key=None,
    )

    assert "CODEX_API_KEY" not in observed_environment
    assert "OPENAI_API_KEY" not in observed_environment
    assert observed_environment["CODEX_HOME"] == str(codex_home.resolve())


def test_prevention_author_clamps_process_to_remaining_poll_deadline(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    clock = _FakeClock()
    deadline = PollDeadline(20, clock=clock)
    clock.advance(7)
    observed_timeout: list[float] = []

    def fake_run(argv, **kwargs):
        observed_timeout.append(kwargs["timeout"])
        return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

    monkeypatch.setattr(prevention_runtime, "run_bounded_process", fake_run)
    PreventionCodexAuthor(
        model="gpt-5.6-sol",
        reasoning_effort="max",
        auth_mode=CodexAuthMode.API_KEY,
        timeout_seconds=17,
        deadline=deadline,
    ).run(
        workspace=workspace,
        scope="pipeline_code",
        summary="Regression",
        evidence_feedback_ids=("review:1:revision-1",),
        policy=_prevention_policy(),
        api_key="explicit-model-key",
    )

    assert observed_timeout == [13.0]


def test_prevention_author_never_starts_after_poll_deadline(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    clock = _FakeClock()
    deadline = PollDeadline(1, clock=clock)
    clock.advance(2)
    started = False

    def fake_run(argv, **kwargs):
        nonlocal started
        started = True
        return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

    monkeypatch.setattr(prevention_runtime, "run_bounded_process", fake_run)
    author = PreventionCodexAuthor(
        model="gpt-5.6-sol",
        reasoning_effort="max",
        auth_mode=CodexAuthMode.API_KEY,
        deadline=deadline,
    )

    with pytest.raises(PollDeadlineExceeded):
        author.run(
            workspace=workspace,
            scope="pipeline_code",
            summary="Regression",
            evidence_feedback_ids=("review:1:revision-1",),
            policy=_prevention_policy(),
            api_key="explicit-model-key",
        )
    assert started is False


def test_prevention_author_preserves_shorter_operation_timeout(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    clock = _FakeClock()

    def fake_run(argv, **_kwargs):
        raise subprocess.TimeoutExpired(argv, 5)

    monkeypatch.setattr(prevention_runtime, "run_bounded_process", fake_run)
    author = PreventionCodexAuthor(
        model="gpt-5.6-sol",
        reasoning_effort="max",
        auth_mode=CodexAuthMode.API_KEY,
        timeout_seconds=5,
        deadline=PollDeadline(20, clock=clock),
    )

    with pytest.raises(CodexTimeoutError):
        author.run(
            workspace=workspace,
            scope="pipeline_code",
            summary="Regression",
            evidence_feedback_ids=("review:1:revision-1",),
            policy=_prevention_policy(),
            api_key="explicit-model-key",
        )


def test_prevention_author_surfaces_deadline_when_clamped_process_times_out(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    clock = _FakeClock()

    def fake_run(argv, **_kwargs):
        raise subprocess.TimeoutExpired(argv, 5)

    monkeypatch.setattr(prevention_runtime, "run_bounded_process", fake_run)
    author = PreventionCodexAuthor(
        model="gpt-5.6-sol",
        reasoning_effort="max",
        auth_mode=CodexAuthMode.API_KEY,
        timeout_seconds=30,
        deadline=PollDeadline(5, clock=clock),
    )

    with pytest.raises(PollDeadlineExceeded):
        author.run(
            workspace=workspace,
            scope="pipeline_code",
            summary="Regression",
            evidence_feedback_ids=("review:1:revision-1",),
            policy=_prevention_policy(),
            api_key="explicit-model-key",
        )


@pytest.mark.parametrize("timeout_call", [1, 2])
def test_sandboxed_runner_promotes_deadline_bound_process_timeouts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    stub_network_canaries: None,
    timeout_call: int,
) -> None:
    base = tmp_path / "base"
    candidate = tmp_path / "candidate"
    base.mkdir()
    candidate.mkdir()
    calls = 0

    def fake_run(argv, **kwargs):
        nonlocal calls
        calls += 1
        if calls == timeout_call:
            raise subprocess.TimeoutExpired(argv, kwargs["timeout"])
        return subprocess.CompletedProcess(argv, 0)

    monkeypatch.setattr(prevention_runtime, "run_bounded_process", fake_run)
    monkeypatch.setattr(
        prevention_runtime,
        "linux_cgroup_parent_procs",
        lambda: None,
    )
    runner = SandboxedTestRunner(
        timeout_seconds=30,
        deadline=PollDeadline(5, clock=lambda: 10.0),
    )

    with pytest.raises(PollDeadlineExceeded):
        runner.run_pair(
            base_workspace=base,
            candidate_workspace=candidate,
            policy=_prevention_policy(),
            base_sha=BASE_SHA,
            candidate_sha=CANDIDATE_SHA,
            test_overlay_hash="c" * 64,
        )

    assert calls == timeout_call


def test_sandboxed_runner_uses_identical_configured_argv_and_minimal_environment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    stub_network_canaries: None,
) -> None:
    base = tmp_path / "base"
    candidate = tmp_path / "candidate"
    base.mkdir()
    candidate.mkdir()
    calls: list[tuple[list[str], dict[str, object]]] = []
    returncodes = iter((0, 1, 0, 0))

    def fake_run(argv, **kwargs):
        calls.append((list(argv), kwargs))
        return subprocess.CompletedProcess(argv, next(returncodes))

    monkeypatch.setattr(prevention_runtime, "run_bounded_process", fake_run)
    cgroup_parent_procs = Path("/sys/fs/cgroup/guardian/cgroup.procs")
    monkeypatch.setattr(
        prevention_runtime,
        "linux_cgroup_parent_procs",
        lambda: cgroup_parent_procs,
    )
    monkeypatch.setenv("GITHUB_TOKEN", "forbidden")
    monkeypatch.setenv("OPENAI_API_KEY", "forbidden")
    monkeypatch.setenv("SSH_AUTH_SOCK", "/private/forbidden-agent.sock")
    results = SandboxedTestRunner(timeout_seconds=23).run_pair(
        base_workspace=base,
        candidate_workspace=candidate,
        policy=_prevention_policy(),
        base_sha=BASE_SHA,
        candidate_sha=CANDIDATE_SHA,
        test_overlay_hash="c" * 64,
    )

    expected = [
        "/usr/bin/guardian-sandbox-wrapper",
        "/opt/localize-guardian/bin/pytest",
        "tests/unit/test_rules.py",
        "-q",
    ]
    sandbox_prefix = list(_prevention_policy().sandbox_argv_prefix)
    prefix_length = len(sandbox_prefix)
    assert [calls[1][0], calls[3][0]] == [expected, expected]
    assert calls[0][0][:prefix_length] == sandbox_prefix
    assert calls[2][0][:prefix_length] == sandbox_prefix
    assert calls[0][0][-1] == str(cgroup_parent_procs)
    assert calls[2][0][-1] == str(cgroup_parent_procs)
    assert "-I" in calls[0][0]
    assert "-c" in calls[0][0]
    assert [calls[1][1]["cwd"], calls[3][1]["cwd"]] == [base, candidate]
    for _argv, kwargs in calls:
        assert kwargs["shell"] is False
        assert kwargs["stdin"] is subprocess.DEVNULL
        assert kwargs["stdout"] is subprocess.DEVNULL
        assert kwargs["stderr"] is subprocess.DEVNULL
        assert kwargs["timeout"] == 23
        assert kwargs["limits"].require_linux_cgroup is True
        assert "GITHUB_TOKEN" not in kwargs["env"]
        assert "OPENAI_API_KEY" not in kwargs["env"]
        assert "SSH_AUTH_SOCK" not in kwargs["env"]
    assert [result.outcome for result in results] == [
        TestOutcome.FAILED,
        TestOutcome.PASSED,
    ]
    assert results[0].argv == results[1].argv
    assert results[0].test_overlay_hash == results[1].test_overlay_hash


def test_sandboxed_runner_reclamps_every_process_to_remaining_deadline(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    stub_network_canaries: None,
) -> None:
    base = tmp_path / "base"
    candidate = tmp_path / "candidate"
    base.mkdir()
    candidate.mkdir()
    clock = _FakeClock()
    observed_timeouts: list[float] = []

    def fake_run(argv, **kwargs):
        observed_timeouts.append(kwargs["timeout"])
        clock.advance(2)
        return subprocess.CompletedProcess(
            argv,
            1 if len(observed_timeouts) == 2 else 0,
        )

    monkeypatch.setattr(prevention_runtime, "run_bounded_process", fake_run)
    monkeypatch.setattr(
        prevention_runtime,
        "linux_cgroup_parent_procs",
        lambda: None,
    )
    runner = SandboxedTestRunner(
        timeout_seconds=30,
        deadline=PollDeadline(10, clock=clock),
    )

    runner.run_pair(
        base_workspace=base,
        candidate_workspace=candidate,
        policy=_prevention_policy(),
        base_sha=BASE_SHA,
        candidate_sha=CANDIDATE_SHA,
        test_overlay_hash="c" * 64,
    )

    assert observed_timeouts == [10.0, 8.0, 6.0, 4.0]


def test_sandboxed_runner_never_starts_after_poll_deadline(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    stub_network_canaries: None,
) -> None:
    base = tmp_path / "base"
    candidate = tmp_path / "candidate"
    base.mkdir()
    candidate.mkdir()
    clock = _FakeClock()
    deadline = PollDeadline(1, clock=clock)
    clock.advance(2)
    started = False

    def fake_run(argv, **kwargs):
        nonlocal started
        started = True
        return subprocess.CompletedProcess(argv, 0)

    monkeypatch.setattr(prevention_runtime, "run_bounded_process", fake_run)
    runner = SandboxedTestRunner(timeout_seconds=10, deadline=deadline)

    with pytest.raises(PollDeadlineExceeded):
        runner.run_pair(
            base_workspace=base,
            candidate_workspace=candidate,
            policy=_prevention_policy(),
            base_sha=BASE_SHA,
            candidate_sha=CANDIDATE_SHA,
            test_overlay_hash="c" * 64,
        )
    assert started is False


def test_snapshot_copy_checks_deadline_between_files(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    for index in range(5):
        (source / f"file-{index}").write_bytes(b"payload")
    deadline = PollDeadline(1, clock=_TickingClock(0.2))

    with pytest.raises(PollDeadlineExceeded):
        prevention_runtime._snapshot_repository(  # noqa: SLF001
            source,
            tmp_path / "destination",
            deadline=deadline,
        )


def test_snapshot_copy_enforces_total_entry_bound(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "first").write_bytes(b"one")
    (source / "second").write_bytes(b"two")
    monkeypatch.setattr(prevention_runtime, "_MAX_SNAPSHOT_ENTRIES", 1)

    with pytest.raises(PreventionRuntimeError, match="entry or byte bound"):
        prevention_runtime._snapshot_repository(  # noqa: SLF001
            source,
            tmp_path / "destination",
        )


@pytest.mark.parametrize("returncodes", [(0, 0), (2, 0), (1, 1)])
def test_sandboxed_runner_rejects_false_regression_proofs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    returncodes: tuple[int, int],
    stub_network_canaries: None,
) -> None:
    base = tmp_path / "base"
    candidate = tmp_path / "candidate"
    base.mkdir()
    candidate.mkdir()
    codes = iter((0, returncodes[0], 0, returncodes[1]))
    monkeypatch.setattr(
        prevention_runtime,
        "run_bounded_process",
        lambda argv, **_kwargs: subprocess.CompletedProcess(argv, next(codes)),
    )
    with pytest.raises(
        prevention_runtime.PreventionPolicyError, match="every configured"
    ):
        SandboxedTestRunner(timeout_seconds=10).run_pair(
            base_workspace=base,
            candidate_workspace=candidate,
            policy=_prevention_policy(),
            base_sha=BASE_SHA,
            candidate_sha=CANDIDATE_SHA,
            test_overlay_hash="c" * 64,
        )


def test_sandboxed_runner_rejects_prefix_that_fails_confinement_probe(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    stub_network_canaries: None,
) -> None:
    base = tmp_path / "base"
    candidate = tmp_path / "candidate"
    base.mkdir()
    candidate.mkdir()
    calls = 0

    def fake_run(argv, **_kwargs):
        nonlocal calls
        calls += 1
        return subprocess.CompletedProcess(argv, 1)

    monkeypatch.setattr(prevention_runtime, "run_bounded_process", fake_run)

    with pytest.raises(
        prevention_runtime.PreventionPolicyError,
        match="confinement probe",
    ):
        SandboxedTestRunner(timeout_seconds=10).run_pair(
            base_workspace=base,
            candidate_workspace=candidate,
            policy=_prevention_policy(),
            base_sha=BASE_SHA,
            candidate_sha=CANDIDATE_SHA,
            test_overlay_hash="c" * 64,
        )

    assert calls == 1


@pytest.mark.parametrize(
    ("field_name", "unsafe_value"),
    [
        (
            "focused_test_argv",
            (("venv/bin/pytest", "tests/unit/test_rules.py"),),
        ),
        (
            "sandbox_argv_prefix",
            ("sandbox-wrapper",),
        ),
    ],
)
def test_sandboxed_runner_rejects_non_absolute_executables_before_execution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    field_name: str,
    unsafe_value: tuple[object, ...],
) -> None:
    policy = _prevention_policy()
    # Exercise the runner's defense in depth even though normal typed construction
    # now rejects this malformed authority before it reaches the runner.
    object.__setattr__(policy, field_name, unsafe_value)
    base = tmp_path / "base"
    candidate = tmp_path / "candidate"
    base.mkdir()
    candidate.mkdir()
    subprocess_calls = 0

    def fake_run(*_args, **_kwargs):
        nonlocal subprocess_calls
        subprocess_calls += 1
        raise AssertionError("an unsafe executable must never run")

    monkeypatch.setattr(prevention_runtime, "run_bounded_process", fake_run)

    with pytest.raises(prevention_runtime.PreventionPolicyError, match="absolute"):
        SandboxedTestRunner(timeout_seconds=10).run_pair(
            base_workspace=base,
            candidate_workspace=candidate,
            policy=policy,
            base_sha=BASE_SHA,
            candidate_sha=CANDIDATE_SHA,
            test_overlay_hash="c" * 64,
        )

    assert subprocess_calls == 0


def test_sandboxed_runner_rejects_prefix_that_allows_outbound_connect(
    tmp_path: Path,
    stub_network_canaries: None,
) -> None:
    base = tmp_path / "base"
    candidate = tmp_path / "candidate"
    base.mkdir()
    candidate.mkdir()
    wrapper = tmp_path / "deny-bind-only"
    wrapper.write_text(
        f"#!{sys.executable}\n"
        + """
import pathlib
import socket
import sys

command = sys.argv[1:]
if len(command) < 4 or command[1:3] != ["-I", "-c"]:
    raise SystemExit(97)

def deny_bytes(*_args, **_kwargs):
    raise PermissionError("outside filesystem access denied")

pathlib.Path.read_bytes = deny_bytes
pathlib.Path.write_bytes = deny_bytes

real_socket = socket.socket

class DenyBindSocket:
    def __init__(self, *args, **kwargs):
        self._socket = real_socket(*args, **kwargs)

    def bind(self, *_args, **_kwargs):
        raise PermissionError("listener denied")

    def connect(self, *_args, **_kwargs):
        return None

    def __getattr__(self, name):
        return getattr(self._socket, name)

socket.socket = DenyBindSocket
sys.argv = ["-c", *command[4:]]
exec(compile(command[3], "<guardian-probe>", "exec"), {"__name__": "__main__"})
""".lstrip(),
        encoding="utf-8",
    )
    wrapper.chmod(0o700)
    policy = replace(
        _prevention_policy(),
        sandbox_argv_prefix=(str(wrapper),),
    )

    with pytest.raises(
        prevention_runtime.PreventionPolicyError,
        match="confinement probe",
    ):
        SandboxedTestRunner(timeout_seconds=10).run_pair(
            base_workspace=base,
            candidate_workspace=candidate,
            policy=policy,
            base_sha=BASE_SHA,
            candidate_sha=CANDIDATE_SHA,
            test_overlay_hash="c" * 64,
        )


def test_sandbox_probe_accepts_denied_socket_and_cgroup_access(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    stub_network_canaries: None,
) -> None:
    workspace = tmp_path / "workspace"
    private = tmp_path / "private"
    workspace.mkdir()
    private.mkdir()
    wrapper = tmp_path / "deny-all-sockets"
    wrapper.write_text(
        f"#!{sys.executable}\n"
        + """
import os
import pathlib
import socket
import sys

command = sys.argv[1:]
if len(command) < 4 or command[1:3] != ["-I", "-c"]:
    raise SystemExit(97)

def deny_bytes(*_args, **_kwargs):
    raise PermissionError("outside filesystem access denied")

def deny_socket(*_args, **_kwargs):
    raise PermissionError("all socket creation denied")

pathlib.Path.read_bytes = deny_bytes
pathlib.Path.write_bytes = deny_bytes
os.open = deny_bytes
socket.socket = deny_socket
sys.argv = ["-c", *command[4:]]
exec(compile(command[3], "<guardian-probe>", "exec"), {"__name__": "__main__"})
""".lstrip(),
        encoding="utf-8",
    )
    wrapper.chmod(0o700)
    cgroup_parent_procs = tmp_path / "cgroup.procs"
    cgroup_parent_procs.touch()
    monkeypatch.setattr(
        prevention_runtime,
        "linux_cgroup_parent_procs",
        lambda: cgroup_parent_procs,
    )
    runner = SandboxedTestRunner(timeout_seconds=10)

    runner._prove_confinement(
        workspace=workspace,
        private=private,
        sandbox_prefix=(str(wrapper),),
        environment=runner._environment(home=private, temp=private),
    )


def test_sandboxed_runner_fails_closed_if_parent_cannot_create_canary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    base = tmp_path / "base"
    candidate = tmp_path / "candidate"
    base.mkdir()
    candidate.mkdir()
    subprocess_calls = 0

    def deny_listener(*_args, **_kwargs):
        raise PermissionError("listener capability denied")

    def fake_run(*_args, **_kwargs):
        nonlocal subprocess_calls
        subprocess_calls += 1
        raise AssertionError("target code must not run without a live canary")

    monkeypatch.setattr(prevention_runtime.socket, "socket", deny_listener)
    monkeypatch.setattr(prevention_runtime, "run_bounded_process", fake_run)

    with pytest.raises(
        prevention_runtime.PreventionPolicyError,
        match="confinement probe",
    ):
        SandboxedTestRunner(timeout_seconds=10).run_pair(
            base_workspace=base,
            candidate_workspace=candidate,
            policy=_prevention_policy(),
            base_sha=BASE_SHA,
            candidate_sha=CANDIDATE_SHA,
            test_overlay_hash="c" * 64,
        )

    assert subprocess_calls == 0


def test_github_broker_revalidates_numeric_identities_and_opens_draft_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    branch = "guardian/prevention-" + "d" * 64
    evidence_hash = "d" * 64
    marker = PreventionGitHubBroker._marker(evidence_hash, CANDIDATE_SHA)
    requests: list[tuple[str, str, object]] = []
    lease_checks = 0

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append((request.method, request.url.path, request.content))
        path = request.url.path
        if path == "/user":
            return _response(request, _authenticated_actor_payload())
        if path == "/repos/guardian/pipeline":
            return _response(request, _repo_payload())
        if path == "/repos/guardian/pipeline/branches/main":
            return _response(request, _branch_payload("main", BASE_SHA))
        if path == f"/repos/guardian/pipeline/branches/{branch}":
            return _response(request, _branch_payload(branch, CANDIDATE_SHA))
        if path == "/repos/guardian/pipeline/pulls" and request.method == "GET":
            return _response(request, [])
        if path == "/repos/guardian/pipeline/pulls" and request.method == "POST":
            assert lease_checks == 2
            payload = json.loads(request.content)
            assert payload["draft"] is True
            assert payload["maintainer_can_modify"] is False
            assert payload["head"] == f"guardian:{branch}"
            assert marker in payload["body"]
            return _response(
                request,
                _pull_payload(
                    number=17,
                    branch=branch,
                    body=payload["body"],
                    draft=True,
                ),
                status=201,
            )
        raise AssertionError(f"unexpected {request.method} {request.url}")

    monkeypatch.setattr(
        prevention_runtime.SecretCommand,
        "read",
        lambda _self: TOKEN,
    )
    broker = PreventionGitHubBroker(
        policy=_prevention_policy(),
        token_command=("credential-helper",),
        base_url="https://api.github.test",
        transport=httpx.MockTransport(handler),
    )
    base = broker.capture_base()
    assert base.revision == _base_revision()
    assert base.target_repository_id == 101
    broker.verify_publish_authority(
        expected_base_sha=BASE_SHA,
        branch=branch,
        candidate_sha=CANDIDATE_SHA,
    )

    def lost_lease() -> None:
        raise RuntimeError("lease lost")

    with pytest.raises(RuntimeError, match="lease lost"):
        broker.open_draft(
            branch=branch,
            expected_base_sha=BASE_SHA,
            candidate_sha=CANDIDATE_SHA,
            evidence_hash=evidence_hash,
            title="Prevent recurrence: placeholder parity",
            body="Validated body\n",
            before_create=lost_lease,
        )
    assert not any(method == "POST" for method, _path, _body in requests)
    requests.clear()

    def before_create() -> None:
        nonlocal lease_checks
        lease_checks += 1

    draft = broker.open_draft(
        branch=branch,
        expected_base_sha=BASE_SHA,
        candidate_sha=CANDIDATE_SHA,
        evidence_hash=evidence_hash,
        title="Prevent recurrence: placeholder parity",
        body="Validated body\n",
        before_create=before_create,
    )

    assert draft == PreventionDraftResult(
        number=17,
        html_url="https://github.com/guardian/pipeline/pull/17",
        candidate_sha=CANDIDATE_SHA,
        created=True,
    )
    assert any(method == "POST" for method, _path, _body in requests)
    assert lease_checks == 2
    assert all(TOKEN.encode() not in body for _method, _path, body in requests)


@pytest.mark.parametrize(
    ("state", "draft", "closed_at", "actor_id", "message"),
    [
        ("closed", True, "2026-09-03T09:00:00Z", PUBLICATION_ACTOR.id, "open draft"),
        ("open", False, None, PUBLICATION_ACTOR.id, "open draft"),
        ("open", True, None, 999, "exact policy"),
    ],
    ids=("closed", "ready", "wrong-author"),
)
def test_github_broker_requires_created_pull_to_be_open_and_draft(
    state: str,
    draft: bool,
    closed_at: str | None,
    actor_id: int,
    message: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    branch = "guardian/prevention-" + "9" * 64
    evidence_hash = "9" * 64
    title = "Prevent recurrence: exact publication provenance"

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/user":
            return _response(request, _authenticated_actor_payload())
        if path == "/repos/guardian/pipeline":
            return _response(request, _repo_payload())
        if path == "/repos/guardian/pipeline/branches/main":
            return _response(request, _branch_payload("main", BASE_SHA))
        if path == f"/repos/guardian/pipeline/branches/{branch}":
            return _response(request, _branch_payload(branch, CANDIDATE_SHA))
        if path == "/repos/guardian/pipeline/pulls" and request.method == "GET":
            return _response(request, [])
        if path == "/repos/guardian/pipeline/pulls" and request.method == "POST":
            payload = json.loads(request.content)
            return _response(
                request,
                _pull_payload(
                    number=40,
                    branch=branch,
                    title=title,
                    body=payload["body"],
                    state=state,
                    draft=draft,
                    closed_at=closed_at,
                    actor_id=actor_id,
                ),
                status=201,
            )
        raise AssertionError(f"unexpected {request.method} {request.url}")

    monkeypatch.setattr(prevention_runtime.SecretCommand, "read", lambda _self: TOKEN)
    broker = PreventionGitHubBroker(
        policy=_prevention_policy(),
        token_command=("credential-helper",),
        base_url="https://api.github.test",
        transport=httpx.MockTransport(handler),
    )

    with pytest.raises(PreventionRuntimeError, match=message):
        broker.open_draft(
            branch=branch,
            expected_base_sha=BASE_SHA,
            candidate_sha=CANDIDATE_SHA,
            evidence_hash=evidence_hash,
            title=title,
            body="Validated body\n",
            before_create=lambda: None,
        )


def test_github_broker_recovers_exact_existing_guardian_pr_without_post(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    branch = "guardian/prevention-" + "e" * 64
    evidence_hash = "e" * 64
    marker = PreventionGitHubBroker._marker(evidence_hash, CANDIDATE_SHA)
    methods: list[str] = []
    title = "Prevent recurrence: placeholder parity"
    pull = _pull_payload(
        number=18,
        branch=branch,
        title=title,
        body=f"{marker}\nValidated body\n",
        draft=False,
    )

    def handler(request: httpx.Request) -> httpx.Response:
        methods.append(request.method)
        path = request.url.path
        if path == "/user":
            return _response(request, _authenticated_actor_payload())
        if path == "/repos/guardian/pipeline":
            return _response(request, _repo_payload())
        if path == "/repos/guardian/pipeline/branches/main":
            return _response(request, _branch_payload("main", BASE_SHA))
        if path == f"/repos/guardian/pipeline/branches/{branch}":
            return _response(request, _branch_payload(branch, CANDIDATE_SHA))
        if path == "/repos/guardian/pipeline/pulls":
            return _response(request, [pull])
        if path == "/repos/guardian/pipeline/pulls/18":
            return _response(request, pull)
        if path == "/repos/guardian/pipeline/issues/18/events":
            return _response(request, [_issue_event(901, "ready_for_review")])
        raise AssertionError(path)

    monkeypatch.setattr(prevention_runtime.SecretCommand, "read", lambda _self: TOKEN)
    broker = PreventionGitHubBroker(
        policy=_prevention_policy(),
        token_command=("credential-helper",),
        base_url="https://api.github.test",
        transport=httpx.MockTransport(handler),
    )
    draft = broker.open_draft(
        branch=branch,
        expected_base_sha=BASE_SHA,
        candidate_sha=CANDIDATE_SHA,
        evidence_hash=evidence_hash,
        title=title,
        body="Validated body\n",
        before_create=lambda: pytest.fail(
            "existing pull recovery must not request a mutation lease"
        ),
    )
    assert draft.created is False
    assert draft.number == 18
    assert "POST" not in methods


@pytest.mark.parametrize("existing", [True, False], ids=("exact-pr", "no-pr"))
def test_read_only_recovery_allows_credential_actor_rotation(
    existing: bool,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    branch = "guardian/prevention-" + "e" * 64
    evidence_hash = "e" * 64
    marker = PreventionGitHubBroker._marker(evidence_hash, CANDIDATE_SHA)
    title = "Prevent recurrence: actor rotation"
    pull = _pull_payload(
        number=18,
        branch=branch,
        title=title,
        body=f"{marker}\nValidated body\n",
        draft=True,
    )

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/user":
            return _response(
                request,
                _authenticated_actor_payload(actor_id=999),
            )
        if path == "/repos/guardian/pipeline":
            return _response(request, _repo_payload())
        if path == "/repos/guardian/pipeline/pulls":
            return _response(request, [pull] if existing else [])
        if path == "/repos/guardian/pipeline/pulls/18":
            return _response(request, pull)
        if path == "/repos/guardian/pipeline/issues/18/events":
            return _response(request, [])
        raise AssertionError(path)

    monkeypatch.setattr(prevention_runtime.SecretCommand, "read", lambda _self: TOKEN)
    broker = PreventionGitHubBroker(
        policy=_prevention_policy(),
        token_command=("credential-helper",),
        base_url="https://api.github.test",
        transport=httpx.MockTransport(handler),
    )

    recovered = broker.find_draft(
        branch=branch,
        expected_base_sha=BASE_SHA,
        candidate_sha=CANDIDATE_SHA,
        evidence_hash=evidence_hash,
        title=title,
        body="Validated body\n",
    )

    assert (recovered is not None) is existing
    if recovered is not None:
        assert recovered.number == 18


@pytest.mark.parametrize("existing", [True, False], ids=("exact-pr", "no-pr"))
def test_read_only_recovery_does_not_require_a_surviving_push_fork(
    existing: bool,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    branch = "guardian/prevention-" + "f" * 64
    evidence_hash = "f" * 64
    marker = PreventionGitHubBroker._marker(evidence_hash, CANDIDATE_SHA)
    title = "Prevent recurrence: deleted push fork"
    pull = _pull_payload(
        number=19,
        branch=branch,
        title=title,
        body=f"{marker}\nValidated body\n",
        draft=True,
    )
    pull["head"] = {
        **dict(pull["head"]),  # type: ignore[arg-type]
        "repo": {"id": 202, "full_name": "guardian-fork/pipeline"},
    }

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/user":
            return _response(request, _authenticated_actor_payload())
        if path == "/repos/guardian/pipeline":
            return _response(request, _repo_payload())
        if path == "/repos/guardian-fork/pipeline":
            pytest.fail("read-only recovery must not require the deleted push fork")
        if path == "/repos/guardian/pipeline/pulls":
            assert request.url.params["head"] == f"guardian-fork:{branch}"
            return _response(request, [pull] if existing else [])
        if path == "/repos/guardian/pipeline/pulls/19":
            return _response(request, pull)
        if path == "/repos/guardian/pipeline/issues/19/events":
            return _response(request, [])
        raise AssertionError(path)

    monkeypatch.setattr(prevention_runtime.SecretCommand, "read", lambda _self: TOKEN)
    broker = PreventionGitHubBroker(
        policy=_prevention_policy(
            push_repository=ExactRepository(
                full_name="guardian-fork/pipeline",
                id=202,
            )
        ),
        token_command=("credential-helper",),
        base_url="https://api.github.test",
        transport=httpx.MockTransport(handler),
    )

    recovered = broker.find_draft(
        branch=branch,
        expected_base_sha=BASE_SHA,
        candidate_sha=CANDIDATE_SHA,
        evidence_hash=evidence_hash,
        title=title,
        body="Validated body\n",
    )

    assert (recovered is not None) is existing


def test_github_broker_recovers_exact_pr_after_target_base_sha_advances(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    branch = "guardian/prevention-" + "a" * 64
    evidence_hash = "a" * 64
    marker = PreventionGitHubBroker._marker(evidence_hash, CANDIDATE_SHA)
    title = "Prevent recurrence: post-crash base movement"
    pull = _pull_payload(
        number=48,
        branch=branch,
        title=title,
        body=f"{marker}\nValidated body\n",
        draft=True,
    )
    pull["base"] = {
        **dict(pull["base"]),  # type: ignore[arg-type]
        "sha": "f" * 40,
    }

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/user":
            return _response(request, _authenticated_actor_payload())
        if path == "/repos/guardian/pipeline":
            return _response(request, _repo_payload())
        if path == "/repos/guardian/pipeline/pulls":
            return _response(request, [pull])
        if path == "/repos/guardian/pipeline/pulls/48":
            return _response(request, pull)
        if path == "/repos/guardian/pipeline/issues/48/events":
            return _response(request, [])
        raise AssertionError(path)

    monkeypatch.setattr(prevention_runtime.SecretCommand, "read", lambda _self: TOKEN)
    broker = PreventionGitHubBroker(
        policy=_prevention_policy(),
        token_command=("credential-helper",),
        base_url="https://api.github.test",
        transport=httpx.MockTransport(handler),
    )

    draft = broker.find_draft(
        branch=branch,
        expected_base_sha=BASE_SHA,
        candidate_sha=CANDIDATE_SHA,
        evidence_hash=evidence_hash,
        title=title,
        body="Validated body\n",
    )

    assert draft is not None
    assert draft.number == 48
    assert draft.created is False


def test_recovery_searches_exact_head_without_hiding_a_modified_base(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    branch = "guardian/prevention-" + "d" * 64
    evidence_hash = "d" * 64
    marker = PreventionGitHubBroker._marker(evidence_hash, CANDIDATE_SHA)
    title = "Prevent recurrence: placeholder parity"
    pull = _pull_payload(
        number=19,
        branch=branch,
        title=title,
        body=f"{marker}\nValidated body\n",
        draft=True,
    )
    pull["base"] = {
        **dict(pull["base"]),  # type: ignore[arg-type]
        "ref": "maintainer-edited-base",
    }

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/user":
            return _response(request, _authenticated_actor_payload())
        if path == "/repos/guardian/pipeline":
            return _response(request, _repo_payload())
        if path == "/repos/guardian/pipeline/pulls":
            assert request.url.params["head"] == f"guardian:{branch}"
            assert "base" not in request.url.params
            return _response(request, [pull])
        if path == "/repos/guardian/pipeline/pulls/19":
            return _response(request, pull)
        if path == "/repos/guardian/pipeline/issues/19/events":
            return _response(request, [])
        raise AssertionError(path)

    monkeypatch.setattr(prevention_runtime.SecretCommand, "read", lambda _self: TOKEN)
    broker = PreventionGitHubBroker(
        policy=_prevention_policy(),
        token_command=("credential-helper",),
        base_url="https://api.github.test",
        transport=httpx.MockTransport(handler),
    )

    with pytest.raises(PreventionRemoteConflictError, match="exact policy"):
        broker.find_draft(
            branch=branch,
            expected_base_sha=BASE_SHA,
            candidate_sha=CANDIDATE_SHA,
            evidence_hash=evidence_hash,
            title=title,
            body="Validated body\n",
        )


def test_github_broker_requires_stable_exact_get_events_get_observation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    branch = "guardian/prevention-" + "f" * 64
    evidence_hash = "f" * 64
    marker = PreventionGitHubBroker._marker(evidence_hash, CANDIDATE_SHA)
    title = "Prevent recurrence: stable recovery"
    pull = _pull_payload(
        number=19,
        branch=branch,
        title=title,
        body=f"{marker}\nValidated body\n",
        draft=True,
    )
    exact_calls = 0
    observations: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal exact_calls
        path = request.url.path
        if path == "/user":
            return _response(request, _authenticated_actor_payload())
        if path == "/repos/guardian/pipeline":
            return _response(request, _repo_payload())
        if path == "/repos/guardian/pipeline/pulls":
            return _response(request, [pull])
        if path == "/repos/guardian/pipeline/pulls/19":
            exact_calls += 1
            observations.append(f"get-{exact_calls}")
            payload = dict(pull)
            if exact_calls == 2:
                payload["title"] = f"{title} edited"
            return _response(request, payload)
        if path == "/repos/guardian/pipeline/issues/19/events":
            observations.append("events")
            return _response(request, [])
        raise AssertionError(path)

    monkeypatch.setattr(prevention_runtime.SecretCommand, "read", lambda _self: TOKEN)
    broker = PreventionGitHubBroker(
        policy=_prevention_policy(),
        token_command=("credential-helper",),
        base_url="https://api.github.test",
        transport=httpx.MockTransport(handler),
    )

    with pytest.raises(PreventionRuntimeError, match="stable observation"):
        broker.find_draft(
            branch=branch,
            expected_base_sha=BASE_SHA,
            candidate_sha=CANDIDATE_SHA,
            evidence_hash=evidence_hash,
            title=title,
            body="Validated body\n",
        )
    assert observations == ["get-1", "events", "get-2"]


def test_github_broker_stable_observation_is_json_type_sensitive(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    branch = "guardian/prevention-" + "f" * 64
    evidence_hash = "f" * 64
    marker = PreventionGitHubBroker._marker(evidence_hash, CANDIDATE_SHA)
    title = "Prevent recurrence: type-sensitive recovery"
    pull = _pull_payload(
        number=19,
        branch=branch,
        title=title,
        body=f"{marker}\nValidated body\n",
        draft=True,
    )
    exact_calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal exact_calls
        path = request.url.path
        if path == "/user":
            return _response(request, _authenticated_actor_payload())
        if path == "/repos/guardian/pipeline":
            return _response(request, _repo_payload())
        if path == "/repos/guardian/pipeline/pulls":
            return _response(request, [pull])
        if path == "/repos/guardian/pipeline/pulls/19":
            exact_calls += 1
            payload = dict(pull)
            payload["number"] = 19.0 if exact_calls == 1 else 19
            return _response(request, payload)
        if path == "/repos/guardian/pipeline/issues/19/events":
            return _response(request, [])
        raise AssertionError(path)

    monkeypatch.setattr(prevention_runtime.SecretCommand, "read", lambda _self: TOKEN)
    broker = PreventionGitHubBroker(
        policy=_prevention_policy(),
        token_command=("credential-helper",),
        base_url="https://api.github.test",
        transport=httpx.MockTransport(handler),
    )

    with pytest.raises(PreventionRuntimeError, match="stable observation"):
        broker.find_draft(
            branch=branch,
            expected_base_sha=BASE_SHA,
            candidate_sha=CANDIDATE_SHA,
            evidence_hash=evidence_hash,
            title=title,
            body="Validated body\n",
        )
    assert exact_calls == 2


@pytest.mark.parametrize(
    ("state", "draft", "events", "closed_at"),
    [
        ("open", True, [], None),
        ("open", False, [_issue_event(1, "ready_for_review")], None),
        (
            "closed",
            True,
            [_issue_event(1, "closed")],
            "2026-09-03T09:00:00Z",
        ),
        (
            "closed",
            False,
            [
                _issue_event(1, "ready_for_review"),
                _issue_event(2, "closed"),
            ],
            "2026-09-03T09:00:00Z",
        ),
    ],
    ids=("untouched-draft", "ready", "closed-draft", "ready-then-closed"),
)
def test_github_broker_recovers_only_allowed_terminal_lifecycles(
    state: str,
    draft: bool,
    events: list[object],
    closed_at: str | None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    branch = "guardian/prevention-" + "1" * 64
    evidence_hash = "1" * 64
    marker = PreventionGitHubBroker._marker(evidence_hash, CANDIDATE_SHA)
    title = "Prevent recurrence: exact publication provenance"
    pull = _pull_payload(
        number=41,
        branch=branch,
        title=title,
        body=f"{marker}\nValidated body\n",
        state=state,
        draft=draft,
        closed_at=closed_at,
    )
    broker = _recovery_broker(
        monkeypatch,
        branch=branch,
        exact_pull=pull,
        event_pages={1: events},
    )

    recovered = broker.open_draft(
        branch=branch,
        expected_base_sha=BASE_SHA,
        candidate_sha=CANDIDATE_SHA,
        evidence_hash=evidence_hash,
        title=title,
        body="Validated body\n",
        before_create=lambda: pytest.fail("recovery must not create a PR"),
    )

    assert recovered.created is False
    assert recovered.number == 41


@pytest.mark.parametrize(
    ("state", "draft", "events", "merged_at", "closed_at"),
    [
        (
            "closed",
            False,
            [
                _issue_event(1, "ready_for_review"),
                _issue_event(2, "closed"),
                _issue_event(3, "reopened"),
                _issue_event(4, "closed"),
            ],
            None,
            "2026-09-03T09:00:00Z",
        ),
        ("open", True, [_issue_event(1, "ready_for_review")], None, None),
        (
            "open",
            False,
            [
                _issue_event(1, "ready_for_review"),
                _issue_event(2, "convert_to_draft"),
                _issue_event(3, "ready_for_review"),
            ],
            None,
            None,
        ),
        (
            "open",
            False,
            [
                _issue_event(1, "ready_for_review"),
                _issue_event(2, "converted_to_draft"),
                _issue_event(3, "ready_for_review"),
            ],
            None,
            None,
        ),
        (
            "closed",
            False,
            [
                _issue_event(1, "ready_for_review"),
                _issue_event(2, "closed"),
                _issue_event(3, "merged"),
            ],
            "2026-09-03T09:00:00Z",
            "2026-09-03T09:00:00Z",
        ),
    ],
    ids=(
        "reopened-and-reclosed",
        "history-state-mismatch",
        "redrafted-rest-name",
        "redrafted-defensive-alias",
        "merged",
    ),
)
def test_github_broker_rejects_modified_or_reopened_lifecycle(
    state: str,
    draft: bool,
    events: list[object],
    merged_at: str | None,
    closed_at: str | None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    branch = "guardian/prevention-" + "2" * 64
    evidence_hash = "2" * 64
    marker = PreventionGitHubBroker._marker(evidence_hash, CANDIDATE_SHA)
    title = "Prevent recurrence: exact publication provenance"
    pull = _pull_payload(
        number=42,
        branch=branch,
        title=title,
        body=f"{marker}\nValidated body\n",
        state=state,
        draft=draft,
        merged_at=merged_at,
        closed_at=closed_at,
    )
    broker = _recovery_broker(
        monkeypatch,
        branch=branch,
        exact_pull=pull,
        event_pages={1: events},
    )

    with pytest.raises(PreventionRemoteConflictError, match="lifecycle"):
        broker.open_draft(
            branch=branch,
            expected_base_sha=BASE_SHA,
            candidate_sha=CANDIDATE_SHA,
            evidence_hash=evidence_hash,
            title=title,
            body="Validated body\n",
            before_create=lambda: pytest.fail("recovery must not create a PR"),
        )


@pytest.mark.parametrize(
    "events",
    [
        [
            _issue_event(1, "head_ref_deleted"),
            _issue_event(2, "head_ref_restored"),
        ],
        [_issue_event(1, "head_ref_force_pushed")],
        [
            _issue_event(1, "base_ref_changed"),
            _issue_event(2, "base_ref_changed"),
        ],
        [_issue_event(1, "automatic_base_change_succeeded")],
        [_issue_event(1, "automatic_base_change_failed")],
    ],
    ids=(
        "deleted-restored",
        "force-pushed",
        "base-restored",
        "automatic-base",
        "failed-automatic-base",
    ),
)
def test_github_broker_rejects_recovered_pull_ref_mutation_history(
    events: list[object],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    branch = "guardian/prevention-" + "7" * 64
    evidence_hash = "7" * 64
    marker = PreventionGitHubBroker._marker(evidence_hash, CANDIDATE_SHA)
    title = "Prevent recurrence: immutable branch provenance"
    pull = _pull_payload(
        number=48,
        branch=branch,
        title=title,
        body=f"{marker}\nValidated body\n",
        draft=True,
    )
    broker = _recovery_broker(
        monkeypatch,
        branch=branch,
        exact_pull=pull,
        event_pages={1: events},
    )

    with pytest.raises(PreventionRemoteConflictError, match="modified"):
        broker.find_draft(
            branch=branch,
            expected_base_sha=BASE_SHA,
            candidate_sha=CANDIDATE_SHA,
            evidence_hash=evidence_hash,
            title=title,
            body="Validated body\n",
        )


@pytest.mark.parametrize(
    "mutation",
    [
        "author-id",
        "author-type",
        "title",
        "body",
        "maintainer",
        "head-sha",
        "head-ref",
        "head-repository-id",
        "head-repository-name",
        "base-ref",
        "base-repository-id",
        "base-repository-name",
        "exact-number",
        "oversized-number",
    ],
)
def test_github_broker_revalidates_exact_recovered_pull_metadata(
    mutation: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    branch = "guardian/prevention-" + "3" * 64
    evidence_hash = "3" * 64
    marker = PreventionGitHubBroker._marker(evidence_hash, CANDIDATE_SHA)
    title = "Prevent recurrence: exact publication provenance"
    listed = _pull_payload(
        number=43,
        branch=branch,
        title=title,
        body=f"{marker}\nValidated body\n",
        draft=True,
    )
    exact = dict(listed)
    exact["head"] = {
        **dict(listed["head"]),  # type: ignore[arg-type]
        "repo": dict(listed["head"]["repo"]),  # type: ignore[index]
    }
    exact["base"] = {
        **dict(listed["base"]),  # type: ignore[arg-type]
        "repo": dict(listed["base"]["repo"]),  # type: ignore[index]
    }
    exact["user"] = dict(listed["user"])  # type: ignore[arg-type]
    if mutation == "author-id":
        exact["user"]["id"] = 999  # type: ignore[index]
    elif mutation == "author-type":
        exact["user"]["type"] = "Bot"  # type: ignore[index]
    elif mutation == "title":
        exact["title"] = f"{title} (edited)"
    elif mutation == "body":
        exact["body"] = f"{marker}\nModified body\n"
    elif mutation == "maintainer":
        exact["maintainer_can_modify"] = True
    elif mutation == "head-sha":
        exact["head"]["sha"] = "c" * 40  # type: ignore[index]
    elif mutation == "head-ref":
        exact["head"]["ref"] = "guardian/prevention-forged"  # type: ignore[index]
    elif mutation == "head-repository-id":
        exact["head"]["repo"]["id"] = 999  # type: ignore[index]
    elif mutation == "head-repository-name":
        exact["head"]["repo"]["full_name"] = "attacker/pipeline"  # type: ignore[index]
    elif mutation == "base-ref":
        exact["base"]["ref"] = "release"  # type: ignore[index]
    elif mutation == "base-repository-id":
        exact["base"]["repo"]["id"] = 999  # type: ignore[index]
    elif mutation == "base-repository-name":
        exact["base"]["repo"]["full_name"] = "guardian/other"  # type: ignore[index]
    elif mutation == "exact-number":
        exact["number"] = 44
    elif mutation == "oversized-number":
        exact["number"] = 2**63
    broker = _recovery_broker(
        monkeypatch,
        branch=branch,
        exact_pull=exact,
        listed_pull=listed,
    )

    with pytest.raises(PreventionRemoteConflictError, match="exact policy"):
        broker.open_draft(
            branch=branch,
            expected_base_sha=BASE_SHA,
            candidate_sha=CANDIDATE_SHA,
            evidence_hash=evidence_hash,
            title=title,
            body="Validated body\n",
            before_create=lambda: pytest.fail("recovery must not create a PR"),
        )


@pytest.mark.parametrize(
    "html_url",
    [
        "http://github.com/guardian/pipeline/pull/45",
        "https://evil.test/guardian/pipeline/pull/45",
        "https://github.com:443/guardian/pipeline/pull/45",
        "https://user@github.com/guardian/pipeline/pull/45",
        "https://github.com/guardian/pipeline/pull/45?diff=1",
        "https://github.com/guardian/pipeline/pull/45#discussion",
        "https://github.com/guardian/other/pull/45",
    ],
)
def test_github_broker_requires_canonical_recovered_pull_url(
    html_url: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    branch = "guardian/prevention-" + "4" * 64
    evidence_hash = "4" * 64
    marker = PreventionGitHubBroker._marker(evidence_hash, CANDIDATE_SHA)
    title = "Prevent recurrence: exact publication provenance"
    pull = _pull_payload(
        number=45,
        branch=branch,
        title=title,
        body=f"{marker}\nValidated body\n",
        draft=True,
        html_url=html_url,
    )
    broker = _recovery_broker(monkeypatch, branch=branch, exact_pull=pull)

    with pytest.raises(PreventionRemoteConflictError, match="URL"):
        broker.open_draft(
            branch=branch,
            expected_base_sha=BASE_SHA,
            candidate_sha=CANDIDATE_SHA,
            evidence_hash=evidence_hash,
            title=title,
            body="Validated body\n",
            before_create=lambda: pytest.fail("recovery must not create a PR"),
        )


@pytest.mark.parametrize(
    "events",
    [
        [{"id": 1}],
        [{"event": "ready_for_review"}],
        [{"id": True, "event": "ready_for_review"}],
        [{"id": 1, "event": "ready_for_review\nforged"}],
    ],
)
def test_github_broker_fails_closed_on_malformed_recovery_history(
    events: list[object],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    branch = "guardian/prevention-" + "5" * 64
    evidence_hash = "5" * 64
    marker = PreventionGitHubBroker._marker(evidence_hash, CANDIDATE_SHA)
    title = "Prevent recurrence: exact publication provenance"
    pull = _pull_payload(
        number=46,
        branch=branch,
        title=title,
        body=f"{marker}\nValidated body\n",
        draft=False,
    )
    broker = _recovery_broker(
        monkeypatch,
        branch=branch,
        exact_pull=pull,
        event_pages={1: events},
    )

    with pytest.raises(PreventionRemoteConflictError, match="history"):
        broker.open_draft(
            branch=branch,
            expected_base_sha=BASE_SHA,
            candidate_sha=CANDIDATE_SHA,
            evidence_hash=evidence_hash,
            title=title,
            body="Validated body\n",
            before_create=lambda: pytest.fail("recovery must not create a PR"),
        )


def test_malformed_history_is_classified_only_after_second_exact_get(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    branch = "guardian/prevention-" + "5" * 64
    evidence_hash = "5" * 64
    marker = PreventionGitHubBroker._marker(evidence_hash, CANDIDATE_SHA)
    title = "Prevent recurrence: stable malformed history"
    pull = _pull_payload(
        number=46,
        branch=branch,
        title=title,
        body=f"{marker}\nValidated body\n",
        draft=True,
    )
    exact_reads = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal exact_reads
        path = request.url.path
        if path == "/user":
            return _response(request, _authenticated_actor_payload())
        if path == "/repos/guardian/pipeline":
            return _response(request, _repo_payload())
        if path == "/repos/guardian/pipeline/pulls":
            return _response(request, [pull])
        if path == "/repos/guardian/pipeline/pulls/46":
            exact_reads += 1
            return _response(request, pull)
        if path == "/repos/guardian/pipeline/issues/46/events":
            return _response(request, {"not": "a list"})
        raise AssertionError(path)

    monkeypatch.setattr(prevention_runtime.SecretCommand, "read", lambda _self: TOKEN)
    broker = PreventionGitHubBroker(
        policy=_prevention_policy(),
        token_command=("credential-helper",),
        base_url="https://api.github.test",
        transport=httpx.MockTransport(handler),
    )

    with pytest.raises(PreventionRemoteConflictError, match="history"):
        broker.find_draft(
            branch=branch,
            expected_base_sha=BASE_SHA,
            candidate_sha=CANDIDATE_SHA,
            evidence_hash=evidence_hash,
            title=title,
            body="Validated body\n",
        )
    assert exact_reads == 2


def test_github_broker_fails_closed_when_recovery_history_exceeds_page_bound(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    branch = "guardian/prevention-" + "6" * 64
    evidence_hash = "6" * 64
    marker = PreventionGitHubBroker._marker(evidence_hash, CANDIDATE_SHA)
    title = "Prevent recurrence: exact publication provenance"
    pull = _pull_payload(
        number=47,
        branch=branch,
        title=title,
        body=f"{marker}\nValidated body\n",
        draft=True,
    )
    events = [_issue_event(index, "labeled") for index in range(1, 101)]
    broker = _recovery_broker(
        monkeypatch,
        branch=branch,
        exact_pull=pull,
        event_pages={1: events},
    )
    monkeypatch.setattr(prevention_runtime, "_MAX_PULL_EVENT_PAGES", 1)
    exact_reads = 0
    request = broker._request  # noqa: SLF001 - count stable-observation reads

    def tracking_request(client, method, path, **kwargs):
        nonlocal exact_reads
        if method == "GET" and path.endswith("/pulls/47"):
            exact_reads += 1
        return request(client, method, path, **kwargs)

    monkeypatch.setattr(broker, "_request", tracking_request)

    with pytest.raises(PreventionRemoteConflictError, match="pagination"):
        broker.open_draft(
            branch=branch,
            expected_base_sha=BASE_SHA,
            candidate_sha=CANDIDATE_SHA,
            evidence_hash=evidence_hash,
            title=title,
            body="Validated body\n",
            before_create=lambda: pytest.fail("recovery must not create a PR"),
        )
    assert exact_reads == 2


def test_github_broker_uses_persisted_legacy_pull_number_without_head_listing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    evidence_hash = "7" * 64
    branch = f"guardian/prevention-{BASE_SHA[:12]}-{evidence_hash}"
    title = "Prevent recurrence: exact legacy recovery"
    marker = PreventionGitHubBroker._marker(evidence_hash, CANDIDATE_SHA)
    pull = _pull_payload(
        number=91,
        branch=branch,
        title=title,
        body=f"{marker}\nValidated body\n",
        draft=True,
    )
    exact_reads = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal exact_reads
        path = request.url.path
        if path == "/user":
            return _response(request, _authenticated_actor_payload())
        if path == "/repos/guardian/pipeline":
            return _response(request, _repo_payload())
        if path == "/repos/guardian/pipeline/pulls/91":
            exact_reads += 1
            return _response(request, pull)
        if path == "/repos/guardian/pipeline/issues/91/events":
            return _response(request, [])
        if path == "/repos/guardian/pipeline/pulls":
            pytest.fail("an opened v1 ledger must not depend on head listing")
        raise AssertionError(path)

    monkeypatch.setattr(prevention_runtime.SecretCommand, "read", lambda _self: TOKEN)
    broker = PreventionGitHubBroker(
        policy=_prevention_policy(),
        token_command=("credential-helper",),
        base_url="https://api.github.test",
        transport=httpx.MockTransport(handler),
    )

    recovered = broker.find_legacy_draft(
        branch=branch,
        expected_base_sha=BASE_SHA,
        candidate_sha=CANDIDATE_SHA,
        evidence_hash=evidence_hash,
        title=title,
        body="Validated body\n",
        expected_number=91,
    )

    assert recovered is not None and recovered.number == 91
    assert exact_reads == 2


def test_github_broker_revalidates_base_after_pagination_before_post(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    branch = "guardian/prevention-" + "f" * 64
    evidence_hash = "f" * 64
    base_reads = 0
    methods: list[str] = []
    lease_checks = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal base_reads
        methods.append(request.method)
        path = request.url.path
        if path == "/user":
            return _response(request, _authenticated_actor_payload())
        if path == "/repos/guardian/pipeline":
            return _response(request, _repo_payload())
        if path == "/repos/guardian/pipeline/branches/main":
            base_reads += 1
            sha = BASE_SHA if base_reads == 1 else "f" * 40
            return _response(request, _branch_payload("main", sha))
        if path == f"/repos/guardian/pipeline/branches/{branch}":
            return _response(request, _branch_payload(branch, CANDIDATE_SHA))
        if path == "/repos/guardian/pipeline/pulls" and request.method == "GET":
            return _response(request, [])
        raise AssertionError(f"unexpected {request.method} {path}")

    def before_create() -> None:
        nonlocal lease_checks
        lease_checks += 1

    monkeypatch.setattr(prevention_runtime.SecretCommand, "read", lambda _self: TOKEN)
    broker = PreventionGitHubBroker(
        policy=_prevention_policy(),
        token_command=("credential-helper",),
        base_url="https://api.github.test",
        transport=httpx.MockTransport(handler),
    )

    with pytest.raises(PreventionRuntimeError, match="base moved"):
        broker.open_draft(
            branch=branch,
            expected_base_sha=BASE_SHA,
            candidate_sha=CANDIDATE_SHA,
            evidence_hash=evidence_hash,
            title="Prevent recurrence: placeholder parity",
            body="Validated body\n",
            before_create=before_create,
        )

    assert lease_checks == 1
    assert "POST" not in methods


@pytest.mark.parametrize("mutation", ["base", "branch"])
def test_github_broker_revalidates_remote_authority_after_final_pr_lookup(
    mutation: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    branch = "guardian/prevention-" + "a" * 64
    pull_reads = 0
    authority_checks = 0
    destination_moved = False
    methods: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal pull_reads
        methods.append(request.method)
        path = request.url.path
        if path == "/user":
            return _response(request, _authenticated_actor_payload())
        if path == "/repos/guardian/pipeline":
            return _response(request, _repo_payload())
        if path == "/repos/guardian/pipeline/branches/main":
            sha = "f" * 40 if mutation == "base" and destination_moved else BASE_SHA
            return _response(request, _branch_payload("main", sha))
        if path == f"/repos/guardian/pipeline/branches/{branch}":
            sha = (
                "f" * 40
                if mutation == "branch" and destination_moved
                else CANDIDATE_SHA
            )
            return _response(request, _branch_payload(branch, sha))
        if path == "/repos/guardian/pipeline/pulls" and request.method == "GET":
            pull_reads += 1
            return _response(request, [])
        raise AssertionError(f"unexpected {request.method} {path}")

    def before_create() -> None:
        nonlocal authority_checks, destination_moved
        authority_checks += 1
        if authority_checks == 2:
            destination_moved = True

    monkeypatch.setattr(prevention_runtime.SecretCommand, "read", lambda _self: TOKEN)
    broker = PreventionGitHubBroker(
        policy=_prevention_policy(),
        token_command=("credential-helper",),
        base_url="https://api.github.test",
        transport=httpx.MockTransport(handler),
    )

    with pytest.raises(PreventionRuntimeError, match=rf"{mutation} moved"):
        broker.open_draft(
            branch=branch,
            expected_base_sha=BASE_SHA,
            candidate_sha=CANDIDATE_SHA,
            evidence_hash="a" * 64,
            title="Prevent recurrence: placeholder parity",
            body="Validated body\n",
            before_create=before_create,
        )

    assert pull_reads == 2
    assert authority_checks == 2
    assert "POST" not in methods


def test_github_broker_rechecks_authority_immediately_before_post(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    branch = "guardian/prevention-" + "e" * 64
    methods: list[str] = []
    publication_slot_checks = 0
    source_authority_checks = 0

    def handler(request: httpx.Request) -> httpx.Response:
        methods.append(request.method)
        path = request.url.path
        if path == "/user":
            return _response(request, _authenticated_actor_payload())
        if path == "/repos/guardian/pipeline":
            return _response(request, _repo_payload())
        if path == "/repos/guardian/pipeline/branches/main":
            return _response(request, _branch_payload("main", BASE_SHA))
        if path == f"/repos/guardian/pipeline/branches/{branch}":
            return _response(request, _branch_payload(branch, CANDIDATE_SHA))
        if path == "/repos/guardian/pipeline/pulls" and request.method == "GET":
            return _response(request, [])
        raise AssertionError(f"unexpected {request.method} {path}")

    def before_create() -> None:
        nonlocal publication_slot_checks
        publication_slot_checks += 1

    def before_post() -> None:
        nonlocal source_authority_checks
        source_authority_checks += 1
        raise PreventionSourceAuthorityError("source changed before POST")

    monkeypatch.setattr(prevention_runtime.SecretCommand, "read", lambda _self: TOKEN)
    broker = PreventionGitHubBroker(
        policy=_prevention_policy(),
        token_command=("credential-helper",),
        base_url="https://api.github.test",
        transport=httpx.MockTransport(handler),
    )

    with pytest.raises(PreventionSourceAuthorityError):
        broker.open_draft(
            branch=branch,
            expected_base_sha=BASE_SHA,
            candidate_sha=CANDIDATE_SHA,
            evidence_hash="e" * 64,
            title="Prevent recurrence: placeholder parity",
            body="Validated body\n",
            before_create=before_create,
            before_post=before_post,
        )

    assert publication_slot_checks == 2
    assert source_authority_checks == 1
    assert "POST" not in methods


def test_github_broker_fails_closed_on_repository_id_or_base_mismatch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    identity_ok = {"value": False}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/user":
            return _response(request, _authenticated_actor_payload())
        if request.url.path == "/repos/guardian/pipeline":
            payload = _repo_payload()
            payload["id"] = 101 if identity_ok["value"] else 999
            return _response(request, payload)
        if request.url.path == "/repos/guardian/pipeline/branches/main":
            return _response(request, _branch_payload("main", "f" * 40))
        raise AssertionError(request.url.path)

    monkeypatch.setattr(prevention_runtime.SecretCommand, "read", lambda _self: TOKEN)
    broker = PreventionGitHubBroker(
        policy=_prevention_policy(),
        token_command=("credential-helper",),
        base_url="https://api.github.test",
        transport=httpx.MockTransport(handler),
    )
    with pytest.raises(PreventionRuntimeError, match="identity"):
        broker.capture_base()
    identity_ok["value"] = True
    with pytest.raises(PreventionRuntimeError, match="base moved"):
        broker.verify_publish_authority(
            expected_base_sha=BASE_SHA,
            branch="guardian/prevention-" + "f" * 64,
            candidate_sha=CANDIDATE_SHA,
        )


@pytest.mark.parametrize("status", [401, 403])
def test_prevention_github_authentication_failure_is_typed(
    monkeypatch: pytest.MonkeyPatch,
    status: int,
) -> None:
    monkeypatch.setattr(prevention_runtime.SecretCommand, "read", lambda _self: TOKEN)
    broker = PreventionGitHubBroker(
        policy=_prevention_policy(),
        token_command=("credential-helper",),
        base_url="https://api.github.test",
        transport=httpx.MockTransport(
            lambda request: _response(request, {}, status=status)
        ),
    )

    with pytest.raises(GitHubAuthenticationError):
        broker.capture_base()


def test_prevention_github_credential_helper_failure_is_typed_and_redacted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_credential(_self) -> str:
        raise CredentialError("explicit-secret-value")

    monkeypatch.setattr(prevention_runtime.SecretCommand, "read", fail_credential)
    broker = PreventionGitHubBroker(
        policy=_prevention_policy(),
        token_command=("credential-helper",),
        base_url="https://api.github.test",
    )

    with pytest.raises(GitHubAuthenticationError) as failure:
        broker.capture_base()

    assert "explicit-secret-value" not in str(failure.value)


class _FakeWorkspace:
    def __init__(
        self,
        path: Path,
        revision: ExactRevision,
        broker: "_FakeBroker",
        checkout_factory: "_FakeCheckoutFactory",
    ) -> None:
        self.path = path
        self.revision = revision
        self.broker = broker
        self.checkout_factory = checkout_factory
        self.published = False

    def commit_prevention_changes(self, *, expected_paths, evidence_hash, **_kwargs):
        assert set(expected_paths) == {"localize/rules.py", "tests/unit/test_rules.py"}
        assert len(evidence_hash) == 64
        return CommitResult(
            commit_sha=CANDIDATE_SHA,
            parent_sha=BASE_SHA,
            changed_paths=tuple(sorted(expected_paths)),
            signature_verified=True,
        )

    def publish_prevention_branch(self, commit, **kwargs):
        kwargs["before_push"]()
        if self.broker.mutation_order is not None:
            self.broker.mutation_order.append("push")
        self.published = True
        self.checkout_factory.publications += 1
        self.broker.branch_shas[kwargs["branch"]] = commit.commit_sha
        assert kwargs["push_repository"] == "guardian/pipeline"
        assert kwargs["branch"].startswith("guardian/prevention-")
        return PreventionPublicationResult(
            repository="guardian/pipeline",
            ref=f"refs/heads/{kwargs['branch']}",
            commit_sha=commit.commit_sha,
            created=True,
        )


class _FakeCheckoutFactory:
    def __init__(self, base_tree: Path, root: Path, broker: "_FakeBroker") -> None:
        self.base_tree = base_tree
        self.root = root
        self.broker = broker
        self.calls = 0
        self.publications = 0

    @contextmanager
    def __call__(self, revision: ExactRevision) -> Iterator[_FakeWorkspace]:
        self.calls += 1
        target = self.root / f"checkout-{self.calls}"
        shutil.copytree(self.base_tree, target)
        yield _FakeWorkspace(target, revision, self.broker, self)


class _FakeAuthor:
    model = "gpt-test"
    max_attempts = 1

    def __init__(self) -> None:
        self.calls = 0

    def run(self, *, workspace: Path, **_kwargs) -> PreventionAuthorResult:
        self.calls += 1
        (workspace / "localize/rules.py").write_text(
            "def preserve(value):\n    return value.strip()\n",
            encoding="utf-8",
        )
        (workspace / "tests/unit/test_rules.py").write_text(
            "def test_preserve():\n    assert preserve(' value ') == 'value'\n",
            encoding="utf-8",
        )
        return PreventionAuthorResult(
            attempts=1,
            usage=CodexUsage(input_tokens=10, output_tokens=5, cost_usd=0.01),
        )


class _FakeTestRunner:
    def run_pair(
        self,
        *,
        policy: PreventionPolicy,
        base_sha: str,
        candidate_sha: str,
        test_overlay_hash: str,
        **_kwargs,
    ) -> tuple[TestCommandResult, ...]:
        argv = policy.focused_test_argv[0]
        return (
            TestCommandResult(
                phase="base",
                outcome=TestOutcome.FAILED,
                argv=argv,
                commit_sha=base_sha,
                parent_sha=None,
                returncode=1,
                test_overlay_hash=test_overlay_hash,
            ),
            TestCommandResult(
                phase="patched",
                outcome=TestOutcome.PASSED,
                argv=argv,
                commit_sha=candidate_sha,
                parent_sha=base_sha,
                returncode=0,
                test_overlay_hash=test_overlay_hash,
            ),
        )


class _FakeBroker:
    def __init__(
        self,
        *,
        private: bool = False,
        mutation_order: list[str] | None = None,
    ) -> None:
        self.private = private
        self.mutation_order = mutation_order
        self.branch_shas: dict[str, str] = {}
        self.capture_calls = 0
        self.verify_calls = 0
        self.open_calls = 0

    def capture_base(self) -> PreventionBaseSnapshot:
        self.capture_calls += 1
        return PreventionBaseSnapshot(
            revision=_base_revision(),
            target_repository_id=101,
            push_repository_id=101,
            private=self.private,
        )

    def branch_sha(self, branch: str) -> str | None:
        return self.branch_shas.get(branch)

    def verify_publish_authority(self, **_kwargs) -> None:
        self.verify_calls += 1
        return None

    def find_draft(self, **_kwargs) -> PreventionDraftResult | None:
        return None

    def find_legacy_draft(self, **kwargs) -> PreventionDraftResult | None:
        return self.find_draft(**kwargs)

    def open_draft(self, *, branch: str, candidate_sha: str, **_kwargs):
        _kwargs["before_create"]()
        before_post = _kwargs.get("before_post")
        if before_post is not None:
            before_post()
        if self.mutation_order is not None:
            self.mutation_order.append("post")
        self.open_calls += 1
        self.branch_shas[branch] = candidate_sha
        return PreventionDraftResult(
            number=20 + self.open_calls,
            html_url=f"https://github.test/guardian/pipeline/pull/{20 + self.open_calls}",
            candidate_sha=candidate_sha,
            created=True,
        )


def _base_tree(tmp_path: Path) -> Path:
    base = tmp_path / "base-tree"
    (base / "localize").mkdir(parents=True)
    (base / "tests/unit").mkdir(parents=True)
    (base / "localize/rules.py").write_text(
        "def preserve(value):\n    return value\n",
        encoding="utf-8",
    )
    (base / "tests/unit/test_rules.py").write_text(
        "def test_preserve():\n    assert True\n",
        encoding="utf-8",
    )
    return base


def _candidate(summary: str = "Placeholder validation omitted one token family"):
    return RecurrenceCandidate(
        scope="pipeline_code",
        summary=summary,
        evidence_feedback_ids=("review_comment:42",),
    )


def _coordinator(
    *,
    state: GuardianState,
    tmp_path: Path,
    broker: _FakeBroker,
    author: _FakeAuthor,
    max_drafts: int = 1,
    api_billed: bool = True,
    max_model_calls_per_day: int = 4,
    model_credential_provider=lambda: "model-key",
    test_runner: _FakeTestRunner | None = None,
    now=lambda: datetime(2026, 8, 30, 12, 0, tzinfo=UTC),
    deadline: PollDeadline | None = None,
) -> PreventionCoordinator:
    _seed_open_source_event(state)
    checkouts = tmp_path / "checkouts"
    checkouts.mkdir(parents=True)
    return PreventionCoordinator(
        state=state,
        checkout_factory=_FakeCheckoutFactory(
            _base_tree(tmp_path),
            checkouts,
            broker,
        ),
        broker_factory=lambda _policy: broker,
        author=author,
        test_runner=test_runner or _FakeTestRunner(),
        model_credential_provider=model_credential_provider,
        publish_credential_environment=lambda: {
            "GIT_ASKPASS": "/usr/bin/false",
            "LOCALIZE_GUARDIAN_GIT_TOKEN": "git-token",
        },
        signing_key="signing-key",
        signing_environment=None,
        max_drafts=max_drafts,
        reservation_usd=1.0 if api_billed else None,
        daily_limit_usd=5.0 if api_billed else None,
        max_model_calls_per_day=max_model_calls_per_day,
        api_billed=api_billed,
        temporary_root=tmp_path,
        now=now,
        deadline=deadline,
    )


def test_expired_poll_never_records_or_starts_model_attempt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = GuardianState(tmp_path / "guardian.sqlite3")
    broker = _FakeBroker()
    author = _FakeAuthor()
    clock = _FakeClock()
    deadline = PollDeadline(1, clock=clock)
    coordinator = _coordinator(
        state=state,
        tmp_path=tmp_path,
        broker=broker,
        author=author,
        deadline=deadline,
    )
    clock.advance(2)
    observed = False

    def fail_reservation(**_kwargs):
        nonlocal observed
        observed = True
        raise AssertionError("expired poll recorded a model attempt")

    monkeypatch.setattr(state, "try_reserve_model_call", fail_reservation)

    with pytest.raises(PollDeadlineExceeded):
        coordinator._reserve_and_author(  # noqa: SLF001
            run_id="run-1",
            base_workspace=_base_tree(tmp_path / "base"),
            workspace=_base_tree(tmp_path / "authoring"),
            candidate=_candidate(),
            evidence_ids=("review:1:revision-1",),
            policy=_prevention_policy(),
            require_live_lease=_live_lease,
            require_cleanup_lease=_live_lease,
        )

    assert observed is False
    assert author.calls == 0


def _ledger_attestation(
    policy: RepositoryPolicy | None = None,
    *,
    base_sha: str = BASE_SHA,
    candidate_sha: str = CANDIDATE_SHA,
) -> dict[str, object]:
    repository_policy = policy or _repository_policy()
    source_policy_json, source_policy_digest = (
        prevention_runtime._source_policy_attestation(  # noqa: SLF001
            repository_policy
        )
    )
    assert repository_policy.prevention is not None
    test_results = tuple(
        result
        for argv in repository_policy.prevention.focused_test_argv
        for result in (
            TestCommandResult(
                phase="base",
                outcome=TestOutcome.FAILED,
                argv=argv,
                commit_sha=base_sha,
                parent_sha=None,
                returncode=1,
                test_overlay_hash="f" * 64,
            ),
            TestCommandResult(
                phase="patched",
                outcome=TestOutcome.PASSED,
                argv=argv,
                commit_sha=candidate_sha,
                parent_sha=base_sha,
                returncode=0,
                test_overlay_hash="f" * 64,
            ),
        )
    )
    tests, test_digest = prevention_runtime._test_attestation(  # noqa: SLF001
        policy=repository_policy.prevention,
        test_results=test_results,
    )
    return {
        "source_policy_json": source_policy_json,
        "source_policy_digest": source_policy_digest,
        "patch_paths": ("localize/rules.py", "tests/unit/test_rules.py"),
        "patch_hash": "e" * 64,
        "test_attestation_json": tests,
        "test_attestation_digest": test_digest,
        "open_source": _open_source(),
        "source_pulls": (),
        "event_revision_ids": (OPEN_SOURCE_REVISION_ID,),
    }


def _pending_prevention_ledger(
    state: GuardianState,
    *,
    now: datetime,
    policy: RepositoryPolicy | None = None,
    evidence_hash: str = "d" * 64,
    candidate_sha: str = CANDIDATE_SHA,
    target_base_sha: str = BASE_SHA,
    phase: str = "pushed",
    source_pulls: tuple[HistoricalPullReference, ...] = (),
    event_revision_ids: tuple[int, ...] = (OPEN_SOURCE_REVISION_ID,),
) -> tuple[str, dict[str, object]]:
    if not source_pulls:
        assert _seed_open_source_event(state) == OPEN_SOURCE_REVISION_ID
    source_policy = policy or _repository_policy()
    run_id = state.start_run(
        repository=source_policy.base_repo,
        locale="ru",
        mode=GuardianMode.PROPOSE_PREVENTION,
        started_at=now,
    )
    branch = f"guardian/prevention-{target_base_sha[:12]}-{evidence_hash}"
    ledger: dict[str, object] = {
        "run_id": run_id,
        "source_repository": source_policy.base_repo,
        "target_repository": "guardian/pipeline",
        "target_base_branch": "main",
        "target_base_sha": target_base_sha,
        "push_repository": "guardian/pipeline",
        "branch": branch,
        "candidate_sha": candidate_sha,
        "evidence_hash": evidence_hash,
        **{
            **_ledger_attestation(
                source_policy,
                base_sha=target_base_sha,
                candidate_sha=candidate_sha,
            ),
            "open_source": None if source_pulls else _open_source(),
            "source_pulls": source_pulls,
            "event_revision_ids": event_revision_ids,
        },
        "title": "Prevent recurrence: placeholder parity",
        "body": "Validated body\n",
    }
    draft_key = state.record_prevention_draft_event(
        **ledger,
        phase="validated",
        occurred_at=now,
    )
    if phase == "pushed":
        state.record_prevention_draft_event(
            **ledger,
            phase="pushed",
            occurred_at=now,
        )
    return draft_key, ledger


def _create_v1_prevention_database(
    database: Path,
    *,
    phase: str,
    evidence_hash: str,
    now: datetime,
    title: str = "Prevent recurrence: placeholder parity",
    target_repository: str = "guardian/pipeline",
    push_repository: str = "guardian/pipeline",
    corrupt_latest: bool = False,
    stored_draft_key: str | None = None,
) -> tuple[str, str]:
    """Create the exact released-v1 prevention tables and one candidate."""

    branch = f"guardian/prevention-{BASE_SHA[:12]}-{evidence_hash}"
    draft_key = guardian_state._legacy_prevention_draft_key(  # noqa: SLF001
        source_repository="acme/translations",
        target_repository=target_repository,
        target_base_branch="main",
        target_base_sha=BASE_SHA,
        candidate_sha=CANDIDATE_SHA,
        evidence_hash=evidence_hash,
    )
    persisted_draft_key = stored_draft_key or draft_key
    run_id = "released-v1-prevention"
    timestamp = guardian_state._serialize_datetime(now)  # noqa: SLF001
    with sqlite3.connect(database) as connection:
        connection.executescript(
            """
            CREATE TABLE runs (
                run_id TEXT PRIMARY KEY,
                repository TEXT NOT NULL,
                locale TEXT NOT NULL,
                mode TEXT NOT NULL,
                status TEXT NOT NULL,
                started_at TEXT NOT NULL,
                finished_at TEXT,
                summary TEXT
            );
            CREATE TABLE prevention_draft_events (
                prevention_event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                draft_key TEXT NOT NULL,
                run_id TEXT NOT NULL,
                source_repository TEXT NOT NULL,
                target_repository TEXT NOT NULL,
                target_base_branch TEXT NOT NULL,
                target_base_sha TEXT NOT NULL,
                push_repository TEXT NOT NULL,
                branch TEXT NOT NULL,
                candidate_sha TEXT NOT NULL,
                evidence_hash TEXT NOT NULL,
                title TEXT NOT NULL,
                body TEXT NOT NULL,
                phase TEXT NOT NULL CHECK (
                    phase IN ('validated', 'pushed', 'draft_opened', 'abandoned')
                ),
                draft_number INTEGER,
                draft_url TEXT,
                occurred_at TEXT NOT NULL,
                UNIQUE (draft_key, phase),
                FOREIGN KEY (run_id) REFERENCES runs(run_id)
            );
            PRAGMA user_version = 1;
            """
        )
        connection.execute(
            """
            INSERT INTO runs (
                run_id, repository, locale, mode, status, started_at
            ) VALUES (?, 'acme/translations', 'ru', ?, 'completed', ?)
            """,
            (run_id, GuardianMode.PROPOSE_PREVENTION.value, timestamp),
        )
        phases = {
            "validated": ("validated",),
            "pushed": ("validated", "pushed"),
            "draft_opened": ("validated", "pushed", "draft_opened"),
            "abandoned": ("validated", "abandoned"),
        }[phase]
        for candidate_phase in phases:
            opened = candidate_phase == "draft_opened"
            connection.execute(
                """
                INSERT INTO prevention_draft_events (
                    draft_key, run_id, source_repository, target_repository,
                    target_base_branch, target_base_sha, push_repository,
                    branch, candidate_sha, evidence_hash, title, body, phase,
                    draft_number, draft_url, occurred_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    persisted_draft_key,
                    run_id,
                    "acme/translations",
                    target_repository,
                    "main",
                    BASE_SHA,
                    push_repository,
                    branch,
                    CANDIDATE_SHA,
                    evidence_hash,
                    title,
                    "Validated body\n",
                    candidate_phase,
                    91 if opened else None,
                    (
                        "https://github.test/guardian/pipeline/pull/91"
                        if opened
                        else None
                    ),
                    timestamp,
                ),
            )
        if corrupt_latest:
            connection.execute(
                """
                INSERT INTO prevention_draft_events (
                    draft_key, run_id, source_repository, target_repository,
                    target_base_branch, target_base_sha, push_repository,
                    branch, candidate_sha, evidence_hash, title, body, phase,
                    draft_number, draft_url, occurred_at
                )
                SELECT draft_key, run_id, source_repository, target_repository,
                       target_base_branch, target_base_sha, push_repository,
                       branch, candidate_sha, evidence_hash, title || ' changed',
                       body, 'draft_opened', 91,
                       'https://github.test/guardian/pipeline/pull/91', occurred_at
                FROM prevention_draft_events
                WHERE phase = 'pushed'
                """
            )
    database.chmod(0o600)
    return persisted_draft_key, branch


def _insert_self_consistent_corrupt_prevention(
    state: GuardianState,
    *,
    run_id: str,
    branch: str,
    occurred_at: str,
    source_policy_json: str | None = None,
    source_pulls: tuple[HistoricalPullReference, ...] = (),
    body: str = "Validated body\n",
    source_repository: str = "acme/translations",
    source_repository_id: int = 42,
    stored_draft_key: str | None = None,
) -> str:
    """Insert a key-consistent legacy row that bypasses public write checks."""

    attestation = _ledger_attestation()
    patch_paths_json = guardian_state._canonical_attestation_json(  # noqa: SLF001
        list(attestation["patch_paths"])
    )
    open_source_json = guardian_state._open_pull_authority_json(  # noqa: SLF001
        None if source_pulls else attestation["open_source"]
    )
    source_pulls_json = guardian_state._prevention_source_pulls_json(  # noqa: SLF001
        source_pulls
    )
    revision_ids_json = guardian_state._canonical_attestation_json(  # noqa: SLF001
        list(attestation["event_revision_ids"])
    )
    persisted_policy_json = source_policy_json or str(attestation["source_policy_json"])
    identity = {
        "run_id": run_id,
        "source_repository": source_repository,
        "target_repository": "guardian/pipeline",
        "target_base_branch": "main",
        "target_base_sha": BASE_SHA,
        "push_repository": "guardian/pipeline",
        "branch": branch,
        "candidate_sha": CANDIDATE_SHA,
        "evidence_hash": "6" * 64,
        "source_policy_json": persisted_policy_json,
        "source_policy_digest": hashlib.sha256(
            persisted_policy_json.encode("ascii")
        ).hexdigest(),
        "patch_paths_json": patch_paths_json,
        "patch_hash": attestation["patch_hash"],
        "test_attestation_json": attestation["test_attestation_json"],
        "test_attestation_digest": attestation["test_attestation_digest"],
        "open_source_json": open_source_json,
        "source_pulls_json": source_pulls_json,
        "event_revision_ids_json": revision_ids_json,
        "title": "Prevent recurrence: corrupt persisted identity",
        "body": body,
    }
    draft_key = stored_draft_key or (
        hashlib.sha256(f"corrupt:{persisted_policy_json}".encode()).hexdigest()
        if source_policy_json is not None
        else guardian_state._prevention_draft_key(  # noqa: SLF001
            **identity
        )
    )
    state._connection.execute(  # noqa: SLF001 - corrupt legacy fixture
        """
            INSERT INTO prevention_candidate_attestations (
                draft_key, attestation_version, source_repository_id,
                target_repository_id, push_repository_id, source_policy_json,
                source_policy_digest, patch_paths_json, patch_hash,
                test_attestation_json, test_attestation_digest,
                open_source_json, source_pulls_json,
                event_revision_ids_json, occurred_at
            ) VALUES (?, 3, ?, 101, 101, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            draft_key,
            source_repository_id,
            identity["source_policy_json"],
            identity["source_policy_digest"],
            identity["patch_paths_json"],
            identity["patch_hash"],
            identity["test_attestation_json"],
            identity["test_attestation_digest"],
            identity["open_source_json"],
            identity["source_pulls_json"],
            identity["event_revision_ids_json"],
            "2026-08-30T12:00:00.000000Z",
        ),
    )
    state._connection.execute(  # noqa: SLF001 - corrupt legacy fixture
        """
        INSERT INTO prevention_draft_events (
            draft_key, run_id, source_repository, target_repository,
            target_base_branch, target_base_sha, push_repository,
            branch, candidate_sha, evidence_hash, title, body, phase,
            occurred_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'validated', ?)
        """,
        (
            draft_key,
            identity["run_id"],
            identity["source_repository"],
            identity["target_repository"],
            identity["target_base_branch"],
            identity["target_base_sha"],
            identity["push_repository"],
            identity["branch"],
            identity["candidate_sha"],
            identity["evidence_hash"],
            identity["title"],
            identity["body"],
            occurred_at,
        ),
    )
    state._connection.commit()  # noqa: SLF001 - corrupt legacy fixture
    return draft_key


def _historical_prevention_source(
    state: GuardianState,
    *,
    now: datetime,
) -> tuple[HistoricalPullReference, int]:
    head_sha = "c" * 40
    base_sha = "d" * 40
    revision = state.record_feedback_event(
        FeedbackEvent(
            repository="acme/translations",
            pr_number=12,
            kind="review_comment",
            event_id="42",
            author="coderabbitai[bot]",
            author_id=202,
            author_type="Bot",
            body="Prevent this placeholder regression.",
            head_sha=head_sha,
            base_sha=base_sha,
            locale="ru",
            updated_at="2026-08-30T08:00:00Z",
            path="l10n/messages_ru.properties",
            line=17,
            html_url=("https://github.test/acme/translations/pull/12#discussion_r42"),
        ),
        observed_at=now,
    )
    source = HistoricalPullReference(
        repository="acme/translations",
        repository_id=42,
        pull_id=500,
        pr_number=12,
        pull_revision_digest="1" * 64,
        authority_digest="2" * 64,
        policy_digest="3" * 64,
        head_sha=head_sha,
        base_sha=base_sha,
    )
    state.record_historical_pull_completion(
        repository=source.repository,
        repository_id=source.repository_id,
        pull_id=source.pull_id,
        pr_number=source.pr_number,
        pull_revision_digest=source.pull_revision_digest,
        policy_digest=source.policy_digest,
        head_sha=source.head_sha,
        base_sha=source.base_sha,
        event_revision_ids=(revision.revision_id,),
        authority_scope=HistoricalCheckScope.ASSESSMENT,
        completed_at=now,
    )
    return source, revision.revision_id


def test_coordinator_authors_proves_signs_publishes_draft_and_deduplicates(
    tmp_path: Path,
) -> None:
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
    with GuardianState(tmp_path / "state.sqlite3") as state:
        run_id = state.start_run(
            repository="acme/translations",
            locale="ru",
            mode=GuardianMode.PROPOSE_PREVENTION,
            started_at=now,
        )
        broker = _FakeBroker()
        author = _FakeAuthor()
        coordinator = _coordinator(
            state=state,
            tmp_path=tmp_path,
            broker=broker,
            author=author,
        )
        outcome = coordinator.propose(
            policy=_repository_policy(),
            recurrence_candidates=(_candidate(), _candidate()),
            evidence_revision_ids={"review_comment:42": OPEN_SOURCE_REVISION_ID},
            run_id=run_id,
            observed_at=now,
            require_live_lease=_live_lease,
            require_current_base_unchanged=_current_base,
            **_open_source_kwargs(),
        )

        assert len(outcome.drafts) == 1
        assert outcome.failures == ()
        assert outcome.skipped == 1
        assert author.calls == 1
        assert broker.open_calls == 1
        assert broker.verify_calls == 2
        assert state.pending_prevention_drafts() == ()
        opened = state.opened_prevention_evidence_hashes(
            source_repository_id=42,
            target_repository_id=101,
        )
        assert len(opened) == 1

        next_run = state.start_run(
            repository="acme/translations",
            locale="ru",
            mode=GuardianMode.PROPOSE_PREVENTION,
            started_at=now,
        )
        duplicate = coordinator.propose(
            policy=_repository_policy(),
            recurrence_candidates=(_candidate(),),
            evidence_revision_ids={"review_comment:42": OPEN_SOURCE_REVISION_ID},
            run_id=next_run,
            observed_at=now,
            require_live_lease=_live_lease,
            require_current_base_unchanged=_current_base,
            **_open_source_kwargs(),
        )
        assert duplicate.drafts == ()
        assert duplicate.skipped == 1
        assert author.calls == 1


def test_api_key_in_allowlisted_candidate_stops_before_any_later_side_effect(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret = "sk-guardian-candidate-regression-secret"
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)

    class CredentialLeakingAuthor(_FakeAuthor):
        def run(self, *, workspace: Path, **_kwargs) -> PreventionAuthorResult:
            self.calls += 1
            (workspace / "localize/rules.py").write_text(
                f'MODEL_CREDENTIAL = "{secret}"\n',
                encoding="utf-8",
            )
            (workspace / "tests/unit/test_rules.py").write_text(
                "def test_preserve():\n    assert True\n",
                encoding="utf-8",
            )
            return PreventionAuthorResult(attempts=1, usage=None)

    class ForbiddenTestRunner(_FakeTestRunner):
        def run_pair(self, **_kwargs):
            raise AssertionError("credential-bearing candidates must never run tests")

    def forbidden_patch_inspection(**_kwargs):
        raise AssertionError(
            "credential scan must precede patch diagnostics and downstream work"
        )

    monkeypatch.setattr(
        prevention_runtime,
        "inspect_prevention_patch",
        forbidden_patch_inspection,
    )
    with GuardianState(tmp_path / "state.sqlite3") as state:
        run_id = state.start_run(
            repository="acme/translations",
            locale="ru",
            mode=GuardianMode.PROPOSE_PREVENTION,
            started_at=now,
        )
        broker = _FakeBroker()
        author = CredentialLeakingAuthor()
        coordinator = _coordinator(
            state=state,
            tmp_path=tmp_path,
            broker=broker,
            author=author,
            model_credential_provider=lambda: secret,
            test_runner=ForbiddenTestRunner(),
        )

        def forbidden_candidate_state(**_kwargs):
            raise AssertionError(
                "credential-bearing candidates must never reach the draft ledger"
            )

        monkeypatch.setattr(
            state,
            "record_prevention_draft_event",
            forbidden_candidate_state,
        )

        outcome = coordinator.propose(
            policy=_repository_policy(),
            recurrence_candidates=(_candidate(),),
            evidence_revision_ids={"review_comment:42": OPEN_SOURCE_REVISION_ID},
            run_id=run_id,
            observed_at=now,
            require_live_lease=_live_lease,
            require_current_base_unchanged=_current_base,
            **_open_source_kwargs(),
        )

        assert outcome.drafts == ()
        assert outcome.failures == ("PreventionRuntimeError",)
        assert secret not in repr(outcome)
        assert author.calls == 1
        assert broker.verify_calls == 0
        assert broker.open_calls == 0
        assert broker.branch_shas == {}
        assert coordinator.checkout_factory.calls == 1
        assert coordinator.checkout_factory.publications == 0
        assert state.pending_prevention_drafts() == ()


def test_new_proposal_reconciles_exact_pr_before_base_or_branch_revalidation(
    tmp_path: Path,
) -> None:
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)

    class PostResponseLostBroker(_FakeBroker):
        def verify_publish_authority(self, **_kwargs: object) -> None:
            raise AssertionError(
                "exact post-crash PR must precede base and branch revalidation"
            )

        def branch_sha(self, _branch: str) -> str | None:
            raise AssertionError(
                "exact post-crash PR must precede branch existence checks"
            )

        def find_draft(
            self, *, candidate_sha: str, **_kwargs: object
        ) -> PreventionDraftResult:
            return PreventionDraftResult(
                number=49,
                html_url="https://github.test/guardian/pipeline/pull/49",
                candidate_sha=candidate_sha,
                created=False,
            )

    with GuardianState(tmp_path / "state.sqlite3") as state:
        run_id = state.start_run(
            repository="acme/translations",
            locale="ru",
            mode=GuardianMode.PROPOSE_PREVENTION,
            started_at=now,
        )
        broker = PostResponseLostBroker()
        author = _FakeAuthor()
        source_checks = 0

        def exact_source(
            _source: OpenPullAuthorityReference,
            _revision_ids: Sequence[int],
        ) -> None:
            nonlocal source_checks
            source_checks += 1

        def moved_base() -> None:
            raise AssertionError(
                "exact post-crash PR must reconcile despite a moved target base"
            )

        outcome = _coordinator(
            state=state,
            tmp_path=tmp_path,
            broker=broker,
            author=author,
        ).propose(
            policy=_repository_policy(),
            recurrence_candidates=(_candidate(),),
            evidence_revision_ids={"review_comment:42": OPEN_SOURCE_REVISION_ID},
            run_id=run_id,
            observed_at=now,
            require_live_lease=_live_lease,
            require_current_base_unchanged=moved_base,
            open_source=_open_source(),
            source_event_revision_ids=(OPEN_SOURCE_REVISION_ID,),
            require_exact_open_source_authority=exact_source,
        )

        assert [draft.number for draft in outcome.drafts] == [49]
        assert outcome.drafts[0].created is False
        assert outcome.failures == ()
        assert author.calls == 1
        assert source_checks == 3
        assert broker.open_calls == 0
        assert broker.branch_shas == {}
        assert state.pending_prevention_drafts() == ()


@pytest.mark.parametrize(
    "invalid_policy",
    ["too-many-files", "too-many-test-commands", "oversized-test-attestation"],
)
def test_coordinator_rejects_state_bound_mismatch_before_model_or_tests(
    invalid_policy: str,
    tmp_path: Path,
) -> None:
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
    prevention = _prevention_policy()
    if invalid_policy == "too-many-files":
        # Simulate a corrupted legacy/state object that bypassed current model
        # construction so the runtime boundary remains independently covered.
        object.__setattr__(prevention, "max_changed_files", 101)
    elif invalid_policy == "too-many-test-commands":
        object.__setattr__(
            prevention,
            "focused_test_argv",
            tuple(
                ("/opt/localize-guardian/bin/pytest", f"test-{index}")
                for index in range(65)
            ),
        )
    else:
        large_argv = ("/opt/localize-guardian/bin/pytest",) + ("x" * 4096,) * 48
        prevention = replace(prevention, focused_test_argv=(large_argv,))
    policy = replace(_repository_policy(), prevention=prevention)
    with GuardianState(tmp_path / "state.sqlite3") as state:
        run_id = state.start_run(
            repository=policy.base_repo,
            locale="ru",
            mode=GuardianMode.PROPOSE_PREVENTION,
            started_at=now,
        )
        broker = _FakeBroker()
        author = _FakeAuthor()
        coordinator = _coordinator(
            state=state,
            tmp_path=tmp_path,
            broker=broker,
            author=author,
        )

        with pytest.raises(
            PreventionPolicyError,
            match="(?:attestation|execution) bound",
        ):
            coordinator.propose(
                policy=policy,
                recurrence_candidates=(_candidate(),),
                evidence_revision_ids={
                    "review_comment:42": OPEN_SOURCE_REVISION_ID,
                },
                run_id=run_id,
                observed_at=now,
                require_live_lease=_live_lease,
                require_current_base_unchanged=_current_base,
                **_open_source_kwargs(),
            )

        assert author.calls == 0
        assert broker.capture_calls == 0


def test_coordinator_rejects_oversized_candidate_evidence_before_lookup_or_model(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
    candidate = _candidate()
    # Preserve runtime defense-in-depth coverage for a corrupted typed object;
    # normal direct construction now rejects this oversized workset earlier.
    object.__setattr__(
        candidate,
        "evidence_feedback_ids",
        tuple(f"review_comment:{index}" for index in range(101)),
    )
    with GuardianState(tmp_path / "state.sqlite3") as state:
        run_id = state.start_run(
            repository="acme/translations",
            locale="ru",
            mode=GuardianMode.PROPOSE_PREVENTION,
            started_at=now,
        )
        broker = _FakeBroker()
        author = _FakeAuthor()

        def forbidden_binding_lookup(**_kwargs: object) -> None:
            raise AssertionError("oversized evidence must not reach a state lookup")

        monkeypatch.setattr(
            state,
            "validate_prevention_evidence_bindings",
            forbidden_binding_lookup,
        )
        outcome = _coordinator(
            state=state,
            tmp_path=tmp_path,
            broker=broker,
            author=author,
        ).propose(
            policy=_repository_policy(),
            recurrence_candidates=(candidate,),
            evidence_revision_ids={
                feedback_id: OPEN_SOURCE_REVISION_ID
                for feedback_id in candidate.evidence_feedback_ids
            },
            run_id=run_id,
            observed_at=now,
            require_live_lease=_live_lease,
            require_current_base_unchanged=_current_base,
            **_open_source_kwargs(),
        )

        assert outcome.failures == ("InvalidRecurrenceEvidence",)
        assert author.calls == 0
        assert broker.capture_calls == 0


def test_coordinator_rejects_swapped_feedback_revision_bindings_before_model(
    tmp_path: Path,
) -> None:
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
    with GuardianState(tmp_path / "state.sqlite3") as state:
        run_id = state.start_run(
            repository="acme/translations",
            locale="ru",
            mode=GuardianMode.PROPOSE_PREVENTION,
            started_at=now,
        )
        broker = _FakeBroker()
        author = _FakeAuthor()
        coordinator = _coordinator(
            state=state,
            tmp_path=tmp_path,
            broker=broker,
            author=author,
        )
        source = _open_source()
        second = state.record_feedback_event(
            FeedbackEvent(
                repository=source.repository,
                pr_number=source.pr_number,
                kind="review_comment",
                event_id="43",
                author="coderabbitai[bot]",
                author_id=202,
                author_type="Bot",
                body="Prevent another regression.",
                head_sha=source.head_sha,
                base_sha=source.base_sha,
                locale="ru",
                updated_at="2026-08-30T08:01:00Z",
            ),
            observed_at=now,
        )
        candidate = replace(
            _candidate(),
            evidence_feedback_ids=("review_comment:42", "review_comment:43"),
        )

        outcome = coordinator.propose(
            policy=_repository_policy(),
            recurrence_candidates=(candidate,),
            evidence_revision_ids={
                "review_comment:42": second.revision_id,
                "review_comment:43": OPEN_SOURCE_REVISION_ID,
            },
            run_id=run_id,
            observed_at=now,
            require_live_lease=_live_lease,
            require_current_base_unchanged=_current_base,
            open_source=source,
            source_event_revision_ids=(OPEN_SOURCE_REVISION_ID, second.revision_id),
            require_exact_open_source_authority=_open_source_authority,
        )

        assert outcome.failures == ("InvalidRecurrenceEvidence",)
        assert author.calls == 0
        assert broker.capture_calls == 0


def test_coordinator_rejects_deleted_exact_source_before_model(
    tmp_path: Path,
) -> None:
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
    with GuardianState(tmp_path / "state.sqlite3") as state:
        run_id = state.start_run(
            repository="acme/translations",
            locale="ru",
            mode=GuardianMode.PROPOSE_PREVENTION,
            started_at=now,
        )
        broker = _FakeBroker()
        author = _FakeAuthor()
        coordinator = _coordinator(
            state=state,
            tmp_path=tmp_path,
            broker=broker,
            author=author,
        )
        source = _open_source()
        deleted = state.record_feedback_event(
            FeedbackEvent(
                repository=source.repository,
                pr_number=source.pr_number,
                kind="review_comment",
                event_id="42",
                author="coderabbitai[bot]",
                author_id=202,
                author_type="Bot",
                body="",
                head_sha=source.head_sha,
                base_sha=source.base_sha,
                locale="ru",
                updated_at="2026-08-30T08:01:00Z",
                deleted=True,
            ),
            observed_at=now,
        )

        outcome = coordinator.propose(
            policy=_repository_policy(),
            recurrence_candidates=(_candidate(),),
            evidence_revision_ids={"review_comment:42": deleted.revision_id},
            run_id=run_id,
            observed_at=now,
            require_live_lease=_live_lease,
            require_current_base_unchanged=_current_base,
            open_source=source,
            source_event_revision_ids=(deleted.revision_id,),
            require_exact_open_source_authority=_open_source_authority,
        )

        assert outcome.failures == ("InvalidRecurrenceEvidence",)
        assert author.calls == 0
        assert broker.capture_calls == 0


def test_prevention_tests_run_only_against_the_frozen_signed_tree(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
    copied_to_signing = False
    copy_regular_paths = prevention_runtime._copy_regular_paths  # noqa: SLF001

    def mutate_author_after_signing_copy(
        source: Path,
        destination: Path,
        paths: Sequence[str],
    ) -> None:
        nonlocal copied_to_signing
        copy_regular_paths(source, destination, paths)
        if source.name == "author" and not copied_to_signing:
            copied_to_signing = True
            (source / "localize/rules.py").write_text(
                "MUTATED AFTER VALIDATION\n",
                encoding="utf-8",
            )
            (source / "tests/unit/test_rules.py").write_text(
                "MUTATED AFTER VALIDATION\n",
                encoding="utf-8",
            )

    class SignedTreeTestRunner(_FakeTestRunner):
        def run_pair(
            self,
            *,
            base_workspace: Path,
            candidate_workspace: Path,
            **kwargs: object,
        ) -> tuple[TestCommandResult, ...]:
            assert (base_workspace / "localize/rules.py").read_text(
                encoding="utf-8"
            ) == "def preserve(value):\n    return value\n"
            assert (base_workspace / "tests/unit/test_rules.py").read_text(
                encoding="utf-8"
            ) == "def test_preserve():\n    assert preserve(' value ') == 'value'\n"
            assert (candidate_workspace / "localize/rules.py").read_text(
                encoding="utf-8"
            ) == "def preserve(value):\n    return value.strip()\n"
            assert (candidate_workspace / "tests/unit/test_rules.py").read_text(
                encoding="utf-8"
            ) == "def test_preserve():\n    assert preserve(' value ') == 'value'\n"
            return super().run_pair(**kwargs)

    monkeypatch.setattr(
        prevention_runtime,
        "_copy_regular_paths",
        mutate_author_after_signing_copy,
    )
    with GuardianState(tmp_path / "state.sqlite3") as state:
        run_id = state.start_run(
            repository="acme/translations",
            locale="ru",
            mode=GuardianMode.PROPOSE_PREVENTION,
            started_at=now,
        )
        outcome = _coordinator(
            state=state,
            tmp_path=tmp_path,
            broker=_FakeBroker(),
            author=_FakeAuthor(),
            test_runner=SignedTreeTestRunner(),
        ).propose(
            policy=_repository_policy(),
            recurrence_candidates=(_candidate(),),
            evidence_revision_ids={
                "review_comment:42": OPEN_SOURCE_REVISION_ID,
            },
            run_id=run_id,
            observed_at=now,
            require_live_lease=_live_lease,
            require_current_base_unchanged=_current_base,
            **_open_source_kwargs(),
        )

        assert copied_to_signing is True
        assert len(outcome.drafts) == 1


def test_coordinator_requires_current_base_callback_on_both_entry_points(
    tmp_path: Path,
) -> None:
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
    with GuardianState(tmp_path / "state.sqlite3") as state:
        coordinator = _coordinator(
            state=state,
            tmp_path=tmp_path,
            broker=_FakeBroker(),
            author=_FakeAuthor(),
        )
        with pytest.raises(TypeError, match="require_current_base_unchanged"):
            coordinator.recover(
                policy=_repository_policy(),
                observed_at=now,
                require_live_lease=_live_lease,
                require_current_base_unchanged=None,  # type: ignore[arg-type]
            )
        with pytest.raises(TypeError, match="require_current_base_unchanged"):
            coordinator.propose(
                policy=_repository_policy(),
                recurrence_candidates=(),
                evidence_revision_ids={},
                run_id="unused",
                observed_at=now,
                require_live_lease=_live_lease,
                require_current_base_unchanged=None,  # type: ignore[arg-type]
            )


def test_coordinator_revalidates_current_base_at_remote_and_terminal_boundaries(
    tmp_path: Path,
) -> None:
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
    order: list[str] = []
    with GuardianState(tmp_path / "state.sqlite3") as state:
        run_id = state.start_run(
            repository="acme/translations",
            locale="ru",
            mode=GuardianMode.PROPOSE_PREVENTION,
            started_at=now,
        )
        coordinator = _coordinator(
            state=state,
            tmp_path=tmp_path,
            broker=_FakeBroker(mutation_order=order),
            author=_FakeAuthor(),
        )

        outcome = coordinator.propose(
            policy=_repository_policy(),
            recurrence_candidates=(_candidate(),),
            evidence_revision_ids={"review_comment:42": OPEN_SOURCE_REVISION_ID},
            run_id=run_id,
            observed_at=now,
            require_live_lease=_live_lease,
            require_current_base_unchanged=lambda: order.append("base"),
            **_open_source_kwargs(),
        )

        assert len(outcome.drafts) == 1
        assert order == ["base", "base", "push", "base", "post", "base"]
        assert state.pending_prevention_drafts() == ()
        row = state._connection.execute(  # noqa: SLF001 - inspect durable ledger
            "SELECT draft_key FROM prevention_draft_events WHERE phase = 'draft_opened'"
        ).fetchone()
        assert row is not None
        record = state.prevention_draft_by_key(str(row["draft_key"]))
        assert record is not None
        policy_attestation = json.loads(record.source_policy_json)
        assert policy_attestation["repository_policy"] == {
            "allowed_branch_globs": ["translation-*"],
            "allowed_head_owners": [
                {"id": 8, "login": "translation-bot", "type": "Organization"}
            ],
            "allowed_head_repositories": [
                {"full_name": "translation-bot/translations", "id": 84}
            ],
            "allowed_path_globs": ["l10n/*.properties"],
            "allowed_pr_authors": [
                {"id": 7, "login": "translation-bot", "type": "User"}
            ],
            "base_branch": "main",
            "base_repo": "acme/translations",
            "base_repo_id": 42,
            "closed_pr_backfill": None,
            "pipeline_config_path": "config.yaml",
            "pipeline_config_source": "base",
            "publication_actor": {
                "id": 301,
                "login": "guardian-publisher",
                "type": "User",
            },
            "prevention": {
                "allowed_code_path_globs": ["localize/*.py"],
                "allowed_test_path_globs": ["tests/**/*.py"],
                "focused_test_argv": [
                    [
                        "/opt/localize-guardian/bin/pytest",
                        "tests/unit/test_rules.py",
                        "-q",
                    ]
                ],
                "max_changed_bytes": 16_384,
                "max_changed_files": 4,
                "private_target_model_opt_in": False,
                "publication_actor": {
                    "id": 301,
                    "login": "guardian-publisher",
                    "type": "User",
                },
                "push_branch_prefix": "guardian/prevention-",
                "push_repository": {"full_name": "guardian/pipeline", "id": 101},
                "sandbox_argv_prefix": [
                    "/usr/bin/guardian-sandbox-wrapper",
                ],
                "target_base_branch": "main",
                "target_repository": {
                    "full_name": "guardian/pipeline",
                    "id": 101,
                },
            },
            "private_repo_model_opt_in": False,
            "source_locale": "en",
            "trusted_bots": {},
            "trusted_reviewers": {
                "ru": [{"id": 9, "login": "reviewer", "type": "User"}]
            },
        }
        assert record.patch_paths == (
            "localize/rules.py",
            "tests/unit/test_rules.py",
        )
        assert len(record.patch_hash) == 64
        test_attestation = json.loads(record.test_attestation_json)
        assert test_attestation["configured_focused_test_argv"] == [
            [
                "/opt/localize-guardian/bin/pytest",
                "tests/unit/test_rules.py",
                "-q",
            ]
        ]
        assert [result["outcome"] for result in test_attestation["results"]] == [
            "failed",
            "passed",
        ]
        assert [result["commit_sha"] for result in test_attestation["results"]] == [
            BASE_SHA,
            CANDIDATE_SHA,
        ]


def test_attested_prevention_policy_round_trips_at_collection_bounds() -> None:
    repository_policy = _repository_policy()
    assert repository_policy.prevention is not None
    prevention = replace(
        repository_policy.prevention,
        allowed_code_path_globs=tuple(f"code/{index}.py" for index in range(100)),
        allowed_test_path_globs=tuple(f"tests/test_{index}.py" for index in range(100)),
        focused_test_argv=tuple(
            (
                "/opt/test",
                f"command-{command_index}",
                *(f"arg-{arg_index}" for arg_index in range(254)),
            )
            for command_index in range(64)
        ),
        max_changed_files=100,
    )
    bounded_policy = replace(repository_policy, prevention=prevention)

    prevention_runtime._validate_authoring_policy_bounds(bounded_policy)  # noqa: SLF001
    encoded, _digest = prevention_runtime._source_policy_attestation(  # noqa: SLF001
        bounded_policy
    )

    assert (
        prevention_runtime._prevention_policy_from_attestation(  # noqa: SLF001
            encoded
        )
        == prevention
    )


def test_historical_prevention_revalidates_sources_at_push_post_and_completion(
    tmp_path: Path,
) -> None:
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
    order: list[str] = []
    with GuardianState(tmp_path / "state.sqlite3") as state:
        run_id = state.start_run(
            repository="acme/translations",
            locale="ru",
            mode=GuardianMode.PROPOSE_PREVENTION,
            started_at=now,
        )
        source, revision_id = _historical_prevention_source(state, now=now)
        coordinator = _coordinator(
            state=state,
            tmp_path=tmp_path,
            broker=_FakeBroker(mutation_order=order),
            author=_FakeAuthor(),
        )

        def require_sources(
            sources: Sequence[HistoricalPullReference],
            revisions: Sequence[int],
        ) -> None:
            assert tuple(sources) == (source,)
            assert tuple(revisions) == (revision_id,)
            order.append("source")

        outcome = coordinator.propose(
            policy=_repository_policy(),
            recurrence_candidates=(_candidate(),),
            evidence_revision_ids={"review_comment:42": revision_id},
            run_id=run_id,
            observed_at=now,
            require_live_lease=_live_lease,
            require_current_base_unchanged=_current_base,
            source_pulls=(source,),
            source_event_revision_ids=(revision_id,),
            require_exact_sources_still_closed=require_sources,
        )

        assert len(outcome.drafts) == 1
        push_index = order.index("push")
        post_index = order.index("post")
        assert order[push_index - 1] == "source"
        assert order[post_index - 1] == "source"
        assert order[-1] == "source"
        assert state.pending_prevention_drafts() == ()


def test_open_prevention_revalidates_exact_source_at_push_post_and_completion(
    tmp_path: Path,
) -> None:
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
    order: list[str] = []
    source = _open_source()
    with GuardianState(tmp_path / "state.sqlite3") as state:
        run_id = state.start_run(
            repository="acme/translations",
            locale="ru",
            mode=GuardianMode.PROPOSE_PREVENTION,
            started_at=now,
        )
        coordinator = _coordinator(
            state=state,
            tmp_path=tmp_path,
            broker=_FakeBroker(mutation_order=order),
            author=_FakeAuthor(),
        )

        def require_source(
            observed_source: OpenPullAuthorityReference,
            revisions: Sequence[int],
        ) -> None:
            assert observed_source == source
            assert tuple(revisions) == (OPEN_SOURCE_REVISION_ID,)
            order.append("source")

        outcome = coordinator.propose(
            policy=_repository_policy(),
            recurrence_candidates=(_candidate(),),
            evidence_revision_ids={"review_comment:42": OPEN_SOURCE_REVISION_ID},
            run_id=run_id,
            observed_at=now,
            require_live_lease=_live_lease,
            require_current_base_unchanged=_current_base,
            open_source=source,
            source_event_revision_ids=(OPEN_SOURCE_REVISION_ID,),
            require_exact_open_source_authority=require_source,
        )

        assert len(outcome.drafts) == 1
        assert order[order.index("push") - 1] == "source"
        assert order[order.index("post") - 1] == "source"
        assert order[-1] == "source"


def test_successful_post_is_durable_before_source_authority_is_revoked(
    tmp_path: Path,
) -> None:
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
    with GuardianState(tmp_path / "state.sqlite3") as state:
        run_id = state.start_run(
            repository="acme/translations",
            locale="ru",
            mode=GuardianMode.PROPOSE_PREVENTION,
            started_at=now,
        )
        broker = _FakeBroker()
        author = _FakeAuthor()
        coordinator = _coordinator(
            state=state,
            tmp_path=tmp_path,
            broker=broker,
            author=author,
        )
        source_checks = 0

        def revoke_after_post(
            _source: OpenPullAuthorityReference,
            _revisions: Sequence[int],
        ) -> None:
            nonlocal source_checks
            source_checks += 1
            if broker.open_calls:
                raise PreventionSourceAuthorityError("source was deleted after POST")

        first = coordinator.propose(
            policy=_repository_policy(),
            recurrence_candidates=(_candidate(),),
            evidence_revision_ids={"review_comment:42": OPEN_SOURCE_REVISION_ID},
            run_id=run_id,
            observed_at=now,
            require_live_lease=_live_lease,
            require_current_base_unchanged=_current_base,
            open_source=_open_source(),
            source_event_revision_ids=(OPEN_SOURCE_REVISION_ID,),
            require_exact_open_source_authority=revoke_after_post,
        )

        assert first.drafts == ()
        assert first.failures == ("PreventionSourceAuthorityError",)
        assert broker.open_calls == 1
        row = state._connection.execute(  # noqa: SLF001
            "SELECT draft_key FROM prevention_draft_events WHERE phase = 'draft_opened'"
        ).fetchone()
        assert row is not None
        opened = state.prevention_draft_by_key(str(row["draft_key"]))
        assert opened is not None
        assert opened.phase == "draft_opened"
        assert opened.draft_number == 21
        health = state.latest_health("guardian_prevention_publication")
        assert health is not None
        assert health.details["failure"] == "PreventionSourceAuthorityError"

        coordinator.begin_poll()
        second = coordinator.propose(
            policy=_repository_policy(),
            recurrence_candidates=(_candidate(),),
            evidence_revision_ids={"review_comment:42": OPEN_SOURCE_REVISION_ID},
            run_id=run_id,
            observed_at=now,
            require_live_lease=_live_lease,
            require_current_base_unchanged=_current_base,
            **_open_source_kwargs(),
        )
        assert second.skipped == 1
        assert broker.open_calls == 1
        assert author.calls == 1


def test_source_edit_racing_post_response_cannot_orphan_created_pr(
    tmp_path: Path,
) -> None:
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
    with GuardianState(tmp_path / "state.sqlite3") as state:
        run_id = state.start_run(
            repository="acme/translations",
            locale="ru",
            mode=GuardianMode.PROPOSE_PREVENTION,
            started_at=now,
        )

        class RacingBroker(_FakeBroker):
            def open_draft(self, **kwargs: object) -> PreventionDraftResult:
                draft = super().open_draft(**kwargs)
                source = _open_source()
                state.record_feedback_event(
                    FeedbackEvent(
                        repository=source.repository,
                        pr_number=source.pr_number,
                        kind="review_comment",
                        event_id="42",
                        author="coderabbitai[bot]",
                        author_id=202,
                        author_type="Bot",
                        body="Edited while POST response was in flight.",
                        head_sha=source.head_sha,
                        base_sha=source.base_sha,
                        locale="ru",
                        updated_at="2026-08-30T12:00:00Z",
                        path="l10n/messages_ru.properties",
                        line=17,
                        html_url=(
                            "https://github.test/acme/translations/pull/12"
                            "#discussion_r42"
                        ),
                    ),
                    observed_at=now,
                )
                return draft

        broker = RacingBroker()
        author = _FakeAuthor()
        coordinator = _coordinator(
            state=state,
            tmp_path=tmp_path,
            broker=broker,
            author=author,
        )

        def require_current_source(
            source: OpenPullAuthorityReference,
            revisions: Sequence[int],
        ) -> None:
            state.validate_prevention_source_attestation(
                source_repository=source.repository,
                open_source=source,
                source_pulls=(),
                event_revision_ids=revisions,
            )

        outcome = coordinator.propose(
            policy=_repository_policy(),
            recurrence_candidates=(_candidate(),),
            evidence_revision_ids={"review_comment:42": OPEN_SOURCE_REVISION_ID},
            run_id=run_id,
            observed_at=now,
            require_live_lease=_live_lease,
            require_current_base_unchanged=_current_base,
            open_source=_open_source(),
            source_event_revision_ids=(OPEN_SOURCE_REVISION_ID,),
            require_exact_open_source_authority=require_current_source,
        )

        assert outcome.failures == ("ValueError",)
        assert broker.open_calls == 1
        row = state._connection.execute(  # noqa: SLF001
            "SELECT draft_key FROM prevention_draft_events WHERE phase = 'draft_opened'"
        ).fetchone()
        assert row is not None
        opened = state.prevention_draft_by_key(str(row["draft_key"]))
        assert opened is not None and opened.draft_number == 21

        coordinator.begin_poll()
        recovered = coordinator.recover(
            policy=_repository_policy(),
            observed_at=now,
            require_live_lease=_live_lease,
            require_current_base_unchanged=_current_base,
            require_exact_open_source_authority=require_current_source,
        )
        assert recovered.drafts == ()
        assert broker.open_calls == 1


def test_exact_post_response_supersedes_racing_local_resolution(
    tmp_path: Path,
) -> None:
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
    with GuardianState(tmp_path / "state.sqlite3") as state:
        run_id = state.start_run(
            repository="acme/translations",
            locale="ru",
            mode=GuardianMode.PROPOSE_PREVENTION,
            started_at=now,
        )

        class RacingTerminalBroker(_FakeBroker):
            def open_draft(
                self,
                *,
                candidate_sha: str,
                **kwargs: object,
            ) -> PreventionDraftResult:
                before_create = kwargs["before_create"]
                assert callable(before_create)
                before_create()
                pending = state.pending_prevention_drafts()
                assert len(pending) == 1
                state.record_prevention_resolution(
                    draft_key=pending[0].draft_key,
                    resolution="base_moved",
                    occurred_at=now,
                )
                self.open_calls += 1
                return PreventionDraftResult(
                    number=71,
                    html_url="https://github.test/guardian/pipeline/pull/71",
                    candidate_sha=candidate_sha,
                    created=True,
                )

        broker = RacingTerminalBroker()
        outcome = _coordinator(
            state=state,
            tmp_path=tmp_path,
            broker=broker,
            author=_FakeAuthor(),
        ).propose(
            policy=_repository_policy(),
            recurrence_candidates=(_candidate(),),
            evidence_revision_ids={"review_comment:42": OPEN_SOURCE_REVISION_ID},
            run_id=run_id,
            observed_at=now,
            require_live_lease=_live_lease,
            require_current_base_unchanged=_current_base,
            **_open_source_kwargs(),
        )

        assert [draft.number for draft in outcome.drafts] == [71]
        row = state._connection.execute(  # noqa: SLF001
            "SELECT draft_key FROM prevention_draft_events WHERE phase = 'draft_opened'"
        ).fetchone()
        assert row is not None
        assert state.prevention_resolution(str(row["draft_key"])) is None
        snapshot = state.status_snapshot(
            mode=GuardianMode.PROPOSE_PREVENTION,
            as_of=now,
        )
        assert snapshot.opened_preventions == 1
        assert snapshot.conflicted_preventions == 0


def test_prevention_rejects_evidence_outside_exact_source_before_authoring(
    tmp_path: Path,
) -> None:
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
    with GuardianState(tmp_path / "state.sqlite3") as state:
        run_id = state.start_run(
            repository="acme/translations",
            locale="ru",
            mode=GuardianMode.PROPOSE_PREVENTION,
            started_at=now,
        )
        broker = _FakeBroker()
        author = _FakeAuthor()
        outcome = _coordinator(
            state=state,
            tmp_path=tmp_path,
            broker=broker,
            author=author,
        ).propose(
            policy=_repository_policy(),
            recurrence_candidates=(_candidate(),),
            evidence_revision_ids={"review_comment:42": OPEN_SOURCE_REVISION_ID},
            run_id=run_id,
            observed_at=now,
            require_live_lease=_live_lease,
            require_current_base_unchanged=_current_base,
            open_source=_open_source(),
            source_event_revision_ids=(8,),
            require_exact_open_source_authority=_open_source_authority,
        )

        assert outcome.failures == ("InvalidRecurrenceEvidence",)
        assert author.calls == 0
        assert broker.capture_calls == 0


def test_prevention_rejects_oversized_canonical_source_before_authoring(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
    monkeypatch.setattr(guardian_state, "_MAX_PREVENTION_SOURCE_JSON_BYTES", 2)
    with GuardianState(tmp_path / "state.sqlite3") as state:
        assert _seed_open_source_event(state) == OPEN_SOURCE_REVISION_ID
        run_id = state.start_run(
            repository="acme/translations",
            locale="ru",
            mode=GuardianMode.PROPOSE_PREVENTION,
            started_at=now,
        )
        broker = _FakeBroker()
        author = _FakeAuthor()
        outcome = _coordinator(
            state=state,
            tmp_path=tmp_path,
            broker=broker,
            author=author,
        ).propose(
            policy=_repository_policy(),
            recurrence_candidates=(_candidate(),),
            evidence_revision_ids={"review_comment:42": OPEN_SOURCE_REVISION_ID},
            run_id=run_id,
            observed_at=now,
            require_live_lease=_live_lease,
            require_current_base_unchanged=_current_base,
            **_open_source_kwargs(),
        )

        assert outcome.failures == ("InvalidRecurrenceEvidence",)
        assert author.calls == 0
        assert broker.capture_calls == 0


def test_prevention_bounds_recurrence_candidates_before_authoring(
    tmp_path: Path,
) -> None:
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
    with GuardianState(tmp_path / "state.sqlite3") as state:
        run_id = state.start_run(
            repository="acme/translations",
            locale="ru",
            mode=GuardianMode.PROPOSE_PREVENTION,
            started_at=now,
        )
        broker = _FakeBroker()
        author = _FakeAuthor()
        coordinator = _coordinator(
            state=state,
            tmp_path=tmp_path,
            broker=broker,
            author=author,
        )

        with pytest.raises(ValueError, match="per-proposal bound"):
            coordinator.propose(
                policy=_repository_policy(),
                recurrence_candidates=tuple(
                    _candidate(str(index)) for index in range(101)
                ),
                evidence_revision_ids={
                    "review_comment:42": OPEN_SOURCE_REVISION_ID,
                },
                run_id=run_id,
                observed_at=now,
                require_live_lease=_live_lease,
                require_current_base_unchanged=_current_base,
                **_open_source_kwargs(),
            )

        assert author.calls == 0
        assert broker.capture_calls == 0


def test_open_source_authority_veto_prevents_branch_publication(
    tmp_path: Path,
) -> None:
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
    with GuardianState(tmp_path / "state.sqlite3") as state:
        run_id = state.start_run(
            repository="acme/translations",
            locale="ru",
            mode=GuardianMode.PROPOSE_PREVENTION,
            started_at=now,
        )
        broker = _FakeBroker()
        author = _FakeAuthor()

        def veto(
            _source: OpenPullAuthorityReference,
            _revision_ids: Sequence[int],
        ) -> None:
            raise PreventionSourceAuthorityError(
                "trusted feedback changed before publication"
            )

        outcome = _coordinator(
            state=state,
            tmp_path=tmp_path,
            broker=broker,
            author=author,
        ).propose(
            policy=_repository_policy(),
            recurrence_candidates=(_candidate(),),
            evidence_revision_ids={"review_comment:42": OPEN_SOURCE_REVISION_ID},
            run_id=run_id,
            observed_at=now,
            require_live_lease=_live_lease,
            require_current_base_unchanged=_current_base,
            open_source=_open_source(),
            source_event_revision_ids=(OPEN_SOURCE_REVISION_ID,),
            require_exact_open_source_authority=veto,
        )

        assert outcome.failures == ("PreventionSourceAuthorityError",)
        assert broker.branch_shas == {}
        assert state.pending_prevention_drafts() == ()
        assert author.calls == 0
        assert broker.capture_calls == 0


def test_subscription_prevention_uses_call_cap_without_api_key_or_usd_cost(
    tmp_path: Path,
) -> None:
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
    with GuardianState(tmp_path / "state.sqlite3") as state:
        run_id = state.start_run(
            repository="acme/translations",
            locale="ru",
            mode=GuardianMode.PROPOSE_PREVENTION,
            started_at=now,
        )
        author = _FakeAuthor()

        def forbidden_api_helper() -> str:
            raise AssertionError("subscription prevention must not read an API key")

        outcome = _coordinator(
            state=state,
            tmp_path=tmp_path,
            broker=_FakeBroker(),
            author=author,
            api_billed=False,
            model_credential_provider=forbidden_api_helper,
        ).propose(
            policy=_repository_policy(),
            recurrence_candidates=(_candidate(),),
            evidence_revision_ids={"review_comment:42": OPEN_SOURCE_REVISION_ID},
            run_id=run_id,
            observed_at=now,
            require_live_lease=_live_lease,
            require_current_base_unchanged=_current_base,
            **_open_source_kwargs(),
        )

        assert len(outcome.drafts) == 1
        assert author.calls == 1
        assert state.model_calls_committed_for_day(now.date()) == 1
        assert state.cost_for_day(now.date()) == 0


def test_coordinator_recovers_pushed_branch_without_new_feedback_or_model_call(
    tmp_path: Path,
) -> None:
    class SourceLastBroker(_FakeBroker):
        def open_draft(self, **kwargs):
            assert kwargs.get("before_post") is kwargs.get("before_create")
            return super().open_draft(**kwargs)

    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
    with GuardianState(tmp_path / "state.sqlite3") as state:
        assert _seed_open_source_event(state) == OPEN_SOURCE_REVISION_ID
        run_id = state.start_run(
            repository="acme/translations",
            locale="ru",
            mode=GuardianMode.PROPOSE_PREVENTION,
            started_at=now,
        )
        evidence_hash = "d" * 64
        branch = f"guardian/prevention-{BASE_SHA[:12]}-{evidence_hash}"
        ledger = {
            "run_id": run_id,
            "source_repository": "acme/translations",
            "target_repository": "guardian/pipeline",
            "target_base_branch": "main",
            "target_base_sha": BASE_SHA,
            "push_repository": "guardian/pipeline",
            "branch": branch,
            "candidate_sha": CANDIDATE_SHA,
            "evidence_hash": evidence_hash,
            **_ledger_attestation(),
            "title": "Prevent recurrence: placeholder parity",
            "body": "Validated body\n",
        }
        state.record_prevention_draft_event(
            **ledger, phase="validated", occurred_at=now
        )
        state.record_prevention_draft_event(**ledger, phase="pushed", occurred_at=now)
        broker = SourceLastBroker()
        broker.branch_shas[branch] = CANDIDATE_SHA
        author = _FakeAuthor()
        coordinator = _coordinator(
            state=state,
            tmp_path=tmp_path,
            broker=broker,
            author=author,
        )
        outcome = coordinator.recover(
            policy=_repository_policy(),
            observed_at=now,
            require_live_lease=_live_lease,
            require_current_base_unchanged=_current_base,
            require_exact_open_source_authority=_open_source_authority,
        )

        assert len(outcome.drafts) == 1
        assert author.calls == 0
        assert state.pending_prevention_drafts() == ()


@pytest.mark.parametrize("during_proposal", [False, True])
def test_recovery_reconciles_exact_pr_before_observing_moved_base_or_branch(
    during_proposal: bool,
    tmp_path: Path,
) -> None:
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)

    class ExistingPullBroker(_FakeBroker):
        def capture_base(self) -> PreventionBaseSnapshot:
            raise AssertionError("exact PR recovery must precede current-base capture")

        def branch_sha(self, _branch: str) -> str | None:
            raise AssertionError("exact PR recovery must precede branch inspection")

        def find_draft(
            self, *, candidate_sha: str, **_kwargs: object
        ) -> PreventionDraftResult:
            return PreventionDraftResult(
                number=77,
                html_url="https://github.test/guardian/pipeline/pull/77",
                candidate_sha=candidate_sha,
                created=False,
            )

    with GuardianState(tmp_path / "state.sqlite3") as state:
        draft_key, ledger = _pending_prevention_ledger(state, now=now)
        broker = ExistingPullBroker()
        coordinator = _coordinator(
            state=state,
            tmp_path=tmp_path,
            broker=broker,
            author=_FakeAuthor(),
            max_drafts=0,
        )

        def moved_base() -> None:
            raise AssertionError(
                "an exact existing PR must reconcile after its base moves"
            )

        if during_proposal:
            outcome = coordinator.propose(
                policy=_repository_policy(),
                recurrence_candidates=(),
                evidence_revision_ids={},
                run_id=str(ledger["run_id"]),
                observed_at=now,
                require_live_lease=_live_lease,
                require_current_base_unchanged=moved_base,
                **_open_source_kwargs(),
            )
        else:
            outcome = coordinator.recover(
                policy=_repository_policy(),
                observed_at=now,
                require_live_lease=_live_lease,
                require_current_base_unchanged=moved_base,
                require_exact_open_source_authority=_open_source_authority,
            )

        assert [draft.number for draft in outcome.drafts] == [77]
        recovered = state.prevention_draft_by_key(draft_key)
        assert recovered is not None
        assert recovered.phase == "draft_opened"


@pytest.mark.parametrize(
    "bad_intake",
    [
        "oversized-candidates",
        "malformed-source",
        "irrelevant-callback",
        "oversized-revision",
    ],
)
def test_pending_exact_pr_recovery_precedes_new_intake_validation(
    bad_intake: str,
    tmp_path: Path,
) -> None:
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)

    class ExistingPullBroker(_FakeBroker):
        def capture_base(self) -> PreventionBaseSnapshot:
            raise AssertionError("invalid new intake must not hide exact PR recovery")

        def branch_sha(self, _branch: str) -> str | None:
            raise AssertionError(
                "invalid new intake must not inspect a recovered branch"
            )

        def find_draft(
            self, *, candidate_sha: str, **_kwargs: object
        ) -> PreventionDraftResult:
            return PreventionDraftResult(
                number=92,
                html_url="https://github.test/guardian/pipeline/pull/92",
                candidate_sha=candidate_sha,
                created=False,
            )

    with GuardianState(tmp_path / "state.sqlite3") as state:
        draft_key, ledger = _pending_prevention_ledger(state, now=now)
        coordinator = _coordinator(
            state=state,
            tmp_path=tmp_path,
            broker=ExistingPullBroker(),
            author=_FakeAuthor(),
            max_drafts=0,
        )
        candidates = (
            tuple(_candidate(str(index)) for index in range(101))
            if bad_intake == "oversized-candidates"
            else ()
        )
        source_pulls: Sequence[HistoricalPullReference] = ()
        if bad_intake == "malformed-source":
            source_pulls = (object(),)  # type: ignore[assignment]
        historical_callback: object | None = None
        if bad_intake == "irrelevant-callback":
            historical_callback = object()
        source_revision_ids = (
            (2**63,)
            if bad_intake == "oversized-revision"
            else (OPEN_SOURCE_REVISION_ID,)
        )

        with pytest.raises((TypeError, ValueError)):
            coordinator.propose(
                policy=_repository_policy(),
                recurrence_candidates=candidates,
                evidence_revision_ids={},
                run_id=str(ledger["run_id"]),
                observed_at=now,
                require_live_lease=_live_lease,
                require_current_base_unchanged=_current_base,
                open_source=_open_source(),
                source_pulls=source_pulls,
                source_event_revision_ids=source_revision_ids,
                require_exact_open_source_authority=_open_source_authority,
                require_exact_sources_still_closed=historical_callback,  # type: ignore[arg-type]
            )

        recovered = state.prevention_draft_by_key(draft_key)
        assert recovered is not None and recovered.phase == "draft_opened"


def test_recovery_rejects_naive_poll_time_without_mutating_pending_ledger(
    tmp_path: Path,
) -> None:
    recorded_at = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
    with GuardianState(tmp_path / "state.sqlite3") as state:
        draft_key, _ledger = _pending_prevention_ledger(state, now=recorded_at)
        broker = _FakeBroker()
        coordinator = _coordinator(
            state=state,
            tmp_path=tmp_path,
            broker=broker,
            author=_FakeAuthor(),
        )

        with pytest.raises(PreventionRuntimeError, match="timezone-aware"):
            coordinator.recover(
                policy=_repository_policy(),
                observed_at=datetime(2026, 8, 30, 11, 0),
                require_live_lease=_live_lease,
                require_current_base_unchanged=_current_base,
                require_exact_open_source_authority=_open_source_authority,
            )

        pending = state.prevention_draft_by_key(draft_key)
        assert pending is not None and pending.phase == "pushed"
        assert state.prevention_resolution(draft_key) is None
        attempts = state._connection.execute(  # noqa: SLF001
            "SELECT COUNT(*) FROM prevention_recovery_attempt_events"
        ).fetchone()
        assert attempts is not None and attempts[0] == 0
        assert broker.capture_calls == 0


@pytest.mark.parametrize(
    "exact_pull", [True, False], ids=("exact-pr", "branch-conflict")
)
def test_recovery_clamps_ledger_time_after_wall_clock_rollback(
    exact_pull: bool,
    tmp_path: Path,
) -> None:
    recorded_at = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)

    class BackwardClockBroker(_FakeBroker):
        def find_draft(
            self, *, candidate_sha: str, **_kwargs: object
        ) -> PreventionDraftResult | None:
            if not exact_pull:
                return None
            return PreventionDraftResult(
                number=84,
                html_url="https://github.test/guardian/pipeline/pull/84",
                candidate_sha=candidate_sha,
                created=False,
            )

    with GuardianState(tmp_path / "state.sqlite3") as state:
        draft_key, ledger = _pending_prevention_ledger(state, now=recorded_at)
        broker = BackwardClockBroker()
        if not exact_pull:
            broker.branch_shas[str(ledger["branch"])] = "c" * 40
        coordinator = _coordinator(
            state=state,
            tmp_path=tmp_path,
            broker=broker,
            author=_FakeAuthor(),
        )

        outcome = coordinator.recover(
            policy=_repository_policy(),
            observed_at=recorded_at - timedelta(hours=1),
            require_live_lease=_live_lease,
            require_current_base_unchanged=_current_base,
            require_exact_open_source_authority=_open_source_authority,
        )

        if exact_pull:
            assert [draft.number for draft in outcome.drafts] == [84]
            recovered = state.prevention_draft_by_key(draft_key)
            assert recovered is not None
            assert recovered.phase == "draft_opened"
            assert recovered.occurred_at == recorded_at
        else:
            assert outcome.failures == ("PreventionBranchModified",)
            resolution = state.prevention_resolution(draft_key)
            assert resolution is not None
            assert resolution.resolution == "branch_modified"
            assert resolution.occurred_at == recorded_at


def test_historical_recovery_reconciles_exact_pr_before_source_revalidation(
    tmp_path: Path,
) -> None:
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
    order: list[str] = []

    class ExistingPullBroker(_FakeBroker):
        def find_draft(
            self, *, candidate_sha: str, **_kwargs: object
        ) -> PreventionDraftResult:
            order.append("find")
            return PreventionDraftResult(
                number=78,
                html_url="https://github.test/guardian/pipeline/pull/78",
                candidate_sha=candidate_sha,
                created=False,
            )

    with GuardianState(tmp_path / "state.sqlite3") as state:
        source, revision_id = _historical_prevention_source(state, now=now)
        _pending_prevention_ledger(
            state,
            now=now,
            source_pulls=(source,),
            event_revision_ids=(revision_id,),
        )

        outcome = _coordinator(
            state=state,
            tmp_path=tmp_path,
            broker=ExistingPullBroker(),
            author=_FakeAuthor(),
        ).recover(
            policy=_repository_policy(),
            observed_at=now,
            require_live_lease=_live_lease,
            require_current_base_unchanged=_current_base,
            require_exact_open_source_authority=_open_source_authority,
            require_exact_sources_still_closed=lambda _sources, _revisions: (
                order.append("source")
            ),
        )

        assert len(outcome.drafts) == 1
        assert order == ["find", "source"]


def test_open_recovery_reconciles_exact_pr_before_source_revalidation(
    tmp_path: Path,
) -> None:
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
    order: list[str] = []
    source = _open_source()

    class ExistingPullBroker(_FakeBroker):
        def find_draft(
            self, *, candidate_sha: str, **_kwargs: object
        ) -> PreventionDraftResult:
            order.append("find")
            return PreventionDraftResult(
                number=80,
                html_url="https://github.test/guardian/pipeline/pull/80",
                candidate_sha=candidate_sha,
                created=False,
            )

    with GuardianState(tmp_path / "state.sqlite3") as state:
        _pending_prevention_ledger(state, now=now)

        def require_source(
            observed_source: OpenPullAuthorityReference,
            revisions: Sequence[int],
        ) -> None:
            assert observed_source == source
            assert tuple(revisions) == (OPEN_SOURCE_REVISION_ID,)
            order.append("source")

        outcome = _coordinator(
            state=state,
            tmp_path=tmp_path,
            broker=ExistingPullBroker(),
            author=_FakeAuthor(),
        ).recover(
            policy=_repository_policy(),
            observed_at=now,
            require_live_lease=_live_lease,
            require_current_base_unchanged=_current_base,
            require_exact_open_source_authority=require_source,
        )

        assert len(outcome.drafts) == 1
        assert order == ["find", "source"]


def test_transient_open_source_revalidation_does_not_starve_new_intake(
    tmp_path: Path,
) -> None:
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)

    class TransientBaseAuthorityError(RuntimeError):
        pass

    class ExistingPullBroker(_FakeBroker):
        def find_draft(
            self, *, candidate_sha: str, **_kwargs: object
        ) -> PreventionDraftResult:
            return PreventionDraftResult(
                number=79,
                html_url="https://github.test/guardian/pipeline/pull/79",
                candidate_sha=candidate_sha,
                created=False,
            )

    with GuardianState(tmp_path / "state.sqlite3") as state:
        draft_key, ledger = _pending_prevention_ledger(state, now=now)
        author = _FakeAuthor()
        calls = 0

        def require_source(
            _source: OpenPullAuthorityReference,
            _revisions: Sequence[int],
        ) -> None:
            nonlocal calls
            calls += 1
            if calls == 1:
                raise TransientBaseAuthorityError("temporary authority read failure")

        outcome = _coordinator(
            state=state,
            tmp_path=tmp_path,
            broker=ExistingPullBroker(),
            author=author,
        ).propose(
            policy=_repository_policy(),
            recurrence_candidates=(_candidate(),),
            evidence_revision_ids={"review_comment:42": OPEN_SOURCE_REVISION_ID},
            run_id=str(ledger["run_id"]),
            observed_at=now,
            require_live_lease=_live_lease,
            require_current_base_unchanged=_current_base,
            open_source=_open_source(),
            source_event_revision_ids=(OPEN_SOURCE_REVISION_ID,),
            require_exact_open_source_authority=require_source,
        )

        assert len(outcome.drafts) == 2
        assert outcome.failures == ("TransientBaseAuthorityError",)
        assert author.calls == 1
        pending = state.prevention_draft_by_key(draft_key)
        assert pending is not None
        assert pending.phase == "draft_opened"
        assert state.prevention_resolution(draft_key) is None


def test_historical_recovery_authority_veto_is_terminal_and_never_publishes(
    tmp_path: Path,
) -> None:
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)

    class ReadOnlyBroker(_FakeBroker):
        def __init__(self) -> None:
            super().__init__()
            self.find_calls = 0

        def find_draft(self, **_kwargs: object) -> PreventionDraftResult | None:
            self.find_calls += 1
            return None

    with GuardianState(tmp_path / "state.sqlite3") as state:
        source, revision_id = _historical_prevention_source(state, now=now)
        draft_key, _ledger = _pending_prevention_ledger(
            state,
            now=now,
            source_pulls=(source,),
            event_revision_ids=(revision_id,),
        )

        def veto(
            _sources: Sequence[HistoricalPullReference],
            _revisions: Sequence[int],
        ) -> None:
            raise RemediationSourceAuthorityError(
                "trusted feedback changed or source reopened"
            )

        broker = ReadOnlyBroker()
        outcome = _coordinator(
            state=state,
            tmp_path=tmp_path,
            broker=broker,
            author=_FakeAuthor(),
        ).recover(
            policy=_repository_policy(),
            observed_at=now,
            require_live_lease=_live_lease,
            require_current_base_unchanged=_current_base,
            require_exact_sources_still_closed=veto,
        )

        assert outcome.drafts == ()
        assert outcome.failures == ("PreventionSourceAuthorityChanged",)
        terminal = state.prevention_resolution(draft_key)
        assert terminal is not None
        assert terminal.resolution == "source_authority_changed"
        assert broker.find_calls == 1
        assert broker.open_calls == 0


def test_exact_pr_is_recorded_even_when_source_is_already_stale(
    tmp_path: Path,
) -> None:
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)

    class ExistingPullBroker(_FakeBroker):
        def find_draft(
            self, *, candidate_sha: str, **_kwargs: object
        ) -> PreventionDraftResult:
            return PreventionDraftResult(
                number=95,
                html_url="https://github.test/guardian/pipeline/pull/95",
                candidate_sha=candidate_sha,
                created=False,
            )

    with GuardianState(tmp_path / "state.sqlite3") as state:
        draft_key, _ledger = _pending_prevention_ledger(state, now=now)

        def veto(
            _source: OpenPullAuthorityReference,
            _revisions: Sequence[int],
        ) -> None:
            raise PreventionSourceAuthorityError("source is stale")

        outcome = _coordinator(
            state=state,
            tmp_path=tmp_path,
            broker=ExistingPullBroker(),
            author=_FakeAuthor(),
        ).recover(
            policy=_repository_policy(),
            observed_at=now,
            require_live_lease=_live_lease,
            require_current_base_unchanged=_current_base,
            require_exact_open_source_authority=veto,
        )

        assert [draft.number for draft in outcome.drafts] == [95]
        assert outcome.failures == ("PreventionSourceAuthorityChanged",)
        opened = state.prevention_draft_by_key(draft_key)
        assert opened is not None and opened.phase == "draft_opened"
        assert opened.draft_number == 95
        assert state.prevention_resolution(draft_key) is None


def test_recovery_terminally_quarantines_a_stable_remote_conflict(
    tmp_path: Path,
) -> None:
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)

    class ConflictingBroker(_FakeBroker):
        def find_draft(self, **_kwargs: object) -> PreventionDraftResult | None:
            raise PreventionRemoteConflictError("exact PR body was edited")

    with GuardianState(tmp_path / "state.sqlite3") as state:
        draft_key, _ledger = _pending_prevention_ledger(state, now=now)
        outcome = _coordinator(
            state=state,
            tmp_path=tmp_path,
            broker=ConflictingBroker(),
            author=_FakeAuthor(),
        ).recover(
            policy=_repository_policy(),
            observed_at=now,
            require_live_lease=_live_lease,
            require_current_base_unchanged=_current_base,
            require_exact_open_source_authority=_open_source_authority,
        )

        assert outcome.failures == ("PreventionRemoteConflict",)
        terminal = state.prevention_resolution(draft_key)
        assert terminal is not None
        assert terminal.resolution == "remote_conflict"


@pytest.mark.parametrize("entry_point", ["recover", "propose"])
@pytest.mark.parametrize("exact_pull", [True, False], ids=("exact-pr", "no-pr"))
def test_removed_prevention_policy_still_reconciles_pending_remote_state(
    entry_point: str,
    exact_pull: bool,
    tmp_path: Path,
) -> None:
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)

    class AttestedPolicyBroker(_FakeBroker):
        def __init__(self) -> None:
            super().__init__()
            self.find_calls = 0

        def find_draft(
            self, *, candidate_sha: str, **_kwargs: object
        ) -> PreventionDraftResult | None:
            self.find_calls += 1
            if not exact_pull:
                return None
            return PreventionDraftResult(
                number=96,
                html_url="https://github.test/guardian/pipeline/pull/96",
                candidate_sha=candidate_sha,
                created=False,
            )

    with GuardianState(tmp_path / "state.sqlite3") as state:
        draft_key, ledger = _pending_prevention_ledger(state, now=now)
        broker = AttestedPolicyBroker()
        author = _FakeAuthor()
        coordinator = _coordinator(
            state=state,
            tmp_path=tmp_path,
            broker=broker,
            author=author,
        )
        revoked_policy = replace(_repository_policy(), prevention=None)
        if entry_point == "recover":
            outcome = coordinator.recover(
                policy=revoked_policy,
                observed_at=now,
                require_live_lease=_live_lease,
                require_current_base_unchanged=_current_base,
            )
        else:
            outcome = coordinator.propose(
                policy=revoked_policy,
                recurrence_candidates=(_candidate(),),
                evidence_revision_ids={},
                run_id=str(ledger["run_id"]),
                observed_at=now,
                require_live_lease=_live_lease,
                require_current_base_unchanged=_current_base,
            )

        assert broker.find_calls == 1
        assert broker.open_calls == 0
        if exact_pull:
            assert [draft.number for draft in outcome.drafts] == [96]
            assert outcome.failures == ("PreventionPolicyChanged",)
            opened = state.prevention_draft_by_key(draft_key)
            assert opened is not None and opened.phase == "draft_opened"
            assert opened.draft_number == 96
            assert state.prevention_resolution(draft_key) is None
        else:
            assert outcome.drafts == ()
            assert outcome.failures == ("PreventionPolicyChanged",)
            resolution = state.prevention_resolution(draft_key)
            assert resolution is not None
            assert resolution.resolution == "policy_changed"
        if entry_point == "propose":
            assert outcome.skipped == 1
            assert author.calls == 0


def test_recovery_attempts_are_bounded_and_become_operator_visible(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
    monkeypatch.setattr(
        "localize.guardian.state._MAX_PREVENTION_RECOVERY_ATTEMPTS",
        1,
    )

    class TransientBroker(_FakeBroker):
        def __init__(self) -> None:
            super().__init__()
            self.find_calls = 0

        def find_draft(self, **_kwargs: object) -> PreventionDraftResult | None:
            self.find_calls += 1
            raise PreventionRuntimeError("temporary GitHub observation failure")

    with GuardianState(tmp_path / "state.sqlite3") as state:
        draft_key, _ledger = _pending_prevention_ledger(state, now=now)
        broker = TransientBroker()
        coordinator = _coordinator(
            state=state,
            tmp_path=tmp_path,
            broker=broker,
            author=_FakeAuthor(),
        )
        first = coordinator.recover(
            policy=_repository_policy(),
            observed_at=now,
            require_live_lease=_live_lease,
            require_current_base_unchanged=_current_base,
            require_exact_open_source_authority=_open_source_authority,
        )
        coordinator.begin_poll()
        second = coordinator.recover(
            policy=_repository_policy(),
            observed_at=now,
            require_live_lease=_live_lease,
            require_current_base_unchanged=_current_base,
            require_exact_open_source_authority=_open_source_authority,
        )
        coordinator.begin_poll()
        third = coordinator.recover(
            policy=_repository_policy(),
            observed_at=now,
            require_live_lease=_live_lease,
            require_current_base_unchanged=_current_base,
            require_exact_open_source_authority=_open_source_authority,
        )

        assert first.failures == ("PreventionRuntimeError",)
        assert second.failures == ("PreventionRecoveryExhausted",)
        assert third == prevention_runtime.PreventionBatchOutcome()
        assert broker.find_calls == 2
        terminal = state.prevention_resolution(draft_key)
        assert terminal is not None
        assert terminal.resolution == "recovery_exhausted"
        health = state.latest_health("guardian_prevention_recovery")
        assert health is not None
        assert health.status == "failed"
        assert health.details["resolution"] == "recovery_exhausted"


def test_recovery_crash_after_rotation_does_not_starve_next_candidate(
    tmp_path: Path,
) -> None:
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
    database = tmp_path / "state.sqlite3"

    class SimulatedProcessCrash(BaseException):
        pass

    class CrashOnceBroker(_FakeBroker):
        def __init__(self) -> None:
            super().__init__()
            self.branches: list[str] = []
            self.crash = True

        def find_draft(
            self,
            *,
            branch: str,
            candidate_sha: str,
            **_kwargs: object,
        ) -> PreventionDraftResult:
            self.branches.append(branch)
            if self.crash:
                self.crash = False
                raise SimulatedProcessCrash
            number = 80 + len(self.branches)
            return PreventionDraftResult(
                number=number,
                html_url=f"https://github.test/guardian/pipeline/pull/{number}",
                candidate_sha=candidate_sha,
                created=False,
            )

    broker = CrashOnceBroker()
    with GuardianState(database) as state:
        _first_key, first = _pending_prevention_ledger(
            state,
            now=now,
            evidence_hash="1" * 64,
        )
        _second_key, second = _pending_prevention_ledger(
            state,
            now=now,
            evidence_hash="2" * 64,
        )
        coordinator = _coordinator(
            state=state,
            tmp_path=tmp_path / "first",
            broker=broker,
            author=_FakeAuthor(),
        )
        with pytest.raises(SimulatedProcessCrash):
            coordinator.recover(
                policy=_repository_policy(),
                observed_at=now,
                require_live_lease=_live_lease,
                require_current_base_unchanged=_current_base,
                require_exact_open_source_authority=_open_source_authority,
            )
        count = state._connection.execute(  # noqa: SLF001
            "SELECT COUNT(*) FROM prevention_recovery_attempt_events"
        ).fetchone()
        assert count is not None and count[0] == 1
        assert broker.branches == [first["branch"]]

    with GuardianState(database) as state:
        recovered = _coordinator(
            state=state,
            tmp_path=tmp_path / "restart",
            broker=broker,
            author=_FakeAuthor(),
        ).recover(
            policy=_repository_policy(),
            observed_at=now,
            require_live_lease=_live_lease,
            require_current_base_unchanged=_current_base,
            require_exact_open_source_authority=_open_source_authority,
        )

        assert broker.branches[1] == second["branch"]
        assert len(recovered.drafts) == 2


def test_final_capped_recovery_still_reconciles_an_exact_existing_pr(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
    monkeypatch.setattr(
        "localize.guardian.state._MAX_PREVENTION_RECOVERY_ATTEMPTS",
        1,
    )

    class FinalReconciliationBroker(_FakeBroker):
        def __init__(self) -> None:
            super().__init__()
            self.find_calls = 0

        def find_draft(
            self, *, candidate_sha: str, **_kwargs: object
        ) -> PreventionDraftResult | None:
            self.find_calls += 1
            if self.find_calls == 1:
                raise PreventionRuntimeError("temporary GitHub observation failure")
            return PreventionDraftResult(
                number=81,
                html_url="https://github.test/guardian/pipeline/pull/81",
                candidate_sha=candidate_sha,
                created=False,
            )

    with GuardianState(tmp_path / "state.sqlite3") as state:
        draft_key, _ledger = _pending_prevention_ledger(state, now=now)
        broker = FinalReconciliationBroker()
        coordinator = _coordinator(
            state=state,
            tmp_path=tmp_path,
            broker=broker,
            author=_FakeAuthor(),
        )
        first = coordinator.recover(
            policy=_repository_policy(),
            observed_at=now,
            require_live_lease=_live_lease,
            require_current_base_unchanged=_current_base,
            require_exact_open_source_authority=_open_source_authority,
        )
        coordinator.begin_poll()
        final = coordinator.recover(
            policy=_repository_policy(),
            observed_at=now,
            require_live_lease=_live_lease,
            require_current_base_unchanged=_current_base,
            require_exact_open_source_authority=_open_source_authority,
        )

        assert first.failures == ("PreventionRuntimeError",)
        assert [draft.number for draft in final.drafts] == [81]
        assert state.prevention_resolution(draft_key) is None
        recovered = state.prevention_draft_by_key(draft_key)
        assert recovered is not None
        assert recovered.phase == "draft_opened"
        assert broker.find_calls == 2


def test_final_lookup_resumes_after_crash_without_unbounded_attempt_rows(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
    database = tmp_path / "state.sqlite3"
    monkeypatch.setattr(
        guardian_state,
        "_MAX_PREVENTION_RECOVERY_ATTEMPTS",
        0,
    )

    class SimulatedProcessCrash(BaseException):
        pass

    class FinalCrashBroker(_FakeBroker):
        def __init__(self) -> None:
            super().__init__()
            self.crash = True

        def find_draft(
            self,
            *,
            candidate_sha: str,
            **_kwargs: object,
        ) -> PreventionDraftResult:
            if self.crash:
                self.crash = False
                raise SimulatedProcessCrash
            return PreventionDraftResult(
                number=88,
                html_url="https://github.test/guardian/pipeline/pull/88",
                candidate_sha=candidate_sha,
                created=False,
            )

    broker = FinalCrashBroker()
    with GuardianState(database) as state:
        draft_key, _ledger = _pending_prevention_ledger(state, now=now)
        with pytest.raises(SimulatedProcessCrash):
            _coordinator(
                state=state,
                tmp_path=tmp_path / "first",
                broker=broker,
                author=_FakeAuthor(),
            ).recover(
                policy=_repository_policy(),
                observed_at=now,
                require_live_lease=_live_lease,
                require_current_base_unchanged=_current_base,
                require_exact_open_source_authority=_open_source_authority,
            )

    with GuardianState(database) as state:
        recovered = _coordinator(
            state=state,
            tmp_path=tmp_path / "restart",
            broker=broker,
            author=_FakeAuthor(),
        ).recover(
            policy=_repository_policy(),
            observed_at=now,
            require_live_lease=_live_lease,
            require_current_base_unchanged=_current_base,
            require_exact_open_source_authority=_open_source_authority,
        )
        attempts = state._connection.execute(  # noqa: SLF001
            "SELECT COUNT(*) FROM prevention_recovery_attempt_events"
        ).fetchone()

        assert [draft.number for draft in recovered.drafts] == [88]
        assert attempts is not None and attempts[0] == 1
        opened = state.prevention_draft_by_key(draft_key)
        assert opened is not None and opened.phase == "draft_opened"


def test_transient_base_capture_isolated_and_terminal_after_final_retry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
    monkeypatch.setattr(
        "localize.guardian.state._MAX_PREVENTION_RECOVERY_ATTEMPTS",
        1,
    )

    class PartiallyTransientBroker(_FakeBroker):
        def __init__(self, *, first_branch: str) -> None:
            super().__init__()
            self.first_branch = first_branch

        def find_draft(
            self,
            *,
            branch: str,
            candidate_sha: str,
            **_kwargs: object,
        ) -> PreventionDraftResult | None:
            if branch == self.first_branch:
                return None
            return PreventionDraftResult(
                number=82,
                html_url="https://github.test/guardian/pipeline/pull/82",
                candidate_sha=candidate_sha,
                created=False,
            )

        def capture_base(self) -> PreventionBaseSnapshot:
            self.capture_calls += 1
            raise PreventionRuntimeError("temporary base observation failure")

    with GuardianState(tmp_path / "state.sqlite3") as state:
        first_key, first_ledger = _pending_prevention_ledger(
            state,
            now=now,
            evidence_hash="1" * 64,
        )
        second_key, _second_ledger = _pending_prevention_ledger(
            state,
            now=now,
            evidence_hash="2" * 64,
        )
        broker = PartiallyTransientBroker(
            first_branch=str(first_ledger["branch"]),
        )
        coordinator = _coordinator(
            state=state,
            tmp_path=tmp_path,
            broker=broker,
            author=_FakeAuthor(),
        )

        first = coordinator.recover(
            policy=_repository_policy(),
            observed_at=now,
            require_live_lease=_live_lease,
            require_current_base_unchanged=_current_base,
            require_exact_open_source_authority=_open_source_authority,
        )

        assert first.failures == ("PreventionRuntimeError",)
        assert [draft.number for draft in first.drafts] == [82]
        first_record = state.prevention_draft_by_key(first_key)
        second_record = state.prevention_draft_by_key(second_key)
        assert first_record is not None and first_record.phase == "pushed"
        assert second_record is not None and second_record.phase == "draft_opened"
        assert broker.capture_calls == 1

        coordinator.begin_poll()
        final = coordinator.recover(
            policy=_repository_policy(),
            observed_at=now,
            require_live_lease=_live_lease,
            require_current_base_unchanged=_current_base,
            require_exact_open_source_authority=_open_source_authority,
        )

        assert final.failures == ("PreventionRecoveryExhausted",)
        terminal = state.prevention_resolution(first_key)
        assert terminal is not None
        assert terminal.resolution == "recovery_exhausted"
        assert broker.capture_calls == 1


def test_recovery_observes_base_after_each_candidates_exact_lookup(
    tmp_path: Path,
) -> None:
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
    second_base_sha = "9" * 40
    second_candidate_sha = "8" * 40

    class MovingBaseBroker(_FakeBroker):
        def __init__(self, *, second_branch: str) -> None:
            super().__init__()
            self.second_branch = second_branch
            self.current_base_sha = BASE_SHA

        def find_draft(
            self,
            *,
            branch: str,
            **_kwargs: object,
        ) -> PreventionDraftResult | None:
            if branch == self.second_branch:
                # The move occurs during this candidate's exact remote lookup.
                self.current_base_sha = second_base_sha
            return None

        def capture_base(self) -> PreventionBaseSnapshot:
            self.capture_calls += 1
            return PreventionBaseSnapshot(
                revision=replace(_base_revision(), sha=self.current_base_sha),
                target_repository_id=101,
                push_repository_id=101,
                private=False,
            )

    with GuardianState(tmp_path / "state.sqlite3") as state:
        first_key, first_ledger = _pending_prevention_ledger(
            state,
            now=now,
            evidence_hash="1" * 64,
        )
        second_key, second_ledger = _pending_prevention_ledger(
            state,
            now=now,
            evidence_hash="2" * 64,
            candidate_sha=second_candidate_sha,
            target_base_sha=second_base_sha,
        )
        broker = MovingBaseBroker(second_branch=str(second_ledger["branch"]))
        broker.branch_shas[str(first_ledger["branch"])] = CANDIDATE_SHA
        broker.branch_shas[str(second_ledger["branch"])] = second_candidate_sha

        outcome = _coordinator(
            state=state,
            tmp_path=tmp_path,
            broker=broker,
            author=_FakeAuthor(),
            max_drafts=2,
        ).recover(
            policy=_repository_policy(),
            observed_at=now,
            require_live_lease=_live_lease,
            require_current_base_unchanged=_current_base,
            require_exact_open_source_authority=_open_source_authority,
        )

        assert [draft.number for draft in outcome.drafts] == [21, 22]
        assert outcome.failures == ()
        assert broker.capture_calls == 2
        assert state.prevention_draft_by_key(first_key).phase == "draft_opened"  # type: ignore[union-attr]
        assert state.prevention_draft_by_key(second_key).phase == "draft_opened"  # type: ignore[union-attr]


def test_private_base_observation_does_not_starve_exact_pr_recovery(
    tmp_path: Path,
) -> None:
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)

    class NewlyPrivateBroker(_FakeBroker):
        def __init__(self, *, first_branch: str) -> None:
            super().__init__(private=True)
            self.first_branch = first_branch

        def find_draft(
            self,
            *,
            branch: str,
            candidate_sha: str,
            **_kwargs: object,
        ) -> PreventionDraftResult | None:
            if branch == self.first_branch:
                return None
            return PreventionDraftResult(
                number=83,
                html_url="https://github.test/guardian/pipeline/pull/83",
                candidate_sha=candidate_sha,
                created=False,
            )

    with GuardianState(tmp_path / "state.sqlite3") as state:
        first_key, first_ledger = _pending_prevention_ledger(
            state,
            now=now,
            evidence_hash="3" * 64,
        )
        second_key, _second_ledger = _pending_prevention_ledger(
            state,
            now=now,
            evidence_hash="4" * 64,
        )
        broker = NewlyPrivateBroker(first_branch=str(first_ledger["branch"]))
        coordinator = _coordinator(
            state=state,
            tmp_path=tmp_path,
            broker=broker,
            author=_FakeAuthor(),
        )

        outcome = coordinator.recover(
            policy=_repository_policy(private_target_opt_in=False),
            observed_at=now,
            require_live_lease=_live_lease,
            require_current_base_unchanged=_current_base,
            require_exact_open_source_authority=_open_source_authority,
        )

        assert outcome.failures == ("PreventionBranchMissing",)
        assert [draft.number for draft in outcome.drafts] == [83]
        first_resolution = state.prevention_resolution(first_key)
        assert first_resolution is not None
        assert first_resolution.resolution == "branch_missing"
        second_record = state.prevention_draft_by_key(second_key)
        assert second_record is not None
        assert second_record.phase == "draft_opened"


def test_recovery_workset_runs_only_once_per_repository_per_poll(
    tmp_path: Path,
) -> None:
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)

    class TransientBroker(_FakeBroker):
        def __init__(self) -> None:
            super().__init__()
            self.find_calls = 0

        def find_draft(self, **_kwargs: object) -> PreventionDraftResult | None:
            self.find_calls += 1
            raise PreventionRuntimeError("temporary GitHub observation failure")

    with GuardianState(tmp_path / "state.sqlite3") as state:
        _pending_prevention_ledger(state, now=now)
        broker = TransientBroker()
        coordinator = _coordinator(
            state=state,
            tmp_path=tmp_path,
            broker=broker,
            author=_FakeAuthor(),
        )

        first = coordinator.recover(
            policy=_repository_policy(),
            observed_at=now,
            require_live_lease=_live_lease,
            require_current_base_unchanged=_current_base,
            require_exact_open_source_authority=_open_source_authority,
        )
        second = coordinator.propose(
            policy=_repository_policy(),
            recurrence_candidates=(),
            evidence_revision_ids={},
            run_id="unused",
            observed_at=now,
            require_live_lease=_live_lease,
            require_current_base_unchanged=_current_base,
            require_exact_open_source_authority=_open_source_authority,
        )

        assert first.failures == ("PreventionRuntimeError",)
        assert second == prevention_runtime.PreventionBatchOutcome()
        assert broker.find_calls == 1


@pytest.mark.parametrize(
    ("branch_sha", "resolution", "failure"),
    [
        (None, "branch_missing", "PreventionBranchMissing"),
        ("c" * 40, "branch_modified", "PreventionBranchModified"),
    ],
)
def test_recovery_quarantines_branch_conflict_without_reauthoring(
    branch_sha: str | None,
    resolution: str,
    failure: str,
    tmp_path: Path,
) -> None:
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
    candidate = _candidate()
    evidence_ids = (f"review_comment:42:revision-{OPEN_SOURCE_REVISION_ID}",)
    evidence_hash = prevention_runtime.prevention_evidence_hash(
        root_cause=candidate.summary,
        evidence_feedback_ids=evidence_ids,
    )
    with GuardianState(tmp_path / "state.sqlite3") as state:
        draft_key, ledger = _pending_prevention_ledger(
            state,
            now=now,
            evidence_hash=evidence_hash,
        )
        broker = _FakeBroker()
        if branch_sha is not None:
            broker.branch_shas[str(ledger["branch"])] = branch_sha
        author = _FakeAuthor()
        coordinator = _coordinator(
            state=state,
            tmp_path=tmp_path,
            broker=broker,
            author=author,
        )

        recovered = coordinator.recover(
            policy=_repository_policy(),
            observed_at=now,
            require_live_lease=_live_lease,
            require_current_base_unchanged=_current_base,
            require_exact_open_source_authority=_open_source_authority,
        )
        assert recovered.failures == (failure,)
        terminal = state.prevention_resolution(draft_key)
        assert terminal is not None
        assert terminal.resolution == resolution

        coordinator.begin_poll()
        retried = coordinator.propose(
            policy=_repository_policy(),
            recurrence_candidates=(candidate,),
            evidence_revision_ids={"review_comment:42": OPEN_SOURCE_REVISION_ID},
            run_id=str(ledger["run_id"]),
            observed_at=now,
            require_live_lease=_live_lease,
            require_current_base_unchanged=_current_base,
            **_open_source_kwargs(),
        )
        assert retried.skipped == 1
        assert author.calls == 0


def test_recovery_operator_quarantine_race_vetoes_post(
    tmp_path: Path,
) -> None:
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
    with GuardianState(tmp_path / "state.sqlite3") as state:
        draft_key, ledger = _pending_prevention_ledger(
            state,
            now=now,
            evidence_hash="5" * 64,
        )

        class QuarantiningBroker(_FakeBroker):
            def open_draft(self, *, before_create, **_kwargs):
                state.record_prevention_resolution(
                    draft_key=draft_key,
                    resolution="operator_quarantined",
                    terminal_local_skip_acknowledged=True,
                    occurred_at=now,
                )
                before_create()
                raise AssertionError("quarantined candidate must not reach POST")

        broker = QuarantiningBroker()
        broker.branch_shas[str(ledger["branch"])] = CANDIDATE_SHA
        outcome = _coordinator(
            state=state,
            tmp_path=tmp_path,
            broker=broker,
            author=_FakeAuthor(),
        ).recover(
            policy=_repository_policy(),
            observed_at=now,
            require_live_lease=_live_lease,
            require_current_base_unchanged=_current_base,
            require_exact_open_source_authority=_open_source_authority,
        )

        assert outcome.drafts == ()
        assert outcome.failures == ("PreventionRecoveryStateChanged",)
        resolution = state.prevention_resolution(draft_key)
        assert resolution is not None
        assert resolution.resolution == "operator_quarantined"
        assert broker.open_calls == 0


def test_new_candidate_branch_conflict_is_ledgered_before_remote_check(
    tmp_path: Path,
) -> None:
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
    candidate = _candidate()
    policy = _repository_policy()
    prevention = policy.prevention
    assert prevention is not None
    evidence_ids = (f"review_comment:42:revision-{OPEN_SOURCE_REVISION_ID}",)
    evidence_hash = prevention_runtime.prevention_evidence_hash(
        root_cause=candidate.summary,
        evidence_feedback_ids=evidence_ids,
    )
    branch = prevention_runtime._branch_name(  # noqa: SLF001
        prevention,
        evidence_hash,
        BASE_SHA,
    )

    class ConflictingBranchBroker(_FakeBroker):
        def verify_publish_authority(self, **kwargs: object) -> None:
            super().verify_publish_authority(**kwargs)
            observed = self.branch_shas.get(str(kwargs["branch"]))
            if observed not in {None, kwargs["candidate_sha"]}:
                raise PreventionRuntimeError(
                    "Prevention branch already exists at an unexpected commit."
                )

    with GuardianState(tmp_path / "state.sqlite3") as state:
        run_id = state.start_run(
            repository="acme/translations",
            locale="ru",
            mode=GuardianMode.PROPOSE_PREVENTION,
            started_at=now,
        )
        broker = ConflictingBranchBroker()
        broker.branch_shas[branch] = "c" * 40
        author = _FakeAuthor()
        coordinator = _coordinator(
            state=state,
            tmp_path=tmp_path,
            broker=broker,
            author=author,
        )
        first = coordinator.propose(
            policy=policy,
            recurrence_candidates=(candidate,),
            evidence_revision_ids={
                "review_comment:42": OPEN_SOURCE_REVISION_ID,
            },
            run_id=run_id,
            observed_at=now,
            require_live_lease=_live_lease,
            require_current_base_unchanged=_current_base,
            **_open_source_kwargs(),
        )

        assert first.failures == ("PreventionRuntimeError",)
        pending = state.pending_prevention_drafts()
        assert len(pending) == 1
        assert pending[0].phase == "validated"
        assert author.calls == 1

        coordinator.begin_poll()
        second = coordinator.propose(
            policy=policy,
            recurrence_candidates=(candidate,),
            evidence_revision_ids={
                "review_comment:42": OPEN_SOURCE_REVISION_ID,
            },
            run_id=run_id,
            observed_at=now,
            require_live_lease=_live_lease,
            require_current_base_unchanged=_current_base,
            **_open_source_kwargs(),
        )

        assert second.failures == ("PreventionBranchModified",)
        assert second.skipped == 1
        assert author.calls == 1
        terminal = state.prevention_resolution(pending[0].draft_key)
        assert terminal is not None
        assert terminal.resolution == "branch_modified"


@pytest.mark.parametrize(
    "malformed_key",
    ["legacy-invalid-key", "", "x" * 4097, "8" * 64],
    ids=("invalid-key", "empty-key", "oversized-key", "missing-attestation"),
)
def test_bad_pending_record_is_isolated_while_new_intake_continues(
    malformed_key: str,
    tmp_path: Path,
) -> None:
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
    with GuardianState(tmp_path / "state.sqlite3") as state:
        run_id = state.start_run(
            repository="acme/translations",
            locale="ru",
            mode=GuardianMode.PROPOSE_PREVENTION,
            started_at=now,
        )
        state._connection.execute(  # noqa: SLF001 - legacy/crash fixture
            """
            INSERT INTO prevention_draft_events (
                draft_key, run_id, source_repository, target_repository,
                target_base_branch, target_base_sha, push_repository,
                branch, candidate_sha, evidence_hash, title, body, phase,
                occurred_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'validated', ?)
            """,
            (
                malformed_key,
                run_id,
                "acme/translations",
                "guardian/pipeline",
                "main",
                BASE_SHA,
                "guardian/pipeline",
                "guardian/prevention-" + "9" * 64,
                CANDIDATE_SHA,
                "9" * 64,
                "Legacy pending candidate",
                "Body\n",
                now.isoformat(),
            ),
        )
        state._connection.commit()  # noqa: SLF001 - legacy/crash fixture
        if len(malformed_key.encode()) > 4096:
            assert state.pending_prevention_draft_keys_for_recovery() == ()
            assert state.has_recoverable_prevention_drafts(
                source_repository="acme/translations",
                source_repository_id=42,
            )
        author = _FakeAuthor()
        coordinator = _coordinator(
            state=state,
            tmp_path=tmp_path,
            broker=_FakeBroker(),
            author=author,
        )

        outcome = coordinator.propose(
            policy=_repository_policy(),
            recurrence_candidates=(_candidate(),),
            evidence_revision_ids={"review_comment:42": OPEN_SOURCE_REVISION_ID},
            run_id=run_id,
            observed_at=now,
            require_live_lease=_live_lease,
            require_current_base_unchanged=_current_base,
            **_open_source_kwargs(),
        )

        assert len(outcome.drafts) == 1
        assert "PreventionInvalidRecord" in outcome.failures
        quarantine = state._connection.execute(  # noqa: SLF001
            """
            SELECT draft_key_digest
            FROM prevention_invalid_record_quarantines
            """
        ).fetchone()
        raw_key = malformed_key.encode()
        digest = (
            hashlib.sha256(
                f"sqlite-text:{len(raw_key)}:".encode("ascii") + raw_key[:4096]
            ).hexdigest()
            if len(raw_key) > 4096
            else hashlib.sha256(raw_key).hexdigest()
        )
        if prevention_runtime._HASH_RE.fullmatch(malformed_key):  # noqa: SLF001
            assert quarantine is None
            resolution = state.prevention_resolution(malformed_key)
            assert resolution is not None
            assert resolution.resolution == "invalid_record"
        else:
            assert quarantine is not None
            assert quarantine["draft_key_digest"] == digest
        health = state.latest_health("guardian_prevention_recovery")
        assert health is not None
        expected_safe_key = (
            malformed_key
            if prevention_runtime._HASH_RE.fullmatch(malformed_key)  # noqa: SLF001
            else f"invalid:{digest}"
        )
        assert health.details["draft_key"] == expected_safe_key
        if malformed_key and expected_safe_key != malformed_key:
            assert malformed_key not in json.dumps(health.details)
        assert state.pending_prevention_draft_keys_for_recovery() == ()
        status = state.status_snapshot(
            mode=GuardianMode.PROPOSE_PREVENTION,
            as_of=now,
        )
        assert status.conflicted_preventions == 1
        assert author.calls == 1


def test_non_text_pending_key_is_opaquely_quarantined_without_hiding_exact_pr(
    tmp_path: Path,
) -> None:
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
    raw_key = b"\x00secret-key\xff"

    class ExistingPullBroker(_FakeBroker):
        def find_draft(
            self, *, candidate_sha: str, **_kwargs: object
        ) -> PreventionDraftResult:
            return PreventionDraftResult(
                number=93,
                html_url="https://github.test/guardian/pipeline/pull/93",
                candidate_sha=candidate_sha,
                created=False,
            )

    with GuardianState(tmp_path / "state.sqlite3") as state:
        corrupt_run = state.start_run(
            repository="acme/translations",
            locale="ru",
            mode=GuardianMode.PROPOSE_PREVENTION,
            started_at=now,
        )
        state._connection.execute(  # noqa: SLF001 - corrupt legacy fixture
            """
            INSERT INTO prevention_draft_events (
                draft_key, run_id, source_repository, target_repository,
                target_base_branch, target_base_sha, push_repository,
                branch, candidate_sha, evidence_hash, title, body, phase,
                occurred_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'validated', ?)
            """,
            (
                raw_key,
                corrupt_run,
                "acme/translations",
                "guardian/pipeline",
                "main",
                BASE_SHA,
                "guardian/pipeline",
                "guardian/prevention-" + "7" * 64,
                CANDIDATE_SHA,
                "7" * 64,
                "Corrupt pending candidate",
                "Body\n",
                now.isoformat(),
            ),
        )
        state._connection.commit()  # noqa: SLF001 - corrupt legacy fixture
        exact_key, _ledger = _pending_prevention_ledger(state, now=now)
        coordinator = _coordinator(
            state=state,
            tmp_path=tmp_path,
            broker=ExistingPullBroker(),
            author=_FakeAuthor(),
        )

        outcome = coordinator.recover(
            policy=_repository_policy(),
            observed_at=now,
            require_live_lease=_live_lease,
            require_current_base_unchanged=_current_base,
            require_exact_open_source_authority=_open_source_authority,
        )

        assert [draft.number for draft in outcome.drafts] == [93]
        assert outcome.failures == ("PreventionInvalidRecord",)
        exact = state.prevention_draft_by_key(exact_key)
        assert exact is not None and exact.phase == "draft_opened"
        expected_digest = hashlib.sha256(
            f"sqlite-blob:{len(raw_key)}:".encode("ascii") + raw_key
        ).hexdigest()
        health = state.latest_health("guardian_prevention_recovery")
        assert health is not None
        assert health.details["draft_key"] == f"invalid:{expected_digest}"
        assert "secret-key" not in json.dumps(health.details)
        assert state.pending_prevention_draft_keys_for_recovery() == ()


def test_oversized_released_opened_record_is_quarantined_once_across_restart(
    tmp_path: Path,
) -> None:
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
    database = tmp_path / "state.sqlite3"
    oversized_key = "v" * (
        guardian_state._MAX_PREVENTION_INVALID_DRAFT_KEY_BYTES + 1  # noqa: SLF001
    )
    _create_v1_prevention_database(
        database,
        phase="draft_opened",
        evidence_hash="7" * 64,
        now=now,
        stored_draft_key=oversized_key,
    )
    broker = _FakeBroker()

    with GuardianState(database) as state:
        before = state.status_snapshot(
            mode=GuardianMode.PROPOSE_PREVENTION,
            as_of=now,
        )
        assert before.conflicted_preventions == 1
        first = _coordinator(
            state=state,
            tmp_path=tmp_path / "first",
            broker=broker,
            author=_FakeAuthor(),
        ).recover(
            policy=_repository_policy(),
            observed_at=now,
            require_live_lease=_live_lease,
            require_current_base_unchanged=_current_base,
            require_exact_open_source_authority=_open_source_authority,
        )
        assert first.failures == ("PreventionInvalidRecord",)
        assert broker.open_calls == 0
        assert (
            state._connection.execute(  # noqa: SLF001
                "SELECT COUNT(*) FROM prevention_invalid_record_quarantines"
            ).fetchone()[0]
            == 1
        )
        after = state.status_snapshot(
            mode=GuardianMode.PROPOSE_PREVENTION,
            as_of=now,
        )
        assert after.conflicted_preventions == 1

    with GuardianState(database) as state:
        restarted = _coordinator(
            state=state,
            tmp_path=tmp_path / "restart",
            broker=broker,
            author=_FakeAuthor(),
        ).recover(
            policy=_repository_policy(),
            observed_at=now + timedelta(minutes=1),
            require_live_lease=_live_lease,
            require_current_base_unchanged=_current_base,
            require_exact_open_source_authority=_open_source_authority,
        )
        assert restarted == prevention_runtime.PreventionBatchOutcome()
        assert (
            state._connection.execute(  # noqa: SLF001
                "SELECT COUNT(*) FROM prevention_invalid_record_quarantines"
            ).fetchone()[0]
            == 1
        )


def test_oversized_modern_records_are_scoped_by_immutable_repository_id(
    tmp_path: Path,
) -> None:
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
    with GuardianState(tmp_path / "state.sqlite3") as state:
        renamed_run_id = state.start_run(
            repository="acme/old-name",
            locale="ru",
            mode=GuardianMode.PROPOSE_PREVENTION,
            started_at=now,
        )
        wrong_id_run_id = state.start_run(
            repository="acme/translations",
            locale="ru",
            mode=GuardianMode.PROPOSE_PREVENTION,
            started_at=now,
        )
        renamed_key = "r" * (
            guardian_state._MAX_PREVENTION_INVALID_DRAFT_KEY_BYTES + 1  # noqa: SLF001
        )
        wrong_id_key = "w" * (
            guardian_state._MAX_PREVENTION_INVALID_DRAFT_KEY_BYTES + 1  # noqa: SLF001
        )
        _insert_self_consistent_corrupt_prevention(
            state,
            run_id=renamed_run_id,
            branch="guardian/prevention-renamed",
            occurred_at="2026-08-30T12:00:00.000000Z",
            source_repository="acme/old-name",
            source_repository_id=42,
            stored_draft_key=renamed_key,
        )
        _insert_self_consistent_corrupt_prevention(
            state,
            run_id=wrong_id_run_id,
            branch="guardian/prevention-wrong-id",
            occurred_at="2026-08-30T12:00:01.000000Z",
            source_repository="acme/translations",
            source_repository_id=99,
            stored_draft_key=wrong_id_key,
        )

        assert state.has_recoverable_prevention_drafts(
            source_repository="acme/translations",
            source_repository_id=42,
        )
        first = state.quarantine_unaddressable_prevention_records(
            source_repository="acme/translations",
            source_repository_id=42,
            occurred_at=now,
        )
        assert len(first) == 1
        quarantined = state._connection.execute(  # noqa: SLF001
            """
            SELECT event.draft_key
            FROM prevention_invalid_record_quarantines AS quarantine
            JOIN prevention_draft_events AS event
              ON event.prevention_event_id = quarantine.prevention_event_id
            """
        ).fetchall()
        assert [str(row["draft_key"]) for row in quarantined] == [renamed_key]
        assert not state.has_recoverable_prevention_drafts(
            source_repository="acme/translations",
            source_repository_id=42,
        )
        assert state.has_recoverable_prevention_drafts(
            source_repository="acme/new-name",
            source_repository_id=99,
        )


@pytest.mark.parametrize(
    "corruption",
    [
        "unsafe-branch",
        "naive-timestamp",
        "recursive-json",
        "aliased-historical-source",
        "oversized-body",
    ],
)
def test_corrupt_persisted_ledger_is_isolated_before_broker_access(
    corruption: str,
    tmp_path: Path,
) -> None:
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)

    class ExactOnlyBroker(_FakeBroker):
        def __init__(self) -> None:
            super().__init__()
            self.find_calls = 0

        def find_draft(
            self, *, candidate_sha: str, **_kwargs: object
        ) -> PreventionDraftResult:
            self.find_calls += 1
            return PreventionDraftResult(
                number=94,
                html_url="https://github.test/guardian/pipeline/pull/94",
                candidate_sha=candidate_sha,
                created=False,
            )

    with GuardianState(tmp_path / "state.sqlite3") as state:
        _seed_open_source_event(state)
        corrupt_run = state.start_run(
            repository="acme/translations",
            locale="ru",
            mode=GuardianMode.PROPOSE_PREVENTION,
            started_at=now,
        )
        aliased_sources: tuple[HistoricalPullReference, ...] = ()
        if corruption == "aliased-historical-source":
            aliased_sources = (
                HistoricalPullReference(
                    repository="acme/translations",
                    repository_id=42,
                    pull_id=500,
                    pr_number=12,
                    pull_revision_digest="1" * 64,
                    authority_digest="2" * 64,
                    policy_digest="3" * 64,
                    head_sha="c" * 40,
                    base_sha="d" * 40,
                ),
                HistoricalPullReference(
                    repository="acme/translations",
                    repository_id=42,
                    pull_id=500,
                    pr_number=13,
                    pull_revision_digest="4" * 64,
                    authority_digest="5" * 64,
                    policy_digest="3" * 64,
                    head_sha="c" * 40,
                    base_sha="d" * 40,
                ),
            )
        corrupt_key = _insert_self_consistent_corrupt_prevention(
            state,
            run_id=corrupt_run,
            branch=(
                "guardian/prevention-../escape"
                if corruption == "unsafe-branch"
                else "guardian/prevention-" + "6" * 64
            ),
            occurred_at=(
                "2026-08-30T12:00:00"
                if corruption == "naive-timestamp"
                else "2026-08-30T12:00:00.000000Z"
            ),
            source_policy_json=(
                '{"nested":' + "[" * 1200 + "0" + "]" * 1200 + "}"
                if corruption == "recursive-json"
                else None
            ),
            source_pulls=aliased_sources,
            body=(
                "x" * (guardian_state._MAX_PREVENTION_BODY_BYTES + 1)  # noqa: SLF001
                if corruption == "oversized-body"
                else "Validated body\n"
            ),
        )
        exact_key, _ledger = _pending_prevention_ledger(state, now=now)
        broker = ExactOnlyBroker()
        coordinator = _coordinator(
            state=state,
            tmp_path=tmp_path,
            broker=broker,
            author=_FakeAuthor(),
        )

        outcome = coordinator.recover(
            policy=_repository_policy(),
            observed_at=now,
            require_live_lease=_live_lease,
            require_current_base_unchanged=_current_base,
            require_exact_open_source_authority=_open_source_authority,
        )

        assert [draft.number for draft in outcome.drafts] == [94]
        assert outcome.failures == ("PreventionInvalidRecord",)
        assert broker.find_calls == 1
        resolution = state.prevention_resolution(corrupt_key)
        assert resolution is not None and resolution.resolution == "invalid_record"
        exact = state.prevention_draft_by_key(exact_key)
        assert exact is not None and exact.phase == "draft_opened"


def test_full_invalid_record_quarantine_cannot_starve_exact_pr_recovery(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
    monkeypatch.setattr(guardian_state, "_MAX_PREVENTION_INVALID_QUARANTINES", 1)

    class ExistingPullBroker(_FakeBroker):
        def find_draft(
            self, *, candidate_sha: str, **_kwargs: object
        ) -> PreventionDraftResult:
            return PreventionDraftResult(
                number=91,
                html_url="https://github.test/guardian/pipeline/pull/91",
                candidate_sha=candidate_sha,
                created=False,
            )

    with GuardianState(tmp_path / "state.sqlite3") as state:
        corrupt_run = state.start_run(
            repository="acme/translations",
            locale="ru",
            mode=GuardianMode.PROPOSE_PREVENTION,
            started_at=now,
        )

        def insert_corrupt(draft_key: str) -> None:
            state._connection.execute(  # noqa: SLF001 - corrupt legacy fixture
                """
                INSERT INTO prevention_draft_events (
                    draft_key, run_id, source_repository, target_repository,
                    target_base_branch, target_base_sha, push_repository,
                    branch, candidate_sha, evidence_hash, title, body, phase,
                    occurred_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'validated', ?)
                """,
                (
                    draft_key,
                    corrupt_run,
                    "acme/translations",
                    "guardian/pipeline",
                    "main",
                    BASE_SHA,
                    "guardian/pipeline",
                    "guardian/prevention-" + "9" * 64,
                    CANDIDATE_SHA,
                    "9" * 64,
                    "Corrupt pending candidate",
                    "Body\n",
                    now.isoformat(),
                ),
            )

        insert_corrupt("legacy-invalid-key")
        corrupt_keys = tuple(
            hashlib.sha256(f"corrupt-{index}".encode()).hexdigest()
            for index in range(100)
        )
        for corrupt_key in corrupt_keys:
            insert_corrupt(corrupt_key)
        state._connection.commit()  # noqa: SLF001 - corrupt legacy fixture
        exact_key, _ledger = _pending_prevention_ledger(state, now=now)
        coordinator = _coordinator(
            state=state,
            tmp_path=tmp_path,
            broker=ExistingPullBroker(),
            author=_FakeAuthor(),
        )

        first = coordinator.recover(
            policy=_repository_policy(),
            observed_at=now,
            require_live_lease=_live_lease,
            require_current_base_unchanged=_current_base,
            require_exact_open_source_authority=_open_source_authority,
        )
        assert first.drafts == ()
        assert first.failures.count("PreventionInvalidRecord") == 100
        assert state.prevention_resolution(corrupt_keys[0]) is not None

        coordinator.begin_poll()
        second = coordinator.recover(
            policy=_repository_policy(),
            observed_at=now,
            require_live_lease=_live_lease,
            require_current_base_unchanged=_current_base,
            require_exact_open_source_authority=_open_source_authority,
        )

        assert [draft.number for draft in second.drafts] == [91]
        assert second.failures == ("PreventionInvalidRecord",)
        exact = state.prevention_draft_by_key(exact_key)
        assert exact is not None and exact.phase == "draft_opened"
        quarantines = state._connection.execute(  # noqa: SLF001
            "SELECT COUNT(*) FROM prevention_invalid_record_quarantines"
        ).fetchone()
        assert quarantines is not None and quarantines[0] == 1
        assert state.pending_prevention_draft_keys_for_recovery() == ()


def test_coordinator_recovery_does_not_touch_credentials_without_pending_state(
    tmp_path: Path,
) -> None:
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
    with GuardianState(tmp_path / "state.sqlite3") as state:
        broker = _FakeBroker()
        coordinator = _coordinator(
            state=state,
            tmp_path=tmp_path,
            broker=broker,
            author=_FakeAuthor(),
        )

        outcome = coordinator.recover(
            policy=_repository_policy(),
            observed_at=now,
            require_live_lease=_live_lease,
            require_current_base_unchanged=_current_base,
            require_exact_open_source_authority=_open_source_authority,
        )

        assert outcome == prevention_runtime.PreventionBatchOutcome()
        assert broker.capture_calls == 0


def test_coordinator_defers_over_cap_then_completes_on_next_poll(
    tmp_path: Path,
) -> None:
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
    with GuardianState(tmp_path / "state.sqlite3") as state:
        run_id = state.start_run(
            repository="acme/translations",
            locale="ru",
            mode=GuardianMode.PROPOSE_PREVENTION,
            started_at=now,
        )
        broker = _FakeBroker()
        author = _FakeAuthor()
        coordinator = _coordinator(
            state=state,
            tmp_path=tmp_path,
            broker=broker,
            author=author,
            max_drafts=1,
        )
        candidates = (
            _candidate("First distinct pipeline recurrence"),
            _candidate("Second distinct pipeline recurrence"),
        )

        first = coordinator.propose(
            policy=_repository_policy(),
            recurrence_candidates=candidates,
            evidence_revision_ids={"review_comment:42": OPEN_SOURCE_REVISION_ID},
            run_id=run_id,
            observed_at=now,
            require_live_lease=_live_lease,
            require_current_base_unchanged=_current_base,
            **_open_source_kwargs(),
        )
        coordinator.begin_poll()
        second = coordinator.propose(
            policy=_repository_policy(),
            recurrence_candidates=candidates,
            evidence_revision_ids={"review_comment:42": OPEN_SOURCE_REVISION_ID},
            run_id=run_id,
            observed_at=now,
            require_live_lease=_live_lease,
            require_current_base_unchanged=_current_base,
            **_open_source_kwargs(),
        )

        assert len(first.drafts) == 1
        assert first.deferred == 1
        assert len(second.drafts) == 1
        assert second.skipped == 1
        assert second.deferred == 0
        assert author.calls == 2
        assert broker.open_calls == 2


def test_failed_candidate_consumes_the_poll_authoring_slot(tmp_path: Path) -> None:
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)

    class FirstInvalidAuthor(_FakeAuthor):
        def run(self, *, workspace: Path, **_kwargs) -> PreventionAuthorResult:
            self.calls += 1
            if self.calls == 1:
                (workspace / "localize/rules.py").write_text(
                    "def preserve(value):\n    return value.strip()\n",
                    encoding="utf-8",
                )
                return PreventionAuthorResult(attempts=1, usage=None)
            raise AssertionError("a second candidate must be deferred in this poll")

    with GuardianState(tmp_path / "state.sqlite3") as state:
        run_id = state.start_run(
            repository="acme/translations",
            locale="ru",
            mode=GuardianMode.PROPOSE_PREVENTION,
            started_at=now,
        )
        author = FirstInvalidAuthor()
        coordinator = _coordinator(
            state=state,
            tmp_path=tmp_path,
            broker=_FakeBroker(),
            author=author,
            max_drafts=1,
        )

        outcome = coordinator.propose(
            policy=_repository_policy(),
            recurrence_candidates=(
                _candidate("First invalid recurrence"),
                _candidate("Second recurrence"),
            ),
            evidence_revision_ids={"review_comment:42": OPEN_SOURCE_REVISION_ID},
            run_id=run_id,
            observed_at=now,
            require_live_lease=_live_lease,
            require_current_base_unchanged=_current_base,
            **_open_source_kwargs(),
        )

        assert author.calls == 1
        assert outcome.drafts == ()
        assert outcome.deferred == 1
        assert outcome.failures == ("PreventionPolicyError",)


def test_open_draft_failures_consume_slot_without_pushing_more_branches(
    tmp_path: Path,
) -> None:
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)

    class FailingDraftBroker(_FakeBroker):
        def open_draft(self, **kwargs):
            kwargs["before_create"]()
            self.open_calls += 1
            raise PreventionRuntimeError("draft API failed")

    with GuardianState(tmp_path / "state.sqlite3") as state:
        run_id = state.start_run(
            repository="acme/translations",
            locale="ru",
            mode=GuardianMode.PROPOSE_PREVENTION,
            started_at=now,
        )
        broker = FailingDraftBroker()
        author = _FakeAuthor()
        coordinator = _coordinator(
            state=state,
            tmp_path=tmp_path,
            broker=broker,
            author=author,
            max_drafts=1,
        )
        candidates = (
            _candidate("First pipeline recurrence"),
            _candidate("Second pipeline recurrence"),
        )

        first = coordinator.propose(
            policy=_repository_policy(),
            recurrence_candidates=candidates,
            evidence_revision_ids={"review_comment:42": OPEN_SOURCE_REVISION_ID},
            run_id=run_id,
            observed_at=now,
            require_live_lease=_live_lease,
            require_current_base_unchanged=_current_base,
            **_open_source_kwargs(),
        )

        checkout_factory = coordinator.checkout_factory
        assert isinstance(checkout_factory, _FakeCheckoutFactory)
        assert checkout_factory.publications == 1
        assert author.calls == 1
        assert broker.open_calls == 1
        assert first.deferred == 1
        assert first.failures == ("PreventionRuntimeError",)

        coordinator.begin_poll()
        retried = coordinator.propose(
            policy=_repository_policy(),
            recurrence_candidates=candidates,
            evidence_revision_ids={"review_comment:42": OPEN_SOURCE_REVISION_ID},
            run_id=run_id,
            observed_at=now,
            require_live_lease=_live_lease,
            require_current_base_unchanged=_current_base,
            **_open_source_kwargs(),
        )

        # Recovery retries the one already-pushed branch. It consumes the new
        # poll's sole mutation slot before POST and cannot push another branch.
        assert checkout_factory.publications == 1
        assert author.calls == 1
        assert broker.open_calls == 2
        assert retried.failures == ("PreventionRuntimeError",)


def test_coordinator_treats_model_credential_failure_as_authentication_failure(
    tmp_path: Path,
) -> None:
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)

    def unavailable() -> str:
        raise RuntimeError("secret helper detail")

    with GuardianState(tmp_path / "state.sqlite3") as state:
        run_id = state.start_run(
            repository="acme/translations",
            locale="ru",
            mode=GuardianMode.PROPOSE_PREVENTION,
            started_at=now,
        )
        coordinator = _coordinator(
            state=state,
            tmp_path=tmp_path,
            broker=_FakeBroker(),
            author=_FakeAuthor(),
            model_credential_provider=unavailable,
        )

        with pytest.raises(CodexAuthenticationError) as error:
            coordinator.propose(
                policy=_repository_policy(),
                recurrence_candidates=(_candidate(),),
                evidence_revision_ids={"review_comment:42": OPEN_SOURCE_REVISION_ID},
                run_id=run_id,
                observed_at=now,
                require_live_lease=_live_lease,
                require_current_base_unchanged=_current_base,
                **_open_source_kwargs(),
            )

        assert "secret helper detail" not in str(error.value)


def test_coordinator_propagates_github_authentication_failure_to_poll_circuit(
    tmp_path: Path,
) -> None:
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)

    class AuthenticationFailureBroker(_FakeBroker):
        def verify_publish_authority(self, **_kwargs) -> None:
            raise GitHubAuthenticationError("redacted GitHub authentication failure")

    with GuardianState(tmp_path / "state.sqlite3") as state:
        run_id = state.start_run(
            repository="acme/translations",
            locale="ru",
            mode=GuardianMode.PROPOSE_PREVENTION,
            started_at=now,
        )
        coordinator = _coordinator(
            state=state,
            tmp_path=tmp_path,
            broker=AuthenticationFailureBroker(),
            author=_FakeAuthor(),
        )

        with pytest.raises(GitHubAuthenticationError):
            coordinator.propose(
                policy=_repository_policy(),
                recurrence_candidates=(_candidate(),),
                evidence_revision_ids={"review_comment:42": OPEN_SOURCE_REVISION_ID},
                run_id=run_id,
                observed_at=now,
                require_live_lease=_live_lease,
                require_current_base_unchanged=_current_base,
                **_open_source_kwargs(),
            )


def test_coordinator_propagates_model_capacity_failure_to_poll_circuit(
    tmp_path: Path,
) -> None:
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)

    class CapacityFailureAuthor(_FakeAuthor):
        def run(self, *, workspace: Path, **_kwargs) -> PreventionAuthorResult:
            self.calls += 1
            raise CodexCapacityError("redacted model capacity failure")

    with GuardianState(tmp_path / "state.sqlite3") as state:
        run_id = state.start_run(
            repository="acme/translations",
            locale="ru",
            mode=GuardianMode.PROPOSE_PREVENTION,
            started_at=now,
        )
        author = CapacityFailureAuthor()
        coordinator = _coordinator(
            state=state,
            tmp_path=tmp_path,
            broker=_FakeBroker(),
            author=author,
            api_billed=False,
        )

        with pytest.raises(CodexCapacityError):
            coordinator.propose(
                policy=_repository_policy(),
                recurrence_candidates=(_candidate(),),
                evidence_revision_ids={"review_comment:42": OPEN_SOURCE_REVISION_ID},
                run_id=run_id,
                observed_at=now,
                require_live_lease=_live_lease,
                require_current_base_unchanged=_current_base,
                **_open_source_kwargs(),
            )

        assert author.calls == 1
        assert state.model_calls_committed_for_day(now.date()) == 1


def test_coordinator_accounts_for_each_author_attempt_independently(
    tmp_path: Path,
) -> None:
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)

    class RetryingAuthor(_FakeAuthor):
        max_attempts = 2

        def run(self, *, workspace: Path, **kwargs) -> PreventionAuthorResult:
            if self.calls == 0:
                self.calls += 1
                raise prevention_runtime.CodexTransientError("first attempt failed")
            return super().run(workspace=workspace, **kwargs)

    with GuardianState(tmp_path / "state.sqlite3") as state:
        run_id = state.start_run(
            repository="acme/translations",
            locale="ru",
            mode=GuardianMode.PROPOSE_PREVENTION,
            started_at=now,
        )
        author = RetryingAuthor()
        coordinator = _coordinator(
            state=state,
            tmp_path=tmp_path,
            broker=_FakeBroker(),
            author=author,
        )

        outcome = coordinator.propose(
            policy=_repository_policy(),
            recurrence_candidates=(_candidate(),),
            evidence_revision_ids={"review_comment:42": OPEN_SOURCE_REVISION_ID},
            run_id=run_id,
            observed_at=now,
            require_live_lease=_live_lease,
            require_current_base_unchanged=_current_base,
            **_open_source_kwargs(),
        )

        assert len(outcome.drafts) == 1
        assert author.calls == 2
        # The failed attempt retains its full conservative $1 reservation;
        # only the successful attempt settles to reported usage.
        assert float(state.budget_committed_for_day(now.date())) == pytest.approx(1.01)


def test_retry_is_fresh_and_old_credential_is_scanned_in_signing_tree(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
    first_key = "sk-first-prevention-attempt"
    second_key = "sk-second-prevention-attempt"

    class RetryingAuthor(_FakeAuthor):
        max_attempts = 2

        def __init__(self) -> None:
            super().__init__()
            self.second_attempt_was_clean = False

        def run(self, *, workspace: Path, **kwargs) -> PreventionAuthorResult:
            marker = workspace / "attempt-one-only"
            if self.calls == 0:
                self.calls += 1
                marker.write_text("partial model edit\n", encoding="utf-8")
                raise prevention_runtime.CodexTransientError("retry")
            self.second_attempt_was_clean = not marker.exists()
            return super().run(workspace=workspace, **kwargs)

    original_inspection = prevention_runtime.inspect_prevention_patch
    inspections = 0

    def inject_old_key_after_signing_inspection(**kwargs):
        nonlocal inspections
        patch = original_inspection(**kwargs)
        inspections += 1
        if inspections == 2:
            candidate = kwargs["candidate_workspace"] / "localize/rules.py"
            candidate.write_text(
                candidate.read_text(encoding="utf-8") + f"\nLEAKED = {first_key!r}\n",
                encoding="utf-8",
            )
        return patch

    monkeypatch.setattr(
        prevention_runtime,
        "inspect_prevention_patch",
        inject_old_key_after_signing_inspection,
    )
    credentials = iter((first_key, second_key))
    with GuardianState(tmp_path / "state.sqlite3") as state:
        run_id = state.start_run(
            repository="acme/translations",
            locale="ru",
            mode=GuardianMode.PROPOSE_PREVENTION,
            started_at=now,
        )
        broker = _FakeBroker()
        author = RetryingAuthor()
        coordinator = _coordinator(
            state=state,
            tmp_path=tmp_path,
            broker=broker,
            author=author,
            model_credential_provider=lambda: next(credentials),
        )

        outcome = coordinator.propose(
            policy=_repository_policy(),
            recurrence_candidates=(_candidate(),),
            evidence_revision_ids={"review_comment:42": OPEN_SOURCE_REVISION_ID},
            run_id=run_id,
            observed_at=now,
            require_live_lease=_live_lease,
            require_current_base_unchanged=_current_base,
            **_open_source_kwargs(),
        )

        assert author.calls == 2
        assert author.second_attempt_was_clean is True
        assert outcome.failures == ("PreventionRuntimeError",)
        assert coordinator.checkout_factory.publications == 0
        assert broker.open_calls == 0


def test_transient_attempt_credential_leak_stops_before_retry(
    tmp_path: Path,
) -> None:
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
    secret = "sk-transient-attempt-leak"

    class LeakingTransientAuthor(_FakeAuthor):
        max_attempts = 2

        def run(self, *, workspace: Path, **_kwargs) -> PreventionAuthorResult:
            self.calls += 1
            (workspace / "localize/rules.py").write_text(
                f"LEAKED = {secret!r}\n",
                encoding="utf-8",
            )
            raise prevention_runtime.CodexTransientError("retry")

    with GuardianState(tmp_path / "state.sqlite3") as state:
        run_id = state.start_run(
            repository="acme/translations",
            locale="ru",
            mode=GuardianMode.PROPOSE_PREVENTION,
            started_at=now,
        )
        broker = _FakeBroker()
        author = LeakingTransientAuthor()
        coordinator = _coordinator(
            state=state,
            tmp_path=tmp_path,
            broker=broker,
            author=author,
            model_credential_provider=lambda: secret,
        )

        outcome = coordinator.propose(
            policy=_repository_policy(),
            recurrence_candidates=(_candidate(),),
            evidence_revision_ids={"review_comment:42": OPEN_SOURCE_REVISION_ID},
            run_id=run_id,
            observed_at=now,
            require_live_lease=_live_lease,
            require_current_base_unchanged=_current_base,
            **_open_source_kwargs(),
        )

        assert outcome.failures == ("PreventionRuntimeError",)
        assert author.calls == 1
        assert coordinator.checkout_factory.publications == 0
        assert broker.open_calls == 0


def test_coordinator_accounts_author_retries_on_their_actual_utc_days(
    tmp_path: Path,
) -> None:
    first_day = datetime(2026, 8, 30, 23, 59, tzinfo=UTC)
    second_day = datetime(2026, 8, 31, 0, 1, tzinfo=UTC)
    timestamps = iter((first_day, first_day, second_day, second_day))

    class RetryingAuthor(_FakeAuthor):
        max_attempts = 2

        def run(self, *, workspace: Path, **kwargs) -> PreventionAuthorResult:
            if self.calls == 0:
                self.calls += 1
                raise prevention_runtime.CodexTransientError("first attempt failed")
            return super().run(workspace=workspace, **kwargs)

    with GuardianState(tmp_path / "state.sqlite3") as state:
        run_id = state.start_run(
            repository="acme/translations",
            locale="ru",
            mode=GuardianMode.PROPOSE_PREVENTION,
            started_at=first_day,
        )
        coordinator = _coordinator(
            state=state,
            tmp_path=tmp_path,
            broker=_FakeBroker(),
            author=RetryingAuthor(),
            now=lambda: next(timestamps),
        )

        outcome = coordinator.propose(
            policy=_repository_policy(),
            recurrence_candidates=(_candidate(),),
            evidence_revision_ids={"review_comment:42": OPEN_SOURCE_REVISION_ID},
            run_id=run_id,
            observed_at=first_day,
            require_live_lease=_live_lease,
            require_current_base_unchanged=_current_base,
            **_open_source_kwargs(),
        )

        assert len(outcome.drafts) == 1
        assert float(state.budget_committed_for_day(first_day.date())) == 1.0
        assert float(state.budget_committed_for_day(second_day.date())) == 0.01


def test_coordinator_skips_project_specific_scope_and_requires_private_opt_in(
    tmp_path: Path,
) -> None:
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
    with GuardianState(tmp_path / "state.sqlite3") as state:
        run_id = state.start_run(
            repository="acme/translations",
            locale="ru",
            mode=GuardianMode.PROPOSE_PREVENTION,
            started_at=now,
        )
        author = _FakeAuthor()
        coordinator = _coordinator(
            state=state,
            tmp_path=tmp_path,
            broker=_FakeBroker(),
            author=author,
        )
        project_candidate = RecurrenceCandidate(
            scope="project_config",
            summary="Change the consuming project's glossary",
            evidence_feedback_ids=("review_comment:42",),
        )
        outcome = coordinator.propose(
            policy=_repository_policy(),
            recurrence_candidates=(project_candidate,),
            evidence_revision_ids={"review_comment:42": OPEN_SOURCE_REVISION_ID},
            run_id=run_id,
            observed_at=now,
            require_live_lease=_live_lease,
            require_current_base_unchanged=_current_base,
            **_open_source_kwargs(),
        )
        assert outcome.skipped == 1
        assert author.calls == 0

    private_root = tmp_path / "private"
    private_root.mkdir(mode=0o700)
    with GuardianState(private_root / "state.sqlite3") as state:
        run_id = state.start_run(
            repository="acme/translations",
            locale="ru",
            mode=GuardianMode.PROPOSE_PREVENTION,
            started_at=now,
        )
        coordinator = _coordinator(
            state=state,
            tmp_path=private_root,
            broker=_FakeBroker(private=True),
            author=_FakeAuthor(),
        )
        # Source-repository model consent must not authorize a distinct private
        # prevention target.
        with pytest.raises(PreventionRuntimeError, match="opt-in"):
            coordinator.propose(
                policy=_repository_policy(private_opt_in=True),
                recurrence_candidates=(_candidate(),),
                evidence_revision_ids={"review_comment:42": OPEN_SOURCE_REVISION_ID},
                run_id=run_id,
                observed_at=now,
                require_live_lease=_live_lease,
                require_current_base_unchanged=_current_base,
                **_open_source_kwargs(),
            )

        opted_in = coordinator.propose(
            policy=_repository_policy(private_target_opt_in=True),
            recurrence_candidates=(_candidate(),),
            evidence_revision_ids={"review_comment:42": OPEN_SOURCE_REVISION_ID},
            run_id=run_id,
            observed_at=now,
            require_live_lease=_live_lease,
            require_current_base_unchanged=_current_base,
            **_open_source_kwargs(),
        )
        assert len(opted_in.drafts) == 1


def test_lease_loss_after_model_completion_prevents_validated_ledger_write(
    tmp_path: Path,
) -> None:
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
    with GuardianState(tmp_path / "state.sqlite3") as state:
        run_id = state.start_run(
            repository="acme/translations",
            locale="ru",
            mode=GuardianMode.PROPOSE_PREVENTION,
            started_at=now,
        )
        author = _FakeAuthor()
        coordinator = _coordinator(
            state=state,
            tmp_path=tmp_path,
            broker=_FakeBroker(),
            author=author,
            api_billed=False,
        )

        def lose_after_model_completion() -> None:
            status = state._connection.execute(  # noqa: SLF001
                """
                SELECT status FROM model_call_reservations
                ORDER BY call_id DESC LIMIT 1
                """
            ).fetchone()
            if status is not None and status[0] == "completed":
                raise RuntimeError("lease moved to another worker")

        with pytest.raises(prevention_runtime.PreventionLeaseLostError):
            coordinator.propose(
                policy=_repository_policy(),
                recurrence_candidates=(_candidate(),),
                evidence_revision_ids={"review_comment:42": OPEN_SOURCE_REVISION_ID},
                run_id=run_id,
                observed_at=now,
                require_live_lease=lose_after_model_completion,
                require_current_base_unchanged=_current_base,
                **_open_source_kwargs(),
            )

        assert author.calls == 1
        assert state.pending_prevention_drafts() == ()
        events = state._connection.execute(  # noqa: SLF001
            "SELECT COUNT(*) FROM prevention_draft_events"
        ).fetchone()
        assert events is not None and events[0] == 0


def test_recovery_lease_loss_aborts_before_attempt_and_new_model_work(
    tmp_path: Path,
) -> None:
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
    with GuardianState(tmp_path / "state.sqlite3") as state:
        _draft_key, ledger = _pending_prevention_ledger(state, now=now)
        author = _FakeAuthor()
        coordinator = _coordinator(
            state=state,
            tmp_path=tmp_path,
            broker=_FakeBroker(),
            author=author,
        )

        def lost_lease() -> None:
            raise RuntimeError("lease moved to another worker")

        with pytest.raises(prevention_runtime.PreventionLeaseLostError):
            coordinator.propose(
                policy=_repository_policy(),
                recurrence_candidates=(_candidate("A distinct later recurrence"),),
                evidence_revision_ids={"review_comment:42": OPEN_SOURCE_REVISION_ID},
                run_id=str(ledger["run_id"]),
                observed_at=now,
                require_live_lease=lost_lease,
                require_current_base_unchanged=_current_base,
                **_open_source_kwargs(),
            )

        attempts = state._connection.execute(  # noqa: SLF001
            "SELECT COUNT(*) FROM prevention_recovery_attempt_events"
        ).fetchone()
        assert attempts is not None and attempts[0] == 0
        assert author.calls == 0


def test_source_preflight_generic_error_preserves_lease_loss(
    tmp_path: Path,
) -> None:
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
    lease_live = True

    def lose_lease_during_source_check(
        _source: OpenPullAuthorityReference,
        _revision_ids: Sequence[int],
    ) -> None:
        nonlocal lease_live
        lease_live = False
        raise RuntimeError("source callback failed after lease loss")

    def require_lease() -> None:
        if not lease_live:
            raise RuntimeError("lease moved to another worker")

    with GuardianState(tmp_path / "state.sqlite3") as state:
        run_id = state.start_run(
            repository="acme/translations",
            locale="ru",
            mode=GuardianMode.PROPOSE_PREVENTION,
            started_at=now,
        )
        author = _FakeAuthor()
        coordinator = _coordinator(
            state=state,
            tmp_path=tmp_path,
            broker=_FakeBroker(),
            author=author,
        )

        with pytest.raises(prevention_runtime.PreventionLeaseLostError):
            coordinator.propose(
                policy=_repository_policy(),
                recurrence_candidates=(_candidate(),),
                evidence_revision_ids={"review_comment:42": OPEN_SOURCE_REVISION_ID},
                run_id=run_id,
                observed_at=now,
                require_live_lease=require_lease,
                require_current_base_unchanged=_current_base,
                open_source=_open_source(),
                source_event_revision_ids=(OPEN_SOURCE_REVISION_ID,),
                require_exact_open_source_authority=(lose_lease_during_source_check),
            )

        assert author.calls == 0


def test_recovery_source_callback_generic_error_preserves_lease_loss(
    tmp_path: Path,
) -> None:
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
    lease_live = True

    def lose_lease_during_source_check(
        _source: OpenPullAuthorityReference,
        _revision_ids: Sequence[int],
    ) -> None:
        nonlocal lease_live
        lease_live = False
        raise RuntimeError("source callback failed after lease loss")

    def require_lease() -> None:
        if not lease_live:
            raise RuntimeError("lease moved to another worker")

    with GuardianState(tmp_path / "state.sqlite3") as state:
        draft_key, _ledger = _pending_prevention_ledger(state, now=now)
        coordinator = _coordinator(
            state=state,
            tmp_path=tmp_path,
            broker=_FakeBroker(),
            author=_FakeAuthor(),
        )

        with pytest.raises(prevention_runtime.PreventionLeaseLostError):
            coordinator.recover(
                policy=_repository_policy(),
                observed_at=now,
                require_live_lease=require_lease,
                require_current_base_unchanged=_current_base,
                require_exact_open_source_authority=(lose_lease_during_source_check),
            )

        record = state.prevention_draft_by_key(draft_key)
        assert record is not None and record.phase == "pushed"
        assert state.prevention_resolution(draft_key) is None


@pytest.mark.parametrize(
    ("phase", "title"),
    [
        ("pushed", "防" * 120),
        ("draft_opened", "Prevent recurrence: placeholder parity"),
    ],
    ids=("post-crash-multibyte-title", "opened-ledger-crash"),
)
def test_released_v1_candidate_only_reconciles_exact_existing_draft(
    phase: str,
    title: str,
    tmp_path: Path,
) -> None:
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
    candidate = _candidate()
    evidence_hash = prevention_runtime.prevention_evidence_hash(
        root_cause=candidate.summary,
        evidence_feedback_ids=("review_comment:42:revision-1",),
    )
    database = tmp_path / "state.sqlite3"
    draft_key, _branch = _create_v1_prevention_database(
        database,
        phase=phase,
        evidence_hash=evidence_hash,
        now=now,
        title=title,
    )
    lease_live = True

    class ExactLegacyBroker(_FakeBroker):
        def __init__(self) -> None:
            super().__init__()
            self.find_calls = 0

        def find_draft(
            self, *, candidate_sha: str, title: str, **_kwargs: object
        ) -> PreventionDraftResult:
            nonlocal lease_live
            self.find_calls += 1
            assert title == title_value
            lease_live = False
            return PreventionDraftResult(
                number=91,
                html_url="https://github.test/guardian/pipeline/pull/91",
                candidate_sha=candidate_sha,
                created=False,
            )

    title_value = title
    broker = ExactLegacyBroker()

    def lost_lease() -> None:
        if not lease_live:
            raise RuntimeError("stale worker")

    first_root = tmp_path / "first"
    with GuardianState(database) as state:
        coordinator = _coordinator(
            state=state,
            tmp_path=first_root,
            broker=broker,
            author=_FakeAuthor(),
        )
        outcome = coordinator.recover(
            policy=_repository_policy(),
            observed_at=now,
            require_live_lease=lost_lease,
            require_current_base_unchanged=_current_base,
            require_exact_open_source_authority=_open_source_authority,
        )

        assert [draft.number for draft in outcome.drafts] == [91]
        assert outcome.failures == ()
        assert broker.open_calls == 0
        reconciliation = state._connection.execute(  # noqa: SLF001
            """
            SELECT 'draft_opened' AS disposition, draft_number
            FROM prevention_legacy_exact_drafts
            """
        ).fetchone()
        assert reconciliation is not None
        assert tuple(reconciliation) == ("draft_opened", 91)
        legacy_event = state._connection.execute(  # noqa: SLF001
            "SELECT legacy_event_id FROM prevention_legacy_exact_drafts"
        ).fetchone()
        assert legacy_event is not None
        with pytest.raises(sqlite3.IntegrityError, match="candidate set is sealed"):
            state._connection.execute(  # noqa: SLF001 - trust-root invariant
                """
                INSERT INTO prevention_legacy_candidate_events (
                    prevention_event_id
                ) VALUES (999999)
                """
            )
        with pytest.raises(sqlite3.IntegrityError, match="resolution conflicts"):
            state._connection.execute(  # noqa: SLF001 - terminality invariant
                """
                INSERT INTO prevention_legacy_invalid_resolutions (
                    legacy_event_id, draft_key_digest, occurred_at
                ) VALUES (?, ?, ?)
                """,
                (legacy_event[0], "f" * 64, "2026-08-30T12:01:00.000000Z"),
            )
        assert state.pending_prevention_draft_keys_for_recovery() == ()

    # A fresh process must treat the exact remote artifact as a durable claim;
    # the released row may never trigger another model call or POST.
    second_root = tmp_path / "second"
    with GuardianState(database) as state:
        author = _FakeAuthor()
        restarted = _coordinator(
            state=state,
            tmp_path=second_root,
            broker=broker,
            author=author,
        )
        run_id = state.start_run(
            repository="acme/translations",
            locale="ru",
            mode=GuardianMode.PROPOSE_PREVENTION,
            started_at=now,
        )
        outcome = restarted.propose(
            policy=_repository_policy(),
            recurrence_candidates=(candidate,),
            evidence_revision_ids={"review_comment:42": OPEN_SOURCE_REVISION_ID},
            run_id=run_id,
            observed_at=now,
            require_live_lease=_live_lease,
            require_current_base_unchanged=_current_base,
            **_open_source_kwargs(),
        )

        assert outcome.drafts == ()
        assert outcome.skipped == 1
        assert outcome.failures == ()
        assert author.calls == 0
        assert broker.open_calls == 0
        assert broker.find_calls == 1
        assert state.legacy_prevention_draft_by_key(draft_key) is not None


def test_exact_legacy_observation_supersedes_racing_local_terminal(
    tmp_path: Path,
) -> None:
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
    database = tmp_path / "state.sqlite3"
    draft_key, _branch = _create_v1_prevention_database(
        database,
        phase="pushed",
        evidence_hash="d" * 64,
        now=now,
    )
    policy = _repository_policy()
    policy_digest = prevention_runtime._source_policy_attestation(policy)[1]  # noqa: SLF001

    with GuardianState(database) as state:
        record = state.legacy_prevention_draft_by_key(draft_key)
        assert record is not None

        class RacingLegacyBroker(_FakeBroker):
            def find_draft(
                self,
                *,
                candidate_sha: str,
                **_kwargs: object,
            ) -> PreventionDraftResult:
                state.record_legacy_prevention_reconciliation(
                    record=record,
                    source_repository_id=42,
                    target_repository_id=101,
                    push_repository_id=101,
                    source_policy_digest=policy_digest,
                    disposition="not_found",
                    occurred_at=now,
                )
                return PreventionDraftResult(
                    number=91,
                    html_url="https://github.test/guardian/pipeline/pull/91",
                    candidate_sha=candidate_sha,
                    created=False,
                )

        outcome = _coordinator(
            state=state,
            tmp_path=tmp_path,
            broker=RacingLegacyBroker(),
            author=_FakeAuthor(),
        ).recover(
            policy=policy,
            observed_at=now,
            require_live_lease=_live_lease,
            require_current_base_unchanged=_current_base,
            require_exact_open_source_authority=_open_source_authority,
        )

        counts = state._connection.execute(  # noqa: SLF001
            """
            SELECT
                (SELECT COUNT(*) FROM prevention_legacy_reconciliations),
                (SELECT COUNT(*) FROM prevention_legacy_exact_drafts)
            """
        ).fetchone()
        assert [draft.number for draft in outcome.drafts] == [91]
        assert counts is not None and tuple(counts) == (1, 1)
        snapshot = state.status_snapshot(
            mode=GuardianMode.PROPOSE_PREVENTION,
            as_of=now,
        )
        assert snapshot.opened_preventions == 1
        assert snapshot.conflicted_preventions == 0


def test_legacy_exact_fact_must_match_released_opened_pr_identity(
    tmp_path: Path,
) -> None:
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
    database = tmp_path / "state.sqlite3"
    draft_key, _branch = _create_v1_prevention_database(
        database,
        phase="draft_opened",
        evidence_hash="d" * 64,
        now=now,
    )
    policy_digest = prevention_runtime._source_policy_attestation(  # noqa: SLF001
        _repository_policy()
    )[1]

    with GuardianState(database) as state:
        record = state.legacy_prevention_draft_by_key(draft_key)
        assert record is not None
        with pytest.raises(ValueError, match="released record"):
            state.record_legacy_prevention_reconciliation(
                record=record,
                source_repository_id=42,
                target_repository_id=101,
                push_repository_id=101,
                source_policy_digest=policy_digest,
                disposition="draft_opened",
                draft_number=92,
                draft_url="https://github.test/guardian/pipeline/pull/92",
                occurred_at=now,
            )

        with pytest.raises(sqlite3.IntegrityError, match="exact prevention draft"):
            state._connection.execute(  # noqa: SLF001 - trust-root invariant
                """
                INSERT INTO prevention_legacy_exact_drafts (
                    legacy_event_id, draft_key, source_repository_id,
                    target_repository_id, push_repository_id,
                    source_policy_digest, evidence_hash, draft_number,
                    draft_url, occurred_at
                ) VALUES (?, ?, 42, 101, 101, ?, ?, 92, ?, ?)
                """,
                (
                    record.prevention_event_id,
                    draft_key,
                    policy_digest,
                    record.evidence_hash,
                    "https://github.test/guardian/pipeline/pull/92",
                    "2026-08-30T12:00:00.000000Z",
                ),
            )


@pytest.mark.parametrize(
    "terminal_kind",
    ("reconciliation", "exact", "invalid", "deferral", "exhaustion"),
)
def test_legacy_terminal_facts_can_only_bind_latest_phase_event(
    terminal_kind: str,
    tmp_path: Path,
) -> None:
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
    database = tmp_path / "state.sqlite3"
    draft_key, _branch = _create_v1_prevention_database(
        database,
        phase="pushed",
        evidence_hash="d" * 64,
        now=now,
    )
    policy_digest = prevention_runtime._source_policy_attestation(  # noqa: SLF001
        _repository_policy()
    )[1]

    with GuardianState(database) as state:
        stale = state._connection.execute(  # noqa: SLF001
            """
            SELECT prevention_event_id, evidence_hash
            FROM prevention_draft_events
            WHERE draft_key = ? AND phase = 'validated'
            """,
            (draft_key,),
        ).fetchone()
        assert stale is not None
        event_id = int(stale["prevention_event_id"])
        evidence_hash = str(stale["evidence_hash"])
        statements: dict[str, tuple[str, tuple[object, ...]]] = {
            "reconciliation": (
                """
                INSERT INTO prevention_legacy_reconciliations (
                    legacy_event_id, draft_key, source_repository_id,
                    target_repository_id, push_repository_id,
                    source_policy_digest, evidence_hash, disposition,
                    occurred_at
                ) VALUES (?, ?, 42, 101, 101, ?, ?, 'not_found', ?)
                """,
                (event_id, draft_key, policy_digest, evidence_hash),
            ),
            "exact": (
                """
                INSERT INTO prevention_legacy_exact_drafts (
                    legacy_event_id, draft_key, source_repository_id,
                    target_repository_id, push_repository_id,
                    source_policy_digest, evidence_hash, draft_number,
                    draft_url, occurred_at
                ) VALUES (?, ?, 42, 101, 101, ?, ?, 91, ?, ?)
                """,
                (
                    event_id,
                    draft_key,
                    policy_digest,
                    evidence_hash,
                    "https://github.test/guardian/pipeline/pull/91",
                ),
            ),
            "invalid": (
                """
                INSERT INTO prevention_legacy_invalid_resolutions (
                    legacy_event_id, draft_key_digest, occurred_at
                ) VALUES (?, ?, ?)
                """,
                (event_id, "e" * 64),
            ),
            "deferral": (
                """
                INSERT INTO prevention_legacy_policy_deferrals (
                    legacy_event_id, source_policy_digest,
                    source_repository_id, target_repository_id,
                    push_repository_id, evidence_hash, reason, occurred_at
                ) VALUES (?, ?, 42, 101, 101, ?, 'policy_unavailable', ?)
                """,
                (event_id, policy_digest, evidence_hash),
            ),
            "exhaustion": (
                """
                INSERT INTO prevention_legacy_deferral_exhaustions (
                    legacy_event_id, occurred_at
                ) VALUES (?, ?)
                """,
                (event_id,),
            ),
        }
        sql, parameters = statements[terminal_kind]
        with pytest.raises(sqlite3.IntegrityError, match="legacy prevention|exact"):
            state._connection.execute(  # noqa: SLF001 - trust-root invariant
                sql,
                (*parameters, "2026-08-30T12:01:00.000000Z"),
            )


def test_released_v1_missing_remote_draft_is_terminal_across_restart(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
    candidate = _candidate()
    evidence_hash = prevention_runtime.prevention_evidence_hash(
        root_cause=candidate.summary,
        evidence_feedback_ids=("review_comment:42:revision-1",),
    )
    database = tmp_path / "state.sqlite3"
    _draft_key, _branch = _create_v1_prevention_database(
        database,
        phase="pushed",
        evidence_hash=evidence_hash,
        now=now,
    )
    broker = _FakeBroker()
    monkeypatch.setattr(
        guardian_state,
        "_MAX_PREVENTION_RECOVERY_ATTEMPTS",
        1,
    )

    with GuardianState(database) as state:
        coordinator = _coordinator(
            state=state,
            tmp_path=tmp_path / "first",
            broker=broker,
            author=_FakeAuthor(),
        )
        outcome = coordinator.recover(
            policy=_repository_policy(),
            observed_at=now,
            require_live_lease=_live_lease,
            require_current_base_unchanged=_current_base,
            require_exact_open_source_authority=_open_source_authority,
        )

        assert outcome.drafts == ()
        assert outcome.failures == ("PreventionLegacyNotFound",)
        result = state._connection.execute(  # noqa: SLF001
            "SELECT disposition FROM prevention_legacy_reconciliations"
        ).fetchone()
        assert result is None

    with GuardianState(database) as state:
        final = _coordinator(
            state=state,
            tmp_path=tmp_path / "second",
            broker=broker,
            author=_FakeAuthor(),
        ).recover(
            policy=_repository_policy(),
            observed_at=now,
            require_live_lease=_live_lease,
            require_current_base_unchanged=_current_base,
            require_exact_open_source_authority=_open_source_authority,
        )
        assert final.failures == ("PreventionLegacyNotFound",)
        result = state._connection.execute(  # noqa: SLF001
            "SELECT disposition FROM prevention_legacy_reconciliations"
        ).fetchone()
        assert result is not None and result[0] == "not_found"

    with GuardianState(database) as state:
        author = _FakeAuthor()
        restarted = _coordinator(
            state=state,
            tmp_path=tmp_path / "third",
            broker=broker,
            author=author,
        )
        run_id = state.start_run(
            repository="acme/translations",
            locale="ru",
            mode=GuardianMode.PROPOSE_PREVENTION,
            started_at=now,
        )
        outcome = restarted.propose(
            policy=_repository_policy(),
            recurrence_candidates=(candidate,),
            evidence_revision_ids={"review_comment:42": OPEN_SOURCE_REVISION_ID},
            run_id=run_id,
            observed_at=now,
            require_live_lease=_live_lease,
            require_current_base_unchanged=_current_base,
            **_open_source_kwargs(),
        )

        assert outcome.drafts == ()
        assert outcome.skipped == 1
        assert outcome.failures == ()
        assert author.calls == 0
        assert broker.open_calls == 0


def test_released_v1_abandoned_candidate_remains_fail_closed_claim(
    tmp_path: Path,
) -> None:
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
    candidate = _candidate()
    evidence_hash = prevention_runtime.prevention_evidence_hash(
        root_cause=candidate.summary,
        evidence_feedback_ids=("review_comment:42:revision-1",),
    )
    database = tmp_path / "state.sqlite3"
    _create_v1_prevention_database(
        database,
        phase="abandoned",
        evidence_hash=evidence_hash,
        now=now,
    )
    with GuardianState(database) as state:
        broker = _FakeBroker()
        author = _FakeAuthor()
        coordinator = _coordinator(
            state=state,
            tmp_path=tmp_path / "work",
            broker=broker,
            author=author,
        )
        run_id = state.start_run(
            repository="acme/translations",
            locale="ru",
            mode=GuardianMode.PROPOSE_PREVENTION,
            started_at=now,
        )
        outcome = coordinator.propose(
            policy=_repository_policy(),
            recurrence_candidates=(candidate,),
            evidence_revision_ids={"review_comment:42": OPEN_SOURCE_REVISION_ID},
            run_id=run_id,
            observed_at=now,
            require_live_lease=_live_lease,
            require_current_base_unchanged=_current_base,
            **_open_source_kwargs(),
        )

        assert outcome.skipped == 1
        assert outcome.drafts == ()
        assert outcome.failures == ()
        assert author.calls == 0
        assert broker.capture_calls == 0
        snapshot = state.status_snapshot(
            mode=GuardianMode.PROPOSE_PREVENTION,
            as_of=now,
        )
        assert snapshot.conflicted_preventions == 1


def test_malformed_released_v1_record_uses_uncapped_terminal_isolation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
    monkeypatch.setattr(guardian_state, "_MAX_PREVENTION_INVALID_QUARANTINES", 1)
    database = tmp_path / "state.sqlite3"
    _create_v1_prevention_database(
        database,
        phase="pushed",
        evidence_hash="d" * 64,
        now=now,
        corrupt_latest=True,
    )
    with GuardianState(database) as state:
        run_id = state.start_run(
            repository="acme/translations",
            locale="ru",
            mode=GuardianMode.PROPOSE_PREVENTION,
            started_at=now,
        )
        ordinary_key = "ordinary-corrupt-record"
        state._connection.execute(  # noqa: SLF001 - corrupt-state fixture
            """
            INSERT INTO prevention_draft_events (
                draft_key, run_id, source_repository, target_repository,
                target_base_branch, target_base_sha, push_repository,
                branch, candidate_sha, evidence_hash, title, body, phase,
                occurred_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'validated', ?)
            """,
            (
                ordinary_key,
                run_id,
                "acme/translations",
                "guardian/pipeline",
                "main",
                BASE_SHA,
                "guardian/pipeline",
                "guardian/prevention-corrupt",
                CANDIDATE_SHA,
                "e" * 64,
                "Corrupt record",
                "Body\n",
                now.isoformat(),
            ),
        )
        state._connection.commit()  # noqa: SLF001 - corrupt-state fixture
        state.quarantine_invalid_prevention_record(
            draft_key=ordinary_key,
            occurred_at=now,
        )
        author = _FakeAuthor()
        coordinator = _coordinator(
            state=state,
            tmp_path=tmp_path / "first",
            broker=_FakeBroker(),
            author=author,
        )
        outcome = coordinator.propose(
            policy=_repository_policy(),
            recurrence_candidates=(_candidate("A separate valid recurrence"),),
            evidence_revision_ids={"review_comment:42": OPEN_SOURCE_REVISION_ID},
            run_id=run_id,
            observed_at=now,
            require_live_lease=_live_lease,
            require_current_base_unchanged=_current_base,
            **_open_source_kwargs(),
        )

        assert outcome.failures == ("PreventionInvalidRecord",)
        assert len(outcome.drafts) == 1
        assert author.calls == 1
        dedicated = state._connection.execute(  # noqa: SLF001
            "SELECT COUNT(*) FROM prevention_legacy_invalid_resolutions"
        ).fetchone()
        ordinary = state._connection.execute(  # noqa: SLF001
            "SELECT COUNT(*) FROM prevention_invalid_record_quarantines"
        ).fetchone()
        assert dedicated is not None and dedicated[0] == 1
        assert ordinary is not None and ordinary[0] == 1

    with GuardianState(database) as state:
        restarted = _coordinator(
            state=state,
            tmp_path=tmp_path / "second",
            broker=_FakeBroker(),
            author=_FakeAuthor(),
        )
        assert (
            restarted.recover(
                policy=_repository_policy(),
                observed_at=now,
                require_live_lease=_live_lease,
                require_current_base_unchanged=_current_base,
                require_exact_open_source_authority=_open_source_authority,
            )
            == prevention_runtime.PreventionBatchOutcome()
        )


def test_released_v1_policy_mismatch_defers_but_keeps_evidence_claimed(
    tmp_path: Path,
) -> None:
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
    candidate = _candidate()
    evidence_hash = prevention_runtime.prevention_evidence_hash(
        root_cause=candidate.summary,
        evidence_feedback_ids=("review_comment:42:revision-1",),
    )
    database = tmp_path / "state.sqlite3"
    _draft_key, _branch = _create_v1_prevention_database(
        database,
        phase="pushed",
        evidence_hash=evidence_hash,
        now=now,
        target_repository="guardian/old-pipeline",
        push_repository="guardian/old-pipeline",
    )
    current_repository = ExactRepository(full_name="guardian/new-pipeline", id=202)
    current_policy = replace(
        _repository_policy(),
        prevention=_prevention_policy(
            target_repository=current_repository,
            push_repository=current_repository,
        ),
    )

    with GuardianState(database) as state:
        author = _FakeAuthor()
        broker = _FakeBroker()
        coordinator = _coordinator(
            state=state,
            tmp_path=tmp_path / "first",
            broker=broker,
            author=author,
        )
        run_id = state.start_run(
            repository="acme/translations",
            locale="ru",
            mode=GuardianMode.PROPOSE_PREVENTION,
            started_at=now,
        )
        first = coordinator.propose(
            policy=current_policy,
            recurrence_candidates=(candidate,),
            evidence_revision_ids={"review_comment:42": OPEN_SOURCE_REVISION_ID},
            run_id=run_id,
            observed_at=now,
            require_live_lease=_live_lease,
            require_current_base_unchanged=_current_base,
            **_open_source_kwargs(),
        )

        assert first.failures == ("PreventionLegacyPolicyUnavailable",)
        assert first.skipped == 1
        assert author.calls == 0
        assert broker.capture_calls == 0
        coordinator.begin_poll()
        second = coordinator.propose(
            policy=current_policy,
            recurrence_candidates=(candidate,),
            evidence_revision_ids={"review_comment:42": OPEN_SOURCE_REVISION_ID},
            run_id=run_id,
            observed_at=now,
            require_live_lease=_live_lease,
            require_current_base_unchanged=_current_base,
            **_open_source_kwargs(),
        )
        assert second.failures == ()
        assert second.skipped == 1
        assert author.calls == 0
        deferrals = state._connection.execute(  # noqa: SLF001
            "SELECT COUNT(*) FROM prevention_legacy_policy_deferrals"
        ).fetchone()
        assert deferrals is not None and deferrals[0] == 1

    class ExactOldBroker(_FakeBroker):
        def find_draft(
            self, *, candidate_sha: str, **_kwargs: object
        ) -> PreventionDraftResult:
            return PreventionDraftResult(
                number=91,
                html_url="https://github.test/guardian/old-pipeline/pull/91",
                candidate_sha=candidate_sha,
                created=False,
            )

    old_repository = ExactRepository(full_name="guardian/old-pipeline", id=303)
    restored_policy = replace(
        _repository_policy(),
        prevention=_prevention_policy(
            target_repository=old_repository,
            push_repository=old_repository,
        ),
    )
    with GuardianState(database) as state:
        restarted = _coordinator(
            state=state,
            tmp_path=tmp_path / "second",
            broker=ExactOldBroker(),
            author=_FakeAuthor(),
        )
        restored = restarted.recover(
            policy=restored_policy,
            observed_at=now,
            require_live_lease=_live_lease,
            require_current_base_unchanged=_current_base,
            require_exact_open_source_authority=_open_source_authority,
        )
        assert [draft.number for draft in restored.drafts] == [91]
        status = state.status_snapshot(
            mode=GuardianMode.PROPOSE_PREVENTION,
            as_of=now,
        )
        assert status.opened_preventions == 1
        assert status.conflicted_preventions == 0


def test_released_v1_policy_deferral_churn_is_bounded(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
    monkeypatch.setattr(
        guardian_state,
        "_MAX_PREVENTION_LEGACY_POLICY_DEFERRALS",
        2,
    )
    database = tmp_path / "state.sqlite3"
    _create_v1_prevention_database(
        database,
        phase="pushed",
        evidence_hash="d" * 64,
        now=now,
        target_repository="guardian/old-pipeline",
        push_repository="guardian/old-pipeline",
    )
    with GuardianState(database) as state:
        coordinator = _coordinator(
            state=state,
            tmp_path=tmp_path / "work",
            broker=_FakeBroker(),
            author=_FakeAuthor(),
        )
        for offset in range(3):
            repository = ExactRepository(
                full_name=f"guardian/new-pipeline-{offset}",
                id=400 + offset,
            )
            policy = replace(
                _repository_policy(),
                prevention=_prevention_policy(
                    target_repository=repository,
                    push_repository=repository,
                ),
            )
            coordinator.begin_poll()
            outcome = coordinator.recover(
                policy=policy,
                observed_at=now,
                require_live_lease=_live_lease,
                require_current_base_unchanged=_current_base,
                require_exact_open_source_authority=_open_source_authority,
            )
            assert outcome.failures == ("PreventionLegacyPolicyUnavailable",)

        counts = state._connection.execute(  # noqa: SLF001
            """
            SELECT
                (SELECT COUNT(*) FROM prevention_legacy_policy_deferrals),
                (SELECT COUNT(*) FROM prevention_legacy_deferral_exhaustions)
            """
        ).fetchone()
        assert counts is not None and tuple(counts) == (2, 1)
        health = state.latest_health("guardian_prevention_recovery")
        assert health is not None
        assert health.details["resolution"] == "legacy_policy_deferral_exhausted"

        repository = ExactRepository(
            full_name="guardian/new-pipeline-after-cap",
            id=499,
        )
        after_cap_policy = replace(
            _repository_policy(),
            prevention=_prevention_policy(
                target_repository=repository,
                push_repository=repository,
            ),
        )
        coordinator.begin_poll()
        assert (
            coordinator.recover(
                policy=after_cap_policy,
                observed_at=now,
                require_live_lease=_live_lease,
                require_current_base_unchanged=_current_base,
                require_exact_open_source_authority=_open_source_authority,
            )
            == prevention_runtime.PreventionBatchOutcome()
        )
        counts_after = state._connection.execute(  # noqa: SLF001
            """
            SELECT
                (SELECT COUNT(*) FROM prevention_legacy_policy_deferrals),
                (SELECT COUNT(*) FROM prevention_legacy_deferral_exhaustions)
            """
        ).fetchone()
        assert counts_after is not None and tuple(counts_after) == (2, 1)


def test_orphan_recovery_terminalizes_absent_draft_from_removed_policy(
    tmp_path: Path,
) -> None:
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)

    class ReadOnlyBroker(_FakeBroker):
        def __init__(self) -> None:
            super().__init__()
            self.find_calls = 0

        def find_draft(self, **_kwargs: object) -> PreventionDraftResult | None:
            self.find_calls += 1
            return None

        def capture_base(self) -> PreventionBaseSnapshot:
            raise AssertionError("orphan recovery must not inspect the current base")

        def branch_sha(self, _branch: str) -> str | None:
            raise AssertionError("orphan recovery must not inspect branches")

        def open_draft(self, **_kwargs: object) -> PreventionDraftResult:
            raise AssertionError("orphan recovery must never open a pull request")

    with GuardianState(tmp_path / "state.sqlite3") as state:
        draft_key, _ledger = _pending_prevention_ledger(state, now=now)
        broker = ReadOnlyBroker()
        attested_policies: list[PreventionPolicy] = []
        coordinator = _coordinator(
            state=state,
            tmp_path=tmp_path,
            broker=broker,
            author=_FakeAuthor(),
        )

        def broker_factory(policy: PreventionPolicy) -> ReadOnlyBroker:
            attested_policies.append(policy)
            return broker

        coordinator.broker_factory = broker_factory
        outcome = coordinator.recover_orphans(
            configured_policies=(),
            observed_at=now,
            require_live_lease=_live_lease,
        )

        assert outcome.drafts == ()
        assert outcome.failures == ("PreventionPolicyChanged",)
        assert broker.find_calls == 1
        assert attested_policies == [_repository_policy().prevention]
        resolution = state.prevention_resolution(draft_key)
        assert resolution is not None
        assert resolution.resolution == "policy_changed"


def test_orphan_recovery_records_exact_draft_before_reporting_changed_policy(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)

    class ExistingDraftBroker(_FakeBroker):
        def find_draft(
            self, *, candidate_sha: str, **_kwargs: object
        ) -> PreventionDraftResult:
            return PreventionDraftResult(
                number=93,
                html_url="https://github.test/guardian/pipeline/pull/93",
                candidate_sha=candidate_sha,
                created=False,
            )

        def open_draft(self, **_kwargs: object) -> PreventionDraftResult:
            raise AssertionError("orphan recovery must never open a pull request")

    with GuardianState(tmp_path / "state.sqlite3") as state:
        draft_key, _ledger = _pending_prevention_ledger(state, now=now)
        broker = ExistingDraftBroker()
        coordinator = _coordinator(
            state=state,
            tmp_path=tmp_path,
            broker=broker,
            author=_FakeAuthor(),
        )
        original_record_health = state.record_health

        def require_opened_before_health(**kwargs: object) -> int:
            opened = state.prevention_draft_by_key(draft_key)
            assert opened is not None and opened.phase == "draft_opened"
            return original_record_health(**kwargs)

        monkeypatch.setattr(state, "record_health", require_opened_before_health)
        changed_policy = replace(_repository_policy(), base_branch="release")
        outcome = coordinator.recover_orphans(
            configured_policies=(changed_policy,),
            observed_at=now,
            require_live_lease=_live_lease,
        )

        assert [draft.number for draft in outcome.drafts] == [93]
        assert outcome.failures == ("PreventionPolicyChanged",)
        opened = state.prevention_draft_by_key(draft_key)
        assert opened is not None and opened.phase == "draft_opened"
        assert opened.draft_number == 93
        assert state.prevention_resolution(draft_key) is None
        assert broker.capture_calls == 0
        assert broker.open_calls == 0


def test_orphan_recovery_skips_current_policy_without_credentials_or_network(
    tmp_path: Path,
) -> None:
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
    with GuardianState(tmp_path / "state.sqlite3") as state:
        draft_key, _ledger = _pending_prevention_ledger(state, now=now)
        coordinator = _coordinator(
            state=state,
            tmp_path=tmp_path,
            broker=_FakeBroker(),
            author=_FakeAuthor(),
        )

        def forbidden_factory(_policy: PreventionPolicy) -> _FakeBroker:
            raise AssertionError("current policies belong to per-policy recovery")

        coordinator.broker_factory = forbidden_factory
        outcome = coordinator.recover_orphans(
            configured_policies=(_repository_policy(),),
            observed_at=now,
            require_live_lease=_live_lease,
        )

        assert outcome == prevention_runtime.PreventionBatchOutcome()
        pending = state.prevention_draft_by_key(draft_key)
        assert pending is not None and pending.phase == "pushed"
        assert state.prevention_resolution(draft_key) is None


def test_orphan_recovery_defers_released_v1_without_guessing_authority(
    tmp_path: Path,
) -> None:
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
    database = tmp_path / "state.sqlite3"
    draft_key, _branch = _create_v1_prevention_database(
        database,
        phase="pushed",
        evidence_hash="d" * 64,
        now=now,
    )
    with GuardianState(database) as state:
        coordinator = _coordinator(
            state=state,
            tmp_path=tmp_path,
            broker=_FakeBroker(),
            author=_FakeAuthor(),
        )

        def forbidden_factory(_policy: PreventionPolicy) -> _FakeBroker:
            raise AssertionError("v1 has no immutable policy for a safe lookup")

        coordinator.broker_factory = forbidden_factory
        outcome = coordinator.recover_orphans(
            configured_policies=(),
            observed_at=now,
            require_live_lease=_live_lease,
        )

        assert outcome.drafts == ()
        assert outcome.deferred == 1
        assert outcome.failures == ()
        assert state.legacy_prevention_draft_by_key(draft_key) is not None
        assert draft_key in state.pending_prevention_draft_keys_for_recovery()


def test_orphan_recovery_isolates_invalid_conflicting_and_transient_records(
    tmp_path: Path,
) -> None:
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)

    class MixedBroker(_FakeBroker):
        def __init__(self) -> None:
            super().__init__()
            self.find_calls: list[str] = []

        def find_draft(
            self, *, branch: str, **_kwargs: object
        ) -> PreventionDraftResult | None:
            self.find_calls.append(branch)
            if branch.endswith("2" * 64):
                raise PreventionRemoteConflictError("stable mismatch")
            if branch.endswith("3" * 64):
                raise PreventionRuntimeError("temporary GitHub failure")
            return None

        def open_draft(self, **_kwargs: object) -> PreventionDraftResult:
            raise AssertionError("orphan recovery must never open a pull request")

    with GuardianState(tmp_path / "state.sqlite3") as state:
        assert _seed_open_source_event(state) == OPEN_SOURCE_REVISION_ID
        corrupt_run = state.start_run(
            repository="acme/translations",
            locale="ru",
            mode=GuardianMode.PROPOSE_PREVENTION,
            started_at=now,
        )
        corrupt_key = _insert_self_consistent_corrupt_prevention(
            state,
            run_id=corrupt_run,
            branch=f"guardian/prevention-{BASE_SHA[:12]}-{'6' * 64}",
            occurred_at="2026-08-30T12:00:00.000000Z",
            source_policy_json="{}",
        )
        conflict_key, _conflict = _pending_prevention_ledger(
            state,
            now=now,
            evidence_hash="2" * 64,
        )
        transient_key, _transient = _pending_prevention_ledger(
            state,
            now=now,
            evidence_hash="3" * 64,
        )
        absent_key, _absent = _pending_prevention_ledger(
            state,
            now=now,
            evidence_hash="4" * 64,
        )
        broker = MixedBroker()
        coordinator = _coordinator(
            state=state,
            tmp_path=tmp_path,
            broker=broker,
            author=_FakeAuthor(),
        )
        outcome = coordinator.recover_orphans(
            configured_policies=(),
            observed_at=now,
            require_live_lease=_live_lease,
        )

        assert outcome.failures == (
            "PreventionInvalidRecord",
            "PreventionRemoteConflict",
            "PreventionRuntimeError",
            "PreventionPolicyChanged",
        )
        assert len(broker.find_calls) == 3
        assert state.prevention_resolution(corrupt_key).resolution == "invalid_record"  # type: ignore[union-attr]
        assert state.prevention_resolution(conflict_key).resolution == "remote_conflict"  # type: ignore[union-attr]
        assert state.prevention_resolution(transient_key) is None
        assert state.prevention_resolution(absent_key).resolution == "policy_changed"  # type: ignore[union-attr]


def test_orphan_recovery_treats_lease_loss_as_a_poll_circuit_breaker(
    tmp_path: Path,
) -> None:
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
    lease_live = True

    class LoseLeaseBroker(_FakeBroker):
        def __init__(self) -> None:
            super().__init__()
            self.find_calls = 0

        def find_draft(self, **_kwargs: object) -> PreventionDraftResult | None:
            nonlocal lease_live
            self.find_calls += 1
            lease_live = False
            return None

    def require_lease() -> None:
        if not lease_live:
            raise RuntimeError("stale worker")

    with GuardianState(tmp_path / "state.sqlite3") as state:
        first_key, _first = _pending_prevention_ledger(
            state,
            now=now,
            evidence_hash="1" * 64,
        )
        second_key, _second = _pending_prevention_ledger(
            state,
            now=now,
            evidence_hash="2" * 64,
        )
        broker = LoseLeaseBroker()
        coordinator = _coordinator(
            state=state,
            tmp_path=tmp_path,
            broker=broker,
            author=_FakeAuthor(),
        )

        with pytest.raises(prevention_runtime.PreventionLeaseLostError):
            coordinator.recover_orphans(
                configured_policies=(),
                observed_at=now,
                require_live_lease=require_lease,
            )

        assert broker.find_calls == 1
        assert state.prevention_resolution(first_key) is None
        assert state.prevention_resolution(second_key) is None


def test_orphan_recovery_defensively_caps_global_workset_at_one_hundred(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
    policy = _repository_policy()
    with GuardianState(tmp_path / "state.sqlite3") as state:
        draft_key, _ledger = _pending_prevention_ledger(state, now=now)
        record = state.prevention_draft_by_key(draft_key)
        assert record is not None
        requested_limits: list[int] = []
        record_reads = 0

        def oversized_workset(*, limit: int, **_kwargs: object) -> tuple[str, ...]:
            requested_limits.append(limit)
            return (draft_key,) * 101

        def read_record(_draft_key: str):
            nonlocal record_reads
            record_reads += 1
            return record

        monkeypatch.setattr(
            state,
            "pending_prevention_draft_keys_for_recovery",
            oversized_workset,
        )
        monkeypatch.setattr(state, "prevention_draft_by_key", read_record)
        coordinator = _coordinator(
            state=state,
            tmp_path=tmp_path,
            broker=_FakeBroker(),
            author=_FakeAuthor(),
        )
        outcome = coordinator.recover_orphans(
            configured_policies=(policy,),
            observed_at=now,
            require_live_lease=_live_lease,
        )

        assert outcome == prevention_runtime.PreventionBatchOutcome()
        assert requested_limits == [100]
        assert record_reads == 100
