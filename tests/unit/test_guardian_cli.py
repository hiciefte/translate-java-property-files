"""Behavioral tests for the self-hosted Guardian command surface."""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import errno
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import threading
import time
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest
import yaml

from localize import cli as root_cli
from localize.guardian import (
    ClosedPrBackfillPolicy,
    ExactRepository,
    FeedbackEvent,
    GuardianConfig,
    GuardianMode,
    HistoricalRemediationPolicy,
    PreventionPolicy,
    SigningFormat,
    TrustedActor,
)
from localize.guardian import cli
from localize.guardian import runtime as guardian_runtime
from localize.guardian.config import load_guardian_config
from localize.guardian.github import GitHubRepositoryIdentity
from localize.guardian.models import HistoricalCheckScope
from localize.guardian.signing import SSHSigningMaterial
from localize.guardian.state import (
    GuardianState,
    HistoricalPullReference,
    RemediationCoverageReason,
    remediation_batch_hash,
)


UTC = timezone.utc
_REAL_CODEX_CAPABILITY_PROBE = cli._codex_capability_probe
_REAL_CODEX_CHATGPT_LOGIN_READY = cli._codex_chatgpt_login_ready
_REAL_DOCTOR_EXECUTABLES_TRUSTED = cli._doctor_executables_trusted


@pytest.fixture(autouse=True)
def _successful_codex_capability_probe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        cli,
        "_codex_capability_probe",
        lambda _executable, **_kwargs: True,
    )
    monkeypatch.setattr(
        cli,
        "_codex_chatgpt_login_ready",
        lambda _config: True,
    )
    monkeypatch.setattr(cli, "_doctor_executables_trusted", lambda _config: True)


def _init_config(tmp_path: Path) -> Path:
    config_path = tmp_path / "operator" / "guardian.yaml"
    assert cli.main(["init", "--config", str(config_path)]) == 0
    return config_path


def _mode(path: Path) -> int:
    return path.stat().st_mode & 0o777


def _record_cli_remediation_attempt(state: GuardianState) -> str:
    now = datetime(2026, 9, 1, 8, 0, tzinfo=UTC)
    revision = state.record_feedback_event(
        FeedbackEvent(
            repository="acme/widgets",
            pr_number=12,
            kind="review_comment",
            event_id="98765",
            author="coderabbitai[bot]",
            author_id=100000004,
            author_type="Bot",
            body="Please correct this translation.",
            head_sha="a" * 40,
            base_sha="b" * 40,
            locale="ru",
            html_url="https://github.test/acme/widgets/pull/12#discussion_r98765",
        ),
        observed_at=now,
    )
    source = HistoricalPullReference(
        repository="acme/widgets",
        repository_id=100000001,
        pull_id=500,
        pr_number=12,
        pull_revision_digest="1" * 64,
        authority_digest="3" * 64,
        policy_digest="2" * 64,
        head_sha="a" * 40,
        base_sha="b" * 40,
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
    evidence_hash = state.validate_historical_remediation_evidence(
        source_pulls=(source,),
        event_revision_ids=(revision.revision_id,),
    )
    run_id = state.start_run(
        repository="acme/widgets",
        locale="ru",
        mode=GuardianMode.PROPOSE_PREVENTION,
        started_at=now,
    )
    edit_hash = "e" * 64
    return state.record_remediation_draft_event(
        run_id=run_id,
        target_repository="acme/widgets",
        target_repository_id=100000001,
        target_base_branch="main",
        target_base_sha="b" * 40,
        push_repository="localization-service/widgets",
        push_repository_id=100000003,
        branch="localization/guardian-remediation-test",
        candidate_sha="c" * 40,
        evidence_hash=evidence_hash,
        batch_hash=remediation_batch_hash((edit_hash,)),
        edit_hashes=(edit_hash,),
        edit_target_hashes=((edit_hash, "f" * 64),),
        source_pulls=(source,),
        event_revision_ids=(revision.revision_id,),
        changed_paths=("src/main/resources/messages_ru.properties",),
        title="Review historical localization correction",
        body="Signed remediation candidate for human review.\n",
        phase="validated",
        occurred_at=now,
    )


def _open_cli_remediation_attempt(
    state: GuardianState,
    draft_key: str,
) -> None:
    record = state.remediation_draft_by_key(draft_key=draft_key)
    assert record is not None
    opened_at = record.occurred_at + timedelta(minutes=1)
    event_kwargs = dict(
        branch_identity_version=record.branch_identity_version,
        run_id=record.run_id,
        target_repository=record.target_repository,
        target_repository_id=record.target_repository_id,
        target_base_branch=record.target_base_branch,
        target_base_sha=record.target_base_sha,
        push_repository=record.push_repository,
        push_repository_id=record.push_repository_id,
        branch=record.branch,
        candidate_sha=record.candidate_sha,
        evidence_hash=record.evidence_hash,
        batch_hash=record.batch_hash,
        edit_hashes=record.edit_hashes,
        edit_target_hashes=record.edit_target_hashes,
        source_pulls=record.source_pulls,
        event_revision_ids=record.event_revision_ids,
        changed_paths=record.changed_paths,
        title=record.title,
        body=record.body,
    )
    state.record_remediation_draft_event(
        **event_kwargs,
        phase="pushed",
        occurred_at=opened_at,
    )
    state.record_remediation_draft_event(
        **event_kwargs,
        phase="draft_opened",
        draft_number=91,
        draft_pull_id=9001,
        draft_url="https://github.test/acme/widgets/pull/91",
        occurred_at=opened_at + timedelta(minutes=1),
    )
    state.record_remediation_remote_observation(
        draft_key=draft_key,
        observation="exact",
        state="closed",
        is_draft=False,
        is_merged=False,
        pr_number=91,
        pr_url="https://github.test/acme/widgets/pull/91",
        observed_base_sha="d" * 40,
        observed_head_sha=record.candidate_sha,
        closed_at="2026-09-01T08:03:00Z",
        observed_at=opened_at + timedelta(minutes=2),
    )
    state.record_draft_backed_remediation_completions(
        {record.source_pulls[0]: (draft_key,)},
        RemediationCoverageReason.DRAFT_RECOVERED,
        required_edit_hashes_by_source={
            record.source_pulls[0]: record.edit_hashes,
        },
        checkpoint_draft_key=draft_key,
        occurred_at=opened_at + timedelta(minutes=3),
    )


def _replace_once(value: str, needle: str, replacement: str) -> str:
    assert needle in value, f"template drift for {needle!r}"
    return value.replace(needle, replacement, 1)


def _remediation_doctor_config(
    config_path: Path,
    *,
    second_policy: bool = False,
) -> GuardianConfig:
    config = load_guardian_config(config_path)
    policy = config.repositories[0]
    publication_actor = policy.publication_actor
    assert publication_actor is not None
    policy = replace(
        policy,
        allowed_branch_globs=(
            *policy.allowed_branch_globs,
            "localization/guardian-remediation-*",
        ),
        closed_pr_backfill=ClosedPrBackfillPolicy(
            lookback_days=90,
            max_prs_per_poll=5,
            remediation=HistoricalRemediationPolicy(
                push_repository=ExactRepository(
                    full_name=policy.allowed_head_repositories[0].full_name,
                    id=policy.allowed_head_repositories[0].id,
                ),
                push_branch_prefix="localization/guardian-remediation-",
                publication_actor=publication_actor,
            ),
        ),
    )
    repositories = (policy,)
    if second_policy:
        repositories += (
            replace(
                policy,
                base_repo="acme/other-widgets",
                base_repo_id=100000011,
            ),
        )
    return replace(
        config,
        mode=GuardianMode.APPLY_OWNED_TRANSLATIONS,
        limits=replace(config.limits, max_remediation_drafts_per_run=1),
        repositories=repositories,
    )


def _prevention_doctor_config(
    config_path: Path,
    *,
    publication_actor: TrustedActor | None = None,
) -> GuardianConfig:
    config = load_guardian_config(config_path)
    policy = config.repositories[0]
    actor = publication_actor or policy.publication_actor
    assert actor is not None
    policy = replace(
        policy,
        prevention=PreventionPolicy(
            target_repository=ExactRepository(
                full_name="acme/localization-pipeline",
                id=100000006,
            ),
            target_base_branch="main",
            push_repository=ExactRepository(
                full_name="localization-service/localization-pipeline",
                id=100000007,
            ),
            push_branch_prefix="guardian/prevention-",
            publication_actor=actor,
            allowed_code_path_globs=("localize/**/*.py",),
            allowed_test_path_globs=("tests/**/*.py",),
            focused_test_argv=(("/usr/bin/true",),),
            sandbox_argv_prefix=("/usr/bin/guardian-sandbox-wrapper",),
            max_changed_files=4,
            max_changed_bytes=262_144,
        ),
    )
    return replace(
        config,
        mode=GuardianMode.PROPOSE_PREVENTION,
        limits=replace(config.limits, max_prevention_drafts_per_run=1),
        repositories=(policy,),
    )


def _mock_actor_stream(
    client: Mock,
    payload: object,
    *,
    status_code: int = 200,
    chunks: tuple[bytes, ...] | None = None,
) -> Mock:
    response = Mock(status_code=status_code)
    encoded = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    response.iter_bytes.return_value = chunks or (encoded,)

    @contextmanager
    def stream(_method: str, _path: str):
        yield response

    client.stream.side_effect = stream
    return response


def _configure_operator_pipeline(config_path: Path) -> Path:
    config_path.parent.chmod(0o700)
    pipeline_path = config_path.parent / "pipeline.yaml"
    pipeline_path.write_text(
        yaml.safe_dump(
            {
                "source_locale": "en",
                "supported_locales": [{"code": "de", "name": "German"}],
                "localization_format": "java_properties",
                "localization_layout": {
                    "id": "suffix",
                    "base_name": "messages",
                    "source_locale": "en",
                },
                "glossary_file_path": "glossary.json",
            }
        ),
        encoding="utf-8",
    )
    pipeline_path.chmod(0o600)
    glossary = config_path.parent / "glossary.json"
    glossary.write_text('{"de": {}}\n', encoding="utf-8")
    glossary.chmod(0o600)
    config_text = config_path.read_text(encoding="utf-8")
    config_text = _replace_once(
        config_text,
        "    pipeline_config_source: base",
        "    pipeline_config_source: operator",
    )
    config_text = _replace_once(
        config_text,
        "    pipeline_config_path: .localize/config.yaml",
        "    pipeline_config_path: pipeline.yaml",
    )
    config_path.write_text(config_text, encoding="utf-8")
    config_path.chmod(0o600)
    return glossary


def _configure_scheduled_runtime(
    config_path: Path,
    root: Path,
    *,
    api_key: bool = True,
) -> tuple[Path, Path, Path]:
    bin_dir = root / "bin"
    bin_dir.mkdir(exist_ok=True)
    codex = bin_dir / "codex"
    github_helper = bin_dir / "github-token"
    model_helper = bin_dir / "model-token"
    git = bin_dir / "git"
    gpg = bin_dir / "gpg"
    for executable in (codex, github_helper, model_helper, git, gpg):
        executable.write_text("#!/bin/sh\n", encoding="utf-8")
        executable.chmod(0o700)
    config = config_path.read_text(encoding="utf-8")
    config = _replace_once(
        config,
        "  codex_executable: codex",
        f"  codex_executable: {codex}",
    )
    config = _replace_once(config, "  git_executable: git", f"  git_executable: {git}")
    config = _replace_once(config, "  signing_program: gpg", f"  signing_program: {gpg}")
    config = _replace_once(
        config,
        "  github_token_command: [gh, auth, token]",
        f"  github_token_command: [{github_helper}]",
    )
    if api_key:
        config = _replace_once(
            config,
            "  codex_auth_mode: chatgpt",
            "  codex_auth_mode: api-key",
        )
        config = _replace_once(
            config,
            "  codex_home: ~/.local/share/localize-guardian/codex\n",
            "",
        )
        config = _replace_once(
            config,
            "  # codex_api_key_command:",
            f"  codex_api_key_command: [{model_helper}]\n  # codex_api_key_command:",
        )
        config = _replace_once(
            config,
            "  # daily_cost_limit_usd: 2.00",
            "  daily_cost_limit_usd: 2.00",
        )
        config = _replace_once(
            config,
            "  # model_call_reservation_usd: 2.00",
            "  model_call_reservation_usd: 2.00",
        )
    config_path.write_text(config, encoding="utf-8")
    return codex, github_helper, model_helper


def test_init_creates_valid_report_only_config_and_private_runtime_directory(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    config_path = tmp_path / "operator" / "guardian.yaml"

    exit_code = cli.main(["init", "--config", str(config_path)])

    captured = capsys.readouterr()
    config = load_guardian_config(config_path)
    assert exit_code == 0
    assert config.mode is GuardianMode.OBSERVE
    assert config.report_only
    assert config.repositories[0].base_repo == "acme/widgets"
    assert config.repositories[0].publication_actor == TrustedActor(
        "localization-machine-user", 100000002, "User"
    )
    assert config.enabled_publication_actors == ()
    assert config.repositories[0].closed_pr_backfill is None
    assert config.limits.max_remediation_drafts_per_run == 0
    assert _mode(config_path) == 0o600
    assert _mode(config_path.parent / ".guardian") == 0o700
    assert "Created report-only Guardian config" in captured.out
    config_text = config_path.read_text(encoding="utf-8")
    normalized_config = " ".join(config_text.replace("#", "").casefold().split())
    assert "OPENAI_API_KEY" not in config_text
    assert "# closed_pr_backfill:" in config_text
    assert "#   lookback_days:" in config_text
    assert "#   max_prs_per_poll:" in config_text
    assert "#   remediation:" in config_text
    assert "#     push_repository:" in config_text
    assert "#     push_branch_prefix:" in config_text
    assert "#     publication_actor:" in config_text
    assert '# - "localization/guardian-remediation-*"' in config_text
    assert "publication_actor, the credential actor" in normalized_config
    assert "resulting pr author" in normalized_config
    assert "observe/prepare keep it dormant" in normalized_config
    assert "durable bounded scan cycles" in normalized_config
    assert "restart at page 1" in normalized_config
    assert "second identity-only traversal" in normalized_config
    assert "not an atomic snapshot" in normalized_config
    assert (
        "quiescent pass within the 100-page/10,000-entry ceiling"
        in normalized_config
    )
    assert "three immediate hydration attempts" in normalized_config
    assert "current-cycle skip and durable priority retry" in normalized_config
    assert "including outside the discovery window" in normalized_config
    assert "# prevention:" in config_text
    assert normalized_config.count("publication_actor:") >= 2
    assert "numeric id + github user type grant authority" in normalized_config
    assert "github app installation-token bot publication cannot satisfy" in (
        normalized_config
    )
    assert "window admits new evidence" in normalized_config
    assert "durable pending recovery group cannot age out" in normalized_config
    assert (
        "must stay closed, exact-identity, and policy/trust eligible"
        in normalized_config
    )
    assert "new current-base correction draft with a signed commit" in normalized_config
    assert "never writes to the closed pr" in normalized_config


def test_init_refuses_to_overwrite_existing_config(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    config_path = tmp_path / "guardian.yaml"
    config_path.write_text("owner: operator\n", encoding="utf-8")

    exit_code = cli.main(["init", "--config", str(config_path)])

    assert exit_code == 1
    assert config_path.read_text(encoding="utf-8") == "owner: operator\n"
    assert "already exists" in capsys.readouterr().err


@pytest.mark.parametrize(
    "message",
    (
        "Guardian configuration is unavailable or unsafe.",
        "Guardian configuration is invalid.",
    ),
)
def test_config_loader_preserves_redacted_failure_reason(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    message: str,
) -> None:
    def fail(_path: Path):
        raise cli.GuardianRuntimeError(message)

    monkeypatch.setattr(cli, "load_trusted_guardian_config", fail)

    with pytest.raises(cli.GuardianCLIError, match=message.replace(".", r"\.")):
        cli._load_config_or_raise(tmp_path / "guardian.yaml")


def test_login_uses_dedicated_chatgpt_home_and_never_inherits_api_keys(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    config_path = _init_config(tmp_path)
    capsys.readouterr()
    codex_home = tmp_path / "private-codex-home"
    config_path.write_text(
        _replace_once(
            config_path.read_text(encoding="utf-8"),
            "~/.local/share/localize-guardian/codex",
            str(codex_home),
        ),
        encoding="utf-8",
    )
    observed: dict[str, object] = {}

    def fake_login(argv, **kwargs):
        observed["argv"] = list(argv)
        observed["env"] = dict(kwargs["env"])
        auth_file = codex_home / "auth.json"
        auth_file.write_text('{"auth":"test-only"}', encoding="utf-8")
        auth_file.chmod(0o600)
        return subprocess.CompletedProcess(argv, 0)

    monkeypatch.setattr(cli, "_command_available", lambda _command: True)
    monkeypatch.setattr(cli.subprocess, "run", fake_login)
    monkeypatch.setenv("OPENAI_API_KEY", "must-not-cross")
    monkeypatch.setenv("CODEX_API_KEY", "must-not-cross-either")

    exit_code = cli.main(["login", "--config", str(config_path)])

    assert exit_code == 0
    assert _mode(codex_home) == 0o700
    assert _mode(codex_home / "auth.json") == 0o600
    assert "--device-auth" in observed["argv"]
    assert 'forced_login_method="chatgpt"' in observed["argv"]
    assert observed["env"]["CODEX_HOME"] == str(codex_home)
    assert "OPENAI_API_KEY" not in observed["env"]
    assert "CODEX_API_KEY" not in observed["env"]
    assert "subscription login ready" in capsys.readouterr().out


def test_chatgpt_login_status_is_checked_without_a_model_call(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config_path = _init_config(tmp_path)
    codex_home = tmp_path / "codex-home"
    codex_home.mkdir(mode=0o700)
    auth_file = codex_home / "auth.json"
    auth_file.write_text('{"auth":"test-only"}', encoding="utf-8")
    auth_file.chmod(0o600)
    config_path.write_text(
        _replace_once(
            config_path.read_text(encoding="utf-8"),
            "~/.local/share/localize-guardian/codex",
            str(codex_home),
        ),
        encoding="utf-8",
    )
    config = load_guardian_config(config_path)
    observed: dict[str, object] = {}

    def fake_run(argv, **kwargs):
        observed["argv"] = list(argv)
        observed["env"] = dict(kwargs["env"])
        return subprocess.CompletedProcess(
            argv,
            0,
            stdout="Logged in using ChatGPT\n",
            stderr="",
        )

    monkeypatch.setattr(cli, "run_bounded_process", fake_run)
    monkeypatch.setenv("OPENAI_API_KEY", "must-not-cross")

    assert _REAL_CODEX_CHATGPT_LOGIN_READY(config) is True
    assert "exec" not in observed["argv"]
    assert observed["argv"][-1] == "status"
    assert "OPENAI_API_KEY" not in observed["env"]


def test_login_rejects_writable_codex_home_ancestor_before_authentication(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    config_path = _init_config(tmp_path)
    capsys.readouterr()
    unsafe_parent = tmp_path / "unsafe"
    unsafe_parent.mkdir(mode=0o777)
    unsafe_parent.chmod(0o777)
    codex_home = unsafe_parent / "codex-home"
    config_path.write_text(
        _replace_once(
            config_path.read_text(encoding="utf-8"),
            "~/.local/share/localize-guardian/codex",
            str(codex_home),
        ),
        encoding="utf-8",
    )
    attempted = False

    def unexpected_login(*_args, **_kwargs):
        nonlocal attempted
        attempted = True
        raise AssertionError("Codex login must not run under an unsafe ancestor")

    monkeypatch.setattr(cli, "_command_available", lambda _command: True)
    monkeypatch.setattr(cli.subprocess, "run", unexpected_login)

    exit_code = cli.main(["login", "--config", str(config_path)])

    assert exit_code == 1
    assert attempted is False
    assert not codex_home.exists()
    assert "unsafe" in capsys.readouterr().err.casefold()


@pytest.mark.parametrize("operation", ["fchmod", "fsync"])
def test_exclusive_write_removes_its_partial_inode_on_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    operation: str,
) -> None:
    destination = tmp_path / "guardian-file"

    def fail(*_args, **_kwargs):
        raise OSError("injected write failure")

    monkeypatch.setattr(cli.os, operation, fail)

    with pytest.raises(cli.GuardianCLIError, match="complete Guardian file"):
        cli._write_exclusive(destination, "content\n", mode=0o600)

    assert not destination.exists()


def test_exclusive_write_never_unlinks_a_replacement_inode(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination = tmp_path / "guardian-file"

    def replace_then_fail(_descriptor: int) -> None:
        destination.unlink()
        destination.write_text("replacement\n", encoding="utf-8")
        raise OSError("injected fsync failure")

    monkeypatch.setattr(cli.os, "fsync", replace_then_fail)

    with pytest.raises(cli.GuardianCLIError, match="complete Guardian file"):
        cli._write_exclusive(destination, "partial\n", mode=0o600)

    assert destination.read_text(encoding="utf-8") == "replacement\n"


def test_doctor_validates_local_dependencies_and_exact_github_identities(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    config_path = _init_config(tmp_path)
    capsys.readouterr()
    monkeypatch.setenv("OPENAI_API_KEY", "doctor-only-test-key")
    monkeypatch.setattr(cli.shutil, "which", lambda name: f"/usr/local/bin/{name}")
    github_probe = Mock(
        return_value=(
            GitHubRepositoryIdentity(
                full_name="acme/widgets",
                repository_id=100000001,
                private=False,
            ),
        )
    )
    monkeypatch.setattr(cli, "_probe_github", github_probe)
    monkeypatch.setattr(
        cli, "_signing_key_configured", lambda _configured, **_kwargs: False
    )

    exit_code = cli.main(["doctor", "--config", str(config_path)])

    captured = capsys.readouterr()
    assert exit_code == 0
    assert "Guardian doctor" in captured.out
    assert "config: ok (observe)" in captured.out
    assert "state directory: ok" in captured.out
    assert "Codex executable: ok" in captured.out
    assert (
        "Codex model/effort: configured gpt-5.6-terra / high "
        "(not capability-validated)"
    ) in captured.out
    assert "Codex capability canary: ok" in captured.out
    assert "result schema: ok" in captured.out
    assert "GitHub credential helper: ok" in captured.out
    assert "repository acme/widgets: ok (public, id=100000001)" in captured.out
    assert "commit signing: not required (observe mode)" in captured.out
    github_probe.assert_called_once()


def test_doctor_fails_when_codex_permission_canary_is_unavailable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    config_path = _init_config(tmp_path)
    capsys.readouterr()
    monkeypatch.setenv("OPENAI_API_KEY", "doctor-only-test-key")
    monkeypatch.setattr(cli.shutil, "which", lambda name: f"/usr/local/bin/{name}")
    monkeypatch.setattr(
        cli,
        "_codex_capability_probe",
        lambda _executable, **_kwargs: False,
    )
    monkeypatch.setattr(
        cli,
        "_probe_github",
        lambda _config: (
            GitHubRepositoryIdentity("acme/widgets", 100000001, False),
        ),
    )
    monkeypatch.setattr(
        cli, "_signing_key_configured", lambda _configured, **_kwargs: False
    )

    exit_code = cli.main(["doctor", "--config", str(config_path)])

    assert exit_code == 1
    assert "Codex capability canary: error" in capsys.readouterr().out


def test_doctor_stops_before_external_probes_when_executable_trust_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    config_path = _init_config(tmp_path)
    capsys.readouterr()
    codex_probe = Mock()
    github_probe = Mock()
    credential_probe = Mock()
    monkeypatch.setattr(cli, "_doctor_executables_trusted", lambda _config: False)
    monkeypatch.setattr(cli, "_codex_capability_probe", codex_probe)
    monkeypatch.setattr(cli, "_probe_github", github_probe)
    monkeypatch.setattr(cli, "_credential_helper_works", credential_probe)

    exit_code = cli.main(["doctor", "--config", str(config_path)])

    assert exit_code == 1
    assert "executable trust: error" in capsys.readouterr().out
    codex_probe.assert_not_called()
    github_probe.assert_not_called()
    credential_probe.assert_not_called()


def test_doctor_real_trust_preflight_rejects_shebang_arguments(
    tmp_path: Path,
) -> None:
    config_path = _init_config(tmp_path)
    codex, _github_helper, _model_helper = _configure_scheduled_runtime(
        config_path,
        tmp_path,
    )
    codex.write_text("#!/bin/sh -e\nexit 0\n", encoding="utf-8")

    assert not _REAL_DOCTOR_EXECUTABLES_TRUSTED(load_guardian_config(config_path))


@pytest.mark.parametrize(
    ("authoring", "profile", "filesystem_setting", "write_flag"),
    [
        (
            False,
            "guardian_evidence",
            'permissions.guardian_evidence.filesystem={":minimal"="read",'
            '":workspace_roots"={"."="read"}}',
            "0",
        ),
        (
            True,
            "guardian_prevention_author",
            'permissions.guardian_prevention_author.filesystem={":minimal"="read",'
            '":workspace_roots"={"."="write"}}',
            "1",
        ),
    ],
)
def test_codex_capability_probe_uses_exact_isolated_profile_and_flags(
    monkeypatch: pytest.MonkeyPatch,
    authoring: bool,
    profile: str,
    filesystem_setting: str,
    write_flag: str,
) -> None:
    calls: list[tuple[list[str], dict[str, object]]] = []

    @contextmanager
    def fake_canaries():
        yield 54321, "/private/tmp/guardian-canary.sock"

    def fake_run(argv, **kwargs):
        calls.append((list(argv), dict(kwargs)))
        return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

    monkeypatch.setattr(cli, "_doctor_network_canaries", fake_canaries)
    monkeypatch.setattr(cli, "run_bounded_process", fake_run)
    cgroup_parent_procs = Path("/sys/fs/cgroup/guardian/cgroup.procs")
    monkeypatch.setattr(
        cli,
        "linux_cgroup_parent_procs",
        lambda: cgroup_parent_procs,
    )
    monkeypatch.setenv("OPENAI_API_KEY", "must-not-cross")
    monkeypatch.setenv("GITHUB_TOKEN", "must-not-cross")

    assert _REAL_CODEX_CAPABILITY_PROBE("/trusted/codex", authoring=authoring)

    assert len(calls) == 2
    flag_argv, flag_kwargs = calls[0]
    sandbox_argv, sandbox_kwargs = calls[1]
    assert flag_argv[1:3] == ["--ask-for-approval", "never"]
    assert flag_argv[-6:] == [
        "exec",
        "--ephemeral",
        "--ignore-user-config",
        "--ignore-rules",
        "--strict-config",
        "--help",
    ]
    assert filesystem_setting in flag_argv
    assert sandbox_argv[sandbox_argv.index("--permission-profile") + 1] == profile
    assert filesystem_setting in sandbox_argv
    assert sandbox_argv[-2:] == [write_flag, str(cgroup_parent_procs)]
    assert sandbox_argv[sandbox_argv.index("--") + 1 :][:2] == ["/bin/sh", "-c"]
    for kwargs in (flag_kwargs, sandbox_kwargs):
        assert kwargs["shell"] is False
        assert kwargs["limits"].require_linux_cgroup is True
        environment = kwargs["env"]
        assert "OPENAI_API_KEY" not in environment
        assert "GITHUB_TOKEN" not in environment
        assert set(environment) == {"CODEX_HOME", "HOME", "NO_COLOR", "PATH", "TMPDIR"}


def test_codex_capability_probe_fails_when_confinement_probe_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    @contextmanager
    def fake_canaries():
        yield 54321, ""

    calls = 0

    def fake_run(argv, **_kwargs):
        nonlocal calls
        calls += 1
        return subprocess.CompletedProcess(
            argv,
            0 if calls == 1 else 1,
            stdout="",
            stderr="",
        )

    monkeypatch.setattr(cli, "_doctor_network_canaries", fake_canaries)
    monkeypatch.setattr(cli, "run_bounded_process", fake_run)

    assert _REAL_CODEX_CAPABILITY_PROBE("/trusted/codex") is False


def test_doctor_github_probe_disables_environment_proxy_inheritance(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config_path = _init_config(tmp_path)
    config = load_guardian_config(config_path)
    monkeypatch.setattr(cli.SecretCommand, "read", lambda _self: "test-token")
    reader = Mock()
    reader.repository_identity.return_value = GitHubRepositoryIdentity(
        "acme/widgets",
        100000001,
        False,
    )
    monkeypatch.setattr(cli, "GitHubReader", lambda _client, _policy: reader)

    with patch("localize.guardian.cli.httpx.Client") as client_factory:
        client_factory.return_value.__enter__.return_value = object()
        identities = cli._probe_github(config)

    assert identities[0].repository_id == 100000001
    assert client_factory.call_args.kwargs["trust_env"] is False


def test_doctor_github_probe_preflights_one_exact_publication_actor_across_policies(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config_path = _init_config(tmp_path)
    config = _remediation_doctor_config(config_path, second_policy=True)
    token_read = Mock(return_value="remediation-secret")
    monkeypatch.setattr(cli.SecretCommand, "read", token_read)
    reader = Mock()
    reader.repository_identity.side_effect = (
        GitHubRepositoryIdentity("acme/widgets", 100000001, False),
        GitHubRepositoryIdentity("acme/other-widgets", 100000011, False),
    )
    monkeypatch.setattr(cli, "GitHubReader", lambda _client, _policy: reader)
    client = Mock()
    _mock_actor_stream(
        client,
        {
            "login": "mutable-display-label",
            "id": 100000002,
            "type": "User",
        },
    )

    with patch("localize.guardian.cli.httpx.Client") as client_factory:
        client_factory.return_value.__enter__.return_value = client
        identities = cli._probe_github(config)

    assert tuple(identity.repository_id for identity in identities) == (
        100000001,
        100000011,
    )
    token_read.assert_called_once()
    client.stream.assert_called_once_with("GET", "/user")


def test_config_rejects_different_publication_actor_across_policies(
    tmp_path: Path,
) -> None:
    config_path = _init_config(tmp_path)
    config = _remediation_doctor_config(config_path, second_policy=True)
    other_actor = TrustedActor("other-service", 100000099, "User")
    second_backfill = config.repositories[1].closed_pr_backfill
    assert second_backfill is not None
    second_remediation = second_backfill.remediation
    assert second_remediation is not None
    second_policy = replace(
        config.repositories[1],
        allowed_pr_authors=(other_actor,),
        closed_pr_backfill=replace(
            second_backfill,
            remediation=replace(
                second_remediation,
                publication_actor=other_actor,
            ),
        ),
    )
    with pytest.raises(
        ValueError,
        match="Enabled publication policies must use one GitHub actor identity",
    ):
        replace(config, repositories=(config.repositories[0], second_policy))


@pytest.mark.parametrize(
    ("status_code", "chunks"),
    [
        (401, (b"credential-specific upstream body",)),
        (
            200,
            (
                b"x" * cli._MAX_DOCTOR_GITHUB_ACTOR_BYTES,
                b"one-byte-too-many",
            ),
        ),
    ],
)
def test_doctor_github_probe_redacts_invalid_actor_responses(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    status_code: int,
    chunks: tuple[bytes, ...],
) -> None:
    config_path = _init_config(tmp_path)
    config = _remediation_doctor_config(config_path)
    monkeypatch.setattr(cli.SecretCommand, "read", lambda _self: "secret-token")
    monkeypatch.setattr(cli, "GitHubReader", Mock())
    client = Mock()
    _mock_actor_stream(
        client,
        {"id": 100000002, "type": "User"},
        status_code=status_code,
        chunks=chunks,
    )

    with patch("localize.guardian.cli.httpx.Client") as client_factory:
        client_factory.return_value.__enter__.return_value = client
        with pytest.raises(cli.GuardianCLIError, match="publication actor") as error:
            cli._probe_github(config)

    assert "credential-specific" not in str(error.value)
    assert "secret-token" not in str(error.value)


@pytest.mark.parametrize(
    "actor_payload",
    [
        {"login": "service", "id": True, "type": "User"},
        {"login": "service", "id": 0, "type": "User"},
        {"login": "service", "id": "100000002", "type": "User"},
        {"login": "service", "id": 100000002, "type": "Bot"},
        {"login": "service", "id": 100000002, "type": "Organization"},
        {"login": "service", "id": 100000002, "type": None},
        {"login": "service", "id": 100000002, "type": []},
        {"login": "", "id": 100000002, "type": "User"},
        {"login": "bad\nlogin", "id": 100000002, "type": "User"},
        {"id": 100000002, "type": "User"},
        [],
    ],
)
def test_doctor_github_probe_rejects_invalid_or_unallowed_publication_actor_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    actor_payload: object,
) -> None:
    config_path = _init_config(tmp_path)
    config = _remediation_doctor_config(config_path)
    monkeypatch.setattr(cli.SecretCommand, "read", lambda _self: "secret-token")
    reader = Mock()
    reader.repository_identity.return_value = GitHubRepositoryIdentity(
        "acme/widgets",
        100000001,
        False,
    )
    monkeypatch.setattr(cli, "GitHubReader", lambda _client, _policy: reader)
    client = Mock()
    _mock_actor_stream(client, actor_payload)

    with patch("localize.guardian.cli.httpx.Client") as client_factory:
        client_factory.return_value.__enter__.return_value = client
        with pytest.raises(cli.GuardianCLIError, match="publication actor"):
            cli._probe_github(config)


def test_doctor_github_probe_preflights_prevention_only_publication_actor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config_path = _init_config(tmp_path)
    config = _prevention_doctor_config(config_path)
    monkeypatch.setattr(cli.SecretCommand, "read", lambda _self: "secret-token")
    reader = Mock()
    reader.repository_identity.return_value = GitHubRepositoryIdentity(
        "acme/widgets",
        100000001,
        False,
    )
    monkeypatch.setattr(cli, "GitHubReader", lambda _client, _policy: reader)
    client = Mock()
    _mock_actor_stream(
        client,
        {"login": "renamed-service", "id": 100000002, "type": "User"},
    )

    with patch("localize.guardian.cli.httpx.Client") as client_factory:
        client_factory.return_value.__enter__.return_value = client
        cli._probe_github(config)

    client.stream.assert_called_once_with("GET", "/user")


def test_config_rejects_different_prevention_and_remediation_actors(
    tmp_path: Path,
) -> None:
    config_path = _init_config(tmp_path)
    remediation_config = _remediation_doctor_config(config_path)
    other_actor = TrustedActor("other-service", 100000099, "User")
    prevention = _prevention_doctor_config(config_path).repositories[0].prevention
    assert prevention is not None
    prevention = replace(prevention, publication_actor=other_actor)
    with pytest.raises(
        ValueError,
        match="Enabled publication policies must use one GitHub actor identity",
    ):
        replace(
            remediation_config,
            mode=GuardianMode.PROPOSE_PREVENTION,
            limits=replace(
                remediation_config.limits,
                max_prevention_drafts_per_run=1,
            ),
            repositories=(
                replace(
                    remediation_config.repositories[0],
                    prevention=prevention,
                ),
            ),
        )


@pytest.mark.parametrize(
    ("mode", "max_prevention_drafts_per_run", "expects_actor_probe"),
    [
        (GuardianMode.PROPOSE_PREVENTION, 0, True),
        (GuardianMode.APPLY_OWNED_TRANSLATIONS, 1, True),
        (GuardianMode.PREPARE, 1, False),
    ],
)
def test_doctor_github_probe_uses_only_currently_enabled_publication_actors(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mode: GuardianMode,
    max_prevention_drafts_per_run: int,
    expects_actor_probe: bool,
) -> None:
    config_path = _init_config(tmp_path)
    config = _prevention_doctor_config(config_path)
    config = replace(
        config,
        mode=mode,
        limits=replace(
            config.limits,
            max_prevention_drafts_per_run=max_prevention_drafts_per_run,
        ),
    )
    monkeypatch.setattr(cli.SecretCommand, "read", lambda _self: "secret-token")
    reader = Mock()
    reader.repository_identity.return_value = GitHubRepositoryIdentity(
        "acme/widgets",
        100000001,
        False,
    )
    monkeypatch.setattr(cli, "GitHubReader", lambda _client, _policy: reader)
    client = Mock()
    if expects_actor_probe:
        _mock_actor_stream(
            client,
            {"login": "renamed-service", "id": 100000002, "type": "User"},
        )

    with patch("localize.guardian.cli.httpx.Client") as client_factory:
        client_factory.return_value.__enter__.return_value = client
        cli._probe_github(config)

    if expects_actor_probe:
        client.stream.assert_called_once_with("GET", "/user")
    else:
        client.stream.assert_not_called()


def test_doctor_github_probe_skips_actor_endpoint_without_publish_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config_path = _init_config(tmp_path)
    config = _remediation_doctor_config(config_path)
    config = replace(
        config,
        mode=GuardianMode.PREPARE,
        limits=replace(config.limits, max_remediation_drafts_per_run=0),
    )
    monkeypatch.setattr(cli.SecretCommand, "read", lambda _self: "secret-token")
    reader = Mock()
    reader.repository_identity.return_value = GitHubRepositoryIdentity(
        "acme/widgets",
        100000001,
        False,
    )
    monkeypatch.setattr(cli, "GitHubReader", lambda _client, _policy: reader)
    client = Mock()

    with patch("localize.guardian.cli.httpx.Client") as client_factory:
        client_factory.return_value.__enter__.return_value = client
        cli._probe_github(config)

    client.stream.assert_not_called()


def test_doctor_never_prints_helper_or_environment_secrets(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    config_path = _init_config(tmp_path)
    capsys.readouterr()
    secret = "guardian-super-secret"
    monkeypatch.setenv("OPENAI_API_KEY", secret)
    monkeypatch.setattr(cli.shutil, "which", lambda name: f"/usr/local/bin/{name}")
    monkeypatch.setattr(
        cli,
        "_probe_github",
        Mock(side_effect=RuntimeError(f"token was {secret}")),
    )
    monkeypatch.setattr(
        cli, "_signing_key_configured", lambda _configured, **_kwargs: False
    )

    exit_code = cli.main(["doctor", "--config", str(config_path)])

    output = capsys.readouterr()
    assert exit_code == 1
    assert secret not in output.out
    assert secret not in output.err
    assert "GitHub read-only probe: error" in output.out


def test_doctor_requires_signing_only_for_write_modes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    config_path = _init_config(tmp_path)
    capsys.readouterr()
    monkeypatch.setenv("OPENAI_API_KEY", "doctor-only-test-key")

    def command_available(command: tuple[str, ...]) -> bool:
        return command != ("gpg",)

    monkeypatch.setattr(cli, "_command_available", command_available)
    monkeypatch.setattr(
        cli,
        "_probe_github",
        lambda _config: (GitHubRepositoryIdentity("acme/widgets", 100000001, False),),
    )
    signing_probe = Mock(return_value=False)
    monkeypatch.setattr(cli, "_signing_key_configured", signing_probe)

    observe_exit = cli.main(["doctor", "--config", str(config_path)])
    observe_output = capsys.readouterr().out
    config_path.write_text(
        _replace_once(
            config_path.read_text(encoding="utf-8"),
            "mode: observe",
            "mode: apply-owned-translations",
        ),
        encoding="utf-8",
    )
    apply_exit = cli.main(["doctor", "--config", str(config_path)])
    apply_output = capsys.readouterr().out

    assert observe_exit == 0
    assert "Signing program: not required (observe mode)" in observe_output
    assert "commit signing: not required (observe mode)" in observe_output
    signing_probe.assert_not_called()
    assert apply_exit == 1
    assert "Signing program: error (not found)" in apply_output
    assert "commit signing: error" in apply_output


def test_doctor_wires_the_complete_ssh_signing_identity_into_real_probe(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    config_path = _init_config(tmp_path)
    capsys.readouterr()
    fingerprint = "SHA256:" + "A" * 43
    configured = config_path.read_text(encoding="utf-8")
    configured = _replace_once(
        configured,
        "mode: observe",
        "mode: apply-owned-translations",
    )
    configured = _replace_once(
        configured,
        "  signing_format: openpgp\n  signing_program: gpg",
        (
            "  signing_format: ssh\n"
            "  signing_program: /usr/bin/ssh-keygen\n"
            f"  signing_key: {fingerprint}\n"
            "  signing_public_key: /keys/guardian.pub"
        ),
    )
    config_path.write_text(configured, encoding="utf-8")
    config_path.chmod(0o600)
    monkeypatch.setattr(cli, "_command_available", lambda _command: True)
    monkeypatch.setattr(
        cli,
        "_probe_github",
        lambda _config: (
            GitHubRepositoryIdentity("acme/widgets", 100000001, False),
        ),
    )
    probe = Mock(return_value=True)
    monkeypatch.setattr(cli, "_signing_key_configured", probe)

    assert cli.main(["doctor", "--config", str(config_path)]) == 0

    probe.assert_called_once_with(
        fingerprint,
        git_executable="git",
        signing_program="/usr/bin/ssh-keygen",
        signing_format=SigningFormat.SSH,
        signing_public_key="/keys/guardian.pub",
        temporary_root=cli.guardian_state_dir(config_path),
    )
    assert "exact key signed and verified" in capsys.readouterr().out


def test_ssh_doctor_uses_trusted_config_parent_without_creating_missing_state_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    config_path = _init_config(tmp_path)
    capsys.readouterr()
    state_directory = cli.guardian_state_dir(config_path)
    state_directory.rmdir()
    fingerprint = "SHA256:" + "A" * 43
    configured = config_path.read_text(encoding="utf-8")
    configured = _replace_once(
        configured,
        "mode: observe",
        "mode: apply-owned-translations",
    )
    configured = _replace_once(
        configured,
        "  signing_format: openpgp\n  signing_program: gpg",
        (
            "  signing_format: ssh\n"
            "  signing_program: /usr/bin/ssh-keygen\n"
            f"  signing_key: {fingerprint}\n"
            "  signing_public_key: /keys/guardian.pub"
        ),
    )
    config_path.write_text(configured, encoding="utf-8")
    config_path.chmod(0o600)
    monkeypatch.setattr(cli, "_command_available", lambda _command: True)
    monkeypatch.setattr(
        cli,
        "_probe_github",
        lambda _config: (
            GitHubRepositoryIdentity("acme/widgets", 100000001, False),
        ),
    )
    probe = Mock(return_value=True)
    monkeypatch.setattr(cli, "_signing_key_configured", probe)

    assert cli.main(["doctor", "--config", str(config_path)]) == 0

    assert not state_directory.exists()
    assert probe.call_args.kwargs["temporary_root"] == config_path.parent


def test_signing_probe_never_falls_back_to_global_git_configuration(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run = Mock(
        return_value=subprocess.CompletedProcess(
            args=["git", "config", "--get", "user.signingkey"],
            returncode=0,
            stdout="GLOBAL-KEY\n",
            stderr="",
        )
    )
    monkeypatch.setattr(cli, "run_bounded_process", run)

    assert (
        cli._signing_key_configured(
            None,
            git_executable="/usr/bin/git",
            signing_program="/usr/bin/gpg",
        )
        is False
    )
    run.assert_not_called()


def test_signing_probe_signs_and_verifies_with_exact_key_in_isolated_context(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify signing uses only the configured identity in its isolated context."""
    gnupg_home = tmp_path / "gnupg"
    gnupg_home.mkdir()
    gnupg_home.chmod(0o700)
    monkeypatch.setenv("GNUPGHOME", str(gnupg_home))
    monkeypatch.setattr(cli.shutil, "which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(cli, "_command_available", lambda _command: True)
    calls: list[tuple[list[str], dict[str, str]]] = []

    fingerprint = "A" * 40

    def run(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        """Record the signing probe invocation and return its configured test result."""
        calls.append((argv, dict(kwargs["env"])))  # type: ignore[arg-type]
        stderr = f"[GNUPG:] VALIDSIG {fingerprint}\n" if "verify-commit" in argv else ""
        return subprocess.CompletedProcess(argv, 0, "", stderr)

    monkeypatch.setattr(cli, "run_bounded_process", run)

    assert cli._signing_key_configured(
        fingerprint,
        git_executable="/usr/bin/git",
        signing_program="/usr/bin/gpg",
    ) is True
    assert len(calls) == 3
    assert calls[0][0][0:3] == ["/usr/bin/git", "-c", "gpg.program=/usr/bin/gpg"]
    assert f"-S{fingerprint}" in calls[1][0]
    assert calls[2][0][-3:] == ["verify-commit", "--raw", "HEAD"]
    for _argv, environment in calls:
        assert environment["GIT_CONFIG_NOSYSTEM"] == "1"
        assert environment["GIT_CONFIG_GLOBAL"] == os.devnull
        assert environment["GNUPGHOME"] == str(gnupg_home.resolve())
        assert "OPENAI_API_KEY" not in environment


def test_signing_probe_fails_closed_when_exact_key_cannot_sign(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    gnupg_home = tmp_path / "gnupg"
    gnupg_home.mkdir()
    gnupg_home.chmod(0o700)
    monkeypatch.setenv("GNUPGHOME", str(gnupg_home))
    monkeypatch.setattr(cli.shutil, "which", lambda _name: "/usr/bin/git")
    monkeypatch.setattr(cli, "_command_available", lambda _command: True)
    calls = 0

    def run(argv: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        nonlocal calls
        calls += 1
        return subprocess.CompletedProcess(argv, 0 if calls == 1 else 1, "", "")

    monkeypatch.setattr(cli, "run_bounded_process", run)

    assert cli._signing_key_configured(
        "B" * 40,
        git_executable="/usr/bin/git",
        signing_program="/usr/bin/gpg",
    ) is False
    assert calls == 2


def test_signing_probe_rejects_an_untrusted_openpgp_home(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    gnupg_home = tmp_path / "gnupg"
    gnupg_home.mkdir(mode=0o700)
    gnupg_home.chmod(0o777)
    monkeypatch.setenv("GNUPGHOME", str(gnupg_home))
    monkeypatch.setattr(cli, "_command_available", lambda _command: True)
    monkeypatch.setattr(
        cli,
        "run_bounded_process",
        lambda *_args, **_kwargs: pytest.fail(
            "an unsafe OpenPGP home must be rejected before invoking Git"
        ),
    )

    assert cli._signing_key_configured(
        "B" * 40,
        git_executable="/usr/bin/git",
        signing_program="/usr/bin/gpg",
    ) is False


def test_ssh_signing_probe_uses_frozen_key_and_agent_only_for_commit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Confine signing material to the probe commit and approved snapshot path."""
    fingerprint = "SHA256:" + "A" * 43
    calls: list[tuple[list[str], dict[str, str]]] = []
    captured_snapshot: dict[str, object] = {}

    @contextmanager
    def fake_snapshot(**kwargs: object):
        """Yield frozen SSH signing material without exposing a real private key."""
        captured_snapshot.update(kwargs)
        root = Path(kwargs["temporary_root"])
        yield SSHSigningMaterial(
            root=root,
            public_key=root / "signing-key.pub",
            allowed_signers=root / "allowed-signers",
            fingerprint=fingerprint,
        )

    def run(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append((argv, dict(kwargs["env"])))  # type: ignore[arg-type]
        output = (
            'Good "git" signature for localize-guardian with ED25519 key '
            f"{fingerprint}\n"
            if "verify-commit" in argv
            else ""
        )
        return subprocess.CompletedProcess(argv, 0, output, "")

    monkeypatch.setattr(cli, "_command_available", lambda _command: True)
    monkeypatch.setattr(cli, "snapshot_ssh_signing_material", fake_snapshot)
    monkeypatch.setattr(
        cli,
        "ssh_agent_environment",
        lambda **_kwargs: {"SSH_AUTH_SOCK": "/private/test-agent.sock"},
    )
    monkeypatch.setattr(cli, "run_bounded_process", run)

    assert cli._signing_key_configured(
        fingerprint,
        signing_format=SigningFormat.SSH,
        signing_public_key="/keys/guardian.pub",
        git_executable="/usr/bin/git",
        signing_program="/usr/bin/ssh-keygen",
        temporary_root=tmp_path,
    )
    assert len(calls) == 3
    commit_call = next(call for call in calls if "commit" in call[0])
    assert commit_call[1]["SSH_AUTH_SOCK"] == "/private/test-agent.sock"
    assert all(
        "SSH_AUTH_SOCK" not in environment
        for arguments, environment in calls
        if "commit" not in arguments
    )
    assert "gpg.format=ssh" in commit_call[0]
    assert "gpg.ssh.program=/usr/bin/ssh-keygen" in commit_call[0]
    assert any(argument.startswith("gpg.ssh.allowedSignersFile=") for argument in commit_call[0])
    assert "gpg.minTrustLevel=fully" in commit_call[0]
    assert any(argument.startswith("-S") for argument in commit_call[0])
    assert captured_snapshot["public_key_path"] == "/keys/guardian.pub"
    assert captured_snapshot["expected_fingerprint"] == fingerprint
    # Match the runtime layout: an extra nested probe directory can exceed
    # macOS's Unix-socket path limit for the pinned agent socket.
    assert captured_snapshot["temporary_root"] == tmp_path


def test_ssh_signing_probe_rejects_wrong_verified_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Reject a successful signature made by an unexpected SSH identity."""
    fingerprint = "SHA256:" + "A" * 43

    @contextmanager
    def fake_snapshot(**kwargs: object):
        root = Path(kwargs["temporary_root"])
        yield SSHSigningMaterial(
            root=root,
            public_key=root / "signing-key.pub",
            allowed_signers=root / "allowed-signers",
            fingerprint=fingerprint,
        )

    monkeypatch.setattr(cli, "_command_available", lambda _command: True)
    monkeypatch.setattr(cli, "snapshot_ssh_signing_material", fake_snapshot)
    monkeypatch.setattr(
        cli,
        "ssh_agent_environment",
        lambda **_kwargs: {"SSH_AUTH_SOCK": "/private/test-agent.sock"},
    )
    monkeypatch.setattr(
        cli,
        "run_bounded_process",
        lambda argv, **_kwargs: subprocess.CompletedProcess(
            argv,
            0,
            (
                'Good "git" signature for localize-guardian with ED25519 key '
                f"SHA256:{'B' * 43}\n"
                if "verify-commit" in argv
                else ""
            ),
            "",
        ),
    )

    assert not cli._signing_key_configured(
        fingerprint,
        signing_format=SigningFormat.SSH,
        signing_public_key="/keys/guardian.pub",
        git_executable="/usr/bin/git",
        signing_program="/usr/bin/ssh-keygen",
        temporary_root=tmp_path,
    )


def test_doctor_consumes_secret_free_runtime_commands_from_config(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    config_path = _init_config(tmp_path)
    capsys.readouterr()
    codex = tmp_path / "bin" / "codex-custom"
    github_helper = tmp_path / "bin" / "github-token"
    api_helper = tmp_path / "bin" / "model-token"
    codex.parent.mkdir()
    for executable in (codex, github_helper, api_helper):
        executable.write_text("#!/bin/sh\n", encoding="utf-8")
        executable.chmod(0o700)
    generated = config_path.read_text(encoding="utf-8")
    config_path.write_text(
            "runtime:\n"
            "  codex_auth_mode: api-key\n"
        "  codex_model: gpt-5.6-terra\n"
        "  codex_reasoning_effort: high\n"
        f"  codex_executable: {codex}\n"
        "  git_executable: /usr/bin/git\n"
        "  signing_program: /usr/bin/gpg\n"
        f"  github_token_command: [{github_helper}]\n"
        f"  codex_api_key_command: [{api_helper}]\n"
            f"  signing_key: {'A' * 40}\n"
            + "limits:\n"
            + "  daily_cost_limit_usd: 2.00\n"
            + "  model_call_reservation_usd: 2.00\n"
            + generated.split("limits:\n", 1)[1],
        encoding="utf-8",
    )
    # The expression above preserves the generated limits/repository policy while
    # replacing only its runtime block.
    config = load_guardian_config(config_path)
    github_probe = Mock(
        return_value=(GitHubRepositoryIdentity("acme/widgets", 100000001, False),)
    )
    monkeypatch.setattr(cli, "_probe_github", github_probe)
    monkeypatch.setattr(cli.shutil, "which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(cli, "_command_available", lambda _command: True)
    monkeypatch.setattr(
        cli, "_credential_helper_works", lambda command: command == (str(api_helper),)
    )
    signing_probe = Mock(return_value=True)
    monkeypatch.setattr(cli, "_signing_key_configured", signing_probe)

    exit_code = cli.main(["doctor", "--config", str(config_path)])

    output = capsys.readouterr().out
    assert exit_code == 0
    assert (
        "Codex model/effort: configured gpt-5.6-terra / high "
        "(not capability-validated)"
    ) in output
    github_probe.assert_called_once_with(config)
    assert "Signing program: not required (observe mode)" in output
    signing_probe.assert_not_called()


def test_doctor_does_not_create_a_missing_state_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    config_path = _init_config(tmp_path)
    capsys.readouterr()
    state_dir = cli.guardian_state_dir(config_path)
    state_dir.rmdir()
    monkeypatch.setenv("OPENAI_API_KEY", "doctor-only-test-key")
    monkeypatch.setattr(cli.shutil, "which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(
        cli,
        "_probe_github",
        lambda _config: (GitHubRepositoryIdentity("acme/widgets", 100000001, False),),
    )
    monkeypatch.setattr(
        cli, "_signing_key_configured", lambda _configured, **_kwargs: False
    )

    exit_code = cli.main(["doctor", "--config", str(config_path)])

    assert exit_code == 0
    assert not state_dir.exists()
    assert list(config_path.parent.glob(".guardian-poll-lock-doctor-*")) == []
    assert "created on first run or install" in capsys.readouterr().out


@pytest.mark.parametrize("missing_state_directory", [False, True])
def test_doctor_snapshots_operator_pipeline_config_without_persistent_artifacts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    missing_state_directory: bool,
) -> None:
    config_path = _init_config(tmp_path)
    capsys.readouterr()
    _configure_operator_pipeline(config_path)
    state_dir = cli.guardian_state_dir(config_path)
    if missing_state_directory:
        state_dir.rmdir()
    monkeypatch.setattr(cli, "_command_available", lambda _command: True)
    monkeypatch.setattr(
        cli,
        "_probe_github",
        lambda _config: (
            GitHubRepositoryIdentity("acme/widgets", 100000001, False),
        ),
    )

    exit_code = cli.main(["doctor", "--config", str(config_path)])

    assert exit_code == 0
    assert "operator pipeline configs: ok (1 snapshotted)" in capsys.readouterr().out
    assert list(config_path.parent.glob(".guardian-operator-config-doctor-*")) == []
    if missing_state_directory:
        assert not state_dir.exists()
    else:
        assert list(state_dir.glob("operator-pipeline-config-*")) == []


@pytest.mark.parametrize("unsafe_glossary", ["wrong-mode", "malformed"])
def test_doctor_fails_before_external_probes_for_unsafe_operator_bundle(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    unsafe_glossary: str,
) -> None:
    config_path = _init_config(tmp_path)
    capsys.readouterr()
    glossary = _configure_operator_pipeline(config_path)
    if unsafe_glossary == "wrong-mode":
        glossary.chmod(0o644)
    else:
        glossary.write_text("{malformed", encoding="utf-8")
        glossary.chmod(0o600)
    command_probe = Mock(return_value=True)
    github_probe = Mock()
    codex_probe = Mock(return_value=True)
    monkeypatch.setattr(cli, "_command_available", command_probe)
    monkeypatch.setattr(cli, "_probe_github", github_probe)
    monkeypatch.setattr(cli, "_codex_capability_probe", codex_probe)

    exit_code = cli.main(["doctor", "--config", str(config_path)])

    output = capsys.readouterr().out
    assert exit_code == 1
    assert "operator pipeline configs: error" in output
    command_probe.assert_not_called()
    github_probe.assert_not_called()
    codex_probe.assert_not_called()
    assert list(cli.guardian_state_dir(config_path).glob("operator-pipeline-config-*")) == []


def test_run_leaves_private_state_creation_to_the_runtime(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config_path = _init_config(tmp_path)
    state_path = cli.guardian_state_path(config_path)
    captured: dict[str, object] = {}

    def run_once(**kwargs: object) -> None:
        assert not state_path.exists()
        captured.update(kwargs)

    imported = Mock(return_value=SimpleNamespace(run_once=run_once))
    monkeypatch.setattr(cli.importlib, "import_module", imported)

    exit_code = cli.main(["run", "--config", str(config_path), "--scheduled"])

    assert exit_code == 0
    assert not state_path.exists()
    imported.assert_called_once_with("localize.guardian.controller")
    assert captured == {
        "config_path": config_path.resolve(),
        "scheduled": True,
    }


def test_run_accepts_a_private_state_directory_created_by_a_racer(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config_path = tmp_path / "guardian.yaml"
    config_path.write_text(cli._STARTER_CONFIG, encoding="utf-8")
    config_path.chmod(0o600)
    state_directory = cli.guardian_state_dir(config_path)

    def racing_mkdir(
        path: Path,
        mode: int = 0o777,
        parents: bool = False,
        exist_ok: bool = False,
    ) -> None:
        assert path == state_directory
        assert parents is True
        assert exist_ok is False
        os.mkdir(path, mode)
        raise FileExistsError

    monkeypatch.setattr(Path, "mkdir", racing_mkdir)
    run_once = Mock(return_value=0)
    monkeypatch.setattr(
        cli.importlib,
        "import_module",
        lambda _name: SimpleNamespace(run_once=run_once),
    )

    assert cli.main(["run", "--config", str(config_path)]) == 0
    assert _mode(state_directory) == 0o700
    run_once.assert_called_once()


@pytest.mark.skipif(
    not guardian_runtime._poll_locking_is_available(),
    reason="POSIX flock is unavailable",
)
def test_first_scheduled_cli_runs_share_one_lock_from_clean_state(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "guardian.yaml"
    config_path.write_text(cli._STARTER_CONFIG, encoding="utf-8")
    config_path.chmod(0o600)
    gate = tmp_path / "start"
    ready_paths = tuple(tmp_path / f"ready-{index}" for index in range(2))
    project_root = Path(__file__).resolve().parents[2]
    environment = os.environ.copy()
    existing_pythonpath = environment.get("PYTHONPATH")
    environment["PYTHONPATH"] = os.pathsep.join(
        value
        for value in (str(project_root), existing_pythonpath)
        if value
    )
    script = """
import os
from pathlib import Path
import sys
import time
from localize.guardian import cli, runtime

os.umask(0o777)
config_path = Path(sys.argv[1])
gate = Path(sys.argv[2])
ready = Path(sys.argv[3])
contended = Path(sys.argv[4])
ready.touch()
deadline = time.monotonic() + 5
while not gate.exists():
    if time.monotonic() >= deadline:
        raise SystemExit(2)
    time.sleep(0.005)

def locked_poll(**_kwargs):
    print("owner", flush=True)
    deadline = time.monotonic() + 5
    while not contended.exists():
        if time.monotonic() >= deadline:
            raise RuntimeError("contender did not finish")
        time.sleep(0.005)
    return 7

runtime._poll_with_locked_state = locked_poll
result = cli.main(["run", "--config", str(config_path), "--scheduled"])
if result == 0:
    contended.touch()
print(f"result={result}", flush=True)
"""
    contended = tmp_path / "contended"
    processes = tuple(
        subprocess.Popen(
            (
                sys.executable,
                "-c",
                script,
                str(config_path),
                str(gate),
                str(ready_paths[index]),
                str(contended),
            ),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=environment,
        )
        for index in range(2)
    )

    ready_deadline = time.monotonic() + 10
    while not all(path.exists() for path in ready_paths):
        if time.monotonic() >= ready_deadline:
            break
        time.sleep(0.005)
    all_ready = all(path.exists() for path in ready_paths)
    gate.touch()
    results = tuple(process.communicate(timeout=10) for process in processes)

    assert all_ready, results
    assert [process.returncode for process in processes] == [0, 0], results
    assert sorted(stdout.strip() for stdout, _stderr in results) == [
        "owner\nresult=7",
        "result=0",
    ], results
    assert all(stderr == "" for _stdout, stderr in results)


def test_run_waits_for_a_live_restrictive_umask_directory_creator(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config_path = tmp_path / "guardian.yaml"
    config_path.write_text(cli._STARTER_CONFIG, encoding="utf-8")
    config_path.chmod(0o600)
    state_directory = cli.guardian_state_dir(config_path)
    creator_is_normalizing = threading.Event()
    release_creator = threading.Event()
    contender_inspected_restricted_directory = threading.Event()
    original_chmod = Path.chmod
    original_stat = Path.stat
    results: dict[str, int] = {}
    run_once = Mock(return_value=0)
    monkeypatch.setattr(
        cli.importlib,
        "import_module",
        lambda _name: SimpleNamespace(run_once=run_once),
    )

    def delayed_creator_chmod(
        path: Path,
        mode: int,
        *args: object,
        **kwargs: object,
    ) -> None:
        if path == state_directory and threading.current_thread().name == "creator":
            creator_is_normalizing.set()
            assert release_creator.wait(timeout=5)
        original_chmod(path, mode, *args, **kwargs)

    def observed_stat(
        path: Path,
        *args: object,
        **kwargs: object,
    ) -> os.stat_result:
        metadata = original_stat(path, *args, **kwargs)
        if (
            path == state_directory
            and threading.current_thread().name == "contender"
            and stat.S_IMODE(metadata.st_mode) != 0o700
        ):
            contender_inspected_restricted_directory.set()
        return metadata

    def run(name: str) -> None:
        results[name] = cli._cmd_run(
            SimpleNamespace(config=str(config_path), scheduled=True)
        )

    monkeypatch.setattr(Path, "chmod", delayed_creator_chmod)
    monkeypatch.setattr(Path, "stat", observed_stat)
    previous_umask = os.umask(0o777)
    try:
        creator = threading.Thread(target=run, args=("creator",), name="creator")
        creator.start()
        assert creator_is_normalizing.wait(timeout=5)
        contender = threading.Thread(target=run, args=("contender",), name="contender")
        contender.start()
        assert contender_inspected_restricted_directory.wait(timeout=5)
        release_creator.set()
        creator.join(timeout=5)
        contender.join(timeout=5)
    finally:
        release_creator.set()
        os.umask(previous_umask)

    assert not creator.is_alive()
    assert not contender.is_alive()
    assert results == {"creator": 0, "contender": 0}
    assert _mode(state_directory) == 0o700
    assert run_once.call_count == 2


def test_run_reports_the_safe_manual_overlap_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    config_path = _init_config(tmp_path)
    capsys.readouterr()
    runtime = SimpleNamespace(
        run_once=Mock(
            side_effect=cli.GuardianRuntimeError(
                "Guardian poll is already running."
            )
        )
    )
    monkeypatch.setattr(cli.importlib, "import_module", lambda _name: runtime)

    exit_code = cli.main(["run", "--config", str(config_path)])

    captured = capsys.readouterr()
    assert exit_code == 1
    assert captured.err == "error: Guardian poll is already running.\n"


def test_run_reports_controller_failure_without_echoing_exception_text(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    config_path = _init_config(tmp_path)
    capsys.readouterr()
    secret = "comment-or-token-secret"
    runtime = SimpleNamespace(run_once=Mock(side_effect=RuntimeError(secret)))
    monkeypatch.setattr(cli.importlib, "import_module", lambda _name: runtime)

    exit_code = cli.main(["run", "--config", str(config_path)])

    captured = capsys.readouterr()
    assert exit_code == 1
    assert secret not in captured.out
    assert secret not in captured.err
    assert "RuntimeError" in captured.err


@pytest.mark.parametrize("unsafe_kind", ["symlink", "mode", "hardlink"])
def test_doctor_rejects_an_unsafe_existing_poll_lock(
    tmp_path: Path,
    unsafe_kind: str,
) -> None:
    config_path = _init_config(tmp_path)
    state_directory = cli.guardian_state_dir(config_path)
    lock_path = state_directory / "poll.lock"
    if unsafe_kind == "symlink":
        target = tmp_path / "target.lock"
        target.write_text("", encoding="utf-8")
        target.chmod(0o600)
        lock_path.symlink_to(target)
    elif unsafe_kind == "hardlink":
        lock_path.write_text("", encoding="utf-8")
        lock_path.chmod(0o600)
        (tmp_path / "alias.lock").hardlink_to(lock_path)
    else:
        lock_path.write_text("", encoding="utf-8")
        lock_path.chmod(0o644)

    status, healthy = cli._state_directory_doctor(config_path)

    assert healthy is False
    assert status == "error (paths must be regular and private)"
    assert list(
        cli.guardian_state_dir(config_path).glob(".guardian-poll-lock-doctor-*")
    ) == []


def test_doctor_rejects_a_hardlinked_state_database(tmp_path: Path) -> None:
    config_path = _init_config(tmp_path)
    state_path = cli.guardian_state_path(config_path)
    state_path.write_text("", encoding="utf-8")
    state_path.chmod(0o600)
    (tmp_path / "state-alias").hardlink_to(state_path)

    status, healthy = cli._state_directory_doctor(config_path)

    assert healthy is False
    assert status == "error (paths must be regular and private)"


def test_doctor_rejects_a_hardlinked_sqlite_sidecar_without_mutating_it(
    tmp_path: Path,
) -> None:
    config_path = _init_config(tmp_path)
    state_path = cli.guardian_state_path(config_path)
    with GuardianState(state_path):
        pass
    wal_path = Path(f"{state_path}-wal")
    if wal_path.exists():
        wal_path.unlink()
    sentinel = tmp_path / "sentinel"
    sentinel.write_bytes(b"do not mutate")
    sentinel.chmod(0o600)
    wal_path.hardlink_to(sentinel)

    status, healthy = cli._state_directory_doctor(config_path)

    assert healthy is False
    assert status == "error (paths must be regular and private)"
    assert sentinel.read_bytes() == b"do not mutate"


@pytest.mark.parametrize("flock_behavior", ["unsupported", "ineffective"])
def test_doctor_exercises_real_flock_semantics(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    flock_behavior: str,
) -> None:
    config_path = _init_config(tmp_path)

    def fake_flock(_descriptor: int, _operation: int) -> None:
        if flock_behavior == "unsupported":
            raise OSError(errno.ENOTSUP, "unsupported")

    assert guardian_runtime.fcntl is not None
    monkeypatch.setattr(guardian_runtime.fcntl, "flock", fake_flock)

    status, healthy = cli._state_directory_doctor(config_path)

    assert healthy is False
    assert status == "error (paths must be regular and private)"
    assert list(
        cli.guardian_state_dir(config_path).glob(".guardian-poll-lock-doctor-*")
    ) == []


def test_doctor_rejects_platforms_without_process_locking(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config_path = _init_config(tmp_path)
    monkeypatch.setattr(guardian_runtime, "fcntl", None)

    status, healthy = cli._state_directory_doctor(config_path)

    assert healthy is False
    assert status == "error (process locking is unavailable)"


def test_doctor_validates_but_does_not_acquire_an_active_poll_lock(
    tmp_path: Path,
) -> None:
    config_path = _init_config(tmp_path)
    state_directory = cli.guardian_state_dir(config_path)

    with guardian_runtime._exclusive_poll_lock(state_directory):
        status, healthy = cli._state_directory_doctor(config_path)

    assert healthy is True
    assert status == "ok"


def test_run_refuses_an_insecure_existing_state_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    config_path = _init_config(tmp_path)
    capsys.readouterr()
    cli.guardian_state_dir(config_path).chmod(0o755)
    imported = Mock()
    monkeypatch.setattr(cli.importlib, "import_module", imported)

    exit_code = cli.main(["run", "--config", str(config_path)])

    assert exit_code == 1
    assert _mode(cli.guardian_state_dir(config_path)) == 0o755
    imported.assert_not_called()
    assert "GuardianCLIError" in capsys.readouterr().err


def test_run_refuses_a_group_writable_authority_config(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    config_path = _init_config(tmp_path)
    capsys.readouterr()
    config_path.chmod(0o620)
    imported = Mock()
    monkeypatch.setattr(cli.importlib, "import_module", imported)

    exit_code = cli.main(["run", "--config", str(config_path)])

    assert exit_code == 1
    imported.assert_not_called()
    assert "GuardianCLIError" in capsys.readouterr().err


def test_status_summarizes_audit_metadata_without_raw_bodies_or_messages(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Keep human-readable status useful without exposing stored review text."""
    config_path = _init_config(tmp_path)
    capsys.readouterr()
    state_path = cli.guardian_state_path(config_path)
    secret = "review body with guardian-super-secret"
    with GuardianState(state_path) as state:
        revision = state.record_feedback_event(
            FeedbackEvent(
                repository="acme/widgets",
                pr_number=17,
                kind="review-comment",
                event_id="91",
                author="reviewer",
                author_id=100000004,
                author_type="User",
                body=secret,
                head_sha="a" * 40,
                base_sha="b" * 40,
                locale="de",
            )
        )
        run_id = state.start_run(
            repository="acme/widgets",
            locale="de",
            mode=GuardianMode.OBSERVE,
            started_at=datetime(2026, 8, 30, 9, 0, tzinfo=UTC),
        )
        state.record_action(
            run_id=run_id,
            event_revision_id=revision.revision_id,
            action="observe",
            status="completed",
        )
        state.finish_run(
            run_id,
            status="completed",
            summary=f"unsafe summary {secret}",
            finished_at=datetime(2026, 8, 30, 9, 1, tzinfo=UTC),
        )
        state.record_health(
            component="github",
            status="ok",
            message=f"unsafe health detail {secret}",
        )
    os.chmod(state_path, 0o600)

    exit_code = cli.main(["status", "--config", str(config_path)])

    output = capsys.readouterr().out
    assert exit_code == 0
    assert "Guardian status" in output
    assert "mode: observe" in output
    assert "last completed run: 2026-08-30T09:01:00" in output
    assert "last successful poll: none" in output
    assert "pending feedback revisions: 0" in output
    assert "actions: completed=1" in output
    assert "health: github=ok" in output
    assert "historical correction attempts: pending=0, opened=0" in output
    assert (
        "remote correction PRs: open=0, closed_unmerged_veto=0, "
        "not_found=0, conflict=0"
    ) in output
    assert secret not in output


def test_status_distinguishes_last_successful_poll_from_later_failure(tmp_path, capsys):
    """Do not let a later failed attempt replace the successful-poll timestamp."""
    config_path = _init_config(tmp_path)
    capsys.readouterr()
    with GuardianState(cli.guardian_state_path(config_path)) as state:
        state.record_health(
            component="guardian", status="ok", message="Poll completed",
            checked_at=datetime(2026, 9, 8, 8, 0, tzinfo=UTC),
        )
        state.record_health(
            component="guardian", status="failed", message="Poll failed",
            checked_at=datetime(2026, 9, 9, 8, 0, tzinfo=UTC),
        )
    assert cli.main(["status", "--config", str(config_path)]) == 0
    output = capsys.readouterr().out
    assert "last successful poll: 2026-09-08T08:00:00" in output
    assert "health: guardian=failed" in output


def test_status_is_read_only_when_no_state_database_exists(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Do not create state merely to report that Guardian has not run."""
    config_path = _init_config(tmp_path)
    capsys.readouterr()
    state_path = cli.guardian_state_path(config_path)
    assert not state_path.exists()

    exit_code = cli.main(["status", "--config", str(config_path)])

    assert exit_code == 0
    assert not state_path.exists()
    assert not (cli.guardian_state_dir(config_path) / "poll.lock").exists()
    assert "state: no runs recorded" in capsys.readouterr().out


def test_remediation_list_is_empty_without_state_database(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    config_path = _init_config(tmp_path)
    capsys.readouterr()

    assert cli.main(
        ["remediation", "list", "--config", str(config_path)]
    ) == 0

    assert capsys.readouterr().out == "No remediation attempts.\n"
    assert not (cli.guardian_state_dir(config_path) / "poll.lock").exists()


def test_history_retry_list_is_empty_without_state_database(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    config_path = _init_config(tmp_path)
    capsys.readouterr()

    assert cli.main(
        ["history-retry", "list", "--config", str(config_path)]
    ) == 0

    assert capsys.readouterr().out == "No pending historical hydration retries.\n"
    assert not (cli.guardian_state_dir(config_path) / "poll.lock").exists()


def test_remediation_quarantine_requires_explicit_terminal_skip_acknowledgement(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    config_path = _init_config(tmp_path)

    assert cli.main(
        [
            "remediation",
            "quarantine",
            "--config",
            str(config_path),
            "--draft-key",
            "a" * 64,
            "--repository",
            "acme/widgets",
        ]
    ) == 1

    assert "--acknowledge-terminal-local-skip" in capsys.readouterr().err


def test_remediation_quarantine_resolves_exact_local_attempt_only(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    config_path = _init_config(tmp_path)
    state_directory = cli.guardian_state_dir(config_path)
    state_directory.mkdir(mode=0o700, exist_ok=True)
    state_directory.chmod(0o700)
    state_path = cli.guardian_state_path(config_path)
    state_path.write_bytes(b"state")
    state_path.chmod(0o600)
    calls: list[dict[str, object]] = []

    @contextmanager
    def fake_lock(_directory: Path):
        yield

    class FakeState:
        def __init__(self, path: Path) -> None:
            assert path == state_path

        def __enter__(self):
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def remediation_draft_by_key(self, *, draft_key: str):
            assert draft_key == "a" * 64
            return SimpleNamespace(target_repository="acme/widgets")

        def record_remediation_resolution(self, **kwargs: object) -> bool:
            calls.append(dict(kwargs))
            return True

    monkeypatch.setattr(cli, "_exclusive_poll_lock", fake_lock)
    monkeypatch.setattr(cli, "GuardianState", FakeState)

    assert cli.main(
        [
            "remediation",
            "quarantine",
            "--config",
            str(config_path),
            "--draft-key",
            "a" * 64,
            "--repository",
            "acme/widgets",
            "--acknowledge-terminal-local-skip",
        ]
    ) == 0

    assert calls == [
        {
            "draft_key": "a" * 64,
            "resolution": "operator_quarantined",
            "terminal_local_skip_acknowledged": True,
        }
    ]
    output = capsys.readouterr().out
    assert "No remote branch or pull request was changed." in output


def test_remediation_list_and_quarantine_use_real_locked_sqlite_state(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    config_path = _init_config(tmp_path)
    capsys.readouterr()
    state_path = cli.guardian_state_path(config_path)
    with GuardianState(state_path) as state:
        draft_key = _record_cli_remediation_attempt(state)

    assert cli.main(
        ["remediation", "list", "--config", str(config_path), "--limit", "1"]
    ) == 0
    listed = capsys.readouterr().out
    assert draft_key in listed
    assert (
        "target=acme/widgets target_id=100000001 "
        "phase=validated identity=v2"
    ) in listed
    assert f"target_base: main@{'b' * 40}" in listed
    assert "push_repository: localization-service/widgets id=100000003" in listed
    assert f"candidate_commit: {'c' * 40}" in listed
    assert "pull_request: none" in listed
    assert "resolution: none" in listed
    assert "remote: none" in listed
    assert "coverage: none" in listed

    quarantine_args = [
        "remediation",
        "quarantine",
        "--config",
        str(config_path),
        "--draft-key",
        draft_key,
        "--repository",
        "acme/widgets",
        "--acknowledge-terminal-local-skip",
    ]
    assert cli.main(quarantine_args) == 0
    first = capsys.readouterr().out
    assert "terminally skipped" in first
    assert "No remote branch or pull request was changed." in first

    # Repeating the exact append is idempotent and never mutates GitHub.
    assert cli.main(quarantine_args) == 0
    assert "Already quarantined" in capsys.readouterr().out
    with GuardianState(state_path) as state:
        assert state.remediation_resolution(draft_key=draft_key) == (
            "operator_quarantined"
        )

    assert cli.main(
        ["remediation", "list", "--config", str(config_path), "--limit", "1"]
    ) == 0
    terminal = capsys.readouterr().out
    assert draft_key in terminal
    assert "resolution: operator_quarantined" in terminal


def test_remediation_list_surfaces_closed_veto_and_exact_coverage(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    config_path = _init_config(tmp_path)
    capsys.readouterr()
    state_path = cli.guardian_state_path(config_path)
    with GuardianState(state_path) as state:
        draft_key = _record_cli_remediation_attempt(state)
        _open_cli_remediation_attempt(state, draft_key)
    monkeypatch.setattr(
        GuardianState,
        "remediation_draft_count_for_operator",
        lambda _self: 3,
    )
    monkeypatch.setattr(
        GuardianState,
        "remediation_source_coverage_count_for_draft",
        lambda _self, _draft_key: 2,
    )

    assert cli.main(
        ["remediation", "list", "--config", str(config_path)]
    ) == 0

    listed = capsys.readouterr().out
    assert "pull_request: #91 https://github.test/acme/widgets/pull/91" in listed
    assert "remote: exact state=closed type=ready merged=false" in listed
    assert f"base={'d' * 40}" in listed
    assert "acme/widgets#12 repository_id=100000001 pull_id=500" in listed
    assert f"pull_revision={'1' * 64}" in listed
    assert f"authority={'3' * 64}" in listed
    assert f"policy={'2' * 64}" in listed
    assert "reason=draft_recovered" in listed
    assert f"effective=true drafts={draft_key}" in listed
    assert "coverage: showing 1 of 2 groups" in listed
    assert "Showing 1 of 3 remediation attempts." in listed


def test_history_retry_list_and_permanent_policy_veto_use_real_sqlite(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    config_path = _init_config(tmp_path)
    capsys.readouterr()
    state_path = cli.guardian_state_path(config_path)
    failed_at = datetime(2026, 9, 1, 8, 0, tzinfo=UTC)
    retry = {
        "repository": "acme/widgets",
        "repository_id": 100000001,
        "policy_digest": "b" * 64,
        "pull_id": 500,
        "pr_number": 12,
    }
    with GuardianState(state_path) as state:
        state.record_historical_pull_retry(
            **retry,
            failure_type="GitHubAPIError",
            failed_at=failed_at,
        )

    assert cli.main(
        ["history-retry", "list", "--config", str(config_path)]
    ) == 0
    listed = capsys.readouterr().out
    for expected in (
        "repository=acme/widgets",
        "repository_id=100000001",
        f"policy_digest={'b' * 64}",
        "pull_id=500",
        "pr_number=12",
        "failure=GitHubAPIError",
    ):
        assert expected in listed

    base_args = [
        "history-retry",
        "quarantine",
        "--config",
        str(config_path),
        "--repository",
        "acme/widgets",
        "--repository-id",
        "100000001",
        "--policy-digest",
        "b" * 64,
        "--pull-id",
        "500",
        "--pr-number",
        "12",
    ]
    assert cli.main(base_args) == 1
    assert "later feedback under that policy will be ignored" in capsys.readouterr().err

    quarantine_args = [*base_args, "--acknowledge-terminal-local-skip"]
    assert cli.main(quarantine_args) == 0
    output = capsys.readouterr().out
    assert "Permanently vetoed source PR #12" in output
    assert "Later comments on this PR are intentionally ignored" in output
    assert "policy change makes it eligible again" in output
    assert "No remote pull request or comment was changed." in output

    assert cli.main(quarantine_args) == 0
    assert "Already permanently vetoed" in capsys.readouterr().out
    with GuardianState(state_path) as state:
        assert state.pending_historical_pull_retry_count() == 0
        state.record_historical_pull_retry(
            **{**retry, "policy_digest": "c" * 64},
            failure_type="GitHubAPIError",
            failed_at=failed_at + timedelta(minutes=1),
        )
        assert state.pending_historical_pull_retry_count() == 1


@pytest.mark.parametrize("command", ["status", "remediation", "history-retry"])
def test_operator_state_commands_fail_closed_while_real_poll_lock_is_held(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    command: str,
) -> None:
    config_path = _init_config(tmp_path)
    capsys.readouterr()
    state_path = cli.guardian_state_path(config_path)
    with GuardianState(state_path):
        pass
    argv = [command]
    if command != "status":
        argv.append("list")
    argv.extend(("--config", str(config_path)))

    with guardian_runtime._exclusive_poll_lock(cli.guardian_state_dir(config_path)):
        assert cli.main(argv) == 1

    assert "unavailable" in capsys.readouterr().err


def test_status_refuses_a_symlinked_state_database_without_reading_its_target(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    config_path = _init_config(tmp_path)
    capsys.readouterr()
    secret = "state-target-secret"
    target = tmp_path / "foreign-state"
    target.write_text(secret, encoding="utf-8")
    cli.guardian_state_path(config_path).symlink_to(target)

    exit_code = cli.main(["status", "--config", str(config_path)])

    captured = capsys.readouterr()
    assert exit_code == 1
    assert secret not in captured.out
    assert secret not in captured.err


@pytest.mark.parametrize(
    "argv",
    [
        ("status",),
        ("remediation", "list"),
        ("history-retry", "list"),
    ],
)
def test_operator_state_commands_reject_unsafe_sqlite_sidecars(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    argv: tuple[str, ...],
) -> None:
    config_path = _init_config(tmp_path)
    capsys.readouterr()
    state_path = cli.guardian_state_path(config_path)
    with GuardianState(state_path):
        pass
    wal_path = Path(f"{state_path}-wal")
    if wal_path.exists():
        wal_path.unlink()
    secret = b"sidecar-secret"
    target = tmp_path / "foreign-wal"
    target.write_bytes(secret)
    target.chmod(0o600)
    wal_path.symlink_to(target)

    assert cli.main([*argv, "--config", str(config_path)]) == 1

    captured = capsys.readouterr()
    assert target.read_bytes() == secret
    assert secret.decode() not in captured.out
    assert secret.decode() not in captured.err
    assert "unavailable or invalid" in captured.err


def test_install_stages_secret_free_launchd_artifacts_without_loading_or_overwriting(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    config_path = _init_config(tmp_path)
    capsys.readouterr()
    executable = tmp_path / "bin" / "localize"
    executable.parent.mkdir()
    executable.write_text("#!/bin/sh\n", encoding="utf-8")
    executable.chmod(0o700)
    _configure_scheduled_runtime(config_path, tmp_path)
    launch_agents = tmp_path / "Library" / "LaunchAgents"
    monkeypatch.setattr(cli, "_default_launch_agents_dir", lambda: launch_agents)
    secret = "must-not-be-embedded"
    monkeypatch.setenv("OPENAI_API_KEY", secret)

    first_exit = cli.main(
        [
            "install",
            "--config",
            str(config_path),
            "--executable",
            str(executable),
        ]
    )
    first_output = capsys.readouterr()

    paths = cli.guardian_install_paths(config_path)
    assert first_exit == 0
    assert paths.runner_path.is_file()
    assert paths.plist_path.is_file()
    assert paths.stdout_path.is_file()
    assert paths.stderr_path.is_file()
    assert _mode(paths.runner_path) == 0o700
    assert _mode(paths.plist_path) == 0o600
    assert _mode(paths.stdout_path) == 0o600
    assert _mode(paths.stderr_path) == 0o600
    combined = paths.runner_path.read_text() + paths.plist_path.read_text()
    assert str(config_path.resolve()) in combined
    assert secret not in combined
    assert "launchctl" not in combined
    assert "staged but not loaded" in first_output.out

    original_runner = paths.runner_path.read_bytes()
    second_exit = cli.main(
        [
            "install",
            "--config",
            str(config_path),
            "--executable",
            str(executable),
        ]
    )
    assert second_exit == 1
    assert paths.runner_path.read_bytes() == original_runner
    assert "already exists" in capsys.readouterr().err


def test_install_subscription_mode_requires_no_api_credential_helper(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    config_path = _init_config(tmp_path)
    capsys.readouterr()
    executable = tmp_path / "localize"
    executable.write_text("#!/bin/sh\n", encoding="utf-8")
    executable.chmod(0o700)
    _configure_scheduled_runtime(config_path, tmp_path, api_key=False)
    config_path.write_text(
        _replace_once(
            config_path.read_text(encoding="utf-8"),
            f"  signing_program: {tmp_path / 'bin' / 'gpg'}",
            "  signing_program: gpg",
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(
        cli,
        "_default_launch_agents_dir",
        lambda: tmp_path / "Library" / "LaunchAgents",
    )

    exit_code = cli.main(
        ["install", "--config", str(config_path), "--executable", str(executable)]
    )

    assert exit_code == 0
    assert "codex_api_key_command:" not in "\n".join(
        line
        for line in config_path.read_text(encoding="utf-8").splitlines()
        if not line.lstrip().startswith("#")
    )
    assert cli.guardian_install_paths(config_path).plist_path.exists()


def test_install_write_mode_requires_absolute_signing_program(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    config_path = _init_config(tmp_path)
    capsys.readouterr()
    _configure_scheduled_runtime(config_path, tmp_path, api_key=False)
    configured = config_path.read_text(encoding="utf-8")
    configured = _replace_once(
        configured,
        "mode: observe",
        "mode: apply-owned-translations",
    )
    configured = _replace_once(
        configured,
        f"  signing_program: {tmp_path / 'bin' / 'gpg'}",
        "  signing_program: gpg",
    )
    config_path.write_text(
        configured,
        encoding="utf-8",
    )
    executable = tmp_path / "localize"
    executable.write_text("#!/bin/sh\n", encoding="utf-8")
    executable.chmod(0o700)
    monkeypatch.setattr(
        cli,
        "_default_launch_agents_dir",
        lambda: tmp_path / "Library" / "LaunchAgents",
    )

    exit_code = cli.main(
        ["install", "--config", str(config_path), "--executable", str(executable)]
    )

    assert exit_code == 1
    assert "runtime.signing_program" in capsys.readouterr().err


@pytest.mark.parametrize(
    ("field", "replacement", "expected_error"),
    [
        ("codex", "codex", "codex_executable"),
        ("git", "git", "git_executable"),
        ("github", "gh", "github_token_command"),
        ("model", "model-token", "codex_api_key_command"),
    ],
)
def test_install_requires_absolute_executables_for_unattended_runs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    field: str,
    replacement: str,
    expected_error: str,
) -> None:
    config_path = _init_config(tmp_path)
    capsys.readouterr()
    codex, github_helper, model_helper = _configure_scheduled_runtime(
        config_path, tmp_path
    )
    executable = tmp_path / "localize"
    executable.write_text("#!/bin/sh\n", encoding="utf-8")
    executable.chmod(0o700)
    configured = config_path.read_text(encoding="utf-8")
    absolute_value = {
        "codex": str(codex),
        "git": str(tmp_path / "bin" / "git"),
        "signing": str(tmp_path / "bin" / "gpg"),
        "github": str(github_helper),
        "model": str(model_helper),
    }[field]
    config_path.write_text(
        _replace_once(configured, absolute_value, replacement),
        encoding="utf-8",
    )
    monkeypatch.setattr(
        cli,
        "_default_launch_agents_dir",
        lambda: tmp_path / "Library" / "LaunchAgents",
    )

    exit_code = cli.main(
        ["install", "--config", str(config_path), "--executable", str(executable)]
    )

    assert exit_code == 1
    assert expected_error in capsys.readouterr().err
    paths = cli.guardian_install_paths(config_path)
    assert not paths.runner_path.exists()
    assert not paths.plist_path.exists()


def test_install_rejects_unchecked_sandbox_policy_arguments_before_staging(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    config_path = _init_config(tmp_path)
    capsys.readouterr()
    _configure_scheduled_runtime(config_path, tmp_path)
    config = _prevention_doctor_config(config_path)
    prevention = config.repositories[0].prevention
    assert prevention is not None
    object.__setattr__(
        prevention,
        "sandbox_argv_prefix",
        ("/usr/bin/sandbox-exec", "-f", "/mutable/policy.sb"),
    )
    monkeypatch.setattr(cli, "_load_config_or_raise", lambda _path: config)
    executable = tmp_path / "localize"
    executable.write_text("#!/bin/sh\n", encoding="utf-8")
    executable.chmod(0o700)

    exit_code = cli.main(
        ["install", "--config", str(config_path), "--executable", str(executable)]
    )

    assert exit_code == 1
    assert "exactly one direct wrapper" in capsys.readouterr().err
    paths = cli.guardian_install_paths(config_path)
    assert not paths.runner_path.exists()
    assert not paths.plist_path.exists()


@pytest.mark.parametrize("unsafe_kind", ["symlink", "group-writable"])
def test_install_rejects_mutable_or_redirected_scheduled_executables(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    unsafe_kind: str,
) -> None:
    config_path = _init_config(tmp_path)
    capsys.readouterr()
    codex, _github_helper, _model_helper = _configure_scheduled_runtime(
        config_path,
        tmp_path,
        api_key=False,
    )
    login_probe = Mock(return_value=True)
    monkeypatch.setattr(cli, "_codex_chatgpt_login_ready", login_probe)
    if unsafe_kind == "symlink":
        target = codex.with_name("codex-target")
        codex.rename(target)
        codex.symlink_to(target)
    else:
        codex.chmod(0o720)
    executable = tmp_path / "localize"
    executable.write_text("#!/bin/sh\n", encoding="utf-8")
    executable.chmod(0o700)
    monkeypatch.setattr(
        cli,
        "_default_launch_agents_dir",
        lambda: tmp_path / "Library" / "LaunchAgents",
    )

    exit_code = cli.main(
        ["install", "--config", str(config_path), "--executable", str(executable)]
    )

    assert exit_code == 1
    assert "runtime.codex_executable" in capsys.readouterr().err
    login_probe.assert_not_called()
    paths = cli.guardian_install_paths(config_path)
    assert not paths.runner_path.exists()
    assert not paths.plist_path.exists()


def test_install_rejects_group_writable_localize_executable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    config_path = _init_config(tmp_path)
    capsys.readouterr()
    _configure_scheduled_runtime(config_path, tmp_path)
    executable = tmp_path / "localize"
    executable.write_text("#!/bin/sh\n", encoding="utf-8")
    executable.chmod(0o720)
    monkeypatch.setattr(
        cli,
        "_default_launch_agents_dir",
        lambda: tmp_path / "Library" / "LaunchAgents",
    )

    exit_code = cli.main(
        ["install", "--config", str(config_path), "--executable", str(executable)]
    )

    assert exit_code == 1
    assert "Localize executable" in capsys.readouterr().err


@pytest.mark.parametrize("field", ["codex", "localize"])
def test_install_rejects_path_dependent_env_shebangs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    field: str,
) -> None:
    config_path = _init_config(tmp_path)
    capsys.readouterr()
    codex, _github_helper, _model_helper = _configure_scheduled_runtime(
        config_path, tmp_path
    )
    executable = tmp_path / "localize"
    executable.write_text("#!/bin/sh\n", encoding="utf-8")
    executable.chmod(0o700)
    target = codex if field == "codex" else executable
    target.write_text("#!/usr/bin/env python3\n", encoding="utf-8")
    target.chmod(0o700)
    monkeypatch.setattr(
        cli,
        "_default_launch_agents_dir",
        lambda: tmp_path / "Library" / "LaunchAgents",
    )

    exit_code = cli.main(
        ["install", "--config", str(config_path), "--executable", str(executable)]
    )

    assert exit_code == 1
    expected = "runtime.codex_executable" if field == "codex" else "Localize executable"
    assert expected in capsys.readouterr().err


def test_install_rolls_back_only_files_created_by_a_failed_attempt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    config_path = _init_config(tmp_path)
    capsys.readouterr()
    _configure_scheduled_runtime(config_path, tmp_path)
    executable = tmp_path / "localize"
    executable.write_text("#!/bin/sh\n", encoding="utf-8")
    executable.chmod(0o700)
    monkeypatch.setattr(
        cli,
        "_default_launch_agents_dir",
        lambda: tmp_path / "Library" / "LaunchAgents",
    )
    paths = cli.guardian_install_paths(config_path)
    paths.stdout_path.write_text("keep this log\n", encoding="utf-8")
    paths.stdout_path.chmod(0o600)
    original_write = cli._write_exclusive

    def fail_plist(path: Path, content: str, *, mode: int) -> tuple[int, int]:
        if path == paths.plist_path:
            raise cli.GuardianCLIError("simulated plist failure")
        return original_write(path, content, mode=mode)

    monkeypatch.setattr(cli, "_write_exclusive", fail_plist)

    exit_code = cli.main(
        ["install", "--config", str(config_path), "--executable", str(executable)]
    )

    assert exit_code == 1
    assert "simulated plist failure" in capsys.readouterr().err
    assert not paths.runner_path.exists()
    assert not paths.plist_path.exists()
    assert paths.stdout_path.read_text(encoding="utf-8") == "keep this log\n"
    assert not paths.stderr_path.exists()


def test_install_refuses_a_symlinked_launch_agents_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    config_path = _init_config(tmp_path)
    capsys.readouterr()
    _configure_scheduled_runtime(config_path, tmp_path)
    executable = tmp_path / "localize"
    executable.write_text("#!/bin/sh\n", encoding="utf-8")
    executable.chmod(0o700)
    library = tmp_path / "Library"
    library.mkdir()
    target = tmp_path / "redirected-launch-agents"
    target.mkdir()
    launch_agents = library / "LaunchAgents"
    launch_agents.symlink_to(target, target_is_directory=True)
    monkeypatch.setattr(cli, "_default_launch_agents_dir", lambda: launch_agents)

    exit_code = cli.main(
        ["install", "--config", str(config_path), "--executable", str(executable)]
    )

    assert exit_code == 1
    assert "symlinked" in capsys.readouterr().err
    assert tuple(target.iterdir()) == ()


def test_install_refuses_a_symlinked_launch_agents_ancestor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    config_path = _init_config(tmp_path)
    capsys.readouterr()
    _configure_scheduled_runtime(config_path, tmp_path)
    executable = tmp_path / "localize"
    executable.write_text("#!/bin/sh\n", encoding="utf-8")
    executable.chmod(0o700)
    redirected = tmp_path / "redirected-library"
    redirected.mkdir()
    library = tmp_path / "Library"
    library.symlink_to(redirected, target_is_directory=True)
    monkeypatch.setattr(
        cli,
        "_default_launch_agents_dir",
        lambda: library / "LaunchAgents",
    )

    exit_code = cli.main(
        ["install", "--config", str(config_path), "--executable", str(executable)]
    )

    assert exit_code == 1
    assert "ancestor" in capsys.readouterr().err
    assert tuple(redirected.iterdir()) == ()


def test_root_cli_delegates_guardian_arguments_through_a_lazy_import(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guardian_main = Mock(return_value=7)
    original_import = root_cli.importlib.import_module

    def import_module(name: str):
        if name == "localize.guardian.cli":
            return SimpleNamespace(main=guardian_main)
        return original_import(name)

    monkeypatch.setattr(root_cli.importlib, "import_module", import_module)

    exit_code = root_cli.main(["guardian", "doctor", "--config", "/tmp/policy.yaml"])

    assert exit_code == 7
    guardian_main.assert_called_once_with(["doctor", "--config", "/tmp/policy.yaml"])


def test_root_cli_never_loads_translation_plugins_for_guardian(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guardian_main = Mock(return_value=0)
    plugin_loader = Mock()
    monkeypatch.setenv("LOCALIZE_PLUGIN_MODULES", "untrusted.translation_plugin")
    original_import = root_cli.importlib.import_module

    def import_module(name: str):
        if name == "localize.guardian.cli":
            return SimpleNamespace(main=guardian_main)
        return original_import(name)

    monkeypatch.setattr(root_cli.importlib, "import_module", import_module)
    monkeypatch.setattr(root_cli, "load_plugins", plugin_loader)

    assert root_cli.main(
        ["guardian", "status", "--config", "/tmp/policy.yaml"]
    ) == 0
    plugin_loader.assert_not_called()

    with pytest.raises(SystemExit):
        root_cli.main(
            [
                "--plugin",
                "untrusted.translation_plugin",
                "guardian",
                "status",
                "--config",
                "/tmp/policy.yaml",
            ]
        )
    plugin_loader.assert_not_called()


def test_guardian_result_schema_is_declared_as_wheel_package_data() -> None:
    import tomllib

    project_root = Path(__file__).resolve().parents[2]
    pyproject = tomllib.loads(
        (project_root / "pyproject.toml").read_text(encoding="utf-8")
    )

    assert pyproject["tool"]["setuptools"]["package-data"]["localize.guardian"] == [
        "schemas/*.json"
    ]
    schema = project_root / "localize/guardian/schemas/guardian-result.schema.json"
    assert json.loads(schema.read_text(encoding="utf-8"))["type"] == "object"
