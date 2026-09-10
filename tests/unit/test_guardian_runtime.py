"""Production assembly tests for one Localize Guardian poll."""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import threading
import time
from types import SimpleNamespace
from typing import Iterator

import httpx
import pytest

from localize.guardian.controller import PollOutcome
from localize.guardian.credentials import CredentialError
from localize.guardian.deadline import PollDeadlineExceeded
from localize.guardian.github import GitHubAuthenticationError
from localize.guardian.models import (
    AllowedHeadRepository,
    ClosedPrBackfillPolicy,
    CodexAuthMode,
    ExactRepository,
    GuardianConfig,
    GuardianLimits,
    GuardianMode,
    GuardianRuntime,
    GuardianSchedule,
    HistoricalRemediationPolicy,
    PreventionPolicy,
    PipelineConfigSnapshot,
    RepositoryPolicy,
    SigningFormat,
    TrustedActor,
)
from localize.guardian.signing import SSHSigningMaterial, SigningError
from localize.guardian.state import (
    GuardianState,
    HistoricalPullReference,
    OpenPullAuthorityReference,
)
from localize.guardian.workspace import (
    ExactRevision,
    HistoricalRevision,
    HistoricalWorkspace,
)
from localize.guardian import runtime


UTC = timezone.utc
NOW = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
_REAL_VALIDATE_RUNTIME_AUTHORITY = runtime._validate_runtime_authority


@pytest.fixture(autouse=True)
def _stub_runtime_authority_for_assembly_tests(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        runtime,
        "_validate_runtime_authority",
        lambda _config, *, scheduled: None,
    )


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.stat(follow_symlinks=False).st_mode)


def _policy() -> RepositoryPolicy:
    return RepositoryPolicy(
        base_repo="acme/widgets",
        base_repo_id=101,
        base_branch="main",
        allowed_pr_authors=(TrustedActor("translation-bot", 102, "Bot"),),
        allowed_head_owners=(TrustedActor("contributor", 103, "User"),),
        allowed_head_repositories=(AllowedHeadRepository("contributor/widgets", 104),),
        allowed_branch_globs=("localization/**",),
        allowed_path_globs=("l10n/**",),
        pipeline_config_path=".localize/config.yaml",
        source_locale="en",
        publication_actor=TrustedActor("translation-machine", 102, "User"),
        trusted_reviewers={"ru": (TrustedActor("reviewer", 105, "User"),)},
        trusted_bots={},
    )


def _prevention_policy() -> PreventionPolicy:
    return PreventionPolicy(
        target_repository=ExactRepository("guardian/pipeline", 201),
        target_base_branch="main",
        push_repository=ExactRepository("guardian/pipeline", 201),
        push_branch_prefix="guardian/prevention-",
        publication_actor=TrustedActor("translation-machine", 102, "User"),
        allowed_code_path_globs=("localize/*.py",),
        allowed_test_path_globs=("tests/**/*.py",),
        focused_test_argv=(
            ("/opt/localize-guardian/bin/pytest", "tests/unit/test_rule.py", "-q"),
        ),
        sandbox_argv_prefix=("/usr/bin/guardian-sandbox-wrapper",),
        max_changed_files=4,
        max_changed_bytes=16_384,
    )


def _config(mode: GuardianMode = GuardianMode.OBSERVE) -> GuardianConfig:
    policy = _policy()
    if mode is GuardianMode.PROPOSE_PREVENTION:
        policy = replace(policy, prevention=_prevention_policy())
    return GuardianConfig(
        repositories=(policy,),
        mode=mode,
        limits=GuardianLimits(
            run_timeout_seconds=240,
            max_attempts=2,
            daily_cost_limit_usd=5,
            model_call_reservation_usd=5,
        ),
        runtime=GuardianRuntime(
            codex_model="gpt-test",
            codex_reasoning_effort="high",
            codex_auth_mode=CodexAuthMode.API_KEY,
            codex_executable="/opt/bin/codex",
            git_executable="/opt/bin/git",
            signing_program="/opt/bin/gpg",
            github_token_command=("/opt/bin/github-token",),
            codex_api_key_command=("/opt/bin/model-token",),
            signing_key="A" * 40,
        ),
    )


def _config_with_closed_backfill(*, remediation: bool) -> GuardianConfig:
    mode = GuardianMode.PROPOSE_PREVENTION if remediation else GuardianMode.OBSERVE
    config = _config(mode)
    remediation_policy = (
        HistoricalRemediationPolicy(
            push_repository=ExactRepository("contributor/widgets", 104),
            push_branch_prefix="localization/remediation-",
            publication_actor=TrustedActor("translation-machine", 102, "User"),
        )
        if remediation
        else None
    )
    policy = replace(
        config.repositories[0],
        allowed_branch_globs=(
            ("localization/**", "localization/remediation-*")
            if remediation
            else config.repositories[0].allowed_branch_globs
        ),
        closed_pr_backfill=ClosedPrBackfillPolicy(
            lookback_days=120,
            max_prs_per_poll=4,
            remediation=remediation_policy,
        ),
    )
    limits = replace(
        config.limits,
        max_remediation_drafts_per_run=1 if remediation else 0,
    )
    return replace(config, repositories=(policy,), limits=limits)


def _write_minimal_config(path: Path) -> None:
    path.write_text(
        """mode: observe
repositories:
  - base_repo: acme/widgets
    base_repo_id: 101
    base_branch: main
    publication_actor: {login: translation-machine, id: 102, type: User}
    allowed_pr_authors:
      - {login: translation-bot, id: 102, type: Bot}
    allowed_head_owners:
      - {login: contributor, id: 103, type: User}
    allowed_head_repositories:
      - {full_name: contributor/widgets, id: 104}
    allowed_branch_globs: [localization/**]
    allowed_path_globs: [l10n/**]
    pipeline_config_path: .localize/config.yaml
    source_locale: en
    trusted_reviewers:
      ru:
        - {login: reviewer, id: 105, type: User}
    trusted_bots: {}
""",
        encoding="utf-8",
    )
    path.chmod(0o600)


def test_subscription_codex_home_must_be_private_file_backed_and_non_symlinked(
    tmp_path: Path,
) -> None:
    codex_home = tmp_path / "codex-home"
    codex_home.mkdir(mode=0o700)
    auth_file = codex_home / "auth.json"
    auth_file.write_text('{"tokens":"redacted-test-value"}', encoding="utf-8")
    auth_file.chmod(0o600)
    config = replace(
        _config(),
        runtime=replace(
            _config().runtime,
            codex_auth_mode=CodexAuthMode.CHATGPT,
            codex_home=str(codex_home),
            codex_api_key_command=(),
        ),
    )

    assert runtime._validate_subscription_codex_home(config) == codex_home

    auth_file.chmod(0o644)
    with pytest.raises(runtime.GuardianRuntimeError, match="authentication"):
        runtime._validate_subscription_codex_home(config)

    auth_file.chmod(0o600)
    linked_home = tmp_path / "linked-home"
    linked_home.symlink_to(codex_home, target_is_directory=True)
    linked_config = replace(
        config,
        runtime=replace(config.runtime, codex_home=str(linked_home)),
    )
    with pytest.raises(runtime.GuardianRuntimeError, match="authentication"):
        runtime._validate_subscription_codex_home(linked_config)


def test_scheduled_executable_authority_is_rechecked_at_runtime(tmp_path: Path) -> None:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(mode=0o700)
    commands: list[str] = []
    for name in ("codex", "git", "gpg", "github-token", "model-token"):
        executable = bin_dir / name
        executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        executable.chmod(0o700)
        commands.append(str(executable))
    config = replace(
        _config(),
        runtime=replace(
            _config().runtime,
            codex_executable=commands[0],
            git_executable=commands[1],
            signing_program=commands[2],
            github_token_command=(commands[3],),
            codex_api_key_command=(commands[4],),
        ),
    )

    runtime._validate_scheduled_executables(config)

    Path(commands[0]).chmod(0o722)
    with pytest.raises(runtime.GuardianRuntimeError, match="executable authority"):
        runtime._validate_scheduled_executables(config)


def test_scheduled_authority_uses_direct_helper_and_sandbox_contracts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _config(GuardianMode.PROPOSE_PREVENTION)
    ordinary_fields: list[str] = []
    direct_fields: list[str] = []
    wrapper_fields: list[str] = []
    monkeypatch.setattr(
        runtime,
        "require_absolute_trusted_executable",
        lambda _command, *, field: ordinary_fields.append(field),
    )
    monkeypatch.setattr(
        runtime,
        "require_absolute_trusted_direct_executable",
        lambda _command, *, field, **_kwargs: direct_fields.append(field),
    )
    monkeypatch.setattr(
        runtime,
        "require_absolute_trusted_wrapper",
        lambda _command, *, field: wrapper_fields.append(field),
    )

    runtime._validate_scheduled_executables(config)

    assert direct_fields == [
        "runtime.github_token_command",
        "runtime.codex_api_key_command",
    ]
    assert wrapper_fields == [
        "repositories.0.prevention.sandbox_argv_prefix",
    ]
    assert "repositories.0.prevention.focused_test_argv" in ordinary_fields


def test_scheduled_signing_program_is_required_only_for_write_modes(
    tmp_path: Path,
) -> None:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(mode=0o700)
    commands: dict[str, str] = {}
    for name in ("codex", "git", "github-token", "model-token"):
        executable = bin_dir / name
        executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        executable.chmod(0o700)
        commands[name] = str(executable)
    config = replace(
        _config(),
        runtime=replace(
            _config().runtime,
            codex_executable=commands["codex"],
            git_executable=commands["git"],
            signing_program="gpg",
            github_token_command=(commands["github-token"],),
            codex_api_key_command=(commands["model-token"],),
        ),
    )

    runtime._validate_scheduled_executables(config)

    write_config = replace(config, mode=GuardianMode.APPLY_OWNED_TRANSLATIONS)
    with pytest.raises(runtime.GuardianRuntimeError, match="executable authority"):
        runtime._validate_scheduled_executables(write_config)


def test_manual_ssh_write_requires_a_trusted_absolute_signing_program(
    tmp_path: Path,
) -> None:
    signing_program = shutil.which("ssh-keygen")
    if signing_program is None:
        pytest.skip("OpenSSH ssh-keygen is unavailable")
    ssh_runtime = replace(
        _config().runtime,
        signing_format=SigningFormat.SSH,
        signing_program=str(Path(signing_program).resolve()),
        signing_key="SHA256:" + "A" * 43,
        signing_public_key="/keys/guardian.pub",
    )
    config = replace(
        _config(GuardianMode.APPLY_OWNED_TRANSLATIONS),
        runtime=ssh_runtime,
    )

    _REAL_VALIDATE_RUNTIME_AUTHORITY(config, scheduled=False)

    unsafe_program = tmp_path / "ssh-keygen"
    unsafe_program.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    unsafe_program.chmod(0o722)
    config = replace(
        config,
        runtime=replace(ssh_runtime, signing_program=str(unsafe_program)),
    )
    with pytest.raises(runtime.GuardianRuntimeError, match="SSH signing authority"):
        _REAL_VALIDATE_RUNTIME_AUTHORITY(config, scheduled=False)


def test_ssh_signing_snapshot_is_exact_private_and_redacts_failures(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fingerprint = "SHA256:" + "A" * 43
    public_key_path = "/keys/guardian.pub"
    material = SSHSigningMaterial(
        root=tmp_path,
        public_key=tmp_path / "signing-key.pub",
        allowed_signers=tmp_path / "allowed-signers",
        fingerprint=fingerprint,
    )
    config = replace(
        _config(GuardianMode.APPLY_OWNED_TRANSLATIONS),
        runtime=replace(
            _config().runtime,
            signing_format=SigningFormat.SSH,
            signing_program="/usr/bin/ssh-keygen",
            signing_key=fingerprint,
            signing_public_key=public_key_path,
        ),
    )
    captured: dict[str, object] = {}

    @contextmanager
    def fake_snapshot(**kwargs: object) -> Iterator[SSHSigningMaterial]:
        captured.update(kwargs)
        yield material

    monkeypatch.setattr(runtime, "snapshot_ssh_signing_material", fake_snapshot)
    with runtime._snapshot_poll_signing_material(
        config=config,
        state_directory=tmp_path,
    ) as selected:
        assert selected is material
    assert captured == {
        "public_key_path": public_key_path,
        "expected_fingerprint": fingerprint,
        "signing_program": "/usr/bin/ssh-keygen",
        "temporary_root": tmp_path,
    }

    @contextmanager
    def failing_snapshot(**_kwargs: object) -> Iterator[SSHSigningMaterial]:
        raise SigningError("secret path and agent diagnostic")
        yield material

    monkeypatch.setattr(runtime, "snapshot_ssh_signing_material", failing_snapshot)
    with pytest.raises(runtime.GuardianRuntimeError, match="unavailable") as failure:
        with runtime._snapshot_poll_signing_material(
            config=config,
            state_directory=tmp_path,
        ):
            pytest.fail("unsafe signing material must not be yielded")
    assert "secret" not in str(failure.value)
    assert failure.value.__cause__ is None


class _Credential:
    def __init__(self, secret: str) -> None:
        self.secret = secret
        self.calls = 0

    def read(self) -> str:
        self.calls += 1
        return self.secret


def test_authenticated_snapshot_provider_uses_reader_and_passes_all_previous_feedback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    credential = _Credential("github-secret")
    previous = (
        SimpleNamespace(source_id="11"),
        SimpleNamespace(source_id="12"),
    )
    observed: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        observed["authorization"] = request.headers.get("Authorization")
        return httpx.Response(200, json={"ok": True})

    transport = httpx.MockTransport(handler)

    class FakeReader:
        def __init__(self, client: httpx.Client, policy: object) -> None:
            observed["policy"] = policy
            observed["response"] = client.get("/probe").json()

        def collect_open_pull_requests(
            self, *, previous_feedback: object
        ) -> tuple[str]:
            observed["previous"] = previous_feedback
            return ("snapshot",)

    monkeypatch.setattr(runtime, "GitHubReader", FakeReader)
    provider = runtime.AuthenticatedGitHubSnapshotProvider(
        credential=credential,  # type: ignore[arg-type]
        transport=transport,
    )

    result = provider(_policy(), previous)  # type: ignore[arg-type]

    assert result == ("snapshot",)
    assert credential.calls == 1
    assert observed["authorization"] == "Bearer github-secret"
    assert observed["previous"] is previous
    assert observed["response"] == {"ok": True}
    assert observed["policy"].repository == "acme/widgets"  # type: ignore[union-attr]


def test_authenticated_snapshot_provider_loads_prior_feedback_only_per_hydrated_pull(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    credential = _Credential("github-secret")
    loaded: list[tuple[str, int]] = []
    old = SimpleNamespace(source_id="12")
    observed: dict[str, object] = {}

    class FakeReader:
        def __init__(self, _client: httpx.Client, _policy: object) -> None:
            pass

        def collect_open_pull_requests(self, **kwargs: object) -> tuple[str]:
            observed.update(kwargs)
            provider = kwargs["previous_feedback_for_pull"]
            assert callable(provider)
            assert provider(12) == (old,)
            return ("snapshot",)

    def previous_feedback(repository: str, pull_number: int) -> tuple[object, ...]:
        loaded.append((repository, pull_number))
        return (old,)

    monkeypatch.setattr(runtime, "GitHubReader", FakeReader)
    provider = runtime.AuthenticatedGitHubSnapshotProvider(
        credential=credential,  # type: ignore[arg-type]
        transport=httpx.MockTransport(lambda request: httpx.Response(200)),
        previous_feedback_provider=previous_feedback,  # type: ignore[arg-type]
    )

    assert provider(_policy(), ()) == ("snapshot",)
    assert provider.loads_previous_feedback_per_pull is True
    assert loaded == [("acme/widgets", 12)]
    assert "previous_feedback" not in observed


def test_authenticated_snapshot_provider_preflights_one_exact_publication_actor() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/user"
        return httpx.Response(
            200,
            json={"login": "translation-machine", "id": 102, "type": "User"},
        )

    provider = runtime.AuthenticatedGitHubSnapshotProvider(
        credential=_Credential("github-secret"),  # type: ignore[arg-type]
        transport=httpx.MockTransport(handler),
    )
    expected = TrustedActor("old-display-name", 102, "User")

    provider.require_publication_actor(_policy(), (expected, expected))

    with pytest.raises(GitHubAuthenticationError, match="does not match"):
        provider.require_publication_actor(
            _policy(),
            (TrustedActor("someone-else", 999, "User"),),
        )


def test_authenticated_snapshot_provider_rejects_bot_publisher_before_network() -> None:
    requests = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal requests
        requests += 1
        return httpx.Response(500)

    provider = runtime.AuthenticatedGitHubSnapshotProvider(
        credential=_Credential("github-secret"),  # type: ignore[arg-type]
        transport=httpx.MockTransport(handler),
    )

    with pytest.raises(GitHubAuthenticationError, match="must be a User"):
        provider.require_publication_actor(
            _policy(),
            (TrustedActor("installation-app[bot]", 102, "Bot"),),
        )

    assert requests == 0


def test_authenticated_snapshot_provider_classifies_credential_failure() -> None:
    class FailingCredential:
        def read(self) -> str:
            raise CredentialError("secret-bearing helper diagnostic")

    provider = runtime.AuthenticatedGitHubSnapshotProvider(
        credential=FailingCredential(),  # type: ignore[arg-type]
    )

    with pytest.raises(GitHubAuthenticationError) as raised:
        provider(_policy(), ())

    assert "secret-bearing" not in str(raised.value)


def test_authenticated_snapshot_provider_uses_ephemeral_reads_for_history(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    credential = _Credential("history-read-secret")
    clients: list[httpx.Client] = []
    captured: dict[str, object] = {}
    previous = (SimpleNamespace(source_id="11"),)

    cutoff = datetime(2026, 1, 1, tzinfo=UTC)
    upper_bound = datetime(2026, 2, 1, tzinfo=UTC)

    def handler(request: httpx.Request) -> httpx.Response:
        captured.setdefault("authorizations", []).append(
            request.headers.get("Authorization")
        )
        return httpx.Response(200, json={"ok": True})

    class FakeReader:
        def __init__(self, client: httpx.Client, policy: object) -> None:
            clients.append(client)
            captured["policy"] = policy

        def collect_closed_pull_requests(self, **kwargs: object) -> tuple[str]:
            captured["closed_kwargs"] = kwargs
            captured["closed_probe"] = clients[-1].get("/closed-probe").json()
            return ("historical",)

        def capture_base_revision(self) -> str:
            captured["base_probe"] = clients[-1].get("/base-probe").json()
            return "current-base"

        def collect_exact_closed_pulls(
            self,
            expected_pulls: tuple[tuple[int, int], ...],
        ) -> tuple[str]:
            captured["exact_pulls"] = expected_pulls
            captured["exact_probe"] = clients[-1].get("/exact-probe").json()
            return ("exact-history",)

        def collect_exact_open_pull(
            self,
            expected_pull: tuple[int, int],
        ) -> str:
            captured["exact_open_pull"] = expected_pull
            captured["exact_open_probe"] = clients[-1].get(
                "/exact-open-probe"
            ).json()
            return "exact-open"

    monkeypatch.setattr(runtime, "GitHubReader", FakeReader)
    provider = runtime.AuthenticatedGitHubSnapshotProvider(
        credential=credential,  # type: ignore[arg-type]
        transport=httpx.MockTransport(handler),
    )

    historical = provider.collect_closed_pull_requests(
        _policy(),
        previous,
        cutoff=cutoff,
        upper_bound=upper_bound,
        max_prs_per_poll=4,
        seen_pulls=((12, 120),),
        excluded_pulls=((14, 140),),
        priority_pull_groups=(((13, 130),),),
    )
    current_base = provider.capture_base_revision(_policy())
    source = HistoricalPullReference(
        repository="acme/widgets",
        repository_id=101,
        pull_id=500,
        pr_number=12,
        pull_revision_digest="1" * 64,
        authority_digest="2" * 64,
        policy_digest="3" * 64,
        head_sha="4" * 40,
        base_sha="5" * 40,
    )
    exact = provider.revalidate_closed_pull_requests(_policy(), (source,))
    open_source = OpenPullAuthorityReference(
        repository="acme/widgets",
        repository_id=101,
        pull_id=500,
        pr_number=12,
        authority_digest="6" * 64,
        head_sha="4" * 40,
        base_sha="5" * 40,
    )
    exact_open = provider.revalidate_open_pull_request(_policy(), open_source)

    assert historical == ("historical",)
    assert current_base == "current-base"
    assert exact == ("exact-history",)
    assert exact_open == "exact-open"
    assert captured["exact_pulls"] == ((500, 12),)
    assert captured["exact_open_pull"] == (500, 12)
    assert captured["closed_kwargs"] == {
        "cutoff": cutoff,
        "upper_bound": upper_bound,
        "max_prs_per_poll": 4,
        "seen_pulls": ((12, 120),),
        "excluded_pulls": ((14, 140),),
        "priority_pull_groups": (((13, 130),),),
        "previous_feedback": previous,
    }
    assert captured["closed_probe"] == {"ok": True}
    assert captured["base_probe"] == {"ok": True}
    assert captured["exact_probe"] == {"ok": True}
    assert captured["exact_open_probe"] == {"ok": True}
    assert captured["authorizations"] == [
        "Bearer history-read-secret",
        "Bearer history-read-secret",
        "Bearer history-read-secret",
        "Bearer history-read-secret",
    ]
    assert credential.calls == 4
    assert len(clients) == 4
    assert all(client.is_closed for client in clients)
    assert all("Authorization" not in client.headers for client in clients)
    assert "history-read-secret" not in repr(provider)


@pytest.mark.parametrize("operation", ["closed", "exact", "base"])
def test_historical_read_adapters_redact_credential_failure(
    operation: str,
) -> None:
    class FailingCredential:
        def read(self) -> str:
            raise CredentialError("historical-secret-bearing diagnostic")

    provider = runtime.AuthenticatedGitHubSnapshotProvider(
        credential=FailingCredential(),  # type: ignore[arg-type]
    )

    with pytest.raises(GitHubAuthenticationError) as raised:
        if operation == "closed":
            provider.collect_closed_pull_requests(
                _policy(),
                (),
                cutoff=datetime(2026, 1, 1, tzinfo=UTC),
                upper_bound=datetime(2026, 2, 1, tzinfo=UTC),
                max_prs_per_poll=1,
                seen_pulls=(),
                excluded_pulls=(),
                priority_pull_groups=(),
            )
        elif operation == "exact":
            provider.revalidate_closed_pull_requests(
                _policy(),
                (
                    HistoricalPullReference(
                        repository="acme/widgets",
                        repository_id=101,
                        pull_id=500,
                        pr_number=12,
                        pull_revision_digest="1" * 64,
                        authority_digest="2" * 64,
                        policy_digest="3" * 64,
                        head_sha="4" * 40,
                        base_sha="5" * 40,
                    ),
                ),
            )
        else:
            provider.capture_base_revision(_policy())

    assert "historical-secret-bearing" not in str(raised.value)


def test_build_controller_wires_exact_runtime_policy_and_credentials(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Check runtime wiring for policy, checkout authority, and scoped credentials."""
    config = _config()
    captured: dict[str, object] = {}

    def git_environment() -> dict[str, str]:
        """Yield the isolated Git credential environment used by the runtime fixture."""
        return {"GIT_ASKPASS": "/private/helper"}

    github_credential = SimpleNamespace(argv=config.runtime.github_token_command)
    model_credential = SimpleNamespace(argv=config.runtime.codex_api_key_command)

    class FakeCodexDriver:
        def __init__(self, **kwargs: object) -> None:
            """Record injected test dependencies without accessing external services."""
            captured["codex"] = kwargs
            self.model = str(kwargs["model"])

    class FakeController:
        def __init__(self, **kwargs: object) -> None:
            """Record injected test dependencies without accessing external services."""
            captured["controller"] = kwargs

    monkeypatch.setattr(runtime, "CodexDriver", FakeCodexDriver)
    monkeypatch.setattr(runtime, "GuardianController", FakeController)
    monkeypatch.setattr(
        runtime,
        "AuthenticatedGitHubSnapshotProvider",
        lambda **kwargs: captured.setdefault("snapshot", kwargs) or object(),
    )

    def resolve_model_key(helper: object) -> str:
        """Resolve the test model key through the injected credential provider."""
        captured["model_helper"] = helper
        return "model-secret"

    monkeypatch.setattr(runtime, "resolve_model_api_key", resolve_model_key)

    controller = runtime._build_controller(
        config=config,
        state=SimpleNamespace(),  # type: ignore[arg-type]
        state_directory=tmp_path,
        github_credential=github_credential,  # type: ignore[arg-type]
        model_credential=model_credential,  # type: ignore[arg-type]
        git_environment=git_environment,
    )

    assert isinstance(controller, FakeController)
    assert captured["codex"] == {
        "model": "gpt-test",
        "reasoning_effort": "high",
        "auth_mode": CodexAuthMode.API_KEY,
        "codex_home": "~/.local/share/localize-guardian/codex",
        "executable": "/opt/bin/codex",
        "timeout_seconds": 120.0,
        "max_attempts": 2,
    }
    controller_kwargs = captured["controller"]
    assert controller_kwargs["snapshot_provider"] is captured["snapshot"]
    assert controller_kwargs["write_broker_factory"] is None
    assert controller_kwargs["prevention_runner"] is None
    assert controller_kwargs["historical_snapshot_provider"] is None
    assert controller_kwargs["historical_checkout_factory"] is None
    assert controller_kwargs["current_base_provider"] is None
    assert controller_kwargs["remediation_runner"] is None
    assert controller_kwargs["publish_credential_environment"] is git_environment
    assert controller_kwargs["evidence_root"] == tmp_path / "evidence"
    assert controller_kwargs["github_host"] == "github.com"
    assert controller_kwargs["signing_key"] == "A" * 40

    assert controller_kwargs["model_credential_provider"]() == "model-secret"
    assert captured["model_helper"] is model_credential

    revision = ExactRevision(
        host="github.com",
        owner="acme",
        repository="widgets",
        ref="refs/heads/main",
        sha="a" * 40,
    )
    sentinel = object()
    materialize = pytest.MonkeyPatch()
    try:
        materialize.setattr(
            runtime,
            "materialize_exact_checkout",
            lambda incoming, **kwargs: (
                captured.update(checkout_revision=incoming, checkout_kwargs=kwargs)
                or sentinel
            ),
        )
        assert controller_kwargs["checkout_factory"](revision) is sentinel
    finally:
        materialize.undo()
    assert captured["checkout_revision"] == revision
    assert captured["checkout_kwargs"] == {
        "credential_environment": git_environment,
        "git_binary": "/opt/bin/git",
        "signing_program": "/opt/bin/gpg",
        "timeout_seconds": 120.0,
    }
    # Read-only PR bases need snapshot materialization even with backfill off.
    historical = HistoricalRevision(
        host="github.com", owner="acme", repository="widgets", sha="b" * 40
    )
    monkeypatch.setattr(
        runtime,
        "materialize_historical_checkout",
        lambda incoming, **kwargs: (
            captured.update(readonly_revision=incoming, readonly_kwargs=kwargs)
            or sentinel
        ),
    )
    assert controller_kwargs["checkout_factory"](historical) is sentinel
    assert captured["readonly_revision"] == historical
    assert captured["readonly_kwargs"] == {
        "credential_environment": git_environment,
        "git_binary": "/opt/bin/git",
        "timeout_seconds": 120.0,
    }


@pytest.mark.parametrize("mode", [GuardianMode.OBSERVE, GuardianMode.PREPARE])
def test_closed_backfill_wires_read_only_historical_dependencies(
    mode: GuardianMode,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = replace(_config_with_closed_backfill(remediation=False), mode=mode)
    captured: dict[str, object] = {}

    class FakeProvider:
        def __call__(self, *_args: object, **_kwargs: object) -> tuple[()]:
            return ()

        def collect_closed_pull_requests(
            self,
            *_args: object,
            **_kwargs: object,
        ) -> tuple[()]:
            return ()

        def capture_base_revision(self, incoming: RepositoryPolicy) -> str:
            captured["base_policy"] = incoming
            return "current-base"

    provider = FakeProvider()
    monkeypatch.setattr(
        runtime, "CodexDriver", lambda **_kwargs: SimpleNamespace(model="x")
    )
    monkeypatch.setattr(runtime, "GuardianController", lambda **kwargs: kwargs)
    monkeypatch.setattr(
        runtime,
        "AuthenticatedGitHubSnapshotProvider",
        lambda **_kwargs: provider,
    )

    @contextmanager
    def materialize(
        revision: HistoricalRevision,
        **kwargs: object,
    ) -> Iterator[HistoricalWorkspace]:
        captured["revision"] = revision
        captured["kwargs"] = kwargs
        yield HistoricalWorkspace(path=tmp_path, revision=revision)

    monkeypatch.setattr(runtime, "materialize_historical_checkout", materialize)

    def git_environment() -> dict[str, str]:
        return {"GIT_ASKPASS": "/private/read-helper"}

    controller = runtime._build_controller(
        config=config,
        state=SimpleNamespace(),  # type: ignore[arg-type]
        state_directory=tmp_path,
        github_credential=SimpleNamespace(argv=config.runtime.github_token_command),  # type: ignore[arg-type]
        model_credential=None,
        git_environment=git_environment,
    )

    assert controller["historical_snapshot_provider"].__self__ is provider
    assert controller["historical_checkout_factory"] is not None
    assert controller["current_base_provider"].__self__ is provider
    assert controller["remediation_runner"] is None
    assert controller["current_base_provider"](config.repositories[0]) == "current-base"
    assert captured["base_policy"] is config.repositories[0]
    revision = HistoricalRevision(
        host="github.com",
        owner="acme",
        repository="widgets",
        sha="a" * 40,
        pull_number=12,
    )
    with controller["historical_checkout_factory"](revision) as workspace:
        assert isinstance(workspace, HistoricalWorkspace)
        assert not hasattr(workspace, "commit_validated_changes")
        assert not hasattr(workspace, "publish_commit")
    assert captured["revision"] is revision
    assert captured["kwargs"] == {
        "credential_environment": git_environment,
        "git_binary": "/opt/bin/git",
        "timeout_seconds": 120.0,
    }


def test_historical_prevention_wires_exact_source_revalidation_without_remediation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    base = _config_with_closed_backfill(remediation=False)
    policy = replace(base.repositories[0], prevention=_prevention_policy())
    config = replace(
        base,
        mode=GuardianMode.PROPOSE_PREVENTION,
        repositories=(policy,),
    )

    class FakeProvider:
        def __call__(self, *_args: object, **_kwargs: object) -> tuple[()]:
            return ()

        def collect_closed_pull_requests(
            self,
            *_args: object,
            **_kwargs: object,
        ) -> tuple[()]:
            return ()

        def capture_base_revision(self, _policy: RepositoryPolicy) -> str:
            return "current-base"

        def revalidate_closed_pull_requests(
            self,
            _policy: RepositoryPolicy,
            _sources: tuple[HistoricalPullReference, ...],
        ) -> tuple[()]:
            return ()

    provider = FakeProvider()
    monkeypatch.setattr(
        runtime, "CodexDriver", lambda **_kwargs: SimpleNamespace(model="x")
    )
    monkeypatch.setattr(runtime, "GuardianController", lambda **kwargs: kwargs)
    monkeypatch.setattr(
        runtime,
        "AuthenticatedGitHubSnapshotProvider",
        lambda **_kwargs: provider,
    )
    monkeypatch.setattr(runtime, "PreventionCodexAuthor", lambda **_kwargs: object())
    monkeypatch.setattr(runtime, "SandboxedTestRunner", lambda **_kwargs: object())
    monkeypatch.setattr(runtime, "PreventionCoordinator", lambda **_kwargs: object())

    controller = runtime._build_controller(
        config=config,
        state=SimpleNamespace(),  # type: ignore[arg-type]
        state_directory=tmp_path,
        github_credential=SimpleNamespace(argv=config.runtime.github_token_command),  # type: ignore[arg-type]
        model_credential=None,
        git_environment=lambda: {},
    )

    assert controller["remediation_runner"] is None
    assert (
        controller["historical_source_snapshot_provider"]
        == provider.revalidate_closed_pull_requests
    )


def test_explicit_closed_remediation_wires_separate_broker_and_coordinator(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _config_with_closed_backfill(remediation=True)
    policy = config.repositories[0]
    state = SimpleNamespace()
    captured: dict[str, object] = {}

    class FakeProvider:
        def __call__(self, *_args: object, **_kwargs: object) -> tuple[()]:
            return ()

        def collect_closed_pull_requests(
            self,
            *_args: object,
            **_kwargs: object,
        ) -> tuple[()]:
            return ()

        def capture_base_revision(self, incoming: RepositoryPolicy) -> str:
            captured["base_policy"] = incoming
            return "base"

        def revalidate_closed_pull_requests(
            self,
            incoming: RepositoryPolicy,
            sources: tuple[HistoricalPullReference, ...],
        ) -> tuple[()]:
            captured["source_policy"] = incoming
            captured["source_pulls"] = sources
            return ()

    provider = FakeProvider()
    monkeypatch.setattr(
        runtime, "CodexDriver", lambda **_kwargs: SimpleNamespace(model="x")
    )
    monkeypatch.setattr(runtime, "GuardianController", lambda **kwargs: kwargs)
    monkeypatch.setattr(
        runtime,
        "AuthenticatedGitHubSnapshotProvider",
        lambda **_kwargs: provider,
    )
    monkeypatch.setattr(runtime, "PreventionCodexAuthor", lambda **_kwargs: object())
    monkeypatch.setattr(runtime, "SandboxedTestRunner", lambda **_kwargs: object())
    monkeypatch.setattr(runtime, "PreventionCoordinator", lambda **_kwargs: object())

    remediation_runner = object()

    def remediation_coordinator(**kwargs: object) -> object:
        captured["remediation_coordinator"] = kwargs
        return remediation_runner

    monkeypatch.setattr(runtime, "RemediationCoordinator", remediation_coordinator)
    monkeypatch.setattr(
        runtime,
        "RemediationGitHubBroker",
        lambda **kwargs: captured.setdefault("remediation_broker", kwargs) or object(),
    )

    def git_environment() -> dict[str, str]:
        return {"GIT_ASKPASS": "/private/write-helper"}

    github_credential = SimpleNamespace(argv=config.runtime.github_token_command)
    controller = runtime._build_controller(
        config=config,
        state=state,  # type: ignore[arg-type]
        state_directory=tmp_path,
        github_credential=github_credential,  # type: ignore[arg-type]
        model_credential=None,
        git_environment=git_environment,
    )

    assert controller["historical_snapshot_provider"].__self__ is provider
    assert controller["historical_checkout_factory"] is not None
    assert controller["current_base_provider"].__self__ is provider
    assert controller["remediation_runner"] is remediation_runner
    assert (
        controller["historical_source_snapshot_provider"]
        == provider.revalidate_closed_pull_requests
    )
    assert controller["current_base_provider"](policy) == "base"
    assert captured["base_policy"] is policy
    coordinator_kwargs = captured["remediation_coordinator"]
    assert coordinator_kwargs == {
        "state": state,
        "broker_factory": coordinator_kwargs["broker_factory"],
        "publish_credential_environment": git_environment,
        "signing_key": "A" * 40,
        "signing_environment": None,
        "max_drafts": 1,
    }
    broker = coordinator_kwargs["broker_factory"](policy)
    assert broker is captured["remediation_broker"]
    assert captured["remediation_broker"] == {
        "policy": policy,
        "create_as_draft": False,
        "credential": github_credential,
        "github_host": "github.com",
        "base_url": "https://api.github.com",
        "timeout_seconds": 30.0,
    }
    assert "github_credential" not in controller


def test_zero_remediation_draft_limit_does_not_construct_write_adapter(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _config_with_closed_backfill(remediation=True)
    config = replace(
        config,
        limits=replace(config.limits, max_remediation_drafts_per_run=0),
    )
    monkeypatch.setattr(
        runtime, "CodexDriver", lambda **_kwargs: SimpleNamespace(model="x")
    )
    monkeypatch.setattr(runtime, "GuardianController", lambda **kwargs: kwargs)
    monkeypatch.setattr(runtime, "PreventionCodexAuthor", lambda **_kwargs: object())
    monkeypatch.setattr(runtime, "SandboxedTestRunner", lambda **_kwargs: object())
    monkeypatch.setattr(runtime, "PreventionCoordinator", lambda **_kwargs: object())
    monkeypatch.setattr(
        runtime,
        "RemediationCoordinator",
        lambda **_kwargs: pytest.fail(
            "a zero publication cap must not construct remediation authority"
        ),
    )
    monkeypatch.setattr(
        runtime,
        "RemediationGitHubBroker",
        lambda **_kwargs: pytest.fail(
            "a zero publication cap must not construct a remediation broker"
        ),
    )

    controller = runtime._build_controller(
        config=config,
        state=SimpleNamespace(),  # type: ignore[arg-type]
        state_directory=tmp_path,
        github_credential=SimpleNamespace(argv=config.runtime.github_token_command),  # type: ignore[arg-type]
        model_credential=None,
        git_environment=lambda: {},
    )

    assert controller["historical_snapshot_provider"] is not None
    assert controller["current_base_provider"] is not None
    assert controller["remediation_runner"] is None


def test_closed_backfill_keeps_subscription_codex_authentication_unchanged(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _config_with_closed_backfill(remediation=False)
    config = replace(
        config,
        runtime=replace(
            config.runtime,
            codex_auth_mode=CodexAuthMode.CHATGPT,
            codex_api_key_command=(),
        ),
    )
    monkeypatch.setattr(
        runtime, "CodexDriver", lambda **_kwargs: SimpleNamespace(model="x")
    )
    monkeypatch.setattr(runtime, "GuardianController", lambda **kwargs: kwargs)
    monkeypatch.setattr(
        runtime,
        "resolve_model_api_key",
        lambda _helper: pytest.fail("subscription mode must not resolve an API key"),
    )

    controller = runtime._build_controller(
        config=config,
        state=SimpleNamespace(),  # type: ignore[arg-type]
        state_directory=tmp_path,
        github_credential=SimpleNamespace(argv=config.runtime.github_token_command),  # type: ignore[arg-type]
        model_credential=None,
        git_environment=lambda: {},
    )

    assert controller["model_credential_provider"]() is None


def test_runtime_keeps_remediation_dormant_without_write_capable_mode(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = replace(
        _config_with_closed_backfill(remediation=True),
        mode=GuardianMode.OBSERVE,
    )
    monkeypatch.setattr(
        runtime, "CodexDriver", lambda **_kwargs: SimpleNamespace(model="x")
    )
    monkeypatch.setattr(runtime, "GuardianController", lambda **kwargs: kwargs)

    monkeypatch.setattr(runtime, "RemediationGitHubBroker", lambda **_kwargs: pytest.fail("dormant config must not create a broker"))
    monkeypatch.setattr(runtime, "RemediationCoordinator", lambda **_kwargs: pytest.fail("dormant config must not create a coordinator"))

    controller = runtime._build_controller(
        config=config,
        state=SimpleNamespace(),  # type: ignore[arg-type]
        state_directory=tmp_path,
        github_credential=SimpleNamespace(argv=config.runtime.github_token_command),  # type: ignore[arg-type]
        model_credential=None,
        git_environment=lambda: {},
    )

    assert controller["remediation_runner"] is None


def test_runtime_allows_remediation_in_apply_mode_without_prevention(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _config_with_closed_backfill(remediation=True)
    policy = replace(config.repositories[0], prevention=None)
    config = replace(
        config,
        mode=GuardianMode.APPLY_OWNED_TRANSLATIONS,
        repositories=(policy,),
    )
    monkeypatch.setattr(
        runtime, "CodexDriver", lambda **_kwargs: SimpleNamespace(model="x")
    )
    monkeypatch.setattr(runtime, "GuardianController", lambda **kwargs: kwargs)
    monkeypatch.setattr(runtime, "RemediationGitHubBroker", lambda **_kwargs: object())
    monkeypatch.setattr(runtime, "RemediationCoordinator", lambda **_kwargs: object())

    controller = runtime._build_controller(
        config=config,
        state=SimpleNamespace(),  # type: ignore[arg-type]
        state_directory=tmp_path,
        github_credential=SimpleNamespace(argv=config.runtime.github_token_command),  # type: ignore[arg-type]
        model_credential=None,
        git_environment=lambda: {},
    )

    assert controller["prevention_runner"] is None
    assert controller["remediation_runner"] is not None


def test_typed_limits_reject_invalid_direct_remediation_limit() -> None:
    config = _config()

    with pytest.raises(ValueError, match="max_remediation_drafts_per_run"):
        replace(
            config.limits,
            max_remediation_drafts_per_run=-1,
        )


def test_build_controller_wires_exact_ssh_snapshot_into_every_write_checkout(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fingerprint = "SHA256:" + "A" * 43
    config = replace(
        _config(GuardianMode.APPLY_OWNED_TRANSLATIONS),
        runtime=replace(
            _config().runtime,
            signing_format=SigningFormat.SSH,
            signing_program="/usr/bin/ssh-keygen",
            signing_key=fingerprint,
            signing_public_key="/keys/guardian.pub",
        ),
    )
    material = SSHSigningMaterial(
        root=tmp_path,
        public_key=tmp_path / "signing-key.pub",
        allowed_signers=tmp_path / "allowed-signers",
        fingerprint=fingerprint,
    )
    captured: dict[str, object] = {}
    monkeypatch.setattr(
        runtime,
        "CodexDriver",
        lambda **_kwargs: SimpleNamespace(model="test"),
    )
    monkeypatch.setattr(runtime, "GuardianController", lambda **kwargs: kwargs)
    monkeypatch.setattr(
        runtime,
        "AuthenticatedGitHubSnapshotProvider",
        lambda **_kwargs: object(),
    )
    monkeypatch.setattr(
        runtime,
        "materialize_exact_checkout",
        lambda revision, **kwargs: (
            captured.update(revision=revision, checkout=kwargs) or object()
        ),
    )
    controller = runtime._build_controller(
        config=config,
        state=SimpleNamespace(),  # type: ignore[arg-type]
        state_directory=tmp_path,
        github_credential=SimpleNamespace(argv=config.runtime.github_token_command),  # type: ignore[arg-type]
        model_credential=None,
        git_environment=lambda: {},
        ssh_signing_material=material,
    )
    revision = ExactRevision(
        host="github.com",
        owner="acme",
        repository="widgets",
        ref="refs/heads/main",
        sha="a" * 40,
    )

    controller["checkout_factory"](revision)

    assert captured["revision"] is revision
    assert captured["checkout"] == {
        "credential_environment": controller["publish_credential_environment"],
        "git_binary": "/opt/bin/git",
        "signing_program": "/usr/bin/ssh-keygen",
        "signing_format": SigningFormat.SSH,
        "ssh_signing_material": material,
        "timeout_seconds": 120.0,
    }


@pytest.mark.parametrize(
    "mode,write_enabled",
    [
        (GuardianMode.OBSERVE, False),
        (GuardianMode.PREPARE, False),
        (GuardianMode.APPLY_OWNED_TRANSLATIONS, True),
        (GuardianMode.PROPOSE_PREVENTION, True),
    ],
)
def test_write_broker_exists_only_for_write_modes(
    mode: GuardianMode,
    write_enabled: bool,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}
    monkeypatch.setattr(
        runtime, "CodexDriver", lambda **_kwargs: SimpleNamespace(model="x")
    )
    monkeypatch.setattr(runtime, "GuardianController", lambda **kwargs: kwargs)
    monkeypatch.setattr(
        runtime,
        "AuthenticatedGitHubSnapshotProvider",
        lambda **_kwargs: object(),
    )
    monkeypatch.setattr(
        runtime,
        "GitHubWriteBroker",
        lambda **kwargs: captured.setdefault("broker", kwargs) or object(),
    )
    config = _config(mode)
    github_credential = SimpleNamespace(argv=config.runtime.github_token_command)
    controller = runtime._build_controller(
        config=config,
        state=SimpleNamespace(),  # type: ignore[arg-type]
        state_directory=tmp_path,
        github_credential=github_credential,  # type: ignore[arg-type]
        model_credential=None,
        git_environment=lambda: {},
    )

    factory = controller["write_broker_factory"]
    assert (factory is not None) is write_enabled
    if factory is not None:
        broker = factory(_policy())
        assert broker is captured["broker"]
        assert captured["broker"]["base_url"] == "https://api.github.com"
        assert captured["broker"]["credential"] is github_credential
        assert captured["broker"]["expected_actor"] == _policy().publication_actor
        assert "token_command" not in captured["broker"]


def test_propose_mode_wires_credential_separated_prevention_coordinator(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}
    config = _config(GuardianMode.PROPOSE_PREVENTION)
    state = SimpleNamespace()

    def git_environment() -> dict[str, str]:
        return {"GIT_ASKPASS": "/private/helper"}

    monkeypatch.setattr(
        runtime,
        "CodexDriver",
        lambda **_kwargs: SimpleNamespace(model="assessment-model"),
    )
    monkeypatch.setattr(runtime, "GuardianController", lambda **kwargs: kwargs)
    monkeypatch.setattr(
        runtime,
        "AuthenticatedGitHubSnapshotProvider",
        lambda **_kwargs: object(),
    )
    monkeypatch.setattr(
        runtime,
        "PreventionCodexAuthor",
        lambda **kwargs: captured.setdefault("author", kwargs) or object(),
    )
    monkeypatch.setattr(
        runtime,
        "SandboxedTestRunner",
        lambda **kwargs: captured.setdefault("test_runner", kwargs) or object(),
    )
    coordinator = object()

    def fake_coordinator(**kwargs: object) -> object:
        captured["coordinator"] = kwargs
        return coordinator

    monkeypatch.setattr(runtime, "PreventionCoordinator", fake_coordinator)
    monkeypatch.setattr(
        runtime,
        "PreventionGitHubBroker",
        lambda **kwargs: captured.setdefault("prevention_broker", kwargs) or object(),
    )

    github_credential = SimpleNamespace(argv=config.runtime.github_token_command)
    controller = runtime._build_controller(
        config=config,
        state=state,  # type: ignore[arg-type]
        state_directory=tmp_path,
        github_credential=github_credential,  # type: ignore[arg-type]
        model_credential=None,
        git_environment=git_environment,
    )

    assert controller["prevention_runner"] is coordinator
    assert captured["author"] == {
        "model": "gpt-test",
        "reasoning_effort": "high",
        "auth_mode": CodexAuthMode.API_KEY,
        "codex_home": "~/.local/share/localize-guardian/codex",
        "executable": "/opt/bin/codex",
        "timeout_seconds": 120.0,
        "max_attempts": 2,
    }
    assert captured["test_runner"] == {"timeout_seconds": 120.0}
    coordinator_kwargs = captured["coordinator"]
    assert coordinator_kwargs["state"] is state
    assert coordinator_kwargs["publish_credential_environment"] is git_environment
    assert coordinator_kwargs["signing_key"] == "A" * 40
    assert coordinator_kwargs["max_drafts"] == 1
    assert coordinator_kwargs["max_model_calls_per_day"] == 2
    assert coordinator_kwargs["api_billed"] is True
    assert coordinator_kwargs["temporary_root"] == tmp_path

    prevention = config.repositories[0].prevention
    assert prevention is not None
    broker = coordinator_kwargs["broker_factory"](prevention)
    assert broker is captured["prevention_broker"]
    assert captured["prevention_broker"] == {
        "policy": prevention,
        "create_as_draft": False,
        "credential": github_credential,
        "github_host": "github.com",
        "base_url": "https://api.github.com",
        "timeout_seconds": 30.0,
    }


def test_run_once_creates_private_state_and_uses_bounded_controller(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config_path = tmp_path / "guardian.yaml"
    _write_minimal_config(config_path)
    captured: dict[str, object] = {}

    @contextmanager
    def fake_git_environment(
        command: object, *, temporary_root: Path
    ) -> Iterator[object]:
        captured["github_command"] = command
        captured["temporary_root"] = temporary_root
        yield lambda: {"GIT_ASKPASS": "/private/helper"}

    class FakeController:
        def poll_once(self) -> PollOutcome:
            captured["polled"] = True
            return PollOutcome(lease_acquired=True, repositories_polled=1)

    monkeypatch.setattr(runtime, "git_credential_environment", fake_git_environment)
    monkeypatch.setattr(
        runtime,
        "_build_controller",
        lambda **kwargs: captured.setdefault("controller_kwargs", kwargs)
        and FakeController(),
    )

    previous_umask = os.umask(0o777)
    try:
        result = runtime.run_once(config_path=config_path)
    finally:
        os.umask(previous_umask)

    state_directory = tmp_path / ".guardian"
    state_path = state_directory / "state.sqlite3"
    assert result == 0
    assert captured["polled"] is True
    assert captured["temporary_root"] == state_directory
    assert isinstance(captured["github_command"], runtime.CredentialSnapshot)
    assert captured["controller_kwargs"]["github_credential"] is captured[
        "github_command"
    ]
    assert _mode(state_directory) == 0o700
    assert _mode(state_path) == 0o600
    assert _mode(state_directory / "poll.lock") == 0o600
    assert all(
        _mode(artifact) == 0o600 and artifact.stat().st_nlink == 1
        for artifact in state_directory.glob("state.sqlite3*")
    )


def test_run_once_shares_one_rotating_github_credential_with_rest_and_git(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config_path = tmp_path / "guardian.yaml"
    _write_minimal_config(config_path)
    issuances = iter(("publication-actor-token", "different-actor-token"))
    helper_reads = 0
    captured: dict[str, object] = {}

    def read_secret(_command: object) -> str:
        nonlocal helper_reads
        helper_reads += 1
        return next(issuances)

    monkeypatch.setattr(runtime.SecretCommand, "read", read_secret)

    class FakeController:
        def poll_once(self) -> PollOutcome:
            credential = captured["credential"]
            rest_token = credential.read()
            git_environment = captured["git_environment"]()
            assert rest_token == "publication-actor-token"
            assert git_environment["LOCALIZE_GUARDIAN_GIT_TOKEN"] == rest_token
            return PollOutcome(lease_acquired=True, repositories_polled=1)

    def build_controller(**kwargs: object) -> FakeController:
        captured["credential"] = kwargs["github_credential"]
        captured["git_environment"] = kwargs["git_environment"]
        return FakeController()

    monkeypatch.setattr(runtime, "_build_controller", build_controller)

    assert runtime.run_once(config_path=config_path) == 0
    assert helper_reads == 1


def test_run_once_never_overlaps_a_poll_for_the_same_config(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config_path = tmp_path / "guardian.yaml"
    _write_minimal_config(config_path)
    state_directory, _state_path = runtime._prepare_private_state(config_path)
    monkeypatch.setattr(
        runtime,
        "_build_controller",
        lambda **_kwargs: pytest.fail("an overlapping poll must not start"),
    )

    with runtime._exclusive_poll_lock(state_directory):
        assert runtime.run_once(config_path=config_path, scheduled=True) == 0
        with pytest.raises(runtime.GuardianRuntimeError, match="already running"):
            runtime.run_once(config_path=config_path, scheduled=False)

    lock_path = state_directory / "poll.lock"
    assert lock_path.is_file()
    assert _mode(lock_path) == 0o600


def test_prepare_private_state_accepts_a_directory_created_by_a_racer(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config_path = tmp_path / "guardian.yaml"
    _write_minimal_config(config_path)
    state_directory = tmp_path / ".guardian"

    def racing_mkdir(
        path: Path,
        mode: int = 0o777,
        parents: bool = False,
        exist_ok: bool = False,
    ) -> None:
        assert path == state_directory
        assert parents is False
        assert exist_ok is False
        os.mkdir(path, mode)
        raise FileExistsError

    monkeypatch.setattr(Path, "mkdir", racing_mkdir)

    directory, database = runtime._prepare_private_state(config_path)

    assert directory == state_directory
    assert database == state_directory / "state.sqlite3"
    assert _mode(directory) == 0o700


def test_prepare_private_state_secures_a_new_directory_under_restrictive_umask(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "guardian.yaml"
    _write_minimal_config(config_path)
    previous_umask = os.umask(0o777)
    try:
        directory, _database = runtime._prepare_private_state(config_path)
    finally:
        os.umask(previous_umask)

    assert _mode(directory) == 0o700


def test_prepare_private_state_waits_for_a_live_restrictive_umask_creator(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config_path = tmp_path / "guardian.yaml"
    _write_minimal_config(config_path)
    state_directory = tmp_path / ".guardian"
    creator_is_normalizing = threading.Event()
    release_creator = threading.Event()
    contender_inspected_restricted_directory = threading.Event()
    original_chmod = Path.chmod
    original_stat = Path.stat
    results: dict[str, object] = {}

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

    def prepare(name: str) -> None:
        try:
            results[name] = runtime._prepare_private_state(config_path)
        except Exception as exc:
            results[name] = exc

    monkeypatch.setattr(Path, "chmod", delayed_creator_chmod)
    monkeypatch.setattr(Path, "stat", observed_stat)
    previous_umask = os.umask(0o777)
    try:
        creator = threading.Thread(target=prepare, args=("creator",), name="creator")
        creator.start()
        assert creator_is_normalizing.wait(timeout=5)
        contender = threading.Thread(
            target=prepare,
            args=("contender",),
            name="contender",
        )
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
    expected = (state_directory, state_directory / "state.sqlite3")
    assert results == {"creator": expected, "contender": expected}
    assert _mode(state_directory) == 0o700


def test_prepare_private_state_rejects_a_hardlinked_database(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "guardian.yaml"
    _write_minimal_config(config_path)
    state_directory = tmp_path / ".guardian"
    state_directory.mkdir(mode=0o700)
    database = state_directory / "state.sqlite3"
    database.write_text("", encoding="utf-8")
    database.chmod(0o600)
    (tmp_path / "state-alias").hardlink_to(database)

    directory, returned_database = runtime._prepare_private_state(config_path)

    assert returned_database == database
    with runtime._exclusive_poll_lock(directory):
        with pytest.raises(runtime.GuardianRuntimeError, match="private"):
            runtime._validate_private_state_artifacts(database)


@pytest.mark.skipif(
    not runtime._poll_locking_is_available(),
    reason="POSIX flock is unavailable",
)
def test_first_poll_lock_creation_is_race_safe_across_processes(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "guardian.yaml"
    _write_minimal_config(config_path)
    gate = tmp_path / "start"
    ready_paths = tuple(tmp_path / f"ready-{index}" for index in range(2))
    project_root = Path(__file__).resolve().parents[2]
    environment = os.environ.copy()
    existing_pythonpath = environment.get("PYTHONPATH")
    environment["PYTHONPATH"] = os.pathsep.join(
        value for value in (str(project_root), existing_pythonpath) if value
    )
    script = """
import os
from pathlib import Path
import sys
import time
from localize.guardian import runtime

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
state_directory, _state_path = runtime._prepare_private_state(config_path)
try:
    with runtime._exclusive_poll_lock(state_directory):
        print("locked", flush=True)
        deadline = time.monotonic() + 5
        while not contended.exists():
            if time.monotonic() >= deadline:
                raise SystemExit(3)
            time.sleep(0.005)
except runtime._GuardianPollAlreadyRunning:
    contended.touch()
    print("contended", flush=True)
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
        "contended",
        "locked",
    ]
    assert all(stderr == "" for _stdout, stderr in results)


def test_poll_lock_is_released_when_the_poll_raises(tmp_path: Path) -> None:
    state_directory = tmp_path / ".guardian"
    state_directory.mkdir(mode=0o700)

    with pytest.raises(RuntimeError, match="sentinel"):
        with runtime._exclusive_poll_lock(state_directory):
            raise RuntimeError("sentinel")

    with runtime._exclusive_poll_lock(state_directory):
        pass


def test_poll_lock_creation_secures_mode_under_restrictive_umask(
    tmp_path: Path,
) -> None:
    state_directory = tmp_path / ".guardian"
    state_directory.mkdir(mode=0o700)
    previous_umask = os.umask(0o777)
    try:
        with runtime._exclusive_poll_lock(state_directory):
            pass
    finally:
        os.umask(previous_umask)

    assert _mode(state_directory / "poll.lock") == 0o600


def test_poll_lock_waits_for_an_exclusive_creator_to_finish_initializing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state_directory = tmp_path / ".guardian"
    state_directory.mkdir(mode=0o700)
    lock_path = state_directory / "poll.lock"
    lock_path.write_bytes(b"")
    lock_path.chmod(0o000)
    waits = 0

    def finish_creator(_seconds: float) -> None:
        nonlocal waits
        waits += 1
        lock_path.chmod(0o600)

    monkeypatch.setattr(runtime.time, "sleep", finish_creator)

    with runtime._exclusive_poll_lock(state_directory):
        pass

    assert waits == 1
    assert _mode(lock_path) == 0o600


def test_poll_lock_retries_when_creator_finishes_after_permission_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state_directory = tmp_path / ".guardian"
    state_directory.mkdir(mode=0o700)
    lock_path = state_directory / "poll.lock"
    lock_path.write_bytes(b"")
    lock_path.chmod(0o000)
    original_open = os.open
    permission_failures = 0

    def open_during_creator_transition(
        path: os.PathLike[str] | str,
        flags: int,
        mode: int = 0o777,
    ) -> int:
        nonlocal permission_failures
        if path == lock_path and not flags & os.O_EXCL and permission_failures == 0:
            permission_failures += 1
            lock_path.chmod(0o600)
            raise PermissionError
        return original_open(path, flags, mode)

    monkeypatch.setattr(runtime.os, "open", open_during_creator_transition)

    with runtime._exclusive_poll_lock(state_directory):
        pass

    assert permission_failures == 1
    assert _mode(lock_path) == 0o600


def test_poll_lock_never_repairs_a_preexisting_unsafe_inode(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state_directory = tmp_path / ".guardian"
    state_directory.mkdir(mode=0o700)
    lock_path = state_directory / "poll.lock"
    lock_path.write_bytes(b"")
    lock_path.chmod(0o000)
    clock = iter((0.0, 2.0))
    monkeypatch.setattr(runtime.time, "monotonic", lambda: next(clock))

    with pytest.raises(runtime.GuardianRuntimeError, match="lock"):
        with runtime._exclusive_poll_lock(state_directory):
            pass

    assert _mode(lock_path) == 0o000


@pytest.mark.parametrize("unsafe_kind", ["symlink", "mode", "hardlink"])
def test_poll_lock_rejects_unsafe_existing_paths(
    tmp_path: Path,
    unsafe_kind: str,
) -> None:
    state_directory = tmp_path / ".guardian"
    state_directory.mkdir(mode=0o700)
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

    with pytest.raises(runtime.GuardianRuntimeError, match="lock"):
        with runtime._exclusive_poll_lock(state_directory):
            pass


def test_scheduled_run_skips_after_failed_attempt_on_same_day_but_manual_runs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config_path = tmp_path / "guardian.yaml"
    _write_minimal_config(config_path)
    state_directory = tmp_path / ".guardian"
    state_directory.mkdir(mode=0o700)
    state_path = state_directory / "state.sqlite3"
    with GuardianState(state_path) as state:
        state.record_health(
            component="guardian-poll-attempt",
            status="attempted",
            message="attempt",
            checked_at=NOW - timedelta(hours=1),
        )

    calls = 0

    class FakeController:
        def poll_once(self) -> PollOutcome:
            nonlocal calls
            calls += 1
            return PollOutcome(lease_acquired=True)

    @contextmanager
    def fake_credentials(*_args: object, **_kwargs: object) -> Iterator[object]:
        yield lambda: {}

    monkeypatch.setattr(runtime, "_local_now", lambda: NOW)
    monkeypatch.setattr(runtime, "git_credential_environment", fake_credentials)
    monkeypatch.setattr(
        runtime, "_build_controller", lambda **_kwargs: FakeController()
    )

    assert runtime.run_once(config_path=config_path, scheduled=True) == 0
    assert calls == 0
    assert runtime.run_once(config_path=config_path, scheduled=False) == 0
    assert calls == 1


def test_scheduled_run_catches_up_when_last_attempt_was_previous_local_day(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config_path = tmp_path / "guardian.yaml"
    _write_minimal_config(config_path)
    state_directory = tmp_path / ".guardian"
    state_directory.mkdir(mode=0o700)
    with GuardianState(state_directory / "state.sqlite3") as state:
        state.record_health(
            component="guardian-poll-attempt",
            status="attempted",
            message="attempt",
            checked_at=NOW - timedelta(days=1),
        )

    calls = 0

    class FakeController:
        def poll_once(self) -> PollOutcome:
            nonlocal calls
            calls += 1
            return PollOutcome(lease_acquired=True)

    @contextmanager
    def fake_credentials(*_args: object, **_kwargs: object) -> Iterator[object]:
        yield lambda: {}

    monkeypatch.setattr(runtime, "_local_now", lambda: NOW)
    monkeypatch.setattr(runtime, "git_credential_environment", fake_credentials)
    monkeypatch.setattr(
        runtime, "_build_controller", lambda **_kwargs: FakeController()
    )

    assert runtime.run_once(config_path=config_path, scheduled=True) == 0
    assert calls == 1


def test_operator_pipeline_config_is_snapshotted_before_controller_poll(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config_path = tmp_path / "guardian.yaml"
    _write_minimal_config(config_path)
    sequence: list[str] = []

    @contextmanager
    def fake_snapshot(**_kwargs: object) -> Iterator[dict[str, PipelineConfigSnapshot]]:
        sequence.append("snapshot-enter")
        try:
            yield {
                "acme/widgets": PipelineConfigSnapshot(
                    config_root=tmp_path,
                    config_path=config_path,
                    bundle_digest="d" * 64,
                )
            }
        finally:
            sequence.append("snapshot-exit")

    @contextmanager
    def fake_credentials(*_args: object, **_kwargs: object) -> Iterator[object]:
        yield lambda: {}

    class FakeController:
        def poll_once(self) -> PollOutcome:
            sequence.append("github-model-poll")
            return PollOutcome(lease_acquired=True)

    monkeypatch.setattr(
        runtime,
        "_snapshot_operator_pipeline_configs",
        fake_snapshot,
    )
    monkeypatch.setattr(runtime, "git_credential_environment", fake_credentials)
    monkeypatch.setattr(
        runtime, "_build_controller", lambda **_kwargs: FakeController()
    )

    assert runtime.run_once(config_path=config_path) == 0
    assert sequence == ["snapshot-enter", "github-model-poll", "snapshot-exit"]
    with GuardianState(tmp_path / ".guardian/state.sqlite3") as state:
        audit = state.latest_health("pipeline-config")
    assert audit is not None
    assert audit.details == {
        "repository": "acme/widgets",
        "bundle_digest": "d" * 64,
    }


def test_setup_deadline_failure_is_recorded_before_runtime_exits(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config_path = tmp_path / "guardian.yaml"
    _write_minimal_config(config_path)

    @contextmanager
    def expired_signing_snapshot(**_kwargs: object) -> Iterator[None]:
        raise PollDeadlineExceeded("Guardian poll deadline was exceeded.")
        yield

    monkeypatch.setattr(
        runtime,
        "_snapshot_poll_signing_material",
        expired_signing_snapshot,
    )

    with pytest.raises(runtime.GuardianRuntimeError, match="failed safely"):
        runtime.run_once(config_path=config_path)

    with GuardianState(tmp_path / ".guardian/state.sqlite3") as state:
        health = state.latest_health("guardian")
    assert health is not None
    assert health.status == "failed"
    assert health.details == {"failure_types": ["PollDeadlineExceeded"]}


def test_failed_scheduled_poll_is_not_retried_until_manual_request(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config_path = tmp_path / "guardian.yaml"
    _write_minimal_config(config_path)
    calls = 0

    class FailingController:
        def poll_once(self) -> PollOutcome:
            nonlocal calls
            calls += 1
            return PollOutcome(
                lease_acquired=True,
                runs_failed=1,
                failures=("safe-failure-type",),
            )

    @contextmanager
    def fake_credentials(*_args: object, **_kwargs: object) -> Iterator[object]:
        yield lambda: {}

    monkeypatch.setattr(runtime, "_local_now", lambda: NOW)
    monkeypatch.setattr(runtime, "git_credential_environment", fake_credentials)
    monkeypatch.setattr(
        runtime, "_build_controller", lambda **_kwargs: FailingController()
    )

    assert runtime.run_once(config_path=config_path, scheduled=True) == 1
    assert runtime.run_once(config_path=config_path, scheduled=True) == 0
    assert calls == 1
    assert runtime.run_once(config_path=config_path, scheduled=False) == 1
    assert calls == 2

    with GuardianState(tmp_path / ".guardian/state.sqlite3") as state:
        attempt = state.latest_health("guardian-poll-attempt")
    assert attempt is not None
    assert attempt.status == "attempted"
    assert attempt.details == {
        "scheduled": False,
        "local_date": NOW.date().isoformat(),
        "local_minute": NOW.hour * 60 + NOW.minute,
    }


def test_model_capacity_circuit_is_a_failed_runtime_outcome() -> None:
    assert (
        runtime._exit_code(PollOutcome(lease_acquired=True, model_circuit_open=True))
        == 1
    )


@pytest.mark.parametrize("failure_field", ["prevention_failures", "remediation_failures"])
def test_publication_failure_is_a_failed_runtime_outcome(failure_field: str) -> None:
    assert runtime._exit_code(
        PollOutcome(lease_acquired=True, **{failure_field: ("GitHubAPIError",)})
    ) == 1


def test_scheduled_due_uses_local_day_instead_of_utc_day() -> None:
    local_zone = timezone(timedelta(hours=14))
    now = datetime(2026, 8, 30, 1, 0, tzinfo=local_zone)
    # The UTC date is still August 29, but this success occurred at 00:30 on
    # August 30 in the scheduler's local time zone.
    attempt = datetime(2026, 8, 29, 10, 30, tzinfo=UTC)
    state = SimpleNamespace(
        latest_health=lambda _component: SimpleNamespace(
            status="attempted",
            checked_at=attempt,
        )
    )

    assert (
        runtime._scheduled_poll_is_due(
            state,
            now=now,
            schedule=GuardianSchedule(),
        )
        is False
    )


def test_scheduled_due_does_not_repeat_across_dst_fallback() -> None:
    now = datetime(2026, 10, 25, 0, 15, tzinfo=timezone(timedelta(hours=1)))
    prior = datetime(2026, 10, 25, 0, 5, tzinfo=timezone(timedelta(hours=2)))
    state = SimpleNamespace(
        latest_health=lambda _component: SimpleNamespace(
            status="attempted",
            checked_at=prior,
            details={
                "scheduled": True,
                "local_date": "2026-10-25",
                "local_minute": 5,
            },
        )
    )

    assert (
        runtime._scheduled_poll_is_due(
            state,
            now=now,
            schedule=GuardianSchedule(hour=0, minute=0),
        )
        is False
    )


def test_manual_poll_before_schedule_does_not_suppress_scheduled_poll() -> None:
    now = datetime(2026, 8, 30, 8, 7, tzinfo=timezone.utc)
    manual = datetime(2026, 8, 30, 7, 0, tzinfo=timezone.utc)
    state = SimpleNamespace(
        latest_health=lambda _component: SimpleNamespace(
            status="attempted",
            checked_at=manual,
            details={
                "scheduled": False,
                "local_date": "2026-08-30",
                "local_minute": 7 * 60,
            },
        )
    )

    assert (
        runtime._scheduled_poll_is_due(
            state,
            now=now,
            schedule=GuardianSchedule(hour=8, minute=7),
        )
        is True
    )


def test_scheduled_due_uses_configured_local_clock() -> None:
    now = datetime(2026, 8, 30, 5, 14, tzinfo=timezone(timedelta(hours=2)))
    state = SimpleNamespace(latest_health=lambda _component: None)

    assert (
        runtime._scheduled_poll_is_due(
            state,
            now=now,
            schedule=GuardianSchedule(hour=5, minute=15),
        )
        is False
    )
    assert (
        runtime._scheduled_poll_is_due(
            state,
            now=now + timedelta(minutes=1),
            schedule=GuardianSchedule(hour=5, minute=15),
        )
        is True
    )


def test_run_once_uses_configured_schedule_for_due_check(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config_path = tmp_path / "guardian.yaml"
    _write_minimal_config(config_path)
    config_path.write_text(
        "schedule: {hour: 13, minute: 0}\n" + config_path.read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    monkeypatch.setattr(runtime, "_local_now", lambda: NOW)
    monkeypatch.setattr(
        runtime,
        "_build_controller",
        lambda **_kwargs: pytest.fail("controller must not run before 13:00"),
    )

    assert runtime.run_once(config_path=config_path, scheduled=True) == 0


def test_run_once_redacts_setup_and_poll_exception_messages(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config_path = tmp_path / "guardian.yaml"
    _write_minimal_config(config_path)
    secret = "never-print-this-token"

    @contextmanager
    def fake_credentials(*_args: object, **_kwargs: object) -> Iterator[object]:
        yield lambda: {}

    class FailingController:
        def poll_once(self) -> PollOutcome:
            raise RuntimeError(secret)

    monkeypatch.setattr(runtime, "git_credential_environment", fake_credentials)
    monkeypatch.setattr(
        runtime, "_build_controller", lambda **_kwargs: FailingController()
    )

    with pytest.raises(runtime.GuardianRuntimeError) as error:
        runtime.run_once(config_path=config_path)

    assert secret not in str(error.value)
    assert error.value.__cause__ is None


def test_run_once_rejects_invalid_config_without_echoing_untrusted_values(
    tmp_path: Path,
) -> None:
    secret = "never-print-this-config-value"
    config_path = tmp_path / "guardian.yaml"
    config_path.write_text(
        f"repositories: []\nunknown_secret: {secret}\n",
        encoding="utf-8",
    )
    config_path.chmod(0o600)

    with pytest.raises(runtime.GuardianRuntimeError) as error:
        runtime.run_once(config_path=config_path)

    assert secret not in str(error.value)
    assert error.value.__cause__ is None


@pytest.mark.parametrize("unsafe_kind", ["group-writable", "symlink"])
def test_runtime_rejects_untrusted_config_ancestor_paths(
    tmp_path: Path,
    unsafe_kind: str,
) -> None:
    trusted = tmp_path / "trusted"
    trusted.mkdir(mode=0o700)
    if unsafe_kind == "symlink":
        config_directory = tmp_path / "operator"
        config_directory.symlink_to(trusted, target_is_directory=True)
    else:
        config_directory = trusted
        config_directory.chmod(0o770)
    config_path = config_directory / "guardian.yaml"
    _write_minimal_config(config_path)

    with pytest.raises(runtime.GuardianRuntimeError, match="unsafe"):
        runtime.run_once(config_path=config_path)

    assert not (trusted / ".guardian").exists()


def test_run_once_requires_explicit_signing_key_before_write_mode_setup(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "guardian.yaml"
    _write_minimal_config(config_path)
    config_path.write_text(
        config_path.read_text(encoding="utf-8").replace(
            "mode: observe",
            "mode: apply-owned-translations",
            1,
        ),
        encoding="utf-8",
    )

    with pytest.raises(runtime.GuardianRuntimeError, match="signing key"):
        runtime.run_once(config_path=config_path)

    assert not (tmp_path / ".guardian").exists()


def test_run_once_rejects_symlinked_or_non_private_state_paths(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "guardian.yaml"
    _write_minimal_config(config_path)
    target = tmp_path / "elsewhere"
    target.mkdir()
    (tmp_path / ".guardian").symlink_to(target, target_is_directory=True)

    with pytest.raises(runtime.GuardianRuntimeError, match="private"):
        runtime.run_once(config_path=config_path)

    (tmp_path / ".guardian").unlink()
    (tmp_path / ".guardian").mkdir(mode=0o755)
    os.chmod(tmp_path / ".guardian", 0o755)
    with pytest.raises(runtime.GuardianRuntimeError, match="private"):
        runtime.run_once(config_path=config_path)
