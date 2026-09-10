"""Operator-owned command surface for the self-hosted Localize Guardian."""

from __future__ import annotations

import argparse
from collections.abc import Mapping
from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import importlib
import json
import os
from pathlib import Path
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
from typing import Iterator, Sequence

from jsonschema import Draft202012Validator
import httpx

from localize.formats import list_localization_adapters
from localize.guardian.codex import (
    RESULT_SCHEMA_PATH,
    codex_auth_config,
    guardian_assessment_permission_config,
    guardian_assessment_permission_profile,
)
from localize.guardian.credentials import CredentialError, SecretCommand
from localize.guardian.executable_trust import (
    ExecutableTrustError,
    require_absolute_trusted_direct_executable,
    require_absolute_trusted_executable,
    require_absolute_trusted_wrapper,
)
from localize.guardian.filesystem_trust import (
    create_or_wait_for_private_directory,
    is_trusted_directory,
    resolve_trusted_private_directory,
)
from localize.guardian.github import (
    GitHubReader,
    GitHubRepositoryIdentity,
    GitHubRepositoryPolicy,
)
from localize.guardian.json_safety import loads_bounded_json
from localize.guardian.models import (
    CodexAuthMode,
    GuardianConfig,
    GuardianMode,
    PipelineConfigSource,
    RepositoryPolicy,
    SigningFormat,
    TrustedActor,
)
from localize.guardian.prevention_runtime import (
    SandboxedTestRunner,
    guardian_prevention_author_permission_config,
    guardian_prevention_author_permission_profile,
)
from localize.guardian.process import (
    ProcessLimits,
    ProcessResourceError,
    WorkspaceQuota,
    linux_cgroup_parent_procs,
    run_bounded_process,
)
from localize.guardian.runtime import (
    GuardianRuntimeError,
    _exclusive_poll_lock,
    _poll_locking_is_available,
    _preflight_poll_lock,
    _probe_poll_lock_semantics,
    _snapshot_operator_pipeline_configs,
    _validate_private_state_artifacts,
    _validate_subscription_codex_home,
    load_trusted_guardian_config,
)
from localize.guardian.scheduler import (
    LaunchdSchedule,
    SchedulerError,
    render_launchd_plist,
    render_launchd_runner,
)
from localize.guardian.signing import (
    SigningError,
    canonical_signing_key,
    canonical_ssh_fingerprint,
    snapshot_ssh_signing_material,
    ssh_agent_environment,
    ssh_signature_matches,
    signature_matches,
)
from localize.guardian.state import GuardianState


_STARTER_CONFIG = """# Generic, report-only policy for an operator-run, self-hosted
# Localize Guardian. Store this operator-owned policy outside every monitored
# repository.
# Replace every example name and numeric ID with values read from GitHub's API.
# Login names are display labels; exact numeric IDs and API types grant authority.
mode: observe

# Scheduled invocations catch up once daily after this local wall-clock time.
schedule:
  hour: 0
  minute: 0

runtime:
  codex_model: gpt-5.6-terra
  codex_reasoning_effort: high
  # Uses the operator's Codex/ChatGPT plan allowance, not API billing.
  codex_auth_mode: chatgpt
  # ChatGPT mode only; remove this key when selecting api-key mode.
  codex_home: ~/.local/share/localize-guardian/codex
  # Interactive defaults use PATH. Before `guardian install`, replace these
  # executable names with absolute paths so launchd cannot resolve another binary.
  codex_executable: codex
  git_executable: git
  # OpenPGP remains the backward-compatible default. For agent-backed SSH,
  # replace these signing fields as documented in docs/guardian.md.
  signing_format: openpgp
  signing_program: gpg
  github_token_command: [gh, auth, token]
  # API billing is opt-in: switch codex_auth_mode to api-key, configure this
  # argv-only OS secret-store helper, and enable both USD limits below.
  # codex_api_key_command: [/absolute/path/to/model-key-helper]
  # Required for write modes; global Git configuration is intentionally ignored.
  # signing_key: REPLACE_WITH_FULL_GPG_FINGERPRINT
  # SSH alternative (all four fields are required together):
  # signing_format: ssh
  # signing_program: /usr/bin/ssh-keygen
  # signing_key: SHA256:REPLACE_WITH_EXACT_PUBLIC_KEY_FINGERPRINT
  # signing_public_key: /absolute/path/to/guardian-signing-key.pub

limits:
  run_timeout_seconds: 1800
  max_attempts: 2
  max_value_edits_per_run: 10
  max_prevention_drafts_per_run: 0
  max_remediation_drafts_per_run: 0
  max_model_calls_per_day: 2
  # API-key mode only:
  # daily_cost_limit_usd: 2.00
  # model_call_reservation_usd: 2.00
  min_apply_confidence: 0.90
  raw_retention_days: 30

repositories:
  - base_repo: acme/widgets
    base_repo_id: 100000001
    base_branch: main
    private_repo_model_opt_in: false
    # Exact GitHub User that authors ordinary commits/comments in write modes.
    # Use a narrowly scoped machine-user token. GitHub App installation-token
    # Bot publication cannot satisfy the GET /user identity proof. This does
    # not authorize which pull requests Guardian may process.
    publication_actor:
      login: localization-machine-user
      id: 100000002
      type: User
    # Existing pull-request authors whose owned branches Guardian may advance.
    # This is independent of publication_actor, including for remediation.
    allowed_pr_authors:
      - login: translation-contributor
        id: 100000008
        type: User
    allowed_head_owners:
      - login: translation-contributor
        id: 100000008
        type: User
    allowed_head_repositories:
      - full_name: translation-contributor/widgets
        id: 100000003
    allowed_branch_globs:
      - "localization/**"
      # Uncomment with the remediation example below:
      # - "localization/guardian-remediation-*"
    allowed_path_globs:
      - "src/main/resources/i18n/**"
    # Set to operator to resolve the path beside this Guardian YAML instead of
    # from the exact repository base SHA. See docs/guardian.md for permissions.
    pipeline_config_source: base
    pipeline_config_path: .localize/config.yaml
    source_locale: en
    # Optional history pass; after open PRs, durable bounded scan cycles restart
    # at page 1 and use a second identity-only traversal for confirmation.
    # GitHub's list is not an atomic snapshot: completion requires a quiescent
    # pass within the 100-page/10,000-entry ceiling, or the operator must narrow
    # the lookback. Each selected PR gets three immediate hydration attempts
    # before a current-cycle skip and durable priority retry on later polls,
    # including outside the discovery window. Closed PRs/comments remain
    # evidence only. The window admits new evidence; a durable pending
    # recovery group cannot age out, but must stay closed, exact-identity, and
    # policy/trust eligible. A nested remediation policy may remain configured
    # while observe/prepare keep it dormant and perform no GitHub writes.
    # closed_pr_backfill:
    #   lookback_days: 90
    #   max_prs_per_poll: 5
    #   # Requires apply-owned-translations or propose-prevention, a positive
    #   # remediation draft cap, and signing. It creates a new current-base
    #   # correction draft with a signed commit and never writes to the closed
    #   # PR. The repository and literal
    #   # push_branch_prefix + "*" glob must both be allowed above. The suffix
    #   # is a deterministic 64-character branch hash.
    #   remediation:
    #     push_repository:
    #       full_name: translation-contributor/widgets
    #       id: 100000003
    #     push_branch_prefix: localization/guardian-remediation-
    #     publication_actor:
    #       login: localization-machine-user
    #       id: 100000002
    #       type: User
    # Optional pipeline-prevention PRs declare their exact publication actor
    # separately. If remediation is enabled too, every declaration must identify
    # the same publication_actor, the credential actor returned by GET /user,
    # and the resulting PR author. Login is only a mutable label; numeric ID +
    # GitHub User type grant authority.
    # prevention:
    #   target_repository:
    #     full_name: acme/localization-pipeline
    #     id: 100000006
    #     base_branch: main
    #   push_repository:
    #     full_name: guardian-machine-user/localization-pipeline
    #     id: 100000007
    #     branch_prefix: guardian/prevention-
    #   publication_actor:
    #     login: localization-machine-user
    #     id: 100000002
    #     type: User
    #   allowed_code_path_globs: ["localize/**/*.py"]
    #   allowed_test_path_globs: ["tests/**/*.py"]
    #   focused_test_argv:
    #     - [/absolute/path/to/python, -m, pytest, tests/unit/test_rules.py, -q]
    #   sandbox_argv_prefix:
    #     - /absolute/path/to/guardian-sandbox-wrapper
    #   max_changed_files: 4
    #   max_changed_bytes: 262144
    #   private_target_model_opt_in: false
    trusted_reviewers:
      de:
        - login: german-maintainer
          id: 100000004
          type: User
    trusted_bots:
      de:
        - login: translation-reviewer[bot]
          id: 100000005
          type: Bot
"""

_WRITE_MODES = frozenset(
    {
        GuardianMode.APPLY_OWNED_TRANSLATIONS,
        GuardianMode.PROPOSE_PREVENTION,
    }
)
_MAX_DOCTOR_GITHUB_ACTOR_BYTES = 1_048_576
_CODEX_PERMISSION_PROBE = r"""
inside_read=$1
inside_write=$2
outside_read=$3
outside_write=$4
nonce=$5
tcp_port=$6
unix_socket_path=$7
workspace_write=$8
cgroup_parent_procs=$9
unsafe=0

if ! value=$(/bin/cat "$inside_read" 2>/dev/null) || [ "$value" != "$nonce" ]; then
    unsafe=1
fi
if (: > "$inside_write") 2>/dev/null; then
    if [ "$workspace_write" != "1" ]; then
        unsafe=1
    fi
elif [ "$workspace_write" = "1" ]; then
    unsafe=1
fi
if /bin/cat "$outside_read" >/dev/null 2>&1; then
    unsafe=1
fi
if (: > "$outside_write") 2>/dev/null; then
    unsafe=1
fi
if /usr/bin/nc -n -z -w 1 127.0.0.1 "$tcp_port" >/dev/null 2>&1; then
    unsafe=1
fi
if [ -n "$unix_socket_path" ] && \
    /usr/bin/nc -U -z -w 1 "$unix_socket_path" >/dev/null 2>&1; then
    unsafe=1
fi
if [ -n "$cgroup_parent_procs" ] && \
    (: > "$cgroup_parent_procs") 2>/dev/null; then
    unsafe=1
fi

listener_pid=
cleanup() {
    if [ -n "$listener_pid" ]; then
        kill "$listener_pid" >/dev/null 2>&1 || true
        wait "$listener_pid" >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT HUP INT TERM
/usr/bin/nc -l 127.0.0.1 0 </dev/null >/dev/null 2>&1 &
listener_pid=$!
/bin/sleep 1
if kill -0 "$listener_pid" >/dev/null 2>&1; then
    unsafe=1
fi
cleanup
listener_pid=
exit "$unsafe"
"""


class GuardianCLIError(RuntimeError):
    """An operator-facing failure whose message contains no secret material."""


@dataclass(frozen=True)
class GuardianInstallPaths:
    """Deterministic, operator-owned files staged by ``guardian install``."""

    label: str
    runner_path: Path
    plist_path: Path
    stdout_path: Path
    stderr_path: Path


def _resolved_config_path(raw_path: str | Path) -> Path:
    return Path(os.path.abspath(Path(raw_path).expanduser()))


def guardian_state_dir(config_path: str | Path) -> Path:
    """Return the private runtime directory beside an operator config."""

    return _resolved_config_path(config_path).parent / ".guardian"


def guardian_state_path(config_path: str | Path) -> Path:
    """Return the SQLite audit path shared with the Guardian controller."""

    return guardian_state_dir(config_path) / "state.sqlite3"


def _default_launch_agents_dir() -> Path:
    return Path.home() / "Library" / "LaunchAgents"


def guardian_install_paths(config_path: str | Path) -> GuardianInstallPaths:
    """Return deterministic launchd paths without creating them."""

    resolved = _resolved_config_path(config_path)
    digest = hashlib.sha256(str(resolved).encode("utf-8")).hexdigest()[:12]
    label = f"org.localize.guardian.{digest}"
    runtime_dir = guardian_state_dir(resolved)
    return GuardianInstallPaths(
        label=label,
        runner_path=runtime_dir / "launchd-runner.sh",
        plist_path=_default_launch_agents_dir() / f"{label}.plist",
        stdout_path=runtime_dir / "guardian.stdout.log",
        stderr_path=runtime_dir / "guardian.stderr.log",
    )


def _owned_by_current_user(metadata: os.stat_result) -> bool:
    return not hasattr(os, "getuid") or metadata.st_uid == os.getuid()


def _ensure_private_directory(path: Path) -> None:
    if path.is_symlink():
        raise GuardianCLIError(f"Refusing symlinked Guardian directory: {path}")
    try:
        metadata = create_or_wait_for_private_directory(path, parents=True)
    except OSError as exc:
        raise GuardianCLIError(
            f"Could not create private Guardian directory: {path}"
        ) from exc
    if not stat.S_ISDIR(metadata.st_mode):
        raise GuardianCLIError(f"Guardian runtime path is not a directory: {path}")
    if not _owned_by_current_user(metadata):
        raise GuardianCLIError(
            f"Guardian runtime directory must be owned by the current user: {path}"
        )
    if stat.S_IMODE(metadata.st_mode) != 0o700:
        raise GuardianCLIError(
            f"Guardian runtime directory must have mode 0700: {path}"
        )


def _ensure_operator_directory(path: Path, *, purpose: str = "Scheduling") -> None:
    """Create or validate an operator-owned, non-writable directory."""

    if not path.is_absolute():
        raise GuardianCLIError(f"{purpose} directory must be absolute.")
    root = Path(path.anchor)
    components = tuple(
        root.joinpath(*path.parts[1:index])
        for index in range(1, len(path.parts) + 1)
    )
    for component in components:
        is_leaf = component == path
        if component.is_symlink():
            location = "directory" if is_leaf else "ancestor"
            raise GuardianCLIError(
                f"Refusing symlinked {purpose.casefold()} {location}: {component}"
            )
        if not component.exists():
            try:
                component.mkdir(mode=0o700)
            except FileExistsError:
                pass
            except OSError as exc:
                raise GuardianCLIError(
                    f"Could not create {purpose.casefold()} directory: {component}"
                ) from exc
        try:
            metadata = component.stat(follow_symlinks=False)
        except OSError as exc:
            raise GuardianCLIError(
                f"Could not inspect {purpose.casefold()} directory ancestor: {component}"
            ) from exc
        trusted_owners = {0}
        if hasattr(os, "getuid"):
            trusted_owners.add(os.getuid())
        if not is_trusted_directory(
            metadata,
            trusted_owners=trusted_owners,
        ):
            location = "directory" if is_leaf else "ancestor"
            raise GuardianCLIError(f"{purpose} {location} is unsafe: {component}")
        if is_leaf and not _owned_by_current_user(metadata):
            raise GuardianCLIError(
                f"{purpose} directory must be owned by the current user: {component}"
            )


def _validate_private_regular_file(path: Path, *, mode: int) -> os.stat_result:
    if path.is_symlink():
        raise GuardianCLIError(f"Refusing symlinked Guardian file: {path}")
    try:
        metadata = path.stat(follow_symlinks=False)
    except OSError as exc:
        raise GuardianCLIError(f"Could not inspect Guardian file: {path}") from exc
    if not stat.S_ISREG(metadata.st_mode):
        raise GuardianCLIError(f"Guardian path is not a regular file: {path}")
    if metadata.st_nlink != 1:
        raise GuardianCLIError(f"Guardian file must not be hard-linked: {path}")
    if not _owned_by_current_user(metadata):
        raise GuardianCLIError(
            f"Guardian file must be owned by the current user: {path}"
        )
    if stat.S_IMODE(metadata.st_mode) != mode:
        raise GuardianCLIError(f"Guardian file must have mode {mode:04o}: {path}")
    return metadata


def _validate_existing_private_directory(path: Path) -> bool:
    """Validate an existing private directory without creating a missing one."""

    try:
        metadata = path.stat(follow_symlinks=False)
    except FileNotFoundError:
        return False
    except OSError as exc:
        raise GuardianCLIError(f"Could not inspect Guardian directory: {path}") from exc
    if stat.S_ISLNK(metadata.st_mode):
        raise GuardianCLIError(f"Refusing symlinked Guardian directory: {path}")
    if not stat.S_ISDIR(metadata.st_mode):
        raise GuardianCLIError(f"Guardian runtime path is not a directory: {path}")
    if not _owned_by_current_user(metadata):
        raise GuardianCLIError(
            f"Guardian runtime directory must be owned by the current user: {path}"
        )
    if stat.S_IMODE(metadata.st_mode) != 0o700:
        raise GuardianCLIError(
            f"Guardian runtime directory must have mode 0700: {path}"
        )
    return True


@contextmanager
def _locked_existing_state(
    config_path: Path,
) -> Iterator[GuardianState | None]:
    """Open an existing private state database under the production poll lock."""

    state_directory = guardian_state_dir(config_path)
    if not _validate_existing_private_directory(state_directory):
        yield None
        return
    state_path = guardian_state_path(config_path)
    _validate_private_state_artifacts(state_path)
    try:
        state_path.stat(follow_symlinks=False)
    except FileNotFoundError:
        # There is no shared state to serialize with. Avoid creating a poll lock
        # merely to report an empty read-only operator view.
        yield None
        return
    except OSError as exc:
        raise GuardianCLIError("Could not inspect Guardian state database.") from exc
    with _exclusive_poll_lock(state_directory):
        if not _validate_existing_private_directory(state_directory):
            raise GuardianCLIError("Guardian state directory disappeared.")
        _validate_private_state_artifacts(state_path)
        try:
            metadata = state_path.stat(follow_symlinks=False)
        except FileNotFoundError:
            yield None
            return
        except OSError as exc:
            raise GuardianCLIError("Could not inspect Guardian state database.") from exc
        _validate_private_regular_file(state_path, mode=0o600)
        if metadata.st_size == 0:
            yield None
            return
        with GuardianState(state_path) as state:
            yield state


def _unlink_created_inode(path: Path, identity: tuple[int, int]) -> None:
    try:
        metadata = path.stat(follow_symlinks=False)
        if (
            stat.S_ISREG(metadata.st_mode)
            and (metadata.st_dev, metadata.st_ino) == identity
        ):
            path.unlink()
    except OSError:
        pass


def _write_exclusive(path: Path, content: str, *, mode: int) -> tuple[int, int]:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, mode)
    except FileExistsError as exc:
        raise GuardianCLIError(f"Refusing to overwrite existing file: {path}") from exc
    except OSError as exc:
        raise GuardianCLIError(f"Could not create Guardian file: {path}") from exc
    try:
        metadata = os.fstat(descriptor)
        identity = (metadata.st_dev, metadata.st_ino)
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as output:
            descriptor = -1
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
    except BaseException as exc:
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError:
                pass
            descriptor = -1
        if "identity" in locals():
            _unlink_created_inode(path, identity)
        if isinstance(exc, OSError):
            raise GuardianCLIError(
                f"Could not complete Guardian file: {path}"
            ) from exc
        raise
    return identity


def _ensure_private_file(path: Path) -> tuple[int, int] | None:
    if path.exists() or path.is_symlink():
        _validate_private_regular_file(path, mode=0o600)
        return None
    return _write_exclusive(path, "", mode=0o600)


def _load_config_or_raise(config_path: Path) -> GuardianConfig:
    try:
        return load_trusted_guardian_config(config_path)
    except GuardianRuntimeError as exc:
        raise GuardianCLIError(str(exc)) from None


def _github_policy(config_policy: RepositoryPolicy) -> GitHubRepositoryPolicy:
    return GitHubRepositoryPolicy(
        repository=config_policy.base_repo,
        repository_id=config_policy.base_repo_id,
        base_branch=config_policy.base_branch,
        allowed_pr_authors=config_policy.allowed_pr_authors,
        allowed_head_owners=config_policy.allowed_head_owners,
        allowed_head_repositories=config_policy.allowed_head_repositories,
        branch_globs=config_policy.allowed_branch_globs,
    )


def _publication_actors(config: GuardianConfig) -> tuple[TrustedActor, ...]:
    """Return actors whose configured write authority is enabled this run."""

    return config.enabled_publication_actors


def _preflight_publication_actor(
    client: httpx.Client,
    expected_actors: Sequence[TrustedActor],
) -> None:
    """Bind one credential actor to every enabled remote publication policy."""

    chunks: list[bytes] = []
    byte_count = 0
    try:
        with client.stream("GET", "/user") as response:
            if response.status_code != 200:
                raise GuardianCLIError("GitHub publication actor probe failed.")
            for chunk in response.iter_bytes():
                byte_count += len(chunk)
                if byte_count > _MAX_DOCTOR_GITHUB_ACTOR_BYTES:
                    raise GuardianCLIError(
                        "GitHub publication actor response is invalid."
                    )
                chunks.append(chunk)
    except httpx.HTTPError:
        raise GuardianCLIError("GitHub publication actor probe failed.") from None
    try:
        payload = loads_bounded_json(b"".join(chunks))
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise GuardianCLIError(
            "GitHub publication actor response is invalid."
        ) from None
    if not isinstance(payload, Mapping):
        raise GuardianCLIError("GitHub publication actor response is invalid.")
    actor_login = payload.get("login")
    actor_id = payload.get("id")
    actor_type = payload.get("type")
    if (
        isinstance(actor_id, bool)
        or not isinstance(actor_id, int)
        or actor_id <= 0
        or actor_type != "User"
    ):
        raise GuardianCLIError("GitHub publication actor response is invalid.")
    try:
        actual_actor = TrustedActor(
            login=actor_login,  # type: ignore[arg-type]
            id=actor_id,
            type=actor_type,
        )
    except (TypeError, ValueError):
        raise GuardianCLIError(
            "GitHub publication actor response is invalid."
        ) from None
    for expected in expected_actors:
        if (
            expected.id != actual_actor.id
            or expected.type != actual_actor.type
        ):
            raise GuardianCLIError(
                "GitHub publication actor does not match every enabled policy."
            )


def _probe_github(config: GuardianConfig) -> tuple[GitHubRepositoryIdentity, ...]:
    """Use the configured argv-only helper for read-only identity probes."""

    identities: list[GitHubRepositoryIdentity] = []
    publication_actors = _publication_actors(config)
    token = SecretCommand(config.runtime.github_token_command).read()
    try:
        with httpx.Client(
            base_url="https://api.github.com",
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {token}",
                "User-Agent": "localize-guardian",
                "X-GitHub-Api-Version": "2022-11-28",
            },
            timeout=30.0,
            follow_redirects=False,
            trust_env=False,
        ) as client:
            if publication_actors:
                _preflight_publication_actor(client, publication_actors)
            for config_policy in config.repositories:
                policy = _github_policy(config_policy)
                identities.append(GitHubReader(client, policy).repository_identity())
    finally:
        token = ""
    return tuple(identities)


def _signing_key_configured(
    configured_key: str | None,
    *,
    git_executable: str,
    signing_program: str,
    signing_format: SigningFormat = SigningFormat.OPENPGP,
    signing_public_key: str | None = None,
    temporary_root: Path | None = None,
) -> bool:
    """Prove the exact configured key can sign in Guardian's isolated context."""

    if signing_format is SigningFormat.SSH:
        return _ssh_signing_key_configured(
            configured_key,
            signing_public_key=signing_public_key,
            git_executable=git_executable,
            signing_program=signing_program,
            temporary_root=temporary_root,
        )
    if signing_format is not SigningFormat.OPENPGP or signing_public_key is not None:
        return False

    try:
        configured_key = canonical_signing_key(configured_key)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return False
    if not _command_available((git_executable,)) or not _command_available(
        (signing_program,)
    ):
        return False
    configured_home = os.environ.get("GNUPGHOME")
    signing_home = (
        Path(configured_home).expanduser()
        if configured_home
        else Path.home() / ".gnupg"
    )
    try:
        resolved_signing_home = resolve_trusted_private_directory(signing_home)
    except (ValueError, subprocess.SubprocessError):
        return False
    try:
        with tempfile.TemporaryDirectory(prefix="localize-guardian-signing-probe-") as raw:
            root = Path(raw)
            isolated_home = root / "home"
            repository = root / "repository"
            isolated_home.mkdir(mode=0o700)
            environment = {
                "GIT_CONFIG_GLOBAL": os.devnull,
                "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_TERMINAL_PROMPT": "0",
                "GNUPGHOME": str(resolved_signing_home),
                "HOME": str(isolated_home),
                "LC_ALL": "C",
                "PATH": os.defpath,
            }
            git_prefix = [
                git_executable,
                "-c",
                f"gpg.program={signing_program}",
            ]
            commands = (
                [*git_prefix, "init", "--quiet", str(repository)],
                [
                    *git_prefix,
                    "-C",
                    str(repository),
                    "-c",
                    "user.name=Localize Guardian",
                    "-c",
                    "user.email=localize-guardian@users.noreply.github.com",
                    "commit",
                    "--allow-empty",
                    "--no-verify",
                    f"-S{configured_key}",
                    "--message=Localize Guardian signing probe",
                ],
                [
                    *git_prefix,
                    "-C",
                    str(repository),
                    "verify-commit",
                    "--raw",
                    "HEAD",
                ],
            )
            process_limits = ProcessLimits.for_timeout(
                20,
                max_file_size_bytes=8 * 1024 * 1024,
            )
            workspace_quota = WorkspaceQuota.capture(
                root,
                max_growth_bytes=16 * 1024 * 1024,
                max_added_entries=1_000,
            )
            verification_output = ""
            for command in commands:
                completed = run_bounded_process(
                    command,
                    check=False,
                    capture_output=True,
                    text=True,
                    shell=False,
                    timeout=20,
                    env=environment,
                    start_new_session=True,
                    limits=process_limits,
                    workspace_quota=workspace_quota,
                )
                if completed.returncode != 0:
                    return False
                verification_output = "\n".join(
                    (completed.stdout or "", completed.stderr or "")
                )
            if not signature_matches(verification_output, configured_key):
                return False
    except (OSError, subprocess.SubprocessError, ProcessResourceError):
        return False
    return True


def _ssh_signing_key_configured(
    configured_key: str | None,
    *,
    signing_public_key: str | None,
    git_executable: str,
    signing_program: str,
    temporary_root: Path | None,
) -> bool:
    """Actually sign and verify with one exact agent-backed SSH public key."""

    try:
        fingerprint = canonical_ssh_fingerprint(configured_key)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return False
    if signing_public_key is None:
        return False
    if not _command_available((git_executable,)) or not _command_available(
        (signing_program,)
    ):
        return False
    try:
        require_absolute_trusted_executable(
            (signing_program,),
            field="runtime.signing_program",
        )
        parent = None if temporary_root is None else str(temporary_root)
        with tempfile.TemporaryDirectory(
            prefix="localize-guardian-ssh-probe-",
            dir=parent,
        ) as raw:
            root = Path(raw).resolve(strict=True)
            root.chmod(0o700)
            isolated_home = root / "home"
            repository = root / "repository"
            isolated_home.mkdir(mode=0o700)
            with snapshot_ssh_signing_material(
                public_key_path=signing_public_key,
                expected_fingerprint=fingerprint,
                signing_program=signing_program,
                # Use the runtime's snapshot parent. Nesting inside the probe
                # can exceed macOS's Unix-socket path limit for agent.sock.
                temporary_root=temporary_root if temporary_root is not None else root,
            ) as material:
                signing_socket = ssh_agent_environment(
                    temporary_root=material.root,
                )
                environment = {
                    "GIT_CONFIG_GLOBAL": os.devnull,
                    "GIT_CONFIG_NOSYSTEM": "1",
                    "GIT_TERMINAL_PROMPT": "0",
                    "HOME": str(isolated_home),
                    "LC_ALL": "C",
                    "PATH": os.defpath,
                }
                git_prefix = [
                    git_executable,
                    "-c",
                    "gpg.format=ssh",
                    "-c",
                    f"gpg.ssh.program={signing_program}",
                    "-c",
                    f"gpg.ssh.allowedSignersFile={material.allowed_signers}",
                    "-c",
                    "gpg.minTrustLevel=fully",
                ]
                commands = (
                    (
                        [*git_prefix, "init", "--quiet", str(repository)],
                        environment,
                    ),
                    (
                        [
                            *git_prefix,
                            "-C",
                            str(repository),
                            "-c",
                            "user.name=Localize Guardian",
                            "-c",
                            "user.email=localize-guardian@users.noreply.github.com",
                            "commit",
                            "--allow-empty",
                            "--no-verify",
                            f"-S{material.public_key}",
                            "--message=Localize Guardian signing probe",
                        ],
                        {**environment, **signing_socket},
                    ),
                    (
                        [
                            *git_prefix,
                            "-C",
                            str(repository),
                            "verify-commit",
                            "--raw",
                            "HEAD",
                        ],
                        environment,
                    ),
                )
                process_limits = ProcessLimits.for_timeout(
                    20,
                    max_file_size_bytes=8 * 1024 * 1024,
                )
                workspace_quota = WorkspaceQuota.capture(
                    root,
                    max_growth_bytes=16 * 1024 * 1024,
                    max_added_entries=1_000,
                )
                verification_output = ""
                for command, command_environment in commands:
                    completed = run_bounded_process(
                        command,
                        check=False,
                        capture_output=True,
                        text=True,
                        shell=False,
                        timeout=20,
                        env=command_environment,
                        start_new_session=True,
                        limits=process_limits,
                        workspace_quota=workspace_quota,
                    )
                    if completed.returncode != 0:
                        return False
                    verification_output = "\n".join(
                        (completed.stdout or "", completed.stderr or "")
                    )
                return ssh_signature_matches(verification_output, fingerprint)
    except (
        ExecutableTrustError,
        OSError,
        SigningError,
        ValueError,
        subprocess.SubprocessError,
        ProcessResourceError,
    ):
        return False


def _command_available(command: Sequence[str]) -> bool:
    if not command:
        return False
    executable = command[0]
    if "/" in executable:
        path = Path(executable).expanduser()
        return path.is_absolute() and path.is_file() and os.access(path, os.X_OK)
    return shutil.which(executable) is not None


def _require_absolute_executable(command: Sequence[str], *, field: str) -> None:
    try:
        require_absolute_trusted_executable(command, field=field)
    except ExecutableTrustError as exc:
        raise GuardianCLIError(str(exc)) from None


def _require_absolute_direct_executable(
    command: Sequence[str],
    *,
    field: str,
    allow_github_cli: bool = False,
) -> None:
    try:
        require_absolute_trusted_direct_executable(
            command,
            field=field,
            allow_github_cli=allow_github_cli,
        )
    except ExecutableTrustError as exc:
        raise GuardianCLIError(str(exc)) from None


def _require_absolute_sandbox_wrapper(
    command: Sequence[str],
    *,
    field: str,
) -> None:
    try:
        require_absolute_trusted_wrapper(command, field=field)
    except ExecutableTrustError as exc:
        raise GuardianCLIError(str(exc)) from None


def _resolved_doctor_command(command: Sequence[str]) -> tuple[str, ...]:
    """Resolve one interactive command before applying unattended trust rules."""

    if not command:
        raise GuardianCLIError("Guardian command is empty.")
    executable = command[0]
    if "/" in executable:
        candidate = Path(executable).expanduser()
        if not candidate.is_absolute():
            raise GuardianCLIError("Guardian executable path must be absolute.")
        resolved = str(candidate)
    else:
        discovered = shutil.which(executable)
        if discovered is None:
            raise GuardianCLIError("Guardian executable was not found.")
        resolved = discovered
    return (resolved, *command[1:])


def _doctor_executables_trusted(config: GuardianConfig) -> bool:
    """Validate every executable before doctor invokes any external process."""

    ordinary_commands: list[tuple[Sequence[str], str]] = [
        ((config.runtime.codex_executable,), "runtime.codex_executable"),
        ((config.runtime.git_executable,), "runtime.git_executable"),
    ]
    if config.mode in _WRITE_MODES:
        ordinary_commands.append(
            ((config.runtime.signing_program,), "runtime.signing_program")
        )
    direct_commands: list[tuple[Sequence[str], str, bool]] = [
        (
            config.runtime.github_token_command,
            "runtime.github_token_command",
            True,
        )
    ]
    if config.runtime.codex_auth_mode is CodexAuthMode.API_KEY:
        direct_commands.append(
            (
                config.runtime.codex_api_key_command,
                "runtime.codex_api_key_command",
                False,
            )
        )

    try:
        for command, field in ordinary_commands:
            require_absolute_trusted_executable(
                _resolved_doctor_command(command),
                field=field,
            )
        for command, field, allow_github_cli in direct_commands:
            require_absolute_trusted_direct_executable(
                _resolved_doctor_command(command),
                field=field,
                allow_github_cli=allow_github_cli,
            )
        if config.mode is GuardianMode.PROPOSE_PREVENTION:
            for index, repository in enumerate(config.repositories):
                prevention = repository.prevention
                if prevention is None:
                    continue
                require_absolute_trusted_wrapper(
                    _resolved_doctor_command(prevention.sandbox_argv_prefix),
                    field=f"repositories.{index}.prevention.sandbox_argv_prefix",
                )
                for test_index, command in enumerate(prevention.focused_test_argv):
                    require_absolute_trusted_executable(
                        _resolved_doctor_command(command),
                        field=(
                            f"repositories.{index}.prevention."
                            f"focused_test_argv.{test_index}"
                        ),
                    )
    except (ExecutableTrustError, GuardianCLIError):
        return False
    return True


def _credential_helper_works(command: Sequence[str]) -> bool:
    """Validate one credential helper while discarding its secret output."""

    if not _command_available(command):
        return False
    try:
        SecretCommand(tuple(command)).read()
    except (CredentialError, ValueError):
        return False
    return True


def _codex_home(config: GuardianConfig) -> Path:
    return Path(os.path.abspath(Path(config.runtime.codex_home).expanduser()))


def _codex_login_environment(codex_home: Path) -> dict[str, str]:
    environment = {
        "CODEX_HOME": str(codex_home),
        "HOME": str(Path.home()),
        "NO_COLOR": "1",
        "PATH": os.defpath,
    }
    for key in (
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
        "REQUESTS_CA_BUNDLE",
        "SSL_CERT_DIR",
        "SSL_CERT_FILE",
        "TERM",
    ):
        value = os.environ.get(key)
        if value:
            environment[key] = value
    return environment


def _codex_chatgpt_login_ready(config: GuardianConfig) -> bool:
    """Verify the dedicated file-backed login without making a model call."""

    if config.runtime.codex_auth_mode is not CodexAuthMode.CHATGPT:
        return False
    try:
        codex_home = _validate_subscription_codex_home(config)
        settings = [
            argument
            for setting in codex_auth_config(CodexAuthMode.CHATGPT)
            for argument in ("-c", setting)
        ]
        completed = run_bounded_process(
            [
                config.runtime.codex_executable,
                "login",
                *settings,
                "status",
            ],
            shell=False,
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
            env=_codex_login_environment(codex_home),
            start_new_session=True,
            limits=ProcessLimits.for_timeout(
                30,
                max_file_size_bytes=2 * 1024 * 1024,
            ),
        )
        if completed.returncode != 0:
            return False
        status = "\n".join((completed.stdout or "", completed.stderr or ""))
        if "chatgpt" not in status.casefold():
            return False
        _validate_subscription_codex_home(config)
    except (OSError, subprocess.SubprocessError, ProcessResourceError, GuardianRuntimeError):
        return False
    return True


def _cmd_login(args: argparse.Namespace) -> int:
    """Create or refresh the dedicated Guardian ChatGPT subscription login."""

    config_path = _resolved_config_path(args.config)
    try:
        config = _load_config_or_raise(config_path)
        if config.runtime.codex_auth_mode is not CodexAuthMode.CHATGPT:
            raise GuardianCLIError(
                "guardian login is available only with codex_auth_mode: chatgpt."
            )
        if not _command_available((config.runtime.codex_executable,)):
            raise GuardianCLIError("Codex executable was not found.")
        codex_home = _codex_home(config)
        _ensure_operator_directory(codex_home, purpose="Codex home")
        _ensure_private_directory(codex_home)
        auth_file = codex_home / "auth.json"
        if auth_file.exists() or auth_file.is_symlink():
            _validate_private_regular_file(auth_file, mode=0o600)
        settings = [
            argument
            for setting in codex_auth_config(CodexAuthMode.CHATGPT)
            for argument in ("-c", setting)
        ]
        previous_umask = os.umask(0o077)
        try:
            completed = subprocess.run(
                [
                    config.runtime.codex_executable,
                    "login",
                    *settings,
                    "--device-auth",
                ],
                shell=False,
                check=False,
                env=_codex_login_environment(codex_home),
            )
        finally:
            os.umask(previous_umask)
        if completed.returncode != 0 or not _codex_chatgpt_login_ready(config):
            raise GuardianCLIError("Codex ChatGPT login did not complete safely.")
    except GuardianCLIError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:
        print(
            f"error: Guardian login failed ({type(exc).__name__}).",
            file=sys.stderr,
        )
        return 1
    print(f"Codex ChatGPT subscription login ready: {codex_home}")
    return 0


def _check_schema() -> None:
    try:
        schema = json.loads(RESULT_SCHEMA_PATH.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
    except Exception as exc:
        raise GuardianCLIError("Guardian result schema is missing or invalid.") from exc


@contextmanager
def _doctor_network_canaries() -> Iterator[tuple[int, str]]:
    """Hold live TCP and Unix endpoints that an effective profile cannot reach."""

    unix_root: Path | None = None
    unix_listener: socket.socket | None = None
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as tcp_listener:
        tcp_listener.bind(("127.0.0.1", 0))
        tcp_listener.listen(1)
        unix_socket_path = ""
        try:
            if hasattr(socket, "AF_UNIX"):
                unix_root = Path(tempfile.mkdtemp(prefix="lg-"))
                unix_socket_path = str(unix_root / "canary.sock")
                unix_listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                unix_listener.bind(unix_socket_path)
                unix_listener.listen(1)
            yield int(tcp_listener.getsockname()[1]), unix_socket_path
        finally:
            if unix_listener is not None:
                unix_listener.close()
            if unix_root is not None:
                shutil.rmtree(unix_root)


def _codex_capability_probe(
    executable: str,
    *,
    auth_mode: CodexAuthMode = CodexAuthMode.CHATGPT,
    authoring: bool = False,
) -> bool:
    """Prove exact non-interactive flags and one named profile without a model call."""

    try:
        with tempfile.TemporaryDirectory(prefix="localize-guardian-doctor-") as raw:
            root = Path(raw)
            root.chmod(0o700)
            home = root / "home"
            codex_home = root / "codex-home"
            evidence = root / "evidence"
            for directory in (home, codex_home, evidence):
                directory.mkdir(mode=0o700)
            nonce = os.urandom(16).hex()
            inside_read = evidence / "inside-read"
            outside_read = root / "outside-read"
            inside_read.write_text(nonce, encoding="utf-8")
            outside_read.write_text(nonce, encoding="utf-8")
            inside_read.chmod(0o400)
            outside_read.chmod(0o400)
            environment = {
                "CODEX_HOME": str(codex_home),
                "HOME": str(home),
                "NO_COLOR": "1",
                "PATH": os.environ.get("PATH", os.defpath),
                "TMPDIR": str(root),
            }
            permission_config = (
                guardian_prevention_author_permission_config()
                if authoring
                else guardian_assessment_permission_config()
            )
            permission_profile = (
                guardian_prevention_author_permission_profile()
                if authoring
                else guardian_assessment_permission_profile()
            )
            config_arguments = [
                argument
                for setting in (*codex_auth_config(auth_mode), *permission_config)
                for argument in ("-c", setting)
            ]
            process_limits = ProcessLimits.for_timeout(
                15,
                max_file_size_bytes=4 * 1024 * 1024,
                require_linux_cgroup=True,
            )
            cgroup_escape_target = linux_cgroup_parent_procs()
            workspace_quota = WorkspaceQuota.capture(
                root,
                max_growth_bytes=16 * 1024 * 1024,
                max_added_entries=1_000,
            )
            flag_probe = run_bounded_process(
                [
                    executable,
                    "--ask-for-approval",
                    "never",
                    *config_arguments,
                    "exec",
                    "--ephemeral",
                    "--ignore-user-config",
                    "--ignore-rules",
                    "--strict-config",
                    "--help",
                ],
                shell=False,
                capture_output=True,
                text=True,
                check=False,
                timeout=15,
                env=environment,
                start_new_session=True,
                limits=process_limits,
                workspace_quota=workspace_quota,
            )
            if flag_probe.returncode != 0:
                return False

            with _doctor_network_canaries() as (tcp_port, unix_socket_path):
                permission_probe = run_bounded_process(
                    [
                        executable,
                        *config_arguments,
                        "sandbox",
                        "--permission-profile",
                        permission_profile,
                        "--cd",
                        str(evidence),
                        "--",
                        "/bin/sh",
                        "-c",
                        _CODEX_PERMISSION_PROBE,
                        "guardian-permission-probe",
                        str(inside_read),
                        str(evidence / "inside-write"),
                        str(outside_read),
                        str(root / "outside-write"),
                        nonce,
                        str(tcp_port),
                        unix_socket_path,
                        "1" if authoring else "0",
                        (
                            str(cgroup_escape_target)
                            if cgroup_escape_target is not None
                            else ""
                        ),
                    ],
                    shell=False,
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=15,
                    env=environment,
                    start_new_session=True,
                    limits=process_limits,
                    workspace_quota=workspace_quota,
                )
            return permission_probe.returncode == 0
    except (OSError, subprocess.SubprocessError, ProcessResourceError):
        return False


def _prevention_sandbox_probe(config: GuardianConfig) -> bool:
    """Validate configured test executables and prove each sandbox prefix."""

    seen_prefixes: set[tuple[str, ...]] = set()
    try:
        for repository in config.repositories:
            policy = repository.prevention
            if policy is None:
                continue
            _require_absolute_sandbox_wrapper(
                policy.sandbox_argv_prefix,
                field=f"{repository.base_repo} prevention sandbox",
            )
            for index, argv in enumerate(policy.focused_test_argv):
                _require_absolute_executable(
                    argv,
                    field=f"{repository.base_repo} focused test {index}",
                )
            if policy.sandbox_argv_prefix in seen_prefixes:
                continue
            seen_prefixes.add(policy.sandbox_argv_prefix)
            with tempfile.TemporaryDirectory(
                prefix="localize-guardian-sandbox-doctor-"
            ) as raw:
                root = Path(raw)
                workspace = root / "workspace"
                private = root / "private"
                workspace.mkdir(mode=0o700)
                private.mkdir(mode=0o700)
                runner = SandboxedTestRunner(
                    timeout_seconds=min(15.0, config.limits.run_timeout_seconds)
                )
                runner._prove_confinement(
                    workspace=workspace,
                    private=private,
                    sandbox_prefix=policy.sandbox_argv_prefix,
                    environment=runner._environment(home=private, temp=private),
                )
    except (GuardianCLIError, OSError, ValueError):
        return False
    return bool(seen_prefixes)


def _cmd_init(args: argparse.Namespace) -> int:
    config_path = _resolved_config_path(args.config)
    if config_path.exists() or config_path.is_symlink():
        print(f"error: configuration already exists: {config_path}", file=sys.stderr)
        return 1
    try:
        config_path.parent.mkdir(parents=True, exist_ok=True)
        _ensure_private_directory(guardian_state_dir(config_path))
        _write_exclusive(config_path, _STARTER_CONFIG, mode=0o600)
    except GuardianCLIError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(f"Created report-only Guardian config: {config_path}")
    print("Replace every example identity before the first run.")
    return 0


def _state_directory_doctor(config_path: Path) -> tuple[str, bool]:
    runtime_dir = guardian_state_dir(config_path)
    if not _poll_locking_is_available():
        return "error (process locking is unavailable)", False
    if not runtime_dir.exists() and not runtime_dir.is_symlink():
        if os.access(runtime_dir.parent, os.W_OK):
            try:
                _probe_poll_lock_semantics(runtime_dir.parent)
            except GuardianRuntimeError:
                return "error (paths must be regular and private)", False
            return "ready (created on first run or install)", True
        return "error (parent directory is not writable)", False
    try:
        _ensure_private_directory(runtime_dir)
        state_path = guardian_state_path(config_path)
        _validate_private_state_artifacts(state_path)
        _preflight_poll_lock(runtime_dir)
        _probe_poll_lock_semantics(runtime_dir)
    except (GuardianCLIError, GuardianRuntimeError):
        return "error (paths must be regular and private)", False
    return "ok", True


def _existing_safe_probe_parent(path: Path) -> Path | None:
    """Return an existing trusted parent without creating or changing it."""

    trusted_owners = {0}
    if hasattr(os, "getuid"):
        trusted_owners.add(os.getuid())
    try:
        metadata = path.lstat()
        if (
            not path.is_absolute()
            or stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISDIR(metadata.st_mode)
            or not _owned_by_current_user(metadata)
            or not is_trusted_directory(
                metadata,
                trusted_owners=trusted_owners,
            )
        ):
            return None
        for ancestor in path.parents:
            ancestor_metadata = ancestor.lstat()
            if stat.S_ISLNK(ancestor_metadata.st_mode) or not is_trusted_directory(
                ancestor_metadata,
                trusted_owners=trusted_owners,
            ):
                return None
    except OSError:
        return None
    return path


def _operator_pipeline_config_doctor(
    config: GuardianConfig,
    *,
    config_path: Path,
) -> tuple[str, bool]:
    """Exercise the production snapshot path without external or model work."""

    operator_count = sum(
        repository.pipeline_config_source is PipelineConfigSource.OPERATOR
        for repository in config.repositories
    )
    if operator_count == 0:
        return "not configured (repository base mode)", True

    runtime_dir = guardian_state_dir(config_path)
    try:
        if runtime_dir.exists():
            _ensure_private_directory(runtime_dir)
            with _snapshot_operator_pipeline_configs(
                config=config,
                guardian_config_path=config_path,
                state_directory=runtime_dir,
            ) as snapshots:
                if len(snapshots) != operator_count:
                    raise GuardianRuntimeError(
                        "Guardian operator pipeline config is unavailable or unsafe."
                    )
        else:
            with tempfile.TemporaryDirectory(
                prefix=".guardian-operator-config-doctor-",
                dir=config_path.parent,
            ) as temporary_directory:
                scratch = Path(temporary_directory)
                scratch.chmod(0o700)
                with _snapshot_operator_pipeline_configs(
                    config=config,
                    guardian_config_path=config_path,
                    state_directory=scratch,
                ) as snapshots:
                    if len(snapshots) != operator_count:
                        raise GuardianRuntimeError(
                            "Guardian operator pipeline config is unavailable or unsafe."
                        )
    except (GuardianCLIError, GuardianRuntimeError, OSError):
        return "error (private config or glossary is unavailable or unsafe)", False
    return f"ok ({operator_count} snapshotted)", True


def _cmd_doctor(args: argparse.Namespace) -> int:
    config_path = _resolved_config_path(args.config)
    print("Guardian doctor")
    try:
        config = _load_config_or_raise(config_path)
    except GuardianCLIError as exc:
        print(f"config: error ({exc})")
        return 1

    healthy = True
    print(f"config: ok ({config.mode.value})")
    state_status, state_ok = _state_directory_doctor(config_path)
    print(f"state directory: {state_status}")
    healthy &= state_ok

    operator_status, operator_ok = _operator_pipeline_config_doctor(
        config,
        config_path=config_path,
    )
    print(f"operator pipeline configs: {operator_status}")
    healthy &= operator_ok
    if not operator_ok:
        return 1

    executable_trust = _doctor_executables_trusted(config)
    print(
        "executable trust: "
        f"{'ok' if executable_trust else 'error (unavailable or unsafe)'}"
    )
    if not executable_trust:
        return 1

    codex_path = _command_available((config.runtime.codex_executable,))
    print(f"Codex executable: {'ok' if codex_path else 'error (not found)'}")
    print(
        "Codex model/effort: configured "
        f"{config.runtime.codex_model} / {config.runtime.codex_reasoning_effort} "
        "(not capability-validated)"
    )
    healthy &= codex_path
    codex_capabilities = (
        _codex_capability_probe(
            config.runtime.codex_executable,
            auth_mode=config.runtime.codex_auth_mode,
        )
        if codex_path
        else False
    )
    print(
        "Codex capability canary: "
        f"{'ok' if codex_capabilities else 'error (flags or confinement unavailable)'}"
    )
    healthy &= codex_capabilities
    if config.mode is GuardianMode.PROPOSE_PREVENTION:
        author_capabilities = (
            _codex_capability_probe(
                config.runtime.codex_executable,
                auth_mode=config.runtime.codex_auth_mode,
                authoring=True,
            )
            if codex_path
            else False
        )
        print(
            "Codex authoring canary: "
            f"{'ok' if author_capabilities else 'error (confinement unavailable)'}"
        )
        healthy &= author_capabilities
        prevention_sandbox = _prevention_sandbox_probe(config)
        print(
            "Prevention test sandbox canary: "
            f"{'ok' if prevention_sandbox else 'error (confinement unavailable)'}"
        )
        healthy &= prevention_sandbox
    try:
        _check_schema()
    except GuardianCLIError:
        print("result schema: error")
        healthy = False
    else:
        print("result schema: ok")

    git_ready = _command_available((config.runtime.git_executable,))
    write_mode = config.mode in _WRITE_MODES
    signing_program_ready = (
        _command_available((config.runtime.signing_program,)) if write_mode else True
    )
    github_helper = _command_available(config.runtime.github_token_command)
    print(f"Git executable: {'ok' if git_ready else 'error (not found)'}")
    if write_mode:
        print(
            "Signing program: "
            f"{'ok' if signing_program_ready else 'error (not found)'}"
        )
    else:
        print(f"Signing program: not required ({config.mode.value} mode)")
    print(
        "GitHub credential helper: "
        f"{'ok' if github_helper else 'error (executable not found)'}"
    )
    healthy &= git_ready and github_helper
    if write_mode:
        healthy &= signing_program_ready

    if github_helper:
        try:
            identities = _probe_github(config)
        except Exception:
            print("GitHub read-only probe: error")
            healthy = False
        else:
            for identity in identities:
                visibility = "private" if identity.private else "public"
                print(
                    f"repository {identity.full_name}: ok "
                    f"({visibility}, id={identity.repository_id})"
                )

    api_key_command = config.runtime.codex_api_key_command
    if config.runtime.codex_auth_mode is CodexAuthMode.CHATGPT:
        chatgpt_ready = codex_path and _codex_chatgpt_login_ready(config)
        print(
            "Codex ChatGPT subscription login: "
            f"{'ok' if chatgpt_ready else 'error (run guardian login)'}"
        )
        healthy &= chatgpt_ready
    elif api_key_command:
        api_key_ready = _credential_helper_works(api_key_command)
        print(f"Codex API key helper: {'ok' if api_key_ready else 'error'}")
        healthy &= api_key_ready
    else:
        print("Codex API credential: error (configure a helper)")
        healthy = False

    configured_signing_key = config.runtime.signing_key
    state_directory = guardian_state_dir(config_path)
    signing_probe_root = (
        state_directory
        if state_ok and state_directory.is_dir() and not state_directory.is_symlink()
        else _existing_safe_probe_parent(config_path.parent)
    )
    if not write_mode:
        print(f"commit signing: not required ({config.mode.value} mode)")
    elif git_ready and signing_program_ready and _signing_key_configured(
        configured_signing_key,
        git_executable=config.runtime.git_executable,
        signing_program=config.runtime.signing_program,
        signing_format=config.runtime.signing_format,
        signing_public_key=config.runtime.signing_public_key,
        temporary_root=signing_probe_root,
    ):
        print(
            "commit signing: exact key signed and verified in isolation "
            "(verified again before publication)"
        )
    else:
        if configured_signing_key is None:
            print(
                "commit signing: error "
                "(write modes require explicit runtime.signing_key)"
            )
        else:
            print(
                "commit signing: error "
                "(configured key could not sign and verify in isolation)"
            )
        healthy = False

    adapters = list_localization_adapters()
    print(
        "localization adapters: "
        f"ok ({len(adapters)} registered; project adapter checked after base fetch)"
    )
    return 0 if healthy else 1


def _cmd_run(args: argparse.Namespace) -> int:
    config_path = _resolved_config_path(args.config)
    try:
        _load_config_or_raise(config_path)
        _ensure_private_directory(guardian_state_dir(config_path))
        controller = importlib.import_module("localize.guardian.controller")
        run_once = getattr(controller, "run_once")
        result = run_once(config_path=config_path, scheduled=bool(args.scheduled))
        if result is None:
            return 0
        if isinstance(result, bool) or not isinstance(result, int):
            raise TypeError(
                "Guardian controller returned an unsupported result type."
            )
        return result
    except GuardianRuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:
        print(
            f"error: Guardian run failed ({type(exc).__name__}); inspect the private audit log.",
            file=sys.stderr,
        )
        return 1


def _cmd_status(args: argparse.Namespace) -> int:
    """Report bounded audit metadata without disclosing review text or credentials."""
    config_path = _resolved_config_path(args.config)
    try:
        config = _load_config_or_raise(config_path)
    except GuardianCLIError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print("Guardian status")
    print(f"mode: {config.mode.value}")
    try:
        with _locked_existing_state(config_path) as state:
            snapshot = None if state is None else state.status_snapshot(mode=config.mode)
    except Exception:
        print("error: Guardian state is unavailable or invalid.", file=sys.stderr)
        return 1
    if snapshot is None:
        print("state: no runs recorded")
        return 0

    print(f"last completed run: {snapshot.last_completed_run or 'none'}")
    print(f"last successful poll: {snapshot.last_successful_poll or 'none'}")
    print(f"pending feedback revisions: {snapshot.pending_revisions}")
    actions = ", ".join(f"{status}={count}" for status, count in snapshot.actions)
    print(f"actions: {actions or 'none'}")
    health = ", ".join(f"{component}={status}" for component, status in snapshot.health)
    print(f"health: {health or 'none'}")
    print(
        "historical hydration retries: "
        f"pending={snapshot.pending_historical_retries}, "
        f"permanently_vetoed={snapshot.quarantined_historical_retries}"
    )
    print(
        "historical correction attempts: "
        f"pending={snapshot.pending_remediations}, "
        f"opened={snapshot.opened_remediations}, "
        f"abandoned={snapshot.abandoned_remediations}, "
        f"quarantined={snapshot.quarantined_remediations}, "
        f"merged={snapshot.merged_remediations}"
    )
    print(
        "remote correction PRs: "
        f"open={snapshot.remote_exact_open_remediations}, "
        "closed_unmerged_veto="
        f"{snapshot.remote_closed_unmerged_remediations}, "
        f"not_found={snapshot.remote_not_found_remediations}, "
        f"conflict={snapshot.remote_conflict_remediations}"
    )
    print(
        "UTC daily model calls: "
        f"{snapshot.model_calls_today}/{config.limits.max_model_calls_per_day}"
    )
    if config.runtime.codex_auth_mode is CodexAuthMode.API_KEY:
        print(
            "UTC daily committed API cost: "
            f"${snapshot.committed_microusd_today / 1_000_000:.6f}"
        )
    return 0


def _cmd_remediation_list(args: argparse.Namespace) -> int:
    """List exact remediation attempts from the private local ledger."""

    config_path = _resolved_config_path(args.config)
    try:
        _load_config_or_raise(config_path)
        with _locked_existing_state(config_path) as state:
            if state is None:
                records = ()
                details = ()
                total = 0
            else:
                records = state.remediation_drafts_for_operator(
                    limit=args.limit
                )
                details = tuple(
                    (
                        record,
                        state.remediation_resolution(draft_key=record.draft_key),
                        state.latest_remediation_remote_observation(
                            record.draft_key
                        ),
                        state.remediation_source_coverage_for_draft(
                            record.draft_key
                        ),
                        state.remediation_source_coverage_count_for_draft(
                            record.draft_key
                        ),
                    )
                    for record in records
                )
                total = state.remediation_draft_count_for_operator()
    except Exception:
        print(
            "error: Guardian remediation state is unavailable or invalid.",
            file=sys.stderr,
        )
        return 1
    if not records:
        print("No remediation attempts.")
        return 0
    print("Remediation attempts (active first, then terminal history)")
    for record, resolution, observation, coverage, coverage_total in details:
        print(
            f"{record.draft_key} target={record.target_repository} "
            f"target_id={record.target_repository_id} "
            f"phase={record.phase} identity=v{record.branch_identity_version} "
            f"branch={record.branch}"
        )
        print(
            f"  target_base: {record.target_base_branch}@{record.target_base_sha}"
        )
        print(
            f"  push_repository: {record.push_repository} "
            f"id={record.push_repository_id}"
        )
        print(f"  candidate_commit: {record.candidate_sha}")
        print(
            f"  evidence: {record.evidence_hash} batch={record.batch_hash}"
        )
        if record.draft_number is None:
            print("  pull_request: none")
        else:
            print(f"  pull_request: #{record.draft_number} {record.draft_url}")
        print(f"  resolution: {resolution or 'none'}")
        if observation is None:
            print("  remote: none")
        elif observation.observation != "exact":
            print(
                f"  remote: {observation.observation} "
                f"observed_at={observation.occurred_at.isoformat()}"
            )
        else:
            remote_kind = "draft" if observation.is_draft else "ready"
            print(
                f"  remote: exact state={observation.state} type={remote_kind} "
                f"merged={str(observation.is_merged).lower()} "
                f"base={observation.observed_base_sha} "
                f"observed_at={observation.occurred_at.isoformat()}"
            )
        if not coverage:
            print("  coverage: none")
        for group in coverage:
            linked = ",".join(group.draft_keys) or "none"
            print(
                "  coverage: "
                f"{group.source.repository}#{group.source.pr_number} "
                f"repository_id={group.source.repository_id} "
                f"pull_id={group.source.pull_id} "
                f"pull_revision={group.source.pull_revision_digest} "
                f"authority={group.source.authority_digest} "
                f"policy={group.source.policy_digest} "
                f"head={group.source.head_sha} base={group.source.base_sha} "
                f"reason={group.reason.value} "
                f"effective={str(group.effective).lower()} drafts={linked}"
            )
        if coverage_total > len(coverage):
            print(
                f"  coverage: showing {len(coverage)} of {coverage_total} groups"
            )
    if total > len(records):
        print(f"Showing {len(records)} of {total} remediation attempts.")
    return 0


def _cmd_remediation_quarantine(args: argparse.Namespace) -> int:
    """Append an explicit local terminal marker for one exact attempt."""

    if not args.acknowledge_terminal_local_skip:
        print(
            "error: pass --acknowledge-terminal-local-skip after inspecting the "
            "listed branch and pull request and accepting a terminal local skip.",
            file=sys.stderr,
        )
        return 1
    config_path = _resolved_config_path(args.config)
    try:
        _load_config_or_raise(config_path)
        with _locked_existing_state(config_path) as state:
            if state is None:
                raise GuardianCLIError("Guardian state has no recorded attempts.")
            record = state.remediation_draft_by_key(draft_key=args.draft_key)
            if record is None:
                raise GuardianCLIError("Unknown remediation draft key.")
            if record.target_repository != args.repository:
                raise GuardianCLIError(
                    "Remediation draft key does not match --repository."
                )
            created = state.record_remediation_resolution(
                draft_key=args.draft_key,
                resolution="operator_quarantined",
                terminal_local_skip_acknowledged=True,
            )
    except GuardianCLIError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except Exception:
        print(
            "error: Guardian remediation quarantine failed; "
            "inspect the private audit log.",
            file=sys.stderr,
        )
        return 1
    action = "Quarantined" if created else "Already quarantined"
    print(
        f"{action} remediation attempt {args.draft_key} for {args.repository}."
    )
    print("The exact local attempt is terminally skipped.")
    print("No remote branch or pull request was changed.")
    return 0


def _cmd_history_retry_list(args: argparse.Namespace) -> int:
    """List bounded unresolved historical pull hydration failures."""

    config_path = _resolved_config_path(args.config)
    try:
        _load_config_or_raise(config_path)
        with _locked_existing_state(config_path) as state:
            if state is None:
                records = ()
                total = 0
            else:
                records = state.pending_historical_pull_retry_records(
                    limit=args.limit
                )
                total = state.pending_historical_pull_retry_count()
    except Exception:
        print(
            "error: Guardian historical retry state is unavailable or invalid.",
            file=sys.stderr,
        )
        return 1
    if not records:
        print("No pending historical hydration retries.")
        return 0
    print("Pending historical hydration retries")
    for record in records:
        print(
            f"repository={record.repository} "
            f"repository_id={record.repository_id} "
            f"policy_digest={record.policy_digest} "
            f"pull_id={record.pull_id} "
            f"pr_number={record.pr_number} "
            f"failure={record.failure_type} "
            f"failed_at={record.occurred_at.isoformat()}"
        )
    if total > len(records):
        print(f"Showing {len(records)} of {total} pending historical retries.")
    return 0


def _cmd_history_retry_quarantine(args: argparse.Namespace) -> int:
    """Append a permanent source-PR veto for one exact policy digest."""

    if not args.acknowledge_terminal_local_skip:
        print(
            "error: pass --acknowledge-terminal-local-skip to permanently veto "
            "this source PR under the exact policy digest; later feedback under "
            "that policy will be ignored.",
            file=sys.stderr,
        )
        return 1
    config_path = _resolved_config_path(args.config)
    try:
        _load_config_or_raise(config_path)
        with _locked_existing_state(config_path) as state:
            if state is None:
                raise GuardianCLIError("Guardian state has no pending retries.")
            created = state.record_historical_pull_retry_resolution(
                repository=args.repository,
                repository_id=args.repository_id,
                policy_digest=args.policy_digest,
                pull_id=args.pull_id,
                pr_number=args.pr_number,
                resolution="operator_quarantined",
                terminal_local_skip_acknowledged=True,
            )
    except GuardianCLIError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except Exception:
        print(
            "error: Guardian historical retry quarantine failed; "
            "inspect the private audit log.",
            file=sys.stderr,
        )
        return 1
    action = "Permanently vetoed" if created else "Already permanently vetoed"
    print(
        f"{action} source PR #{args.pr_number} ({args.pull_id}) in "
        f"{args.repository} under policy {args.policy_digest}."
    )
    print(
        "Later comments on this PR are intentionally ignored while that exact "
        "policy digest remains active; a policy change makes it eligible again."
    )
    print("No remote pull request or comment was changed.")
    return 0


def _resolve_localize_executable(raw_executable: str | None) -> Path:
    if raw_executable:
        executable = Path(raw_executable).expanduser().resolve()
    else:
        discovered = shutil.which("localize")
        if discovered is None:
            raise GuardianCLIError(
                "Could not find the localize executable; pass --executable with an absolute path."
            )
        executable = Path(discovered).resolve()
    _require_absolute_executable((str(executable),), field="Localize executable")
    return executable


def _cmd_install(args: argparse.Namespace) -> int:
    config_path = _resolved_config_path(args.config)
    created_files: list[tuple[Path, int, int]] = []

    def remember_created(path: Path, identity: tuple[int, int]) -> None:
        created_files.append((path, *identity))

    def rollback_created() -> None:
        for path, expected_device, expected_inode in reversed(created_files):
            try:
                metadata = path.stat(follow_symlinks=False)
                if (
                    metadata.st_dev == expected_device
                    and metadata.st_ino == expected_inode
                    and stat.S_ISREG(metadata.st_mode)
                ):
                    path.unlink()
            except OSError:
                continue

    try:
        config = _load_config_or_raise(config_path)
        _require_absolute_executable(
            (config.runtime.codex_executable,),
            field="runtime.codex_executable",
        )
        _require_absolute_executable(
            (config.runtime.git_executable,),
            field="runtime.git_executable",
        )
        if config.mode in _WRITE_MODES:
            _require_absolute_executable(
                (config.runtime.signing_program,),
                field="runtime.signing_program",
            )
        _require_absolute_direct_executable(
            config.runtime.github_token_command,
            field="runtime.github_token_command",
            allow_github_cli=True,
        )
        if config.runtime.codex_auth_mode is CodexAuthMode.API_KEY:
            _require_absolute_direct_executable(
                config.runtime.codex_api_key_command,
                field="runtime.codex_api_key_command",
            )
        if config.mode is GuardianMode.PROPOSE_PREVENTION:
            for index, repository in enumerate(config.repositories):
                prevention = repository.prevention
                if prevention is None:
                    continue
                _require_absolute_sandbox_wrapper(
                    prevention.sandbox_argv_prefix,
                    field=f"repositories.{index}.prevention.sandbox_argv_prefix",
                )
                for test_index, command in enumerate(prevention.focused_test_argv):
                    _require_absolute_executable(
                        command,
                        field=(
                            f"repositories.{index}.prevention."
                            f"focused_test_argv.{test_index}"
                        ),
                    )
        if config.runtime.codex_auth_mode is CodexAuthMode.CHATGPT:
            if not _codex_chatgpt_login_ready(config):
                raise GuardianCLIError(
                    "Scheduled runs require a dedicated ChatGPT login; run guardian login."
                )
        elif not config.runtime.codex_api_key_command:
            raise GuardianCLIError(
                "API-key scheduled runs require runtime.codex_api_key_command."
            )
        executable = _resolve_localize_executable(args.executable)
        paths = guardian_install_paths(config_path)
        if paths.runner_path.exists() or paths.runner_path.is_symlink():
            raise GuardianCLIError(
                f"Scheduler runner already exists: {paths.runner_path}"
            )
        if paths.plist_path.exists() or paths.plist_path.is_symlink():
            raise GuardianCLIError(f"LaunchAgent already exists: {paths.plist_path}")
        _ensure_private_directory(guardian_state_dir(config_path))
        _ensure_operator_directory(paths.plist_path.parent)
        for log_path in (paths.stdout_path, paths.stderr_path):
            identity = _ensure_private_file(log_path)
            if identity is not None:
                remember_created(log_path, identity)
        runner = render_launchd_runner(executable=executable, config_path=config_path)
        plist = render_launchd_plist(
            LaunchdSchedule(
                label=paths.label,
                runner_path=paths.runner_path,
                stdout_path=paths.stdout_path,
                stderr_path=paths.stderr_path,
            )
        )
        runner_identity = _write_exclusive(paths.runner_path, runner, mode=0o700)
        remember_created(paths.runner_path, runner_identity)
        plist_identity = _write_exclusive(paths.plist_path, plist, mode=0o600)
        remember_created(paths.plist_path, plist_identity)
    except (GuardianCLIError, SchedulerError) as exc:
        rollback_created()
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:
        rollback_created()
        print(
            f"error: Guardian installation failed ({type(exc).__name__}).",
            file=sys.stderr,
        )
        return 1

    print(f"LaunchAgent staged but not loaded: {paths.plist_path}")
    print(f"runner: {paths.runner_path}")
    print(f"stdout: {paths.stdout_path}")
    print(f"stderr: {paths.stderr_path}")
    print("Inspect these files, then load the LaunchAgent explicitly when ready.")
    return 0


def _positive_operator_integer(raw_value: str) -> int:
    try:
        value = int(raw_value)
    except ValueError:
        raise argparse.ArgumentTypeError("must be a positive integer") from None
    if value <= 0:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return value


def _operator_list_limit(raw_value: str) -> int:
    value = _positive_operator_integer(raw_value)
    if value > 100:
        raise argparse.ArgumentTypeError("must be between 1 and 100")
    return value


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="localize guardian",
        description="Operate the optional, self-hosted localization PR Guardian.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    init_parser = subparsers.add_parser(
        "init", help="Create a report-only starter policy."
    )
    init_parser.add_argument(
        "--config", required=True, help="Operator-owned Guardian YAML path."
    )
    init_parser.set_defaults(func=_cmd_init)

    doctor_parser = subparsers.add_parser(
        "doctor", help="Run read-only prerequisite checks."
    )
    doctor_parser.add_argument(
        "--config", required=True, help="Operator-owned Guardian YAML path."
    )
    doctor_parser.set_defaults(func=_cmd_doctor)

    login_parser = subparsers.add_parser(
        "login",
        help="Authenticate the dedicated Guardian Codex home with ChatGPT.",
    )
    login_parser.add_argument(
        "--config", required=True, help="Operator-owned Guardian YAML path."
    )
    login_parser.set_defaults(func=_cmd_login)

    run_parser = subparsers.add_parser("run", help="Perform one bounded Guardian poll.")
    run_parser.add_argument(
        "--config", required=True, help="Operator-owned Guardian YAML path."
    )
    run_parser.add_argument("--scheduled", action="store_true", help=argparse.SUPPRESS)
    run_parser.set_defaults(func=_cmd_run)

    status_parser = subparsers.add_parser(
        "status", help="Print a redacted audit summary."
    )
    status_parser.add_argument(
        "--config", required=True, help="Operator-owned Guardian YAML path."
    )
    status_parser.set_defaults(func=_cmd_status)

    remediation_parser = subparsers.add_parser(
        "remediation",
        help="Inspect or quarantine historical correction attempts.",
    )
    remediation_subparsers = remediation_parser.add_subparsers(
        dest="remediation_command",
        required=True,
    )
    remediation_list_parser = remediation_subparsers.add_parser(
        "list",
        help="List active and terminal local correction attempts.",
    )
    remediation_list_parser.add_argument(
        "--config", required=True, help="Operator-owned Guardian YAML path."
    )
    remediation_list_parser.add_argument(
        "--limit",
        type=_operator_list_limit,
        default=100,
        help="Maximum rows to print (1-100; default: 100).",
    )
    remediation_list_parser.set_defaults(func=_cmd_remediation_list)
    remediation_quarantine_parser = remediation_subparsers.add_parser(
        "quarantine",
        help="Terminally skip one exact local correction attempt.",
    )
    remediation_quarantine_parser.add_argument(
        "--config", required=True, help="Operator-owned Guardian YAML path."
    )
    remediation_quarantine_parser.add_argument(
        "--draft-key",
        required=True,
        help="Exact 64-character draft key printed by remediation list.",
    )
    remediation_quarantine_parser.add_argument(
        "--repository",
        required=True,
        help="Exact owner/name printed by remediation list.",
    )
    remediation_quarantine_parser.add_argument(
        "--acknowledge-terminal-local-skip",
        action="store_true",
        help=(
            "Confirm a terminal local skip after remote inspection; this does "
            "not change a remote branch or pull request."
        ),
    )
    remediation_quarantine_parser.set_defaults(func=_cmd_remediation_quarantine)

    history_retry_parser = subparsers.add_parser(
        "history-retry",
        help="Inspect or permanently veto historical pull hydration retries.",
    )
    history_retry_subparsers = history_retry_parser.add_subparsers(
        dest="history_retry_command",
        required=True,
    )
    history_retry_list_parser = history_retry_subparsers.add_parser(
        "list",
        help="List pending historical pull hydration retries.",
    )
    history_retry_list_parser.add_argument(
        "--config", required=True, help="Operator-owned Guardian YAML path."
    )
    history_retry_list_parser.add_argument(
        "--limit",
        type=_operator_list_limit,
        default=100,
        help="Maximum rows to print (1-100; default: 100).",
    )
    history_retry_list_parser.set_defaults(func=_cmd_history_retry_list)
    history_retry_quarantine_parser = history_retry_subparsers.add_parser(
        "quarantine",
        help="Permanently veto one source PR under one exact policy digest.",
    )
    history_retry_quarantine_parser.add_argument(
        "--config", required=True, help="Operator-owned Guardian YAML path."
    )
    history_retry_quarantine_parser.add_argument(
        "--repository",
        required=True,
        help="Exact owner/name printed by history-retry list.",
    )
    history_retry_quarantine_parser.add_argument(
        "--repository-id",
        required=True,
        type=_positive_operator_integer,
        help="Exact numeric repository ID printed by history-retry list.",
    )
    history_retry_quarantine_parser.add_argument(
        "--policy-digest",
        required=True,
        help="Exact policy digest printed by history-retry list.",
    )
    history_retry_quarantine_parser.add_argument(
        "--pull-id",
        required=True,
        type=_positive_operator_integer,
        help="Exact numeric pull ID printed by history-retry list.",
    )
    history_retry_quarantine_parser.add_argument(
        "--pr-number",
        required=True,
        type=_positive_operator_integer,
        help="Exact pull-request number printed by history-retry list.",
    )
    history_retry_quarantine_parser.add_argument(
        "--acknowledge-terminal-local-skip",
        action="store_true",
        help=(
            "Confirm a permanent local source-PR veto: later feedback is ignored "
            "under the same policy digest and no remote state is changed."
        ),
    )
    history_retry_quarantine_parser.set_defaults(
        func=_cmd_history_retry_quarantine
    )

    install_parser = subparsers.add_parser(
        "install",
        help="Stage a secret-free macOS LaunchAgent for operator inspection.",
    )
    install_parser.add_argument(
        "--config", required=True, help="Operator-owned Guardian YAML path."
    )
    install_parser.add_argument(
        "--executable",
        default=None,
        help="Absolute localize executable path (defaults to PATH lookup).",
    )
    install_parser.set_defaults(func=_cmd_install)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
