"""Production-only assembly for one bounded Localize Guardian poll.

The core controller is dependency-injected and fully testable without network
or credential access.  This module is the deliberately small trust boundary
that connects it to GitHub, Codex, ephemeral Git workspaces, and private local
state.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from datetime import date, datetime
import errno
import json
import os
from pathlib import Path, PurePosixPath
import stat
import tempfile
import time
from typing import Any

import httpx
import yaml

try:
    import fcntl
except ImportError:  # pragma: no cover - Guardian scheduling is POSIX-only today.
    fcntl = None  # type: ignore[assignment]

from localize.guardian.codex import CodexDriver
from localize.guardian.config import GuardianConfigError, parse_guardian_config_yaml
from localize.guardian.controller import GuardianController, PollOutcome, _stored_feedback
from localize.guardian.credentials import (
    CredentialError,
    CredentialSnapshot,
    SecretCommand,
    credential_snapshot,
    git_credential_environment,
    resolve_model_api_key,
)
from localize.guardian.deadline import PollDeadline, PollDeadlineExceeded
from localize.guardian.executable_trust import (
    ExecutableTrustError,
    require_absolute_trusted_direct_executable,
    require_absolute_trusted_executable,
    require_absolute_trusted_wrapper,
)
from localize.guardian.filesystem_trust import (
    create_or_wait_for_private_directory,
    is_trusted_directory,
)
from localize.guardian.github import (
    BaseRevisionSnapshot,
    ClosedPullScanResult,
    FeedbackRevision,
    GitHubAuthenticationError,
    GitHubReader,
    GitHubRepositoryPolicy,
    GitHubWriteBroker,
    OpenPullPathAuthority,
    PullRequestFeedbackSnapshot,
)
from localize.guardian.models import (
    CodexAuthMode,
    GuardianConfig,
    GuardianMode,
    GuardianSchedule,
    PipelineConfigSnapshot,
    PipelineConfigSource,
    PreventionPolicy,
    RepositoryPolicy,
    SigningFormat,
    TrustedActor,
    pipeline_config_bundle_digest,
)
from localize.guardian.prevention_runtime import (
    PreventionCodexAuthor,
    PreventionCoordinator,
    PreventionGitHubBroker,
    SandboxedTestRunner,
)
from localize.guardian.remediation import (
    RemediationCoordinator,
    RemediationGitHubBroker,
)
from localize.guardian.scheduler import is_run_due
from localize.guardian.signing import (
    SSHSigningMaterial,
    SigningError,
    canonical_signing_key,
    canonical_ssh_fingerprint,
    snapshot_ssh_signing_material,
)
from localize.guardian.state import (
    GuardianState,
    HistoricalPullReference,
    OpenPullAuthorityReference,
    _validate_sqlite_state_artifacts,
)
from localize.guardian.workspace import (
    ExactRevision,
    HistoricalRevision,
    materialize_exact_checkout,
    materialize_historical_checkout,
)


_GITHUB_API_URL = "https://api.github.com"
_GITHUB_HOST = "github.com"
_POLL_ATTEMPT_COMPONENT = "guardian-poll-attempt"
_MAX_CONFIG_BYTES = 1_048_576
_MAX_CODEX_AUTH_BYTES = 1_048_576
_MAX_OPERATOR_PIPELINE_FILE_BYTES = 1_048_576
_POLL_LOCK_INITIALIZATION_TIMEOUT_SECONDS = 1.0
_POLL_LOCK_RETRY_SECONDS = 0.002
_WRITE_MODES = frozenset(
    {
        GuardianMode.APPLY_OWNED_TRANSLATIONS,
        GuardianMode.PROPOSE_PREVENTION,
    }
)


class GuardianRuntimeError(RuntimeError):
    """A redacted production-wiring failure safe for operator output."""


class _GuardianPollAlreadyRunning(RuntimeError):
    """Signal that another process owns this config's exclusive poll lock."""


def _resolved_config_path(path: str | Path) -> Path:
    """Return an absolute path without silently following a symlinked leaf."""

    return Path(os.path.abspath(Path(path).expanduser()))


def _trusted_owners() -> frozenset[int]:
    owners = {0}
    if hasattr(os, "getuid"):
        owners.add(os.getuid())
    return frozenset(owners)


def _validate_trusted_ancestors(path: Path) -> None:
    owners = _trusted_owners()
    for ancestor in reversed(path.parents):
        try:
            metadata = ancestor.stat(follow_symlinks=False)
        except OSError:
            raise GuardianRuntimeError(
                "Guardian configuration is unavailable or unsafe."
            ) from None
        if ancestor.is_symlink() or not is_trusted_directory(
            metadata,
            trusted_owners=owners,
        ):
            raise GuardianRuntimeError(
                "Guardian configuration is unavailable or unsafe."
            )


def load_trusted_guardian_config(path: Path) -> GuardianConfig:
    """Parse the exact regular file verified through one non-following descriptor."""

    _validate_trusted_ancestors(path)
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError:
        raise GuardianRuntimeError(
            "Guardian configuration is unavailable or unsafe."
        ) from None
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) & 0o022
            or (hasattr(os, "getuid") and metadata.st_uid != os.getuid())
            or metadata.st_size > _MAX_CONFIG_BYTES
        ):
            raise GuardianRuntimeError(
                "Guardian configuration is unavailable or unsafe."
            )
        with os.fdopen(descriptor, "r", encoding="utf-8", closefd=False) as source:
            raw_text = source.read(_MAX_CONFIG_BYTES + 1)
        if len(raw_text.encode("utf-8")) > _MAX_CONFIG_BYTES:
            raise GuardianRuntimeError(
                "Guardian configuration is unavailable or unsafe."
            )
    except (OSError, UnicodeError):
        raise GuardianRuntimeError(
            "Guardian configuration is unavailable or unsafe."
        ) from None
    finally:
        os.close(descriptor)
    try:
        return parse_guardian_config_yaml(raw_text)
    except GuardianConfigError:
        raise GuardianRuntimeError("Guardian configuration is invalid.") from None


def _private_state_paths(config_path: Path) -> tuple[Path, Path]:
    directory = config_path.parent / ".guardian"
    return directory, directory / "state.sqlite3"


def _prepare_private_state(config_path: Path) -> tuple[Path, Path]:
    """Create or validate the non-shared Guardian state boundary."""

    directory, database = _private_state_paths(config_path)
    try:
        metadata = create_or_wait_for_private_directory(directory)
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or (hasattr(os, "getuid") and metadata.st_uid != os.getuid())
            or stat.S_IMODE(metadata.st_mode) != 0o700
        ):
            raise GuardianRuntimeError("Guardian state path must remain private.")

    except GuardianRuntimeError:
        raise
    except OSError:
        raise GuardianRuntimeError("Guardian state path must remain private.") from None
    return directory, database


def _poll_locking_is_available() -> bool:
    """Return whether this platform provides the required process lock."""

    return fcntl is not None and callable(getattr(fcntl, "flock", None))


def _poll_lock_descriptor_metadata(descriptor: int) -> os.stat_result:
    try:
        return os.fstat(descriptor)
    except OSError:
        raise GuardianRuntimeError(
            "Guardian poll lock is unavailable or unsafe."
        ) from None


def _validate_poll_lock_descriptor(descriptor: int) -> os.stat_result:
    """Require the exact private regular inode used for process locking."""

    metadata = _poll_lock_descriptor_metadata(descriptor)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or (hasattr(os, "getuid") and metadata.st_uid != os.getuid())
        or stat.S_IMODE(metadata.st_mode) != 0o600
    ):
        raise GuardianRuntimeError("Guardian poll lock is unavailable or unsafe.")
    return metadata


def _poll_lock_inode_may_be_initializing(metadata: os.stat_result) -> bool:
    """Recognize only the restrictive-umask window of our exclusive creator."""

    mode = stat.S_IMODE(metadata.st_mode)
    return (
        stat.S_ISREG(metadata.st_mode)
        and metadata.st_nlink == 1
        and (not hasattr(os, "getuid") or metadata.st_uid == os.getuid())
        and metadata.st_size == 0
        and mode != 0o600
        and mode & ~0o600 == 0
    )


def _poll_lock_path_may_be_initializing_or_ready(lock_path: Path) -> bool:
    """Recognize the safe states around a creator's final chmod."""

    try:
        metadata = lock_path.stat(follow_symlinks=False)
    except OSError:
        return False
    return _poll_lock_inode_may_be_initializing(metadata) or (
        stat.S_ISREG(metadata.st_mode)
        and metadata.st_nlink == 1
        and (not hasattr(os, "getuid") or metadata.st_uid == os.getuid())
        and metadata.st_size == 0
        and stat.S_IMODE(metadata.st_mode) == 0o600
    )


def _open_private_poll_lock(lock_path: Path) -> int:
    """Create an exact 0600 lock or open a previously validated lock inode."""

    flags = os.O_RDWR
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    deadline = time.monotonic() + _POLL_LOCK_INITIALIZATION_TIMEOUT_SECONDS
    while True:
        created = False
        try:
            try:
                descriptor = os.open(
                    lock_path,
                    flags | os.O_CREAT | os.O_EXCL,
                    0o600,
                )
                created = True
            except FileExistsError:
                descriptor = os.open(lock_path, flags)
        except FileNotFoundError:
            if time.monotonic() < deadline:
                time.sleep(_POLL_LOCK_RETRY_SECONDS)
                continue
            raise GuardianRuntimeError(
                "Guardian poll lock is unavailable or unsafe."
            ) from None
        except PermissionError:
            if (
                time.monotonic() < deadline
                and _poll_lock_path_may_be_initializing_or_ready(lock_path)
            ):
                time.sleep(_POLL_LOCK_RETRY_SECONDS)
                continue
            raise GuardianRuntimeError(
                "Guardian poll lock is unavailable or unsafe."
            ) from None
        except OSError:
            raise GuardianRuntimeError(
                "Guardian poll lock is unavailable or unsafe."
            ) from None

        try:
            if created:
                os.fchmod(descriptor, 0o600)
            _validate_poll_lock_descriptor(descriptor)
            return descriptor
        except GuardianRuntimeError:
            try:
                metadata = _poll_lock_descriptor_metadata(descriptor)
            except GuardianRuntimeError:
                os.close(descriptor)
                raise
            os.close(descriptor)
            if (
                not created
                and time.monotonic() < deadline
                and _poll_lock_inode_may_be_initializing(metadata)
            ):
                time.sleep(_POLL_LOCK_RETRY_SECONDS)
                continue
            raise
        except OSError:
            os.close(descriptor)
            raise GuardianRuntimeError(
                "Guardian poll lock is unavailable or unsafe."
            ) from None


def _preflight_poll_lock(state_directory: Path) -> None:
    """Validate an existing lock inode without creating or acquiring it."""

    if not _poll_locking_is_available():
        raise GuardianRuntimeError(
            "Guardian process locking is unavailable on this platform."
        )
    lock_path = state_directory / "poll.lock"
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if hasattr(os, "O_NONBLOCK"):
        flags |= os.O_NONBLOCK
    try:
        descriptor = os.open(lock_path, flags)
    except FileNotFoundError:
        return
    except OSError:
        raise GuardianRuntimeError(
            "Guardian poll lock is unavailable or unsafe."
        ) from None
    try:
        _validate_poll_lock_descriptor(descriptor)
    finally:
        os.close(descriptor)


def _probe_poll_lock_semantics(parent_directory: Path) -> None:
    """Prove exclusive contention and release on a disposable private inode."""

    try:
        with tempfile.TemporaryDirectory(
            prefix=".guardian-poll-lock-doctor-",
            dir=parent_directory,
        ) as raw_directory:
            probe_directory = Path(raw_directory)
            probe_directory.chmod(0o700)
            with _exclusive_poll_lock(probe_directory):
                try:
                    with _exclusive_poll_lock(probe_directory):
                        pass
                except _GuardianPollAlreadyRunning:
                    pass
                else:
                    raise GuardianRuntimeError(
                        "Guardian process locking is unavailable on this platform."
                    )
            with _exclusive_poll_lock(probe_directory):
                pass
    except GuardianRuntimeError:
        raise
    except OSError:
        raise GuardianRuntimeError(
            "Guardian process locking is unavailable on this platform."
        ) from None


@contextmanager
def _exclusive_poll_lock(state_directory: Path) -> Iterator[None]:
    """Hold one private, non-blocking process lock for the complete poll."""

    if not _poll_locking_is_available():
        raise GuardianRuntimeError(
            "Guardian process locking is unavailable on this platform."
        )
    assert fcntl is not None
    lock_path = state_directory / "poll.lock"
    descriptor = _open_private_poll_lock(lock_path)
    locked = False
    try:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            if exc.errno in {errno.EACCES, errno.EAGAIN}:
                raise _GuardianPollAlreadyRunning from None
            raise GuardianRuntimeError(
                "Guardian poll lock is unavailable or unsafe."
            ) from None
        locked = True
        yield
    finally:
        if locked:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            except OSError:
                pass
        os.close(descriptor)


def _validate_private_state_artifacts(database: Path) -> None:
    """Apply one redacted runtime boundary to all SQLite state artifacts."""

    try:
        _validate_sqlite_state_artifacts(database)
    except (OSError, ValueError):
        raise GuardianRuntimeError("Guardian state path must remain private.") from None


def _require_private_operator_directory(path: Path) -> Path:
    """Require a current-user, non-symlink 0700 directory and safe ancestors."""

    try:
        _validate_trusted_ancestors(path)
        metadata = path.stat(follow_symlinks=False)
        if (
            path.is_symlink()
            or not stat.S_ISDIR(metadata.st_mode)
            or (hasattr(os, "getuid") and metadata.st_uid != os.getuid())
            or stat.S_IMODE(metadata.st_mode) != 0o700
        ):
            raise GuardianRuntimeError(
                "Guardian operator pipeline config is unavailable or unsafe."
            )
    except GuardianRuntimeError:
        raise
    except OSError:
        raise GuardianRuntimeError(
            "Guardian operator pipeline config is unavailable or unsafe."
        ) from None
    return path


def _safe_operator_relative_path(raw_path: str) -> PurePosixPath:
    """Normalize one non-empty relative operator path without traversal."""

    if (
        not isinstance(raw_path, str)
        or not raw_path
        or len(raw_path) > 4096
        or not raw_path.isprintable()
        or "\\" in raw_path
        or "\x00" in raw_path
    ):
        raise GuardianRuntimeError(
            "Guardian operator pipeline config is unavailable or unsafe."
        )
    path = PurePosixPath(raw_path)
    if (
        path.is_absolute()
        or any(part in {"", ".", ".."} for part in path.parts)
        or any(character in raw_path for character in "*?[]")
    ):
        raise GuardianRuntimeError(
            "Guardian operator pipeline config is unavailable or unsafe."
        )
    return path


def _read_private_operator_file(
    path: Path,
    *,
    root: Path,
    required: bool,
    deadline: PollDeadline | None = None,
) -> bytes | None:
    """Read one bounded 0600 file through a non-following descriptor."""

    try:
        relative = path.relative_to(root)
    except ValueError:
        raise GuardianRuntimeError(
            "Guardian operator pipeline config is unavailable or unsafe."
        ) from None
    current = root
    for component in relative.parts[:-1]:
        current = current / component
        _require_private_operator_directory(current)

    try:
        leaf_metadata = path.lstat()
    except FileNotFoundError:
        if not required:
            return None
        raise GuardianRuntimeError(
            "Guardian operator pipeline config is unavailable or unsafe."
        ) from None
    except OSError:
        raise GuardianRuntimeError(
            "Guardian operator pipeline config is unavailable or unsafe."
        ) from None
    if stat.S_ISLNK(leaf_metadata.st_mode) or not stat.S_ISREG(leaf_metadata.st_mode):
        raise GuardianRuntimeError(
            "Guardian operator pipeline config is unavailable or unsafe."
        )

    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except FileNotFoundError:
        if not required and not path.is_symlink():
            return None
        raise GuardianRuntimeError(
            "Guardian operator pipeline config is unavailable or unsafe."
        ) from None
    except OSError:
        raise GuardianRuntimeError(
            "Guardian operator pipeline config is unavailable or unsafe."
        ) from None
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_dev != leaf_metadata.st_dev
            or metadata.st_ino != leaf_metadata.st_ino
            or (hasattr(os, "getuid") and metadata.st_uid != os.getuid())
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_size > _MAX_OPERATOR_PIPELINE_FILE_BYTES
        ):
            raise GuardianRuntimeError(
                "Guardian operator pipeline config is unavailable or unsafe."
            )
        chunks: list[bytes] = []
        remaining = _MAX_OPERATOR_PIPELINE_FILE_BYTES + 1
        while remaining:
            if deadline is not None:
                deadline.require_remaining()
            chunk = os.read(descriptor, min(65_536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        content = b"".join(chunks)
        if len(content) > _MAX_OPERATOR_PIPELINE_FILE_BYTES:
            raise GuardianRuntimeError(
                "Guardian operator pipeline config is unavailable or unsafe."
            )
        return content
    except GuardianRuntimeError:
        raise
    except OSError:
        raise GuardianRuntimeError(
            "Guardian operator pipeline config is unavailable or unsafe."
        ) from None
    finally:
        os.close(descriptor)


def _decode_operator_yaml(content: bytes) -> Mapping[str, Any]:
    """Decode one bounded UTF-8 YAML object or fail through the redacted boundary."""

    try:
        payload = yaml.safe_load(content.decode("utf-8"))
    except (UnicodeDecodeError, yaml.YAMLError):
        raise GuardianRuntimeError(
            "Guardian operator pipeline config is unavailable or unsafe."
        ) from None
    if not isinstance(payload, Mapping):
        raise GuardianRuntimeError(
            "Guardian operator pipeline config is unavailable or unsafe."
        )
    return payload


def _copy_private_bundle_file(
    root: Path,
    relative: PurePosixPath,
    content: bytes,
    *,
    deadline: PollDeadline | None = None,
) -> Path:
    """Copy immutable snapshot bytes below a fresh private bundle root."""

    destination = root.joinpath(*relative.parts)
    if deadline is not None:
        deadline.require_remaining()
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    current = root
    for component in relative.parts[:-1]:
        current = current / component
        current.chmod(0o700)
    if deadline is not None:
        deadline.require_remaining()
    destination.write_bytes(content)
    destination.chmod(0o600)
    return destination


@contextmanager
def _snapshot_operator_pipeline_configs(
    *,
    config: GuardianConfig,
    guardian_config_path: Path,
    state_directory: Path,
    deadline: PollDeadline | None = None,
) -> Iterator[dict[str, PipelineConfigSnapshot]]:
    """Snapshot every operator pipeline config before external poll work starts."""

    operator_policies = tuple(
        policy
        for policy in config.repositories
        if policy.pipeline_config_source is PipelineConfigSource.OPERATOR
    )
    if not operator_policies:
        yield {}
        return

    operator_root = _require_private_operator_directory(guardian_config_path.parent)
    with tempfile.TemporaryDirectory(
        prefix="operator-pipeline-config-",
        dir=state_directory,
    ) as temporary_directory:
        snapshot_parent = Path(temporary_directory)
        snapshot_parent.chmod(0o700)
        snapshots: dict[str, PipelineConfigSnapshot] = {}
        for index, policy in enumerate(operator_policies):
            if deadline is not None:
                deadline.require_remaining()
            config_relative = _safe_operator_relative_path(policy.pipeline_config_path)
            live_config_path = operator_root.joinpath(*config_relative.parts)
            if deadline is not None:
                deadline.require_remaining()
            config_bytes = _read_private_operator_file(
                live_config_path,
                root=operator_root,
                required=True,
                deadline=deadline,
            )
            assert config_bytes is not None
            pipeline_config = _decode_operator_yaml(config_bytes)

            configured_glossary = pipeline_config.get("glossary_file_path")
            explicit_glossary = configured_glossary is not None
            if configured_glossary is not None and not isinstance(
                configured_glossary,
                str,
            ):
                raise GuardianRuntimeError(
                    "Guardian operator pipeline config is unavailable or unsafe."
                )
            glossary_relative_to_config = _safe_operator_relative_path(
                configured_glossary or "glossary.json"
            )
            glossary_relative = PurePosixPath(
                *config_relative.parent.parts,
                *glossary_relative_to_config.parts,
            )
            live_glossary_path = operator_root.joinpath(*glossary_relative.parts)
            if deadline is not None:
                deadline.require_remaining()
            glossary_bytes = _read_private_operator_file(
                live_glossary_path,
                root=operator_root,
                required=explicit_glossary,
                deadline=deadline,
            )
            if glossary_bytes is not None:
                try:
                    glossary_payload = json.loads(glossary_bytes.decode("utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError):
                    raise GuardianRuntimeError(
                        "Guardian operator pipeline config is unavailable or unsafe."
                    ) from None
                if not isinstance(glossary_payload, dict):
                    raise GuardianRuntimeError(
                        "Guardian operator pipeline config is unavailable or unsafe."
                    )

            bundle_files = {config_relative.as_posix(): config_bytes}
            if glossary_bytes is not None:
                bundle_files[glossary_relative.as_posix()] = glossary_bytes
            if deadline is not None:
                deadline.require_remaining()
            snapshot_root = snapshot_parent / f"repository-{index}"
            snapshot_root.mkdir(mode=0o700)
            if deadline is not None:
                deadline.require_remaining()
            snapshot_config = _copy_private_bundle_file(
                snapshot_root,
                config_relative,
                config_bytes,
                deadline=deadline,
            )
            if glossary_bytes is not None:
                if deadline is not None:
                    deadline.require_remaining()
                _copy_private_bundle_file(
                    snapshot_root,
                    glossary_relative,
                    glossary_bytes,
                    deadline=deadline,
                )
            snapshots[policy.base_repo] = PipelineConfigSnapshot(
                config_root=snapshot_root.resolve(),
                config_path=snapshot_config.resolve(),
                bundle_digest=pipeline_config_bundle_digest(bundle_files),
            )
        yield snapshots


def _resolved_codex_home(config: GuardianConfig) -> Path:
    return Path(os.path.abspath(Path(config.runtime.codex_home).expanduser()))


def _validate_subscription_codex_home(config: GuardianConfig) -> Path:
    """Require one private file-backed ChatGPT login owned by the operator."""

    codex_home = _resolved_codex_home(config)
    auth_file = codex_home / "auth.json"
    try:
        _validate_trusted_ancestors(codex_home)
        home_metadata = codex_home.stat(follow_symlinks=False)
        auth_metadata = auth_file.stat(follow_symlinks=False)
        if (
            codex_home.is_symlink()
            or not stat.S_ISDIR(home_metadata.st_mode)
            or (hasattr(os, "getuid") and home_metadata.st_uid != os.getuid())
            or stat.S_IMODE(home_metadata.st_mode) != 0o700
            or auth_file.is_symlink()
            or not stat.S_ISREG(auth_metadata.st_mode)
            or (hasattr(os, "getuid") and auth_metadata.st_uid != os.getuid())
            or stat.S_IMODE(auth_metadata.st_mode) != 0o600
            or auth_metadata.st_size <= 0
            or auth_metadata.st_size > _MAX_CODEX_AUTH_BYTES
        ):
            raise GuardianRuntimeError(
                "Guardian ChatGPT authentication is unavailable or unsafe."
            )
    except GuardianRuntimeError:
        raise
    except OSError:
        raise GuardianRuntimeError(
            "Guardian ChatGPT authentication is unavailable or unsafe."
        ) from None
    return codex_home


def _validate_scheduled_executables(config: GuardianConfig) -> None:
    commands: list[tuple[Sequence[str], str]] = [
        ((config.runtime.codex_executable,), "runtime.codex_executable"),
        ((config.runtime.git_executable,), "runtime.git_executable"),
    ]
    direct_commands: list[tuple[Sequence[str], str, bool]] = [
        (
            config.runtime.github_token_command,
            "runtime.github_token_command",
            True,
        ),
    ]
    sandbox_wrappers: list[tuple[Sequence[str], str]] = []
    if config.mode in _WRITE_MODES:
        commands.append(((config.runtime.signing_program,), "runtime.signing_program"))
    if config.runtime.codex_auth_mode is CodexAuthMode.API_KEY:
        direct_commands.append(
            (
                config.runtime.codex_api_key_command,
                "runtime.codex_api_key_command",
                False,
            )
        )
    if config.mode is GuardianMode.PROPOSE_PREVENTION:
        for policy_index, policy in enumerate(config.repositories):
            prevention = policy.prevention
            if prevention is None:
                continue
            sandbox_wrappers.append(
                (
                    prevention.sandbox_argv_prefix,
                    f"repositories.{policy_index}.prevention.sandbox_argv_prefix",
                )
            )
            commands.extend(
                (argv, f"repositories.{policy_index}.prevention.focused_test_argv")
                for argv in prevention.focused_test_argv
            )
    try:
        for command, field in commands:
            require_absolute_trusted_executable(command, field=field)
        for command, field, allow_github_cli in direct_commands:
            require_absolute_trusted_direct_executable(
                command,
                field=field,
                allow_github_cli=allow_github_cli,
            )
        for command, field in sandbox_wrappers:
            require_absolute_trusted_wrapper(command, field=field)
    except ExecutableTrustError:
        raise GuardianRuntimeError(
            "Guardian scheduled executable authority is unavailable or unsafe."
        ) from None


def _validate_runtime_authority(config: GuardianConfig, *, scheduled: bool) -> None:
    if config.runtime.codex_auth_mode is CodexAuthMode.CHATGPT:
        _validate_subscription_codex_home(config)
    if (
        config.mode in _WRITE_MODES
        and config.runtime.signing_format is SigningFormat.SSH
    ):
        try:
            require_absolute_trusted_executable(
                (config.runtime.signing_program,),
                field="runtime.signing_program",
            )
        except ExecutableTrustError:
            raise GuardianRuntimeError(
                "Guardian SSH signing authority is unavailable or unsafe."
            ) from None
    if scheduled:
        _validate_scheduled_executables(config)


def _github_policy(policy: RepositoryPolicy) -> GitHubRepositoryPolicy:
    return GitHubRepositoryPolicy(
        repository=policy.base_repo,
        repository_id=policy.base_repo_id,
        base_branch=policy.base_branch,
        allowed_pr_authors=policy.allowed_pr_authors,
        allowed_head_owners=policy.allowed_head_owners,
        allowed_head_repositories=policy.allowed_head_repositories,
        branch_globs=policy.allowed_branch_globs,
    )


class AuthenticatedGitHubSnapshotProvider:
    """Mint a read credential and collect complete GitHub feedback snapshots."""

    def __init__(
        self,
        *,
        credential: SecretCommand | CredentialSnapshot,
        timeout_seconds: float = 30.0,
        transport: httpx.BaseTransport | None = None,
        deadline: PollDeadline | None = None,
        previous_feedback_provider: Callable[
            [str, int], tuple[FeedbackRevision, ...]
        ]
        | None = None,
    ) -> None:
        if timeout_seconds <= 0:
            raise ValueError("GitHub timeout must be positive.")
        self._credential = credential
        self._timeout_seconds = float(timeout_seconds)
        self._transport = transport
        self._deadline = deadline
        self._previous_feedback_provider = previous_feedback_provider
        self.loads_previous_feedback_per_pull = (
            previous_feedback_provider is not None
        )

    def _previous_for_pull(
        self,
        policy: RepositoryPolicy,
    ) -> Callable[[int], tuple[FeedbackRevision, ...]] | None:
        provider = self._previous_feedback_provider
        if provider is None:
            return None
        return lambda pull_number: provider(policy.base_repo, pull_number)

    def require_publication_actor(
        self,
        policy: RepositoryPolicy,
        expected_actors: Sequence[TrustedActor],
    ) -> None:
        """Fail before poll work unless one credential matches every writer."""

        expected = tuple(expected_actors)
        if not expected:
            return
        if any(actor.type != "User" for actor in expected):
            raise GitHubAuthenticationError(
                "GitHub publication actor must be a User identity."
            )
        with self._reader(policy) as reader:
            actual = reader.authenticated_actor()
        if actual.type != "User" or any(
            (actor.id, actor.type) != (actual.id, actual.type)
            for actor in expected
        ):
            raise GitHubAuthenticationError(
                "GitHub publication actor does not match enabled policy."
            )

    @contextmanager
    def _reader(self, policy: RepositoryPolicy) -> Iterator[GitHubReader]:
        """Yield one read-only client whose token exists only for this call."""

        credential = self._credential
        if self._deadline is not None and isinstance(credential, SecretCommand):
            credential = SecretCommand(
                credential.argv,
                timeout_seconds=self._deadline.remaining(
                    credential.timeout_seconds
                ),
                environment=credential.environment,
            )
        try:
            token = credential.read()
        except CredentialError:
            if self._deadline is not None:
                self._deadline.require_remaining()
            raise GitHubAuthenticationError("GitHub credential helper failed") from None
        try:
            with httpx.Client(
                base_url=_GITHUB_API_URL,
                headers={
                    "Accept": "application/vnd.github+json",
                    "Authorization": f"Bearer {token}",
                    "User-Agent": "localize-guardian",
                    "X-GitHub-Api-Version": "2022-11-28",
                },
                timeout=(
                    self._timeout_seconds
                    if self._deadline is None
                    else self._deadline.remaining(self._timeout_seconds)
                ),
                transport=self._transport,
                follow_redirects=False,
                trust_env=False,
            ) as client:
                try:
                    reader_kwargs: dict[str, object] = {}
                    if self._deadline is not None:
                        reader_kwargs["deadline"] = self._deadline
                    yield GitHubReader(client, _github_policy(policy), **reader_kwargs)
                finally:
                    client.headers.pop("Authorization", None)
        finally:
            token = ""

    def __call__(
        self,
        policy: RepositoryPolicy,
        previous_feedback: tuple[FeedbackRevision, ...],
    ) -> Sequence[PullRequestFeedbackSnapshot]:
        with self._reader(policy) as reader:
            per_pull = self._previous_for_pull(policy)
            if per_pull is None:
                return reader.collect_open_pull_requests(
                    previous_feedback=previous_feedback
                )
            return reader.collect_open_pull_requests(
                previous_feedback_for_pull=per_pull
            )

    def collect_closed_pull_requests(
        self,
        policy: RepositoryPolicy,
        previous_feedback: tuple[FeedbackRevision, ...],
        *,
        cutoff: datetime,
        upper_bound: datetime,
        max_prs_per_poll: int,
        seen_pulls: tuple[tuple[int, int], ...],
        excluded_pulls: tuple[tuple[int, int], ...],
        priority_pull_groups: tuple[tuple[tuple[int, int], ...], ...],
    ) -> ClosedPullScanResult:
        """Collect one restart-safe historical batch under an ephemeral token."""

        with self._reader(policy) as reader:
            kwargs: dict[str, object] = {}
            per_pull = self._previous_for_pull(policy)
            if per_pull is None:
                kwargs["previous_feedback"] = previous_feedback
            else:
                kwargs["previous_feedback_for_pull"] = per_pull
            return reader.collect_closed_pull_requests(
                cutoff=cutoff,
                upper_bound=upper_bound,
                max_prs_per_poll=max_prs_per_poll,
                seen_pulls=seen_pulls,
                excluded_pulls=excluded_pulls,
                priority_pull_groups=priority_pull_groups,
                **kwargs,
            )

    def revalidate_closed_pull_requests(
        self,
        policy: RepositoryPolicy,
        sources: tuple[HistoricalPullReference, ...],
    ) -> tuple[PullRequestFeedbackSnapshot, ...]:
        """Rehydrate exact historical sources at a mutation boundary."""

        if not sources or any(
            not isinstance(source, HistoricalPullReference) for source in sources
        ):
            raise ValueError("sources must contain exact historical pull identities")
        with self._reader(policy) as reader:
            return reader.collect_exact_closed_pulls(
                tuple((source.pull_id, source.pr_number) for source in sources)
            )

    def revalidate_open_pull_request(
        self,
        policy: RepositoryPolicy,
        source: OpenPullAuthorityReference,
    ) -> PullRequestFeedbackSnapshot:
        """Rehydrate one exact open source under an ephemeral read token."""

        if not isinstance(source, OpenPullAuthorityReference) or (
            source.repository,
            source.repository_id,
        ) != (policy.base_repo, policy.base_repo_id):
            raise ValueError("source must match the exact open repository policy")
        with self._reader(policy) as reader:
            return reader.collect_exact_open_pull(
                (source.pull_id, source.pr_number)
            )

    def collect_open_changed_paths(
        self,
        policy: RepositoryPolicy,
    ) -> tuple[OpenPullPathAuthority, ...]:
        """Capture complete allowed open-PR path authority without review text."""

        with self._reader(policy) as reader:
            return reader.collect_open_changed_paths()

    def capture_base_revision(
        self,
        policy: RepositoryPolicy,
    ) -> BaseRevisionSnapshot:
        """Capture the exact current base under an ephemeral read token."""

        with self._reader(policy) as reader:
            return reader.capture_base_revision()


def _attempt_timeout(config: GuardianConfig) -> float:
    """Keep configured retries within one model-call timeout budget."""

    return config.limits.run_timeout_seconds / config.limits.max_attempts


def _require_explicit_write_signing_key(config: GuardianConfig) -> None:
    key = config.runtime.signing_key
    if config.mode not in _WRITE_MODES:
        return
    try:
        if config.runtime.signing_format is SigningFormat.SSH:
            canonical_ssh_fingerprint(key)  # type: ignore[arg-type]
            public_key = config.runtime.signing_public_key
            if public_key is None or not Path(public_key).is_absolute():
                raise ValueError
        else:
            canonical_signing_key(key)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        raise GuardianRuntimeError(
            "Guardian write modes require an explicit exact signing key fingerprint."
        ) from None


@contextmanager
def _snapshot_poll_signing_material(
    *,
    config: GuardianConfig,
    state_directory: Path,
    deadline: PollDeadline | None = None,
) -> Iterator[SSHSigningMaterial | None]:
    """Freeze an SSH public identity before any external write-mode work."""

    if (
        config.mode not in _WRITE_MODES
        or config.runtime.signing_format is not SigningFormat.SSH
    ):
        yield None
        return
    try:
        assert config.runtime.signing_public_key is not None
        assert config.runtime.signing_key is not None
        snapshot_kwargs: dict[str, object] = {
            "public_key_path": config.runtime.signing_public_key,
            "expected_fingerprint": config.runtime.signing_key,
            "signing_program": config.runtime.signing_program,
            "temporary_root": state_directory,
        }
        if deadline is not None:
            snapshot_kwargs["deadline"] = deadline
        with snapshot_ssh_signing_material(**snapshot_kwargs) as material:
            yield material
    except PollDeadlineExceeded:
        raise
    except SigningError:
        raise GuardianRuntimeError(
            "Guardian SSH signing identity is unavailable or unsafe."
        ) from None


def _build_controller(
    *,
    config: GuardianConfig,
    state: GuardianState,
    state_directory: Path,
    github_credential: SecretCommand | CredentialSnapshot,
    model_credential: SecretCommand | None,
    git_environment: Any,
    ssh_signing_material: SSHSigningMaterial | None = None,
    operator_pipeline_configs: Mapping[str, PipelineConfigSnapshot] | None = None,
    deadline: PollDeadline | None = None,
) -> GuardianController:
    """Assemble trusted production adapters without invoking a credential yet."""

    _require_explicit_write_signing_key(config)
    attempt_timeout = _attempt_timeout(config)
    github_timeout = min(30.0, attempt_timeout)
    deadline_kwargs: dict[str, PollDeadline] = (
        {} if deadline is None else {"deadline": deadline}
    )
    snapshot_provider = AuthenticatedGitHubSnapshotProvider(
        credential=github_credential,
        timeout_seconds=github_timeout,
        previous_feedback_provider=lambda repository, pr_number: _stored_feedback(
            state.latest_event_revisions(
                repository=repository,
                pr_number=pr_number,
            )
        ),
        **deadline_kwargs,
    )
    has_historical_backfill = any(
        policy.closed_pr_backfill is not None for policy in config.repositories
    )
    has_historical_remediation = any(
        policy.closed_pr_backfill is not None
        and policy.closed_pr_backfill.remediation is not None
        for policy in config.repositories
    )
    has_historical_prevention = (
        config.mode is GuardianMode.PROPOSE_PREVENTION
        and any(
            policy.closed_pr_backfill is not None
            and policy.prevention is not None
            for policy in config.repositories
        )
    )
    remediation_limit = config.limits.max_remediation_drafts_per_run
    if (
        isinstance(remediation_limit, bool)
        or not isinstance(remediation_limit, int)
        or remediation_limit < 0
    ):
        raise GuardianRuntimeError(
            "Historical remediation publication limit is invalid."
        )
    codex_driver = CodexDriver(
        model=config.runtime.codex_model,
        reasoning_effort=config.runtime.codex_reasoning_effort,
        auth_mode=config.runtime.codex_auth_mode,
        codex_home=config.runtime.codex_home,
        executable=config.runtime.codex_executable,
        timeout_seconds=attempt_timeout,
        max_attempts=config.limits.max_attempts,
        **deadline_kwargs,
    )

    def checkout_factory(revision: ExactRevision | HistoricalRevision):
        if isinstance(revision, HistoricalRevision):
            return create_historical_checkout(revision)
        checkout_kwargs: dict[str, Any] = {
            "credential_environment": git_environment,
            "git_binary": config.runtime.git_executable,
            "signing_program": config.runtime.signing_program,
            "timeout_seconds": attempt_timeout,
        }
        checkout_kwargs.update(deadline_kwargs)
        if config.runtime.signing_format is SigningFormat.SSH:
            if ssh_signing_material is None:
                if config.mode in _WRITE_MODES:
                    raise GuardianRuntimeError(
                        "Guardian SSH signing identity is unavailable or unsafe."
                    )
                checkout_kwargs["signing_program"] = None
            else:
                checkout_kwargs.update(
                    signing_format=SigningFormat.SSH,
                    ssh_signing_material=ssh_signing_material,
                )
        return materialize_exact_checkout(revision, **checkout_kwargs)

    historical_snapshot_provider = (
        snapshot_provider.collect_closed_pull_requests
        if has_historical_backfill
        else None
    )
    current_base_provider = (
        snapshot_provider.capture_base_revision if has_historical_backfill else None
    )

    def create_historical_checkout(revision: HistoricalRevision):
        checkout_kwargs: dict[str, Any] = {
            "credential_environment": git_environment,
            "git_binary": config.runtime.git_executable,
            "timeout_seconds": attempt_timeout,
        }
        checkout_kwargs.update(deadline_kwargs)
        return materialize_historical_checkout(revision, **checkout_kwargs)

    historical_checkout_factory = (
        create_historical_checkout if has_historical_backfill else None
    )

    def model_credential_provider() -> str | None:
        if config.runtime.codex_auth_mode is CodexAuthMode.CHATGPT:
            return None
        if model_credential is None:
            return resolve_model_api_key(None)
        if deadline is None:
            return resolve_model_api_key(model_credential)
        bounded_credential = SecretCommand(
            model_credential.argv,
            timeout_seconds=deadline.remaining(model_credential.timeout_seconds),
            environment=model_credential.environment,
        )
        try:
            return resolve_model_api_key(bounded_credential)
        except CredentialError:
            deadline.require_remaining()
            raise

    write_broker_factory = None
    if config.mode in _WRITE_MODES:

        def create_write_broker(policy: RepositoryPolicy) -> GitHubWriteBroker:
            if policy.publication_actor is None:  # pragma: no cover - config invariant
                raise GuardianRuntimeError(
                    "Write-capable repository lacks a publication actor."
                )
            return GitHubWriteBroker(
                policy=_github_policy(policy),
                expected_actor=policy.publication_actor,
                credential=github_credential,
                base_url=_GITHUB_API_URL,
                timeout=github_timeout,
                **deadline_kwargs,
            )

        write_broker_factory = create_write_broker

    prevention_runner = None
    if config.mode is GuardianMode.PROPOSE_PREVENTION:

        def create_prevention_broker(
            policy: PreventionPolicy,
        ) -> PreventionGitHubBroker:
            return PreventionGitHubBroker(
                policy=policy,
                credential=github_credential,
                github_host=_GITHUB_HOST,
                base_url=_GITHUB_API_URL,
                timeout_seconds=github_timeout,
                **deadline_kwargs,
            )

        prevention_runner = PreventionCoordinator(
            state=state,
            checkout_factory=checkout_factory,
            broker_factory=create_prevention_broker,
            author=PreventionCodexAuthor(
                model=config.runtime.codex_model,
                reasoning_effort=config.runtime.codex_reasoning_effort,
                auth_mode=config.runtime.codex_auth_mode,
                codex_home=config.runtime.codex_home,
                executable=config.runtime.codex_executable,
                timeout_seconds=attempt_timeout,
                max_attempts=config.limits.max_attempts,
                **deadline_kwargs,
            ),
            test_runner=SandboxedTestRunner(
                timeout_seconds=attempt_timeout,
                **deadline_kwargs,
            ),
            model_credential_provider=model_credential_provider,
            publish_credential_environment=git_environment,
            signing_key=config.runtime.signing_key,
            signing_environment=None,
            max_drafts=config.limits.max_prevention_drafts_per_run,
            reservation_usd=config.limits.model_call_reservation_usd,
            daily_limit_usd=config.limits.daily_cost_limit_usd,
            max_model_calls_per_day=config.limits.max_model_calls_per_day,
            api_billed=(config.runtime.codex_auth_mode is CodexAuthMode.API_KEY),
            temporary_root=state_directory,
            **deadline_kwargs,
        )

    remediation_runner = None
    if (
        has_historical_remediation
        and remediation_limit > 0
        and config.mode in _WRITE_MODES
    ):

        def create_remediation_broker(
            policy: RepositoryPolicy,
        ) -> RemediationGitHubBroker:
            return RemediationGitHubBroker(
                policy=policy,
                credential=github_credential,
                github_host=_GITHUB_HOST,
                base_url=_GITHUB_API_URL,
                timeout_seconds=github_timeout,
                **deadline_kwargs,
            )

        remediation_runner = RemediationCoordinator(
            state=state,
            broker_factory=create_remediation_broker,
            publish_credential_environment=git_environment,
            signing_key=config.runtime.signing_key,
            signing_environment=None,
            max_drafts=remediation_limit,
            **deadline_kwargs,
        )

    return GuardianController(
        config=config,
        state=state,
        snapshot_provider=snapshot_provider,
        checkout_factory=checkout_factory,
        codex_driver=codex_driver,
        model_credential_provider=model_credential_provider,
        write_broker_factory=write_broker_factory,
        prevention_runner=prevention_runner,
        historical_snapshot_provider=historical_snapshot_provider,
        historical_source_snapshot_provider=(
            snapshot_provider.revalidate_closed_pull_requests
            if remediation_runner is not None or has_historical_prevention
            else None
        ),
        historical_checkout_factory=historical_checkout_factory,
        current_base_provider=current_base_provider,
        remediation_runner=remediation_runner,
        publish_credential_environment=git_environment,
        evidence_root=state_directory / "evidence",
        github_host=_GITHUB_HOST,
        signing_key=config.runtime.signing_key,
        operator_pipeline_configs=operator_pipeline_configs,
        publication_actor_preflight=(
            lambda: snapshot_provider.require_publication_actor(
                config.repositories[0],
                config.enabled_publication_actors,
            )
        ),
        **deadline_kwargs,
    )


def _local_now() -> datetime:
    return datetime.now().astimezone()


def _scheduled_poll_is_due(
    state: GuardianState,
    *,
    now: datetime,
    schedule: GuardianSchedule,
) -> bool:
    """Use the latest durable poll attempt as the once-daily checkpoint."""

    latest_attempt = state.latest_health(_POLL_ATTEMPT_COMPONENT)
    if latest_attempt is None:
        # Upgrade compatibility: older Guardian versions recorded only a
        # successful bounded poll. Respect that same-day checkpoint once.
        legacy_success = state.latest_health("guardian")
        latest_attempt = (
            legacy_success
            if legacy_success is not None and legacy_success.status == "ok"
            else None
        )
    if latest_attempt is not None:
        details = getattr(latest_attempt, "details", {})
        recorded_local_date = (
            details.get("local_date") if isinstance(details, Mapping) else None
        )
        if isinstance(recorded_local_date, str):
            try:
                recorded_date = date.fromisoformat(recorded_local_date)
            except ValueError:
                pass
            else:
                if (
                    recorded_date.isoformat() == recorded_local_date
                    and recorded_date == now.date()
                ):
                    if details.get("scheduled") is True:
                        return False
                    recorded_local_minute = details.get("local_minute")
                    if (
                        isinstance(recorded_local_minute, int)
                        and not isinstance(recorded_local_minute, bool)
                        and 0 <= recorded_local_minute < 24 * 60
                    ):
                        scheduled_minute = schedule.hour * 60 + schedule.minute
                        if recorded_local_minute >= scheduled_minute:
                            return False
                        return is_run_due(
                            now=now,
                            last_success=None,
                            hour=schedule.hour,
                            minute=schedule.minute,
                        )
                return is_run_due(
                    now=now,
                    last_success=None,
                    hour=schedule.hour,
                    minute=schedule.minute,
                )
    return is_run_due(
        now=now,
        last_success=(
            latest_attempt.checked_at if latest_attempt is not None else None
        ),
        hour=schedule.hour,
        minute=schedule.minute,
    )


def _exit_code(outcome: PollOutcome) -> int:
    if (
        outcome.authentication_circuit_open
        or outcome.model_circuit_open
        or outcome.runs_failed
        or outcome.prevention_failures
        or outcome.remediation_failures
        or outcome.failures
    ):
        return 1
    return 0


@contextmanager
def _deadline_credential_snapshot(
    command: SecretCommand,
    *,
    deadline: PollDeadline,
) -> Iterator[CredentialSnapshot]:
    """Mint one credential using no more than the poll's remaining budget."""

    bounded_command = SecretCommand(
        command.argv,
        timeout_seconds=deadline.remaining(command.timeout_seconds),
        environment=command.environment,
    )
    with credential_snapshot(bounded_command) as snapshot:
        deadline.require_remaining()
        yield snapshot


@contextmanager
def _record_poll_deadline_failure(
    *,
    state: GuardianState,
    checked_at: datetime,
) -> Iterator[None]:
    """Persist a redacted terminal health record for setup-time expiry."""

    try:
        yield
    except PollDeadlineExceeded:
        state.record_health(
            component="guardian",
            status="failed",
            message="Guardian poll deadline was exceeded.",
            details={"failure_types": ("PollDeadlineExceeded",)},
            checked_at=checked_at,
        )
        raise


def _poll_with_locked_state(
    *,
    config: GuardianConfig,
    resolved_config: Path,
    state_directory: Path,
    state_path: Path,
    scheduled: bool,
) -> int:
    """Execute a poll while the caller holds the config's process lock."""

    try:
        state_context = GuardianState(state_path)
    except Exception:
        raise GuardianRuntimeError("Guardian private state is unavailable.") from None

    try:
        with state_context as state:
            attempted_at = _local_now()
            if scheduled and not _scheduled_poll_is_due(
                state,
                now=attempted_at,
                schedule=config.schedule,
            ):
                return 0
            deadline = PollDeadline(config.limits.run_timeout_seconds)
            state.record_health(
                component=_POLL_ATTEMPT_COMPONENT,
                status="attempted",
                message="Guardian poll attempt started.",
                details={
                    "scheduled": scheduled,
                    "local_date": attempted_at.date().isoformat(),
                    "local_minute": attempted_at.hour * 60 + attempted_at.minute,
                },
                checked_at=attempted_at,
            )
            with _record_poll_deadline_failure(
                state=state,
                checked_at=attempted_at,
            ):
                _validate_runtime_authority(config, scheduled=scheduled)
                deadline.require_remaining()

            helper_timeout = min(30.0, _attempt_timeout(config))
            github_credential_command = SecretCommand(
                config.runtime.github_token_command,
                timeout_seconds=helper_timeout,
            )
            model_credential = (
                SecretCommand(
                    config.runtime.codex_api_key_command,
                    timeout_seconds=helper_timeout,
                )
                if config.runtime.codex_auth_mode is CodexAuthMode.API_KEY
                else None
            )
            with (
                _record_poll_deadline_failure(
                    state=state,
                    checked_at=attempted_at,
                ),
                _snapshot_poll_signing_material(
                    config=config,
                    state_directory=state_directory,
                    deadline=deadline,
                ) as ssh_signing_material,
                _snapshot_operator_pipeline_configs(
                    config=config,
                    guardian_config_path=resolved_config,
                    state_directory=state_directory,
                    deadline=deadline,
                ) as operator_pipeline_configs,
                _deadline_credential_snapshot(
                    github_credential_command,
                    deadline=deadline,
                ) as github_credential,
            ):
                for repository, snapshot in operator_pipeline_configs.items():
                    state.record_health(
                        component="pipeline-config",
                        status="ok",
                        message="Operator pipeline config snapshot selected.",
                        details={
                            "repository": repository,
                            "bundle_digest": snapshot.bundle_digest,
                        },
                        checked_at=attempted_at,
                    )
                with git_credential_environment(
                    github_credential,
                    temporary_root=state_directory,
                ) as git_environment:
                    controller = _build_controller(
                        config=config,
                        state=state,
                        state_directory=state_directory,
                        github_credential=github_credential,
                        model_credential=model_credential,
                        git_environment=git_environment,
                        ssh_signing_material=ssh_signing_material,
                        operator_pipeline_configs=operator_pipeline_configs,
                        deadline=deadline,
                    )
                    try:
                        outcome = controller.poll_once()
                    except Exception:
                        raise GuardianRuntimeError(
                            "Guardian poll failed before a bounded outcome was recorded."
                        ) from None
                    return _exit_code(outcome)
    except GuardianRuntimeError:
        raise
    except Exception:
        raise GuardianRuntimeError(
            "Guardian poll runtime failed safely."
        ) from None


def run_once(config_path: Path, scheduled: bool = False) -> int:
    """Load trusted policy and execute one finite, non-overlapping poll.

    Scheduled calls run at most once per local calendar day after the first
    attempted wake, regardless of its outcome. Manual invocations always poll.
    Credential contents and untrusted exception messages never cross this
    adapter's error boundary.
    """

    if not isinstance(scheduled, bool):
        raise GuardianRuntimeError("Guardian scheduled flag is invalid.")
    resolved_config = _resolved_config_path(config_path)
    config = load_trusted_guardian_config(resolved_config)
    _require_explicit_write_signing_key(config)
    state_directory, state_path = _prepare_private_state(resolved_config)
    try:
        with _exclusive_poll_lock(state_directory):
            _validate_private_state_artifacts(state_path)
            return _poll_with_locked_state(
                config=config,
                resolved_config=resolved_config,
                state_directory=state_directory,
                state_path=state_path,
                scheduled=scheduled,
            )
    except _GuardianPollAlreadyRunning:
        if scheduled:
            return 0
        raise GuardianRuntimeError("Guardian poll is already running.") from None


__all__: Sequence[str] = (
    "AuthenticatedGitHubSnapshotProvider",
    "GuardianRuntimeError",
    "load_trusted_guardian_config",
    "run_once",
)
