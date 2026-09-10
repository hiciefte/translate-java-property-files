"""Fail-closed validation for a separately authored prevention draft.

This module deliberately performs no command execution or repository mutation.  A
controller may use it only after separately materializing exact base and candidate
workspaces and running the recorded tests.  The result is a bounded, deterministic
plan that a distinct write broker may choose to publish as a draft pull request.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import hashlib
import html
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
from typing import Iterable, Mapping, Sequence
import unicodedata

from localize.guardian.deadline import PollDeadline
from localize.guardian.path_globs import matches_any_path_glob


_SHA_RE = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_HASH_RE = re.compile(r"^[0-9a-f]{64}$")
_FEEDBACK_ID_RE = re.compile(r"^[A-Za-z0-9_.-]+(?::[A-Za-z0-9_.-]+)+$")
_SHELL_EXECUTABLES = frozenset(
    {
        "bash",
        "cmd",
        "dash",
        "env",
        "fish",
        "ksh",
        "powershell",
        "pwsh",
        "sh",
        "zsh",
    }
)
_ALLOWED_TEXT_CONTROLS = frozenset("\t\n\r\f")
_DEFAULT_MAX_CHANGED_BYTES = 256 * 1024
_MAX_ROOT_CAUSE_LENGTH = 500
_MAX_FEEDBACK_IDS = 100
_MAX_PATH_GLOBS = 100
_MAX_CHANGED_FILES = 100
_MAX_ARGV_ITEMS = 256
_MAX_FOCUSED_TEST_COMMANDS = 64
_MAX_TEST_RESULT_RECORDS = _MAX_FOCUSED_TEST_COMMANDS * 2
_MAX_ARGUMENT_BYTES = 4096
_MAX_TITLE_CHARS = 120
_MAX_TITLE_BYTES = 256
_MAX_BODY_BYTES = 60 * 1024
_MAX_BODY_LIST_BYTES = 16 * 1024
# Full-tree inspection stays finite before tighter changed-file limits apply.
_MAX_INVENTORY_ENTRIES = 100_000
_MAX_INVENTORY_BYTES = 2 * 1024 * 1024 * 1024
_MAX_INVENTORY_FILE_BYTES = 256 * 1024 * 1024


class PreventionPolicyError(ValueError):
    """A proposed prevention draft failed a deterministic safety gate."""


class DuplicatePreventionCandidateError(PreventionPolicyError):
    """The same normalized root cause and evidence were already planned."""


class TestOutcome(str, Enum):
    """Controller-observed outcome for one completed test command."""

    PASSED = "passed"
    FAILED = "failed"
    ERROR = "error"
    TIMED_OUT = "timed_out"


TestOutcome.__test__ = False


def _validated_sha(value: object, *, label: str) -> str:
    if not isinstance(value, str) or not _SHA_RE.fullmatch(value):
        raise ValueError(f"{label} must be a full lowercase Git object ID")
    return value


def _executable_name(value: str) -> str:
    return value.replace("\\", "/").rsplit("/", 1)[-1].lower()


def _validate_argv(argv: object) -> tuple[str, ...]:
    if not isinstance(argv, tuple) or not 1 <= len(argv) <= _MAX_ARGV_ITEMS:
        raise ValueError("test command argv must be a non-empty tuple of strings")
    for argument in argv:
        if (
            not isinstance(argument, str)
            or not argument
            or len(argument.encode("utf-8")) > _MAX_ARGUMENT_BYTES
            or any(
                unicodedata.category(character).startswith("C")
                for character in argument
            )
        ):
            raise ValueError("test command argv contains an invalid argument")

    executable = _executable_name(argv[0])
    if executable in _SHELL_EXECUTABLES:
        raise ValueError("test command argv must not invoke a shell wrapper")
    if executable.startswith("python") and "-c" in argv[1:]:
        raise ValueError("test command argv must not use an interpreter command string")
    if executable in {"node", "ruby", "perl"} and any(
        argument in {"-e", "--eval"} for argument in argv[1:]
    ):
        raise ValueError("test command argv must not use an interpreter command string")
    if executable == "php" and "-r" in argv[1:]:
        raise ValueError("test command argv must not use an interpreter command string")
    return argv


@dataclass(frozen=True, slots=True)
class TestCommandResult:
    """Trusted controller metadata for one argv-only test invocation.

    The record contains no output text and grants no ability to execute its argv.
    ``phase`` identifies the exact checkout on which the controller ran it.
    """

    phase: str
    outcome: TestOutcome
    argv: tuple[str, ...]
    commit_sha: str
    parent_sha: str | None
    returncode: int
    test_overlay_hash: str
    focused: bool = True

    def __post_init__(self) -> None:
        if self.phase not in {"base", "patched"}:
            raise ValueError("test result phase must be base or patched")
        try:
            outcome = TestOutcome(self.outcome)
        except (TypeError, ValueError) as exc:
            raise ValueError("test result outcome is invalid") from exc
        object.__setattr__(self, "outcome", outcome)
        object.__setattr__(self, "argv", _validate_argv(self.argv))
        _validated_sha(self.commit_sha, label="test result commit_sha")
        if self.parent_sha is not None:
            _validated_sha(self.parent_sha, label="test result parent_sha")
        if not isinstance(self.returncode, int) or isinstance(self.returncode, bool):
            raise ValueError("test result returncode must be an integer")
        if not isinstance(self.test_overlay_hash, str) or not _HASH_RE.fullmatch(
            self.test_overlay_hash
        ):
            raise ValueError("test result test_overlay_hash must be a SHA-256 digest")
        if outcome is TestOutcome.PASSED and self.returncode != 0:
            raise ValueError("a passed test result must have returncode zero")
        if outcome is not TestOutcome.PASSED and self.returncode == 0:
            raise ValueError("a non-passing test result must have a nonzero returncode")
        if outcome is TestOutcome.FAILED and self.returncode < 0:
            raise ValueError(
                "a failed test result must be a completed positive exit code"
            )
        if not isinstance(self.focused, bool):
            raise ValueError("test result focused must be a boolean")


TestCommandResult.__test__ = False


@dataclass(frozen=True, slots=True)
class DraftPreventionPlan:
    """Validated metadata for a future draft-only prevention pull request."""

    title: str
    body: str
    paths: tuple[str, ...]
    evidence_hash: str
    base_sha: str
    candidate_sha: str
    patch_hash: str


@dataclass(frozen=True, slots=True)
class PreventionPatch:
    """Deterministically inspected candidate content before it is signed."""

    paths: tuple[str, ...]
    test_paths: tuple[str, ...]
    patch_hash: str
    test_overlay_hash: str


@dataclass(frozen=True, slots=True)
class _TreeEntry:
    kind: str
    size: int
    mode: int
    digest: str
    path: Path


def _validate_limit(
    value: object,
    *,
    label: str,
    maximum: int | None = None,
) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise PreventionPolicyError(f"{label} must be a positive integer")
    if maximum is not None and value > maximum:
        raise PreventionPolicyError(f"{label} exceeds the bound {maximum}")
    return value


def _trusted_workspace(path: Path, *, label: str) -> Path:
    raw_path = path.expanduser()
    try:
        metadata = raw_path.lstat()
    except OSError as exc:
        raise PreventionPolicyError(
            f"{label} workspace is not an accessible directory"
        ) from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise PreventionPolicyError(
            f"{label} workspace must be a non-symlinked directory"
        )
    return raw_path.resolve()


def _workspaces_overlap(first: Path, second: Path) -> bool:
    try:
        first.relative_to(second)
        return True
    except ValueError:
        pass
    try:
        second.relative_to(first)
        return True
    except ValueError:
        return False


def _safe_relative_path(parts: tuple[str, ...]) -> str:
    if not parts:
        raise PreventionPolicyError("repository path must not be empty")
    if any(
        not part
        or part in {".", ".."}
        or "\\" in part
        or any(
            ord(character) < 32
            or ord(character) == 127
            or unicodedata.category(character).startswith("C")
            for character in part
        )
        for part in parts
    ):
        raise PreventionPolicyError("repository contains an unsafe path")
    relative = PurePosixPath(*parts).as_posix()
    if PurePosixPath(relative).is_absolute():
        raise PreventionPolicyError("repository path traversal is not allowed")
    return relative


def _digest_regular_file(
    path: Path,
    expected_metadata: os.stat_result,
    *,
    deadline: PollDeadline | None = None,
) -> str:
    if deadline is not None:
        deadline.require_remaining()
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise PreventionPolicyError(
            "repository file changed while it was inspected"
        ) from exc
    digest = hashlib.sha256()
    try:
        opened_metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened_metadata.st_mode)
            or opened_metadata.st_dev != expected_metadata.st_dev
            or opened_metadata.st_ino != expected_metadata.st_ino
            or opened_metadata.st_size != expected_metadata.st_size
        ):
            raise PreventionPolicyError(
                "repository file changed while it was inspected"
            )
        while chunk := os.read(descriptor, 64 * 1024):
            if deadline is not None:
                deadline.require_remaining()
            digest.update(chunk)
    finally:
        os.close(descriptor)
    return digest.hexdigest()


def _inventory(
    root: Path,
    *,
    deadline: PollDeadline | None = None,
) -> dict[str, _TreeEntry]:
    result: dict[str, _TreeEntry] = {}
    pending: list[tuple[Path, tuple[str, ...]]] = [(root, ())]
    entries_seen = 0
    bytes_seen = 0
    while pending:
        if deadline is not None:
            deadline.require_remaining()
        directory, parent_parts = pending.pop()
        try:
            entries = []
            with os.scandir(directory) as scanner:
                for entry in scanner:
                    if deadline is not None:
                        deadline.require_remaining()
                    if not parent_parts and entry.name == ".git":
                        continue
                    entries_seen += 1
                    if entries_seen > _MAX_INVENTORY_ENTRIES:
                        raise PreventionPolicyError(
                            "workspace exceeds the inventory entry bound"
                        )
                    entries.append(entry)
            entries.sort(key=lambda item: item.name)
        except OSError as exc:
            raise PreventionPolicyError(
                "workspace could not be inspected safely"
            ) from exc
        for entry in entries:
            if deadline is not None:
                deadline.require_remaining()
            parts = (*parent_parts, entry.name)
            relative = _safe_relative_path(parts)
            try:
                metadata = entry.stat(follow_symlinks=False)
            except OSError as exc:
                raise PreventionPolicyError(
                    "workspace changed while it was inspected"
                ) from exc
            entry_path = Path(entry.path)
            permissions = stat.S_IMODE(metadata.st_mode)
            if stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
                bytes_seen += metadata.st_size
            if bytes_seen > _MAX_INVENTORY_BYTES or (
                stat.S_ISREG(metadata.st_mode)
                and metadata.st_size > _MAX_INVENTORY_FILE_BYTES
            ):
                raise PreventionPolicyError(
                    "workspace exceeds the inventory file or byte bound"
                )
            if stat.S_ISDIR(metadata.st_mode):
                result[relative] = _TreeEntry(
                    kind="directory",
                    size=0,
                    mode=permissions,
                    digest="",
                    path=entry_path,
                )
                pending.append((entry_path, parts))
            elif stat.S_ISREG(metadata.st_mode):
                if metadata.st_nlink != 1:
                    raise PreventionPolicyError(
                        f"repository path {relative!r} is hard-linked"
                    )
                result[relative] = _TreeEntry(
                    kind="regular",
                    size=metadata.st_size,
                    mode=permissions,
                    digest=_digest_regular_file(
                        entry_path,
                        metadata,
                        deadline=deadline,
                    ),
                    path=entry_path,
                )
            elif stat.S_ISLNK(metadata.st_mode):
                try:
                    target = os.readlink(entry_path)
                except OSError as exc:
                    raise PreventionPolicyError(
                        "workspace symbolic link changed while it was inspected"
                    ) from exc
                result[relative] = _TreeEntry(
                    kind="symlink",
                    size=len(os.fsencode(target)),
                    mode=permissions,
                    digest=hashlib.sha256(os.fsencode(target)).hexdigest(),
                    path=entry_path,
                )
            else:
                result[relative] = _TreeEntry(
                    kind="special",
                    size=metadata.st_size,
                    mode=permissions,
                    digest="",
                    path=entry_path,
                )
    return result


def _entry_changed(before: _TreeEntry | None, after: _TreeEntry | None) -> bool:
    if before is None or after is None:
        return True
    if before.kind != after.kind:
        return True
    if before.kind == "directory":
        return False
    executable_before = bool(before.mode & 0o111)
    executable_after = bool(after.mode & 0o111)
    return (
        before.size != after.size
        or before.digest != after.digest
        or executable_before != executable_after
    )


def _changed_entries(
    before: dict[str, _TreeEntry],
    after: dict[str, _TreeEntry],
    *,
    deadline: PollDeadline | None = None,
) -> dict[str, tuple[_TreeEntry | None, _TreeEntry | None]]:
    result: dict[str, tuple[_TreeEntry | None, _TreeEntry | None]] = {}
    for path in sorted(set(before) | set(after)):
        if deadline is not None:
            deadline.require_remaining()
        base_entry = before.get(path)
        candidate_entry = after.get(path)
        if (
            base_entry is None
            and candidate_entry is not None
            and candidate_entry.kind == "directory"
        ) or (
            candidate_entry is None
            and base_entry is not None
            and base_entry.kind == "directory"
        ):
            continue
        if _entry_changed(base_entry, candidate_entry):
            result[path] = (base_entry, candidate_entry)
    return result


def _validate_globs(values: Sequence[str], *, label: str) -> tuple[str, ...]:
    if isinstance(values, (str, bytes)) or not values:
        raise PreventionPolicyError(f"{label} path glob allowlist must not be empty")
    if len(values) > _MAX_PATH_GLOBS:
        raise PreventionPolicyError(
            f"{label} path glob allowlist exceeds its {_MAX_PATH_GLOBS}-item bound"
        )
    result: list[str] = []
    for value in values:
        if (
            not isinstance(value, str)
            or not value
            or len(value.encode("utf-8")) > _MAX_ARGUMENT_BYTES
            or "\\" in value
            or "\x00" in value
            or value.startswith("/")
            or "//" in value
            or any(
                unicodedata.category(character).startswith("C") for character in value
            )
        ):
            if (
                isinstance(value, str)
                and len(value.encode("utf-8")) > _MAX_ARGUMENT_BYTES
            ):
                raise PreventionPolicyError(
                    f"{label} path glob exceeds {_MAX_ARGUMENT_BYTES} UTF-8 bytes"
                )
            raise PreventionPolicyError(f"{label} path glob is unsafe")
        parts = value.split("/")
        if any(part in {"", ".", ".."} for part in parts) or parts[0] == ".git":
            raise PreventionPolicyError(
                f"{label} path glob permits traversal or metadata"
            )
        result.append(value)
    return tuple(dict.fromkeys(result))


def _matches(path: str, patterns: Sequence[str]) -> bool:
    return matches_any_path_glob(path, patterns)


def _read_changed_text(
    entry: _TreeEntry,
    *,
    deadline: PollDeadline | None = None,
) -> None:
    if deadline is not None:
        deadline.require_remaining()
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(entry.path, flags)
    except OSError as exc:
        raise PreventionPolicyError("changed file could not be read safely") from exc
    chunks: list[bytes] = []
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size != entry.size:
            raise PreventionPolicyError("changed file changed while it was validated")
        while chunk := os.read(descriptor, 64 * 1024):
            if deadline is not None:
                deadline.require_remaining()
            chunks.append(chunk)
    finally:
        os.close(descriptor)
    payload = b"".join(chunks)
    if hashlib.sha256(payload).hexdigest() != entry.digest:
        raise PreventionPolicyError("changed file changed while it was validated")
    if b"\x00" in payload:
        raise PreventionPolicyError("changed file is binary and contains NUL bytes")
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise PreventionPolicyError("changed file is not valid UTF-8 text") from exc
    if any(
        (ord(character) < 32 and character not in _ALLOWED_TEXT_CONTROLS)
        or ord(character) == 127
        for character in text
    ):
        raise PreventionPolicyError("changed file contains binary control bytes")


def _normalize_root_cause(value: object) -> str:
    if not isinstance(value, str):
        raise PreventionPolicyError("root cause must be a string")
    normalized = unicodedata.normalize("NFKC", value)
    if any(
        unicodedata.category(character).startswith("C") and not character.isspace()
        for character in normalized
    ):
        raise PreventionPolicyError("root cause contains unsafe control characters")
    normalized = " ".join(normalized.split())
    if not normalized or len(normalized) > _MAX_ROOT_CAUSE_LENGTH:
        raise PreventionPolicyError(
            f"root cause must contain 1-{_MAX_ROOT_CAUSE_LENGTH} normalized characters"
        )
    return normalized


def _normalize_feedback_ids(values: Iterable[str]) -> tuple[str, ...]:
    if isinstance(values, (str, bytes)):
        raise PreventionPolicyError("evidence feedback IDs must be a sequence")
    result: list[str] = []
    for value in values:
        if (
            not isinstance(value, str)
            or len(value) > 256
            or not _FEEDBACK_ID_RE.fullmatch(value)
        ):
            raise PreventionPolicyError(f"invalid evidence feedback ID {value!r}")
        if value in result:
            raise PreventionPolicyError(f"duplicate feedback ID {value!r}")
        result.append(value)
    if not result:
        raise PreventionPolicyError("at least one evidence feedback ID is required")
    if len(result) > _MAX_FEEDBACK_IDS:
        raise PreventionPolicyError("too many evidence feedback IDs")
    return tuple(sorted(result))


def prevention_evidence_hash(
    *,
    root_cause: str,
    evidence_feedback_ids: Iterable[str],
) -> str:
    """Return the stable deduplication key for one recurrence candidate."""

    normalized_cause = _normalize_root_cause(root_cause)
    normalized_feedback = _normalize_feedback_ids(evidence_feedback_ids)
    canonical = json.dumps(
        {
            "evidence_feedback_ids": normalized_feedback,
            "root_cause": normalized_cause.casefold(),
            "version": 1,
        },
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    return hashlib.sha256(canonical).hexdigest()


def _known_hashes(values: Iterable[str]) -> frozenset[str]:
    if isinstance(values, (str, bytes)):
        raise PreventionPolicyError("known evidence hashes must be a sequence")
    result: set[str] = set()
    for value in values:
        if not isinstance(value, str) or not _HASH_RE.fullmatch(value):
            raise PreventionPolicyError("known evidence hash is not a SHA-256 digest")
        result.add(value)
    return frozenset(result)


def _regression_evidence(
    *,
    exact_base_sha: str,
    records: Iterable[TestCommandResult],
) -> tuple[str, tuple[tuple[str, ...], ...], str]:
    if isinstance(records, (str, bytes)):
        raise PreventionPolicyError("test results must be a sequence of records")
    supplied = tuple(records)
    if not supplied:
        raise PreventionPolicyError(
            "focused regression evidence must have failed on the exact base SHA"
        )
    if len(supplied) > _MAX_TEST_RESULT_RECORDS:
        raise PreventionPolicyError(
            "focused regression evidence exceeds its bounded result count"
        )

    seen: set[tuple[str, tuple[str, ...]]] = set()
    candidate_shas: set[str] = set()
    failed_on_base: set[tuple[str, ...]] = set()
    passed_on_patch: set[tuple[str, ...]] = set()
    overlay_hashes: set[str] = set()
    for record in supplied:
        if not isinstance(record, TestCommandResult):
            raise PreventionPolicyError("test results contain an invalid record")
        identity = (record.phase, record.argv)
        if identity in seen:
            raise PreventionPolicyError(
                "duplicate test result for the same phase and argv"
            )
        seen.add(identity)
        overlay_hashes.add(record.test_overlay_hash)
        if record.phase == "base":
            if record.commit_sha != exact_base_sha:
                raise PreventionPolicyError(
                    "base test result does not match the exact base SHA"
                )
            if record.focused and record.outcome is TestOutcome.FAILED:
                failed_on_base.add(record.argv)
        else:
            if record.parent_sha != exact_base_sha:
                raise PreventionPolicyError(
                    "patched test result is not for a direct child of the exact base"
                )
            if record.commit_sha == exact_base_sha:
                raise PreventionPolicyError(
                    "patched test result is not for a distinct direct child"
                )
            if len(record.commit_sha) != len(exact_base_sha):
                raise PreventionPolicyError(
                    "base and candidate test results use different Git object formats"
                )
            candidate_shas.add(record.commit_sha)
            if record.focused and record.outcome is TestOutcome.PASSED:
                passed_on_patch.add(record.argv)

    if not failed_on_base:
        raise PreventionPolicyError(
            "focused regression evidence must have failed on the exact base SHA"
        )
    if not passed_on_patch:
        raise PreventionPolicyError(
            "focused regression evidence must have passed on its direct child"
        )
    if len(candidate_shas) != 1:
        raise PreventionPolicyError("test results must describe one candidate commit")
    if len(overlay_hashes) != 1:
        raise PreventionPolicyError(
            "base and patched tests must use the identical test overlay"
        )
    matched = tuple(sorted(failed_on_base & passed_on_patch))
    if not matched:
        raise PreventionPolicyError(
            "regression evidence must use the same focused argv on base and patch"
        )
    if len(matched) > _MAX_FOCUSED_TEST_COMMANDS:
        raise PreventionPolicyError(
            "focused regression command count exceeds its bound"
        )
    return next(iter(candidate_shas)), matched, next(iter(overlay_hashes))


def _patch_hash(
    changes: dict[str, tuple[_TreeEntry | None, _TreeEntry | None]],
    *,
    deadline: PollDeadline | None = None,
) -> str:
    canonical = []
    for path, (before, after) in changes.items():
        if deadline is not None:
            deadline.require_remaining()
        canonical.append(
            {
                "after": None
                if after is None
                else [after.kind, after.size, bool(after.mode & 0o111), after.digest],
                "before": None
                if before is None
                else [
                    before.kind,
                    before.size,
                    bool(before.mode & 0o111),
                    before.digest,
                ],
                "path": path,
            }
        )
    return hashlib.sha256(
        json.dumps(
            canonical,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
    ).hexdigest()


def _overlay_hash(
    test_paths: Sequence[str],
    changes: Mapping[str, tuple[_TreeEntry | None, _TreeEntry | None]],
    *,
    deadline: PollDeadline | None = None,
) -> str:
    canonical = []
    for path in test_paths:
        if deadline is not None:
            deadline.require_remaining()
        candidate = changes[path][1]
        if candidate is None:  # pragma: no cover - deletions are rejected first
            raise PreventionPolicyError("test overlay cannot contain a deletion")
        canonical.append([path, candidate.size, candidate.digest])
    return hashlib.sha256(
        json.dumps(canonical, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    ).hexdigest()


def inspect_prevention_patch(
    *,
    base_workspace: Path,
    candidate_workspace: Path,
    allowed_code_path_globs: Sequence[str],
    allowed_test_path_globs: Sequence[str],
    max_changed_files: int,
    max_changed_bytes: int = _DEFAULT_MAX_CHANGED_BYTES,
    deadline: PollDeadline | None = None,
) -> PreventionPatch:
    """Inspect candidate bytes and scope before exposing a signing credential."""

    file_limit = _validate_limit(
        max_changed_files,
        label="changed file limit",
        maximum=_MAX_CHANGED_FILES,
    )
    byte_limit = _validate_limit(max_changed_bytes, label="changed byte limit")
    code_globs = _validate_globs(allowed_code_path_globs, label="code")
    test_globs = _validate_globs(allowed_test_path_globs, label="test")
    base_root = _trusted_workspace(base_workspace, label="base")
    candidate_root = _trusted_workspace(candidate_workspace, label="candidate")
    if _workspaces_overlap(base_root, candidate_root):
        raise PreventionPolicyError("base and candidate workspaces overlap")
    changes = _changed_entries(
        _inventory(base_root, deadline=deadline),
        _inventory(candidate_root, deadline=deadline),
        deadline=deadline,
    )
    if not changes:
        raise PreventionPolicyError("prevention draft contains no changed files")
    if len(changes) > file_limit:
        raise PreventionPolicyError(
            f"changed file count {len(changes)} exceeds the file limit {file_limit}"
        )

    changed_bytes = 0
    code_paths: list[str] = []
    test_paths: list[str] = []
    for path, (base_entry, candidate_entry) in changes.items():
        if deadline is not None:
            deadline.require_remaining()
        if base_entry is not None and candidate_entry is None:
            raise PreventionPolicyError(
                f"prevention draft must not delete repository path {path!r}"
            )
        entries = tuple(
            entry for entry in (base_entry, candidate_entry) if entry is not None
        )
        if any(entry.kind == "symlink" for entry in entries):
            raise PreventionPolicyError(
                f"changed repository path {path!r} is a symbolic link"
            )
        if any(entry.kind != "regular" for entry in entries):
            raise PreventionPolicyError(
                f"changed repository path {path!r} is not a regular file"
            )
        is_code = _matches(path, code_globs)
        is_test = _matches(path, test_globs)
        if not is_code and not is_test:
            raise PreventionPolicyError(
                f"changed repository path {path!r} is outside the allowed code/test paths"
            )
        if is_code and is_test:
            raise PreventionPolicyError(
                f"changed repository path {path!r} matches both code and test scopes"
            )
        changed_bytes += max(entry.size for entry in entries)
        if changed_bytes > byte_limit:
            raise PreventionPolicyError(
                f"changed content exceeds the {byte_limit}-byte limit"
            )
        for entry in entries:
            _read_changed_text(entry, deadline=deadline)
        if (
            is_code
            and candidate_entry is not None
            and (base_entry is None or base_entry.digest != candidate_entry.digest)
        ):
            code_paths.append(path)
        if (
            is_test
            and candidate_entry is not None
            and (base_entry is None or base_entry.digest != candidate_entry.digest)
        ):
            test_paths.append(path)

    if not code_paths:
        raise PreventionPolicyError(
            "prevention draft must include at least one code file content change"
        )
    if not test_paths:
        raise PreventionPolicyError(
            "prevention draft must include at least one test file content change"
        )
    sorted_test_paths = tuple(sorted(test_paths))
    return PreventionPatch(
        paths=tuple(changes),
        test_paths=sorted_test_paths,
        patch_hash=_patch_hash(changes, deadline=deadline),
        test_overlay_hash=_overlay_hash(
            sorted_test_paths,
            changes,
            deadline=deadline,
        ),
    )


def _code(value: str) -> str:
    escaped = html.escape(value, quote=True)
    for character, entity in {
        "`": "&#96;",
        "@": "&#64;",
        "[": "&#91;",
        "]": "&#93;",
        "(": "&#40;",
        ")": "&#41;",
    }.items():
        escaped = escaped.replace(character, entity)
    return f"<code>{escaped}</code>"


def _truncate_utf8(
    value: str,
    *,
    max_bytes: int,
    max_chars: int,
    suffix: str = "…",
) -> str:
    """Truncate at a Unicode boundary while satisfying both public limits."""

    if len(value) <= max_chars and len(value.encode("utf-8")) <= max_bytes:
        return value
    suffix_bytes = len(suffix.encode("utf-8"))
    if len(suffix) > max_chars or suffix_bytes > max_bytes:
        raise PreventionPolicyError("generated text suffix exceeds its byte bound")
    candidate = value[: max_chars - len(suffix)]
    byte_budget = max_bytes - suffix_bytes
    low = 0
    high = len(candidate)
    while low < high:
        midpoint = (low + high + 1) // 2
        if len(candidate[:midpoint].encode("utf-8")) <= byte_budget:
            low = midpoint
        else:
            high = midpoint - 1
    return candidate[:low].rstrip() + suffix


def _sequence_fingerprint(values: Sequence[str]) -> str:
    digest = hashlib.sha256()
    for value in values:
        encoded = value.encode("utf-8")
        digest.update(len(encoded).to_bytes(8, "big"))
        digest.update(encoded)
    return digest.hexdigest()


def _bounded_code_list(values: Sequence[str], *, max_bytes: int) -> str:
    """Render complete list items and summarize any omitted tail deterministically."""

    rendered = tuple(f"- {_code(value)}" for value in values)
    complete = "\n".join(rendered)
    if len(complete.encode("utf-8")) <= max_bytes:
        return complete

    fingerprint = _sequence_fingerprint(values)
    selected: list[str] = []
    selected_bytes = 0
    for index, line in enumerate(rendered):
        omitted = len(rendered) - index - 1
        omission = (
            f"- {omitted} additional item(s) omitted; full-list fingerprint: "
            f"{_code(fingerprint)}"
        )
        separator_bytes = 1 if selected else 0
        projected = (
            selected_bytes
            + separator_bytes
            + len(line.encode("utf-8"))
            + 1
            + len(omission.encode("utf-8"))
        )
        if projected > max_bytes:
            break
        selected.append(line)
        selected_bytes += separator_bytes + len(line.encode("utf-8"))

    omitted = len(rendered) - len(selected)
    omission = (
        f"- {omitted} additional item(s) omitted; full-list fingerprint: "
        f"{_code(fingerprint)}"
    )
    result = "\n".join((*selected, omission))
    if len(result.encode("utf-8")) > max_bytes:  # pragma: no cover - fixed text
        raise PreventionPolicyError("generated list summary exceeds its byte bound")
    return result


def _argv_display(argv: tuple[str, ...]) -> str:
    """Expose only a generic runner label, never private executable paths or args."""
    executable = _executable_name(argv[0])
    label = "Configured test runner"
    if executable in {"pytest", "pytest.exe"}:
        label = "pytest"
    elif executable.startswith("python") and argv[1:3] == ("-m", "pytest"):
        label = "python -m pytest"
    return (
        f"{label}; executable path and arguments retained in private audit; "
        "command fingerprint: "
        f"{_sequence_fingerprint(argv)}"
    )


def _draft_text(
    *,
    root_cause: str,
    feedback_ids: Sequence[str],
    evidence_hash: str,
    base_sha: str,
    candidate_sha: str,
    patch_hash: str,
    paths: Sequence[str],
    focused_argv: Sequence[tuple[str, ...]],
) -> tuple[str, str]:
    """Render bounded public evidence without disclosing private test commands."""
    title_prefix = "Prevent recurrence: "
    summary = _truncate_utf8(
        root_cause.replace("@", "＠"),
        max_bytes=_MAX_TITLE_BYTES - len(title_prefix.encode("utf-8")),
        max_chars=_MAX_TITLE_CHARS - len(title_prefix),
    )
    title = title_prefix + summary

    feedback_lines = _bounded_code_list(
        feedback_ids,
        max_bytes=_MAX_BODY_LIST_BYTES,
    )
    path_lines = _bounded_code_list(paths, max_bytes=_MAX_BODY_LIST_BYTES)
    command_lines = _bounded_code_list(
        tuple(_argv_display(argv) for argv in focused_argv),
        max_bytes=_MAX_BODY_LIST_BYTES,
    )
    body = (
        "## Localize Guardian prevention draft\n\n"
        f"Root cause: {_code(root_cause)}\n\n"
        f"Evidence fingerprint: {_code(evidence_hash)}\n\n"
        "### Review evidence\n\n"
        f"{feedback_lines}\n\n"
        "### Bounded patch\n\n"
        f"Base: {_code(base_sha)}\n\n"
        f"Candidate direct child: {_code(candidate_sha)}\n\n"
        f"Patch fingerprint: {_code(patch_hash)}\n\n"
        f"{path_lines}\n\n"
        "### Regression proof supplied by the controller\n\n"
        "The same focused argv failed on the exact base and passed on its direct child:\n\n"
        "Portable runner labels below are display-only; exact commands remain private.\n\n"
        f"{command_lines}\n\n"
        "Publication of this draft requires a separate broker to re-verify current "
        "state and publish only this signed candidate. The Guardian cannot merge or "
        "deploy prevention drafts.\n"
    )
    if len(title.encode("utf-8")) > _MAX_TITLE_BYTES:  # pragma: no cover - helper
        raise PreventionPolicyError("generated title exceeds its byte bound")
    if len(body.encode("utf-8")) > _MAX_BODY_BYTES:
        raise PreventionPolicyError("generated body exceeds its byte bound")
    return title, body


def plan_prevention_draft(
    *,
    base_workspace: Path,
    candidate_workspace: Path,
    allowed_code_path_globs: Sequence[str],
    allowed_test_path_globs: Sequence[str],
    exact_base_sha: str,
    root_cause: str,
    evidence_feedback_ids: Iterable[str],
    max_changed_files: int,
    test_results: Iterable[TestCommandResult],
    max_changed_bytes: int = _DEFAULT_MAX_CHANGED_BYTES,
    known_evidence_hashes: Iterable[str] = (),
    deadline: PollDeadline | None = None,
) -> DraftPreventionPlan:
    """Validate and describe a candidate prevention patch without mutating state.

    The controller is responsible for materializing both exact workspaces and for
    supplying truthful test records.  This boundary verifies direct-child commit
    metadata, the fail/pass regression shape, patch scope and content, and a stable
    deduplication key.  It intentionally cannot run a model, Git, tests, or a broker.
    """

    try:
        base_sha = _validated_sha(exact_base_sha, label="exact_base_sha")
    except ValueError as exc:
        raise PreventionPolicyError(str(exc)) from exc
    normalized_cause = _normalize_root_cause(root_cause)
    feedback_ids = _normalize_feedback_ids(evidence_feedback_ids)
    evidence_hash = prevention_evidence_hash(
        root_cause=normalized_cause,
        evidence_feedback_ids=feedback_ids,
    )
    if evidence_hash in _known_hashes(known_evidence_hashes):
        raise DuplicatePreventionCandidateError(
            f"prevention candidate {evidence_hash} was already planned"
        )
    candidate_sha, focused_argv, test_overlay_hash = _regression_evidence(
        exact_base_sha=base_sha,
        records=test_results,
    )
    patch = inspect_prevention_patch(
        base_workspace=base_workspace,
        candidate_workspace=candidate_workspace,
        allowed_code_path_globs=allowed_code_path_globs,
        allowed_test_path_globs=allowed_test_path_globs,
        max_changed_files=max_changed_files,
        max_changed_bytes=max_changed_bytes,
        deadline=deadline,
    )
    if test_overlay_hash != patch.test_overlay_hash:
        raise PreventionPolicyError(
            "regression results do not match the candidate test overlay"
        )
    title, body = _draft_text(
        root_cause=normalized_cause,
        feedback_ids=feedback_ids,
        evidence_hash=evidence_hash,
        base_sha=base_sha,
        candidate_sha=candidate_sha,
        patch_hash=patch.patch_hash,
        paths=patch.paths,
        focused_argv=focused_argv,
    )
    return DraftPreventionPlan(
        title=title,
        body=body,
        paths=patch.paths,
        evidence_hash=evidence_hash,
        base_sha=base_sha,
        candidate_sha=candidate_sha,
        patch_hash=patch.patch_hash,
    )


__all__ = [
    "DraftPreventionPlan",
    "DuplicatePreventionCandidateError",
    "PreventionPolicyError",
    "PreventionPatch",
    "TestCommandResult",
    "TestOutcome",
    "inspect_prevention_patch",
    "plan_prevention_draft",
    "prevention_evidence_hash",
]
