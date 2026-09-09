"""Ephemeral, exact-revision Git workspaces for Localize Guardian.

It materializes an identity-bound remote ref, verifies the exact intake SHA,
creates one narrowly scoped local commit, and can publish that exact descendant
without overwriting an existing remote ref under a separately supplied credential.
"""

from __future__ import annotations

import os
import re
import stat
import subprocess
import tempfile
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from urllib.parse import urlsplit

from localize.guardian.deadline import PollDeadline
from localize.guardian.deadline import PollDeadlineExceeded
from localize.guardian.executable_trust import require_absolute_trusted_executable
from localize.guardian.filesystem_trust import resolve_trusted_private_directory
from localize.guardian.models import SigningFormat
from localize.guardian.signing import (
    SSHSigningMaterial,
    canonical_signing_key,
    canonical_ssh_fingerprint,
    ssh_agent_environment,
    ssh_signature_matches,
    signature_matches,
)
from localize.guardian.process import ProcessLimits, run_bounded_process


_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9_.-]*[A-Za-z0-9])?$")
_OWNER_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?$")
_SHA_RE = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_HOST_LABEL_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
_ENVIRONMENT_KEY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_FEEDBACK_FRAGMENT_RE = re.compile(
    r"^(?:discussion_r|issuecomment-|pullrequestreview-)\d+$"
)
_FORBIDDEN_REF_CHARACTERS = frozenset(" ~^:?*[\\")
_PROTECTED_ENVIRONMENT_KEYS = frozenset(
    {
        "GIT_ALLOW_PROTOCOL",
        "GIT_ASKPASS_REQUIRE",
        "GIT_CONFIG_GLOBAL",
        "GIT_CONFIG_NOSYSTEM",
        "GIT_PROTOCOL_FROM_USER",
        "GIT_TERMINAL_PROMPT",
        "HOME",
        "PATH",
    }
)
_OPENPGP_SIGNING_ENVIRONMENT_KEYS = frozenset({"GNUPGHOME"})
_DEFAULT_AUTHOR_NAME = "Localize Guardian"
_DEFAULT_AUTHOR_EMAIL = "localize-guardian@users.noreply.github.com"
_COMMIT_SUBJECT = "[localize-guardian] Apply review feedback"
_PREVENTION_COMMIT_SUBJECT = "[localize-guardian] Prevent review recurrence"
_REMEDIATION_COMMIT_SUBJECT = "[localize-guardian] Repair historical feedback"


ProcessRunner = Callable[..., subprocess.CompletedProcess[str]]
CredentialEnvironment = Callable[[], Mapping[str, str]]


class WorkspaceError(RuntimeError):
    """A checkout or commit failed a Guardian workspace invariant."""


def _bounded_git_process(
    argv: Sequence[str],
    **kwargs: object,
) -> subprocess.CompletedProcess[str]:
    timeout = kwargs.get("timeout")
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)):
        raise ValueError("bounded Git invocation requires a numeric timeout")
    return run_bounded_process(
        argv,
        **kwargs,  # type: ignore[arg-type]
        start_new_session=True,
        limits=ProcessLimits.for_timeout(
            timeout,
            max_file_size_bytes=512 * 1024 * 1024,
        ),
    )


def _validate_host(host: str) -> None:
    if not isinstance(host, str) or len(host) > 253 or not host:
        raise ValueError("host must be a valid DNS hostname")
    labels = host.split(".")
    if any(not _HOST_LABEL_RE.fullmatch(label) for label in labels):
        raise ValueError("host must be a valid DNS hostname")


def _validate_ref(ref: str) -> None:
    prefix = "refs/heads/"
    if not isinstance(ref, str) or not ref.startswith(prefix):
        raise ValueError("ref must be a full refs/heads/... reference")
    branch = ref[len(prefix) :]
    if (
        not branch
        or branch == "@"
        or branch.startswith("/")
        or branch.endswith(("/", "."))
        or "//" in branch
        or ".." in branch
        or "@{" in branch
        or any(character in _FORBIDDEN_REF_CHARACTERS for character in branch)
        or any(ord(character) < 32 or ord(character) == 127 for character in branch)
    ):
        raise ValueError("ref is not a canonical branch reference")
    components = branch.split("/")
    if any(component.startswith(".") or component.endswith(".lock") for component in components):
        raise ValueError("ref is not a canonical branch reference")


@dataclass(frozen=True, slots=True)
class ExactRevision:
    """An exact repository branch revision captured from trusted GitHub metadata."""

    host: str
    owner: str
    repository: str
    ref: str
    sha: str

    def __post_init__(self) -> None:
        _validate_host(self.host)
        if not isinstance(self.owner, str) or not _OWNER_RE.fullmatch(self.owner):
            raise ValueError("owner must be a canonical GitHub owner")
        if (
            not isinstance(self.repository, str)
            or not _IDENTIFIER_RE.fullmatch(self.repository)
            or self.repository in {".", ".."}
        ):
            raise ValueError("repository must be a canonical GitHub repository name")
        _validate_ref(self.ref)
        if not isinstance(self.sha, str) or not _SHA_RE.fullmatch(self.sha):
            raise ValueError("sha must be a full lowercase Git object ID")

    @property
    def remote_url(self) -> str:
        return f"https://{self.host}/{self.owner}/{self.repository}.git"


@dataclass(frozen=True, slots=True)
class HistoricalRevision:
    """An immutable commit fetched by object ID or an upstream pull-request ref."""

    host: str
    owner: str
    repository: str
    sha: str
    pull_number: int | None = None

    def __post_init__(self) -> None:
        _validate_host(self.host)
        if not isinstance(self.owner, str) or not _OWNER_RE.fullmatch(self.owner):
            raise ValueError("owner must be a canonical GitHub owner")
        if (
            not isinstance(self.repository, str)
            or not _IDENTIFIER_RE.fullmatch(self.repository)
            or self.repository in {".", ".."}
        ):
            raise ValueError("repository must be a canonical GitHub repository name")
        if not isinstance(self.sha, str) or not _SHA_RE.fullmatch(self.sha):
            raise ValueError("sha must be a full lowercase Git object ID")
        if self.pull_number is not None and (
            isinstance(self.pull_number, bool)
            or not isinstance(self.pull_number, int)
            or self.pull_number <= 0
        ):
            raise ValueError("pull_number must be a positive integer")

    @property
    def remote_url(self) -> str:
        return f"https://{self.host}/{self.owner}/{self.repository}.git"

    @property
    def fetch_target(self) -> str:
        """Return an immutable object request or GitHub's upstream pull ref."""

        if self.pull_number is None:
            return self.sha
        return f"refs/pull/{self.pull_number}/head"


@dataclass(frozen=True, slots=True)
class CommitResult:
    """Verified output of a single Guardian translation commit."""

    commit_sha: str
    parent_sha: str
    changed_paths: tuple[str, ...]
    signature_verified: bool


@dataclass(frozen=True, slots=True)
class _CommitPipelineContract:
    """Operation-specific checks and diagnostics for the shared commit pipeline."""

    staged_codes: frozenset[str]
    staged_status_error: str
    staged_paths_error: str
    parent_error: str
    changed_paths_error: str
    dirty_tree_error: str


_VALIDATED_COMMIT_CONTRACT = _CommitPipelineContract(
    staged_codes=frozenset({"M "}),
    staged_status_error="working tree changed while Guardian staged its edit",
    staged_paths_error="staged paths do not match the exact Guardian allowlist",
    parent_error="Guardian commit parent does not match the exact intake SHA",
    changed_paths_error="Guardian commit changed paths outside the exact allowlist",
    dirty_tree_error="working tree is not clean after the Guardian commit",
)
_HISTORICAL_REMEDIATION_COMMIT_CONTRACT = _CommitPipelineContract(
    staged_codes=frozenset({"M "}),
    staged_status_error="historical remediation changed while Guardian staged it",
    staged_paths_error="staged remediation paths do not match the exact allowlist",
    parent_error="historical remediation commit is not a direct child of exact base",
    changed_paths_error=(
        "signed remediation commit changed paths outside the exact allowlist"
    ),
    dirty_tree_error="working tree is not clean after historical remediation commit",
)
_PREVENTION_COMMIT_CONTRACT = _CommitPipelineContract(
    staged_codes=frozenset({"M ", "A "}),
    staged_status_error="prevention candidate changed while it was staged",
    staged_paths_error="staged prevention paths do not match the allowlist",
    parent_error="prevention commit is not a direct child of exact base",
    changed_paths_error="signed prevention commit changed unexpected paths",
    dirty_tree_error="working tree is not clean after prevention commit",
)


@dataclass(frozen=True, slots=True)
class PublicationResult:
    """A remote branch update confirmed after a normal fast-forward push."""

    ref: str
    previous_sha: str
    commit_sha: str


@dataclass(frozen=True, slots=True)
class PreventionPublicationResult:
    """An exact signed candidate present on one new prevention branch."""

    repository: str
    ref: str
    commit_sha: str
    created: bool


def _validated_remote_url(
    revision: ExactRevision | HistoricalRevision,
    remote_url: str | None,
    *,
    allow_file_remote: bool,
) -> str:
    candidate = revision.remote_url if remote_url is None else remote_url
    if not isinstance(candidate, str) or any(character in candidate for character in "\r\n\x00"):
        raise ValueError("remote URL must be a single, non-empty URL")
    parsed = urlsplit(candidate)
    if parsed.query or parsed.fragment or parsed.username is not None or parsed.password is not None:
        raise ValueError("remote URL must not contain credentials, query data, or fragments")
    expected_path = f"/{revision.owner}/{revision.repository}.git"

    if parsed.scheme == "https":
        if parsed.hostname is None or parsed.hostname.lower() != revision.host.lower():
            raise ValueError("remote URL host does not match repository identity")
        try:
            port = parsed.port
        except ValueError as exc:
            raise ValueError("remote URL contains an invalid port") from exc
        if port is not None or parsed.path != expected_path or parsed.netloc.lower() != revision.host.lower():
            raise ValueError("remote URL does not match repository identity")
        return candidate

    if parsed.scheme == "file" and allow_file_remote:
        if parsed.netloc not in {"", "localhost"} or "%" in parsed.path:
            raise ValueError("local remote URL must be an unencoded absolute file URL")
        local_path = Path(parsed.path)
        if (
            not local_path.is_absolute()
            or local_path.name != f"{revision.repository}.git"
            or local_path.parent.name != revision.owner
        ):
            raise ValueError("local remote URL does not match repository identity")
        return candidate

    raise ValueError("remote URL must use identity-bound HTTPS")


def _base_environment(home: Path, *, allow_file_remote: bool) -> dict[str, str]:
    environment = {
        "GIT_ALLOW_PROTOCOL": "https:file" if allow_file_remote else "https",
        "GIT_ASKPASS_REQUIRE": "force",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_PROTOCOL_FROM_USER": "0",
        "GIT_TERMINAL_PROMPT": "0",
        "HOME": str(home),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": os.defpath,
    }
    temporary_directory = os.environ.get("TMPDIR")
    if temporary_directory:
        environment["TMPDIR"] = temporary_directory
    return environment


def _validated_environment(
    values: Mapping[str, str],
    *,
    label: str,
) -> dict[str, str]:
    if not isinstance(values, Mapping):
        raise WorkspaceError(f"{label} must return an environment mapping")
    normalized: dict[str, str] = {}
    for key, value in values.items():
        if (
            not isinstance(key, str)
            or not _ENVIRONMENT_KEY_RE.fullmatch(key)
            or key in _PROTECTED_ENVIRONMENT_KEYS
            or (key != "GIT_ASKPASS" and not key.startswith("LOCALIZE_GUARDIAN_"))
            or not isinstance(value, str)
            or "\x00" in value
        ):
            raise WorkspaceError(f"{label} contains an unsafe entry")
        normalized[key] = value
    askpass = normalized.get("GIT_ASKPASS")
    if askpass is not None:
        askpass_path = Path(askpass)
        try:
            metadata = askpass_path.lstat()
        except OSError as exc:
            raise WorkspaceError(f"{label} contains an unusable askpass helper") from exc
        if (
            not askpass_path.is_absolute()
            or stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISREG(metadata.st_mode)
            or not os.access(askpass_path, os.X_OK)
        ):
            raise WorkspaceError(f"{label} contains an unusable askpass helper")
    return normalized


@dataclass(slots=True)
class _GitRunner:
    path: Path
    environment: Mapping[str, str]
    process_runner: ProcessRunner = field(repr=False)
    git_binary: str = "git"
    signing_program: str | None = None
    signing_format: SigningFormat = SigningFormat.OPENPGP
    ssh_signing_material: SSHSigningMaterial | None = None
    timeout_seconds: float = 120.0
    deadline: PollDeadline | None = field(default=None, repr=False)

    def _ssh_material(self) -> SSHSigningMaterial:
        material = self.ssh_signing_material
        if self.signing_format is not SigningFormat.SSH or material is None:
            raise WorkspaceError("exact SSH signing material is unavailable")
        if self.signing_program is None:
            raise WorkspaceError("SSH signing program is unavailable")
        try:
            canonical_ssh_fingerprint(material.fingerprint)
            root = material.root
            root_metadata = root.lstat()
            if (
                not root.is_absolute()
                or stat.S_ISLNK(root_metadata.st_mode)
                or not stat.S_ISDIR(root_metadata.st_mode)
                or stat.S_IMODE(root_metadata.st_mode) != 0o700
                or root_metadata.st_uid not in {0, os.getuid()}
            ):
                raise OSError
            for path in (material.public_key, material.allowed_signers):
                metadata = path.lstat()
                path.relative_to(root)
                if (
                    not path.is_absolute()
                    or stat.S_ISLNK(metadata.st_mode)
                    or not stat.S_ISREG(metadata.st_mode)
                    or stat.S_IMODE(metadata.st_mode) != 0o600
                    or metadata.st_uid not in {0, os.getuid()}
                    or metadata.st_nlink != 1
                ):
                    raise OSError
        except (OSError, ValueError):
            raise WorkspaceError("exact SSH signing material is unavailable") from None
        return material

    def run(
        self,
        arguments: Sequence[str],
        *,
        check: bool = True,
        extra_environment: Mapping[str, str] | None = None,
        input_text: str | None = None,
    ) -> subprocess.CompletedProcess[str]:
        if "SSH_AUTH_SOCK" in self.environment:
            raise WorkspaceError("base Git environment must not contain SSH_AUTH_SOCK")
        if extra_environment and "SSH_AUTH_SOCK" in extra_environment and (
            self.signing_format is not SigningFormat.SSH
            or not arguments
            or arguments[0] != "commit"
        ):
            raise WorkspaceError("SSH_AUTH_SOCK is only permitted for SSH git commit")
        environment = dict(self.environment)
        if extra_environment:
            overlap = _PROTECTED_ENVIRONMENT_KEYS.intersection(extra_environment)
            if overlap:
                raise WorkspaceError("command environment cannot override Git security controls")
            environment.update(extra_environment)
        command = [
            self.git_binary,
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "credential.helper=",
        ]
        if self.signing_program is not None:
            if self.signing_format is SigningFormat.SSH:
                material = self._ssh_material()
                command.extend(
                    (
                        "-c",
                        "gpg.format=ssh",
                        "-c",
                        f"gpg.ssh.program={self.signing_program}",
                        "-c",
                        f"gpg.ssh.allowedSignersFile={material.allowed_signers}",
                        "-c",
                        "gpg.minTrustLevel=fully",
                    )
                )
            else:
                command.extend(("-c", f"gpg.program={self.signing_program}"))
        command.extend(("-C", str(self.path), *arguments))
        effective_timeout = (
            self.timeout_seconds
            if self.deadline is None
            else self.deadline.remaining(self.timeout_seconds)
        )
        deadline_bound_timeout = (
            self.deadline is not None and effective_timeout < self.timeout_seconds
        )
        try:
            completed = self.process_runner(
                command,
                check=False,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="surrogateescape",
                env=environment,
                input=input_text,
                shell=False,
                timeout=effective_timeout,
            )
        except subprocess.TimeoutExpired as exc:
            if deadline_bound_timeout:
                raise PollDeadlineExceeded(
                    "Guardian poll deadline was exceeded."
                ) from None
            if self.deadline is not None:
                try:
                    self.deadline.require_remaining()
                except PollDeadlineExceeded:
                    raise
            operation = arguments[0] if arguments else "command"
            raise WorkspaceError(f"git {operation} timed out") from exc
        except OSError as exc:
            operation = arguments[0] if arguments else "command"
            raise WorkspaceError(f"git {operation} could not start") from exc
        if check and completed.returncode != 0:
            operation = arguments[0] if arguments else "command"
            raise WorkspaceError(f"git {operation} failed with exit code {completed.returncode}")
        return completed

    def revision(self, expression: str) -> str:
        value = self.run(("rev-parse", "--verify", expression)).stdout.strip()
        if not _SHA_RE.fullmatch(value):
            raise WorkspaceError("git returned a non-canonical object ID")
        return value


def _normalize_relative_path(raw_path: str) -> str:
    if (
        not isinstance(raw_path, str)
        or not raw_path
        or "\\" in raw_path
        or any(ord(character) < 32 or ord(character) == 127 for character in raw_path)
        or any(0xD800 <= ord(character) <= 0xDFFF for character in raw_path)
    ):
        raise ValueError("expected path must be a canonical repository-relative POSIX path")
    path = PurePosixPath(raw_path)
    if (
        path.is_absolute()
        or path.as_posix() != raw_path
        or any(component in {"", ".", ".."} for component in path.parts)
        or any(component.casefold() == ".git" for component in path.parts)
    ):
        raise ValueError("expected path must be a canonical repository-relative POSIX path")
    return raw_path


def _split_nul_paths(output: str) -> tuple[str, ...]:
    if not output:
        return ()
    if not output.endswith("\x00"):
        raise WorkspaceError("git returned malformed path data")
    paths = output[:-1].split("\x00")
    if any(not path for path in paths):
        raise WorkspaceError("git returned malformed path data")
    return tuple(paths)


def _porcelain_status(runner: _GitRunner) -> tuple[tuple[str, str], ...]:
    output = runner.run(
        ("status", "--porcelain=v1", "-z", "--untracked-files=all", "--ignored=matching")
    ).stdout
    if not output:
        return ()
    if not output.endswith("\x00"):
        raise WorkspaceError("git returned malformed working-tree status")
    records = output[:-1].split("\x00")
    entries: list[tuple[str, str]] = []
    index = 0
    while index < len(records):
        record = records[index]
        if len(record) < 4 or record[2] != " ":
            raise WorkspaceError("git returned malformed working-tree status")
        status_code = record[:2]
        path = record[3:]
        if "R" in status_code or "C" in status_code:
            raise WorkspaceError("renamed or copied files are not valid Guardian edits")
        entries.append((status_code, path))
        index += 1
    return tuple(entries)


def _initialize_exact_checkout(runner: _GitRunner) -> None:
    runner.run(("init", "--quiet"))
    if runner.deadline is not None:
        runner.deadline.require_remaining()
    # Review and commit stored blob bytes, not transformations selected by
    # untrusted repository attributes. In particular, text attributes added
    # without renormalization can make a fresh checkout appear dirty.
    # info/attributes takes precedence without changing any tracked file.
    attributes = runner.path / ".git" / "info" / "attributes"
    with attributes.open("x", encoding="utf-8") as stream:
        stream.write("* -text -filter -ident -working-tree-encoding\n")


def _validate_regular_tracked_file(root: Path, runner: _GitRunner, relative_path: str) -> None:
    current = root
    for index, component in enumerate(PurePosixPath(relative_path).parts):
        current = current / component
        try:
            metadata = current.lstat()
        except FileNotFoundError as exc:
            raise WorkspaceError(f"expected path is missing: {relative_path}") from exc
        if stat.S_ISLNK(metadata.st_mode):
            raise WorkspaceError(f"expected path must not be a symbolic link: {relative_path}")
        if index < len(PurePosixPath(relative_path).parts) - 1 and not stat.S_ISDIR(metadata.st_mode):
            raise WorkspaceError(f"expected path has a non-directory parent: {relative_path}")
    leaf_metadata = metadata
    if not stat.S_ISREG(leaf_metadata.st_mode) or leaf_metadata.st_nlink != 1:
        raise WorkspaceError(
            "expected path must be a regular non-hard-linked file: "
            f"{relative_path}"
        )

    root_resolved = root.resolve(strict=True)
    try:
        current.resolve(strict=True).relative_to(root_resolved)
    except ValueError as exc:
        raise WorkspaceError(f"expected path escapes the checkout: {relative_path}") from exc

    index_entry = runner.run(("ls-files", "--stage", "-z", "--", relative_path)).stdout
    records = _split_nul_paths(index_entry)
    if len(records) != 1 or "\t" not in records[0]:
        raise WorkspaceError(f"expected path is not one tracked file: {relative_path}")
    metadata, indexed_path = records[0].split("\t", 1)
    mode = metadata.split(" ", 1)[0]
    if indexed_path != relative_path or mode not in {"100644", "100755"}:
        raise WorkspaceError(f"expected path is not a tracked regular file: {relative_path}")


def _validate_regular_candidate_file(
    root: Path,
    runner: _GitRunner,
    relative_path: str,
) -> bool:
    """Validate a regular tracked or new file and return whether it is tracked."""

    current = root
    components = PurePosixPath(relative_path).parts
    for index, component in enumerate(components):
        current = current / component
        try:
            metadata = current.lstat()
        except FileNotFoundError as exc:
            raise WorkspaceError(f"expected path is missing: {relative_path}") from exc
        if stat.S_ISLNK(metadata.st_mode):
            raise WorkspaceError(
                f"expected path must not be a symbolic link: {relative_path}"
            )
        if index < len(components) - 1 and not stat.S_ISDIR(metadata.st_mode):
            raise WorkspaceError(
                f"expected path has a non-directory parent: {relative_path}"
            )
    metadata = current.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise WorkspaceError(
            f"expected path must be one regular non-hard-linked file: {relative_path}"
        )
    try:
        current.resolve(strict=True).relative_to(root.resolve(strict=True))
    except ValueError as exc:
        raise WorkspaceError(f"expected path escapes the checkout: {relative_path}") from exc

    indexed = runner.run(("ls-files", "--stage", "-z", "--", relative_path)).stdout
    records = _split_nul_paths(indexed)
    if not records:
        return False
    if len(records) != 1 or "\t" not in records[0]:
        raise WorkspaceError(f"expected path has ambiguous index state: {relative_path}")
    index_metadata, indexed_path = records[0].split("\t", 1)
    mode = index_metadata.split(" ", 1)[0]
    if indexed_path != relative_path or mode not in {"100644", "100755"}:
        raise WorkspaceError(
            f"expected path is not a tracked regular file: {relative_path}"
        )
    return True


def _validate_feedback_urls(
    revision: ExactRevision,
    pull_number: int,
    feedback_urls: Sequence[str],
    *,
    feedback_repository: str | None = None,
) -> tuple[str, ...]:
    if isinstance(pull_number, bool) or not isinstance(pull_number, int) or pull_number <= 0:
        raise ValueError("pull_number must be a positive integer")
    if not feedback_urls:
        raise ValueError("at least one feedback URL is required")
    if feedback_repository is None:
        feedback_owner = revision.owner
        feedback_name = revision.repository
    else:
        if not isinstance(feedback_repository, str) or feedback_repository.count("/") != 1:
            raise ValueError("feedback_repository must use owner/name form")
        feedback_owner, feedback_name = feedback_repository.split("/", 1)
        if not _OWNER_RE.fullmatch(feedback_owner) or not _IDENTIFIER_RE.fullmatch(
            feedback_name
        ):
            raise ValueError("feedback_repository must use owner/name form")
    expected_paths = {
        f"/{feedback_owner}/{feedback_name}/pull/{pull_number}",
        f"/{feedback_owner}/{feedback_name}/issues/{pull_number}",
    }
    normalized: list[str] = []
    for feedback_url in feedback_urls:
        if not isinstance(feedback_url, str) or any(
            character in feedback_url for character in "\r\n\x00"
        ):
            raise ValueError("feedback URLs must be canonical GitHub links")
        parsed = urlsplit(feedback_url)
        if (
            parsed.scheme != "https"
            or parsed.hostname is None
            or parsed.hostname.lower() != revision.host.lower()
            or parsed.netloc.lower() != revision.host.lower()
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.path not in expected_paths
            or not _FEEDBACK_FRAGMENT_RE.fullmatch(parsed.fragment)
        ):
            raise ValueError("feedback URL does not match the exact pull request")
        normalized.append(feedback_url)
    if len(set(normalized)) != len(normalized):
        raise ValueError("feedback URLs must be unique")
    return tuple(sorted(normalized))


def _validate_historical_feedback_urls(
    revision: ExactRevision,
    pull_numbers: Sequence[int],
    feedback_urls: Sequence[str],
    *,
    feedback_repository: str,
) -> tuple[str, ...]:
    """Bind every historical link to an explicitly selected repository and PR."""

    numbers = tuple(pull_numbers)
    if (
        not numbers
        or len(set(numbers)) != len(numbers)
        or any(
            isinstance(number, bool)
            or not isinstance(number, int)
            or number <= 0
            for number in numbers
        )
    ):
        raise ValueError(
            "feedback_pull_numbers must contain unique positive integers"
        )
    if not isinstance(feedback_repository, str) or feedback_repository.count("/") != 1:
        raise ValueError("feedback_repository must use owner/name form")
    feedback_owner, feedback_name = feedback_repository.split("/", 1)
    if not _OWNER_RE.fullmatch(feedback_owner) or not _IDENTIFIER_RE.fullmatch(
        feedback_name
    ):
        raise ValueError("feedback_repository must use owner/name form")
    if not feedback_urls:
        raise ValueError("at least one historical feedback URL is required")

    paths_to_number = {
        path: number
        for number in numbers
        for path in (
            f"/{feedback_owner}/{feedback_name}/pull/{number}",
            f"/{feedback_owner}/{feedback_name}/issues/{number}",
        )
    }
    normalized: list[str] = []
    represented_numbers: set[int] = set()
    for feedback_url in feedback_urls:
        if not isinstance(feedback_url, str) or any(
            character in feedback_url for character in "\r\n\x00"
        ):
            raise ValueError("historical feedback URL is not canonical")
        parsed = urlsplit(feedback_url)
        pull_number = paths_to_number.get(parsed.path)
        if (
            parsed.scheme != "https"
            or parsed.hostname is None
            or parsed.hostname.lower() != revision.host.lower()
            or parsed.netloc.lower() != revision.host.lower()
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or pull_number is None
            or not _FEEDBACK_FRAGMENT_RE.fullmatch(parsed.fragment)
        ):
            raise ValueError("historical feedback URL does not match its source PR")
        normalized.append(feedback_url)
        represented_numbers.add(pull_number)
    if len(set(normalized)) != len(normalized):
        raise ValueError("historical feedback URLs must be unique")
    if represented_numbers != set(numbers):
        raise ValueError("every historical feedback PR must have an exact URL")
    return tuple(sorted(normalized))


def _validate_identity_value(value: str, *, label: str) -> str:
    if not isinstance(value, str) or not value.strip() or any(
        character in value for character in "\r\n\x00"
    ):
        raise ValueError(f"{label} must be a non-empty single-line value")
    return value


def _openpgp_signing_environment(values: Mapping[str, str] | None) -> dict[str, str]:
    if values is None:
        configured_home = os.environ.get("GNUPGHOME")
        candidate = Path(configured_home) if configured_home else Path.home() / ".gnupg"
        try:
            trusted_home = resolve_trusted_private_directory(candidate)
        except ValueError:
            return {}
        return {"GNUPGHOME": str(trusted_home)}
    if not isinstance(values, Mapping) or any(
        key not in _OPENPGP_SIGNING_ENVIRONMENT_KEYS or not isinstance(value, str)
        for key, value in values.items()
    ):
        raise ValueError("signing_environment may only set GNUPGHOME")
    normalized = dict(values)
    if "GNUPGHOME" in normalized:
        home = Path(normalized["GNUPGHOME"])
        try:
            trusted_home = resolve_trusted_private_directory(home)
        except ValueError:
            raise ValueError(
                "GNUPGHOME must be an absolute, current-user-owned, "
                "non-symlinked 0700 directory below trusted ancestors"
            ) from None
        normalized["GNUPGHOME"] = str(trusted_home)
    return normalized


def _ssh_signing_environment(
    values: Mapping[str, str] | None,
    *,
    require_socket: bool,
) -> dict[str, str]:
    if require_socket:
        return ssh_agent_environment(values)
    if values is not None and (
        not isinstance(values, Mapping) or any(
            key != "SSH_AUTH_SOCK" or not isinstance(value, str)
            for key, value in values.items()
        )
    ):
        raise ValueError("signing_environment may only set SSH_AUTH_SOCK")
    if values is not None and "SSH_AUTH_SOCK" in values:
        raw_socket = values["SSH_AUTH_SOCK"]
        socket_path = Path(raw_socket)
        if (
            not raw_socket
            or any(character in raw_socket for character in "\r\n\x00")
            or not socket_path.is_absolute()
            or ".." in socket_path.parts
        ):
            raise ValueError("SSH_AUTH_SOCK must be an absolute Unix socket path")
    return {}


def _canonical_signing_identity(
    runner: _GitRunner,
    signing_key: str | None,
) -> str | None:
    if runner.signing_format is SigningFormat.SSH:
        expected = runner._ssh_material().fingerprint
        if signing_key is not None and canonical_ssh_fingerprint(signing_key) != expected:
            raise ValueError("signing key fingerprint does not match SSH signing material")
        return expected
    return canonical_signing_key(signing_key) if signing_key is not None else None


def _commit_signing_environment(
    runner: _GitRunner,
    values: Mapping[str, str] | None,
) -> dict[str, str]:
    if runner.signing_format is SigningFormat.SSH:
        return ssh_agent_environment(
            values,
            temporary_root=runner._ssh_material().root,
        )
    return _openpgp_signing_environment(values)


def _verification_signing_environment(
    runner: _GitRunner,
    values: Mapping[str, str] | None,
) -> dict[str, str]:
    if runner.signing_format is SigningFormat.SSH:
        return _ssh_signing_environment(values, require_socket=False)
    return _openpgp_signing_environment(values)


def _verify_commit_signature(
    runner: _GitRunner,
    commit_sha: str,
    *,
    signing_key: str | None,
    signing_environment: Mapping[str, str],
) -> None:
    completed = runner.run(
        ("verify-commit", "--raw", commit_sha),
        extra_environment=signing_environment,
    )
    output = "\n".join((completed.stdout or "", completed.stderr or ""))
    if runner.signing_format is SigningFormat.SSH:
        expected = _canonical_signing_identity(runner, signing_key)
        assert expected is not None
        if not ssh_signature_matches(output, expected):
            raise WorkspaceError(
                "verified SSH commit signer does not match the configured fingerprint"
            )
    elif signing_key is not None and not signature_matches(output, signing_key):
        raise WorkspaceError(
            "verified commit signer does not match the configured fingerprint"
        )


@dataclass(slots=True)
class GuardianWorkspace:
    """One detached exact-SHA checkout owned by a temporary-directory context."""

    path: Path
    revision: ExactRevision
    _runner: _GitRunner = field(repr=False)

    @property
    def original_sha(self) -> str:
        return self.revision.sha

    def _stage_commit_and_verify(
        self,
        *,
        normalized_paths: tuple[str, ...],
        message: str,
        contract: _CommitPipelineContract,
        sign: bool,
        signing_key: str | None,
        signing_environment: Mapping[str, str],
        author_name: str,
        author_email: str,
    ) -> CommitResult:
        """Stage exact paths, create one commit, and verify its immutable result."""

        self._runner.run(("add", "--", *normalized_paths))
        staged_status = _porcelain_status(self._runner)
        if (
            any(code not in contract.staged_codes for code, _path in staged_status)
            or tuple(sorted(path for _code, path in staged_status)) != normalized_paths
        ):
            raise WorkspaceError(contract.staged_status_error)
        staged_paths = tuple(
            sorted(
                _split_nul_paths(
                    self._runner.run(
                        (
                            "diff",
                            "--cached",
                            "--name-only",
                            "--no-renames",
                            "-z",
                            "HEAD",
                            "--",
                        )
                    ).stdout
                )
            )
        )
        if staged_paths != normalized_paths:
            raise WorkspaceError(contract.staged_paths_error)

        command = ["commit", "--cleanup=verbatim", "--file=-"]
        if sign:
            if self._runner.signing_format is SigningFormat.SSH:
                command.append(f"-S{self._runner._ssh_material().public_key}")
            else:
                command.append("-S" if signing_key is None else f"-S{signing_key}")
        else:
            command.append("--no-gpg-sign")
        identity_environment = {
            "GIT_AUTHOR_EMAIL": author_email,
            "GIT_AUTHOR_NAME": author_name,
            "GIT_COMMITTER_EMAIL": author_email,
            "GIT_COMMITTER_NAME": author_name,
            **signing_environment,
        }
        self._runner.run(
            tuple(command),
            extra_environment=identity_environment,
            input_text=message,
        )

        commit_sha = self._runner.revision("HEAD^{commit}")
        parent_sha = self._runner.revision("HEAD^1^{commit}")
        if parent_sha != self.original_sha:
            raise WorkspaceError(contract.parent_error)
        changed_paths = tuple(
            sorted(
                _split_nul_paths(
                    self._runner.run(
                        (
                            "diff-tree",
                            "--no-commit-id",
                            "--name-only",
                            "--no-renames",
                            "-z",
                            "-r",
                            parent_sha,
                            commit_sha,
                            "--",
                        )
                    ).stdout
                )
            )
        )
        if changed_paths != normalized_paths:
            raise WorkspaceError(contract.changed_paths_error)
        if sign:
            _verify_commit_signature(
                self._runner,
                commit_sha,
                signing_key=signing_key,
                signing_environment=(
                    {}
                    if self._runner.signing_format is SigningFormat.SSH
                    else signing_environment
                ),
            )
        if _porcelain_status(self._runner):
            raise WorkspaceError(contract.dirty_tree_error)
        return CommitResult(
            commit_sha=commit_sha,
            parent_sha=parent_sha,
            changed_paths=changed_paths,
            signature_verified=sign,
        )

    def commit_validated_changes(
        self,
        *,
        expected_paths: Sequence[str],
        pull_number: int,
        feedback_urls: Sequence[str],
        feedback_repository: str | None = None,
        sign: bool = True,
        signing_key: str | None = None,
        signing_environment: Mapping[str, str] | None = None,
        author_name: str = _DEFAULT_AUTHOR_NAME,
        author_email: str = _DEFAULT_AUTHOR_EMAIL,
    ) -> CommitResult:
        """Commit exactly the already-validated files, then re-verify the commit."""
        if not isinstance(sign, bool):
            raise ValueError("sign must be a boolean")
        if sign or signing_key is not None:
            signing_key = _canonical_signing_identity(self._runner, signing_key)
        if not sign and signing_environment is not None:
            raise ValueError("signing_environment requires signed commits")
        verified_signing_environment = (
            _commit_signing_environment(self._runner, signing_environment)
            if sign
            else {}
        )
        author_name = _validate_identity_value(author_name, label="author_name")
        author_email = _validate_identity_value(author_email, label="author_email")
        normalized_paths = tuple(sorted(_normalize_relative_path(path) for path in expected_paths))
        if not normalized_paths or len(set(normalized_paths)) != len(normalized_paths):
            raise ValueError("expected_paths must contain unique changed files")
        normalized_feedback = _validate_feedback_urls(
            self.revision,
            pull_number,
            feedback_urls,
            feedback_repository=feedback_repository,
        )

        if self._runner.revision("HEAD^{commit}") != self.original_sha:
            raise WorkspaceError("checkout HEAD no longer matches the original exact SHA")
        for relative_path in normalized_paths:
            _validate_regular_tracked_file(self.path, self._runner, relative_path)

        status_entries = _porcelain_status(self._runner)
        if any(code[0] not in {" ", "?", "!"} for code, _path in status_entries):
            raise WorkspaceError("pre-staged changes are not accepted by Guardian")
        if (
            any(code != " M" for code, _path in status_entries)
            or tuple(sorted(path for _code, path in status_entries)) != normalized_paths
        ):
            raise WorkspaceError("unexpected working-tree changes are present")

        message_lines = [
            _COMMIT_SUBJECT,
            "",
            "Created by the Localize Guardian bot.",
            "",
            "Validated feedback:",
            *(f"- {url}" for url in normalized_feedback),
            "",
        ]
        return self._stage_commit_and_verify(
            normalized_paths=normalized_paths,
            message="\n".join(message_lines),
            contract=_VALIDATED_COMMIT_CONTRACT,
            sign=sign,
            signing_key=signing_key,
            signing_environment=verified_signing_environment,
            author_name=author_name,
            author_email=author_email,
        )

    def commit_historical_remediation_changes(
        self,
        *,
        expected_paths: Sequence[str],
        feedback_repository: str,
        feedback_pull_numbers: Sequence[int],
        feedback_urls: Sequence[str],
        evidence_hash: str,
        signing_key: str | None = None,
        signing_environment: Mapping[str, str] | None = None,
        author_name: str = _DEFAULT_AUTHOR_NAME,
        author_email: str = _DEFAULT_AUTHOR_EMAIL,
    ) -> CommitResult:
        """Sign one tracked-file-only current-base historical remediation."""

        if not re.fullmatch(r"[0-9a-f]{64}", evidence_hash):
            raise ValueError("evidence_hash must be a lowercase SHA-256 digest")
        signing_key = _canonical_signing_identity(self._runner, signing_key)
        verified_signing_environment = _commit_signing_environment(
            self._runner,
            signing_environment,
        )
        author_name = _validate_identity_value(author_name, label="author_name")
        author_email = _validate_identity_value(author_email, label="author_email")
        normalized_paths = tuple(
            sorted(_normalize_relative_path(path) for path in expected_paths)
        )
        if not normalized_paths or len(set(normalized_paths)) != len(normalized_paths):
            raise ValueError("expected_paths must contain unique changed files")
        normalized_feedback = _validate_historical_feedback_urls(
            self.revision,
            feedback_pull_numbers,
            feedback_urls,
            feedback_repository=feedback_repository,
        )

        if self._runner.revision("HEAD^{commit}") != self.original_sha:
            raise WorkspaceError("checkout HEAD no longer matches the original exact SHA")
        for relative_path in normalized_paths:
            _validate_regular_tracked_file(self.path, self._runner, relative_path)

        status_entries = _porcelain_status(self._runner)
        if any(code[0] not in {" ", "?", "!"} for code, _path in status_entries):
            raise WorkspaceError("pre-staged changes are not accepted by Guardian")
        if (
            any(code != " M" for code, _path in status_entries)
            or tuple(sorted(path for _code, path in status_entries))
            != normalized_paths
        ):
            raise WorkspaceError(
                "unexpected historical remediation working-tree changes are present"
            )

        message_lines = [
            _REMEDIATION_COMMIT_SUBJECT,
            "",
            "Created by the Localize Guardian bot for human review.",
            "",
            f"Historical evidence: {evidence_hash}",
            "",
            "Validated historical feedback:",
            *(f"- {url}" for url in normalized_feedback),
            "",
        ]
        return self._stage_commit_and_verify(
            normalized_paths=normalized_paths,
            message="\n".join(message_lines),
            contract=_HISTORICAL_REMEDIATION_COMMIT_CONTRACT,
            sign=True,
            signing_key=signing_key,
            signing_environment=verified_signing_environment,
            author_name=author_name,
            author_email=author_email,
        )

    def commit_prevention_changes(
        self,
        *,
        expected_paths: Sequence[str],
        evidence_hash: str,
        signing_key: str | None = None,
        signing_environment: Mapping[str, str] | None = None,
        author_name: str = _DEFAULT_AUTHOR_NAME,
        author_email: str = _DEFAULT_AUTHOR_EMAIL,
    ) -> CommitResult:
        """Sign one validated code-and-test candidate, including bounded new files."""

        if not re.fullmatch(r"[0-9a-f]{64}", evidence_hash):
            raise ValueError("evidence_hash must be a lowercase SHA-256 digest")
        signing_key = _canonical_signing_identity(self._runner, signing_key)
        verified_signing_environment = _commit_signing_environment(
            self._runner,
            signing_environment,
        )
        author_name = _validate_identity_value(author_name, label="author_name")
        author_email = _validate_identity_value(author_email, label="author_email")
        normalized_paths = tuple(
            sorted(_normalize_relative_path(path) for path in expected_paths)
        )
        if not normalized_paths or len(set(normalized_paths)) != len(normalized_paths):
            raise ValueError("expected_paths must contain unique changed files")
        if self._runner.revision("HEAD^{commit}") != self.original_sha:
            raise WorkspaceError("checkout HEAD no longer matches the original exact SHA")

        tracked = {
            path: _validate_regular_candidate_file(self.path, self._runner, path)
            for path in normalized_paths
        }
        status_entries = _porcelain_status(self._runner)
        if tuple(sorted(path for _code, path in status_entries)) != normalized_paths:
            raise WorkspaceError("unexpected prevention working-tree changes are present")
        for code, path in status_entries:
            expected_code = " M" if tracked[path] else "??"
            if code != expected_code:
                raise WorkspaceError("prevention candidate has an unsupported file operation")

        return self._stage_commit_and_verify(
            normalized_paths=normalized_paths,
            message=(
                f"{_PREVENTION_COMMIT_SUBJECT}\n\n"
                "Created by the Localize Guardian bot for human review.\n\n"
                f"Prevention evidence: {evidence_hash}\n"
            ),
            contract=_PREVENTION_COMMIT_CONTRACT,
            sign=True,
            signing_key=signing_key,
            signing_environment=verified_signing_environment,
            author_name=author_name,
            author_email=author_email,
        )

    def publish_prevention_branch(
        self,
        commit: CommitResult,
        *,
        push_repository: str,
        branch: str,
        branch_prefix: str,
        credential_environment: CredentialEnvironment,
        before_push: Callable[[], None],
        signing_key: str | None = None,
        signing_environment: Mapping[str, str] | None = None,
        remote_url: str | None = None,
        allow_file_remote: bool = False,
        _operation: str = "prevention",
    ) -> PreventionPublicationResult:
        """Create exactly one new allowlisted branch with an absence lease."""

        if _operation not in {"prevention", "remediation"}:
            raise ValueError("branch publication operation is invalid")

        if push_repository.count("/") != 1:
            raise ValueError("push_repository must use owner/name form")
        owner, repository = push_repository.split("/", 1)
        ref = f"refs/heads/{branch}"
        _validate_ref(ref)
        if not branch.startswith(branch_prefix) or branch == branch_prefix:
            raise ValueError(f"{_operation} branch is outside the configured prefix")
        push_revision = ExactRevision(
            host=self.revision.host,
            owner=owner,
            repository=repository,
            ref=ref,
            sha=self.original_sha,
        )
        remote = _validated_remote_url(
            push_revision,
            remote_url,
            allow_file_remote=allow_file_remote,
        )
        if not commit.signature_verified:
            raise WorkspaceError(
                f"Guardian refuses to publish an unsigned {_operation} commit"
            )
        if self._runner.revision("HEAD^{commit}") != commit.commit_sha:
            raise WorkspaceError(
                f"checkout HEAD no longer matches {_operation} commit"
            )
        if (
            commit.parent_sha != self.original_sha
            or self._runner.revision("HEAD^1^{commit}") != self.original_sha
        ):
            raise WorkspaceError(
                f"{_operation} commit is not a direct child of exact base"
            )
        if _porcelain_status(self._runner):
            raise WorkspaceError(
                f"working tree is not clean before {_operation} publication"
            )
        _verify_commit_signature(
            self._runner,
            commit.commit_sha,
            signing_key=_canonical_signing_identity(self._runner, signing_key),
            signing_environment=_verification_signing_environment(
                self._runner,
                signing_environment,
            ),
        )

        try:
            credentials = _validated_environment(
                credential_environment(),
                label="credential environment",
            )
        except PollDeadlineExceeded:
            raise
        except WorkspaceError:
            raise
        except Exception:
            raise WorkspaceError("credential environment provider failed") from None
        before = self._runner.run(
            ("ls-remote", "--refs", remote, ref),
            extra_environment=credentials,
        ).stdout
        records = [line.split("\t", 1) for line in before.splitlines() if line]
        if records == [[commit.commit_sha, ref]]:
            return PreventionPublicationResult(
                repository=push_repository,
                ref=ref,
                commit_sha=commit.commit_sha,
                created=False,
            )
        if records:
            raise WorkspaceError(
                f"{_operation} branch already exists at another commit"
            )

        _verify_commit_signature(
            self._runner,
            commit.commit_sha,
            signing_key=_canonical_signing_identity(self._runner, signing_key),
            signing_environment=_verification_signing_environment(
                self._runner,
                signing_environment,
            ),
        )
        before_push()
        self._runner.run(
            (
                "push",
                "--porcelain",
                "--no-verify",
                "--atomic",
                f"--force-with-lease={ref}:",
                remote,
                f"{commit.commit_sha}:{ref}",
            ),
            extra_environment=credentials,
        )
        after = self._runner.run(
            ("ls-remote", "--refs", remote, ref),
            extra_environment=credentials,
        ).stdout
        confirmed = [line.split("\t", 1) for line in after.splitlines() if line]
        if confirmed != [[commit.commit_sha, ref]]:
            raise WorkspaceError(f"remote did not confirm the {_operation} commit")
        return PreventionPublicationResult(
            repository=push_repository,
            ref=ref,
            commit_sha=commit.commit_sha,
            created=True,
        )

    def publish_remediation_branch(
        self,
        commit: CommitResult,
        *,
        push_repository: str,
        branch: str,
        branch_prefix: str,
        credential_environment: CredentialEnvironment,
        before_push: Callable[[], None],
        signing_key: str | None = None,
        signing_environment: Mapping[str, str] | None = None,
        remote_url: str | None = None,
        allow_file_remote: bool = False,
    ) -> PreventionPublicationResult:
        """Publish an exact remediation branch with remediation diagnostics."""

        return self.publish_prevention_branch(
            commit,
            push_repository=push_repository,
            branch=branch,
            branch_prefix=branch_prefix,
            credential_environment=credential_environment,
            before_push=before_push,
            signing_key=signing_key,
            signing_environment=signing_environment,
            remote_url=remote_url,
            allow_file_remote=allow_file_remote,
            _operation="remediation",
        )

    def publish_commit(
        self,
        commit: CommitResult,
        *,
        credential_environment: CredentialEnvironment | None = None,
        require_signature: bool = True,
        signing_key: str | None = None,
        signing_environment: Mapping[str, str] | None = None,
        before_push: Callable[[], None] | None = None,
    ) -> PublicationResult:
        """Publish one verified direct descendant with an exact remote-head lease."""

        if not isinstance(commit, CommitResult):
            raise TypeError("commit must be a CommitResult")
        if not isinstance(require_signature, bool):
            raise ValueError("require_signature must be a boolean")
        if require_signature and not commit.signature_verified:
            raise WorkspaceError("Guardian refuses to publish an unsigned commit")
        if self._runner.revision("HEAD^{commit}") != commit.commit_sha:
            raise WorkspaceError("checkout HEAD no longer matches the Guardian commit")
        if self._runner.revision("HEAD^1^{commit}") != self.original_sha:
            raise WorkspaceError("Guardian commit is not a direct descendant of intake")
        if commit.parent_sha != self.original_sha:
            raise WorkspaceError("commit result parent does not match intake")
        actual_paths = tuple(
            sorted(
                _split_nul_paths(
                    self._runner.run(
                        (
                            "diff-tree",
                            "--no-commit-id",
                            "--name-only",
                            "--no-renames",
                            "-z",
                            "-r",
                            self.original_sha,
                            commit.commit_sha,
                            "--",
                        )
                    ).stdout
                )
            )
        )
        if not actual_paths or actual_paths != commit.changed_paths:
            raise WorkspaceError("commit result paths do not match the exact local commit")
        if _porcelain_status(self._runner):
            raise WorkspaceError("working tree is not clean before publication")
        if require_signature:
            _verify_commit_signature(
                self._runner,
                commit.commit_sha,
                signing_key=_canonical_signing_identity(self._runner, signing_key),
                signing_environment=_verification_signing_environment(
                    self._runner,
                    signing_environment,
                ),
            )

        def credentials() -> dict[str, str]:
            if credential_environment is None:
                return {}
            try:
                values = credential_environment()
            except PollDeadlineExceeded:
                raise
            except Exception:
                raise WorkspaceError("credential environment provider failed") from None
            return _validated_environment(values, label="credential environment")

        self._runner.run(
            (
                "fetch",
                "--quiet",
                "--no-tags",
                "--no-recurse-submodules",
                "--depth=1",
                "origin",
                self.revision.ref,
            ),
            extra_environment=credentials(),
        )
        if self._runner.revision("FETCH_HEAD^{commit}") != self.original_sha:
            raise WorkspaceError("remote branch changed since intake")

        push_environment = credentials()
        if require_signature:
            _verify_commit_signature(
                self._runner,
                commit.commit_sha,
                signing_key=_canonical_signing_identity(self._runner, signing_key),
                signing_environment=_verification_signing_environment(
                    self._runner,
                    signing_environment,
                ),
            )
        if before_push is not None:
            before_push()
        self._runner.run(
            (
                "push",
                "--porcelain",
                "--no-verify",
                "--atomic",
                f"--force-with-lease={self.revision.ref}:{self.original_sha}",
                "origin",
                f"{commit.commit_sha}:{self.revision.ref}",
            ),
            extra_environment=push_environment,
        )
        remote_output = self._runner.run(
            ("ls-remote", "--refs", "origin", self.revision.ref),
            extra_environment=credentials(),
        ).stdout
        records = [line.split("\t", 1) for line in remote_output.splitlines() if line]
        if records != [[commit.commit_sha, self.revision.ref]]:
            raise WorkspaceError("remote did not confirm the exact Guardian commit")
        return PublicationResult(
            ref=self.revision.ref,
            previous_sha=self.original_sha,
            commit_sha=commit.commit_sha,
        )


@dataclass(frozen=True, slots=True)
class HistoricalWorkspace:
    """Read-only capability wrapper around an exact historical checkout."""

    path: Path
    revision: HistoricalRevision

    @property
    def original_sha(self) -> str:
        return self.revision.sha


@contextmanager
def materialize_exact_checkout(
    revision: ExactRevision,
    *,
    remote_url: str | None = None,
    allow_file_remote: bool = False,
    temporary_root: Path | str | None = None,
    credential_environment: CredentialEnvironment | None = None,
    git_binary: str = "git",
    signing_program: str | None = None,
    signing_format: SigningFormat = SigningFormat.OPENPGP,
    ssh_signing_material: SSHSigningMaterial | None = None,
    timeout_seconds: float = 120.0,
    deadline: PollDeadline | None = None,
    _process_runner: ProcessRunner = _bounded_git_process,
) -> Iterator[GuardianWorkspace]:
    """Yield an ephemeral detached checkout iff ``ref`` resolves to ``sha`` exactly."""
    if not isinstance(revision, ExactRevision):
        raise TypeError("revision must be an ExactRevision")
    if not isinstance(allow_file_remote, bool):
        raise ValueError("allow_file_remote must be a boolean")
    if (
        not isinstance(git_binary, str)
        or not git_binary
        or any(character in git_binary for character in "\r\n\x00")
    ):
        raise ValueError("git_binary must be a safe executable name or path")
    if signing_program is not None and (
        not isinstance(signing_program, str)
        or not signing_program
        or any(character in signing_program for character in "\r\n\x00")
    ):
        raise ValueError("signing_program must be a safe executable name or path")
    if not isinstance(signing_format, SigningFormat):
        raise TypeError("signing_format must be a SigningFormat")
    if signing_format is SigningFormat.SSH:
        if signing_program is None or ssh_signing_material is None:
            raise ValueError(
                "SSH signing requires a signing program and exact signing material"
            )
        require_absolute_trusted_executable(
            (signing_program,),
            field="signing_program",
        )
    elif ssh_signing_material is not None:
        raise ValueError("SSH signing material is only valid with SSH signing")
    if (
        isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, (int, float))
        or timeout_seconds <= 0
    ):
        raise ValueError("timeout_seconds must be positive")
    validated_remote = _validated_remote_url(
        revision,
        remote_url,
        allow_file_remote=allow_file_remote,
    )

    root = None if temporary_root is None else str(Path(temporary_root))
    with tempfile.TemporaryDirectory(prefix="localize-guardian-git-", dir=root) as temp_dir:
        temporary_directory = Path(temp_dir)
        home = temporary_directory / "home"
        checkout = temporary_directory / "checkout"
        home.mkdir(mode=0o700)
        checkout.mkdir(mode=0o700)
        runner = _GitRunner(
            path=checkout,
            environment=_base_environment(home, allow_file_remote=allow_file_remote),
            process_runner=_process_runner,
            git_binary=git_binary,
            signing_program=signing_program,
            signing_format=signing_format,
            ssh_signing_material=ssh_signing_material,
            timeout_seconds=float(timeout_seconds),
            deadline=deadline,
        )
        _initialize_exact_checkout(runner)
        runner.run(("remote", "add", "origin", validated_remote))

        fetch_environment: dict[str, str] = {}
        if credential_environment is not None:
            try:
                provided_environment = credential_environment()
            except PollDeadlineExceeded:
                raise
            except Exception:
                raise WorkspaceError("credential environment provider failed") from None
            fetch_environment = _validated_environment(
                provided_environment,
                label="credential environment",
            )
        runner.run(
            (
                "fetch",
                "--quiet",
                "--no-tags",
                "--no-recurse-submodules",
                "--depth=1",
                "origin",
                revision.ref,
            ),
            extra_environment=fetch_environment,
        )
        if runner.revision("FETCH_HEAD^{commit}") != revision.sha:
            raise WorkspaceError("remote ref did not resolve to the exact expected SHA")
        runner.run(("checkout", "--quiet", "--detach", "--force", revision.sha, "--"))
        if runner.revision("HEAD^{commit}") != revision.sha:
            raise WorkspaceError("checkout did not materialize the exact expected SHA")
        symbolic_head = runner.run(("symbolic-ref", "--quiet", "HEAD"), check=False)
        if symbolic_head.returncode == 0:
            raise WorkspaceError("exact checkout unexpectedly has an attached branch")
        if _porcelain_status(runner):
            raise WorkspaceError("exact checkout is not clean")
        yield GuardianWorkspace(path=checkout, revision=revision, _runner=runner)


@contextmanager
def materialize_historical_checkout(
    revision: HistoricalRevision,
    *,
    remote_url: str | None = None,
    allow_file_remote: bool = False,
    temporary_root: Path | str | None = None,
    credential_environment: CredentialEnvironment | None = None,
    git_binary: str = "git",
    timeout_seconds: float = 120.0,
    deadline: PollDeadline | None = None,
    _process_runner: ProcessRunner = _bounded_git_process,
) -> Iterator[HistoricalWorkspace]:
    """Yield a detached exact historical checkout with no write capabilities."""

    if not isinstance(revision, HistoricalRevision):
        raise TypeError("revision must be a HistoricalRevision")
    if not isinstance(allow_file_remote, bool):
        raise ValueError("allow_file_remote must be a boolean")
    if (
        not isinstance(git_binary, str)
        or not git_binary
        or any(character in git_binary for character in "\r\n\x00")
    ):
        raise ValueError("git_binary must be a safe executable name or path")
    if (
        isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, (int, float))
        or timeout_seconds <= 0
    ):
        raise ValueError("timeout_seconds must be positive")
    validated_remote = _validated_remote_url(
        revision,
        remote_url,
        allow_file_remote=allow_file_remote,
    )

    root = None if temporary_root is None else str(Path(temporary_root))
    with tempfile.TemporaryDirectory(
        prefix="localize-guardian-history-git-",
        dir=root,
    ) as temp_dir:
        temporary_directory = Path(temp_dir)
        home = temporary_directory / "home"
        checkout = temporary_directory / "checkout"
        home.mkdir(mode=0o700)
        checkout.mkdir(mode=0o700)
        runner = _GitRunner(
            path=checkout,
            environment=_base_environment(home, allow_file_remote=allow_file_remote),
            process_runner=_process_runner,
            git_binary=git_binary,
            timeout_seconds=float(timeout_seconds),
            deadline=deadline,
        )
        _initialize_exact_checkout(runner)
        runner.run(("remote", "add", "origin", validated_remote))

        fetch_environment: dict[str, str] = {}
        if credential_environment is not None:
            try:
                provided_environment = credential_environment()
            except PollDeadlineExceeded:
                raise
            except Exception:
                raise WorkspaceError("credential environment provider failed") from None
            fetch_environment = _validated_environment(
                provided_environment,
                label="credential environment",
            )
        runner.run(
            (
                "fetch",
                "--quiet",
                "--no-tags",
                "--no-recurse-submodules",
                "--depth=1",
                "origin",
                revision.fetch_target,
            ),
            extra_environment=fetch_environment,
        )
        if runner.revision("FETCH_HEAD^{commit}") != revision.sha:
            raise WorkspaceError("historical ref did not resolve to the exact expected SHA")
        runner.run(("checkout", "--quiet", "--detach", "--force", revision.sha, "--"))
        if runner.revision("HEAD^{commit}") != revision.sha:
            raise WorkspaceError("checkout did not materialize the exact expected SHA")
        symbolic_head = runner.run(("symbolic-ref", "--quiet", "HEAD"), check=False)
        if symbolic_head.returncode == 0:
            raise WorkspaceError("historical checkout unexpectedly has an attached branch")
        if _porcelain_status(runner):
            raise WorkspaceError("historical checkout is not clean")
        yield HistoricalWorkspace(path=checkout, revision=revision)


__all__ = [
    "CommitResult",
    "ExactRevision",
    "GuardianWorkspace",
    "HistoricalRevision",
    "HistoricalWorkspace",
    "PreventionPublicationResult",
    "PublicationResult",
    "WorkspaceError",
    "materialize_exact_checkout",
    "materialize_historical_checkout",
]
