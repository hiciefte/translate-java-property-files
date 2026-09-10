"""Deterministic GitHub intake and least-privilege write brokerage for Guardian.

Review text and pull-request metadata are untrusted data.  This module only
normalizes them into immutable records; it never invokes a shell or treats
their contents as commands.  Write operations use a separately minted token,
re-read the pull request, and enforce the configured repository/owner/branch
boundary immediately before each mutation.
"""

from __future__ import annotations

import hashlib
import json
import re
from contextlib import contextmanager
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from enum import Enum
from fnmatch import fnmatchcase
from typing import Any, Callable, Iterable, Iterator, Mapping, Sequence
from urllib.parse import quote, urlsplit

import httpx

from localize.guardian.deadline import PollDeadline, deadline_httpx_timeout
from localize.guardian.credentials import (
    CredentialError,
    CredentialSnapshot,
    SecretCommand,
)
from localize.guardian.json_safety import loads_bounded_json
from localize.guardian.models import AllowedHeadRepository, TrustedActor


_REPOSITORY_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_BRANCH_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/\-]*$")
_SHA_RE = re.compile(r"^[0-9a-fA-F]{40,64}$")
_FULL_LOWER_SHA_RE = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_MARKER_ID_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,200}$")
_CODERABBIT_LOGINS = frozenset({"coderabbitai[bot]"})
_MAX_PAGINATION_PAGES = 100
_MAX_PAGINATION_ITEMS = 10_000
_MAX_RESPONSE_BYTES = 4 * 1024 * 1024
_MAX_OPEN_PULL_REQUESTS = 200
_MAX_FEEDBACK_ITEMS_PER_PULL = 500
_MAX_FEEDBACK_BYTES_PER_PULL = 2 * 1024 * 1024
_MAX_CHANGED_FILES_PER_PULL = 500
_MAX_AFFECTED_PATHS_PER_OPEN_PULL = 2 * _MAX_CHANGED_FILES_PER_PULL
_MAX_CHANGED_FILE_BYTES_PER_PULL = 4 * 1024 * 1024
_MAX_REPOSITORY_PATH_BYTES = 4096
_MAX_CLOSED_PULL_REQUESTS_PER_POLL = 100
_MAX_CLOSED_PULL_LIST_PAGES_PER_POLL = 100
_MAX_CLOSED_PULL_HYDRATION_ATTEMPTS = 3
_MAX_CLOSED_PULL_IDENTITIES_PER_CYCLE = _MAX_CLOSED_PULL_LIST_PAGES_PER_POLL * 100
_MAX_CLOSED_PULL_EXCLUSIONS = _MAX_PAGINATION_ITEMS

_RATE_LIMIT_MARKERS = (
    "review limit reached",
    "rate limited",
    "rate-limited",
    "review quota",
    "usage credits",
    "insufficient credits",
)
_SKIP_MARKERS = (
    "review skipped",
    "review was skipped",
    "too many files",
    "over the limit",
)


def matches_guardian_pr_body(actual: object, expected: str) -> bool:
    """Match exact Guardian text, optionally followed by bounded untrusted notes.

    CodeRabbit appends release notes after starting review. Its marker is not
    author authentication: the entire suffix is ignored, never used as evidence
    or authority. Every byte of the ledger-bound original body must remain intact.
    """
    if actual == expected:
        return True
    if not isinstance(actual, str) or not expected or not actual.startswith(expected):
        return False
    suffix = actual[len(expected):]
    if len(suffix) > 8192 or "\x00" in suffix:
        return False
    try:
        if len(suffix.encode("utf-8")) > 8192:
            return False
    except UnicodeEncodeError:
        return False
    notes = suffix.lstrip("\n")
    if not 1 <= len(suffix) - len(notes) <= 3:
        return False
    start = "<!-- This is an auto-generated comment: release notes by coderabbit.ai -->"
    end = "<!-- end of auto-generated comment: release notes by coderabbit.ai -->"
    notes = notes.removesuffix("\n")
    if not notes.startswith(start + "\n") or not notes.endswith(end):
        return False
    content = notes[len(start):-len(end)]
    return not any(marker in content for marker in (start, end, "<!-- localize-guardian"))


def _valid_repository_name(value: object) -> bool:
    return bool(
        isinstance(value, str)
        and _REPOSITORY_RE.fullmatch(value)
        and all(component not in {".", ".."} for component in value.split("/"))
    )


def _github_web_base_url(api_base_url: str) -> str:
    parsed = urlsplit(api_base_url)
    hostname = parsed.hostname or ""
    if hostname.startswith("api."):
        hostname = hostname[4:]
    if ":" in hostname and not hostname.startswith("["):
        hostname = f"[{hostname}]"
    port = f":{parsed.port}" if parsed.port is not None else ""
    return f"{parsed.scheme}://{hostname}{port}"


def _validate_base_branch(branch: str) -> None:
    if (
        not isinstance(branch, str)
        or len(branch) > 255
        or branch.startswith("refs/")
        or not _BRANCH_RE.fullmatch(branch)
        or "//" in branch
        or ".." in branch
        or "@{" in branch
        or branch.endswith(".")
        or any(
            component.startswith(".") or component.endswith(".lock")
            for component in branch.split("/")
        )
    ):
        raise ValueError("base_branch must be a canonical Git branch name")


class GitHubAPIError(RuntimeError):
    """A redacted GitHub or token-helper failure."""


class GitHubAuthenticationError(GitHubAPIError):
    """GitHub authentication or authorization failed; further calls must stop."""


class PolicyViolation(RuntimeError):
    """A requested write no longer satisfies the trusted repository policy."""


class FeedbackKind(str, Enum):
    ISSUE_COMMENT = "issue_comment"
    REVIEW = "review"
    REVIEW_COMMENT = "review_comment"


class CodeRabbitCoverageStatus(str, Enum):
    REVIEWED = "reviewed"
    SKIPPED = "skipped"
    RATE_LIMITED = "rate_limited"
    ABSENT = "absent"


@dataclass(frozen=True)
class GitHubRepositoryPolicy:
    """Trusted boundary for one target repository and its contributor branch."""

    repository: str
    repository_id: int | None
    base_branch: str
    allowed_pr_authors: tuple[TrustedActor, ...]
    allowed_head_owners: tuple[TrustedActor, ...]
    allowed_head_repositories: tuple[AllowedHeadRepository, ...]
    branch_globs: tuple[str, ...]

    def __post_init__(self) -> None:
        if not _valid_repository_name(self.repository):
            raise ValueError("repository must use the exact 'owner/name' form")
        if self.repository_id is not None and (
            isinstance(self.repository_id, bool)
            or not isinstance(self.repository_id, int)
            or self.repository_id <= 0
        ):
            raise ValueError("repository_id must be a positive integer")
        _validate_base_branch(self.base_branch)
        if not self.allowed_pr_authors:
            raise ValueError("allowed_pr_authors must contain typed numeric identities")
        if not self.allowed_head_owners:
            raise ValueError(
                "allowed_head_owners must contain typed numeric identities"
            )
        if not self.allowed_head_repositories:
            raise ValueError("allowed_head_repositories must contain exact identities")
        if not self.branch_globs or any(
            not pattern or any(char in pattern for char in "\r\n\x00")
            for pattern in self.branch_globs
        ):
            raise ValueError("branch_globs must contain safe, non-empty patterns")

    def permits(self, pull_request: "PullRequestSnapshot") -> bool:
        if pull_request.repository != self.repository:
            return False
        if (
            self.repository_id is not None
            and pull_request.base_repository_id != self.repository_id
        ):
            return False
        if pull_request.base_ref != self.base_branch:
            return False
        author = next(
            (
                actor
                for actor in self.allowed_pr_authors
                if actor.id == pull_request.author_id
                and actor.type == pull_request.author_type
            ),
            None,
        )
        if author is None:
            return False
        head_owner = next(
            (
                actor
                for actor in self.allowed_head_owners
                if actor.id == pull_request.head_owner_id
                and actor.type == pull_request.head_owner_type
            ),
            None,
        )
        if head_owner is None:
            return False
        head_repository = next(
            (
                repository
                for repository in self.allowed_head_repositories
                if repository.id == pull_request.head_repository_id
            ),
            None,
        )
        if head_repository is None:
            return False
        return any(
            fnmatchcase(pull_request.head_ref, pattern) for pattern in self.branch_globs
        )


@dataclass(frozen=True)
class GitHubRepositoryIdentity:
    """Authoritative repository identity and visibility from GitHub."""

    full_name: str
    repository_id: int
    private: bool


@dataclass(frozen=True)
class BaseRevisionSnapshot:
    """Immutable current base revision captured from the configured repository."""

    repository_identity: GitHubRepositoryIdentity
    branch: str
    sha: str


@dataclass(frozen=True)
class PullRequestSnapshot:
    repository: str
    base_repository_id: int
    pull_id: int
    number: int
    state: str
    html_url: str
    created_at: str
    updated_at: str
    author_login: str
    author_id: int | None
    author_type: str
    head_sha: str
    head_ref: str
    head_owner: str
    head_owner_id: int | None
    head_owner_type: str
    head_repository: str
    head_repository_id: int | None
    base_sha: str
    base_ref: str
    base_repository: str = ""


@dataclass(frozen=True)
class FeedbackRevision:
    """One immutable observed revision of a GitHub feedback object."""

    repository: str
    pull_number: int
    kind: FeedbackKind
    source_id: str
    node_id: str | None
    author_login: str
    author_id: int | None
    author_type: str
    body: str
    created_at: str
    updated_at: str
    html_url: str
    review_state: str | None = None
    path: str | None = None
    line: int | None = None
    commit_id: str | None = None
    deleted: bool = False

    @property
    def object_key(self) -> tuple[str, int, FeedbackKind, str]:
        return (self.repository, self.pull_number, self.kind, self.source_id)

    @property
    def revision_id(self) -> str:
        payload = json.dumps(
            {
                "body": self.body,
                "commit_id": self.commit_id,
                "deleted": self.deleted,
                "line": self.line,
                "path": self.path,
                "review_state": self.review_state,
                "updated_at": self.updated_at,
            },
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        return f"{self.kind.value}:{self.source_id}:{digest}"


@dataclass(frozen=True)
class CodeRabbitCoverage:
    status: CodeRabbitCoverageStatus
    source_revision_id: str | None = None


@dataclass(frozen=True)
class ChangedFile:
    """One file reported by GitHub for the exact pull-request comparison."""

    path: str
    status: str
    sha: str
    previous_path: str | None = None
    patch: str | None = None


@dataclass(frozen=True)
class OpenPullPathIdentity:
    """Open-pull identity, exact only while its head repository still exists."""

    repository: str
    repository_id: int
    pull_id: int
    number: int
    head_repository: str
    head_repository_id: int | None
    head_ref: str
    head_sha: str

    def __post_init__(self) -> None:
        if not _valid_repository_name(self.repository):
            raise ValueError("open pull repositories must use owner/name form")
        if not isinstance(self.head_repository, str):
            raise ValueError("open pull head repository identity is malformed")
        exact_head_repository = self.head_repository_id is not None
        if (not exact_head_repository and self.head_repository != "") or (
            exact_head_repository and not _valid_repository_name(self.head_repository)
        ):
            raise ValueError("open pull head repository identity is malformed")
        if any(
            isinstance(value, bool) or not isinstance(value, int) or value <= 0
            for value in (
                self.repository_id,
                self.pull_id,
                self.number,
            )
        ):
            raise ValueError("open pull numeric identities must be positive integers")
        if exact_head_repository and (
            isinstance(self.head_repository_id, bool)
            or not isinstance(self.head_repository_id, int)
            or self.head_repository_id <= 0
        ):
            raise ValueError("open pull numeric identities must be positive integers")
        if (
            not isinstance(self.head_ref, str)
            or not _BRANCH_RE.fullmatch(self.head_ref)
            or len(self.head_ref) > 255
            or not isinstance(self.head_sha, str)
            or not _FULL_LOWER_SHA_RE.fullmatch(self.head_sha)
        ):
            raise ValueError("open pull head identity is malformed")


@dataclass(frozen=True)
class OpenPullPathAuthority:
    """Bounded current and previous paths for one exact open pull request."""

    identity: OpenPullPathIdentity
    changed_paths: tuple[str, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.identity, OpenPullPathIdentity):
            raise ValueError("open pull path authority requires an exact identity")
        if isinstance(self.changed_paths, (str, bytes)):
            raise ValueError("open pull changed paths must be a bounded sequence")
        paths = tuple(self.changed_paths)
        invalid_path = any(
            not isinstance(path, str)
            or not path
            or (
                isinstance(path, str)
                and (
                    len(path.encode("utf-8")) > _MAX_REPOSITORY_PATH_BYTES
                    or path.startswith("/")
                    or "\\" in path
                    or any(part in {"", ".", ".."} for part in path.split("/"))
                    or any(character in path for character in "\r\n\x00")
                )
            )
            for path in paths
        )
        if (
            len(paths) > _MAX_AFFECTED_PATHS_PER_OPEN_PULL
            or invalid_path
            or len(set(paths)) != len(paths)
        ):
            raise ValueError("open pull changed paths are malformed or unbounded")
        object.__setattr__(self, "changed_paths", tuple(sorted(paths)))


@dataclass(frozen=True)
class PullRequestFeedbackSnapshot:
    repository_identity: GitHubRepositoryIdentity
    pull_request: PullRequestSnapshot
    feedback: tuple[FeedbackRevision, ...]
    coderabbit: CodeRabbitCoverage
    changed_files: tuple[ChangedFile, ...] = ()


@dataclass(frozen=True)
class ClosedPullScanPosition:
    """Observed GitHub list position for one closed pull."""

    page: int
    offset: int
    cycle_complete: bool = False


@dataclass(frozen=True)
class ClosedPullScanItem:
    """One bounded hydration outcome from the frozen historical window."""

    position: ClosedPullScanPosition
    snapshot: PullRequestFeedbackSnapshot | None = None
    pull_id: int | None = None
    pull_number: int | None = None
    failure_type: str | None = None
    hydration_attempted: bool = False


@dataclass(frozen=True)
class ClosedPullScanResult:
    """One bounded restart-safe scan over the frozen historical window."""

    items: tuple[ClosedPullScanItem, ...]
    hydration_attempts: int
    cycle_complete: bool = False

    @property
    def snapshots(self) -> tuple[PullRequestFeedbackSnapshot, ...]:
        return tuple(item.snapshot for item in self.items if item.snapshot is not None)

    @property
    def failures(self) -> tuple[ClosedPullScanItem, ...]:
        return tuple(item for item in self.items if item.failure_type is not None)


@dataclass(frozen=True)
class ReplyResult:
    comment_id: int
    html_url: str
    body: str
    created: bool


def _as_mapping(value: Any, *, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise GitHubAPIError(f"GitHub returned malformed {label} data")
    return value


def _as_int(value: Any, *, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise GitHubAPIError(f"GitHub returned malformed {label} data")
    return value


def _trusted_actor_from_payload(value: Any, *, label: str) -> TrustedActor:
    payload = _as_mapping(value, label=label)
    login = payload.get("login")
    actor_id = _as_int(payload.get("id"), label=f"{label} id")
    actor_type = payload.get("type")
    if (
        not isinstance(login, str)
        or not login
        or len(login.encode("utf-8")) > 256
        or any(character in login for character in "\r\n\x00")
        or actor_type not in {"User", "Bot"}
    ):
        raise GitHubAPIError(f"GitHub returned malformed {label} data")
    return TrustedActor(login=login, id=actor_id, type=actor_type)


def _optional_int(value: Any, *, label: str) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise GitHubAPIError(f"GitHub returned malformed {label} data")
    return value


def _parse_pull_request(
    repository: str, payload: Mapping[str, Any]
) -> PullRequestSnapshot:
    head = _as_mapping(payload.get("head"), label="pull-request head")
    base = _as_mapping(payload.get("base"), label="pull-request base")
    # GitHub returns ``head.repo: null`` after a contributor deletes a fork.
    # That is a normal, permanently unauthorized historical shape rather than
    # malformed API data; retain the pull metadata so policy can skip it.
    raw_head_repo = head.get("repo")
    head_repo = (
        {}
        if raw_head_repo is None
        else _as_mapping(raw_head_repo, label="pull-request head repository")
    )
    base_repo = _as_mapping(base.get("repo"), label="pull-request base repository")
    head_user = _as_mapping(head.get("user") or {}, label="pull-request head owner")
    author = _as_mapping(payload.get("user") or {}, label="pull-request author")
    return PullRequestSnapshot(
        repository=repository,
        base_repository_id=_as_int(base_repo.get("id"), label="base repository id"),
        pull_id=_as_int(payload.get("id"), label="pull-request id"),
        number=_as_int(payload.get("number"), label="pull-request number"),
        state=str(payload.get("state") or ""),
        html_url=str(payload.get("html_url") or ""),
        created_at=str(payload.get("created_at") or ""),
        updated_at=str(payload.get("updated_at") or ""),
        author_login=str(author.get("login") or ""),
        author_id=_optional_int(author.get("id"), label="pull-request author id"),
        author_type=str(author.get("type") or ""),
        head_sha=str(head.get("sha") or ""),
        head_ref=str(head.get("ref") or ""),
        head_owner=str(head_user.get("login") or ""),
        head_owner_id=_optional_int(
            head_user.get("id"),
            label="pull-request head owner id",
        ),
        head_owner_type=str(head_user.get("type") or ""),
        head_repository=str(head_repo.get("full_name") or ""),
        head_repository_id=_optional_int(
            head_repo.get("id"),
            label="pull-request head repository id",
        ),
        base_sha=str(base.get("sha") or ""),
        base_ref=str(base.get("ref") or ""),
        base_repository=str(base_repo.get("full_name") or ""),
    )


def _pull_hydration_identity(pull: PullRequestSnapshot) -> tuple[object, ...]:
    """Return metadata that must stay immutable throughout one hydration."""

    return (
        pull.repository,
        pull.base_repository,
        pull.base_repository_id,
        pull.pull_id,
        pull.number,
        pull.state,
        pull.html_url,
        pull.created_at,
        pull.updated_at,
        pull.author_login,
        pull.author_id,
        pull.author_type,
        pull.head_sha,
        pull.head_ref,
        pull.head_owner,
        pull.head_owner_id,
        pull.head_owner_type,
        pull.head_repository,
        pull.head_repository_id,
        pull.base_sha,
        pull.base_ref,
    )


def _parse_feedback(
    repository: str,
    pull_number: int,
    kind: FeedbackKind,
    payload: Mapping[str, Any],
) -> FeedbackRevision:
    user = _as_mapping(payload.get("user") or {}, label="feedback author")
    source_id = str(_as_int(payload.get("id"), label="feedback id"))
    created_at = str(payload.get("created_at") or payload.get("submitted_at") or "")
    updated_at = str(
        payload.get("updated_at")
        or payload.get("submitted_at")
        or payload.get("created_at")
        or ""
    )
    raw_line = payload.get("line")
    if raw_line is None:
        raw_line = payload.get("original_line")
    line = _optional_int(raw_line, label="feedback line")
    return FeedbackRevision(
        repository=repository,
        pull_number=pull_number,
        kind=kind,
        source_id=source_id,
        node_id=str(payload.get("node_id"))
        if payload.get("node_id") is not None
        else None,
        author_login=str(user.get("login") or ""),
        author_id=_optional_int(user.get("id"), label="feedback author id"),
        author_type=str(user.get("type") or ""),
        body=str(payload.get("body") or ""),
        created_at=created_at,
        updated_at=updated_at,
        html_url=str(payload.get("html_url") or ""),
        review_state=str(payload.get("state"))
        if payload.get("state") is not None
        else None,
        path=str(payload.get("path")) if payload.get("path") is not None else None,
        line=line,
        commit_id=str(payload.get("commit_id"))
        if payload.get("commit_id") is not None
        else None,
    )


def _parse_changed_file(payload: Mapping[str, Any]) -> ChangedFile:
    return ChangedFile(
        path=str(payload.get("filename") or ""),
        status=str(payload.get("status") or ""),
        sha=str(payload.get("sha") or ""),
        previous_path=(
            str(payload.get("previous_filename"))
            if payload.get("previous_filename") is not None
            else None
        ),
        patch=(str(payload.get("patch")) if payload.get("patch") is not None else None),
    )


def _parse_utc_timestamp(value: object, *, label: str) -> datetime:
    if not isinstance(value, str) or not value:
        raise GitHubAPIError(f"GitHub returned malformed {label} data")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise GitHubAPIError(f"GitHub returned malformed {label} data") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        raise GitHubAPIError(f"GitHub returned malformed {label} data")
    return parsed.astimezone(timezone.utc)


def _latest_by_object(
    feedback: Iterable[FeedbackRevision],
) -> dict[tuple[str, int, FeedbackKind, str], FeedbackRevision]:
    latest: dict[tuple[str, int, FeedbackKind, str], FeedbackRevision] = {}
    for revision in feedback:
        current = latest.get(revision.object_key)
        if current is None or (
            revision.updated_at,
            revision.deleted,
            revision.revision_id,
        ) > (
            current.updated_at,
            current.deleted,
            current.revision_id,
        ):
            latest[revision.object_key] = revision
    return latest


def _coderabbit_coverage(feedback: Iterable[FeedbackRevision]) -> CodeRabbitCoverage:
    bot_feedback = [
        revision
        for revision in feedback
        if not revision.deleted and revision.author_login.lower() in _CODERABBIT_LOGINS
    ]
    if not bot_feedback:
        return CodeRabbitCoverage(CodeRabbitCoverageStatus.ABSENT)
    latest = max(bot_feedback, key=lambda item: (item.updated_at, item.revision_id))
    normalized = latest.body.casefold()
    if any(marker in normalized for marker in _RATE_LIMIT_MARKERS):
        status = CodeRabbitCoverageStatus.RATE_LIMITED
    elif any(marker in normalized for marker in _SKIP_MARKERS):
        status = CodeRabbitCoverageStatus.SKIPPED
    else:
        status = CodeRabbitCoverageStatus.REVIEWED
    return CodeRabbitCoverage(status, latest.revision_id)


class _GitHubHTTP:
    def __init__(
        self,
        client: httpx.Client,
        *,
        deadline: PollDeadline | None = None,
    ) -> None:
        self.client = client
        self.deadline = deadline

    def _request_timeout(self) -> httpx.Timeout:
        return deadline_httpx_timeout(self.deadline, self.client.timeout)

    @staticmethod
    def _raise_for_status(response: httpx.Response, *, method: str) -> None:
        if 200 <= response.status_code < 300:
            return
        retry_after = response.headers.get("retry-after", "").strip()
        rate_limit_remaining = response.headers.get("x-ratelimit-remaining", "").strip()
        rate_limit_reset = response.headers.get("x-ratelimit-reset", "").strip()
        is_rate_limited = bool(retry_after) or (
            rate_limit_remaining == "0" and bool(rate_limit_reset)
        )
        if response.status_code == 403 and is_rate_limited:
            raise GitHubAPIError(f"GitHub API {method} request was rate limited")
        if response.status_code in {401, 403}:
            raise GitHubAuthenticationError(
                f"GitHub API {method} authentication failed"
            )
        raise GitHubAPIError(
            f"GitHub API {method} request failed with status {response.status_code}"
        )

    def _bounded_json(self, response: httpx.Response, *, label: str) -> Any:
        content = bytearray()
        try:
            for chunk in response.iter_bytes():
                if self.deadline is not None:
                    self.deadline.require_remaining()
                if len(content) + len(chunk) > _MAX_RESPONSE_BYTES:
                    raise GitHubAPIError(
                        f"GitHub API {label} response exceeded the byte limit"
                    )
                content.extend(chunk)
            if self.deadline is not None:
                self.deadline.require_remaining()
        except httpx.TimeoutException:
            raise
        except httpx.HTTPError as exc:
            raise GitHubAPIError(f"GitHub API {label} response failed") from exc
        try:
            return loads_bounded_json(content)
        except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as exc:
            raise GitHubAPIError(f"GitHub API {label} returned invalid JSON") from exc

    def request_json(
        self,
        method: str,
        url: str,
        *,
        params: Mapping[str, Any] | None = None,
        payload: Mapping[str, Any] | None = None,
    ) -> Any:
        request_timeout = self._request_timeout()
        try:
            with self.client.stream(
                method,
                url,
                params=params,
                json=payload,
                timeout=request_timeout,
            ) as response:
                self._raise_for_status(response, method=method)
                return self._bounded_json(response, label=method)
        except GitHubAPIError:
            raise
        except httpx.TimeoutException as exc:
            if self.deadline is not None:
                self.deadline.require_remaining()
            raise GitHubAPIError(f"GitHub API {method} request failed") from exc
        except httpx.HTTPError as exc:
            raise GitHubAPIError(f"GitHub API {method} request failed") from exc

    def paginate(
        self,
        url: str,
        *,
        params: Mapping[str, Any] | None = None,
        max_items: int = _MAX_PAGINATION_ITEMS,
    ) -> list[Mapping[str, Any]]:
        if max_items <= 0:
            raise ValueError("GitHub pagination max_items is outside the safe bound")
        effective_item_limit = min(max_items, _MAX_PAGINATION_ITEMS)
        items: list[Mapping[str, Any]] = []
        next_url: str | None = url
        next_params: Mapping[str, Any] | None = dict(params or {})
        next_params.setdefault("per_page", 100)
        seen_urls: set[str] = set()
        pages = 0
        while next_url is not None:
            pages += 1
            if pages > _MAX_PAGINATION_PAGES:
                raise GitHubAPIError("GitHub API pagination limit was exceeded")
            resolved_url = self.client.base_url.join(next_url)
            base_parts = urlsplit(str(self.client.base_url))
            next_parts = urlsplit(str(resolved_url))
            if (
                next_parts.scheme,
                next_parts.hostname,
                next_parts.port,
            ) != (
                base_parts.scheme,
                base_parts.hostname,
                base_parts.port,
            ):
                raise GitHubAPIError("GitHub API returned an unsafe pagination link")
            canonical_url = str(resolved_url)
            if canonical_url in seen_urls:
                raise GitHubAPIError("GitHub API returned a repeated pagination link")
            seen_urls.add(canonical_url)
            request_timeout = self._request_timeout()
            try:
                with self.client.stream(
                    "GET",
                    resolved_url,
                    params=next_params,
                    timeout=request_timeout,
                ) as response:
                    self._raise_for_status(response, method="GET")
                    page = self._bounded_json(response, label="GET")
                    next_link = response.links.get("next")
            except GitHubAPIError:
                raise
            except httpx.TimeoutException as exc:
                if self.deadline is not None:
                    self.deadline.require_remaining()
                raise GitHubAPIError("GitHub API GET request failed") from exc
            except httpx.HTTPError as exc:
                raise GitHubAPIError("GitHub API GET request failed") from exc
            if not isinstance(page, list):
                raise GitHubAPIError(
                    "GitHub API GET returned malformed pagination data"
                )
            if len(items) + len(page) > effective_item_limit:
                raise GitHubAPIError("GitHub API pagination item limit was exceeded")
            for item in page:
                items.append(_as_mapping(item, label="pagination item"))
            next_url = str(next_link["url"]) if next_link else None
            # Passing an empty mapping makes httpx 0.28 discard a query that
            # is already embedded in GitHub's absolute Link URL.
            next_params = None
        return items


class GitHubReader:
    """Collect policy-matching pull requests and read-only repository state."""

    def __init__(
        self,
        client: httpx.Client,
        policy: GitHubRepositoryPolicy,
        *,
        deadline: PollDeadline | None = None,
    ) -> None:
        self._http = _GitHubHTTP(client, deadline=deadline)
        self.policy = policy

    def repository_identity(self) -> GitHubRepositoryIdentity:
        """Return visibility before any caller sends repository data to a model."""
        payload = _as_mapping(
            self._http.request_json("GET", f"/repos/{self.policy.repository}"),
            label="repository",
        )
        full_name = str(payload.get("full_name") or "")
        repository_id = _as_int(payload.get("id"), label="repository id")
        if full_name != self.policy.repository:
            raise PolicyViolation("GitHub repository identity no longer matches policy")
        if (
            self.policy.repository_id is not None
            and repository_id != self.policy.repository_id
        ):
            raise PolicyViolation("GitHub repository id no longer matches policy")
        private = payload.get("private")
        if not isinstance(private, bool):
            raise GitHubAPIError("GitHub returned malformed repository privacy data")
        return GitHubRepositoryIdentity(
            full_name=full_name,
            repository_id=repository_id,
            private=private,
        )

    def authenticated_actor(self) -> TrustedActor:
        """Return the exact actor behind this read credential."""

        return _trusted_actor_from_payload(
            self._http.request_json("GET", "/user"),
            label="authenticated actor",
        )

    def capture_base_revision(self) -> BaseRevisionSnapshot:
        """Capture the configured branch head after exact repository validation."""
        if self.policy.repository_id is None:
            raise PolicyViolation(
                "base revision capture requires a configured repository id"
            )
        repository_identity = self.repository_identity()
        encoded_branch = quote(self.policy.base_branch, safe="")
        payload = _as_mapping(
            self._http.request_json(
                "GET",
                f"/repos/{self.policy.repository}/branches/{encoded_branch}",
            ),
            label="base branch",
        )
        branch = str(payload.get("name") or "")
        if branch != self.policy.base_branch:
            raise PolicyViolation("GitHub base branch no longer matches policy")
        commit = _as_mapping(payload.get("commit"), label="base branch commit")
        sha = commit.get("sha")
        if not isinstance(sha, str) or not _FULL_LOWER_SHA_RE.fullmatch(sha):
            raise GitHubAPIError("GitHub returned malformed base branch SHA data")
        return BaseRevisionSnapshot(
            repository_identity=repository_identity,
            branch=branch,
            sha=sha,
        )

    def _previous_feedback_by_pull(
        self,
        feedback: Iterable[FeedbackRevision],
    ) -> dict[
        int,
        dict[tuple[str, int, FeedbackKind, str], FeedbackRevision],
    ]:
        """Group eager compatibility input once instead of scanning it per PR."""

        grouped: dict[int, list[FeedbackRevision]] = {}
        for revision in feedback:
            if revision.repository != self.policy.repository:
                raise ValueError("previous feedback escaped the repository policy")
            grouped.setdefault(revision.pull_number, []).append(revision)
        return {
            pull_number: self._validated_previous_feedback(
                pull_number,
                revisions,
            )
            for pull_number, revisions in grouped.items()
        }

    def _load_previous_feedback_for_pull(
        self,
        pull_number: int,
        provider: Callable[[int], Iterable[FeedbackRevision]],
    ) -> dict[tuple[str, int, FeedbackKind, str], FeedbackRevision]:
        """Load only one hydrated pull's bounded prior feedback."""

        return self._validated_previous_feedback(
            pull_number,
            tuple(provider(pull_number)),
        )

    def _validated_previous_feedback(
        self,
        pull_number: int,
        feedback: Iterable[FeedbackRevision],
    ) -> dict[tuple[str, int, FeedbackKind, str], FeedbackRevision]:
        revisions = tuple(feedback)
        if len(revisions) > _MAX_FEEDBACK_ITEMS_PER_PULL:
            raise GitHubAPIError(
                "Stored pull-request feedback exceeded the intake bound"
            )
        if any(
            not isinstance(revision, FeedbackRevision)
            or revision.repository != self.policy.repository
            or revision.pull_number != pull_number
            for revision in revisions
        ):
            raise GitHubAPIError(
                "Stored pull-request feedback escaped its exact pull identity"
            )
        return _latest_by_object(revisions)

    def collect_open_pull_requests(
        self,
        *,
        previous_feedback: Iterable[FeedbackRevision] = (),
        previous_feedback_for_pull: Callable[[int], Iterable[FeedbackRevision]]
        | None = None,
    ) -> tuple[PullRequestFeedbackSnapshot, ...]:
        """Poll all open PRs; never gate discovery on PR creation time or head SHA."""
        repository_identity = self.repository_identity()
        pulls = self._http.paginate(
            f"/repos/{self.policy.repository}/pulls",
            params={"state": "open"},
            max_items=_MAX_OPEN_PULL_REQUESTS,
        )
        previous_items = tuple(previous_feedback)
        if previous_feedback_for_pull is not None and previous_items:
            raise ValueError(
                "previous feedback must use either eager or per-pull loading"
            )
        previous_by_pull = self._previous_feedback_by_pull(previous_items)
        loaded_previous: dict[
            int,
            dict[tuple[str, int, FeedbackKind, str], FeedbackRevision],
        ] = {}

        def previous_for(
            pull_number: int,
        ) -> Mapping[tuple[str, int, FeedbackKind, str], FeedbackRevision]:
            if previous_feedback_for_pull is None:
                return previous_by_pull.get(pull_number, {})
            if pull_number not in loaded_previous:
                loaded_previous[pull_number] = self._load_previous_feedback_for_pull(
                    pull_number,
                    previous_feedback_for_pull,
                )
            return loaded_previous[pull_number]

        snapshots: list[PullRequestFeedbackSnapshot] = []
        for raw_pull in pulls:
            pull = _parse_pull_request(self.policy.repository, raw_pull)
            if pull.state.casefold() != "open" or not self.policy.permits(pull):
                continue
            snapshots.append(
                self._hydrate_pull(
                    repository_identity=repository_identity,
                    pull=pull,
                    previous_by_object=previous_for(pull.number),
                )
            )
        snapshots.sort(key=lambda item: item.pull_request.number)
        return tuple(snapshots)

    def collect_open_changed_paths(self) -> tuple[OpenPullPathAuthority, ...]:
        """Return a complete, stable, bounded view of every open-PR path.

        This intentionally avoids fetching review bodies: historical remediation
        only needs to know whether any open pull request now touches one of its
        candidate files. The complete pull listing is read
        again after every candidate has been hydrated, and each file list is
        independently read twice with a final exact pull revalidation.  Any
        pagination, size, identity, or stability failure raises instead of
        returning a partial authority view.
        """

        repository_identity = self.repository_identity()

        def all_open_pulls() -> tuple[PullRequestSnapshot, ...]:
            raw_pulls = self._http.paginate(
                f"/repos/{self.policy.repository}/pulls",
                params={"state": "open"},
                max_items=_MAX_OPEN_PULL_REQUESTS,
            )
            pulls: list[PullRequestSnapshot] = []
            identities: set[tuple[int, int]] = set()
            pull_ids: set[int] = set()
            pull_numbers: set[int] = set()
            for raw_pull in raw_pulls:
                pull = _parse_pull_request(self.policy.repository, raw_pull)
                if pull.state.casefold() != "open":
                    raise GitHubAPIError(
                        "GitHub open-pull listing returned a non-open pull request"
                    )
                identity = (pull.pull_id, pull.number)
                if (
                    identity in identities
                    or pull.pull_id in pull_ids
                    or pull.number in pull_numbers
                ):
                    raise GitHubAPIError(
                        "GitHub open pulls repeated a pull-request identity"
                    )
                identities.add(identity)
                pull_ids.add(pull.pull_id)
                pull_numbers.add(pull.number)
                pulls.append(pull)
            return tuple(sorted(pulls, key=lambda item: (item.number, item.pull_id)))

        def changed_files(pull: PullRequestSnapshot) -> tuple[ChangedFile, ...]:
            changed = tuple(
                sorted(
                    (
                        _parse_changed_file(raw_file)
                        for raw_file in self._http.paginate(
                            f"/repos/{self.policy.repository}/pulls/"
                            f"{pull.number}/files",
                            max_items=_MAX_CHANGED_FILES_PER_PULL,
                        )
                    ),
                    key=lambda item: (
                        item.path,
                        item.status,
                        item.sha,
                        item.previous_path or "",
                        item.patch or "",
                    ),
                )
            )
            if len({item.path for item in changed}) != len(changed):
                raise GitHubAPIError(
                    "GitHub pull-request files repeated a changed path"
                )
            if any(
                item.status == "renamed" and item.previous_path is None
                for item in changed
            ):
                raise GitHubAPIError(
                    "GitHub returned a malformed pull-request rename source path"
                )
            changed_file_bytes = sum(
                len((item.patch or "").encode("utf-8"))
                + len(item.path.encode("utf-8"))
                + (
                    len(item.previous_path.encode("utf-8"))
                    if item.previous_path is not None
                    else 0
                )
                for item in changed
            )
            if changed_file_bytes > _MAX_CHANGED_FILE_BYTES_PER_PULL:
                raise GitHubAPIError(
                    "GitHub pull-request changed-file metadata exceeded the "
                    "intake bound"
                )
            if any(
                not item.path
                or "\x00" in item.path
                or (
                    item.previous_path is not None
                    and (not item.previous_path or "\x00" in item.previous_path)
                )
                for item in changed
            ):
                raise GitHubAPIError(
                    "GitHub returned a malformed pull-request changed path"
                )
            return changed

        initial_pulls = all_open_pulls()
        authorities: list[OpenPullPathAuthority] = []
        for pull in initial_pulls:
            current = changed_files(pull)
            confirmed = changed_files(pull)
            if confirmed != current:
                raise GitHubAPIError(
                    "GitHub pull-request changed files moved during hydration"
                )
            final_pull = _parse_pull_request(
                self.policy.repository,
                _as_mapping(
                    self._http.request_json(
                        "GET",
                        f"/repos/{self.policy.repository}/pulls/{pull.number}",
                    ),
                    label="open pull path-authority revalidation",
                ),
            )
            if final_pull.state.casefold() != "open" or _pull_hydration_identity(
                final_pull
            ) != _pull_hydration_identity(pull):
                raise GitHubAPIError(
                    "GitHub open pull changed during path-authority hydration"
                )
            try:
                authority = OpenPullPathAuthority(
                    identity=OpenPullPathIdentity(
                        repository=pull.repository,
                        repository_id=pull.base_repository_id,
                        pull_id=pull.pull_id,
                        number=pull.number,
                        head_repository=pull.head_repository,
                        head_repository_id=pull.head_repository_id,
                        head_ref=pull.head_ref,
                        head_sha=pull.head_sha,
                    ),
                    changed_paths=tuple(
                        sorted(
                            {
                                path
                                for item in current
                                for path in (item.path, item.previous_path)
                                if path is not None
                            }
                        )
                    ),
                )
            except ValueError as exc:
                raise GitHubAPIError(
                    "GitHub open pull returned malformed path-authority identity"
                ) from exc
            authorities.append(authority)

        if all_open_pulls() != initial_pulls:
            raise GitHubAPIError(
                "GitHub open-pull listing changed during path hydration"
            )
        # Each of the at most 500 changed files can affect its current path and,
        # for a rename, its previous path across at most 200 open pulls.
        if sum(len(item.changed_paths) for item in authorities) > (
            _MAX_OPEN_PULL_REQUESTS * _MAX_AFFECTED_PATHS_PER_OPEN_PULL
        ):
            raise GitHubAPIError("GitHub open-pull path authority exceeded its bound")
        # Re-read identity after the potentially long multi-PR hydration so a
        # repository replacement cannot inherit the prior view.
        if self.repository_identity() != repository_identity:
            raise GitHubAPIError(
                "GitHub repository identity changed during path hydration"
            )
        return tuple(authorities)

    def collect_exact_open_pull(
        self,
        expected_pull: tuple[int, int],
    ) -> PullRequestFeedbackSnapshot:
        """Rehydrate one exact open pull without relying on list discovery."""

        if (
            not isinstance(expected_pull, tuple)
            or len(expected_pull) != 2
            or any(
                isinstance(value, bool) or not isinstance(value, int) or value <= 0
                for value in expected_pull
            )
        ):
            raise ValueError(
                "exact open pull identity must contain a positive pull ID and number"
            )
        pull_id, pull_number = expected_pull
        repository_identity = self.repository_identity()
        pull = _parse_pull_request(
            self.policy.repository,
            _as_mapping(
                self._http.request_json(
                    "GET",
                    f"/repos/{self.policy.repository}/pulls/{pull_number}",
                ),
                label="exact open pull request",
            ),
        )
        if (
            (pull.pull_id, pull.number) != (pull_id, pull_number)
            or pull.state != "open"
            or not self.policy.permits(pull)
        ):
            raise PolicyViolation("GitHub exact open pull no longer matches policy")
        return self._hydrate_pull(
            repository_identity=repository_identity,
            pull=pull,
            previous_by_object={},
        )

    def collect_exact_closed_pulls(
        self,
        expected_pulls: Iterable[tuple[int, int]],
    ) -> tuple[PullRequestFeedbackSnapshot, ...]:
        """Rehydrate exact closed pull identities without scanning history."""

        identities = tuple(expected_pulls)
        pull_numbers_by_id: dict[int, int] = {}
        pull_ids_by_number: dict[int, int] = {}
        if not identities or len(identities) > _MAX_CLOSED_PULL_REQUESTS_PER_POLL:
            raise ValueError(
                "exact closed pull identities must contain 1 through "
                f"{_MAX_CLOSED_PULL_REQUESTS_PER_POLL} entries"
            )
        for identity in identities:
            if (
                not isinstance(identity, tuple)
                or len(identity) != 2
                or any(
                    isinstance(value, bool) or not isinstance(value, int) or value <= 0
                    for value in identity
                )
            ):
                raise ValueError(
                    "exact closed pull identities must contain positive integer pairs"
                )
            pull_id, pull_number = identity
            if pull_id in pull_numbers_by_id or pull_number in pull_ids_by_number:
                raise ValueError(
                    "exact closed pull identities must be unique by id and number"
                )
            pull_numbers_by_id[pull_id] = pull_number
            pull_ids_by_number[pull_number] = pull_id

        repository_identity = self.repository_identity()
        snapshots: list[PullRequestFeedbackSnapshot] = []
        for pull_id, pull_number in sorted(identities, key=lambda item: item[1]):
            pull = _parse_pull_request(
                self.policy.repository,
                _as_mapping(
                    self._http.request_json(
                        "GET",
                        f"/repos/{self.policy.repository}/pulls/{pull_number}",
                    ),
                    label="exact closed pull request",
                ),
            )
            if (
                (pull.pull_id, pull.number) != (pull_id, pull_number)
                or pull.state != "closed"
                or not self.policy.permits(pull)
            ):
                raise PolicyViolation(
                    "GitHub exact closed pull no longer matches policy"
                )
            snapshots.append(
                self._hydrate_pull(
                    repository_identity=repository_identity,
                    pull=pull,
                    previous_by_object={},
                )
            )
        return tuple(snapshots)

    def collect_closed_pull_requests(
        self,
        *,
        cutoff: datetime,
        upper_bound: datetime,
        max_prs_per_poll: int,
        seen_pulls: Iterable[tuple[int, int]] = (),
        excluded_pulls: Iterable[tuple[int, int]] = (),
        priority_pull_groups: Iterable[Iterable[tuple[int, int]]] = (),
        previous_feedback: Iterable[FeedbackRevision] = (),
        previous_feedback_for_pull: Callable[[int], Iterable[FeedbackRevision]]
        | None = None,
    ) -> ClosedPullScanResult:
        """Restart at page one and hydrate bounded unseen pulls in one window."""

        for value, label in ((cutoff, "cutoff"), (upper_bound, "upper_bound")):
            if (
                not isinstance(value, datetime)
                or value.tzinfo is None
                or value.utcoffset() != timedelta(0)
            ):
                raise ValueError(f"{label} must be a timezone-aware UTC datetime")
        if upper_bound < cutoff:
            raise ValueError("upper_bound must not precede cutoff")
        if (
            isinstance(max_prs_per_poll, bool)
            or not isinstance(max_prs_per_poll, int)
            or not 1 <= max_prs_per_poll <= _MAX_CLOSED_PULL_REQUESTS_PER_POLL
        ):
            raise ValueError(
                "max_prs_per_poll must be between 1 and "
                f"{_MAX_CLOSED_PULL_REQUESTS_PER_POLL}"
            )

        def normalized_identities(
            values: Iterable[tuple[int, int]],
            *,
            label: str,
            maximum: int,
        ) -> tuple[tuple[int, int], ...]:
            identities = tuple(values)
            if len(identities) > maximum:
                raise ValueError(f"{label} exceeded its identity bound")
            pull_numbers_by_id: dict[int, int] = {}
            pull_ids_by_number: dict[int, int] = {}
            for identity in identities:
                if (
                    not isinstance(identity, tuple)
                    or len(identity) != 2
                    or any(
                        isinstance(value, bool)
                        or not isinstance(value, int)
                        or value <= 0
                        for value in identity
                    )
                ):
                    raise ValueError(
                        f"{label} must contain positive integer identity pairs"
                    )
                pull_id, pull_number = identity
                if (
                    pull_id in pull_numbers_by_id
                    and pull_numbers_by_id[pull_id] != pull_number
                ) or (
                    pull_number in pull_ids_by_number
                    and pull_ids_by_number[pull_number] != pull_id
                ):
                    raise ValueError(f"{label} contains an identity collision")
                pull_numbers_by_id[pull_id] = pull_number
                pull_ids_by_number[pull_number] = pull_id
            if len(set(identities)) != len(identities):
                raise ValueError(f"{label} contains a duplicate identity")
            return tuple(sorted(identities, key=lambda item: (item[1], item[0])))

        seen = frozenset(
            normalized_identities(
                seen_pulls,
                label="seen_pulls",
                maximum=_MAX_CLOSED_PULL_IDENTITIES_PER_CYCLE,
            )
        )
        excluded = frozenset(
            normalized_identities(
                excluded_pulls,
                label="excluded_pulls",
                maximum=_MAX_CLOSED_PULL_EXCLUSIONS,
            )
        )
        raw_priority_groups = tuple(priority_pull_groups)
        if len(raw_priority_groups) > 1:
            raise ValueError("priority_pull_groups exceeded its group bound")
        priority_groups = tuple(
            normalized_identities(
                group,
                label=f"priority_pull_groups[{index}]",
                maximum=_MAX_CLOSED_PULL_REQUESTS_PER_POLL,
            )
            for index, group in enumerate(raw_priority_groups)
        )
        if any(not group for group in priority_groups):
            raise ValueError("priority_pull_groups must not contain empty groups")
        priorities = tuple(identity for group in priority_groups for identity in group)
        if len(priorities) > max_prs_per_poll:
            raise ValueError("priority_pull_groups must fit within max_prs_per_poll")
        normalized_identities(
            priorities,
            label="priority pull identities",
            maximum=_MAX_CLOSED_PULL_REQUESTS_PER_POLL,
        )
        priority_set = frozenset(priorities)
        if priority_set & excluded:
            raise ValueError("priority_pull_groups must not overlap excluded_pulls")
        normalized_identities(
            tuple(dict.fromkeys((*seen, *priorities))),
            label="closed pull identities",
            maximum=_MAX_CLOSED_PULL_IDENTITIES_PER_CYCLE,
        )

        repository_identity = self.repository_identity()
        previous_items = tuple(previous_feedback)
        if previous_feedback_for_pull is not None and previous_items:
            raise ValueError(
                "previous feedback must use either eager or per-pull loading"
            )
        previous_by_pull = self._previous_feedback_by_pull(previous_items)
        loaded_previous: dict[
            int,
            dict[tuple[str, int, FeedbackKind, str], FeedbackRevision],
        ] = {}

        def previous_for(
            pull_number: int,
        ) -> Mapping[tuple[str, int, FeedbackKind, str], FeedbackRevision]:
            if previous_feedback_for_pull is None:
                return previous_by_pull.get(pull_number, {})
            if pull_number not in loaded_previous:
                loaded_previous[pull_number] = self._load_previous_feedback_for_pull(
                    pull_number,
                    previous_feedback_for_pull,
                )
            return loaded_previous[pull_number]

        items: list[ClosedPullScanItem] = []
        hydration_attempts = 0
        covered_identities = set(seen)

        def hydrate(
            pull: PullRequestSnapshot,
            *,
            position: ClosedPullScanPosition,
        ) -> None:
            nonlocal hydration_attempts
            hydration_attempts += 1
            covered_identities.add((pull.pull_id, pull.number))
            for attempt in range(1, _MAX_CLOSED_PULL_HYDRATION_ATTEMPTS + 1):
                try:
                    snapshot = self._hydrate_pull(
                        repository_identity=repository_identity,
                        pull=pull,
                        previous_by_object=previous_for(pull.number),
                    )
                except GitHubAuthenticationError:
                    raise
                except GitHubAPIError as exc:
                    if attempt < _MAX_CLOSED_PULL_HYDRATION_ATTEMPTS:
                        continue
                    items.append(
                        ClosedPullScanItem(
                            position=position,
                            pull_id=pull.pull_id,
                            pull_number=pull.number,
                            failure_type=type(exc).__name__,
                            hydration_attempted=True,
                        )
                    )
                else:
                    items.append(
                        ClosedPullScanItem(
                            position=position,
                            snapshot=snapshot,
                            pull_id=pull.pull_id,
                            pull_number=pull.number,
                            hydration_attempted=True,
                        )
                    )
                break

        def record_priority_group_failure(
            group: tuple[tuple[int, int], ...],
            *,
            failure_type: str = "GitHubAPIError",
        ) -> None:
            """Consume an atomic priority group as exact retryable failures."""

            nonlocal hydration_attempts
            for group_offset, (pull_id, pull_number) in enumerate(group):
                hydration_attempts += 1
                covered_identities.add((pull_id, pull_number))
                items.append(
                    ClosedPullScanItem(
                        position=ClosedPullScanPosition(
                            page=1,
                            offset=group_offset,
                        ),
                        pull_id=pull_id,
                        pull_number=pull_number,
                        failure_type=failure_type,
                        hydration_attempted=True,
                    )
                )

        def listing_is_confirmed_complete() -> bool:
            """Re-scan identities before declaring a mutable listing complete."""

            previous_updated_at: datetime | None = None
            pull_numbers_by_id: dict[int, int] = {}
            pull_ids_by_number: dict[int, int] = {}
            observed: set[tuple[int, int]] = set()
            for page in range(1, _MAX_CLOSED_PULL_LIST_PAGES_PER_POLL + 1):
                raw_page = self._http.request_json(
                    "GET",
                    f"/repos/{self.policy.repository}/pulls",
                    params={
                        "state": "closed",
                        "sort": "updated",
                        "direction": "desc",
                        "per_page": 100,
                        "page": page,
                    },
                )
                if not isinstance(raw_page, list) or len(raw_page) > 100:
                    raise GitHubAPIError("GitHub returned a malformed closed-pull page")
                if not raw_page:
                    return True
                for raw in raw_page:
                    pull = _parse_pull_request(
                        self.policy.repository,
                        _as_mapping(raw, label="closed pull"),
                    )
                    if pull.state != "closed":
                        raise GitHubAPIError(
                            "GitHub returned a non-closed pull request in the "
                            "closed listing"
                        )
                    updated_at = _parse_utc_timestamp(
                        pull.updated_at,
                        label="pull-request updated_at",
                    )
                    identity = (pull.pull_id, pull.number)
                    if identity in observed:
                        raise GitHubAPIError(
                            "GitHub closed pulls repeated a pull-request identity"
                        )
                    if (
                        pull.pull_id in pull_numbers_by_id
                        and pull_numbers_by_id[pull.pull_id] != pull.number
                    ) or (
                        pull.number in pull_ids_by_number
                        and pull_ids_by_number[pull.number] != pull.pull_id
                    ):
                        raise GitHubAPIError(
                            "GitHub closed pulls contained an identity collision"
                        )
                    if (
                        previous_updated_at is not None
                        and updated_at > previous_updated_at
                    ):
                        raise GitHubAPIError(
                            "GitHub closed pulls were not in descending "
                            "updated_at order"
                        )
                    observed.add(identity)
                    pull_numbers_by_id[pull.pull_id] = pull.number
                    pull_ids_by_number[pull.number] = pull.pull_id
                    previous_updated_at = updated_at
                    if updated_at > upper_bound:
                        continue
                    if updated_at < cutoff:
                        return True
                    if (
                        self.policy.permits(pull)
                        and identity not in covered_identities
                        and identity not in excluded
                    ):
                        return False
                if len(raw_page) < 100:
                    return True
            safety_bound = _MAX_CLOSED_PULL_LIST_PAGES_PER_POLL * 100
            raise GitHubAPIError(
                "GitHub closed-pull confirmation exceeded the "
                f"{safety_bound:,}-item safety bound"
            )

        # A pending branch-only recovery is re-read directly before ordinary
        # discovery. An identity already durably marked seen is suppressed;
        # the controller decides when a recovery attempt becomes advanceable.
        for priority_group in priority_groups:
            if all(identity in seen for identity in priority_group):
                continue
            group_pulls: list[PullRequestSnapshot] = []
            group_is_eligible = True
            try:
                for pull_id, pull_number in priority_group:
                    raw_priority = self._http.request_json(
                        "GET",
                        f"/repos/{self.policy.repository}/pulls/{pull_number}",
                    )
                    pull = _parse_pull_request(
                        self.policy.repository,
                        _as_mapping(raw_priority, label="priority closed pull"),
                    )
                    if (pull.pull_id, pull.number) != (pull_id, pull_number):
                        raise GitHubAPIError(
                            "GitHub priority pull no longer matches its durable identity"
                        )
                    _parse_utc_timestamp(
                        pull.updated_at,
                        label="pull-request updated_at",
                    )
                    # The discovery window admits new evidence. It must not evict a
                    # durable, already-authorized recovery group: a published branch
                    # can still need reconciliation after its source PR ages out (or
                    # moves beyond the cycle's frozen upper bound).
                    if pull.state != "closed" or not self.policy.permits(pull):
                        group_is_eligible = False
                    group_pulls.append(pull)
            except GitHubAuthenticationError:
                raise
            except GitHubAPIError as exc:
                record_priority_group_failure(
                    priority_group,
                    failure_type=type(exc).__name__,
                )
                if (
                    hydration_attempts >= max_prs_per_poll
                    or len(covered_identities) >= _MAX_CLOSED_PULL_IDENTITIES_PER_CYCLE
                ):
                    return ClosedPullScanResult(
                        items=tuple(items),
                        hydration_attempts=hydration_attempts,
                        cycle_complete=False,
                    )
                continue
            if not group_is_eligible:
                record_priority_group_failure(priority_group)
                if (
                    hydration_attempts >= max_prs_per_poll
                    or len(covered_identities) >= _MAX_CLOSED_PULL_IDENTITIES_PER_CYCLE
                ):
                    return ClosedPullScanResult(
                        items=tuple(items),
                        hydration_attempts=hydration_attempts,
                        cycle_complete=False,
                    )
                continue
            first_group_item = len(items)
            for group_offset, pull in enumerate(group_pulls):
                hydrate(
                    pull,
                    position=ClosedPullScanPosition(
                        page=1,
                        offset=group_offset,
                    ),
                )
            if any(item.failure_type is not None for item in items[first_group_item:]):
                items[first_group_item:] = [
                    ClosedPullScanItem(
                        position=item.position,
                        pull_id=item.pull_id,
                        pull_number=item.pull_number,
                        failure_type="GitHubAPIError",
                        hydration_attempted=True,
                    )
                    for item in items[first_group_item:]
                ]
            if (
                hydration_attempts >= max_prs_per_poll
                or len(covered_identities) >= _MAX_CLOSED_PULL_IDENTITIES_PER_CYCLE
            ):
                return ClosedPullScanResult(
                    items=tuple(items),
                    hydration_attempts=hydration_attempts,
                    cycle_complete=False,
                )

        previous_updated_at: datetime | None = None
        pull_numbers_by_id: dict[int, int] = {}
        pull_ids_by_number: dict[int, int] = {}
        seen_pull_identities: set[tuple[int, int]] = set()
        for page in range(1, _MAX_CLOSED_PULL_LIST_PAGES_PER_POLL + 1):
            raw_page = self._http.request_json(
                "GET",
                f"/repos/{self.policy.repository}/pulls",
                params={
                    "state": "closed",
                    "sort": "updated",
                    "direction": "desc",
                    "per_page": 100,
                    "page": page,
                },
            )
            if not isinstance(raw_page, list) or len(raw_page) > 100:
                raise GitHubAPIError("GitHub returned a malformed closed-pull page")
            if not raw_page:
                return ClosedPullScanResult(
                    items=tuple(items),
                    hydration_attempts=hydration_attempts,
                    cycle_complete=listing_is_confirmed_complete(),
                )
            parsed_page: list[tuple[int, PullRequestSnapshot, datetime]] = []
            for offset, raw in enumerate(raw_page):
                pull = _parse_pull_request(
                    self.policy.repository,
                    _as_mapping(raw, label="closed pull"),
                )
                if pull.state != "closed":
                    raise GitHubAPIError(
                        "GitHub returned a non-closed pull request in the closed listing"
                    )
                updated_at = _parse_utc_timestamp(
                    pull.updated_at,
                    label="pull-request updated_at",
                )
                identity = (pull.pull_id, pull.number)
                if identity in seen_pull_identities:
                    raise GitHubAPIError(
                        "GitHub closed pulls repeated a pull-request identity"
                    )
                if (
                    pull.pull_id in pull_numbers_by_id
                    and pull_numbers_by_id[pull.pull_id] != pull.number
                ) or (
                    pull.number in pull_ids_by_number
                    and pull_ids_by_number[pull.number] != pull.pull_id
                ):
                    raise GitHubAPIError(
                        "GitHub closed pulls contained an identity collision"
                    )
                seen_pull_identities.add(identity)
                pull_numbers_by_id[pull.pull_id] = pull.number
                pull_ids_by_number[pull.number] = pull.pull_id
                if previous_updated_at is not None and updated_at > previous_updated_at:
                    raise GitHubAPIError(
                        "GitHub closed pulls were not in descending updated_at order"
                    )
                previous_updated_at = updated_at
                parsed_page.append((offset, pull, updated_at))

            for offset, pull, updated_at in parsed_page:
                identity = (pull.pull_id, pull.number)
                if updated_at > upper_bound:
                    continue
                if updated_at < cutoff:
                    return ClosedPullScanResult(
                        items=tuple(items),
                        hydration_attempts=hydration_attempts,
                        cycle_complete=listing_is_confirmed_complete(),
                    )
                if (
                    identity in priority_set
                    or identity in seen
                    or identity in excluded
                    or not self.policy.permits(pull)
                ):
                    continue
                if len(covered_identities) >= _MAX_CLOSED_PULL_IDENTITIES_PER_CYCLE:
                    raise GitHubAPIError(
                        "GitHub closed-pull hydration would exceed the "
                        f"{_MAX_CLOSED_PULL_IDENTITIES_PER_CYCLE:,}-identity "
                        "safety bound"
                    )
                hydrate(
                    pull,
                    position=ClosedPullScanPosition(page=page, offset=offset),
                )
                if (
                    hydration_attempts >= max_prs_per_poll
                    or len(covered_identities) >= _MAX_CLOSED_PULL_IDENTITIES_PER_CYCLE
                ):
                    at_known_end = len(raw_page) < 100 and offset == len(raw_page) - 1
                    return ClosedPullScanResult(
                        items=tuple(items),
                        hydration_attempts=hydration_attempts,
                        cycle_complete=(
                            at_known_end and listing_is_confirmed_complete()
                        ),
                    )
            if len(raw_page) < 100:
                return ClosedPullScanResult(
                    items=tuple(items),
                    hydration_attempts=hydration_attempts,
                    cycle_complete=listing_is_confirmed_complete(),
                )
        safety_bound = _MAX_CLOSED_PULL_LIST_PAGES_PER_POLL * 100
        raise GitHubAPIError(
            "GitHub closed-pull listing exceeded the "
            f"{safety_bound:,}-item safety bound"
        )

    def _hydrate_pull(
        self,
        *,
        repository_identity: GitHubRepositoryIdentity,
        pull: PullRequestSnapshot,
        previous_by_object: Mapping[
            tuple[str, int, FeedbackKind, str], FeedbackRevision
        ],
    ) -> PullRequestFeedbackSnapshot:
        _parse_utc_timestamp(
            pull.updated_at,
            label="pull-request updated_at",
        )
        endpoints = (
            (
                FeedbackKind.ISSUE_COMMENT,
                f"/repos/{self.policy.repository}/issues/{pull.number}/comments",
            ),
            (
                FeedbackKind.REVIEW,
                f"/repos/{self.policy.repository}/pulls/{pull.number}/reviews",
            ),
            (
                FeedbackKind.REVIEW_COMMENT,
                f"/repos/{self.policy.repository}/pulls/{pull.number}/comments",
            ),
        )

        def collect_material() -> tuple[
            tuple[FeedbackRevision, ...],
            tuple[ChangedFile, ...],
        ]:
            feedback: list[FeedbackRevision] = []
            feedback_bytes = 0
            for kind, endpoint in endpoints:
                for raw_feedback in self._http.paginate(
                    endpoint,
                    max_items=_MAX_FEEDBACK_ITEMS_PER_PULL,
                ):
                    revision = _parse_feedback(
                        self.policy.repository,
                        pull.number,
                        kind,
                        raw_feedback,
                    )
                    feedback_bytes += len(revision.body.encode("utf-8"))
                    if (
                        len(feedback) >= _MAX_FEEDBACK_ITEMS_PER_PULL
                        or feedback_bytes > _MAX_FEEDBACK_BYTES_PER_PULL
                    ):
                        raise GitHubAPIError(
                            "GitHub pull-request feedback exceeded the intake bound"
                        )
                    feedback.append(revision)
            feedback.sort(
                key=lambda item: (
                    item.kind.value,
                    int(item.source_id),
                    item.revision_id,
                )
            )
            if len({item.object_key for item in feedback}) != len(feedback):
                raise GitHubAPIError(
                    "GitHub pull-request feedback repeated an object identity"
                )

            changed = tuple(
                sorted(
                    (
                        _parse_changed_file(raw_file)
                        for raw_file in self._http.paginate(
                            f"/repos/{self.policy.repository}/pulls/"
                            f"{pull.number}/files",
                            max_items=_MAX_CHANGED_FILES_PER_PULL,
                        )
                    ),
                    key=lambda item: (
                        item.path,
                        item.status,
                        item.sha,
                        item.previous_path or "",
                        item.patch or "",
                    ),
                )
            )
            if len({item.path for item in changed}) != len(changed):
                raise GitHubAPIError(
                    "GitHub pull-request files repeated a changed path"
                )
            changed_file_bytes = sum(
                len((changed_file.patch or "").encode("utf-8"))
                + len(changed_file.path.encode("utf-8"))
                for changed_file in changed
            )
            if changed_file_bytes > _MAX_CHANGED_FILE_BYTES_PER_PULL:
                raise GitHubAPIError(
                    "GitHub pull-request changed-file metadata exceeded the intake bound"
                )
            return tuple(feedback), changed

        current, changed_files = collect_material()
        confirmed_feedback, confirmed_changed_files = collect_material()
        if confirmed_feedback != current or confirmed_changed_files != changed_files:
            raise GitHubAPIError("GitHub pull request changed during hydration")

        final_pull = _parse_pull_request(
            self.policy.repository,
            _as_mapping(
                self._http.request_json(
                    "GET",
                    f"/repos/{self.policy.repository}/pulls/{pull.number}",
                ),
                label="pull request revalidation",
            ),
        )
        _parse_utc_timestamp(
            final_pull.updated_at,
            label="pull-request updated_at",
        )
        if _pull_hydration_identity(final_pull) != _pull_hydration_identity(pull):
            raise GitHubAPIError("GitHub pull request changed during hydration")

        current_by_object = {revision.object_key: revision for revision in current}
        for object_key, old_revision in previous_by_object.items():
            if object_key[0] != self.policy.repository or object_key[1] != pull.number:
                continue
            if object_key not in current_by_object and not old_revision.deleted:
                current_by_object[object_key] = replace(
                    old_revision,
                    body="",
                    deleted=True,
                )

        if len(current_by_object) > _MAX_FEEDBACK_ITEMS_PER_PULL:
            raise GitHubAPIError(
                "GitHub pull-request feedback authority exceeded the intake bound"
            )

        current = tuple(
            sorted(
                current_by_object.values(),
                key=lambda item: (
                    item.kind.value,
                    int(item.source_id),
                    item.revision_id,
                ),
            )
        )
        visible = tuple(item for item in current if not item.deleted)
        return PullRequestFeedbackSnapshot(
            repository_identity=repository_identity,
            pull_request=pull,
            feedback=tuple(current),
            coderabbit=_coderabbit_coverage(visible),
            changed_files=changed_files,
        )


class GitHubWriteBroker:
    """Perform narrowly allowlisted GitHub writes with a just-in-time token."""

    def __init__(
        self,
        *,
        policy: GitHubRepositoryPolicy,
        expected_actor: TrustedActor,
        token_command: Sequence[str] | None = None,
        credential: SecretCommand | CredentialSnapshot | None = None,
        base_url: str = "https://api.github.com",
        transport: httpx.BaseTransport | None = None,
        timeout: float = 30.0,
        token_command_timeout: float = 30.0,
        token_command_env: Mapping[str, str] | None = None,
        deadline: PollDeadline | None = None,
    ) -> None:
        if (token_command is None) == (credential is None):
            raise ValueError("exactly one GitHub credential source is required")
        if token_command is not None and (
            not token_command
            or any(not isinstance(item, str) or not item for item in token_command)
        ):
            raise ValueError("token_command must be a non-empty argv sequence")
        if credential is not None and not isinstance(
            credential, (SecretCommand, CredentialSnapshot)
        ):
            raise TypeError("credential must be a trusted credential reader")
        self._validate_expected_actor(expected_actor)
        self.policy = policy
        self.expected_actor = expected_actor
        self.token_command = tuple(token_command or ())
        self.base_url = base_url
        self.web_base_url = _github_web_base_url(base_url)
        self.transport = transport
        self.timeout = timeout
        self.deadline = deadline
        self._token_helper = (
            credential
            if credential is not None
            else SecretCommand(
                tuple(token_command or ()),
                timeout_seconds=token_command_timeout,
                environment=token_command_env,
            )
        )

    def _mint_token(self) -> str:
        helper = self._token_helper
        if self.deadline is not None and isinstance(helper, SecretCommand):
            helper = replace(
                helper,
                timeout_seconds=self.deadline.remaining(helper.timeout_seconds),
            )
        elif self.deadline is not None:
            self.deadline.require_remaining()
        try:
            return helper.read()
        except CredentialError:
            if self.deadline is not None:
                self.deadline.require_remaining()
            raise GitHubAuthenticationError("GitHub token helper failed") from None

    def _client(self, token: str) -> httpx.Client:
        return httpx.Client(
            base_url=self.base_url,
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {token}",
                "X-GitHub-Api-Version": "2022-11-28",
            },
            timeout=self.timeout,
            transport=self.transport,
            trust_env=False,
        )

    @contextmanager
    def authenticated_client(self) -> Iterator[httpx.Client]:
        """Yield a short-lived authenticated client without exposing its token."""

        token = self._mint_token()
        with self._client(token) as client:
            self._require_expected_actor(
                _GitHubHTTP(client, deadline=self.deadline),
                expected_actor=self.expected_actor,
            )
            yield client

    def _assert_repository_identity(self, http: _GitHubHTTP) -> None:
        payload = _as_mapping(
            http.request_json("GET", f"/repos/{self.policy.repository}"),
            label="repository",
        )
        if str(payload.get("full_name") or "") != self.policy.repository:
            raise PolicyViolation("GitHub repository identity no longer matches policy")
        repository_id = _as_int(payload.get("id"), label="repository id")
        if (
            self.policy.repository_id is not None
            and repository_id != self.policy.repository_id
        ):
            raise PolicyViolation("GitHub repository id no longer matches policy")

    def _fresh_pull(
        self,
        http: _GitHubHTTP,
        *,
        pull_number: int,
        expected_head_sha: str,
        expected_base_sha: str,
    ) -> PullRequestSnapshot:
        self._assert_repository_identity(http)
        raw_pull = _as_mapping(
            http.request_json(
                "GET",
                f"/repos/{self.policy.repository}/pulls/{pull_number}",
            ),
            label="pull request",
        )
        pull = _parse_pull_request(self.policy.repository, raw_pull)
        if pull.state.casefold() != "open":
            raise PolicyViolation("pull request is no longer open")
        if not self.policy.permits(pull):
            raise PolicyViolation("pull request no longer matches repository policy")
        if pull.head_sha != expected_head_sha:
            raise PolicyViolation("pull-request head changed after review")
        if pull.base_sha != expected_base_sha:
            raise PolicyViolation("pull-request base changed after review")
        if not _valid_repository_name(pull.head_repository):
            raise PolicyViolation("pull-request head repository is invalid")
        return pull

    @staticmethod
    def _validate_sha(value: str, *, label: str) -> None:
        if not _SHA_RE.fullmatch(value):
            raise ValueError(f"{label} must be a full hexadecimal commit SHA")

    def verify_pull(
        self,
        *,
        pull_number: int,
        expected_head_sha: str,
        expected_base_sha: str,
        expected_actor: TrustedActor,
    ) -> PullRequestSnapshot:
        """Revalidate all ownership and revision constraints without writing."""

        self._validate_sha(expected_head_sha, label="expected_head_sha")
        self._validate_sha(expected_base_sha, label="expected_base_sha")
        self._validate_expected_actor(expected_actor)
        token = self._mint_token()
        with self._client(token) as client:
            http = _GitHubHTTP(client, deadline=self.deadline)
            self._require_expected_actor(http, expected_actor=expected_actor)
            return self._fresh_pull(
                http,
                pull_number=pull_number,
                expected_head_sha=expected_head_sha,
                expected_base_sha=expected_base_sha,
            )

    @staticmethod
    def _validate_marker_id(value: str, *, label: str) -> None:
        if not _MARKER_ID_RE.fullmatch(value):
            raise ValueError(f"{label} contains unsupported characters")

    @staticmethod
    def _reply_marker(action_id: str, event_revision_id: str) -> str:
        return (
            "<!-- localize-guardian:v1 "
            f"action={action_id} event={event_revision_id} -->"
        )

    def _authenticated_actor(self, http: _GitHubHTTP) -> TrustedActor:
        return _trusted_actor_from_payload(
            http.request_json("GET", "/user"),
            label="authenticated actor",
        )

    @staticmethod
    def _validate_expected_actor(expected_actor: TrustedActor) -> None:
        if not isinstance(expected_actor, TrustedActor):
            raise TypeError("expected_actor must be a TrustedActor")
        if expected_actor.type != "User":
            raise ValueError("expected_actor must be a User identity")

    def _require_expected_actor(
        self,
        http: _GitHubHTTP,
        *,
        expected_actor: TrustedActor,
    ) -> TrustedActor:
        """Authenticate the exact configured writer by immutable identity."""

        self._validate_expected_actor(expected_actor)
        if (expected_actor.id, expected_actor.type) != (
            self.expected_actor.id,
            self.expected_actor.type,
        ):
            raise PolicyViolation(
                "GitHub write actor does not match the broker's configured authority."
            )
        actual = self._authenticated_actor(http)
        if (actual.id, actual.type) != (expected_actor.id, expected_actor.type):
            raise GitHubAuthenticationError(
                "GitHub publication actor does not match configured authority."
            )
        return actual

    def _reply_body(
        self,
        *,
        marker: str,
        head_repository: str,
        commit_sha: str,
    ) -> str:
        short_sha = commit_sha[:12]
        commit_url = f"{self.web_base_url}/{head_repository}/commit/{commit_sha}"
        return (
            f"{marker}\n"
            "🤖 **Localize Guardian:** Applied a validated translation-only "
            f"correction in [`{short_sha}`]({commit_url}). The review thread "
            "remains open for reviewer confirmation."
        )

    def _validated_reply_comment(
        self,
        value: Any,
        *,
        expected_actor: TrustedActor,
        expected_body: str,
        pull_number: int,
        created: bool,
    ) -> ReplyResult:
        comment = _as_mapping(value, label="status comment")
        comment_id = _as_int(comment.get("id"), label="comment id")
        author = _trusted_actor_from_payload(
            comment.get("user"),
            label="status comment author",
        )
        body = comment.get("body")
        html_url = comment.get("html_url")
        expected_url = (
            f"{self.web_base_url}/{self.policy.repository}/pull/{pull_number}"
            f"#issuecomment-{comment_id}"
        )
        if (
            (author.id, author.type) != (expected_actor.id, expected_actor.type)
            or body != expected_body
            or html_url != expected_url
        ):
            raise PolicyViolation(
                "Guardian status marker conflicts with its exact actor or content."
            )
        return ReplyResult(
            comment_id=comment_id,
            html_url=html_url,
            body=body,
            created=created,
        )

    def post_commit_reply(
        self,
        *,
        pull_number: int,
        expected_head_sha: str,
        expected_base_sha: str,
        commit_sha: str,
        action_id: str,
        event_revision_id: str,
        expected_actor: TrustedActor,
        before_create: Callable[[], None] | None = None,
    ) -> ReplyResult:
        """Post an idempotent status comment after a confirmed owned-branch update."""
        self._validate_sha(expected_head_sha, label="expected_head_sha")
        self._validate_sha(expected_base_sha, label="expected_base_sha")
        self._validate_sha(commit_sha, label="commit_sha")
        self._validate_expected_actor(expected_actor)
        if commit_sha != expected_head_sha:
            raise PolicyViolation(
                "status reply commit is not the current reviewed head"
            )
        self._validate_marker_id(action_id, label="action_id")
        self._validate_marker_id(event_revision_id, label="event_revision_id")
        marker = self._reply_marker(action_id, event_revision_id)

        token = self._mint_token()
        with self._client(token) as client:
            http = _GitHubHTTP(client, deadline=self.deadline)
            self._require_expected_actor(http, expected_actor=expected_actor)
            pull = self._fresh_pull(
                http,
                pull_number=pull_number,
                expected_head_sha=expected_head_sha,
                expected_base_sha=expected_base_sha,
            )
            comments_url = (
                f"/repos/{self.policy.repository}/issues/{pull_number}/comments"
            )
            body = self._reply_body(
                marker=marker,
                head_repository=pull.head_repository,
                commit_sha=commit_sha,
            )
            matching: list[ReplyResult] = []
            for raw_comment in http.paginate(comments_url):
                raw_body = str(raw_comment.get("body") or "")
                if marker in raw_body:
                    matching.append(
                        self._validated_reply_comment(
                            raw_comment,
                            expected_actor=expected_actor,
                            expected_body=body,
                            pull_number=pull_number,
                            created=False,
                        )
                    )
            if len(matching) > 1:
                raise PolicyViolation(
                    "Multiple exact Guardian status comments share one marker."
                )
            if matching:
                return matching[0]

            if before_create is not None:
                before_create()
            self._require_expected_actor(http, expected_actor=expected_actor)
            # The source callback may perform slow local preparation and
            # remote hydration. Re-read the destination only after it and the
            # writer identity are both current, immediately before the POST.
            pull = self._fresh_pull(
                http,
                pull_number=pull_number,
                expected_head_sha=expected_head_sha,
                expected_base_sha=expected_base_sha,
            )
            fresh_body = self._reply_body(
                marker=marker,
                head_repository=pull.head_repository,
                commit_sha=commit_sha,
            )
            if before_create is not None:
                # The exact source snapshot includes the pull authority and
                # trusted feedback that the destination-only read above does
                # not hydrate. Keep that full source authority as the final
                # remote observation before the irreversible comment POST.
                before_create()
            created = _as_mapping(
                http.request_json("POST", comments_url, payload={"body": fresh_body}),
                label="created comment",
            )
            return self._validated_reply_comment(
                created,
                expected_actor=expected_actor,
                expected_body=fresh_body,
                pull_number=pull_number,
                created=True,
            )
