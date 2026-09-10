"""Exact-current-base publication for closed-PR translation remediations.

Historical pull requests and their comments are evidence only.  This module
owns the separate authority that may publish a signed candidate branch and a
draft pull request against the repository's current configured base branch.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from fnmatch import fnmatchcase
import hashlib
import json
import re
from urllib.parse import quote, urlsplit

import httpx

from localize.guardian.deadline import PollDeadline, deadline_httpx_timeout
from localize.guardian.credentials import (
    CredentialError,
    CredentialSnapshot,
    SecretCommand,
)
from localize.guardian.github import GitHubAuthenticationError, OpenPullPathIdentity
from localize.guardian.json_safety import loads_bounded_json
from localize.guardian.models import (
    HistoricalRemediationPolicy,
    ProposedReplacement,
    RepositoryPolicy,
)
from localize.guardian.path_globs import matches_any_path_glob
from localize.guardian.policy import PatchResult
from localize.guardian.state import (
    GuardianState,
    HistoricalPullReference,
    RemediationCoverageReason,
    RemediationDraftRecord,
    remediation_batch_hash,
    remediation_edit_hash,
    remediation_target_hash,
)
from localize.guardian.workspace import (
    CommitResult,
    ExactRevision,
    GuardianWorkspace,
    PreventionPublicationResult,
)


_SHA_RE = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_HASH_RE = re.compile(r"^[0-9a-f]{64}$")
_BRANCH_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/\-]*$")
_FEEDBACK_FRAGMENT_RE = re.compile(
    r"^(?:discussion_r|issuecomment-|pullrequestreview-)\d+$"
)
_MAX_RESPONSE_BYTES = 4 * 1024 * 1024
_MAX_PULL_PAGES = 100
_MAX_PULL_EVENT_PAGES = 100
_MAX_PENDING_RECOVERIES_PER_REPOSITORY = 100
_MAX_RETRY_SOURCE_PULLS = 100
_MAX_TITLE_BYTES = 256
_MAX_BODY_BYTES = 64 * 1024
_MAX_URL_BYTES = 4096
_MAX_CHANGED_PATHS = 100
_MAX_PATH_BYTES = 4096
_LIFECYCLE_EVENTS = frozenset(
    {
        "ready_for_review",
        "convert_to_draft",
        "converted_to_draft",
        "closed",
        "reopened",
        "merged",
    }
)
_UTC = timezone.utc


class RemediationRuntimeError(RuntimeError):
    """A redacted failure at the remediation publication boundary."""


class RemediationRemoteConflictError(RemediationRuntimeError):
    """A remediation PR lookup returned ambiguous or conflicting metadata."""


class RemediationSourceAuthorityError(RemediationRuntimeError):
    """A closed source no longer matches its assessed authority snapshot."""


class RemediationOpenPullAuthorityError(RemediationRuntimeError):
    """Complete open-PR path authority is unavailable or overlaps a draft."""


@dataclass(frozen=True, slots=True)
class RemediationBaseSnapshot:
    """Exact current target base after numeric repository revalidation."""

    revision: ExactRevision
    target_repository_id: int
    push_repository_id: int
    private: bool


@dataclass(frozen=True, slots=True)
class RemediationDraftResult:
    """An exact human-review remediation PR, newly created or recovered."""

    number: int
    html_url: str
    candidate_sha: str
    created: bool
    pull_id: int | None = None
    state: str = "open"
    merged: bool = False
    draft: bool = True
    base_sha: str | None = None
    closed_at: str | None = None
    merged_at: str | None = None

    def __post_init__(self) -> None:
        if self.pull_id is not None and (
            isinstance(self.pull_id, bool)
            or not isinstance(self.pull_id, int)
            or self.pull_id <= 0
        ):
            raise ValueError("remediation pull ID must be a positive integer")
        if self.state not in {"open", "closed"}:
            raise ValueError("remediation draft state must be open or closed")
        if type(self.created) is not bool or type(self.draft) is not bool:
            raise ValueError("remediation draft lifecycle flags must be booleans")
        if type(self.merged) is not bool:
            raise ValueError("remediation draft lifecycle flags must be booleans")
        if self.created and self.state != "open":
            raise ValueError("new remediation pull requests must be open")
        if self.merged and (self.state != "closed" or self.draft):
            raise ValueError("remediation draft merged lifecycle is inconsistent")
        if self.base_sha is not None and (
            not isinstance(self.base_sha, str) or not _SHA_RE.fullmatch(self.base_sha)
        ):
            raise ValueError("remediation draft base SHA must be a full SHA")


@dataclass(frozen=True, slots=True)
class _RepositoryPublicationIdentity:
    repository_id: int
    private: bool
    network_root_id: int


def _mapping(value: object, *, label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise RemediationRuntimeError(f"GitHub returned malformed {label} metadata.")
    return value


def _positive_int(value: object, *, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise RemediationRuntimeError(f"GitHub returned malformed {label} metadata.")
    return value


def _full_sha(value: object, *, label: str) -> str:
    if not isinstance(value, str) or not _SHA_RE.fullmatch(value):
        raise RemediationRuntimeError(f"GitHub returned malformed {label} metadata.")
    return value


def _safe_single_line(
    value: str,
    *,
    label: str,
    max_bytes: int,
) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value.encode("utf-8")) > max_bytes
        or any(character in value for character in "\r\n\x00")
    ):
        raise ValueError(f"{label} must be a safe non-empty single-line value")
    return value


def _safe_body(value: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or "\x00" in value
        or len(value.encode("utf-8")) > _MAX_BODY_BYTES
    ):
        raise ValueError("body must be non-empty and within its byte bound")
    return value


def _canonical_hash(payload: object) -> str:
    serialized = json.dumps(
        payload,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("observed_at must be timezone-aware")
    return value.astimezone(_UTC)


def _lifecycle_timestamp(value: object, *, label: str) -> tuple[str, datetime] | None:
    if value is None:
        return None
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 64
        or any(character in value for character in "\r\n\x00")
    ):
        raise RemediationRuntimeError(
            "GitHub returned malformed remediation pull request lifecycle metadata."
        )
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise RemediationRuntimeError(
            "GitHub returned malformed remediation pull request lifecycle metadata."
        ) from None
    if (
        parsed.tzinfo is None
        or parsed.utcoffset() is None
        or parsed.utcoffset() != _UTC.utcoffset(None)
    ):
        raise RemediationRuntimeError(
            "GitHub returned malformed remediation pull request lifecycle metadata."
        )
    return value, parsed


def _pull_lifecycle(
    pull: Mapping[str, object], *, state: str
) -> tuple[bool, str | None, str | None]:
    if "merged_at" not in pull or "closed_at" not in pull:
        raise RemediationRuntimeError(
            "GitHub returned malformed remediation pull request lifecycle metadata."
        )
    merged = _lifecycle_timestamp(pull["merged_at"], label="merged_at")
    closed = _lifecycle_timestamp(pull["closed_at"], label="closed_at")
    if (state == "open") != (closed is None):
        raise RemediationRuntimeError(
            "GitHub returned malformed remediation pull request lifecycle metadata."
        )
    if merged is not None and (
        state != "closed" or closed is None or merged[1] > closed[1]
    ):
        raise RemediationRuntimeError(
            "GitHub returned malformed remediation pull request lifecycle metadata."
        )
    return (
        merged is not None,
        None if merged is None else merged[0],
        None if closed is None else closed[0],
    )


class RemediationGitHubBroker:
    """Create or recover one exact remediation draft; never merge or comment."""

    def __init__(
        self,
        *,
        policy: RepositoryPolicy,
        token_command: Sequence[str] | None = None,
        credential: SecretCommand | CredentialSnapshot | None = None,
        github_host: str = "github.com",
        base_url: str = "https://api.github.com",
        transport: httpx.BaseTransport | None = None,
        timeout_seconds: float = 30.0,
        token_command_timeout: float = 30.0,
        deadline: PollDeadline | None = None,
        create_as_draft: bool = True,
    ) -> None:
        if type(create_as_draft) is not bool:
            raise TypeError("create_as_draft must be a boolean")
        self.create_as_draft = create_as_draft
        if not isinstance(policy, RepositoryPolicy):
            raise TypeError("policy must be a RepositoryPolicy")
        closed_policy = policy.closed_pr_backfill
        if closed_policy is None or closed_policy.remediation is None:
            raise ValueError("an explicit historical remediation policy is required")
        if (token_command is None) == (credential is None):
            raise ValueError("exactly one remediation credential source is required")
        if token_command is not None and (
            not token_command
            or any(
                not isinstance(argument, str) or not argument
                for argument in token_command
            )
        ):
            raise ValueError("token_command must be a non-empty argv sequence")
        if credential is not None and not isinstance(
            credential, (SecretCommand, CredentialSnapshot)
        ):
            raise TypeError("credential must be a trusted credential reader")
        if timeout_seconds <= 0 or token_command_timeout <= 0:
            raise ValueError("remediation timeouts must be positive")
        self.policy = policy
        self.remediation = closed_policy.remediation
        self.github_host = github_host
        self.base_url = base_url
        self.transport = transport
        self.timeout_seconds = float(timeout_seconds)
        self.deadline = deadline
        self._token = (
            credential
            if credential is not None
            else SecretCommand(
                tuple(token_command or ()),
                timeout_seconds=float(token_command_timeout),
            )
        )

    @contextmanager
    def _client(self) -> Iterator[tuple[httpx.Client, tuple[int, str]]]:
        helper = self._token
        if self.deadline is not None and isinstance(helper, SecretCommand):
            helper = replace(
                helper,
                timeout_seconds=self.deadline.remaining(helper.timeout_seconds),
            )
        elif self.deadline is not None:
            self.deadline.require_remaining()
        try:
            token = helper.read()
        except CredentialError:
            if self.deadline is not None:
                self.deadline.require_remaining()
            raise GitHubAuthenticationError(
                "GitHub remediation credential helper failed."
            ) from None
        try:
            with httpx.Client(
                base_url=self.base_url,
                headers={
                    "Accept": "application/vnd.github+json",
                    "Authorization": f"Bearer {token}",
                    "User-Agent": "localize-guardian",
                    "X-GitHub-Api-Version": "2022-11-28",
                },
                timeout=self.timeout_seconds,
                transport=self.transport,
                follow_redirects=False,
                trust_env=False,
            ) as client:
                actor = self._assert_authenticated_actor(client)
                yield client, actor
        finally:
            token = ""

    def _request(
        self,
        client: httpx.Client,
        method: str,
        path: str,
        *,
        params: Mapping[str, str | int] | None = None,
        payload: Mapping[str, object] | None = None,
        allow_missing: bool = False,
    ) -> object | None:
        request_timeout = deadline_httpx_timeout(
            self.deadline,
            self.timeout_seconds,
        )
        try:
            with client.stream(
                method,
                path,
                params=params,
                json=payload,
                timeout=request_timeout,
            ) as response:
                if allow_missing and response.status_code == 404:
                    return None
                if response.status_code < 200 or response.status_code >= 300:
                    retry_after = response.headers.get("retry-after", "").strip()
                    rate_limit_remaining = response.headers.get(
                        "x-ratelimit-remaining", ""
                    ).strip()
                    rate_limit_reset = response.headers.get(
                        "x-ratelimit-reset", ""
                    ).strip()
                    is_rate_limited = bool(retry_after) or (
                        rate_limit_remaining == "0" and bool(rate_limit_reset)
                    )
                    if response.status_code == 403 and is_rate_limited:
                        raise RemediationRuntimeError(
                            "GitHub remediation request was rate limited."
                        )
                    if response.status_code in {401, 403}:
                        raise GitHubAuthenticationError(
                            "GitHub remediation authentication failed."
                        )
                    raise RemediationRuntimeError(
                        "GitHub remediation request failed with status "
                        f"{response.status_code}."
                    )
                content = bytearray()
                for chunk in response.iter_bytes():
                    if self.deadline is not None:
                        self.deadline.require_remaining()
                    if len(chunk) > _MAX_RESPONSE_BYTES - len(content):
                        raise RemediationRuntimeError(
                            "GitHub remediation response exceeded its size bound."
                        )
                    content.extend(chunk)
                if self.deadline is not None:
                    self.deadline.require_remaining()
        except httpx.TimeoutException:
            if self.deadline is not None:
                self.deadline.require_remaining()
            raise RemediationRuntimeError(
                "GitHub remediation request failed."
            ) from None
        except httpx.HTTPError:
            raise RemediationRuntimeError(
                "GitHub remediation request failed."
            ) from None
        try:
            return loads_bounded_json(content)
        except (UnicodeDecodeError, ValueError, RecursionError):
            raise RemediationRuntimeError(
                "GitHub remediation request returned invalid JSON."
            ) from None

    def _repository(
        self,
        client: httpx.Client,
        *,
        full_name: str,
        repository_id: int,
    ) -> Mapping[str, object]:
        payload = _mapping(
            self._request(client, "GET", f"/repos/{full_name}"),
            label="repository",
        )
        if (
            payload.get("full_name") != full_name
            or _positive_int(payload.get("id"), label="repository id") != repository_id
        ):
            raise RemediationRuntimeError(
                "GitHub repository identity no longer matches remediation policy."
            )
        return payload

    def _assert_authenticated_actor(
        self,
        client: httpx.Client,
    ) -> tuple[int, str]:
        """Return immutable actor authority independently of its mutable login."""
        actor_id, actor_type, _login = self._authenticated_actor_identity(client)
        return actor_id, actor_type

    def publication_author_email(self) -> str:
        """Use the current authenticated login after enforcing pinned actor authority."""
        with self._client() as (client, _actor):
            actor_id, _actor_type, login = self._authenticated_actor_identity(client)
            return f"{actor_id}+{login}@users.noreply.github.com"

    def _authenticated_actor_identity(
        self,
        client: httpx.Client,
    ) -> tuple[int, str, str]:
        """Validate the pinned credential actor and retain its current login."""
        payload = _mapping(
            self._request(client, "GET", "/user"),
            label="authenticated actor",
        )
        actor_id = _positive_int(
            payload.get("id"),
            label="authenticated actor id",
        )
        actor_type = payload.get("type")
        login = payload.get("login")
        expected = self.remediation.publication_actor
        if (
            not isinstance(login, str)
            or not login
            or any(character in login for character in "\r\n\x00")
            or actor_type != "User"
            or actor_id != expected.id
            or actor_type != expected.type
        ):
            raise GitHubAuthenticationError(
                "GitHub remediation actor is not allowed by policy."
            )
        return actor_id, actor_type, login

    @staticmethod
    def _publication_identity(
        repository: Mapping[str, object],
        *,
        repository_id: int,
    ) -> _RepositoryPublicationIdentity:
        """Validate privacy and fork-network metadata used for publication authority."""
        private = repository.get("private")
        fork = repository.get("fork")
        if type(private) is not bool or type(fork) is not bool:
            raise RemediationRuntimeError(
                "GitHub returned malformed repository publication metadata."
            )
        if not fork:
            if (
                repository.get("parent") is not None
                or repository.get("source") is not None
            ):
                raise RemediationRuntimeError(
                    "GitHub returned inconsistent repository network metadata."
                )
            return _RepositoryPublicationIdentity(
                repository_id=repository_id,
                private=private,
                network_root_id=repository_id,
            )

        parent = _mapping(repository.get("parent"), label="fork parent repository")
        source = _mapping(repository.get("source"), label="fork source repository")
        parent_id = _positive_int(parent.get("id"), label="fork parent repository id")
        source_id = _positive_int(source.get("id"), label="fork source repository id")
        if (
            parent_id == repository_id
            or source_id == repository_id
            or source.get("fork") is not False
        ):
            raise RemediationRuntimeError(
                "GitHub returned inconsistent repository network metadata."
            )
        return _RepositoryPublicationIdentity(
            repository_id=repository_id,
            private=private,
            network_root_id=source_id,
        )

    def _assert_identities(self, client: httpx.Client) -> bool:
        target = self._repository(
            client,
            full_name=self.policy.base_repo,
            repository_id=self.policy.base_repo_id,
        )
        push = self._repository(
            client,
            full_name=self.remediation.push_repository.full_name,
            repository_id=self.remediation.push_repository.id,
        )
        owner = _mapping(push.get("owner"), label="push repository owner")
        owner_id = _positive_int(owner.get("id"), label="push repository owner id")
        owner_type = owner.get("type")
        allowed_owner = self.policy.allowed_head_owner_by_id(owner_id)
        if allowed_owner is None or allowed_owner.type != owner_type:
            raise RemediationRuntimeError(
                "GitHub push repository owner identity no longer matches policy."
            )
        target_identity = self._publication_identity(
            target,
            repository_id=self.policy.base_repo_id,
        )
        push_identity = self._publication_identity(
            push,
            repository_id=self.remediation.push_repository.id,
        )
        if target_identity.private and not push_identity.private:
            raise RemediationRuntimeError(
                "Guardian refuses to publish private repository content to a public "
                "push repository."
            )
        if (
            target_identity.repository_id != push_identity.repository_id
            and target_identity.network_root_id != push_identity.network_root_id
        ):
            raise RemediationRuntimeError(
                "GitHub push repository is outside the target repository fork network."
            )
        return target_identity.private

    def _base_sha(self, client: httpx.Client) -> str:
        encoded = quote(self.policy.base_branch, safe="")
        payload = _mapping(
            self._request(
                client,
                "GET",
                f"/repos/{self.policy.base_repo}/branches/{encoded}",
            ),
            label="base branch",
        )
        if payload.get("name") != self.policy.base_branch:
            raise RemediationRuntimeError(
                "Remediation target base branch changed identity."
            )
        commit = _mapping(payload.get("commit"), label="base commit")
        return _full_sha(commit.get("sha"), label="base SHA")

    def capture_base(self) -> RemediationBaseSnapshot:
        """Capture current base only after revalidating both numeric identities."""

        with self._client() as (client, _actor):
            private = self._assert_identities(client)
            sha = self._base_sha(client)
        owner, repository = self.policy.base_repo.split("/", 1)
        return RemediationBaseSnapshot(
            revision=ExactRevision(
                host=self.github_host,
                owner=owner,
                repository=repository,
                ref=f"refs/heads/{self.policy.base_branch}",
                sha=sha,
            ),
            target_repository_id=self.policy.base_repo_id,
            push_repository_id=self.remediation.push_repository.id,
            private=private,
        )

    def branch_sha(self, branch: str) -> str | None:
        """Return an allowlisted push branch SHA after identity revalidation."""

        branch = self._safe_branch(branch)
        encoded = quote(branch, safe="")
        with self._client() as (client, _actor):
            self._assert_identities(client)
            raw = self._request(
                client,
                "GET",
                f"/repos/{self.remediation.push_repository.full_name}/branches/{encoded}",
                allow_missing=True,
            )
            if raw is None:
                return None
            payload = _mapping(raw, label="remediation branch")
            if payload.get("name") != branch:
                raise RemediationRuntimeError("Remediation branch changed identity.")
            commit = _mapping(payload.get("commit"), label="branch commit")
            return _full_sha(commit.get("sha"), label="branch SHA")

    def _require_branch_candidate(
        self,
        client: httpx.Client,
        *,
        branch: str,
        candidate_sha: str,
    ) -> None:
        encoded = quote(branch, safe="")
        branch_payload = _mapping(
            self._request(
                client,
                "GET",
                f"/repos/{self.remediation.push_repository.full_name}/branches/{encoded}",
            ),
            label="remediation branch",
        )
        if (
            branch_payload.get("name") != branch
            or _full_sha(
                _mapping(
                    branch_payload.get("commit"),
                    label="branch commit",
                ).get("sha"),
                label="branch SHA",
            )
            != candidate_sha
        ):
            raise RemediationRuntimeError(
                "Remediation branch is not the exact candidate commit."
            )

    def verify_publish_authority(
        self,
        *,
        expected_base_sha: str,
        branch: str,
        candidate_sha: str,
    ) -> None:
        """Recheck exact base and absence lease before a candidate push."""

        _full_sha(expected_base_sha, label="expected base SHA")
        _full_sha(candidate_sha, label="candidate SHA")
        branch = self._safe_branch(branch)
        with self._client() as (client, _actor):
            self._assert_identities(client)
            if self._base_sha(client) != expected_base_sha:
                raise RemediationRuntimeError(
                    "Remediation target base moved before publish."
                )
        current = self.branch_sha(branch)
        if current not in {None, candidate_sha}:
            raise RemediationRuntimeError(
                "Remediation branch exists at an unexpected commit."
            )

    def _safe_branch(self, branch: str) -> str:
        branch = _safe_single_line(branch, label="branch", max_bytes=255)
        prefix = self.remediation.push_branch_prefix
        if (
            not branch.startswith(prefix)
            or branch == prefix
            or not any(
                fnmatchcase(branch, pattern)
                for pattern in self.policy.allowed_branch_globs
            )
            or branch.startswith("refs/")
            or not _BRANCH_RE.fullmatch(branch)
            or "//" in branch
            or ".." in branch
            or "@{" in branch
            or branch.endswith(("/", "."))
            or any(
                component.startswith(".") or component.endswith(".lock")
                for component in branch.split("/")
            )
        ):
            raise ValueError("remediation branch is unsafe or outside its prefix")
        return branch

    @staticmethod
    def marker(evidence_hash: str, candidate_sha: str) -> str:
        """Return the exact idempotency marker embedded in the draft body."""

        if not _HASH_RE.fullmatch(evidence_hash) or not _SHA_RE.fullmatch(
            candidate_sha
        ):
            raise ValueError("remediation marker identity is invalid")
        return (
            "<!-- localize-guardian-remediation:v1 "
            f"evidence={evidence_hash} candidate={candidate_sha} -->"
        )

    def _validated_html_url(self, value: object, *, number: int) -> str:
        if (
            not isinstance(value, str)
            or not value
            or len(value.encode("utf-8")) > _MAX_URL_BYTES
            or any(character in value for character in "\r\n\x00")
        ):
            raise RemediationRuntimeError(
                "GitHub returned malformed remediation pull request URL."
            )
        parsed = urlsplit(value)
        expected_path = f"/{self.policy.base_repo}/pull/{number}"
        if (
            parsed.scheme != "https"
            or parsed.hostname is None
            or parsed.hostname.casefold() != self.github_host.casefold()
            or parsed.netloc.casefold() != self.github_host.casefold()
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path != expected_path
            or parsed.query
            or parsed.fragment
        ):
            raise RemediationRuntimeError(
                "GitHub returned malformed remediation pull request URL."
            )
        return value

    def _validated_pull(
        self,
        raw: object,
        *,
        branch: str,
        expected_base_sha: str,
        candidate_sha: str,
        marker: str,
        expected_author: tuple[int, str],
        expected_title: str,
        expected_body: str,
        require_new_draft: bool,
        expected_number: int | None = None,
    ) -> RemediationDraftResult:
        try:
            return self._validated_pull_metadata(
                raw,
                branch=branch,
                expected_base_sha=expected_base_sha,
                candidate_sha=candidate_sha,
                marker=marker,
                expected_author=expected_author,
                expected_title=expected_title,
                expected_body=expected_body,
                require_new_draft=require_new_draft,
                expected_number=expected_number,
            )
        except RemediationRemoteConflictError:
            raise
        except (RemediationRuntimeError, ValueError) as exc:
            raise RemediationRemoteConflictError(str(exc)) from None

    def _validated_pull_metadata(
        self,
        raw: object,
        *,
        branch: str,
        expected_base_sha: str,
        candidate_sha: str,
        marker: str,
        expected_author: tuple[int, str],
        expected_title: str,
        expected_body: str,
        require_new_draft: bool,
        expected_number: int | None,
    ) -> RemediationDraftResult:
        pull = _mapping(raw, label="remediation pull request")
        pull_id = _positive_int(pull.get("id"), label="pull request id")
        number = _positive_int(pull.get("number"), label="pull request number")
        if expected_number is not None and number != expected_number:
            raise RemediationRuntimeError(
                "Remediation pull request no longer matches exact policy."
            )
        html_url = self._validated_html_url(pull.get("html_url"), number=number)
        pull_body = pull.get("body")
        state = pull.get("state")
        draft = pull.get("draft")
        if (
            state not in {"open", "closed"}
            or type(draft) is not bool
            or pull.get("maintainer_can_modify") is not False
            or not isinstance(pull_body, str)
            or not pull_body
            or "\x00" in pull_body
            or len(pull_body.encode("utf-8")) > _MAX_BODY_BYTES
        ):
            raise RemediationRuntimeError(
                "GitHub returned malformed remediation pull request metadata."
            )
        merged, merged_at, closed_at = _pull_lifecycle(pull, state=state)
        if require_new_draft and (state != "open" or draft is not self.create_as_draft):
            raise RemediationRuntimeError(
                "GitHub did not create a draft remediation pull request."
            )
        head = _mapping(pull.get("head"), label="pull request head")
        base = _mapping(pull.get("base"), label="pull request base")
        author = _mapping(pull.get("user"), label="pull request author")
        head_repo = _mapping(head.get("repo"), label="head repository")
        base_repo = _mapping(base.get("repo"), label="base repository")
        base_sha = _full_sha(base.get("sha"), label="pull base SHA")
        author_id = _positive_int(author.get("id"), label="pull request author id")
        if (
            head.get("ref") != branch
            or _full_sha(head.get("sha"), label="pull head SHA") != candidate_sha
            or head_repo.get("full_name") != self.remediation.push_repository.full_name
            or _positive_int(head_repo.get("id"), label="head repository id")
            != self.remediation.push_repository.id
            or base.get("ref") != self.policy.base_branch
            or base_repo.get("full_name") != self.policy.base_repo
            or _positive_int(base_repo.get("id"), label="base repository id")
            != self.policy.base_repo_id
            or pull.get("title") != expected_title
            or pull_body != expected_body
            or marker not in pull_body
            or (require_new_draft and base_sha != expected_base_sha)
            or (author_id, author.get("type")) != expected_author
        ):
            raise RemediationRuntimeError(
                "Remediation pull request no longer matches exact policy."
            )
        return RemediationDraftResult(
            number=number,
            html_url=html_url,
            candidate_sha=candidate_sha,
            created=require_new_draft,
            pull_id=pull_id,
            state=state,
            merged=merged,
            draft=draft,
            base_sha=base_sha,
            closed_at=closed_at,
            merged_at=merged_at,
        )

    def _matching_pulls(
        self,
        client: httpx.Client,
        *,
        branch: str,
    ) -> list[object]:
        push_owner = self.remediation.push_repository.full_name.split("/", 1)[0]
        matches: list[object] = []
        for page in range(1, _MAX_PULL_PAGES + 1):
            raw_page = self._request(
                client,
                "GET",
                f"/repos/{self.policy.base_repo}/pulls",
                params={
                    "state": "all",
                    "head": f"{push_owner}:{branch}",
                    "per_page": 100,
                    "page": page,
                },
            )
            if not isinstance(raw_page, list) or len(raw_page) > 100:
                raise RemediationRemoteConflictError(
                    "GitHub returned malformed remediation pull request list."
                )
            if any(not isinstance(raw, Mapping) for raw in raw_page):
                raise RemediationRemoteConflictError(
                    "GitHub returned malformed remediation pull request list."
                )
            matches.extend(raw_page)
            if len(matches) > 1:
                raise RemediationRemoteConflictError(
                    "GitHub returned duplicate remediation pull requests."
                )
            if len(raw_page) < 100:
                break
        else:
            raise RemediationRemoteConflictError(
                "GitHub remediation pull request pagination exceeded its bound."
            )
        return matches

    def _pull_event_history(
        self,
        client: httpx.Client,
        *,
        number: int,
    ) -> tuple[str, ...]:
        history: list[str] = []
        seen_ids: set[int] = set()
        for page in range(1, _MAX_PULL_EVENT_PAGES + 1):
            raw_page = self._request(
                client,
                "GET",
                f"/repos/{self.policy.base_repo}/issues/{number}/events",
                params={"per_page": 100, "page": page},
                allow_missing=True,
            )
            if not isinstance(raw_page, list) or len(raw_page) > 100:
                raise RemediationRemoteConflictError(
                    "GitHub returned malformed remediation pull request history."
                )
            for raw_event in raw_page:
                if not isinstance(raw_event, Mapping):
                    raise RemediationRemoteConflictError(
                        "GitHub returned malformed remediation pull request history."
                    )
                event_id = raw_event.get("id")
                event_name = raw_event.get("event")
                if (
                    isinstance(event_id, bool)
                    or not isinstance(event_id, int)
                    or event_id <= 0
                    or event_id in seen_ids
                    or not isinstance(event_name, str)
                    or not event_name
                    or len(event_name.encode("utf-8")) > 64
                    or any(character in event_name for character in "\r\n\x00")
                ):
                    raise RemediationRemoteConflictError(
                        "GitHub returned malformed remediation pull request history."
                    )
                seen_ids.add(event_id)
                if event_name in _LIFECYCLE_EVENTS:
                    history.append(event_name)
            if len(raw_page) < 100:
                return tuple(history)
        raise RemediationRemoteConflictError(
            "GitHub remediation pull request history pagination exceeded its bound."
        )

    def _validate_recovery_history(
        self,
        pull: RemediationDraftResult,
        history: tuple[str, ...],
    ) -> None:
        state = "open"
        # Ready-created PRs have no ready_for_review event. Legacy drafts may
        # still be recovered, but a redraft or reopen remains a human veto.
        draft = not (
            not self.create_as_draft
            and not pull.draft
            and "ready_for_review" not in history
        )
        merged = False
        valid = True
        for event in history:
            if event == "ready_for_review":
                if state != "open" or not draft or merged:
                    valid = False
                    break
                draft = False
            elif event in {"convert_to_draft", "converted_to_draft"}:
                # Guardian creates the candidate as a draft. Converting it back
                # to draft is an operator lifecycle mutation, not recovery.
                valid = False
                break
            elif event == "closed":
                if state != "open":
                    valid = False
                    break
                state = "closed"
            elif event == "reopened":
                if state != "closed" or merged:
                    valid = False
                    break
                state = "open"
            elif event == "merged":
                if state != "open" or draft or merged:
                    valid = False
                    break
                merged = True
            else:  # pragma: no cover - caller retains only lifecycle events
                valid = False
                break
        if (
            not valid
            or "reopened" in history
            or (state, draft, merged) != (pull.state, pull.draft, pull.merged)
        ):
            raise RemediationRemoteConflictError(
                "Remediation pull request lifecycle is inconsistent or ambiguous."
            )

    def _stable_recovered_pull(
        self,
        client: httpx.Client,
        raw: object,
        *,
        branch: str,
        expected_base_sha: str,
        candidate_sha: str,
        marker: str,
        expected_author: tuple[int, str],
        expected_title: str,
        expected_body: str,
    ) -> RemediationDraftResult:
        listed = self._validated_pull(
            raw,
            branch=branch,
            expected_base_sha=expected_base_sha,
            candidate_sha=candidate_sha,
            marker=marker,
            expected_author=expected_author,
            expected_title=expected_title,
            expected_body=expected_body,
            require_new_draft=False,
        )
        exact_path = f"/repos/{self.policy.base_repo}/pulls/{listed.number}"
        exact_before = self._request(
            client,
            "GET",
            exact_path,
            allow_missing=True,
        )
        if exact_before is None:
            raise RemediationRemoteConflictError(
                "Remediation pull request disappeared during observation."
            )
        before = self._validated_pull(
            exact_before,
            branch=branch,
            expected_base_sha=expected_base_sha,
            candidate_sha=candidate_sha,
            marker=marker,
            expected_author=expected_author,
            expected_title=expected_title,
            expected_body=expected_body,
            require_new_draft=False,
            expected_number=listed.number,
        )
        history_before = self._pull_event_history(client, number=listed.number)
        exact_middle = self._request(
            client,
            "GET",
            exact_path,
            allow_missing=True,
        )
        if exact_middle is None:
            raise RemediationRemoteConflictError(
                "Remediation pull request disappeared during observation."
            )
        middle = self._validated_pull(
            exact_middle,
            branch=branch,
            expected_base_sha=expected_base_sha,
            candidate_sha=candidate_sha,
            marker=marker,
            expected_author=expected_author,
            expected_title=expected_title,
            expected_body=expected_body,
            require_new_draft=False,
            expected_number=listed.number,
        )
        history_after = self._pull_event_history(client, number=listed.number)
        exact_after = self._request(
            client,
            "GET",
            exact_path,
            allow_missing=True,
        )
        if exact_after is None:
            raise RemediationRemoteConflictError(
                "Remediation pull request disappeared during observation."
            )
        after = self._validated_pull(
            exact_after,
            branch=branch,
            expected_base_sha=expected_base_sha,
            candidate_sha=candidate_sha,
            marker=marker,
            expected_author=expected_author,
            expected_title=expected_title,
            expected_body=expected_body,
            require_new_draft=False,
            expected_number=listed.number,
        )
        if (
            listed != before
            or before != middle
            or middle != after
            or history_before != history_after
        ):
            raise RemediationRemoteConflictError(
                "Remediation pull request or lifecycle changed during stable "
                "observation."
            )
        self._validate_recovery_history(after, history_after)
        return after

    def find_draft(
        self,
        *,
        branch: str,
        expected_base_sha: str,
        candidate_sha: str,
        marker_candidate_sha: str | None = None,
        evidence_hash: str,
        title: str,
        body: str,
    ) -> RemediationDraftResult | None:
        """Find one exact prior remediation PR without creating remote state."""

        branch = self._safe_branch(branch)
        _full_sha(expected_base_sha, label="expected base SHA")
        _full_sha(candidate_sha, label="candidate SHA")
        marker_sha = (
            candidate_sha if marker_candidate_sha is None else marker_candidate_sha
        )
        _full_sha(marker_sha, label="marker candidate SHA")
        marker = self.marker(evidence_hash, marker_sha)
        title = _safe_single_line(title, label="title", max_bytes=_MAX_TITLE_BYTES)
        body = _safe_body(body)
        expected_body = _safe_body(f"{marker}\n{body}")
        with self._client() as (client, actor):
            self._assert_identities(client)
            matching = self._matching_pulls(
                client,
                branch=branch,
            )
            if not matching:
                return None
            return self._stable_recovered_pull(
                client,
                matching[0],
                branch=branch,
                expected_base_sha=expected_base_sha,
                candidate_sha=candidate_sha,
                marker=marker,
                expected_author=actor,
                expected_title=title,
                expected_body=expected_body,
            )

    def open_draft(
        self,
        *,
        branch: str,
        expected_base_sha: str,
        candidate_sha: str,
        evidence_hash: str,
        title: str,
        body: str,
        before_create: Callable[[], None],
        before_post: Callable[[], None],
    ) -> RemediationDraftResult:
        """Recover an exact prior PR or create one new human-review draft."""

        if not callable(before_create) or not callable(before_post):
            raise TypeError("draft publication guards must be callable")
        branch = self._safe_branch(branch)
        _full_sha(expected_base_sha, label="expected base SHA")
        _full_sha(candidate_sha, label="candidate SHA")
        title = _safe_single_line(
            title,
            label="title",
            max_bytes=_MAX_TITLE_BYTES,
        )
        body = _safe_body(body)
        marker = self.marker(evidence_hash, candidate_sha)
        draft_body = _safe_body(f"{marker}\n{body}")
        push_owner = self.remediation.push_repository.full_name.split("/", 1)[0]

        with self._client() as (client, actor):
            self._assert_identities(client)
            matching = self._matching_pulls(
                client,
                branch=branch,
            )
            if matching:
                return self._stable_recovered_pull(
                    client,
                    matching[0],
                    branch=branch,
                    expected_base_sha=expected_base_sha,
                    candidate_sha=candidate_sha,
                    marker=marker,
                    expected_author=actor,
                    expected_title=title,
                    expected_body=draft_body,
                )

            if self._base_sha(client) != expected_base_sha:
                raise RemediationRuntimeError(
                    "Remediation target base moved before draft creation."
                )
            self._require_branch_candidate(
                client,
                branch=branch,
                candidate_sha=candidate_sha,
            )

            self._assert_identities(client)
            if self._base_sha(client) != expected_base_sha:
                raise RemediationRuntimeError(
                    "Remediation target base moved before draft creation."
                )
            self._require_branch_candidate(
                client,
                branch=branch,
                candidate_sha=candidate_sha,
            )
            before_create()
            # The callback may perform slow source/base revalidation. Re-read
            # every remote publication identity after it returns so no stale
            # pre-callback decision is used for the POST.
            if self._assert_authenticated_actor(client) != actor:
                raise GitHubAuthenticationError(
                    "GitHub remediation actor changed before draft creation."
                )
            self._assert_identities(client)
            if self._base_sha(client) != expected_base_sha:
                raise RemediationRuntimeError(
                    "Remediation target base moved before draft creation."
                )
            self._require_branch_candidate(
                client,
                branch=branch,
                candidate_sha=candidate_sha,
            )
            concurrent = self._matching_pulls(client, branch=branch)
            if concurrent:
                return self._stable_recovered_pull(
                    client,
                    concurrent[0],
                    branch=branch,
                    expected_base_sha=expected_base_sha,
                    candidate_sha=candidate_sha,
                    marker=marker,
                    expected_author=actor,
                    expected_title=title,
                    expected_body=draft_body,
                )
            # Source authority is the final explicit check before the POST.
            # No finite REST sequence can make the source and destination
            # observations atomic, but neither side relies on a value captured
            # before slow local preparation.
            before_post()
            created = self._request(
                client,
                "POST",
                f"/repos/{self.policy.base_repo}/pulls",
                payload={
                    "title": title,
                    "body": draft_body,
                    "head": f"{push_owner}:{branch}",
                    "head_repo": self.remediation.push_repository.full_name.split(
                        "/", 1
                    )[1],
                    "base": self.policy.base_branch,
                    "draft": self.create_as_draft,
                    "maintainer_can_modify": False,
                },
            )
            return self._validated_pull(
                created,
                branch=branch,
                expected_base_sha=expected_base_sha,
                candidate_sha=candidate_sha,
                marker=marker,
                expected_author=actor,
                expected_title=title,
                expected_body=draft_body,
                require_new_draft=True,
            )


class _PublicationCapacityError(RemediationRuntimeError):
    """The current poll has no remote-mutation slot remaining."""


@dataclass(frozen=True, slots=True)
class RemediationBatchOutcome:
    """Secret-free result of bounded historical remediation publication."""

    drafts: tuple[RemediationDraftResult, ...] = ()
    deferred: int = 0
    abandoned: int = 0
    checkpoints: int = 0
    retry_source_batches: tuple[tuple[HistoricalPullReference, ...], ...] = ()


def _remediation_policy(policy: RepositoryPolicy) -> HistoricalRemediationPolicy:
    closed = policy.closed_pr_backfill
    if closed is None or closed.remediation is None:
        raise ValueError("an explicit historical remediation policy is required")
    return closed.remediation


def _normalized_source_pulls(
    policy: RepositoryPolicy,
    source_pulls: Sequence[HistoricalPullReference],
) -> tuple[HistoricalPullReference, ...]:
    pulls = tuple(source_pulls)
    if (
        not pulls
        or any(not isinstance(item, HistoricalPullReference) for item in pulls)
        or len(set(pulls)) != len(pulls)
        or len({item.pull_id for item in pulls}) != len(pulls)
        or len({item.pr_number for item in pulls}) != len(pulls)
        or any(
            item.repository != policy.base_repo
            or item.repository_id != policy.base_repo_id
            for item in pulls
        )
        or len({item.policy_digest for item in pulls}) != 1
    ):
        raise ValueError("source_pulls must be unique exact identities for one policy")
    return tuple(
        sorted(
            pulls,
            key=lambda item: (
                item.repository,
                item.repository_id,
                item.pull_id,
                item.pr_number,
                item.pull_revision_digest,
                item.authority_digest,
                item.policy_digest,
                item.head_sha,
                item.base_sha,
            ),
        )
    )


def _source_policy_digests(
    source_pulls: Sequence[HistoricalPullReference],
) -> tuple[str, ...]:
    return tuple(sorted({item.policy_digest for item in source_pulls}))


def _normalized_revision_ids(values: Sequence[int]) -> tuple[int, ...]:
    revision_ids = tuple(values)
    if (
        not revision_ids
        or len(set(revision_ids)) != len(revision_ids)
        or any(
            isinstance(value, bool) or not isinstance(value, int) or value <= 0
            for value in revision_ids
        )
    ):
        raise ValueError("event_revision_ids must be unique positive integers")
    return tuple(sorted(revision_ids))


def _normalized_replacements(
    patch_result: PatchResult,
    replacements: Sequence[ProposedReplacement],
) -> tuple[ProposedReplacement, ...]:
    if not isinstance(patch_result, PatchResult):
        raise TypeError("patch_result must be a PatchResult")
    proposals = tuple(replacements)
    if not proposals or any(
        not isinstance(item, ProposedReplacement) for item in proposals
    ):
        raise ValueError("replacements must contain validated proposals")
    targets = tuple((item.path, item.key) for item in proposals)
    if len(set(targets)) != len(targets):
        raise ValueError("replacements must target unique translation entries")
    changed_files = tuple(patch_result.changed_files)
    changed_keys = tuple(patch_result.changed_keys)
    if (
        not changed_files
        or len(set(changed_files)) != len(changed_files)
        or not changed_keys
        or len(set(changed_keys)) != len(changed_keys)
        or set(targets) != set(changed_keys)
        or {path for path, _key in changed_keys} != set(changed_files)
    ):
        raise ValueError("patch_result does not exactly match selected replacements")
    return tuple(
        sorted(
            proposals,
            key=lambda item: (
                item.path,
                item.key,
                item.feedback_id,
                item.locale,
                item.expected_value,
                item.proposed_value,
            ),
        )
    )


def _normalized_changed_paths(values: Sequence[str]) -> tuple[str, ...]:
    """Bound exact candidate paths before they enter callbacks or state."""

    if isinstance(values, (str, bytes)):
        raise ValueError("changed paths must be a bounded sequence")
    paths = tuple(values)
    invalid_path = any(
        not isinstance(path, str)
        or not path
        or (
            isinstance(path, str)
            and (
                len(path.encode("utf-8")) > _MAX_PATH_BYTES
                or path.startswith("/")
                or "\\" in path
                or any(part in {"", ".", ".."} for part in path.split("/"))
                or any(character in path for character in "\r\n\x00")
            )
        )
        for path in paths
    )
    if (
        not paths
        or len(paths) > _MAX_CHANGED_PATHS
        or invalid_path
        or len(set(paths)) != len(paths)
    ):
        raise ValueError("changed paths must contain bounded safe repository paths")
    return tuple(sorted(paths))


def _opened_pull_identity(
    record: RemediationDraftRecord,
    *,
    policy: RepositoryPolicy | None = None,
    head_sha: str | None = None,
) -> OpenPullPathIdentity:
    """Build an exclusion only from a fully attested opened-draft ledger row."""

    if (
        record.phase != "draft_opened"
        or record.draft_pull_id is None
        or record.draft_number is None
        or record.changed_paths is None
    ):
        raise RemediationOpenPullAuthorityError(
            "Exact opened remediation pull identity is unavailable."
        )
    if policy is not None:
        remediation = _remediation_policy(policy)
        if (
            record.target_repository_id != policy.base_repo_id
            or record.push_repository_id != remediation.push_repository.id
        ):
            raise RemediationOpenPullAuthorityError(
                "Exact opened remediation repository identity is unavailable."
            )
        target_repository = policy.base_repo
        push_repository = remediation.push_repository.full_name
    else:
        target_repository = record.target_repository
        push_repository = record.push_repository
    return OpenPullPathIdentity(
        repository=target_repository,
        repository_id=record.target_repository_id,
        pull_id=record.draft_pull_id,
        number=record.draft_number,
        head_repository=push_repository,
        head_repository_id=record.push_repository_id,
        head_ref=record.branch,
        head_sha=record.candidate_sha if head_sha is None else head_sha,
    )


def _normalized_feedback_urls(
    *,
    base: RemediationBaseSnapshot,
    policy: RepositoryPolicy,
    source_pulls: Sequence[HistoricalPullReference],
    feedback_urls: Sequence[str],
) -> tuple[str, ...]:
    urls = tuple(feedback_urls)
    pull_numbers = {item.pr_number for item in source_pulls}
    paths = {
        path: number
        for number in pull_numbers
        for path in (
            f"/{policy.base_repo}/pull/{number}",
            f"/{policy.base_repo}/issues/{number}",
        )
    }
    represented: set[int] = set()
    for value in urls:
        if (
            not isinstance(value, str)
            or not value
            or len(value.encode("utf-8")) > _MAX_URL_BYTES
            or any(character in value for character in "\r\n\x00")
        ):
            raise ValueError("feedback_urls must contain bounded canonical links")
        parsed = urlsplit(value)
        number = paths.get(parsed.path)
        if (
            parsed.scheme != "https"
            or parsed.hostname is None
            or parsed.hostname.casefold() != base.revision.host.casefold()
            or parsed.netloc.casefold() != base.revision.host.casefold()
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or number is None
            or not _FEEDBACK_FRAGMENT_RE.fullmatch(parsed.fragment)
        ):
            raise ValueError("feedback URL does not match an exact historical pull")
        represented.add(number)
    if not urls or len(set(urls)) != len(urls) or represented != pull_numbers:
        raise ValueError("every historical pull needs a unique feedback URL")
    return tuple(sorted(urls))


def _evidence_hash(
    source_pulls: Sequence[HistoricalPullReference],
    feedback_urls: Sequence[str],
) -> str:
    return _canonical_hash(
        {
            "feedback_urls": list(feedback_urls),
            "source_pulls": [
                {
                    "authority_digest": item.authority_digest,
                    "base_sha": item.base_sha,
                    "head_sha": item.head_sha,
                    "pr_number": item.pr_number,
                    "pull_id": item.pull_id,
                    "pull_revision_digest": item.pull_revision_digest,
                    "repository": item.repository,
                    "repository_id": item.repository_id,
                }
                for item in source_pulls
            ],
        }
    )


def _edit_hashes(
    replacements: Sequence[ProposedReplacement],
) -> tuple[str, ...]:
    return tuple(sorted(remediation_edit_hash(item) for item in replacements))


def _edit_target_hashes(
    replacements: Sequence[ProposedReplacement],
) -> tuple[tuple[str, str], ...]:
    return tuple(
        sorted(
            (remediation_edit_hash(item), remediation_target_hash(item))
            for item in replacements
        )
    )


def _batch_hash(replacements: Sequence[ProposedReplacement]) -> str:
    return remediation_batch_hash(_edit_hashes(replacements))


def _branch_name(
    *,
    prefix: str,
    batch_hash: str,
    target_base_sha: str,
    evidence_hash: str,
    branch_identity_version: int = 1,
    policy_digests: Sequence[str] = (),
) -> str:
    if not isinstance(batch_hash, str) or not _HASH_RE.fullmatch(batch_hash):
        raise ValueError("batch_hash must be a SHA-256 digest")
    if not isinstance(target_base_sha, str) or not _SHA_RE.fullmatch(target_base_sha):
        raise ValueError("target_base_sha must be a full Git object id")
    if not isinstance(evidence_hash, str) or not _HASH_RE.fullmatch(evidence_hash):
        raise ValueError("evidence_hash must be a SHA-256 digest")
    if (
        isinstance(branch_identity_version, bool)
        or not isinstance(branch_identity_version, int)
        or branch_identity_version not in {1, 2}
    ):
        raise ValueError("branch_identity_version must be 1 or 2")
    raw_policy_digests = tuple(policy_digests)
    if any(
        not isinstance(value, str) or not _HASH_RE.fullmatch(value)
        for value in raw_policy_digests
    ):
        raise ValueError("policy_digests must contain SHA-256 digests")
    normalized_policy_digests = tuple(sorted(set(raw_policy_digests)))
    if branch_identity_version == 2 and not normalized_policy_digests:
        raise ValueError("v2 branch identity requires a policy digest")
    # A semantic batch may be reassessed after its original branch was pushed
    # but before a draft was created. Include every immutable input that can
    # require a fresh candidate so that the abandoned branch can remain
    # untouched without wedging the replacement attempt.
    identity: dict[str, object] = {
        "batch_hash": batch_hash,
        "evidence_hash": evidence_hash,
        "target_base_sha": target_base_sha,
        "version": branch_identity_version,
    }
    if branch_identity_version == 2:
        identity["policy_digests"] = list(normalized_policy_digests)
    attempt_hash = _canonical_hash(identity)
    branch = f"{prefix}{attempt_hash}"
    if len(branch.encode("utf-8")) > 255:
        raise ValueError("remediation branch prefix leaves no bounded identity space")
    return branch


def _draft_text(
    *,
    base: RemediationBaseSnapshot,
    policy: RepositoryPolicy,
    source_pulls: Sequence[HistoricalPullReference],
    feedback_urls: Sequence[str],
    patch_result: PatchResult,
    evidence_hash: str,
    batch_hash: str,
) -> tuple[str, str]:
    title = "[Localize Guardian bot] Historical translation corrections"
    source_urls = tuple(
        f"https://{base.revision.host}/{policy.base_repo}/pull/{item.pr_number}"
        for item in source_pulls
    )
    body = "\n".join(
        (
            "Bot-generated pull request for human review only.",
            "",
            "This current-base candidate does not modify or comment on the closed "
            "source pull requests and is never merged automatically.",
            "",
            "Historical source pull requests:",
            *(f"- {url}" for url in source_urls),
            "",
            "Validated review feedback:",
            *(f"- {url}" for url in feedback_urls),
            "",
            f"Changed localization files: {len(patch_result.changed_files)}",
            f"Changed translation entries: {len(patch_result.changed_keys)}",
            "",
            f"Evidence SHA-256: `{evidence_hash}`",
            f"Batch SHA-256: `{batch_hash}`",
            "",
        )
    )
    return (
        _safe_single_line(title, label="title", max_bytes=_MAX_TITLE_BYTES),
        _safe_body(body),
    )


class RemediationCoordinator:
    """Sign, publish, and recover bounded current-base remediation drafts."""

    def __init__(
        self,
        *,
        state: GuardianState,
        broker_factory: Callable[[RepositoryPolicy], RemediationGitHubBroker],
        publish_credential_environment: Callable[[], Mapping[str, str]],
        signing_key: str | None,
        signing_environment: Mapping[str, str] | None,
        max_drafts: int,
        deadline: PollDeadline | None = None,
    ) -> None:
        if (
            isinstance(max_drafts, bool)
            or not isinstance(max_drafts, int)
            or max_drafts < 0
        ):
            raise ValueError("max_drafts must be a non-negative integer")
        if not callable(broker_factory):
            raise TypeError("broker_factory must be callable")
        if not callable(publish_credential_environment):
            raise TypeError("publish_credential_environment must be callable")
        self.state = state
        self.broker_factory = broker_factory
        self.publish_credential_environment = publish_credential_environment
        self.signing_key = signing_key
        self.signing_environment = (
            None if signing_environment is None else dict(signing_environment)
        )
        self.max_drafts = max_drafts
        self.deadline = deadline
        self._publication_slots_used = 0
        self._publication_repositories_used: set[tuple[str, int]] = set()

    def begin_poll(self) -> None:
        """Reset the process-local publication cap for one bounded poll."""

        self._publication_slots_used = 0
        self._publication_repositories_used.clear()

    def _require_remaining(self) -> None:
        if self.deadline is not None:
            self.deadline.require_remaining()

    def revalidate_successor_pull(
        self,
        *,
        policy: RepositoryPolicy,
        publication_key: str,
        expected_remote_head_sha: str,
        expected_base_sha: str,
        require_open: bool,
        require_live_lease: Callable[[], None],
        require_no_open_translation_overlap: Callable[
            [Sequence[str], OpenPullPathIdentity | None], None
        ],
    ) -> RemediationDraftResult:
        """Rehydrate one exact remediation PR and its durable successor lineage."""

        if not callable(require_live_lease):
            raise TypeError("require_live_lease must be callable")
        if not callable(require_no_open_translation_overlap):
            raise TypeError("require_no_open_translation_overlap must be callable")
        if type(require_open) is not bool:
            raise TypeError("require_open must be a boolean")
        _full_sha(expected_remote_head_sha, label="expected remote head SHA")
        _full_sha(expected_base_sha, label="expected base SHA")
        try:
            intent = self.state.remediation_successor_intent(
                publication_key=publication_key
            )
        except (TypeError, ValueError, RuntimeError) as exc:
            raise RemediationRemoteConflictError(
                "Remediation successor intent is unavailable or malformed."
            ) from exc
        if intent is None:
            raise RemediationRemoteConflictError(
                "Remediation successor has no durable prepared intent."
            )
        publication_actor = _remediation_policy(policy).publication_actor
        if (
            intent.publication_actor_id != publication_actor.id
            or intent.publication_actor_type != publication_actor.type
        ):
            raise RemediationRemoteConflictError(
                "Remediation successor publication actor changed from its exact "
                "prepared intent."
            )
        record = self.state.remediation_draft_by_key(draft_key=intent.draft_key)
        if (
            record is None
            or record.phase != "draft_opened"
            or record.draft_number is None
            or record.draft_pull_id is None
            or not self._record_matches_policy(record, policy)
            or expected_base_sha != record.target_base_sha
            or expected_remote_head_sha
            not in {intent.parent_candidate_sha, intent.successor_candidate_sha}
        ):
            raise RemediationRemoteConflictError(
                "Remediation successor no longer matches its exact ledger."
            )
        try:
            successors = self.state.remediation_successor_publications(
                draft_key=record.draft_key
            )
        except (TypeError, ValueError, RuntimeError) as exc:
            raise RemediationRemoteConflictError(
                "Remediation successor lineage is unavailable or malformed."
            ) from exc
        current_tip = self.state.remediation_candidate_tip(record.draft_key)
        if current_tip == intent.parent_candidate_sha:
            # Before publication (or after a push-before-checkpoint crash), the
            # durable intent alone authorizes observing either side of the one
            # exact transition.
            lineage_is_exact = True
        else:
            latest = successors[-1] if successors else None
            lineage_is_exact = bool(
                current_tip == intent.successor_candidate_sha
                and latest is not None
                and latest.publication_key == publication_key
                and latest.parent_candidate_sha == intent.parent_candidate_sha
                and latest.successor_candidate_sha == intent.successor_candidate_sha
                and expected_remote_head_sha == intent.successor_candidate_sha
            )
        if not lineage_is_exact:
            raise RemediationRemoteConflictError(
                "Remediation successor no longer matches its current lineage."
            )

        # RemediationGitHubBroker independently requires the authenticated
        # credential actor and the recovered PR author to match this same
        # current policy actor on every exact read.
        self._require_remaining()
        broker = self.broker_factory(policy)
        find_arguments = {
            "branch": record.branch,
            "expected_base_sha": record.target_base_sha,
            "candidate_sha": expected_remote_head_sha,
            "marker_candidate_sha": record.candidate_sha,
            "evidence_hash": record.evidence_hash,
            "title": record.title,
            "body": record.body,
        }
        require_live_lease()
        self._require_remaining()
        draft = broker.find_draft(
            **find_arguments,
        )
        require_live_lease()
        if (
            draft is None
            or draft.number != record.draft_number
            or draft.pull_id != record.draft_pull_id
            or draft.candidate_sha != expected_remote_head_sha
            or (require_open and draft.base_sha != expected_base_sha)
            or (require_open and (draft.state != "open" or draft.merged))
        ):
            raise RemediationRemoteConflictError(
                "Remediation successor pull no longer has exact publication authority."
            )
        if require_open:
            require_live_lease()
            require_no_open_translation_overlap(
                intent.changed_paths,
                _opened_pull_identity(
                    record,
                    policy=policy,
                    head_sha=expected_remote_head_sha,
                ),
            )
            require_live_lease()
            # The overlap refresh is a slow remote authority read. Re-read the
            # exact PR afterwards so lifecycle, author, marker, title/body,
            # repository/base/head identity and the durable lineage are all
            # adjacent to the caller's push or reply boundary.
            self._require_remaining()
            refreshed = broker.find_draft(**find_arguments)
            require_live_lease()
            try:
                refreshed_intent = self.state.remediation_successor_intent(
                    publication_key=publication_key
                )
                refreshed_record = self.state.remediation_draft_by_key(
                    draft_key=intent.draft_key
                )
                refreshed_successors = self.state.remediation_successor_publications(
                    draft_key=record.draft_key
                )
                refreshed_tip = self.state.remediation_candidate_tip(record.draft_key)
            except (TypeError, ValueError, RuntimeError) as exc:
                raise RemediationRemoteConflictError(
                    "Remediation successor lineage changed during revalidation."
                ) from exc
            if refreshed_tip == intent.parent_candidate_sha:
                refreshed_lineage_is_exact = True
            else:
                refreshed_latest = (
                    refreshed_successors[-1] if refreshed_successors else None
                )
                refreshed_lineage_is_exact = bool(
                    refreshed_tip == intent.successor_candidate_sha
                    and refreshed_latest is not None
                    and refreshed_latest.publication_key == publication_key
                    and refreshed_latest.parent_candidate_sha
                    == intent.parent_candidate_sha
                    and refreshed_latest.successor_candidate_sha
                    == intent.successor_candidate_sha
                    and expected_remote_head_sha == intent.successor_candidate_sha
                )
            if (
                refreshed is None
                or refreshed != draft
                or refreshed_intent != intent
                or refreshed_record != record
                or not refreshed_lineage_is_exact
                or refreshed.number != record.draft_number
                or refreshed.pull_id != record.draft_pull_id
                or refreshed.candidate_sha != expected_remote_head_sha
                or refreshed.base_sha != expected_base_sha
                or refreshed.state != "open"
                or refreshed.merged
            ):
                raise RemediationRemoteConflictError(
                    "Remediation successor pull no longer has exact publication "
                    "authority."
                )
            draft = refreshed
            require_live_lease()
        return draft

    def capture_base(self, policy: RepositoryPolicy) -> RemediationBaseSnapshot:
        """Capture the current base through the narrow remediation broker."""

        _remediation_policy(policy)
        self._require_remaining()
        return self.broker_factory(policy).capture_base()

    @staticmethod
    def _validate_base(
        *,
        policy: RepositoryPolicy,
        base: RemediationBaseSnapshot,
        workspace: GuardianWorkspace | None = None,
    ) -> None:
        remediation = _remediation_policy(policy)
        if not isinstance(base, RemediationBaseSnapshot):
            raise TypeError("base must be a RemediationBaseSnapshot")
        owner, repository = policy.base_repo.split("/", 1)
        expected_ref = f"refs/heads/{policy.base_branch}"
        if (
            base.target_repository_id != policy.base_repo_id
            or base.push_repository_id != remediation.push_repository.id
            or base.revision.owner != owner
            or base.revision.repository != repository
            or base.revision.ref != expected_ref
        ):
            raise RemediationRuntimeError(
                "Captured remediation base does not match exact policy."
            )
        if workspace is not None and (
            workspace.revision != base.revision
            or workspace.original_sha != base.revision.sha
        ):
            raise RemediationRuntimeError(
                "Remediation workspace is not the exact captured current base."
            )

    @staticmethod
    def _record_metadata(record: RemediationDraftRecord) -> dict[str, object]:
        return {
            "branch_identity_version": record.branch_identity_version,
            "run_id": record.run_id,
            "target_repository": record.target_repository,
            "target_repository_id": record.target_repository_id,
            "target_base_branch": record.target_base_branch,
            "target_base_sha": record.target_base_sha,
            "push_repository": record.push_repository,
            "push_repository_id": record.push_repository_id,
            "branch": record.branch,
            "candidate_sha": record.candidate_sha,
            "evidence_hash": record.evidence_hash,
            "batch_hash": record.batch_hash,
            "edit_hashes": record.edit_hashes,
            "edit_target_hashes": record.edit_target_hashes,
            "source_pulls": record.source_pulls,
            "event_revision_ids": record.event_revision_ids,
            "changed_paths": record.changed_paths,
            "title": record.title,
            "body": record.body,
        }

    @staticmethod
    def _record_matches_policy(
        record: RemediationDraftRecord,
        policy: RepositoryPolicy,
    ) -> bool:
        remediation = _remediation_policy(policy)
        try:
            expected_branch = _branch_name(
                prefix=remediation.push_branch_prefix,
                batch_hash=record.batch_hash,
                target_base_sha=record.target_base_sha,
                evidence_hash=record.evidence_hash,
                branch_identity_version=record.branch_identity_version,
                policy_digests=_source_policy_digests(record.source_pulls),
            )
        except ValueError:
            return False
        return bool(
            record.target_repository_id == policy.base_repo_id
            and record.target_base_branch == policy.base_branch
            and record.push_repository_id == remediation.push_repository.id
            and record.branch.startswith(remediation.push_branch_prefix)
            and record.branch != remediation.push_branch_prefix
            and any(
                fnmatchcase(record.branch, pattern)
                for pattern in policy.allowed_branch_globs
            )
            and record.branch == expected_branch
            and record.changed_paths is not None
            and bool(record.changed_paths)
            and all(
                matches_any_path_glob(path, policy.allowed_path_globs)
                for path in record.changed_paths
            )
            and all(
                item.repository_id == policy.base_repo_id
                for item in record.source_pulls
            )
        )

    @staticmethod
    def _event_revision_ids_by_source(
        *,
        source_pulls: Sequence[HistoricalPullReference],
        event_revision_ids: Sequence[int],
        state: GuardianState,
    ) -> dict[HistoricalPullReference, tuple[int, ...]]:
        by_pair = {
            (source.repository, source.pr_number): source for source in source_pulls
        }
        grouped: dict[HistoricalPullReference, list[int]] = {
            source: [] for source in source_pulls
        }
        for revision_id in event_revision_ids:
            revision = state.get_event_revision(revision_id)
            if revision is None:
                raise RemediationRuntimeError(
                    "Remediation event evidence disappeared before completion."
                )
            source = by_pair.get((revision.repository, revision.pr_number))
            if source is None:
                raise RemediationRuntimeError(
                    "Remediation event evidence escaped its exact source set."
                )
            grouped[source].append(revision_id)
        if any(not revision_ids for revision_ids in grouped.values()):
            raise RemediationRuntimeError(
                "Every remediation source requires exact event evidence."
            )
        return {
            source: tuple(sorted(revision_ids))
            for source, revision_ids in grouped.items()
        }

    def _record_remote_observation(
        self,
        *,
        draft_key: str,
        draft: RemediationDraftResult,
        observed_at: datetime,
        require_live_lease: Callable[[], None],
    ) -> None:
        if draft.base_sha is None:
            raise RemediationRemoteConflictError(
                "Exact remediation pull request omitted its base SHA."
            )
        require_live_lease()
        self.state.record_remediation_remote_observation(
            draft_key=draft_key,
            observation="exact",
            state=draft.state,
            is_draft=draft.draft,
            is_merged=draft.merged,
            pr_number=draft.number,
            pr_url=draft.html_url,
            observed_base_sha=draft.base_sha,
            observed_head_sha=draft.candidate_sha,
            closed_at=draft.closed_at,
            merged_at=draft.merged_at,
            observed_at=observed_at,
        )

    def _find_draft(
        self,
        *,
        broker: RemediationGitHubBroker,
        record: RemediationDraftRecord,
        observed_at: datetime,
        require_live_lease: Callable[[], None],
    ) -> RemediationDraftResult | None:
        require_live_lease()
        self._require_remaining()
        try:
            draft = broker.find_draft(
                branch=record.branch,
                expected_base_sha=record.target_base_sha,
                candidate_sha=self.state.remediation_candidate_tip(record.draft_key),
                marker_candidate_sha=record.candidate_sha,
                evidence_hash=record.evidence_hash,
                title=record.title,
                body=record.body,
            )
        except RemediationRemoteConflictError:
            require_live_lease()
            self.state.record_remediation_remote_observation(
                draft_key=record.draft_key,
                observation="conflict",
                observed_at=observed_at,
            )
            raise
        require_live_lease()
        if draft is None:
            self.state.record_remediation_remote_observation(
                draft_key=record.draft_key,
                observation="not_found",
                observed_at=observed_at,
            )
        return draft

    def _checkpoint_draft(
        self,
        *,
        draft_key: str,
        source_pulls: Sequence[HistoricalPullReference],
        event_revision_ids: Sequence[int],
        prior_draft_keys_by_source: Mapping[HistoricalPullReference, tuple[str, ...]],
        required_edit_hashes_by_source: Mapping[
            HistoricalPullReference, tuple[str, ...]
        ],
        created: bool,
        observed_at: datetime,
        require_live_lease: Callable[[], None],
        require_exact_sources_still_closed: Callable[
            [Sequence[HistoricalPullReference], Sequence[int]], None
        ],
    ) -> int:
        require_live_lease()
        require_exact_sources_still_closed(source_pulls, event_revision_ids)
        require_live_lease()
        before = {
            source: self.state.historical_pull_is_complete(
                repository=source.repository,
                repository_id=source.repository_id,
                pull_id=source.pull_id,
                pull_revision_digest=source.pull_revision_digest,
                policy_digest=source.policy_digest,
                authority_scope="remediation",
            )
            for source in source_pulls
        }
        coverage_by_source = {
            source: tuple(
                sorted(
                    {
                        *prior_draft_keys_by_source.get(source, ()),
                        draft_key,
                    }
                )
            )
            for source in source_pulls
        }
        semantic_dedupe = any(
            prior_draft_keys_by_source.get(source) for source in source_pulls
        )
        reason = (
            RemediationCoverageReason.DRAFT_SEMANTIC_DEDUPE
            if semantic_dedupe
            else (
                RemediationCoverageReason.DRAFT_PUBLISHED
                if created
                else RemediationCoverageReason.DRAFT_RECOVERED
            )
        )
        event_ids_by_source = (
            self._event_revision_ids_by_source(
                source_pulls=source_pulls,
                event_revision_ids=event_revision_ids,
                state=self.state,
            )
            if semantic_dedupe
            else None
        )
        require_live_lease()
        self.state.record_draft_backed_remediation_completions(
            coverage_by_source,
            reason,
            required_edit_hashes_by_source=required_edit_hashes_by_source,
            event_revision_ids_by_source=event_ids_by_source,
            checkpoint_draft_key=draft_key,
            occurred_at=observed_at,
        )
        return sum(
            not was_complete
            and self.state.historical_pull_is_complete(
                repository=source.repository,
                repository_id=source.repository_id,
                pull_id=source.pull_id,
                pull_revision_digest=source.pull_revision_digest,
                policy_digest=source.policy_digest,
                authority_scope="remediation",
            )
            for source, was_complete in before.items()
        )

    def _consume_slot(
        self,
        *,
        repository_identity: tuple[str, int],
        require_live_lease: Callable[[], None],
        consumed: list[bool],
    ) -> None:
        require_live_lease()
        if consumed[0]:
            return
        if self._publication_slots_used >= self.max_drafts:
            raise _PublicationCapacityError("Remediation publication cap is exhausted.")
        if repository_identity in self._publication_repositories_used:
            raise _PublicationCapacityError(
                "Remediation repository publication cap is exhausted."
            )
        self._publication_slots_used += 1
        self._publication_repositories_used.add(repository_identity)
        consumed[0] = True

    def publish(
        self,
        *,
        policy: RepositoryPolicy,
        base: RemediationBaseSnapshot,
        workspace: GuardianWorkspace,
        patch_result: PatchResult,
        replacements: Sequence[ProposedReplacement],
        source_pulls: Sequence[HistoricalPullReference],
        event_revision_ids: Sequence[int],
        feedback_urls: Sequence[str],
        run_id: str,
        observed_at: datetime,
        require_live_lease: Callable[[], None],
        require_current_base_unchanged: Callable[[], None],
        require_exact_sources_still_closed: Callable[
            [Sequence[HistoricalPullReference], Sequence[int]], None
        ],
        require_no_open_translation_overlap: Callable[
            [Sequence[str], OpenPullPathIdentity | None], None
        ],
        prior_draft_keys_by_source: Mapping[HistoricalPullReference, tuple[str, ...]],
        required_edit_hashes_by_source: Mapping[HistoricalPullReference, Sequence[str]],
    ) -> RemediationBatchOutcome:
        """Publish one batched, signed correction draft against an exact base."""

        repository_identity = (policy.base_repo, policy.base_repo_id)

        def publication_capacity_available() -> bool:
            """Check the bounded creation allowance without consuming a slot."""
            return bool(
                self._publication_slots_used < self.max_drafts
                and repository_identity not in self._publication_repositories_used
            )

        if not callable(require_live_lease):
            raise TypeError("require_live_lease must be callable")
        if not callable(require_current_base_unchanged):
            raise TypeError("require_current_base_unchanged must be callable")
        if not callable(require_exact_sources_still_closed):
            raise TypeError("require_exact_sources_still_closed must be callable")
        if not callable(require_no_open_translation_overlap):
            raise TypeError("require_no_open_translation_overlap must be callable")
        observed_at = _as_utc(observed_at)
        run_id = _safe_single_line(run_id, label="run_id", max_bytes=4096)
        self._validate_base(policy=policy, base=base, workspace=workspace)
        remediation = _remediation_policy(policy)
        pulls = _normalized_source_pulls(policy, source_pulls)
        if (
            not isinstance(prior_draft_keys_by_source, Mapping)
            or set(prior_draft_keys_by_source) != set(pulls)
            or any(
                not isinstance(keys, tuple)
                or len(set(keys)) != len(keys)
                or any(
                    not isinstance(key, str) or not _HASH_RE.fullmatch(key)
                    for key in keys
                )
                for keys in prior_draft_keys_by_source.values()
            )
        ):
            raise ValueError(
                "prior_draft_keys_by_source must map every exact source to "
                "unique draft keys"
            )
        prior_draft_keys = {
            source: tuple(sorted(prior_draft_keys_by_source[source]))
            for source in pulls
        }
        if not isinstance(required_edit_hashes_by_source, Mapping) or set(
            required_edit_hashes_by_source
        ) != set(pulls):
            raise ValueError(
                "required_edit_hashes_by_source must map every exact source"
            )
        required_edit_hashes = {
            source: tuple(sorted(required_edit_hashes_by_source[source]))
            for source in pulls
        }
        if any(
            not hashes
            or len(hashes) > 1000
            or len(set(hashes)) != len(hashes)
            or any(
                not isinstance(edit_hash, str) or not _HASH_RE.fullmatch(edit_hash)
                for edit_hash in hashes
            )
            for hashes in required_edit_hashes.values()
        ):
            raise ValueError(
                "required edit hashes must be bounded unique SHA-256 digests"
            )
        policy_digests = _source_policy_digests(pulls)
        revision_ids = _normalized_revision_ids(event_revision_ids)
        proposals = _normalized_replacements(patch_result, replacements)
        changed_paths = _normalized_changed_paths(patch_result.changed_files)
        urls = _normalized_feedback_urls(
            base=base,
            policy=policy,
            source_pulls=pulls,
            feedback_urls=feedback_urls,
        )
        evidence_hash = self.state.validate_current_historical_remediation_evidence(
            source_pulls=pulls,
            event_revision_ids=revision_ids,
            feedback_urls=urls,
            replacements=proposals,
        )
        if evidence_hash != _evidence_hash(pulls, urls):
            raise RemediationRuntimeError(
                "Durable remediation evidence hash did not match its exact batch."
            )
        require_live_lease()
        require_exact_sources_still_closed(pulls, revision_ids)
        require_live_lease()

        def require_current_evidence() -> None:
            """Reauthenticate current source evidence before publishing remediation."""
            current_hash = self.state.validate_current_historical_remediation_evidence(
                source_pulls=pulls,
                event_revision_ids=revision_ids,
                feedback_urls=urls,
                replacements=proposals,
            )
            if current_hash != evidence_hash:
                raise RemediationRuntimeError(
                    "Durable remediation evidence changed before publication."
                )

        edit_hashes = _edit_hashes(proposals)
        edit_target_hashes = _edit_target_hashes(proposals)
        batch_hash = _batch_hash(proposals)
        branch = _branch_name(
            prefix=remediation.push_branch_prefix,
            batch_hash=batch_hash,
            target_base_sha=base.revision.sha,
            evidence_hash=evidence_hash,
            branch_identity_version=2,
            policy_digests=policy_digests,
        )
        title, body = _draft_text(
            base=base,
            policy=policy,
            source_pulls=pulls,
            feedback_urls=urls,
            patch_result=patch_result,
            evidence_hash=evidence_hash,
            batch_hash=batch_hash,
        )
        coverage = self.state.remediation_edit_coverage(
            target_repository=policy.base_repo,
            target_repository_id=policy.base_repo_id,
            edit_target_hashes=edit_target_hashes,
        )
        if (
            coverage.repository_identity_conflict
            or coverage.incompatible_edit_hashes
            or coverage.conflicting_edit_hashes
            or coverage.unmapped_active_conflict
        ):
            return RemediationBatchOutcome(deferred=1)
        prior_attempts = self.state.active_remediation_drafts_for_identity(
            repository=policy.base_repo,
            repository_id=policy.base_repo_id,
            batch_hash=batch_hash,
        )
        if any(
            not self._record_matches_policy(record, policy)
            or record.edit_hashes != edit_hashes
            for record in prior_attempts
        ):
            return RemediationBatchOutcome(deferred=1)
        if not prior_attempts and (
            coverage.opened_edit_hashes or coverage.pending_edit_hashes
        ):
            return RemediationBatchOutcome(deferred=1)
        self._require_remaining()
        broker = self.broker_factory(policy)
        if prior_attempts:
            candidate_shas = {record.candidate_sha for record in prior_attempts}
            if len(candidate_shas) != 1:
                raise RemediationRuntimeError(
                    "Durable remediation attempts disagree on candidate identity."
                )
            prior = max(
                prior_attempts,
                key=lambda record: (
                    record.phase == "draft_opened",
                    record.occurred_at,
                ),
            )
            opened_attempts = tuple(
                record for record in prior_attempts if record.phase == "draft_opened"
            )
            if len(opened_attempts) > 1:
                raise RemediationRuntimeError(
                    "Multiple durable drafts cover the same remediation edits."
                )
            checkpoint_prior_keys = {
                source: tuple(
                    sorted(
                        {
                            *prior_draft_keys[source],
                            *(
                                (prior.draft_key,)
                                if source not in prior.source_pulls
                                else ()
                            ),
                        }
                    )
                )
                for source in pulls
            }
            if opened_attempts:
                prior = opened_attempts[0]
                try:
                    draft = self._find_draft(
                        broker=broker,
                        record=prior,
                        observed_at=observed_at,
                        require_live_lease=require_live_lease,
                    )
                except RemediationRemoteConflictError:
                    return RemediationBatchOutcome(deferred=1)
                if draft is None:
                    return RemediationBatchOutcome(deferred=1)
                self._record_remote_observation(
                    draft_key=prior.draft_key,
                    draft=draft,
                    observed_at=observed_at,
                    require_live_lease=require_live_lease,
                )
                require_live_lease()
                require_current_base_unchanged()
                require_live_lease()
                checkpoints = self._checkpoint_draft(
                    draft_key=prior.draft_key,
                    source_pulls=pulls,
                    event_revision_ids=revision_ids,
                    prior_draft_keys_by_source=checkpoint_prior_keys,
                    required_edit_hashes_by_source=required_edit_hashes,
                    created=False,
                    observed_at=observed_at,
                    require_live_lease=require_live_lease,
                    require_exact_sources_still_closed=(
                        require_exact_sources_still_closed
                    ),
                )
                return RemediationBatchOutcome(
                    drafts=(draft,),
                    checkpoints=checkpoints,
                )
            try:
                draft = self._find_draft(
                    broker=broker,
                    record=prior,
                    observed_at=observed_at,
                    require_live_lease=require_live_lease,
                )
            except RemediationRemoteConflictError:
                return RemediationBatchOutcome(deferred=1)
            if draft is None:
                require_live_lease()
                self._require_remaining()
                branch_sha = broker.branch_sha(prior.branch)
                require_live_lease()
                if branch_sha is None:
                    if not publication_capacity_available():
                        return RemediationBatchOutcome(deferred=1)
                    if any(
                        attempt.phase == "draft_opened" for attempt in prior_attempts
                    ):
                        raise RemediationRuntimeError(
                            "An opened remediation draft disappeared remotely."
                        )
                    for attempt in prior_attempts:
                        require_live_lease()
                        self.state.record_remediation_draft_event(
                            **self._record_metadata(attempt),
                            phase="abandoned",
                            occurred_at=observed_at,
                        )
                else:
                    if branch_sha != prior.candidate_sha:
                        raise RemediationRuntimeError(
                            "Remediation branch exists at an unexpected commit."
                        )
                    same_attempt = bool(
                        prior.branch
                        == _branch_name(
                            prefix=remediation.push_branch_prefix,
                            batch_hash=batch_hash,
                            target_base_sha=base.revision.sha,
                            evidence_hash=evidence_hash,
                            branch_identity_version=prior.branch_identity_version,
                            policy_digests=policy_digests,
                        )
                        and prior.target_base_sha == base.revision.sha
                        and prior.evidence_hash == evidence_hash
                        and prior.changed_paths == changed_paths
                        and _source_policy_digests(prior.source_pulls) == policy_digests
                        and prior.title == title
                        and prior.body == body
                    )
                    if not same_attempt:
                        if not publication_capacity_available():
                            return RemediationBatchOutcome(deferred=1)
                        for attempt in prior_attempts:
                            require_live_lease()
                            self.state.record_remediation_draft_event(
                                **self._record_metadata(attempt),
                                phase="abandoned",
                                occurred_at=observed_at,
                            )
                    else:
                        consumed = [False]

                        def before_recovered_create() -> None:
                            """Revalidate recovered candidate authority before creating its missing PR."""
                            require_live_lease()
                            require_no_open_translation_overlap(
                                changed_paths,
                                None,
                            )
                            require_live_lease()
                            require_current_base_unchanged()
                            require_live_lease()
                            require_current_evidence()
                            self._consume_slot(
                                repository_identity=repository_identity,
                                require_live_lease=require_live_lease,
                                consumed=consumed,
                            )
                            # Keep exact historical source authority last: the
                            # overlap scan is remote and may be slow enough for
                            # a source PR or trusted comment to change.
                            require_live_lease()
                            require_exact_sources_still_closed(
                                pulls,
                                revision_ids,
                            )

                        try:
                            require_live_lease()
                            self._require_remaining()
                            draft = broker.open_draft(
                                branch=prior.branch,
                                expected_base_sha=prior.target_base_sha,
                                candidate_sha=prior.candidate_sha,
                                evidence_hash=prior.evidence_hash,
                                title=prior.title,
                                body=prior.body,
                                before_create=before_recovered_create,
                                before_post=before_recovered_create,
                            )
                        except _PublicationCapacityError:
                            return RemediationBatchOutcome(deferred=1)
                        except RemediationRemoteConflictError:
                            require_live_lease()
                            self.state.record_remediation_remote_observation(
                                draft_key=prior.draft_key,
                                observation="conflict",
                                observed_at=observed_at,
                            )
                            return RemediationBatchOutcome(deferred=1)
                        require_live_lease()
            if draft is not None:
                prior_ledger = self._record_metadata(prior)
                if prior.phase == "validated":
                    require_live_lease()
                    self.state.record_remediation_draft_event(
                        **prior_ledger,
                        phase="pushed",
                        occurred_at=observed_at,
                    )
                require_live_lease()
                self.state.record_remediation_draft_event(
                    **prior_ledger,
                    phase="draft_opened",
                    draft_number=draft.number,
                    draft_pull_id=draft.pull_id,
                    draft_url=draft.html_url,
                    occurred_at=observed_at,
                )
                self._record_remote_observation(
                    draft_key=prior.draft_key,
                    draft=draft,
                    observed_at=observed_at,
                    require_live_lease=require_live_lease,
                )
                require_live_lease()
                require_current_base_unchanged()
                require_live_lease()
                checkpoints = self._checkpoint_draft(
                    draft_key=prior.draft_key,
                    source_pulls=pulls,
                    event_revision_ids=revision_ids,
                    prior_draft_keys_by_source=checkpoint_prior_keys,
                    required_edit_hashes_by_source=required_edit_hashes,
                    created=draft.created,
                    observed_at=observed_at,
                    require_live_lease=require_live_lease,
                    require_exact_sources_still_closed=(
                        require_exact_sources_still_closed
                    ),
                )
                return RemediationBatchOutcome(
                    drafts=(draft,),
                    checkpoints=checkpoints,
                )
        if not publication_capacity_available():
            return RemediationBatchOutcome(deferred=1)
        self._require_remaining()
        commit = workspace.commit_historical_remediation_changes(
            author_email=broker.publication_author_email(),
            expected_paths=tuple(sorted(patch_result.changed_files)),
            feedback_repository=policy.base_repo,
            feedback_pull_numbers=tuple(item.pr_number for item in pulls),
            feedback_urls=urls,
            evidence_hash=evidence_hash,
            signing_key=self.signing_key,
            signing_environment=self.signing_environment,
        )
        if (
            not isinstance(commit, CommitResult)
            or commit.parent_sha != base.revision.sha
            or tuple(sorted(commit.changed_paths))
            != tuple(sorted(patch_result.changed_files))
            or not commit.signature_verified
        ):
            raise RemediationRuntimeError(
                "Signed remediation commit does not match the validated batch."
            )
        ledger: dict[str, object] = {
            "branch_identity_version": 2,
            "run_id": run_id,
            "target_repository": policy.base_repo,
            "target_repository_id": policy.base_repo_id,
            "target_base_branch": policy.base_branch,
            "target_base_sha": base.revision.sha,
            "push_repository": remediation.push_repository.full_name,
            "push_repository_id": remediation.push_repository.id,
            "branch": branch,
            "candidate_sha": commit.commit_sha,
            "evidence_hash": evidence_hash,
            "batch_hash": batch_hash,
            "edit_hashes": edit_hashes,
            "edit_target_hashes": edit_target_hashes,
            "source_pulls": pulls,
            "event_revision_ids": revision_ids,
            "changed_paths": changed_paths,
            "title": title,
            "body": body,
        }
        require_live_lease()
        draft_key = self.state.record_remediation_draft_event(
            **ledger,
            phase="validated",
            occurred_at=observed_at,
        )
        require_live_lease()
        self._require_remaining()
        broker.verify_publish_authority(
            expected_base_sha=base.revision.sha,
            branch=branch,
            candidate_sha=commit.commit_sha,
        )
        require_live_lease()
        consumed = [False]

        def consume_slot() -> None:
            """Consume capacity once before a remote operation that may succeed."""
            self._consume_slot(
                repository_identity=repository_identity,
                require_live_lease=require_live_lease,
                consumed=consumed,
            )

        def before_push() -> None:
            """Revalidate publication capacity and exact authority at the push boundary."""
            require_live_lease()
            require_no_open_translation_overlap(changed_paths, None)
            require_live_lease()
            require_current_base_unchanged()
            require_live_lease()
            self._require_remaining()
            broker.verify_publish_authority(
                expected_base_sha=base.revision.sha,
                branch=branch,
                candidate_sha=commit.commit_sha,
            )
            require_live_lease()
            require_current_evidence()
            consume_slot()
            # The remote overlap traversal is deliberately first. Revalidate
            # the immutable source evidence last before the branch CAS write.
            require_live_lease()
            require_exact_sources_still_closed(pulls, revision_ids)

        def before_create() -> None:
            """Recheck source and publication authority immediately before PR creation."""
            require_live_lease()
            require_no_open_translation_overlap(changed_paths, None)
            require_live_lease()
            require_current_base_unchanged()
            require_live_lease()
            require_current_evidence()
            consume_slot()
            # This callback is also passed as ``before_post``. Its final remote
            # source check therefore follows the slow overlap traversal at both
            # PR creation boundaries.
            require_live_lease()
            require_exact_sources_still_closed(pulls, revision_ids)

        try:
            self._require_remaining()
            publication: PreventionPublicationResult = (
                workspace.publish_remediation_branch(
                    commit,
                    push_repository=remediation.push_repository.full_name,
                    branch=branch,
                    branch_prefix=remediation.push_branch_prefix,
                    credential_environment=self.publish_credential_environment,
                    before_push=before_push,
                    signing_key=self.signing_key,
                    signing_environment=self.signing_environment,
                )
            )
        except _PublicationCapacityError:
            return RemediationBatchOutcome(deferred=1)
        except RemediationRemoteConflictError:
            require_live_lease()
            self.state.record_remediation_remote_observation(
                draft_key=draft_key,
                observation="conflict",
                observed_at=observed_at,
            )
            return RemediationBatchOutcome(deferred=1)
        if (
            publication.repository != remediation.push_repository.full_name
            or publication.ref != f"refs/heads/{branch}"
            or publication.commit_sha != commit.commit_sha
        ):
            raise RemediationRuntimeError(
                "Remediation branch publication returned an unexpected identity."
            )
        require_live_lease()
        self.state.record_remediation_draft_event(
            **ledger,
            phase="pushed",
            occurred_at=observed_at,
        )
        try:
            require_live_lease()
            self._require_remaining()
            draft = broker.open_draft(
                branch=branch,
                expected_base_sha=base.revision.sha,
                candidate_sha=commit.commit_sha,
                evidence_hash=evidence_hash,
                title=title,
                body=body,
                before_create=before_create,
                before_post=before_create,
            )
        except _PublicationCapacityError:
            return RemediationBatchOutcome(deferred=1)
        require_live_lease()
        self.state.record_remediation_draft_event(
            **ledger,
            phase="draft_opened",
            draft_number=draft.number,
            draft_pull_id=draft.pull_id,
            draft_url=draft.html_url,
            occurred_at=observed_at,
        )
        self._record_remote_observation(
            draft_key=draft_key,
            draft=draft,
            observed_at=observed_at,
            require_live_lease=require_live_lease,
        )
        require_live_lease()
        require_current_base_unchanged()
        require_live_lease()
        checkpoints = self._checkpoint_draft(
            draft_key=draft_key,
            source_pulls=pulls,
            event_revision_ids=revision_ids,
            prior_draft_keys_by_source=prior_draft_keys,
            required_edit_hashes_by_source=required_edit_hashes,
            created=draft.created,
            observed_at=observed_at,
            require_live_lease=require_live_lease,
            require_exact_sources_still_closed=(require_exact_sources_still_closed),
        )
        return RemediationBatchOutcome(
            drafts=(draft,),
            checkpoints=checkpoints,
        )

    def recover(
        self,
        *,
        policy: RepositoryPolicy,
        policy_digest: str,
        observed_at: datetime,
        require_live_lease: Callable[[], None],
        require_current_base_unchanged: Callable[[], None],
        require_exact_sources_still_closed: Callable[
            [Sequence[HistoricalPullReference], Sequence[int]], None
        ],
        require_no_open_translation_overlap: Callable[
            [Sequence[str], OpenPullPathIdentity | None], None
        ],
    ) -> RemediationBatchOutcome:
        """Reconcile exact remote drafts and enqueue incomplete source groups."""

        _remediation_policy(policy)
        if not isinstance(policy_digest, str) or not _HASH_RE.fullmatch(policy_digest):
            raise ValueError("policy_digest must be a SHA-256 digest")
        if not callable(require_live_lease):
            raise TypeError("require_live_lease must be callable")
        if not callable(require_current_base_unchanged):
            raise TypeError("require_current_base_unchanged must be callable")
        if not callable(require_exact_sources_still_closed):
            raise TypeError("require_exact_sources_still_closed must be callable")
        if not callable(require_no_open_translation_overlap):
            raise TypeError("require_no_open_translation_overlap must be callable")
        observed_at = _as_utc(observed_at)
        require_live_lease()
        all_pending = self.state.pending_remediation_drafts_for_recovery(
            repository_id=policy.base_repo_id,
            limit=_MAX_PENDING_RECOVERIES_PER_REPOSITORY,
        )
        opened_records = self.state.opened_remediation_drafts_for_reconciliation(
            repository_id=policy.base_repo_id,
            limit=_MAX_PENDING_RECOVERIES_PER_REPOSITORY,
        )
        merged_revalidations = self.state.pending_merged_remediation_revalidations(
            repository_id=policy.base_repo_id,
            limit=_MAX_PENDING_RECOVERIES_PER_REPOSITORY,
        )
        if not all_pending and not opened_records and not merged_revalidations:
            return RemediationBatchOutcome()

        backfill = policy.closed_pr_backfill
        assert backfill is not None
        retry_limit = min(
            backfill.max_prs_per_poll,
            _MAX_RETRY_SOURCE_PULLS,
        )
        retry_batch: tuple[HistoricalPullReference, ...] | None = None
        deferred = 0
        abandoned = 0
        drafts: list[RemediationDraftResult] = []

        def select_retry_batch(record: RemediationDraftRecord) -> bool:
            nonlocal retry_batch
            batch = tuple(record.source_pulls)
            if retry_batch is not None:
                return retry_batch == batch
            if not batch or len(batch) > retry_limit:
                return False
            retry_batch = batch
            return True

        if merged_revalidations:
            first_draft_key = merged_revalidations[0].draft_key
            selected_revalidations = tuple(
                item
                for item in merged_revalidations
                if item.draft_key == first_draft_key
            )[:retry_limit]
            require_live_lease()
            require_current_base_unchanged()
            require_live_lease()
            unresolved_sources: list[HistoricalPullReference] = []
            for item in selected_revalidations:
                require_live_lease()
                self._require_remaining()
                self.state.record_merged_remediation_revalidation_attempt(
                    revalidation_key=item.revalidation_key,
                    occurred_at=observed_at,
                )
                try:
                    require_exact_sources_still_closed(
                        (item.source,),
                        item.event_revision_ids,
                    )
                except RemediationSourceAuthorityError:
                    require_live_lease()
                    self.state.resolve_merged_remediation_revalidation(
                        revalidation_key=item.revalidation_key,
                        outcome="no_longer_applicable",
                        occurred_at=observed_at,
                    )
                    deferred += 1
                else:
                    require_live_lease()
                    complete = self.state.historical_pull_is_complete(
                        repository=item.source.repository,
                        repository_id=item.source.repository_id,
                        pull_id=item.source.pull_id,
                        pull_revision_digest=item.source.pull_revision_digest,
                        policy_digest=item.source.policy_digest,
                        authority_scope="remediation",
                    )
                    if complete:
                        require_live_lease()
                        self.state.resolve_merged_remediation_revalidation(
                            revalidation_key=item.revalidation_key,
                            outcome="resolved",
                            occurred_at=observed_at,
                        )
                    else:
                        unresolved_sources.append(item.source)
            if unresolved_sources:
                retry_batch = tuple(unresolved_sources)
                deferred += len(unresolved_sources)

        self._require_remaining()
        broker = self.broker_factory(policy)

        def validate_ledger(record: RemediationDraftRecord) -> None:
            evidence_hash = self.state.validate_historical_remediation_evidence(
                source_pulls=record.source_pulls,
                event_revision_ids=record.event_revision_ids,
            )
            if evidence_hash != record.evidence_hash:
                raise RemediationRuntimeError(
                    "Recovered remediation evidence no longer matches its ledger."
                )

        records = tuple(
            sorted(
                (*opened_records, *all_pending),
                key=lambda record: (
                    {source.policy_digest for source in record.source_pulls}
                    != {policy_digest},
                    record.phase != "draft_opened",
                    record.occurred_at,
                    record.draft_key,
                ),
            )
        )
        for record in records:
            # Rotate every bounded row after it is examined, including records
            # made structurally incompatible by a later policy change.
            require_live_lease()
            self._require_remaining()
            self.state.record_remediation_recovery_attempt(
                draft_key=record.draft_key,
                occurred_at=observed_at,
            )
            if not self._record_matches_policy(record, policy):
                deferred += 1
                continue
            validate_ledger(record)
            try:
                draft = self._find_draft(
                    broker=broker,
                    record=record,
                    observed_at=observed_at,
                    require_live_lease=require_live_lease,
                )
            except RemediationRemoteConflictError:
                deferred += 1
                continue

            if draft is not None:
                ledger = self._record_metadata(record)
                if record.phase == "validated":
                    require_live_lease()
                    self.state.record_remediation_draft_event(
                        **ledger,
                        phase="pushed",
                        occurred_at=observed_at,
                    )
                if record.phase != "draft_opened":
                    require_live_lease()
                    self.state.record_remediation_draft_event(
                        **ledger,
                        phase="draft_opened",
                        draft_number=draft.number,
                        draft_pull_id=draft.pull_id,
                        draft_url=draft.html_url,
                        occurred_at=observed_at,
                    )
                    drafts.append(draft)
                self._record_remote_observation(
                    draft_key=record.draft_key,
                    draft=draft,
                    observed_at=observed_at,
                    require_live_lease=require_live_lease,
                )
                require_live_lease()
                require_current_base_unchanged()
                require_live_lease()
                try:
                    require_exact_sources_still_closed(
                        record.source_pulls,
                        record.event_revision_ids,
                    )
                except RemediationSourceAuthorityError:
                    deferred += 1
                    continue
                require_live_lease()

                all_complete = all(
                    self.state.historical_pull_is_complete(
                        repository=source.repository,
                        repository_id=source.repository_id,
                        pull_id=source.pull_id,
                        pull_revision_digest=source.pull_revision_digest,
                        policy_digest=source.policy_digest,
                        authority_scope="remediation",
                    )
                    for source in record.source_pulls
                )
                if draft.merged:
                    # Exact merge observation atomically queued every source;
                    # the next bounded pass performs current-base revalidation.
                    deferred += 1
                elif not all_complete:
                    select_retry_batch(record)
                    deferred += 1
                continue

            # There is no exact remote PR. A source or policy change makes a
            # branch-only attempt stale; abandoning only the local attempt is
            # safe because no human review artifact exists to preserve.
            source_changed = {
                source.policy_digest for source in record.source_pulls
            } != {policy_digest}
            if not source_changed:
                try:
                    current_hash = (
                        self.state.validate_current_historical_remediation_evidence(
                            source_pulls=record.source_pulls,
                            event_revision_ids=record.event_revision_ids,
                        )
                    )
                    source_changed = current_hash != record.evidence_hash
                    if not source_changed:
                        require_live_lease()
                        require_exact_sources_still_closed(
                            record.source_pulls,
                            record.event_revision_ids,
                        )
                        require_live_lease()
                except (ValueError, RemediationSourceAuthorityError):
                    source_changed = True
            if source_changed:
                require_live_lease()
                self.state.record_remediation_draft_event(
                    **self._record_metadata(record),
                    phase="abandoned",
                    occurred_at=observed_at,
                )
                abandoned += 1
            else:
                select_retry_batch(record)
                deferred += 1

        return RemediationBatchOutcome(
            drafts=tuple(drafts),
            deferred=deferred,
            abandoned=abandoned,
            checkpoints=0,
            retry_source_batches=(retry_batch,) if retry_batch is not None else (),
        )


__all__ = (
    "RemediationBatchOutcome",
    "RemediationBaseSnapshot",
    "RemediationCoordinator",
    "RemediationDraftResult",
    "RemediationGitHubBroker",
    "RemediationOpenPullAuthorityError",
    "RemediationRemoteConflictError",
    "RemediationRuntimeError",
    "RemediationSourceAuthorityError",
)
