"""SQLite-backed audit and event-revision state for the PR guardian."""

from __future__ import annotations

from contextlib import nullcontext
from dataclasses import dataclass, field as dataclass_field
from datetime import date, datetime, time, timedelta, timezone
from decimal import Decimal
from enum import Enum
import hashlib
from itertools import islice
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
from typing import Any, Callable, Mapping, Sequence
from uuid import UUID, uuid4

from localize.guardian.models import (
    FeedbackEvent,
    GuardianMode,
    HistoricalCheckScope,
    ProposedReplacement,
)
from localize.guardian.json_safety import loads_bounded_json
from localize.guardian.prevention import TestCommandResult, TestOutcome


_UTC = timezone.utc
_SCHEMA_VERSION = 10
_SUPPORTED_SCHEMA_VERSIONS = frozenset(range(_SCHEMA_VERSION + 1))
_TERMINAL_ACTION_STATUSES = frozenset({"completed", "skipped"})
_ACTION_STATUSES = _TERMINAL_ACTION_STATUSES | {"failed", "pending"}
_RUN_STATUSES = frozenset({"completed", "failed", "cancelled"})
_MAX_ASSESSMENT_RESULT_BYTES = 2 * 1024 * 1024
_MAX_HISTORICAL_DISCOVERY_PAGE = 2_147_483_647
# Keep this storage invariant aligned with the bounded GitHub history reader.
# The state layer enforces it independently so a future provider regression
# cannot persist a cycle that the next poll refuses to load.
_MAX_HISTORICAL_CYCLE_SEEN_PULLS = 10_000
_MAX_HISTORICAL_PULL_RETRIES = 10_000
_MAX_HISTORICAL_PULL_RETRY_RESOLUTIONS = 10_000
_MAX_REMEDIATION_EDIT_HASHES = 1000
_MAX_REMEDIATION_COVERAGE_ROWS = 10_000
_MAX_REMEDIATION_SOURCE_COVERAGE_GROUPS = 10_000
_MAX_REMEDIATION_SOURCE_COVERAGE_MEMBERS = 100
_MAX_REMEDIATION_REMOTE_OBSERVATIONS = 10_000
_MAX_REMEDIATION_MERGE_REVALIDATIONS = 10_000
_MAX_REMEDIATION_SOURCE_EVENT_REVISIONS = 500
_MAX_REMEDIATION_SOURCE_EVENT_REVISIONS_JSON_BYTES = 16 * 1024
_MAX_REMEDIATION_SUCCESSORS = 10_000
_MAX_REMEDIATION_SOURCE_PULLS = 100
_MAX_REMEDIATION_SOURCE_REVISIONS = 50_000
_MAX_REMEDIATION_SOURCE_JSON_BYTES = 2 * 1024 * 1024
_MAX_REMEDIATION_CHANGED_PATHS = 100
_MAX_REMEDIATION_PATH_BYTES = 4096
_MAX_REMEDIATION_PATHS_JSON_BYTES = 512 * 1024
_MAX_CURRENT_FEEDBACK_PER_PULL = 500
_MAX_CURRENT_FEEDBACK_PER_REPOSITORY = 10_000
_MAX_PENDING_EVENT_WORKSET = 500
_MAX_PENDING_PUBLICATION_WORKSET = 100
_MAX_PUBLICATION_COMPLETION_PLAN_BYTES = 512 * 1024
_PREVENTION_DRAFT_RUN_MODES = frozenset({GuardianMode.PROPOSE_PREVENTION})
_REMEDIATION_DRAFT_RUN_MODES = frozenset(
    {
        GuardianMode.APPLY_OWNED_TRANSLATIONS,
        GuardianMode.PROPOSE_PREVENTION,
    }
)
_PUBLICATION_REPLY_TERMINAL_REASONS = frozenset(
    {"remediation_closed_unmerged", "remediation_merged", "trusted_feedback_changed"}
)
_MAX_RUN_ID_BYTES = 128
_MAX_REPOSITORY_BYTES = 512
_MAX_PREVENTION_PATCH_PATHS = 100
_MAX_PREVENTION_PATH_BYTES = 4096
_MAX_PREVENTION_PATCH_JSON_BYTES = 512 * 1024
_MAX_PREVENTION_ATTESTATION_BYTES = 512 * 1024
_MAX_PREVENTION_TITLE_BYTES = 256
_MAX_LEGACY_PREVENTION_TITLE_BYTES = 120 * 4
_MAX_PREVENTION_BODY_BYTES = 60 * 1024
_MAX_PREVENTION_URL_BYTES = 4096
_MAX_PREVENTION_INVALID_DRAFT_KEY_BYTES = 4096
_MAX_PREVENTION_RECOVERY_ATTEMPTS = 10_000
_MAX_PREVENTION_CANDIDATE_HASHES = 100
_MAX_PREVENTION_SOURCE_PULLS = 100
_MAX_PREVENTION_SOURCE_REVISIONS = 50_000
_MAX_PREVENTION_SOURCE_JSON_BYTES = 2 * 1024 * 1024
_MAX_PREVENTION_INVALID_QUARANTINES = 10_000
_MAX_PREVENTION_LEGACY_POLICY_DEFERRALS = 16
_MAX_OPERATOR_LIST_ROWS = 100
_SQLITE_IN_QUERY_CHUNK = 500
_SQLITE_MAX_INTEGER = 9_223_372_036_854_775_807
_SQLITE_STATE_SUFFIXES = ("", "-wal", "-shm", "-journal")
_REPOSITORY_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_PREVENTION_BRANCH_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]*$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_LEGACY_UNATTESTED_AUTHORITY_DIGEST = "0" * 64
_COMMITTED_BUDGET_SQL = """
    SELECT
        (SELECT COALESCE(SUM(amount_microusd), 0) FROM costs
         WHERE incurred_at >= ? AND incurred_at < ?)
        +
        (SELECT COALESCE(SUM(amount_microusd), 0)
         FROM budget_reservations
         WHERE reserved_at >= ? AND reserved_at < ?
           AND status IN ('reserved', 'unknown')) AS committed
"""
_MODE_RESOLUTION_AUTHORITY: Mapping[GuardianMode, tuple[GuardianMode, ...]] = {
    GuardianMode.OBSERVE: tuple(GuardianMode),
    GuardianMode.PREPARE: (
        GuardianMode.PREPARE,
        GuardianMode.APPLY_OWNED_TRANSLATIONS,
        GuardianMode.PROPOSE_PREVENTION,
    ),
    GuardianMode.APPLY_OWNED_TRANSLATIONS: (
        GuardianMode.APPLY_OWNED_TRANSLATIONS,
        GuardianMode.PROPOSE_PREVENTION,
    ),
    GuardianMode.PROPOSE_PREVENTION: (GuardianMode.PROPOSE_PREVENTION,),
}


@dataclass(frozen=True)
class EventRevision:
    """Stored immutable identity plus its separately retained raw body."""

    revision_id: int
    repository: str
    pr_number: int
    kind: str
    event_id: str
    author: str
    author_id: int
    author_type: str
    locale: str
    body_hash: str
    revision_hash: str
    head_sha: str
    base_sha: str
    observed_at: datetime
    body: str | None
    updated_at: str | None
    path: str | None
    line: int | None
    html_url: str | None
    deleted: bool
    is_new: bool = False


@dataclass(frozen=True)
class RunRecord:
    """One guardian execution recorded for audit and budget attribution."""

    run_id: str
    repository: str
    locale: str
    mode: GuardianMode
    status: str
    started_at: datetime
    finished_at: datetime | None
    summary: str | None


@dataclass(frozen=True)
class HealthRecord:
    """One append-only component health observation."""

    health_id: int
    component: str
    status: str
    message: str
    details: Mapping[str, Any]
    checked_at: datetime


@dataclass(frozen=True)
class PublicationRecord:
    """Latest append-only phase for one exact Guardian commit publication."""

    publication_key: str
    run_id: str
    repository: str
    repository_id: int | None
    pr_number: int
    original_head_sha: str
    base_sha: str
    commit_sha: str
    publication_actor_id: int | None
    publication_actor_type: str | None
    event_revision_ids: tuple[int, ...]
    open_source: OpenPullAuthorityReference | None
    phase: str
    occurred_at: datetime


@dataclass(frozen=True)
class OpenPullAuthorityReference:
    """Exact open-pull authority needed to reauthenticate prevention work."""

    repository: str
    repository_id: int
    pull_id: int
    pr_number: int
    authority_digest: str
    head_sha: str
    base_sha: str
    feedback_digest: str | None = None

    def __post_init__(self) -> None:
        if (
            not isinstance(self.repository, str)
            or not _REPOSITORY_RE.fullmatch(self.repository)
            or any(component in {".", ".."} for component in self.repository.split("/"))
        ):
            raise ValueError("repository must use canonical owner/name form.")
        for field, value in (
            ("repository_id", self.repository_id),
            ("pull_id", self.pull_id),
            ("pr_number", self.pr_number),
        ):
            if (
                isinstance(value, bool)
                or not isinstance(value, int)
                or not 0 < value <= _SQLITE_MAX_INTEGER
            ):
                raise ValueError(f"{field} must be a positive integer.")
        if not isinstance(self.authority_digest, str) or not _SHA256_RE.fullmatch(
            self.authority_digest
        ):
            raise ValueError("authority_digest must be a SHA-256 digest.")
        if self.feedback_digest is not None and (
            not isinstance(self.feedback_digest, str)
            or not _SHA256_RE.fullmatch(self.feedback_digest)
        ):
            raise ValueError("feedback_digest must be a SHA-256 digest or None.")
        for field, value in (("head_sha", self.head_sha), ("base_sha", self.base_sha)):
            if not isinstance(value, str) or not re.fullmatch(
                r"(?:[0-9a-f]{40}|[0-9a-f]{64})",
                value,
            ):
                raise ValueError(f"{field} must be a full lowercase object ID.")


@dataclass(frozen=True)
class PreventionDraftRecord:
    """Latest append-only phase for one validated prevention candidate."""

    draft_key: str
    run_id: str
    source_repository: str
    source_repository_id: int
    target_repository: str
    target_repository_id: int
    target_base_branch: str
    target_base_sha: str
    push_repository: str
    push_repository_id: int
    branch: str
    candidate_sha: str
    evidence_hash: str
    source_policy_json: str
    source_policy_digest: str
    patch_paths: tuple[str, ...]
    patch_hash: str
    test_attestation_json: str
    test_attestation_digest: str
    open_source: OpenPullAuthorityReference | None
    source_pulls: tuple[HistoricalPullReference, ...]
    event_revision_ids: tuple[int, ...]
    title: str
    body: str
    phase: str
    draft_number: int | None
    draft_url: str | None
    occurred_at: datetime


@dataclass(frozen=True)
class LegacyPreventionDraftRecord:
    """A released-v1 candidate usable only for read-only PR reconciliation."""

    prevention_event_id: int
    draft_key: str
    run_id: str
    source_repository: str
    target_repository: str
    target_base_branch: str
    target_base_sha: str
    push_repository: str
    branch: str
    candidate_sha: str
    evidence_hash: str
    title: str
    body: str
    phase: str
    draft_number: int | None
    draft_url: str | None
    occurred_at: datetime


@dataclass(frozen=True)
class PreventionResolutionRecord:
    """One append-only terminal resolution for a prevention attempt."""

    resolution_id: int
    draft_key: str
    resolution: str
    occurred_at: datetime


class PreventionRecoveryAttemptDisposition(str, Enum):
    """Whether a durable recovery lookup may retry after this attempt."""

    RETRYABLE = "retryable"
    FINAL = "final"
    EXHAUSTED = "exhausted"


@dataclass(frozen=True)
class HistoricalPullReference:
    """Exact historical pull identity retained for remediation recovery."""

    repository: str
    repository_id: int
    pull_id: int
    pr_number: int
    pull_revision_digest: str
    authority_digest: str
    policy_digest: str
    head_sha: str
    base_sha: str

    def __post_init__(self) -> None:
        if (
            not isinstance(self.repository, str)
            or not _REPOSITORY_RE.fullmatch(self.repository)
            or any(component in {".", ".."} for component in self.repository.split("/"))
        ):
            raise ValueError("repository must use canonical owner/name form.")
        for field, value in (
            ("repository_id", self.repository_id),
            ("pull_id", self.pull_id),
            ("pr_number", self.pr_number),
        ):
            if (
                isinstance(value, bool)
                or not isinstance(value, int)
                or not 0 < value <= _SQLITE_MAX_INTEGER
            ):
                raise ValueError(f"{field} must be a positive integer.")
        if not isinstance(self.pull_revision_digest, str) or not _SHA256_RE.fullmatch(
            self.pull_revision_digest
        ):
            raise ValueError("pull_revision_digest must be a SHA-256 digest.")
        if not isinstance(self.authority_digest, str) or not _SHA256_RE.fullmatch(
            self.authority_digest
        ):
            raise ValueError("authority_digest must be a SHA-256 digest.")
        if not isinstance(self.policy_digest, str) or not _SHA256_RE.fullmatch(
            self.policy_digest
        ):
            raise ValueError("policy_digest must be a SHA-256 digest.")
        for field, value in (("head_sha", self.head_sha), ("base_sha", self.base_sha)):
            if not isinstance(value, str) or not re.fullmatch(
                r"(?:[0-9a-f]{40}|[0-9a-f]{64})",
                value,
            ):
                raise ValueError(f"{field} must be a full lowercase object ID.")


@dataclass(frozen=True)
class HistoricalDiscoveryCursor:
    """Latest durable position within one bounded closed-PR scan cycle."""

    cursor_id: int
    repository: str
    repository_id: int
    policy_digest: str
    cycle_id: str
    cycle_started_at: datetime
    next_page: int
    next_offset: int
    cycle_complete: bool
    recorded_at: datetime


@dataclass(frozen=True)
class HistoricalPullRetryRecord:
    """One latest unresolved historical hydration failure for operator review."""

    retry_event_id: int
    repository: str
    repository_id: int
    policy_digest: str
    pull_id: int
    pr_number: int
    failure_type: str
    occurred_at: datetime


@dataclass(frozen=True)
class RemediationDraftRecord:
    """Latest append-only phase for one exact historical correction draft."""

    draft_key: str
    branch_identity_version: int
    run_id: str
    target_repository: str
    target_repository_id: int
    target_base_branch: str
    target_base_sha: str
    push_repository: str
    push_repository_id: int
    branch: str
    candidate_sha: str
    evidence_hash: str
    batch_hash: str
    edit_hashes: tuple[str, ...]
    edit_target_hashes: tuple[tuple[str, str], ...]
    source_pulls: tuple[HistoricalPullReference, ...]
    event_revision_ids: tuple[int, ...]
    changed_paths: tuple[str, ...] | None
    title: str
    body: str
    phase: str
    draft_number: int | None
    draft_pull_id: int | None
    draft_url: str | None
    occurred_at: datetime

    def __post_init__(self) -> None:
        if self.changed_paths is not None:
            paths, _serialized = _validated_remediation_changed_paths(
                self.changed_paths
            )
            object.__setattr__(self, "changed_paths", paths)
        if self.draft_pull_id is not None and (
            isinstance(self.draft_pull_id, bool)
            or not isinstance(self.draft_pull_id, int)
            or self.draft_pull_id <= 0
        ):
            raise ValueError("draft_pull_id must be a positive integer.")
        if self.phase != "draft_opened" and self.draft_pull_id is not None:
            raise ValueError("Only an opened remediation draft may have a pull ID.")


@dataclass(frozen=True)
class RemediationEditCoverage:
    """Durable opened, pending, and structurally incompatible edit coverage."""

    opened_edit_hashes: frozenset[str]
    pending_edit_hashes: frozenset[str]
    incompatible_edit_hashes: frozenset[str]
    conflicting_edit_hashes: frozenset[str] = frozenset()
    opened_draft_keys_by_edit_hash: Mapping[str, tuple[str, ...]] = dataclass_field(
        default_factory=dict
    )
    repository_identity_conflict: bool = False
    unmapped_active_conflict: bool = False


class RemediationCoverageReason(str, Enum):
    """Auditable reasons that establish one exact remediation completion."""

    INDEPENDENT_NO_ACTION = "independent_no_action"
    INDEPENDENT_POLICY_REJECTED = "independent_policy_rejected"
    INDEPENDENT_ALREADY_CURRENT = "independent_already_current"
    DRAFT_PUBLISHED = "draft_published"
    DRAFT_RECOVERED = "draft_recovered"
    DRAFT_SEMANTIC_DEDUPE = "draft_semantic_dedupe"
    OPERATOR_QUARANTINED = "operator_quarantined"
    MIGRATED_LEGACY = "migrated_legacy"


_INDEPENDENT_REMEDIATION_REASONS = frozenset(
    {
        RemediationCoverageReason.INDEPENDENT_NO_ACTION,
        RemediationCoverageReason.INDEPENDENT_POLICY_REJECTED,
        RemediationCoverageReason.INDEPENDENT_ALREADY_CURRENT,
    }
)
_DRAFT_BACKED_REMEDIATION_REASONS = frozenset(RemediationCoverageReason).difference(
    _INDEPENDENT_REMEDIATION_REASONS
)


@dataclass(frozen=True)
class RemediationSourceCoverageGroup:
    """One attested coverage generation for an exact remediation completion."""

    coverage_group_id: int
    completion_id: int
    source: HistoricalPullReference
    kind: str
    reason: RemediationCoverageReason
    draft_keys: tuple[str, ...]
    required_edit_hashes: tuple[str, ...]
    member_count: int
    canonical_hash: str
    occurred_at: datetime
    effective: bool


@dataclass(frozen=True)
class RemediationRemoteObservation:
    """One append-only observation of a correction PR's remote lifecycle."""

    observation_id: int
    draft_key: str
    observation: str
    state: str | None
    is_draft: bool | None
    is_merged: bool | None
    pr_number: int | None
    pr_url: str | None
    observed_base_sha: str | None
    observed_head_sha: str | None
    closed_at: str | None
    merged_at: str | None
    occurred_at: datetime


@dataclass(frozen=True)
class MergedRemediationRevalidation:
    """One durable source awaiting current-base review after a merge."""

    revalidation_key: str
    draft_key: str
    source: HistoricalPullReference
    event_revision_ids: tuple[int, ...]
    phase: str
    occurred_at: datetime


@dataclass(frozen=True)
class RemediationSuccessorPublication:
    """One signed, published linear successor of a remediation PR head."""

    lineage_key: str
    draft_key: str
    publication_key: str
    run_id: str
    parent_candidate_sha: str
    successor_candidate_sha: str
    source_pulls: tuple[HistoricalPullReference, ...]
    edit_hashes: tuple[str, ...]
    changed_paths: tuple[str, ...]
    actor_id: int
    actor_type: str
    publication_actor_id: int
    publication_actor_type: str
    occurred_at: datetime


@dataclass(frozen=True)
class RemediationSuccessorIntent:
    """Durable metadata needed to reconcile a pushed successor after restart."""

    intent_key: str
    draft_key: str
    publication_key: str
    run_id: str
    parent_candidate_sha: str
    successor_candidate_sha: str
    source_pulls: tuple[HistoricalPullReference, ...]
    edit_hashes: tuple[str, ...]
    changed_paths: tuple[str, ...]
    actor_id: int
    actor_type: str
    publication_actor_id: int
    publication_actor_type: str
    occurred_at: datetime


@dataclass(frozen=True)
class _RemediationSuccessorEntry:
    key: str
    draft_key: str
    publication_key: str
    run_id: str
    parent_candidate_sha: str
    successor_candidate_sha: str
    source_pulls: tuple[HistoricalPullReference, ...]
    edit_hashes: tuple[str, ...]
    changed_paths: tuple[str, ...]
    actor_id: int
    actor_type: str
    publication_actor_id: int
    publication_actor_type: str
    occurred_at: datetime


def _remediation_coverage_reason(
    reason: RemediationCoverageReason | str,
) -> RemediationCoverageReason:
    try:
        return RemediationCoverageReason(reason)
    except (TypeError, ValueError):
        raise ValueError("Unsupported remediation coverage reason.") from None


def _remediation_coverage_kind(reason: RemediationCoverageReason) -> str:
    return (
        "independent" if reason in _INDEPENDENT_REMEDIATION_REASONS else "draft_backed"
    )


def _remediation_coverage_hash(
    *,
    kind: str,
    reason: RemediationCoverageReason,
    draft_keys: Sequence[str],
    required_edit_hashes: Sequence[str],
    authority_digest: str,
) -> str:
    payload: dict[str, object] = {
        "authority_digest": authority_digest,
        "draft_keys": list(draft_keys),
        "kind": kind,
        "reason": reason.value,
    }
    if required_edit_hashes:
        payload["required_edit_hashes"] = list(required_edit_hashes)
    return hashlib.sha256(_canonical_json(payload).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class GuardianStateStatus:
    """Redacted aggregate state used by the operator status command."""

    last_completed_run: str | None
    pending_revisions: int
    actions: tuple[tuple[str, int], ...]
    health: tuple[tuple[str, str], ...]
    committed_microusd_today: int
    model_calls_today: int
    pending_historical_retries: int
    quarantined_historical_retries: int
    pending_preventions: int
    opened_preventions: int
    conflicted_preventions: int
    quarantined_preventions: int
    pending_remediations: int
    opened_remediations: int
    abandoned_remediations: int
    quarantined_remediations: int
    merged_remediations: int
    remote_exact_open_remediations: int
    remote_closed_unmerged_remediations: int
    remote_not_found_remediations: int
    remote_conflict_remediations: int
    last_successful_poll: str | None = None


def _now() -> datetime:
    """Return an aware UTC timestamp for audit operations."""
    return datetime.now(_UTC)


def _serialize_datetime(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("Guardian timestamps must be timezone-aware.")
    return (
        value.astimezone(_UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")
    )


def _parse_datetime(value: str | None) -> datetime | None:
    if value is None:
        return None
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _canonical_json(value: Mapping[str, Any] | None) -> str:
    return json.dumps(
        value or {}, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    )


def _validate_repository_id_filter(repository_id: int | None) -> None:
    """Require a normalized immutable repository identity when supplied."""

    if repository_id is not None and (
        isinstance(repository_id, bool)
        or not isinstance(repository_id, int)
        or not 0 < repository_id <= _SQLITE_MAX_INTEGER
    ):
        raise ValueError("repository_id must be a positive integer or None.")


def _canonical_attestation_json(value: object) -> str:
    return json.dumps(
        value,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    )


def _bounded_sequence(
    values: Sequence[Any],
    *,
    limit: int,
    label: str,
) -> tuple[Any, ...]:
    """Materialize no more than one item beyond a public workset bound."""

    try:
        items = tuple(islice(iter(values), limit + 1))
    except TypeError:
        raise ValueError(f"{label} must be a bounded sequence.") from None
    if len(items) > limit:
        raise ValueError(f"{label} exceed their bounded workset.")
    return items


def _normalized_publication_completion_actions(
    values: Sequence[tuple[int, str, Mapping[str, Any]]],
) -> tuple[tuple[int, str, str], ...]:
    """Validate and canonically serialize one bounded publication action plan."""

    raw_actions = _bounded_sequence(
        values,
        limit=_MAX_PENDING_EVENT_WORKSET,
        label="completion_actions",
    )
    normalized: list[tuple[int, str, str]] = []
    for item in raw_actions:
        if (
            not isinstance(item, (tuple, list))
            or len(item) != 3
            or isinstance(item[0], bool)
            or not isinstance(item[0], int)
            or not 0 < item[0] <= _SQLITE_MAX_INTEGER
            or not isinstance(item[1], str)
            or item[1] not in _TERMINAL_ACTION_STATUSES
            or not isinstance(item[2], Mapping)
        ):
            raise ValueError(
                "completion_actions must contain revision/status/detail triples."
            )
        normalized.append((item[0], item[1], _canonical_json(item[2])))
    revision_ids = tuple(item[0] for item in normalized)
    if not revision_ids or len(set(revision_ids)) != len(revision_ids):
        raise ValueError("completion_actions must contain unique positive revisions.")
    canonical = tuple(sorted(normalized, key=lambda item: item[0]))
    serialized = _canonical_attestation_json(
        [
            {
                "details": json.loads(details_json),
                "event_revision_id": revision_id,
                "status": status,
            }
            for revision_id, status, details_json in canonical
        ]
    )
    if len(serialized.encode("ascii")) > _MAX_PUBLICATION_COMPLETION_PLAN_BYTES:
        raise ValueError("completion_actions exceed their canonical byte bound.")
    return canonical


def _validated_remediation_changed_paths(
    values: Sequence[str],
) -> tuple[tuple[str, ...], str]:
    """Validate and canonically serialize exact remediation candidate paths."""

    paths = _bounded_sequence(
        values,
        limit=_MAX_REMEDIATION_CHANGED_PATHS,
        label="changed_paths",
    )
    if (
        not paths
        or any(
            not isinstance(path, str)
            or not path
            or len(path.encode("utf-8")) > _MAX_REMEDIATION_PATH_BYTES
            or path.startswith("/")
            or "\\" in path
            or any(part in {"", ".", ".."} for part in path.split("/"))
            or any(character in path for character in "\r\n\x00")
            for path in paths
        )
        or len(set(paths)) != len(paths)
    ):
        raise ValueError(
            "changed_paths must contain bounded unique safe repository paths."
        )
    normalized = tuple(sorted(paths))
    serialized = _canonical_attestation_json(list(normalized))
    if len(serialized.encode("ascii")) > _MAX_REMEDIATION_PATHS_JSON_BYTES:
        raise ValueError("changed_paths exceed their canonical byte bound.")
    return normalized, serialized


def _validated_revision_ids_json(value: object, *, label: str) -> tuple[int, ...]:
    """Parse one bounded, canonical list of durable SQLite revision IDs."""

    if (
        not isinstance(value, str)
        or not value
        or len(value.encode("utf-8")) > _MAX_PREVENTION_SOURCE_JSON_BYTES
        or "\x00" in value
    ):
        raise RuntimeError(f"{label} contains malformed evidence.")
    try:
        decoded = loads_bounded_json(value)
        canonical = _canonical_attestation_json(decoded)
    except (TypeError, ValueError, json.JSONDecodeError, RecursionError):
        raise RuntimeError(f"{label} contains malformed evidence.") from None
    if (
        not isinstance(decoded, list)
        or len(decoded) > _MAX_PREVENTION_SOURCE_REVISIONS
        or any(
            isinstance(revision_id, bool)
            or not isinstance(revision_id, int)
            or not 0 < revision_id <= _SQLITE_MAX_INTEGER
            for revision_id in decoded
        )
        or len(set(decoded)) != len(decoded)
        or decoded != sorted(decoded)
        or canonical != value
    ):
        raise RuntimeError(f"{label} contains malformed evidence.")
    return tuple(decoded)


def _merged_revalidation_revision_ids_json(values: Sequence[int]) -> str:
    """Return one bounded canonical exact-source revalidation attestation."""

    revision_ids = _bounded_sequence(
        values,
        limit=_MAX_REMEDIATION_SOURCE_EVENT_REVISIONS,
        label="merged remediation source revision IDs",
    )
    if (
        not revision_ids
        or len(set(revision_ids)) != len(revision_ids)
        or tuple(sorted(revision_ids)) != revision_ids
        or any(
            isinstance(revision_id, bool)
            or not isinstance(revision_id, int)
            or not 0 < revision_id <= _SQLITE_MAX_INTEGER
            for revision_id in revision_ids
        )
    ):
        raise ValueError(
            "Merged remediation source revision IDs must be a non-empty "
            "bounded sorted set of positive integers."
        )
    payload = _canonical_attestation_json(list(revision_ids))
    if (
        len(payload.encode("ascii"))
        > _MAX_REMEDIATION_SOURCE_EVENT_REVISIONS_JSON_BYTES
    ):
        raise ValueError(
            "Merged remediation source revision IDs exceed their byte bound."
        )
    return payload


def _validated_attestation_json(value: str, *, label: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value.encode("utf-8")) > _MAX_PREVENTION_ATTESTATION_BYTES
        or "\x00" in value
    ):
        raise ValueError(f"{label} must be a bounded canonical JSON document.")
    try:
        decoded = loads_bounded_json(value)
        canonical = _canonical_attestation_json(decoded)
    except (ValueError, RecursionError):
        raise ValueError(
            f"{label} must be a bounded canonical JSON document."
        ) from None
    if not isinstance(decoded, Mapping) or canonical != value:
        raise ValueError(f"{label} must be a bounded canonical JSON document.")
    return value


@dataclass(frozen=True)
class _PreventionPolicyAttestation:
    source_repository: tuple[str, int]
    target_repository: tuple[str, int]
    push_repository: tuple[str, int]
    target_base_branch: str
    push_branch_prefix: str
    focused_test_argv: tuple[tuple[str, ...], ...]


def _prevention_policy_from_json(value: str) -> _PreventionPolicyAttestation:
    """Extract immutable source, target, and push identities from an attestation."""

    try:
        raw = loads_bounded_json(value)
        repository_policy = raw["repository_policy"]
        prevention = repository_policy["prevention"]

        def exact_repository(raw_repository: object) -> tuple[str, int]:
            if not isinstance(raw_repository, Mapping):
                raise ValueError
            full_name = raw_repository["full_name"]
            repository_id = raw_repository["id"]
            if (
                not isinstance(full_name, str)
                or len(full_name.encode("utf-8")) > _MAX_REPOSITORY_BYTES
                or not _REPOSITORY_RE.fullmatch(full_name)
                or any(component in {".", ".."} for component in full_name.split("/"))
                or isinstance(repository_id, bool)
                or not isinstance(repository_id, int)
                or not 0 < repository_id <= _SQLITE_MAX_INTEGER
            ):
                raise ValueError
            return full_name, repository_id

        source = exact_repository(
            {
                "full_name": repository_policy["base_repo"],
                "id": repository_policy["base_repo_id"],
            }
        )
        target = exact_repository(prevention["target_repository"])
        push = exact_repository(prevention["push_repository"])
        target_base_branch = prevention["target_base_branch"]
        push_branch_prefix = prevention["push_branch_prefix"]
        raw_commands = prevention["focused_test_argv"]
        if (
            not isinstance(target_base_branch, str)
            or not target_base_branch
            or len(target_base_branch) > 255
            or not _PREVENTION_BRANCH_RE.fullmatch(target_base_branch)
            or not isinstance(push_branch_prefix, str)
            or not push_branch_prefix
            or len(push_branch_prefix) + 77 > 255
            or not _PREVENTION_BRANCH_RE.fullmatch(f"{push_branch_prefix}{'0' * 64}")
            or not isinstance(raw_commands, list)
            or not 1 <= len(raw_commands) <= 64
        ):
            raise ValueError
        focused_test_argv = tuple(
            tuple(command) if isinstance(command, list) else ()
            for command in raw_commands
        )
        if any(
            not 1 <= len(command) <= 256
            or any(
                not isinstance(argument, str)
                or not argument
                or len(argument.encode("utf-8")) > 4096
                or "\x00" in argument
                for argument in command
            )
            for command in focused_test_argv
        ):
            raise ValueError
    except (KeyError, TypeError, ValueError, json.JSONDecodeError, RecursionError):
        raise ValueError(
            "source_policy_json must bind exact repository identities."
        ) from None
    return _PreventionPolicyAttestation(
        source_repository=source,
        target_repository=target,
        push_repository=push,
        target_base_branch=target_base_branch,
        push_branch_prefix=push_branch_prefix,
        focused_test_argv=focused_test_argv,
    )


def _validate_prevention_test_attestation(
    value: str,
    *,
    policy: _PreventionPolicyAttestation,
    target_base_sha: str,
    candidate_sha: str,
) -> None:
    """Require exact base-fail/candidate-pass evidence for every configured argv."""

    try:
        raw = loads_bounded_json(value)
        if (
            not isinstance(raw, Mapping)
            or set(raw)
            != {
                "attestation_version",
                "configured_focused_test_argv",
                "results",
            }
            or raw["attestation_version"] != 1
            or not isinstance(raw["configured_focused_test_argv"], list)
            or tuple(
                tuple(command) if isinstance(command, list) else ()
                for command in raw["configured_focused_test_argv"]
            )
            != policy.focused_test_argv
            or not isinstance(raw["results"], list)
        ):
            raise ValueError
        results: list[TestCommandResult] = []
        for raw_result in raw["results"]:
            if not isinstance(raw_result, Mapping) or set(raw_result) != {
                "argv",
                "commit_sha",
                "focused",
                "outcome",
                "parent_sha",
                "phase",
                "returncode",
                "test_overlay_hash",
            }:
                raise ValueError
            results.append(
                TestCommandResult(
                    phase=raw_result["phase"],
                    outcome=TestOutcome(raw_result["outcome"]),
                    argv=(
                        tuple(raw_result["argv"])
                        if isinstance(raw_result["argv"], list)
                        else ()
                    ),
                    commit_sha=raw_result["commit_sha"],
                    parent_sha=raw_result["parent_sha"],
                    returncode=raw_result["returncode"],
                    test_overlay_hash=raw_result["test_overlay_hash"],
                    focused=raw_result["focused"],
                )
            )
        expected_pairs = {
            (phase, argv)
            for argv in policy.focused_test_argv
            for phase in ("base", "patched")
        }
        if (
            len(results) != len(expected_pairs)
            or {(result.phase, result.argv) for result in results} != expected_pairs
            or len({result.test_overlay_hash for result in results}) != 1
            or any(
                not result.focused
                or (
                    result.phase == "base"
                    and (
                        result.outcome is not TestOutcome.FAILED
                        or result.returncode != 1
                        or result.commit_sha != target_base_sha
                        or result.parent_sha is not None
                    )
                )
                or (
                    result.phase == "patched"
                    and (
                        result.outcome is not TestOutcome.PASSED
                        or result.commit_sha != candidate_sha
                        or result.parent_sha != target_base_sha
                    )
                )
                for result in results
            )
        ):
            raise ValueError
    except (KeyError, TypeError, ValueError, json.JSONDecodeError, RecursionError):
        raise ValueError(
            "test_attestation_json must bind exact regression evidence."
        ) from None


def _prevention_source_pulls_json(
    source_pulls: Sequence[HistoricalPullReference],
) -> str:
    return _canonical_attestation_json(
        [
            {
                "authority_digest": item.authority_digest,
                "base_sha": item.base_sha,
                "head_sha": item.head_sha,
                "policy_digest": item.policy_digest,
                "pr_number": item.pr_number,
                "pull_id": item.pull_id,
                "pull_revision_digest": item.pull_revision_digest,
                "repository": item.repository,
                "repository_id": item.repository_id,
            }
            for item in source_pulls
        ]
    )


def _open_pull_authority_json(
    source: OpenPullAuthorityReference | None,
) -> str:
    if source is None:
        return _canonical_attestation_json(None)
    payload: dict[str, object] = {
        "authority_digest": source.authority_digest,
        "base_sha": source.base_sha,
        "head_sha": source.head_sha,
        "pr_number": source.pr_number,
        "pull_id": source.pull_id,
        "repository": source.repository,
        "repository_id": source.repository_id,
    }
    if source.feedback_digest is not None:
        payload["feedback_digest"] = source.feedback_digest
    return _canonical_attestation_json(payload)


def _open_pull_authority_from_json(value: object) -> OpenPullAuthorityReference | None:
    if (
        not isinstance(value, str)
        or not value
        or len(value.encode("utf-8")) > _MAX_PREVENTION_ATTESTATION_BYTES
        or "\x00" in value
    ):
        raise ValueError("open_source_json must be bounded canonical JSON.")
    try:
        raw = loads_bounded_json(value)
        canonical = _canonical_attestation_json(raw)
    except (ValueError, RecursionError):
        raise ValueError("open_source_json must be bounded canonical JSON.") from None
    if canonical != value:
        raise ValueError("open_source_json must be bounded canonical JSON.")
    if raw is None:
        return None
    if not isinstance(raw, Mapping):
        raise ValueError("open_source_json must be bounded canonical JSON.")
    try:
        source = OpenPullAuthorityReference(
            repository=raw["repository"],
            repository_id=raw["repository_id"],
            pull_id=raw["pull_id"],
            pr_number=raw["pr_number"],
            authority_digest=raw["authority_digest"],
            head_sha=raw["head_sha"],
            base_sha=raw["base_sha"],
            feedback_digest=raw.get("feedback_digest"),
        )
    except (KeyError, TypeError, ValueError):
        raise ValueError("open_source_json must be bounded canonical JSON.") from None
    if _open_pull_authority_json(source) != value:
        raise ValueError("open_source_json must be bounded canonical JSON.")
    return source


def _historical_pull_reference_json(source: HistoricalPullReference) -> str:
    """Return one exact historical source as bounded canonical JSON."""

    if not isinstance(source, HistoricalPullReference):
        raise TypeError("source must be a HistoricalPullReference.")
    return _canonical_attestation_json(
        {
            "authority_digest": source.authority_digest,
            "base_sha": source.base_sha,
            "head_sha": source.head_sha,
            "policy_digest": source.policy_digest,
            "pr_number": source.pr_number,
            "pull_id": source.pull_id,
            "pull_revision_digest": source.pull_revision_digest,
            "repository": source.repository,
            "repository_id": source.repository_id,
        }
    )


def _historical_pull_reference_from_json(value: object) -> HistoricalPullReference:
    """Parse one exact historical source and reject non-canonical encodings."""

    if not isinstance(value, str) or not value or "\x00" in value:
        raise ValueError("source_json must be bounded canonical JSON.")
    try:
        raw = loads_bounded_json(value)
        canonical = _canonical_attestation_json(raw)
    except (ValueError, RecursionError):
        raise ValueError("source_json must be bounded canonical JSON.") from None
    if not isinstance(raw, Mapping) or canonical != value:
        raise ValueError("source_json must be bounded canonical JSON.")
    try:
        source = HistoricalPullReference(
            repository=raw["repository"],
            repository_id=raw["repository_id"],
            pull_id=raw["pull_id"],
            pr_number=raw["pr_number"],
            pull_revision_digest=raw["pull_revision_digest"],
            authority_digest=raw["authority_digest"],
            policy_digest=raw["policy_digest"],
            head_sha=raw["head_sha"],
            base_sha=raw["base_sha"],
        )
    except (KeyError, TypeError, ValueError):
        raise ValueError("source_json must be bounded canonical JSON.") from None
    if _historical_pull_reference_json(source) != value:
        raise ValueError("source_json must be bounded canonical JSON.")
    return source


def _validate_prevention_event_identity(
    *,
    source_repository: object,
    target_repository: object,
    target_base_branch: object,
    target_base_sha: object,
    push_repository: object,
    branch: object,
    candidate_sha: object,
    evidence_hash: object,
    title: object,
    body: object,
    phase: object,
    draft_number: object,
    draft_url: object,
    title_max_bytes: int = _MAX_PREVENTION_TITLE_BYTES,
) -> None:
    """Apply identical bounded identity checks on prevention writes and reads."""

    if phase not in {"validated", "pushed", "draft_opened", "abandoned"}:
        raise ValueError("Unsupported prevention draft phase.")
    if any(
        not isinstance(value, str)
        or len(value.encode("utf-8")) > _MAX_REPOSITORY_BYTES
        or not _REPOSITORY_RE.fullmatch(value)
        or any(component in {".", ".."} for component in value.split("/"))
        for value in (
            source_repository,
            target_repository,
            push_repository,
        )
    ):
        raise ValueError("Prevention repositories must use owner/name form.")
    if any(
        not isinstance(value, str)
        or not re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", value)
        for value in (target_base_sha, candidate_sha)
    ):
        raise ValueError("Prevention SHAs must be full lowercase object IDs.")
    if not isinstance(evidence_hash, str) or not _SHA256_RE.fullmatch(evidence_hash):
        raise ValueError("evidence_hash must be a SHA-256 digest.")
    for value, label in (
        (target_base_branch, "target_base_branch"),
        (branch, "branch"),
    ):
        if (
            not isinstance(value, str)
            or len(value) > 255
            or not _PREVENTION_BRANCH_RE.fullmatch(value)
            or "//" in value
            or ".." in value
            or "@{" in value
            or value.endswith(("/", "."))
            or any(
                part.startswith(".") or part.endswith(".lock")
                for part in value.split("/")
            )
        ):
            raise ValueError(f"{label} must be a safe Git branch name.")
    if (
        not isinstance(title, str)
        or not title
        or len(title.encode("utf-8")) > title_max_bytes
        or any(character in title for character in "\r\n\x00")
    ):
        raise ValueError("title must be a bounded safe non-empty value.")
    if (
        not isinstance(body, str)
        or not body
        or len(body.encode("utf-8")) > _MAX_PREVENTION_BODY_BYTES
        or "\x00" in body
    ):
        raise ValueError("body must be a bounded non-empty value without NUL.")
    if phase == "draft_opened":
        if (
            isinstance(draft_number, bool)
            or not isinstance(draft_number, int)
            or not 0 < draft_number <= _SQLITE_MAX_INTEGER
            or not isinstance(draft_url, str)
            or not draft_url
            or len(draft_url.encode("utf-8")) > _MAX_PREVENTION_URL_BYTES
            or any(character in draft_url for character in "\r\n\x00")
        ):
            raise ValueError("An opened prevention draft needs its number and URL.")
    elif draft_number is not None or draft_url is not None:
        raise ValueError("Only an opened prevention draft may store PR metadata.")


def _prevention_draft_key(
    *,
    run_id: str,
    source_repository: str,
    target_repository: str,
    target_base_branch: str,
    target_base_sha: str,
    push_repository: str,
    branch: str,
    candidate_sha: str,
    evidence_hash: str,
    source_policy_json: str,
    source_policy_digest: str,
    patch_paths_json: str,
    patch_hash: str,
    test_attestation_json: str,
    test_attestation_digest: str,
    open_source_json: str,
    source_pulls_json: str,
    event_revision_ids_json: str,
    title: str,
    body: str,
) -> str:
    payload = {
        "attestation_version": 3,
        "body": body,
        "branch": branch,
        "candidate_sha": candidate_sha,
        "event_revision_ids": loads_bounded_json(event_revision_ids_json),
        "evidence_hash": evidence_hash,
        "patch_hash": patch_hash,
        "patch_paths": loads_bounded_json(patch_paths_json),
        "push_repository": push_repository,
        "run_id": run_id,
        "source_policy": loads_bounded_json(source_policy_json),
        "source_policy_digest": source_policy_digest,
        "open_source": loads_bounded_json(open_source_json),
        "source_pulls": loads_bounded_json(source_pulls_json),
        "source_repository": source_repository,
        "target_base_branch": target_base_branch,
        "target_base_sha": target_base_sha,
        "target_repository": target_repository,
        "test_attestation": loads_bounded_json(test_attestation_json),
        "test_attestation_digest": test_attestation_digest,
        "title": title,
    }
    return hashlib.sha256(
        _canonical_attestation_json(payload).encode("ascii")
    ).hexdigest()


def _legacy_prevention_draft_key(
    *,
    source_repository: str,
    target_repository: str,
    target_base_branch: str,
    target_base_sha: str,
    candidate_sha: str,
    evidence_hash: str,
) -> str:
    """Recreate the exact key emitted by the released schema-v1 writer."""

    payload = (
        f"{source_repository}\n{target_repository}\n{target_base_branch}\n"
        f"{target_base_sha}\n{candidate_sha}\n{evidence_hash}"
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _body_hash(body: str) -> str:
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


def _historical_remediation_evidence_hash(
    source_pulls: Sequence[HistoricalPullReference],
    feedback_urls: Sequence[str],
) -> str:
    payload = {
        "feedback_urls": list(feedback_urls),
        "source_pulls": [
            {
                **(
                    {"authority_digest": item.authority_digest}
                    if item.authority_digest != _LEGACY_UNATTESTED_AUTHORITY_DIGEST
                    else {}
                ),
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
    return hashlib.sha256(_canonical_json(payload).encode("utf-8")).hexdigest()


def remediation_edit_hash(replacement: ProposedReplacement) -> str:
    """Return the policy- and evidence-independent identity of one exact edit."""

    if not isinstance(replacement, ProposedReplacement):
        raise TypeError("replacement must be a ProposedReplacement.")
    payload = {
        "expected_value": replacement.expected_value,
        "key": replacement.key,
        "path": replacement.path,
        "proposed_value": replacement.proposed_value,
        "source_value": replacement.source_value,
    }
    return hashlib.sha256(_canonical_json(payload).encode("utf-8")).hexdigest()


def remediation_target_hash(replacement: ProposedReplacement) -> str:
    """Return the value-independent identity of one localization target."""

    if not isinstance(replacement, ProposedReplacement):
        raise TypeError("replacement must be a ProposedReplacement.")
    payload = {
        "key": replacement.key,
        "path": replacement.path,
    }
    return hashlib.sha256(_canonical_json(payload).encode("utf-8")).hexdigest()


def remediation_batch_hash(edit_hashes: Sequence[str]) -> str:
    """Return the order-independent identity of one exact set of edits."""

    normalized = tuple(edit_hashes)
    if (
        not normalized
        or len(normalized) > _MAX_REMEDIATION_EDIT_HASHES
        or len(set(normalized)) != len(normalized)
        or any(
            not isinstance(edit_hash, str) or not _SHA256_RE.fullmatch(edit_hash)
            for edit_hash in normalized
        )
    ):
        raise ValueError("edit_hashes must contain bounded unique SHA-256 digests.")
    return hashlib.sha256(
        _canonical_json({"edit_hashes": sorted(normalized)}).encode("utf-8")
    ).hexdigest()


def _amount_to_microusd(amount_usd: Decimal | float | str) -> int:
    amount = Decimal(str(amount_usd))
    micros = amount * Decimal(1_000_000)
    if amount < 0 or not amount.is_finite() or micros != micros.to_integral_value():
        raise ValueError(
            "amount_usd must be finite, non-negative, and have at most 6 decimals."
        )
    return int(micros)


def feedback_revision_hash(event: FeedbackEvent) -> str:
    """Return the durable content identity for one feedback revision."""

    payload = json.dumps(
        {
            "author_id": event.author_id,
            "author_type": event.author_type,
            "body": event.body,
            "deleted": event.deleted,
            "html_url": event.html_url,
            "line": event.line,
            "locale": event.locale,
            "path": event.path,
            "updated_at": event.updated_at,
        },
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _revision_hash(event: FeedbackEvent) -> str:
    """Compatibility alias for the pre-public helper name."""

    return feedback_revision_hash(event)


def _legacy_revision_hash(event: FeedbackEvent) -> str:
    """Return the schema-v1 hash for safe duplicate compatibility."""

    payload = json.dumps(
        {
            "body": event.body,
            "deleted": event.deleted,
            "html_url": event.html_url,
            "line": event.line,
            "path": event.path,
            "updated_at": event.updated_at,
        },
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _validate_assessment_metadata(
    *,
    cache_key: str,
    repository: str,
    pr_number: int,
    head_sha: str,
    base_sha: str,
    model: str,
    reasoning_effort: str,
    result_json: str,
    input_tokens: int | None = None,
    output_tokens: int | None = None,
) -> None:
    """Validate the immutable assessment identity and serialized result."""

    if not re.fullmatch(r"[0-9a-f]{64}", cache_key):
        raise ValueError("assessment cache key must be a SHA-256 digest")
    token_counts_invalid = any(
        value is not None and value < 0 for value in (input_tokens, output_tokens)
    )
    if (
        not repository
        or pr_number <= 0
        or not re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", head_sha)
        or not re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", base_sha)
        or not model
        or not reasoning_effort
        or token_counts_invalid
        or len(result_json.encode("utf-8")) > _MAX_ASSESSMENT_RESULT_BYTES
    ):
        raise ValueError("assessment cache metadata is invalid")
    try:
        parsed_result = loads_bounded_json(result_json)
    except (TypeError, ValueError):
        raise ValueError("assessment cache result must be JSON") from None
    if not isinstance(parsed_result, Mapping):
        raise ValueError("assessment cache result must be a JSON object")


def _store_and_verify_assessment(
    connection: sqlite3.Connection,
    *,
    cache_key: str,
    repository: str,
    pr_number: int,
    head_sha: str,
    base_sha: str,
    model: str,
    reasoning_effort: str,
    result_json: str,
    timestamp: str,
) -> None:
    """Insert one idempotent assessment and reject cache-key collisions."""

    connection.execute(
        """
        INSERT OR IGNORE INTO assessment_results (
            cache_key, repository, pr_number, head_sha, base_sha,
            model, reasoning_effort, result_json, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            cache_key,
            repository,
            pr_number,
            head_sha,
            base_sha,
            model,
            reasoning_effort,
            result_json,
            timestamp,
        ),
    )
    cached = connection.execute(
        "SELECT * FROM assessment_results WHERE cache_key = ?",
        (cache_key,),
    ).fetchone()
    if cached is None or any(
        cached[field] != value
        for field, value in (
            ("repository", repository),
            ("pr_number", pr_number),
            ("head_sha", head_sha),
            ("base_sha", base_sha),
            ("model", model),
            ("reasoning_effort", reasoning_effort),
            ("result_json", result_json),
        )
    ):
        raise RuntimeError("assessment cache identity collision")


def _validate_sqlite_state_artifact(
    path: Path,
    *,
    description: str,
    required: bool,
) -> os.stat_result | None:
    """Validate one SQLite inode before the library may open or mutate it."""

    try:
        metadata = path.stat(follow_symlinks=False)
    except FileNotFoundError:
        if not required:
            return None
        raise ValueError(f"Guardian {description} is unavailable.") from None
    except OSError:
        raise ValueError(f"Guardian {description} is unavailable or unsafe.") from None
    if stat.S_ISLNK(metadata.st_mode):
        raise ValueError(f"Guardian {description} must not be a symlink.")
    if not stat.S_ISREG(metadata.st_mode):
        raise ValueError(f"Guardian {description} must be a regular file.")
    if metadata.st_nlink != 1:
        raise ValueError(f"Guardian {description} must not be hard-linked.")
    if hasattr(os, "getuid") and metadata.st_uid != os.getuid():
        raise ValueError(f"Guardian {description} must be owned by the current user.")
    if stat.S_IMODE(metadata.st_mode) != 0o600:
        raise ValueError(f"Guardian {description} must have mode 0600.")
    return metadata


def _validate_sqlite_state_artifacts(database_path: Path) -> None:
    """Reject unsafe main, WAL, shared-memory, or rollback-journal aliases."""

    for suffix in _SQLITE_STATE_SUFFIXES:
        _validate_sqlite_state_artifact(
            Path(f"{database_path}{suffix}"),
            description="state database" if not suffix else "state artifact",
            required=False,
        )


class GuardianState:
    """Own a SQLite connection and the guardian's durable audit state."""

    def __init__(self, database_path: str | Path) -> None:
        self.database_path = Path(database_path)
        parent = self.database_path.parent
        if parent.is_symlink():
            raise ValueError("Guardian state directory must not be a symlink.")
        if not parent.exists():
            parent.mkdir(parents=True, mode=0o700)
            parent.chmod(0o700)
        parent_metadata = parent.stat(follow_symlinks=False)
        if not stat.S_ISDIR(parent_metadata.st_mode):
            raise ValueError("Guardian state parent must be a directory.")
        if hasattr(os, "getuid") and parent_metadata.st_uid != os.getuid():
            raise ValueError(
                "Guardian state directory must be owned by the current user."
            )
        if stat.S_IMODE(parent_metadata.st_mode) != 0o700:
            raise ValueError("Guardian state directory must have mode 0700.")

        _validate_sqlite_state_artifacts(self.database_path)
        if (
            _validate_sqlite_state_artifact(
                self.database_path,
                description="state database",
                required=False,
            )
            is None
        ):
            flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            try:
                descriptor = os.open(self.database_path, flags, 0o600)
            except FileExistsError:
                # A direct concurrent caller may have completed the same
                # exclusive creation. Production callers are process-locked.
                descriptor = -1
            except OSError:
                raise ValueError(
                    "Guardian state database is unavailable or unsafe."
                ) from None
            try:
                if descriptor >= 0:
                    os.fchmod(descriptor, 0o600)
            except OSError:
                raise ValueError(
                    "Guardian state database is unavailable or unsafe."
                ) from None
            finally:
                if descriptor >= 0:
                    os.close(descriptor)
        _validate_sqlite_state_artifact(
            self.database_path,
            description="state database",
            required=True,
        )
        _validate_sqlite_state_artifacts(self.database_path)
        try:
            self._connection = sqlite3.connect(self.database_path, timeout=30.0)
            self._connection.row_factory = sqlite3.Row
            current_version = int(
                self._connection.execute("PRAGMA user_version").fetchone()[0]
            )
            if current_version not in _SUPPORTED_SCHEMA_VERSIONS:
                raise RuntimeError(
                    f"Unsupported guardian state schema version {current_version}."
                )
            self._connection.execute("PRAGMA foreign_keys = ON")
            self._connection.execute("PRAGMA journal_mode = WAL")
            _validate_sqlite_state_artifacts(self.database_path)
            self._initialize_schema(previous_version=current_version)
            _validate_sqlite_state_artifacts(self.database_path)
        except BaseException:
            connection = getattr(self, "_connection", None)
            if connection is not None:
                connection.close()
            raise

    def __enter__(self) -> GuardianState:
        return self

    def __exit__(self, *_exc_info: object) -> None:
        self.close()

    def close(self) -> None:
        """Release this audit database connection."""
        self._connection.close()

    def _initialize_schema(self, *, previous_version: int) -> None:
        """Upgrade and verify the audit schema without partial migration commits."""
        self._connection.executescript(
            """
            BEGIN IMMEDIATE;

            CREATE TABLE IF NOT EXISTS runs (
                run_id TEXT PRIMARY KEY,
                repository TEXT NOT NULL,
                locale TEXT NOT NULL,
                mode TEXT NOT NULL,
                status TEXT NOT NULL,
                started_at TEXT NOT NULL,
                finished_at TEXT,
                summary TEXT
            );

            CREATE TABLE IF NOT EXISTS event_revisions (
                revision_id INTEGER PRIMARY KEY AUTOINCREMENT,
                repository TEXT NOT NULL,
                pr_number INTEGER NOT NULL CHECK (pr_number > 0),
                kind TEXT NOT NULL,
                event_id TEXT NOT NULL,
                body_hash TEXT NOT NULL,
                revision_hash TEXT NOT NULL,
                head_sha TEXT NOT NULL,
                base_sha TEXT NOT NULL,
                author TEXT NOT NULL,
                author_id INTEGER NOT NULL CHECK (author_id > 0),
                author_type TEXT NOT NULL,
                locale TEXT NOT NULL,
                event_updated_at TEXT,
                path TEXT,
                line INTEGER,
                html_url TEXT,
                deleted INTEGER NOT NULL CHECK (deleted IN (0, 1)),
                observed_at TEXT NOT NULL,
                UNIQUE (
                    repository,
                    pr_number,
                    kind,
                    event_id,
                    revision_hash,
                    head_sha,
                    base_sha
                )
            );

            CREATE TABLE IF NOT EXISTS event_raw_bodies (
                event_revision_id INTEGER PRIMARY KEY,
                body TEXT NOT NULL,
                observed_at TEXT NOT NULL,
                FOREIGN KEY (event_revision_id)
                    REFERENCES event_revisions(revision_id)
            );

            CREATE TABLE IF NOT EXISTS event_current_observations (
                observation_id INTEGER PRIMARY KEY AUTOINCREMENT,
                repository TEXT NOT NULL,
                pr_number INTEGER NOT NULL CHECK (pr_number > 0),
                kind TEXT NOT NULL,
                event_id TEXT NOT NULL,
                event_revision_id INTEGER NOT NULL,
                observed_at TEXT NOT NULL,
                FOREIGN KEY (event_revision_id)
                    REFERENCES event_revisions(revision_id)
            );

            CREATE TABLE IF NOT EXISTS actions (
                action_id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id TEXT NOT NULL,
                event_revision_id INTEGER NOT NULL,
                action TEXT NOT NULL,
                status TEXT NOT NULL,
                details_json TEXT NOT NULL,
                occurred_at TEXT NOT NULL,
                FOREIGN KEY (run_id) REFERENCES runs(run_id),
                FOREIGN KEY (event_revision_id)
                    REFERENCES event_revisions(revision_id)
            );

            CREATE TABLE IF NOT EXISTS costs (
                cost_id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id TEXT NOT NULL,
                amount_microusd INTEGER NOT NULL CHECK (amount_microusd >= 0),
                model TEXT NOT NULL,
                input_tokens INTEGER NOT NULL CHECK (input_tokens >= 0),
                output_tokens INTEGER NOT NULL CHECK (output_tokens >= 0),
                incurred_at TEXT NOT NULL,
                FOREIGN KEY (run_id) REFERENCES runs(run_id)
            );

            CREATE TABLE IF NOT EXISTS budget_reservations (
                reservation_id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id TEXT NOT NULL,
                amount_microusd INTEGER NOT NULL CHECK (amount_microusd >= 0),
                model TEXT NOT NULL,
                status TEXT NOT NULL CHECK (status IN ('reserved', 'unknown', 'settled')),
                reserved_at TEXT NOT NULL,
                settled_at TEXT,
                FOREIGN KEY (run_id) REFERENCES runs(run_id)
            );

            CREATE TABLE IF NOT EXISTS model_call_reservations (
                call_id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id TEXT NOT NULL,
                model TEXT NOT NULL,
                purpose TEXT NOT NULL,
                status TEXT NOT NULL CHECK (
                    status IN ('reserved', 'completed', 'unknown', 'cancelled')
                ),
                reserved_at TEXT NOT NULL,
                finalized_at TEXT,
                FOREIGN KEY (run_id) REFERENCES runs(run_id)
            );

            CREATE TABLE IF NOT EXISTS assessment_results (
                cache_key TEXT PRIMARY KEY,
                repository TEXT NOT NULL,
                pr_number INTEGER NOT NULL CHECK (pr_number > 0),
                head_sha TEXT NOT NULL,
                base_sha TEXT NOT NULL,
                model TEXT NOT NULL,
                reasoning_effort TEXT NOT NULL,
                result_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS health (
                health_id INTEGER PRIMARY KEY AUTOINCREMENT,
                component TEXT NOT NULL,
                status TEXT NOT NULL,
                message TEXT NOT NULL,
                details_json TEXT NOT NULL,
                checked_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS publication_events (
                publication_event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                publication_key TEXT NOT NULL,
                run_id TEXT NOT NULL,
                repository TEXT NOT NULL,
                repository_id INTEGER CHECK (repository_id > 0),
                pr_number INTEGER NOT NULL CHECK (pr_number > 0),
                original_head_sha TEXT NOT NULL,
                base_sha TEXT NOT NULL,
                commit_sha TEXT NOT NULL,
                publication_actor_id INTEGER NOT NULL CHECK (
                    publication_actor_id > 0
                ),
                publication_actor_type TEXT NOT NULL CHECK (
                    publication_actor_type IN ('User', 'Bot')
                ),
                event_revision_ids_json TEXT NOT NULL,
                open_source_json TEXT,
                phase TEXT NOT NULL CHECK (
                    phase IN ('prepared', 'published', 'replied', 'abandoned')
                ),
                occurred_at TEXT NOT NULL,
                UNIQUE (publication_key, phase),
                FOREIGN KEY (run_id) REFERENCES runs(run_id)
            );

            CREATE TABLE IF NOT EXISTS publication_completion_plan_items (
                publication_key TEXT NOT NULL,
                plan_index INTEGER NOT NULL CHECK (
                    plan_index >= 0 AND plan_index < 500
                ),
                run_id TEXT NOT NULL,
                publication_actor_id INTEGER NOT NULL CHECK (
                    publication_actor_id > 0
                ),
                publication_actor_type TEXT NOT NULL CHECK (
                    publication_actor_type IN ('User', 'Bot')
                ),
                event_revision_id INTEGER NOT NULL,
                action TEXT NOT NULL,
                status TEXT NOT NULL CHECK (status IN ('completed', 'skipped')),
                details_json TEXT NOT NULL,
                occurred_at TEXT NOT NULL,
                PRIMARY KEY (publication_key, event_revision_id),
                UNIQUE (publication_key, plan_index),
                FOREIGN KEY (run_id) REFERENCES runs(run_id),
                FOREIGN KEY (event_revision_id)
                    REFERENCES event_revisions(revision_id)
            );

            CREATE TABLE IF NOT EXISTS prevention_draft_events (
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
                draft_pull_id INTEGER CHECK (draft_pull_id > 0),
                draft_url TEXT,
                occurred_at TEXT NOT NULL,
                UNIQUE (draft_key, phase),
                FOREIGN KEY (run_id) REFERENCES runs(run_id)
            );

            CREATE TABLE IF NOT EXISTS prevention_candidate_attestations (
                draft_key TEXT PRIMARY KEY,
                attestation_version INTEGER NOT NULL CHECK (
                    attestation_version = 3
                ),
                source_repository_id INTEGER NOT NULL CHECK (
                    source_repository_id > 0
                ),
                target_repository_id INTEGER NOT NULL CHECK (
                    target_repository_id > 0
                ),
                push_repository_id INTEGER NOT NULL CHECK (
                    push_repository_id > 0
                ),
                source_policy_json TEXT NOT NULL,
                source_policy_digest TEXT NOT NULL,
                patch_paths_json TEXT NOT NULL,
                patch_hash TEXT NOT NULL,
                test_attestation_json TEXT NOT NULL,
                test_attestation_digest TEXT NOT NULL,
                open_source_json TEXT NOT NULL,
                source_pulls_json TEXT NOT NULL,
                event_revision_ids_json TEXT NOT NULL,
                occurred_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS prevention_recovery_attempt_events (
                recovery_attempt_id INTEGER PRIMARY KEY AUTOINCREMENT,
                draft_key TEXT NOT NULL,
                occurred_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS prevention_resolution_events (
                resolution_id INTEGER PRIMARY KEY AUTOINCREMENT,
                draft_key TEXT NOT NULL UNIQUE,
                resolution TEXT NOT NULL CHECK (
                    resolution IN (
                        'base_moved',
                        'branch_missing',
                        'branch_modified',
                        'invalid_record',
                        'policy_changed',
                        'recovery_exhausted',
                        'remote_conflict',
                        'source_authority_changed',
                        'operator_quarantined'
                    )
                ),
                occurred_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS prevention_invalid_record_quarantines (
                quarantine_id INTEGER PRIMARY KEY AUTOINCREMENT,
                prevention_event_id INTEGER NOT NULL UNIQUE,
                draft_key_digest TEXT NOT NULL CHECK (
                    length(draft_key_digest) = 64
                ),
                occurred_at TEXT NOT NULL,
                FOREIGN KEY (prevention_event_id)
                    REFERENCES prevention_draft_events(prevention_event_id)
            );

            CREATE TABLE IF NOT EXISTS prevention_legacy_reconciliations (
                legacy_event_id INTEGER PRIMARY KEY,
                draft_key TEXT NOT NULL,
                source_repository_id INTEGER NOT NULL CHECK (
                    source_repository_id > 0
                ),
                target_repository_id INTEGER CHECK (
                    target_repository_id > 0
                ),
                push_repository_id INTEGER CHECK (
                    push_repository_id > 0
                ),
                source_policy_digest TEXT NOT NULL CHECK (
                    length(source_policy_digest) = 64
                ),
                evidence_hash TEXT NOT NULL CHECK (
                    length(evidence_hash) = 64
                ),
                disposition TEXT NOT NULL CHECK (
                    disposition IN (
                        'draft_opened',
                        'not_found',
                        'remote_conflict',
                        'policy_changed',
                        'recovery_exhausted'
                    )
                ),
                draft_number INTEGER,
                draft_url TEXT,
                occurred_at TEXT NOT NULL,
                FOREIGN KEY (legacy_event_id)
                    REFERENCES prevention_draft_events(prevention_event_id)
            );

            CREATE TABLE IF NOT EXISTS prevention_legacy_exact_drafts (
                legacy_event_id INTEGER PRIMARY KEY,
                draft_key TEXT NOT NULL,
                source_repository_id INTEGER NOT NULL CHECK (
                    source_repository_id > 0
                ),
                target_repository_id INTEGER NOT NULL CHECK (
                    target_repository_id > 0
                ),
                push_repository_id INTEGER NOT NULL CHECK (
                    push_repository_id > 0
                ),
                source_policy_digest TEXT NOT NULL CHECK (
                    length(source_policy_digest) = 64
                ),
                evidence_hash TEXT NOT NULL CHECK (
                    length(evidence_hash) = 64
                ),
                draft_number INTEGER NOT NULL CHECK (draft_number > 0),
                draft_url TEXT NOT NULL,
                occurred_at TEXT NOT NULL,
                FOREIGN KEY (legacy_event_id)
                    REFERENCES prevention_draft_events(prevention_event_id)
            );

            CREATE TABLE IF NOT EXISTS prevention_legacy_candidate_events (
                prevention_event_id INTEGER PRIMARY KEY,
                FOREIGN KEY (prevention_event_id)
                    REFERENCES prevention_draft_events(prevention_event_id)
            );

            CREATE TABLE IF NOT EXISTS prevention_legacy_invalid_resolutions (
                legacy_event_id INTEGER PRIMARY KEY,
                draft_key_digest TEXT NOT NULL CHECK (
                    length(draft_key_digest) = 64
                ),
                occurred_at TEXT NOT NULL,
                FOREIGN KEY (legacy_event_id)
                    REFERENCES prevention_draft_events(prevention_event_id)
            );

            CREATE TABLE IF NOT EXISTS prevention_legacy_policy_deferrals (
                legacy_event_id INTEGER NOT NULL,
                source_policy_digest TEXT NOT NULL CHECK (
                    length(source_policy_digest) = 64
                ),
                source_repository_id INTEGER NOT NULL CHECK (
                    source_repository_id > 0
                ),
                target_repository_id INTEGER CHECK (
                    target_repository_id > 0
                ),
                push_repository_id INTEGER CHECK (
                    push_repository_id > 0
                ),
                evidence_hash TEXT NOT NULL CHECK (
                    length(evidence_hash) = 64
                ),
                reason TEXT NOT NULL CHECK (
                    reason = 'policy_unavailable'
                ),
                occurred_at TEXT NOT NULL,
                PRIMARY KEY (legacy_event_id, source_policy_digest),
                FOREIGN KEY (legacy_event_id)
                    REFERENCES prevention_draft_events(prevention_event_id)
            );

            CREATE TABLE IF NOT EXISTS prevention_legacy_deferral_exhaustions (
                legacy_event_id INTEGER PRIMARY KEY,
                occurred_at TEXT NOT NULL,
                FOREIGN KEY (legacy_event_id)
                    REFERENCES prevention_draft_events(prevention_event_id)
            );

            CREATE TABLE IF NOT EXISTS historical_pull_completions (
                completion_id INTEGER PRIMARY KEY AUTOINCREMENT,
                repository TEXT NOT NULL,
                repository_id INTEGER NOT NULL CHECK (repository_id > 0),
                pull_id INTEGER NOT NULL CHECK (pull_id > 0),
                pr_number INTEGER NOT NULL CHECK (pr_number > 0),
                pull_revision_digest TEXT NOT NULL,
                policy_digest TEXT NOT NULL,
                authority_scope TEXT NOT NULL CHECK (
                    authority_scope IN (
                        'assessment', 'prevention', 'remediation'
                    )
                ),
                completed_at TEXT NOT NULL,
                head_sha TEXT NOT NULL,
                base_sha TEXT NOT NULL,
                event_revision_ids_json TEXT NOT NULL,
                ignored_event_revision_ids_json TEXT NOT NULL DEFAULT '[]',
                event_revision_watermark INTEGER NOT NULL DEFAULT 0 CHECK (
                    event_revision_watermark >= 0
                ),
                UNIQUE (
                    repository,
                    repository_id,
                    pull_id,
                    pull_revision_digest,
                    policy_digest,
                    authority_scope
                )
            );

            CREATE TABLE IF NOT EXISTS historical_pull_completion_observations (
                observation_id INTEGER PRIMARY KEY AUTOINCREMENT,
                repository TEXT NOT NULL,
                repository_id INTEGER NOT NULL CHECK (repository_id > 0),
                pull_id INTEGER NOT NULL CHECK (pull_id > 0),
                pr_number INTEGER NOT NULL CHECK (pr_number > 0),
                policy_digest TEXT NOT NULL,
                authority_scope TEXT NOT NULL CHECK (
                    authority_scope IN (
                        'assessment', 'prevention', 'remediation'
                    )
                ),
                completion_id INTEGER NOT NULL,
                observed_at TEXT NOT NULL,
                FOREIGN KEY (completion_id)
                    REFERENCES historical_pull_completions(completion_id)
            );

            CREATE TABLE IF NOT EXISTS historical_pull_identities (
                identity_id INTEGER PRIMARY KEY AUTOINCREMENT,
                repository TEXT NOT NULL,
                repository_id INTEGER NOT NULL CHECK (repository_id > 0),
                pull_id INTEGER NOT NULL CHECK (pull_id > 0),
                pr_number INTEGER NOT NULL CHECK (pr_number > 0),
                first_seen_at TEXT NOT NULL,
                UNIQUE (repository, repository_id, pull_id),
                UNIQUE (repository, repository_id, pr_number)
            );

            CREATE TABLE IF NOT EXISTS historical_discovery_cursor_events (
                cursor_id INTEGER PRIMARY KEY AUTOINCREMENT,
                repository TEXT NOT NULL,
                repository_id INTEGER NOT NULL CHECK (repository_id > 0),
                policy_digest TEXT NOT NULL,
                cycle_id TEXT NOT NULL,
                cycle_started_at TEXT NOT NULL,
                next_page INTEGER NOT NULL CHECK (
                    next_page > 0 AND next_page <= 2147483647
                ),
                next_offset INTEGER NOT NULL CHECK (
                    next_offset >= 0 AND next_offset < 100
                ),
                cycle_complete INTEGER NOT NULL CHECK (cycle_complete IN (0, 1)),
                previous_cursor_id INTEGER,
                recorded_at TEXT NOT NULL,
                FOREIGN KEY (previous_cursor_id)
                    REFERENCES historical_discovery_cursor_events(cursor_id)
            );

            CREATE TABLE IF NOT EXISTS historical_cycle_seen_pull_events (
                seen_event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                repository TEXT NOT NULL,
                repository_id INTEGER NOT NULL CHECK (repository_id > 0),
                policy_digest TEXT NOT NULL,
                cycle_id TEXT NOT NULL,
                pull_id INTEGER NOT NULL CHECK (pull_id > 0),
                pr_number INTEGER NOT NULL CHECK (pr_number > 0),
                seen_at TEXT NOT NULL,
                UNIQUE (
                    repository, repository_id, policy_digest, cycle_id, pull_id
                ),
                UNIQUE (
                    repository, repository_id, policy_digest, cycle_id, pr_number
                )
            );

            CREATE TABLE IF NOT EXISTS historical_pull_retry_events (
                retry_event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                repository TEXT NOT NULL,
                repository_id INTEGER NOT NULL CHECK (repository_id > 0),
                policy_digest TEXT NOT NULL,
                pull_id INTEGER NOT NULL CHECK (pull_id > 0),
                pr_number INTEGER NOT NULL CHECK (pr_number > 0),
                phase TEXT NOT NULL CHECK (phase IN ('pending', 'resolved')),
                failure_type TEXT,
                occurred_at TEXT NOT NULL,
                CHECK (
                    (phase = 'pending' AND failure_type IS NOT NULL)
                    OR (phase = 'resolved' AND failure_type IS NULL)
                )
            );

            CREATE TABLE IF NOT EXISTS historical_pull_retry_resolution_events (
                resolution_event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                repository TEXT NOT NULL,
                repository_id INTEGER NOT NULL CHECK (repository_id > 0),
                policy_digest TEXT NOT NULL,
                pull_id INTEGER NOT NULL CHECK (pull_id > 0),
                pr_number INTEGER NOT NULL CHECK (pr_number > 0),
                resolution TEXT NOT NULL CHECK (
                    resolution = 'operator_quarantined'
                ),
                occurred_at TEXT NOT NULL,
                UNIQUE (
                    repository, repository_id, policy_digest, pull_id, pr_number
                )
            );

            CREATE TABLE IF NOT EXISTS remediation_draft_events (
                remediation_event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                draft_key TEXT NOT NULL,
                branch_identity_version INTEGER NOT NULL DEFAULT 2 CHECK (
                    branch_identity_version IN (1, 2)
                ),
                run_id TEXT NOT NULL,
                target_repository TEXT NOT NULL,
                target_repository_id INTEGER NOT NULL CHECK (
                    target_repository_id > 0
                ),
                target_base_branch TEXT NOT NULL,
                target_base_sha TEXT NOT NULL,
                push_repository TEXT NOT NULL,
                push_repository_id INTEGER NOT NULL CHECK (
                    push_repository_id > 0
                ),
                branch TEXT NOT NULL,
                candidate_sha TEXT NOT NULL,
                evidence_hash TEXT NOT NULL,
                batch_hash TEXT NOT NULL,
                source_pulls_json TEXT NOT NULL,
                event_revision_ids_json TEXT NOT NULL,
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

            CREATE TABLE IF NOT EXISTS remediation_draft_edit_events (
                edit_event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                draft_key TEXT NOT NULL,
                edit_hash TEXT NOT NULL,
                target_hash TEXT,
                UNIQUE (draft_key, edit_hash)
            );

            CREATE TABLE IF NOT EXISTS remediation_draft_path_attestations (
                draft_key TEXT PRIMARY KEY,
                changed_paths_json TEXT NOT NULL CHECK (
                    length(CAST(changed_paths_json AS BLOB)) <= 524288
                    AND CASE
                        WHEN json_valid(changed_paths_json)
                        THEN json_type(changed_paths_json) = 'array'
                             AND json_array_length(changed_paths_json)
                                 BETWEEN 1 AND 100
                        ELSE 0
                    END
                )
            );

            CREATE TABLE IF NOT EXISTS remediation_checkpoint_events (
                checkpoint_event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                draft_key TEXT NOT NULL UNIQUE,
                occurred_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS remediation_recovery_attempt_events (
                recovery_attempt_id INTEGER PRIMARY KEY AUTOINCREMENT,
                draft_key TEXT NOT NULL,
                occurred_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS remediation_recovery_cursors (
                draft_key TEXT PRIMARY KEY,
                recovery_rank INTEGER NOT NULL CHECK (recovery_rank > 0),
                occurred_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS remediation_resolution_events (
                resolution_id INTEGER PRIMARY KEY AUTOINCREMENT,
                draft_key TEXT NOT NULL UNIQUE,
                resolution TEXT NOT NULL CHECK (
                    resolution IN ('merged', 'operator_quarantined')
                ),
                occurred_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS remediation_source_coverage_groups (
                coverage_group_id INTEGER PRIMARY KEY AUTOINCREMENT,
                completion_id INTEGER NOT NULL,
                authority_digest TEXT NOT NULL,
                kind TEXT NOT NULL CHECK (
                    kind IN ('independent', 'draft_backed')
                ),
                reason TEXT NOT NULL CHECK (
                    reason IN (
                        'independent_no_action',
                        'independent_policy_rejected',
                        'independent_already_current',
                        'draft_published',
                        'draft_recovered',
                        'draft_semantic_dedupe',
                        'operator_quarantined',
                        'migrated_legacy'
                    )
                ),
                canonical_hash TEXT NOT NULL,
                member_count INTEGER NOT NULL CHECK (
                    member_count >= 0 AND member_count <= 100
                ),
                occurred_at TEXT NOT NULL,
                UNIQUE (completion_id, canonical_hash),
                FOREIGN KEY (completion_id)
                    REFERENCES historical_pull_completions(completion_id)
            );

            CREATE TABLE IF NOT EXISTS remediation_source_coverage_members (
                coverage_member_id INTEGER PRIMARY KEY AUTOINCREMENT,
                coverage_group_id INTEGER NOT NULL,
                member_position INTEGER NOT NULL CHECK (
                    member_position >= 0 AND member_position < 100
                ),
                draft_key TEXT NOT NULL,
                UNIQUE (coverage_group_id, member_position),
                UNIQUE (coverage_group_id, draft_key),
                FOREIGN KEY (coverage_group_id)
                    REFERENCES remediation_source_coverage_groups(
                        coverage_group_id
                    )
            );

            CREATE TABLE IF NOT EXISTS remediation_source_required_edit_events (
                required_edit_event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                coverage_group_id INTEGER NOT NULL,
                member_position INTEGER NOT NULL CHECK (
                    member_position >= 0 AND member_position < 1000
                ),
                edit_hash TEXT NOT NULL,
                UNIQUE (coverage_group_id, member_position),
                UNIQUE (coverage_group_id, edit_hash),
                FOREIGN KEY (coverage_group_id)
                    REFERENCES remediation_source_coverage_groups(
                        coverage_group_id
                    )
            );

            CREATE TABLE IF NOT EXISTS remediation_remote_observation_events (
                observation_id INTEGER PRIMARY KEY AUTOINCREMENT,
                draft_key TEXT NOT NULL,
                observation TEXT NOT NULL CHECK (
                    observation IN ('exact', 'not_found', 'conflict')
                ),
                state TEXT CHECK (state IN ('open', 'closed')),
                is_draft INTEGER CHECK (is_draft IN (0, 1)),
                is_merged INTEGER CHECK (is_merged IN (0, 1)),
                pr_number INTEGER CHECK (pr_number > 0),
                pr_url TEXT,
                observed_base_sha TEXT,
                observed_head_sha TEXT,
                closed_at TEXT,
                merged_at TEXT,
                occurred_at TEXT NOT NULL,
                CHECK (
                    (
                        observation = 'exact'
                        AND state IS NOT NULL
                        AND is_draft IS NOT NULL
                        AND is_merged IS NOT NULL
                        AND pr_number IS NOT NULL
                        AND pr_url IS NOT NULL
                        AND observed_base_sha IS NOT NULL
                        AND observed_head_sha IS NOT NULL
                    )
                    OR (
                        observation = 'not_found'
                        AND state IS NULL
                        AND is_draft IS NULL
                        AND is_merged IS NULL
                        AND pr_number IS NULL
                        AND pr_url IS NULL
                        AND observed_base_sha IS NULL
                        AND observed_head_sha IS NULL
                        AND closed_at IS NULL
                        AND merged_at IS NULL
                    )
                    OR (
                        observation = 'conflict'
                        AND (
                            (
                                state IS NULL
                                AND is_draft IS NULL
                                AND is_merged IS NULL
                                AND pr_number IS NULL
                                AND pr_url IS NULL
                                AND observed_base_sha IS NULL
                                AND observed_head_sha IS NULL
                                AND closed_at IS NULL
                                AND merged_at IS NULL
                            )
                            OR (
                                state IS NOT NULL
                                AND is_draft IS NOT NULL
                                AND is_merged IS NOT NULL
                                AND pr_number IS NOT NULL
                                AND pr_url IS NOT NULL
                                AND observed_base_sha IS NOT NULL
                                AND observed_head_sha IS NOT NULL
                            )
                        )
                    )
                ),
                CHECK (
                    is_merged IS NULL
                    OR is_merged = 0
                    OR (state = 'closed' AND is_draft = 0)
                )
            );

            CREATE TABLE IF NOT EXISTS remediation_merge_revalidation_events (
                merge_revalidation_event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                revalidation_key TEXT NOT NULL,
                draft_key TEXT NOT NULL,
                source_json TEXT NOT NULL,
                event_revision_ids_json TEXT NOT NULL,
                phase TEXT NOT NULL CHECK (
                    phase IN (
                        'pending', 'attempted', 'resolved',
                        'no_longer_applicable'
                    )
                ),
                occurred_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS remediation_successor_publications (
                successor_id INTEGER PRIMARY KEY AUTOINCREMENT,
                lineage_key TEXT NOT NULL UNIQUE,
                draft_key TEXT NOT NULL,
                publication_key TEXT NOT NULL UNIQUE,
                run_id TEXT NOT NULL,
                parent_candidate_sha TEXT NOT NULL,
                successor_candidate_sha TEXT NOT NULL,
                source_pulls_json TEXT NOT NULL,
                edit_hashes_json TEXT NOT NULL,
                changed_paths_json TEXT,
                actor_id INTEGER NOT NULL CHECK (actor_id > 0),
                actor_type TEXT NOT NULL,
                publication_actor_id INTEGER,
                publication_actor_type TEXT,
                occurred_at TEXT NOT NULL,
                UNIQUE (draft_key, parent_candidate_sha),
                UNIQUE (draft_key, successor_candidate_sha),
                FOREIGN KEY (run_id) REFERENCES runs(run_id)
            );

            CREATE TABLE IF NOT EXISTS remediation_successor_intents (
                intent_id INTEGER PRIMARY KEY AUTOINCREMENT,
                intent_key TEXT NOT NULL UNIQUE,
                draft_key TEXT NOT NULL,
                publication_key TEXT NOT NULL UNIQUE,
                run_id TEXT NOT NULL,
                parent_candidate_sha TEXT NOT NULL,
                successor_candidate_sha TEXT NOT NULL,
                source_pulls_json TEXT NOT NULL,
                edit_hashes_json TEXT NOT NULL,
                changed_paths_json TEXT,
                actor_id INTEGER NOT NULL CHECK (actor_id > 0),
                actor_type TEXT NOT NULL,
                publication_actor_id INTEGER,
                publication_actor_type TEXT,
                occurred_at TEXT NOT NULL,
                UNIQUE (draft_key, successor_candidate_sha),
                FOREIGN KEY (run_id) REFERENCES runs(run_id)
            );

            CREATE TABLE IF NOT EXISTS publication_reply_terminal_events (
                publication_key TEXT PRIMARY KEY,
                reason TEXT NOT NULL CHECK (
                    reason IN (
                        'remediation_closed_unmerged',
                        'remediation_merged',
                        'trusted_feedback_changed'
                    )
                ),
                occurred_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS leases (
                name TEXT PRIMARY KEY,
                owner TEXT NOT NULL,
                acquired_at TEXT NOT NULL,
                expires_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS event_revisions_repo_pr
                ON event_revisions(repository, pr_number, revision_id);
            CREATE INDEX IF NOT EXISTS event_current_observations_latest
                ON event_current_observations(
                    repository, pr_number, kind, event_id, observation_id
                );
            CREATE INDEX IF NOT EXISTS historical_completion_observations_latest
                ON historical_pull_completion_observations(
                    repository, repository_id, pull_id, pr_number,
                    policy_digest, authority_scope, observation_id
                );
            CREATE INDEX IF NOT EXISTS actions_event_status
                ON actions(event_revision_id, status);
            CREATE INDEX IF NOT EXISTS costs_incurred_at
                ON costs(incurred_at);
            CREATE INDEX IF NOT EXISTS budget_reservations_reserved_at
                ON budget_reservations(reserved_at, status);
            CREATE INDEX IF NOT EXISTS model_call_reservations_reserved_at
                ON model_call_reservations(reserved_at, status);
            CREATE INDEX IF NOT EXISTS assessment_results_created_at
                ON assessment_results(created_at);
            CREATE INDEX IF NOT EXISTS health_component_checked
                ON health(component, checked_at DESC, health_id DESC);
            CREATE INDEX IF NOT EXISTS publication_events_pending
                ON publication_events(repository, pr_number, publication_key,
                                      publication_event_id DESC);
            CREATE INDEX IF NOT EXISTS publication_completion_plan_by_run
                ON publication_completion_plan_items(run_id, publication_key,
                                                     plan_index);
            CREATE INDEX IF NOT EXISTS prevention_draft_events_pending
                ON prevention_draft_events(source_repository, target_repository,
                                           draft_key, prevention_event_id DESC);
            CREATE INDEX IF NOT EXISTS prevention_draft_events_claimed_evidence
                ON prevention_draft_events(
                    source_repository, target_repository, evidence_hash
                );
            CREATE INDEX IF NOT EXISTS prevention_recovery_attempt_latest
                ON prevention_recovery_attempt_events(
                    draft_key, recovery_attempt_id DESC
                );
            CREATE INDEX IF NOT EXISTS prevention_resolution_by_reason
                ON prevention_resolution_events(resolution, resolution_id DESC);
            CREATE INDEX IF NOT EXISTS remediation_draft_events_pending
                ON remediation_draft_events(target_repository, draft_key,
                                            remediation_event_id DESC);
            CREATE INDEX IF NOT EXISTS remediation_draft_edits_by_hash
                ON remediation_draft_edit_events(edit_hash, draft_key);
            CREATE INDEX IF NOT EXISTS remediation_recovery_attempt_latest
                ON remediation_recovery_attempt_events(
                    draft_key, recovery_attempt_id DESC
                );
            CREATE INDEX IF NOT EXISTS remediation_recovery_cursor_rank
                ON remediation_recovery_cursors(recovery_rank, draft_key);
            CREATE INDEX IF NOT EXISTS remediation_source_coverage_by_completion
                ON remediation_source_coverage_groups(
                    completion_id, coverage_group_id
                );
            CREATE INDEX IF NOT EXISTS remediation_source_coverage_by_draft
                ON remediation_source_coverage_members(
                    draft_key, coverage_group_id
                );
            CREATE INDEX IF NOT EXISTS remediation_required_edits_by_hash
                ON remediation_source_required_edit_events(
                    edit_hash, coverage_group_id
                );
            CREATE INDEX IF NOT EXISTS remediation_remote_observation_latest
                ON remediation_remote_observation_events(
                    draft_key, observation_id DESC
                );
            CREATE INDEX IF NOT EXISTS remediation_merge_revalidation_latest
                ON remediation_merge_revalidation_events(
                    revalidation_key, merge_revalidation_event_id DESC
                );
            CREATE INDEX IF NOT EXISTS remediation_successor_by_draft
                ON remediation_successor_publications(
                    draft_key, successor_id
                );
            CREATE INDEX IF NOT EXISTS remediation_successor_intent_by_draft
                ON remediation_successor_intents(draft_key, intent_id);
            CREATE INDEX IF NOT EXISTS historical_discovery_cursor_latest
                ON historical_discovery_cursor_events(
                    repository, repository_id, policy_digest, cursor_id DESC
                );
            CREATE UNIQUE INDEX IF NOT EXISTS historical_discovery_cursor_initial
                ON historical_discovery_cursor_events(
                    repository, repository_id, policy_digest
                )
                WHERE previous_cursor_id IS NULL;
            CREATE UNIQUE INDEX IF NOT EXISTS historical_discovery_cursor_successor
                ON historical_discovery_cursor_events(previous_cursor_id)
                WHERE previous_cursor_id IS NOT NULL;

            CREATE INDEX IF NOT EXISTS historical_cycle_seen_pull_cycle
                ON historical_cycle_seen_pull_events(
                    repository, repository_id, policy_digest, cycle_id,
                    seen_event_id
                );

            CREATE INDEX IF NOT EXISTS historical_pull_retry_latest
                ON historical_pull_retry_events(
                    repository, repository_id, policy_digest, pull_id,
                    retry_event_id DESC
                );

            CREATE INDEX IF NOT EXISTS historical_pull_retry_resolution_lookup
                ON historical_pull_retry_resolution_events(
                    repository, repository_id, policy_digest, pull_id,
                    resolution_event_id DESC
                );

            CREATE TRIGGER IF NOT EXISTS event_revisions_no_update
            BEFORE UPDATE ON event_revisions
            BEGIN
                SELECT RAISE(ABORT, 'event revisions are immutable');
            END;

            CREATE TRIGGER IF NOT EXISTS event_revisions_no_delete
            BEFORE DELETE ON event_revisions
            BEGIN
                SELECT RAISE(ABORT, 'event revisions are immutable');
            END;

            CREATE TRIGGER IF NOT EXISTS event_current_observations_no_update
            BEFORE UPDATE ON event_current_observations
            BEGIN
                SELECT RAISE(ABORT, 'event current observations are immutable');
            END;

            CREATE TRIGGER IF NOT EXISTS event_current_observations_no_delete
            BEFORE DELETE ON event_current_observations
            BEGIN
                SELECT RAISE(ABORT, 'event current observations are immutable');
            END;

            CREATE TRIGGER IF NOT EXISTS event_current_observations_identity
            BEFORE INSERT ON event_current_observations
            WHEN NOT EXISTS (
                SELECT 1 FROM event_revisions AS revision
                WHERE revision.revision_id = NEW.event_revision_id
                  AND revision.repository = NEW.repository
                  AND revision.pr_number = NEW.pr_number
                  AND revision.kind = NEW.kind
                  AND revision.event_id = NEW.event_id
            )
            BEGIN
                SELECT RAISE(
                    ABORT,
                    'event current observation identity mismatch'
                );
            END;

            CREATE TRIGGER IF NOT EXISTS historical_completion_observations_no_update
            BEFORE UPDATE ON historical_pull_completion_observations
            BEGIN
                SELECT RAISE(
                    ABORT,
                    'historical completion observations are immutable'
                );
            END;

            CREATE TRIGGER IF NOT EXISTS historical_completion_observations_no_delete
            BEFORE DELETE ON historical_pull_completion_observations
            BEGIN
                SELECT RAISE(
                    ABORT,
                    'historical completion observations are immutable'
                );
            END;

            CREATE TRIGGER IF NOT EXISTS historical_completion_observations_identity
            BEFORE INSERT ON historical_pull_completion_observations
            WHEN NOT EXISTS (
                SELECT 1 FROM historical_pull_completions AS completion
                WHERE completion.completion_id = NEW.completion_id
                  AND completion.repository = NEW.repository
                  AND completion.repository_id = NEW.repository_id
                  AND completion.pull_id = NEW.pull_id
                  AND completion.pr_number = NEW.pr_number
                  AND completion.policy_digest = NEW.policy_digest
                  AND completion.authority_scope = NEW.authority_scope
            )
            BEGIN
                SELECT RAISE(
                    ABORT,
                    'historical completion observation identity mismatch'
                );
            END;

            CREATE TRIGGER IF NOT EXISTS publication_events_no_update
            BEFORE UPDATE ON publication_events
            BEGIN
                SELECT RAISE(ABORT, 'publication events are immutable');
            END;

            CREATE TRIGGER IF NOT EXISTS publication_events_no_delete
            BEFORE DELETE ON publication_events
            BEGIN
                SELECT RAISE(ABORT, 'publication events are immutable');
            END;

            CREATE TRIGGER IF NOT EXISTS publication_completion_plans_no_update
            BEFORE UPDATE ON publication_completion_plan_items
            BEGIN
                SELECT RAISE(ABORT, 'publication completion plans are immutable');
            END;

            CREATE TRIGGER IF NOT EXISTS publication_completion_plans_no_delete
            BEFORE DELETE ON publication_completion_plan_items
            BEGIN
                SELECT RAISE(ABORT, 'publication completion plans are immutable');
            END;

            CREATE TRIGGER IF NOT EXISTS publication_completion_plans_prepared
            BEFORE INSERT ON publication_completion_plan_items
            WHEN NOT EXISTS (
                SELECT 1
                FROM publication_events AS publication
                JOIN runs AS run ON run.run_id = publication.run_id
                JOIN event_revisions AS revision
                  ON revision.revision_id = NEW.event_revision_id
                WHERE publication.publication_key = NEW.publication_key
                  AND publication.phase = 'prepared'
                  AND publication.run_id = NEW.run_id
                  AND run.mode = NEW.action
                  AND revision.repository = publication.repository
                  AND revision.pr_number = publication.pr_number
                  AND revision.head_sha = publication.original_head_sha
                  AND revision.base_sha = publication.base_sha
                  AND NEW.occurred_at >= publication.occurred_at
            )
            BEGIN
                SELECT RAISE(
                    ABORT,
                    'publication completion plan requires exact prepared authority'
                );
            END;

            CREATE TRIGGER IF NOT EXISTS publication_events_first_prepared
            BEFORE INSERT ON publication_events
            WHEN NOT EXISTS (
                SELECT 1 FROM publication_events
                WHERE publication_key = NEW.publication_key
            ) AND NEW.phase != 'prepared'
            BEGIN
                SELECT RAISE(ABORT, 'publication must begin prepared');
            END;

            CREATE TRIGGER IF NOT EXISTS publication_events_identity
            BEFORE INSERT ON publication_events
            WHEN EXISTS (
                SELECT 1 FROM publication_events AS first
                WHERE first.publication_key = NEW.publication_key
                  AND (
                      first.run_id IS NOT NEW.run_id
                      OR first.repository IS NOT NEW.repository
                      OR first.pr_number IS NOT NEW.pr_number
                      OR first.original_head_sha IS NOT NEW.original_head_sha
                      OR first.base_sha IS NOT NEW.base_sha
                      OR first.commit_sha IS NOT NEW.commit_sha
                      OR first.event_revision_ids_json
                         IS NOT NEW.event_revision_ids_json
                      OR first.open_source_json IS NOT NEW.open_source_json
                  )
            )
            BEGIN
                SELECT RAISE(ABORT, 'publication event identity mismatch');
            END;

            CREATE TRIGGER IF NOT EXISTS publication_events_run_authority
            BEFORE INSERT ON publication_events
            WHEN NEW.phase = 'prepared' AND NOT EXISTS (
                SELECT 1 FROM runs AS run
                WHERE run.run_id = NEW.run_id
                  AND run.repository = NEW.repository
                  AND run.mode IN (
                      'apply-owned-translations', 'propose-prevention'
                  )
                  AND run.status = 'running'
            )
            BEGIN
                SELECT RAISE(ABORT, 'publication run authority mismatch');
            END;

            CREATE TRIGGER IF NOT EXISTS publication_events_monotonic
            BEFORE INSERT ON publication_events
            WHEN EXISTS (
                SELECT 1 FROM publication_events AS prior
                WHERE prior.publication_key = NEW.publication_key
                  AND prior.occurred_at > NEW.occurred_at
            )
            BEGIN
                SELECT RAISE(ABORT, 'publication timestamps must be monotonic');
            END;

            CREATE TRIGGER IF NOT EXISTS publication_events_transition
            BEFORE INSERT ON publication_events
            WHEN EXISTS (
                SELECT 1 FROM publication_events
                WHERE publication_key = NEW.publication_key
            ) AND NOT (
                NEW.phase = (
                    SELECT latest.phase FROM publication_events AS latest
                    WHERE latest.publication_key = NEW.publication_key
                    ORDER BY latest.publication_event_id DESC
                    LIMIT 1
                )
                OR (
                    (
                        SELECT latest.phase FROM publication_events AS latest
                        WHERE latest.publication_key = NEW.publication_key
                        ORDER BY latest.publication_event_id DESC
                        LIMIT 1
                    ) = 'prepared'
                    AND NEW.phase IN ('published', 'abandoned')
                )
                OR (
                    (
                        SELECT latest.phase FROM publication_events AS latest
                        WHERE latest.publication_key = NEW.publication_key
                        ORDER BY latest.publication_event_id DESC
                        LIMIT 1
                    ) = 'published'
                    AND NEW.phase IN ('replied', 'abandoned')
                )
            )
            BEGIN
                SELECT RAISE(ABORT, 'publication phase transition is invalid');
            END;

            CREATE TRIGGER IF NOT EXISTS publication_events_published_plan
            BEFORE INSERT ON publication_events
            WHEN NEW.phase = 'published' AND (
                NOT EXISTS (
                    SELECT 1 FROM publication_completion_plan_items AS plan
                    WHERE plan.publication_key = NEW.publication_key
                      AND plan.run_id = NEW.run_id
                )
                OR EXISTS (
                    SELECT 1 FROM json_each(NEW.event_revision_ids_json) AS selected
                    WHERE NOT EXISTS (
                        SELECT 1
                        FROM publication_completion_plan_items AS plan
                        WHERE plan.publication_key = NEW.publication_key
                          AND plan.event_revision_id = selected.value
                    )
                )
            )
            BEGIN
                SELECT RAISE(ABORT, 'published publication requires complete plan');
            END;

            CREATE TRIGGER IF NOT EXISTS publication_events_replied_complete
            BEFORE INSERT ON publication_events
            WHEN NEW.phase = 'replied' AND (
                NOT EXISTS (
                    SELECT 1 FROM runs AS run
                    WHERE run.run_id = NEW.run_id AND run.status = 'completed'
                )
                OR EXISTS (
                    SELECT 1
                    FROM publication_completion_plan_items AS plan
                    WHERE plan.publication_key = NEW.publication_key
                      AND NOT EXISTS (
                          SELECT 1 FROM actions AS action
                          WHERE action.run_id = plan.run_id
                            AND action.event_revision_id = plan.event_revision_id
                            AND action.action = plan.action
                            AND action.status = plan.status
                            AND action.details_json = plan.details_json
                      )
                )
            )
            BEGIN
                SELECT RAISE(ABORT, 'replied publication requires completed plan');
            END;

            CREATE TRIGGER IF NOT EXISTS publication_events_abandoned_complete
            BEFORE INSERT ON publication_events
            WHEN NEW.phase = 'abandoned' AND (
                NOT EXISTS (
                    SELECT 1 FROM runs AS run
                    WHERE run.run_id = NEW.run_id AND run.status = 'failed'
                )
                OR EXISTS (
                    SELECT 1
                    FROM publication_completion_plan_items AS plan
                    WHERE plan.publication_key = NEW.publication_key
                      AND NOT EXISTS (
                          SELECT 1 FROM actions AS action
                          WHERE action.run_id = plan.run_id
                            AND action.event_revision_id = plan.event_revision_id
                            AND action.action = plan.action
                            AND action.status = 'failed'
                      )
                )
            )
            BEGIN
                SELECT RAISE(ABORT, 'abandoned publication requires failed plan');
            END;

            CREATE TRIGGER IF NOT EXISTS prevention_draft_events_no_update
            BEFORE UPDATE ON prevention_draft_events
            BEGIN
                SELECT RAISE(ABORT, 'prevention draft events are immutable');
            END;

            CREATE TRIGGER IF NOT EXISTS prevention_draft_events_no_delete
            BEFORE DELETE ON prevention_draft_events
            BEGIN
                SELECT RAISE(ABORT, 'prevention draft events are immutable');
            END;

            CREATE TRIGGER IF NOT EXISTS prevention_draft_events_monotonic
            BEFORE INSERT ON prevention_draft_events
            WHEN EXISTS (
                SELECT 1 FROM prevention_draft_events
                WHERE draft_key = NEW.draft_key
                  AND occurred_at > NEW.occurred_at
            )
            BEGIN
                SELECT RAISE(
                    ABORT,
                    'prevention draft event timestamps must be monotonic'
                );
            END;

            CREATE TRIGGER IF NOT EXISTS prevention_draft_events_require_validated
            BEFORE INSERT ON prevention_draft_events
            WHEN NEW.phase != 'validated' AND NOT EXISTS (
                SELECT 1 FROM prevention_draft_events
                WHERE draft_key = NEW.draft_key AND phase = 'validated'
            )
            BEGIN
                SELECT RAISE(
                    ABORT,
                    'prevention draft must begin with validated phase'
                );
            END;

            CREATE TRIGGER IF NOT EXISTS prevention_draft_events_terminal
            BEFORE INSERT ON prevention_draft_events
            WHEN EXISTS (
                SELECT 1 FROM prevention_draft_events
                WHERE draft_key = NEW.draft_key
                  AND phase IN ('draft_opened', 'abandoned')
                  AND phase != NEW.phase
            )
            BEGIN
                SELECT RAISE(ABORT, 'prevention draft phase is terminal');
            END;

            CREATE TRIGGER IF NOT EXISTS prevention_draft_events_resolved_terminal
            BEFORE INSERT ON prevention_draft_events
            WHEN NEW.phase != 'draft_opened' AND EXISTS (
                SELECT 1 FROM prevention_resolution_events
                WHERE draft_key = NEW.draft_key
            )
            BEGIN
                SELECT RAISE(ABORT, 'prevention draft resolution is terminal');
            END;

            CREATE TRIGGER IF NOT EXISTS prevention_draft_events_quarantined_terminal
            BEFORE INSERT ON prevention_draft_events
            WHEN EXISTS (
                SELECT 1
                FROM prevention_draft_events AS existing
                LEFT JOIN prevention_invalid_record_quarantines AS quarantine
                  ON quarantine.prevention_event_id = existing.prevention_event_id
                LEFT JOIN prevention_legacy_reconciliations AS reconciliation
                  ON reconciliation.legacy_event_id = existing.prevention_event_id
                LEFT JOIN prevention_legacy_exact_drafts AS legacy_exact
                  ON legacy_exact.legacy_event_id = existing.prevention_event_id
                LEFT JOIN prevention_legacy_invalid_resolutions AS invalid
                  ON invalid.legacy_event_id = existing.prevention_event_id
                LEFT JOIN prevention_legacy_deferral_exhaustions AS exhausted
                  ON exhausted.legacy_event_id = existing.prevention_event_id
                WHERE existing.draft_key = NEW.draft_key
                  AND (
                      quarantine.prevention_event_id IS NOT NULL
                      OR reconciliation.legacy_event_id IS NOT NULL
                      OR legacy_exact.legacy_event_id IS NOT NULL
                      OR invalid.legacy_event_id IS NOT NULL
                      OR exhausted.legacy_event_id IS NOT NULL
                  )
            )
            BEGIN
                SELECT RAISE(ABORT, 'prevention draft quarantine is terminal');
            END;

            CREATE TRIGGER IF NOT EXISTS prevention_attestations_no_update
            BEFORE UPDATE ON prevention_candidate_attestations
            BEGIN
                SELECT RAISE(ABORT, 'prevention attestations are immutable');
            END;

            CREATE TRIGGER IF NOT EXISTS prevention_attestations_no_delete
            BEFORE DELETE ON prevention_candidate_attestations
            BEGIN
                SELECT RAISE(ABORT, 'prevention attestations are immutable');
            END;

            CREATE TRIGGER IF NOT EXISTS prevention_legacy_reconciliations_no_update
            BEFORE UPDATE ON prevention_legacy_reconciliations
            BEGIN
                SELECT RAISE(ABORT, 'legacy prevention reconciliations are immutable');
            END;

            CREATE TRIGGER IF NOT EXISTS prevention_legacy_reconciliations_no_delete
            BEFORE DELETE ON prevention_legacy_reconciliations
            BEGIN
                SELECT RAISE(ABORT, 'legacy prevention reconciliations are immutable');
            END;

            CREATE TRIGGER IF NOT EXISTS prevention_legacy_reconciliations_guard
            BEFORE INSERT ON prevention_legacy_reconciliations
            WHEN NOT EXISTS (
                SELECT 1 FROM prevention_legacy_candidate_events AS legacy
                WHERE legacy.prevention_event_id = NEW.legacy_event_id
            ) OR NOT EXISTS (
                SELECT 1 FROM prevention_draft_events AS event
                WHERE event.prevention_event_id = NEW.legacy_event_id
                  AND event.draft_key = NEW.draft_key
                  AND event.evidence_hash = NEW.evidence_hash
            ) OR EXISTS (
                SELECT 1
                FROM prevention_draft_events AS event
                JOIN prevention_draft_events AS newer
                  ON newer.draft_key = event.draft_key
                 AND newer.prevention_event_id > event.prevention_event_id
                WHERE event.prevention_event_id = NEW.legacy_event_id
            ) OR EXISTS (
                SELECT 1 FROM prevention_legacy_invalid_resolutions AS invalid
                WHERE invalid.legacy_event_id = NEW.legacy_event_id
            ) OR EXISTS (
                SELECT 1 FROM prevention_legacy_exact_drafts AS exact
                WHERE exact.legacy_event_id = NEW.legacy_event_id
            ) OR EXISTS (
                SELECT 1
                FROM prevention_legacy_deferral_exhaustions AS exhausted
                WHERE exhausted.legacy_event_id = NEW.legacy_event_id
            ) OR EXISTS (
                SELECT 1
                FROM prevention_resolution_events AS resolution
                WHERE resolution.draft_key = NEW.draft_key
            ) OR EXISTS (
                SELECT 1
                FROM prevention_invalid_record_quarantines AS quarantine
                WHERE quarantine.prevention_event_id = NEW.legacy_event_id
            )
            BEGIN
                SELECT RAISE(ABORT, 'legacy prevention reconciliation conflicts');
            END;

            CREATE TRIGGER IF NOT EXISTS prevention_legacy_exact_drafts_no_update
            BEFORE UPDATE ON prevention_legacy_exact_drafts
            BEGIN
                SELECT RAISE(ABORT, 'legacy exact prevention drafts are immutable');
            END;

            CREATE TRIGGER IF NOT EXISTS prevention_legacy_exact_drafts_no_delete
            BEFORE DELETE ON prevention_legacy_exact_drafts
            BEGIN
                SELECT RAISE(ABORT, 'legacy exact prevention drafts are immutable');
            END;

            CREATE TRIGGER IF NOT EXISTS prevention_legacy_exact_drafts_guard
            BEFORE INSERT ON prevention_legacy_exact_drafts
            WHEN NOT EXISTS (
                SELECT 1 FROM prevention_legacy_candidate_events AS legacy
                WHERE legacy.prevention_event_id = NEW.legacy_event_id
            ) OR NOT EXISTS (
                SELECT 1 FROM prevention_draft_events AS event
                WHERE event.prevention_event_id = NEW.legacy_event_id
                  AND event.draft_key = NEW.draft_key
                  AND event.evidence_hash = NEW.evidence_hash
            ) OR EXISTS (
                SELECT 1
                FROM prevention_draft_events AS event
                JOIN prevention_draft_events AS newer
                  ON newer.draft_key = event.draft_key
                 AND newer.prevention_event_id > event.prevention_event_id
                WHERE event.prevention_event_id = NEW.legacy_event_id
            ) OR EXISTS (
                SELECT 1
                FROM prevention_draft_events AS event
                WHERE event.prevention_event_id = NEW.legacy_event_id
                  AND event.phase = 'draft_opened'
                  AND (
                      typeof(event.draft_number) != 'integer'
                      OR event.draft_number != NEW.draft_number
                      OR typeof(event.draft_url) != 'text'
                      OR event.draft_url != NEW.draft_url
                  )
            ) OR typeof(NEW.draft_key) != 'text'
               OR length(NEW.draft_key) != 64
               OR NEW.draft_key GLOB '*[^0-9a-f]*'
               OR typeof(NEW.source_policy_digest) != 'text'
               OR length(NEW.source_policy_digest) != 64
               OR NEW.source_policy_digest GLOB '*[^0-9a-f]*'
               OR typeof(NEW.evidence_hash) != 'text'
               OR length(NEW.evidence_hash) != 64
               OR NEW.evidence_hash GLOB '*[^0-9a-f]*'
               OR typeof(NEW.source_repository_id) != 'integer'
               OR NEW.source_repository_id NOT BETWEEN 1 AND 9223372036854775807
               OR typeof(NEW.target_repository_id) != 'integer'
               OR NEW.target_repository_id NOT BETWEEN 1 AND 9223372036854775807
               OR typeof(NEW.push_repository_id) != 'integer'
               OR NEW.push_repository_id NOT BETWEEN 1 AND 9223372036854775807
               OR typeof(NEW.draft_number) != 'integer'
               OR NEW.draft_number NOT BETWEEN 1 AND 9223372036854775807
               OR typeof(NEW.draft_url) != 'text'
               OR length(CAST(NEW.draft_url AS BLOB)) > 4096
               OR NEW.draft_url = ''
               OR instr(NEW.draft_url, char(10)) > 0
               OR instr(NEW.draft_url, char(13)) > 0
               OR instr(NEW.draft_url, char(0)) > 0
               OR typeof(NEW.occurred_at) != 'text'
               OR length(CAST(NEW.occurred_at AS BLOB)) NOT BETWEEN 1 AND 64
               OR instr(NEW.occurred_at, char(10)) > 0
               OR instr(NEW.occurred_at, char(13)) > 0
               OR instr(NEW.occurred_at, char(0)) > 0
            OR EXISTS (
                SELECT 1
                FROM prevention_legacy_reconciliations AS reconciliation
                WHERE reconciliation.legacy_event_id = NEW.legacy_event_id
                  AND reconciliation.disposition = 'draft_opened'
                  AND (
                      reconciliation.draft_key != NEW.draft_key
                      OR reconciliation.source_repository_id !=
                         NEW.source_repository_id
                      OR reconciliation.target_repository_id !=
                         NEW.target_repository_id
                      OR reconciliation.push_repository_id !=
                         NEW.push_repository_id
                      OR reconciliation.source_policy_digest !=
                         NEW.source_policy_digest
                      OR reconciliation.evidence_hash != NEW.evidence_hash
                      OR reconciliation.draft_number != NEW.draft_number
                      OR reconciliation.draft_url != NEW.draft_url
                  )
            )
            BEGIN
                SELECT RAISE(ABORT, 'legacy exact prevention draft conflicts');
            END;

            CREATE TRIGGER IF NOT EXISTS prevention_legacy_candidates_no_update
            BEFORE UPDATE ON prevention_legacy_candidate_events
            BEGIN
                SELECT RAISE(ABORT, 'legacy prevention candidates are immutable');
            END;

            CREATE TRIGGER IF NOT EXISTS prevention_legacy_candidates_no_delete
            BEFORE DELETE ON prevention_legacy_candidate_events
            BEGIN
                SELECT RAISE(ABORT, 'legacy prevention candidates are immutable');
            END;

            CREATE TRIGGER IF NOT EXISTS prevention_legacy_invalid_no_update
            BEFORE UPDATE ON prevention_legacy_invalid_resolutions
            BEGIN
                SELECT RAISE(ABORT, 'legacy prevention invalid resolutions are immutable');
            END;

            CREATE TRIGGER IF NOT EXISTS prevention_legacy_invalid_no_delete
            BEFORE DELETE ON prevention_legacy_invalid_resolutions
            BEGIN
                SELECT RAISE(ABORT, 'legacy prevention invalid resolutions are immutable');
            END;

            CREATE TRIGGER IF NOT EXISTS prevention_legacy_invalid_guard
            BEFORE INSERT ON prevention_legacy_invalid_resolutions
            WHEN NOT EXISTS (
                SELECT 1 FROM prevention_legacy_candidate_events AS legacy
                WHERE legacy.prevention_event_id = NEW.legacy_event_id
            ) OR EXISTS (
                SELECT 1
                FROM prevention_draft_events AS event
                JOIN prevention_draft_events AS newer
                  ON newer.draft_key = event.draft_key
                 AND newer.prevention_event_id > event.prevention_event_id
                WHERE event.prevention_event_id = NEW.legacy_event_id
            ) OR EXISTS (
                SELECT 1 FROM prevention_legacy_reconciliations AS reconciliation
                WHERE reconciliation.legacy_event_id = NEW.legacy_event_id
            ) OR EXISTS (
                SELECT 1 FROM prevention_legacy_exact_drafts AS exact
                WHERE exact.legacy_event_id = NEW.legacy_event_id
            ) OR EXISTS (
                SELECT 1
                FROM prevention_legacy_deferral_exhaustions AS exhausted
                WHERE exhausted.legacy_event_id = NEW.legacy_event_id
            ) OR EXISTS (
                SELECT 1
                FROM prevention_draft_events AS event
                JOIN prevention_resolution_events AS resolution
                  ON resolution.draft_key = event.draft_key
                WHERE event.prevention_event_id = NEW.legacy_event_id
            ) OR EXISTS (
                SELECT 1
                FROM prevention_invalid_record_quarantines AS quarantine
                WHERE quarantine.prevention_event_id = NEW.legacy_event_id
            )
            BEGIN
                SELECT RAISE(ABORT, 'legacy prevention invalid resolution conflicts');
            END;

            CREATE TRIGGER IF NOT EXISTS prevention_legacy_deferrals_no_update
            BEFORE UPDATE ON prevention_legacy_policy_deferrals
            BEGIN
                SELECT RAISE(ABORT, 'legacy prevention deferrals are immutable');
            END;

            CREATE TRIGGER IF NOT EXISTS prevention_legacy_deferrals_no_delete
            BEFORE DELETE ON prevention_legacy_policy_deferrals
            BEGIN
                SELECT RAISE(ABORT, 'legacy prevention deferrals are immutable');
            END;

            CREATE TRIGGER IF NOT EXISTS prevention_legacy_deferrals_guard
            BEFORE INSERT ON prevention_legacy_policy_deferrals
            WHEN NOT EXISTS (
                SELECT 1 FROM prevention_legacy_candidate_events AS legacy
                WHERE legacy.prevention_event_id = NEW.legacy_event_id
            ) OR NOT EXISTS (
                SELECT 1 FROM prevention_draft_events AS event
                WHERE event.prevention_event_id = NEW.legacy_event_id
                  AND event.evidence_hash = NEW.evidence_hash
            ) OR EXISTS (
                SELECT 1
                FROM prevention_draft_events AS event
                JOIN prevention_draft_events AS newer
                  ON newer.draft_key = event.draft_key
                 AND newer.prevention_event_id > event.prevention_event_id
                WHERE event.prevention_event_id = NEW.legacy_event_id
            ) OR EXISTS (
                SELECT 1 FROM prevention_legacy_reconciliations AS reconciliation
                WHERE reconciliation.legacy_event_id = NEW.legacy_event_id
            ) OR EXISTS (
                SELECT 1 FROM prevention_legacy_exact_drafts AS exact
                WHERE exact.legacy_event_id = NEW.legacy_event_id
            ) OR EXISTS (
                SELECT 1 FROM prevention_legacy_invalid_resolutions AS invalid
                WHERE invalid.legacy_event_id = NEW.legacy_event_id
            ) OR EXISTS (
                SELECT 1
                FROM prevention_legacy_deferral_exhaustions AS exhausted
                WHERE exhausted.legacy_event_id = NEW.legacy_event_id
            ) OR EXISTS (
                SELECT 1
                FROM prevention_draft_events AS event
                JOIN prevention_resolution_events AS resolution
                  ON resolution.draft_key = event.draft_key
                WHERE event.prevention_event_id = NEW.legacy_event_id
            ) OR EXISTS (
                SELECT 1
                FROM prevention_invalid_record_quarantines AS quarantine
                WHERE quarantine.prevention_event_id = NEW.legacy_event_id
            )
            BEGIN
                SELECT RAISE(ABORT, 'legacy prevention deferral conflicts');
            END;

            CREATE TRIGGER IF NOT EXISTS prevention_legacy_deferral_exhaustions_no_update
            BEFORE UPDATE ON prevention_legacy_deferral_exhaustions
            BEGIN
                SELECT RAISE(ABORT, 'legacy prevention deferral exhaustion is immutable');
            END;

            CREATE TRIGGER IF NOT EXISTS prevention_legacy_deferral_exhaustions_no_delete
            BEFORE DELETE ON prevention_legacy_deferral_exhaustions
            BEGIN
                SELECT RAISE(ABORT, 'legacy prevention deferral exhaustion is immutable');
            END;


            CREATE TRIGGER IF NOT EXISTS prevention_legacy_deferral_exhaustions_guard
            BEFORE INSERT ON prevention_legacy_deferral_exhaustions
            WHEN NOT EXISTS (
                SELECT 1 FROM prevention_legacy_candidate_events AS legacy
                WHERE legacy.prevention_event_id = NEW.legacy_event_id
            ) OR EXISTS (
                SELECT 1
                FROM prevention_draft_events AS event
                JOIN prevention_draft_events AS newer
                  ON newer.draft_key = event.draft_key
                 AND newer.prevention_event_id > event.prevention_event_id
                WHERE event.prevention_event_id = NEW.legacy_event_id
            ) OR EXISTS (
                SELECT 1 FROM prevention_legacy_reconciliations AS reconciliation
                WHERE reconciliation.legacy_event_id = NEW.legacy_event_id
            ) OR EXISTS (
                SELECT 1 FROM prevention_legacy_exact_drafts AS exact
                WHERE exact.legacy_event_id = NEW.legacy_event_id
            ) OR EXISTS (
                SELECT 1 FROM prevention_legacy_invalid_resolutions AS invalid
                WHERE invalid.legacy_event_id = NEW.legacy_event_id
            ) OR EXISTS (
                SELECT 1
                FROM prevention_draft_events AS event
                JOIN prevention_resolution_events AS resolution
                  ON resolution.draft_key = event.draft_key
                WHERE event.prevention_event_id = NEW.legacy_event_id
            ) OR EXISTS (
                SELECT 1
                FROM prevention_invalid_record_quarantines AS quarantine
                WHERE quarantine.prevention_event_id = NEW.legacy_event_id
            )
            BEGIN
                SELECT RAISE(ABORT, 'legacy prevention deferral exhaustion conflicts');
            END;

            CREATE TRIGGER IF NOT EXISTS prevention_recovery_attempts_no_update
            BEFORE UPDATE ON prevention_recovery_attempt_events
            BEGIN
                SELECT RAISE(ABORT, 'prevention recovery attempts are immutable');
            END;

            CREATE TRIGGER IF NOT EXISTS prevention_recovery_attempts_no_delete
            BEFORE DELETE ON prevention_recovery_attempt_events
            BEGIN
                SELECT RAISE(ABORT, 'prevention recovery attempts are immutable');
            END;

            CREATE TRIGGER IF NOT EXISTS prevention_recovery_attempts_bounded
            BEFORE INSERT ON prevention_recovery_attempt_events
            WHEN (
                SELECT COUNT(*) FROM prevention_recovery_attempt_events
                WHERE draft_key = NEW.draft_key
            ) >= 10001
            BEGIN
                SELECT RAISE(ABORT, 'prevention recovery attempt bound reached');
            END;

            CREATE TRIGGER IF NOT EXISTS prevention_recovery_attempts_require_pending
            BEFORE INSERT ON prevention_recovery_attempt_events
            WHEN NOT EXISTS (
                SELECT 1
                FROM prevention_draft_events AS event
                LEFT JOIN prevention_legacy_candidate_events AS legacy
                  ON legacy.prevention_event_id = event.prevention_event_id
                WHERE event.draft_key = NEW.draft_key
                  AND NOT EXISTS (
                      SELECT 1
                      FROM prevention_draft_events AS newer
                      WHERE newer.draft_key = event.draft_key
                        AND newer.prevention_event_id > event.prevention_event_id
                  )
                  AND (
                      event.phase IN ('validated', 'pushed')
                      OR (
                          event.phase = 'draft_opened'
                          AND legacy.prevention_event_id IS NOT NULL
                      )
                  )
                  AND NOT EXISTS (
                      SELECT 1 FROM prevention_resolution_events AS resolution
                      WHERE resolution.draft_key = event.draft_key
                  )
                  AND NOT EXISTS (
                      SELECT 1
                      FROM prevention_invalid_record_quarantines AS quarantine
                      WHERE quarantine.prevention_event_id =
                            event.prevention_event_id
                  )
                  AND NOT EXISTS (
                      SELECT 1
                      FROM prevention_legacy_reconciliations AS reconciliation
                      WHERE reconciliation.legacy_event_id =
                            event.prevention_event_id
                  )
                  AND NOT EXISTS (
                      SELECT 1
                      FROM prevention_legacy_exact_drafts AS exact
                      WHERE exact.legacy_event_id = event.prevention_event_id
                  )
                  AND NOT EXISTS (
                      SELECT 1
                      FROM prevention_legacy_invalid_resolutions AS invalid
                      WHERE invalid.legacy_event_id = event.prevention_event_id
                  )
                  AND NOT EXISTS (
                      SELECT 1
                      FROM prevention_legacy_deferral_exhaustions AS exhausted
                      WHERE exhausted.legacy_event_id = event.prevention_event_id
                  )
            )
            BEGIN
                SELECT RAISE(
                    ABORT,
                    'prevention recovery attempt requires latest pending event'
                );
            END;

            CREATE TRIGGER IF NOT EXISTS prevention_resolutions_no_update
            BEFORE UPDATE ON prevention_resolution_events
            BEGIN
                SELECT RAISE(ABORT, 'prevention resolutions are immutable');
            END;

            CREATE TRIGGER IF NOT EXISTS prevention_resolutions_no_delete
            BEFORE DELETE ON prevention_resolution_events
            BEGIN
                SELECT RAISE(ABORT, 'prevention resolutions are immutable');
            END;

            CREATE TRIGGER IF NOT EXISTS prevention_resolutions_require_pending
            BEFORE INSERT ON prevention_resolution_events
            WHEN NOT EXISTS (
                SELECT 1
                FROM prevention_draft_events AS candidate
                WHERE candidate.draft_key = NEW.draft_key
                  AND candidate.phase IN ('validated', 'pushed')
                  AND NOT EXISTS (
                      SELECT 1
                      FROM prevention_draft_events AS newer
                      WHERE newer.draft_key = candidate.draft_key
                        AND newer.prevention_event_id >
                            candidate.prevention_event_id
                  )
                  AND NOT EXISTS (
                      SELECT 1
                      FROM prevention_legacy_exact_drafts AS exact
                      WHERE exact.legacy_event_id =
                            candidate.prevention_event_id
                  )
                  AND NOT EXISTS (
                      SELECT 1
                      FROM prevention_invalid_record_quarantines AS quarantine
                      WHERE quarantine.prevention_event_id =
                            candidate.prevention_event_id
                  )
            )
            BEGIN
                SELECT RAISE(
                    ABORT,
                    'prevention resolution requires latest pending event'
                );
            END;

            CREATE TRIGGER IF NOT EXISTS prevention_resolutions_reject_legacy
            BEFORE INSERT ON prevention_resolution_events
            WHEN EXISTS (
                SELECT 1
                FROM prevention_draft_events AS event
                JOIN prevention_legacy_candidate_events AS legacy
                  ON legacy.prevention_event_id = event.prevention_event_id
                WHERE event.draft_key = NEW.draft_key
            )
            BEGIN
                SELECT RAISE(
                    ABORT,
                    'legacy prevention uses its reconciliation ledger'
                );
            END;

            CREATE TRIGGER IF NOT EXISTS prevention_resolutions_monotonic
            BEFORE INSERT ON prevention_resolution_events
            WHEN NEW.resolution != 'invalid_record' AND EXISTS (
                SELECT 1 FROM prevention_draft_events
                WHERE draft_key = NEW.draft_key
                  AND occurred_at > NEW.occurred_at
            )
            BEGIN
                SELECT RAISE(
                    ABORT,
                    'prevention resolution timestamp must be monotonic'
                );
            END;

            CREATE TRIGGER IF NOT EXISTS prevention_invalid_quarantines_no_update
            BEFORE UPDATE ON prevention_invalid_record_quarantines
            BEGIN
                SELECT RAISE(
                    ABORT,
                    'prevention invalid-record quarantines are immutable'
                );
            END;

            CREATE TRIGGER IF NOT EXISTS prevention_invalid_quarantines_no_delete
            BEFORE DELETE ON prevention_invalid_record_quarantines
            BEGIN
                SELECT RAISE(
                    ABORT,
                    'prevention invalid-record quarantines are immutable'
                );
            END;

            CREATE TRIGGER IF NOT EXISTS prevention_invalid_quarantines_bounded
            BEFORE INSERT ON prevention_invalid_record_quarantines
            WHEN (
                SELECT COUNT(*) FROM prevention_invalid_record_quarantines
            ) >= 10000
            BEGIN
                SELECT RAISE(
                    ABORT,
                    'prevention invalid-record quarantine bound reached'
                );
            END;

            CREATE TRIGGER IF NOT EXISTS prevention_invalid_quarantines_pending
            BEFORE INSERT ON prevention_invalid_record_quarantines
            WHEN NOT EXISTS (
                SELECT 1
                FROM prevention_draft_events AS candidate
                WHERE candidate.prevention_event_id = NEW.prevention_event_id
                  AND (
                      candidate.phase IN ('validated', 'pushed')
                      OR (
                          candidate.phase = 'draft_opened'
                          AND EXISTS (
                              SELECT 1
                              FROM prevention_legacy_candidate_events AS legacy
                              WHERE legacy.prevention_event_id =
                                    candidate.prevention_event_id
                          )
                      )
                  )
                  AND NOT EXISTS (
                      SELECT 1
                      FROM prevention_resolution_events AS resolution
                      WHERE resolution.draft_key = candidate.draft_key
                  )
                  AND NOT EXISTS (
                      SELECT 1
                      FROM prevention_draft_events AS newer
                      WHERE newer.draft_key = candidate.draft_key
                        AND newer.prevention_event_id >
                            candidate.prevention_event_id
                  )
                  AND NOT EXISTS (
                      SELECT 1
                      FROM prevention_legacy_reconciliations AS reconciliation
                      WHERE reconciliation.legacy_event_id =
                            candidate.prevention_event_id
                  )
                  AND NOT EXISTS (
                      SELECT 1
                      FROM prevention_legacy_exact_drafts AS exact
                      WHERE exact.legacy_event_id =
                            candidate.prevention_event_id
                  )
                  AND NOT EXISTS (
                      SELECT 1
                      FROM prevention_legacy_invalid_resolutions AS invalid
                      WHERE invalid.legacy_event_id =
                            candidate.prevention_event_id
                  )
                  AND NOT EXISTS (
                      SELECT 1
                      FROM prevention_legacy_policy_deferrals AS deferral
                      WHERE deferral.legacy_event_id =
                            candidate.prevention_event_id
                  )
                  AND NOT EXISTS (
                      SELECT 1
                      FROM prevention_legacy_deferral_exhaustions AS exhausted
                      WHERE exhausted.legacy_event_id =
                            candidate.prevention_event_id
                  )
            )
            BEGIN
                SELECT RAISE(
                    ABORT,
                    'prevention invalid-record quarantine requires latest pending event'
                );
            END;

            CREATE TRIGGER IF NOT EXISTS prevention_invalid_quarantines_terminal
            BEFORE INSERT ON prevention_draft_events
            WHEN EXISTS (
                SELECT 1
                FROM prevention_invalid_record_quarantines AS quarantine
                JOIN prevention_draft_events AS quarantined
                  ON quarantined.prevention_event_id =
                     quarantine.prevention_event_id
                WHERE quarantined.draft_key = NEW.draft_key
            )
            BEGIN
                SELECT RAISE(
                    ABORT,
                    'prevention invalid-record quarantine is terminal'
                );
            END;

            CREATE TRIGGER IF NOT EXISTS historical_pull_completions_no_update
            BEFORE UPDATE ON historical_pull_completions
            BEGIN
                SELECT RAISE(ABORT, 'historical pull completions are immutable');
            END;

            CREATE TRIGGER IF NOT EXISTS historical_pull_completions_no_delete
            BEFORE DELETE ON historical_pull_completions
            BEGIN
                SELECT RAISE(ABORT, 'historical pull completions are immutable');
            END;

            CREATE TRIGGER IF NOT EXISTS historical_pull_identities_no_update
            BEFORE UPDATE ON historical_pull_identities
            BEGIN
                SELECT RAISE(ABORT, 'historical pull identities are immutable');
            END;

            CREATE TRIGGER IF NOT EXISTS historical_pull_identities_no_delete
            BEFORE DELETE ON historical_pull_identities
            BEGIN
                SELECT RAISE(ABORT, 'historical pull identities are immutable');
            END;

            CREATE TRIGGER IF NOT EXISTS historical_discovery_cursor_events_no_update
            BEFORE UPDATE ON historical_discovery_cursor_events
            BEGIN
                SELECT RAISE(ABORT, 'historical discovery cursors are immutable');
            END;

            CREATE TRIGGER IF NOT EXISTS historical_discovery_cursor_events_no_delete
            BEFORE DELETE ON historical_discovery_cursor_events
            BEGIN
                SELECT RAISE(ABORT, 'historical discovery cursors are immutable');
            END;

            CREATE TRIGGER IF NOT EXISTS historical_cycle_seen_pulls_no_update
            BEFORE UPDATE ON historical_cycle_seen_pull_events
            BEGIN
                SELECT RAISE(ABORT, 'historical cycle seen pulls are immutable');
            END;

            CREATE TRIGGER IF NOT EXISTS historical_cycle_seen_pulls_no_delete
            BEFORE DELETE ON historical_cycle_seen_pull_events
            BEGIN
                SELECT RAISE(ABORT, 'historical cycle seen pulls are immutable');
            END;

            CREATE TRIGGER IF NOT EXISTS historical_pull_retries_no_update
            BEFORE UPDATE ON historical_pull_retry_events
            BEGIN
                SELECT RAISE(ABORT, 'historical pull retries are immutable');
            END;

            CREATE TRIGGER IF NOT EXISTS historical_pull_retries_no_delete
            BEFORE DELETE ON historical_pull_retry_events
            BEGIN
                SELECT RAISE(ABORT, 'historical pull retries are immutable');
            END;

            CREATE TRIGGER IF NOT EXISTS historical_pull_retry_resolutions_no_update
            BEFORE UPDATE ON historical_pull_retry_resolution_events
            BEGIN
                SELECT RAISE(
                    ABORT,
                    'historical pull retry resolutions are immutable'
                );
            END;

            CREATE TRIGGER IF NOT EXISTS historical_pull_retry_resolutions_bounded
            BEFORE INSERT ON historical_pull_retry_resolution_events
            WHEN (
                SELECT COUNT(*)
                FROM historical_pull_retry_resolution_events
                WHERE repository = NEW.repository
                  AND repository_id = NEW.repository_id
                  AND policy_digest = NEW.policy_digest
            ) >= 10000
            BEGIN
                SELECT RAISE(
                    ABORT,
                    'historical pull retry resolution bound reached'
                );
            END;

            CREATE TRIGGER IF NOT EXISTS historical_pull_retry_resolutions_no_delete
            BEFORE DELETE ON historical_pull_retry_resolution_events
            BEGIN
                SELECT RAISE(
                    ABORT,
                    'historical pull retry resolutions are immutable'
                );
            END;

            CREATE TRIGGER IF NOT EXISTS remediation_draft_events_no_update
            BEFORE UPDATE ON remediation_draft_events
            BEGIN
                SELECT RAISE(ABORT, 'remediation draft events are immutable');
            END;

            CREATE TRIGGER IF NOT EXISTS remediation_draft_events_no_delete
            BEFORE DELETE ON remediation_draft_events
            BEGIN
                SELECT RAISE(ABORT, 'remediation draft events are immutable');
            END;

            CREATE TRIGGER IF NOT EXISTS remediation_draft_events_monotonic
            BEFORE INSERT ON remediation_draft_events
            WHEN EXISTS (
                SELECT 1 FROM remediation_draft_events
                WHERE draft_key = NEW.draft_key
                  AND occurred_at > NEW.occurred_at
            )
            BEGIN
                SELECT RAISE(
                    ABORT,
                    'remediation draft event timestamps must be monotonic'
                );
            END;

            CREATE TRIGGER IF NOT EXISTS remediation_draft_edits_no_update
            BEFORE UPDATE ON remediation_draft_edit_events
            BEGIN
                SELECT RAISE(ABORT, 'remediation draft edits are immutable');
            END;

            CREATE TRIGGER IF NOT EXISTS remediation_draft_edits_no_delete
            BEFORE DELETE ON remediation_draft_edit_events
            BEGIN
                SELECT RAISE(ABORT, 'remediation draft edits are immutable');
            END;

            CREATE TRIGGER IF NOT EXISTS remediation_draft_paths_no_update
            BEFORE UPDATE ON remediation_draft_path_attestations
            BEGIN
                SELECT RAISE(ABORT, 'remediation draft paths are immutable');
            END;

            CREATE TRIGGER IF NOT EXISTS remediation_draft_paths_no_delete
            BEFORE DELETE ON remediation_draft_path_attestations
            BEGIN
                SELECT RAISE(ABORT, 'remediation draft paths are immutable');
            END;

            CREATE TRIGGER IF NOT EXISTS remediation_draft_paths_safe_members
            BEFORE INSERT ON remediation_draft_path_attestations
            WHEN EXISTS (
                SELECT 1 FROM json_each(NEW.changed_paths_json)
                WHERE type != 'text'
                   OR length(CAST(value AS BLOB)) = 0
                   OR length(CAST(value AS BLOB)) > 4096
                   OR substr(value, 1, 1) = '/'
                   OR instr(value, '\\') > 0
                   OR instr(value, char(0)) > 0
                   OR instr(value, char(10)) > 0
                   OR instr(value, char(13)) > 0
                   OR value IN ('.', '..')
                   OR value LIKE './%'
                   OR value LIKE '../%'
                   OR value LIKE '%/./%'
                   OR value LIKE '%/../%'
                   OR value LIKE '%/.'
                   OR value LIKE '%/..'
                   OR value LIKE '%//%'
            )
            OR (
                SELECT COUNT(*) FROM json_each(NEW.changed_paths_json)
            ) != (
                SELECT COUNT(DISTINCT value)
                FROM json_each(NEW.changed_paths_json)
            )
            BEGIN
                SELECT RAISE(
                    ABORT,
                    'remediation draft paths contain an unsafe member'
                );
            END;

            CREATE TRIGGER IF NOT EXISTS remediation_checkpoint_events_no_update
            BEFORE UPDATE ON remediation_checkpoint_events
            BEGIN
                SELECT RAISE(ABORT, 'remediation checkpoints are immutable');
            END;

            CREATE TRIGGER IF NOT EXISTS remediation_checkpoint_events_no_delete
            BEFORE DELETE ON remediation_checkpoint_events
            BEGIN
                SELECT RAISE(ABORT, 'remediation checkpoints are immutable');
            END;

            CREATE TRIGGER IF NOT EXISTS remediation_recovery_attempts_no_update
            BEFORE UPDATE ON remediation_recovery_attempt_events
            BEGIN
                SELECT RAISE(ABORT, 'remediation recovery attempts are immutable');
            END;

            CREATE TRIGGER IF NOT EXISTS remediation_recovery_attempts_no_delete
            BEFORE DELETE ON remediation_recovery_attempt_events
            BEGIN
                SELECT RAISE(ABORT, 'remediation recovery attempts are immutable');
            END;

            CREATE TRIGGER IF NOT EXISTS remediation_resolutions_no_update
            BEFORE UPDATE ON remediation_resolution_events
            BEGIN
                SELECT RAISE(ABORT, 'remediation resolutions are immutable');
            END;

            CREATE TRIGGER IF NOT EXISTS remediation_resolutions_no_delete
            BEFORE DELETE ON remediation_resolution_events
            BEGIN
                SELECT RAISE(ABORT, 'remediation resolutions are immutable');
            END;

            CREATE TRIGGER IF NOT EXISTS remediation_resolutions_monotonic
            BEFORE INSERT ON remediation_resolution_events
            WHEN EXISTS (
                SELECT 1 FROM remediation_draft_events
                WHERE draft_key = NEW.draft_key
                  AND occurred_at > NEW.occurred_at
            ) OR EXISTS (
                SELECT 1 FROM remediation_remote_observation_events
                WHERE draft_key = NEW.draft_key
                  AND occurred_at > NEW.occurred_at
            )
            BEGIN
                SELECT RAISE(
                    ABORT,
                    'remediation resolution timestamp must be monotonic'
                );
            END;

            CREATE TRIGGER IF NOT EXISTS remediation_source_groups_no_update
            BEFORE UPDATE ON remediation_source_coverage_groups
            BEGIN
                SELECT RAISE(ABORT, 'remediation source groups are immutable');
            END;

            CREATE TRIGGER IF NOT EXISTS remediation_source_groups_no_delete
            BEFORE DELETE ON remediation_source_coverage_groups
            BEGIN
                SELECT RAISE(ABORT, 'remediation source groups are immutable');
            END;

            CREATE TRIGGER IF NOT EXISTS remediation_source_groups_bounded
            BEFORE INSERT ON remediation_source_coverage_groups
            WHEN (
                SELECT COUNT(*) FROM remediation_source_coverage_groups
                WHERE completion_id = NEW.completion_id
            ) >= 10000
            BEGIN
                SELECT RAISE(
                    ABORT,
                    'remediation source coverage group bound reached'
                );
            END;

            CREATE TRIGGER IF NOT EXISTS remediation_source_members_no_update
            BEFORE UPDATE ON remediation_source_coverage_members
            BEGIN
                SELECT RAISE(ABORT, 'remediation source members are immutable');
            END;

            CREATE TRIGGER IF NOT EXISTS remediation_source_members_no_delete
            BEFORE DELETE ON remediation_source_coverage_members
            BEGIN
                SELECT RAISE(ABORT, 'remediation source members are immutable');
            END;

            CREATE TRIGGER IF NOT EXISTS remediation_source_members_bounded
            BEFORE INSERT ON remediation_source_coverage_members
            WHEN (
                SELECT COUNT(*) FROM remediation_source_coverage_members
                WHERE coverage_group_id = NEW.coverage_group_id
            ) >= 100
            BEGIN
                SELECT RAISE(
                    ABORT,
                    'remediation source coverage member bound reached'
                );
            END;

            CREATE TRIGGER IF NOT EXISTS remediation_required_edits_no_update
            BEFORE UPDATE ON remediation_source_required_edit_events
            BEGIN
                SELECT RAISE(ABORT, 'remediation required edits are immutable');
            END;

            CREATE TRIGGER IF NOT EXISTS remediation_required_edits_no_delete
            BEFORE DELETE ON remediation_source_required_edit_events
            BEGIN
                SELECT RAISE(ABORT, 'remediation required edits are immutable');
            END;

            CREATE TRIGGER IF NOT EXISTS remediation_required_edits_bounded
            BEFORE INSERT ON remediation_source_required_edit_events
            WHEN (
                SELECT COUNT(*) FROM remediation_source_required_edit_events
                WHERE coverage_group_id = NEW.coverage_group_id
            ) >= 1000
            BEGIN
                SELECT RAISE(ABORT, 'remediation required edit bound reached');
            END;

            CREATE TRIGGER IF NOT EXISTS remediation_remote_observations_no_update
            BEFORE UPDATE ON remediation_remote_observation_events
            BEGIN
                SELECT RAISE(ABORT, 'remediation remote observations are immutable');
            END;

            CREATE TRIGGER IF NOT EXISTS remediation_remote_observations_no_delete
            BEFORE DELETE ON remediation_remote_observation_events
            BEGIN
                SELECT RAISE(ABORT, 'remediation remote observations are immutable');
            END;

            CREATE TRIGGER IF NOT EXISTS remediation_remote_observations_bounded
            BEFORE INSERT ON remediation_remote_observation_events
            WHEN (
                SELECT COUNT(*) FROM remediation_remote_observation_events
                WHERE draft_key = NEW.draft_key
            ) >= 10000
            BEGIN
                SELECT RAISE(
                    ABORT,
                    'remediation remote observation bound reached'
                );
            END;

            CREATE TRIGGER IF NOT EXISTS remediation_remote_observations_monotonic
            BEFORE INSERT ON remediation_remote_observation_events
            WHEN EXISTS (
                SELECT 1 FROM remediation_remote_observation_events
                WHERE draft_key = NEW.draft_key
                  AND occurred_at > NEW.occurred_at
            )
            BEGIN
                SELECT RAISE(
                    ABORT,
                    'remediation remote observation timestamps must be monotonic'
                );
            END;

            CREATE TRIGGER IF NOT EXISTS remediation_remote_observations_terminal
            BEFORE INSERT ON remediation_remote_observation_events
            WHEN EXISTS (
                SELECT 1 FROM remediation_resolution_events
                WHERE draft_key = NEW.draft_key
            )
            BEGIN
                SELECT RAISE(
                    ABORT,
                    'resolved remediation remote lifecycle is terminal'
                );
            END;

            CREATE TRIGGER IF NOT EXISTS remediation_merge_revalidations_no_update
            BEFORE UPDATE ON remediation_merge_revalidation_events
            BEGIN
                SELECT RAISE(ABORT, 'remediation merge revalidations are immutable');
            END;

            CREATE TRIGGER IF NOT EXISTS remediation_merge_revalidations_no_delete
            BEFORE DELETE ON remediation_merge_revalidation_events
            BEGIN
                SELECT RAISE(ABORT, 'remediation merge revalidations are immutable');
            END;

            CREATE TRIGGER IF NOT EXISTS remediation_merge_revalidations_bounded
            BEFORE INSERT ON remediation_merge_revalidation_events
            WHEN (
                SELECT COUNT(*) FROM remediation_merge_revalidation_events
                WHERE revalidation_key = NEW.revalidation_key
            ) >= 10000
            BEGIN
                SELECT RAISE(ABORT, 'remediation merge revalidation bound reached');
            END;

            CREATE TRIGGER IF NOT EXISTS remediation_merge_revalidations_initial
            BEFORE INSERT ON remediation_merge_revalidation_events
            WHEN NOT EXISTS (
                SELECT 1 FROM remediation_merge_revalidation_events
                WHERE revalidation_key = NEW.revalidation_key
            ) AND NEW.phase != 'pending'
            BEGIN
                SELECT RAISE(ABORT, 'remediation merge revalidation must start pending');
            END;

            CREATE TRIGGER IF NOT EXISTS remediation_merge_revalidations_identity
            BEFORE INSERT ON remediation_merge_revalidation_events
            WHEN EXISTS (
                SELECT 1 FROM remediation_merge_revalidation_events
                WHERE revalidation_key = NEW.revalidation_key
                  AND (
                      draft_key != NEW.draft_key
                      OR source_json != NEW.source_json
                      OR event_revision_ids_json != NEW.event_revision_ids_json
                  )
            )
            BEGIN
                SELECT RAISE(ABORT, 'remediation merge revalidation identity changed');
            END;

            CREATE TRIGGER IF NOT EXISTS remediation_merge_revalidations_monotonic
            BEFORE INSERT ON remediation_merge_revalidation_events
            WHEN EXISTS (
                SELECT 1 FROM remediation_merge_revalidation_events
                WHERE revalidation_key = NEW.revalidation_key
                  AND occurred_at > NEW.occurred_at
            )
            BEGIN
                SELECT RAISE(ABORT, 'remediation merge revalidation time regressed');
            END;

            CREATE TRIGGER IF NOT EXISTS remediation_merge_revalidations_terminal
            BEFORE INSERT ON remediation_merge_revalidation_events
            WHEN EXISTS (
                SELECT 1 FROM remediation_merge_revalidation_events
                WHERE revalidation_key = NEW.revalidation_key
                  AND phase IN ('resolved', 'no_longer_applicable')
            )
            BEGIN
                SELECT RAISE(ABORT, 'remediation merge revalidation is terminal');
            END;

            CREATE TRIGGER IF NOT EXISTS remediation_merge_revalidations_no_requeue
            BEFORE INSERT ON remediation_merge_revalidation_events
            WHEN EXISTS (
                SELECT 1 FROM remediation_merge_revalidation_events
                WHERE revalidation_key = NEW.revalidation_key
            ) AND NEW.phase = 'pending'
            BEGIN
                SELECT RAISE(ABORT, 'remediation merge revalidation cannot requeue');
            END;

            CREATE TRIGGER IF NOT EXISTS remediation_successors_no_update
            BEFORE UPDATE ON remediation_successor_publications
            BEGIN
                SELECT RAISE(ABORT, 'remediation successors are immutable');
            END;

            CREATE TRIGGER IF NOT EXISTS remediation_successors_no_delete
            BEFORE DELETE ON remediation_successor_publications
            BEGIN
                SELECT RAISE(ABORT, 'remediation successors are immutable');
            END;

            CREATE TRIGGER IF NOT EXISTS remediation_successors_bounded
            BEFORE INSERT ON remediation_successor_publications
            WHEN (
                SELECT COUNT(*) FROM remediation_successor_publications
                WHERE draft_key = NEW.draft_key
            ) >= 10000
            BEGIN
                SELECT RAISE(ABORT, 'remediation successor bound reached');
            END;

            CREATE TRIGGER IF NOT EXISTS remediation_successors_require_intent
            BEFORE INSERT ON remediation_successor_publications
            WHEN NOT EXISTS (
                SELECT 1 FROM remediation_successor_intents AS intent
                WHERE intent.intent_key = NEW.lineage_key
                  AND intent.draft_key = NEW.draft_key
                  AND intent.publication_key = NEW.publication_key
                  AND intent.run_id = NEW.run_id
                  AND intent.parent_candidate_sha = NEW.parent_candidate_sha
                  AND intent.successor_candidate_sha = NEW.successor_candidate_sha
                  AND intent.source_pulls_json = NEW.source_pulls_json
                  AND intent.edit_hashes_json = NEW.edit_hashes_json
                  AND intent.actor_id = NEW.actor_id
                  AND intent.actor_type = NEW.actor_type
                  AND intent.publication_actor_id = NEW.publication_actor_id
                  AND intent.publication_actor_type = NEW.publication_actor_type
            )
            BEGIN
                SELECT RAISE(
                    ABORT,
                    'remediation successor requires exact prepared intent'
                );
            END;

            CREATE TRIGGER IF NOT EXISTS remediation_successor_intents_no_update
            BEFORE UPDATE ON remediation_successor_intents
            BEGIN
                SELECT RAISE(ABORT, 'remediation successor intents are immutable');
            END;

            CREATE TRIGGER IF NOT EXISTS remediation_successor_intents_no_delete
            BEFORE DELETE ON remediation_successor_intents
            BEGIN
                SELECT RAISE(ABORT, 'remediation successor intents are immutable');
            END;

            CREATE TRIGGER IF NOT EXISTS remediation_successor_intents_bounded
            BEFORE INSERT ON remediation_successor_intents
            WHEN (
                SELECT COUNT(*) FROM remediation_successor_intents
                WHERE draft_key = NEW.draft_key
            ) >= 10000
            BEGIN
                SELECT RAISE(ABORT, 'remediation successor intent bound reached');
            END;

            CREATE TRIGGER IF NOT EXISTS remediation_successor_intents_prepared
            BEFORE INSERT ON remediation_successor_intents
            WHEN NOT EXISTS (
                SELECT 1
                FROM publication_events AS publication
                JOIN remediation_draft_events AS draft
                  ON draft.draft_key = NEW.draft_key
                 AND draft.phase = 'draft_opened'
                WHERE publication.publication_key = NEW.publication_key
                  AND publication.phase = 'prepared'
                  AND publication.run_id = NEW.run_id
                  AND publication.repository = draft.target_repository
                  AND publication.pr_number = draft.draft_number
                  AND publication.original_head_sha = NEW.parent_candidate_sha
                  AND publication.commit_sha = NEW.successor_candidate_sha
                  AND NOT EXISTS (
                      SELECT 1 FROM remediation_resolution_events AS resolution
                      WHERE resolution.draft_key = NEW.draft_key
                  )
            )
            BEGIN
                SELECT RAISE(
                    ABORT,
                    'remediation successor intent requires prepared publication'
                );
            END;
            """
        )
        completion_columns = {
            str(row["name"])
            for row in self._connection.execute(
                "PRAGMA table_info(historical_pull_completions)"
            ).fetchall()
        }
        publication_columns = {
            str(row["name"])
            for row in self._connection.execute(
                "PRAGMA table_info(publication_events)"
            ).fetchall()
        }
        if "open_source_json" not in publication_columns:
            # Released v1 publications did not retain the complete authority
            # snapshot. NULL is deliberately preserved as a fail-closed
            # legacy marker; recovery must never infer it from current state.
            self._connection.execute(
                "ALTER TABLE publication_events ADD COLUMN open_source_json TEXT"
            )
        if "publication_actor_id" not in publication_columns:
            # Legacy publications did not retain the exact GitHub actor whose
            # authority was used. NULL remains a fail-closed marker: it must
            # never be inferred from current repository state during recovery.
            self._connection.execute(
                "ALTER TABLE publication_events ADD COLUMN publication_actor_id INTEGER"
            )
        if "publication_actor_type" not in publication_columns:
            self._connection.execute(
                "ALTER TABLE publication_events ADD COLUMN publication_actor_type TEXT"
            )
        publication_repository_id_added = "repository_id" not in publication_columns
        if publication_repository_id_added:
            # Released schemas stored the immutable repository ID only inside
            # the exact open-source authority. Preserve NULL for legacy or
            # malformed rows instead of inferring authority from a mutable name.
            self._connection.execute(
                "ALTER TABLE publication_events "
                "ADD COLUMN repository_id INTEGER CHECK (repository_id > 0)"
            )
        completion_plan_columns = {
            str(row["name"])
            for row in self._connection.execute(
                "PRAGMA table_info(publication_completion_plan_items)"
            ).fetchall()
        }
        if "publication_actor_id" not in completion_plan_columns:
            self._connection.execute(
                "ALTER TABLE publication_completion_plan_items "
                "ADD COLUMN publication_actor_id INTEGER"
            )
        if "publication_actor_type" not in completion_plan_columns:
            self._connection.execute(
                "ALTER TABLE publication_completion_plan_items "
                "ADD COLUMN publication_actor_type TEXT"
            )
        self._connection.execute("DROP TRIGGER IF EXISTS publication_events_identity")
        self._connection.execute(
            """
            CREATE TRIGGER publication_events_identity
            BEFORE INSERT ON publication_events
            WHEN EXISTS (
                SELECT 1 FROM publication_events AS first
                WHERE first.publication_key = NEW.publication_key
                  AND (
                      first.run_id IS NOT NEW.run_id
                      OR first.repository IS NOT NEW.repository
                      OR first.repository_id IS NOT NEW.repository_id
                      OR first.pr_number IS NOT NEW.pr_number
                      OR first.original_head_sha IS NOT NEW.original_head_sha
                      OR first.base_sha IS NOT NEW.base_sha
                      OR first.commit_sha IS NOT NEW.commit_sha
                      OR first.publication_actor_id
                         IS NOT NEW.publication_actor_id
                      OR first.publication_actor_type
                         IS NOT NEW.publication_actor_type
                      OR first.event_revision_ids_json
                         IS NOT NEW.event_revision_ids_json
                      OR first.open_source_json IS NOT NEW.open_source_json
                  )
            )
            BEGIN
                SELECT RAISE(ABORT, 'publication event identity mismatch');
            END
            """
        )
        self._connection.execute(
            """
            CREATE TRIGGER IF NOT EXISTS publication_events_repository_id_safe
            BEFORE INSERT ON publication_events
            WHEN NEW.repository_id IS NULL
              OR typeof(NEW.repository_id) != 'integer'
              OR NEW.repository_id NOT BETWEEN 1 AND 9223372036854775807
            BEGIN
                SELECT RAISE(ABORT, 'publication repository id is unsafe');
            END
            """
        )
        self._connection.execute(
            """
            CREATE TRIGGER IF NOT EXISTS publication_events_actor_safe
            BEFORE INSERT ON publication_events
            WHEN NEW.publication_actor_id IS NULL
              OR typeof(NEW.publication_actor_id) != 'integer'
              OR NEW.publication_actor_id NOT BETWEEN 1 AND 9223372036854775807
              OR NEW.publication_actor_type IS NULL
              OR NEW.publication_actor_type NOT IN ('User', 'Bot')
            BEGIN
                SELECT RAISE(ABORT, 'publication actor is unsafe');
            END
            """
        )
        self._connection.execute(
            """
            CREATE INDEX IF NOT EXISTS publication_events_pending_by_repository_id
            ON publication_events(
                repository_id, pr_number, publication_key,
                publication_event_id DESC
            )
            """
        )
        self._connection.execute(
            """
            CREATE INDEX IF NOT EXISTS publication_events_replied_by_repository_id
            ON publication_events(
                repository_id, pr_number, commit_sha, phase,
                publication_event_id DESC
            )
            """
        )
        self._connection.execute(
            """
            CREATE INDEX IF NOT EXISTS remediation_draft_events_pending_by_repository_id
            ON remediation_draft_events(
                target_repository_id, draft_key, remediation_event_id DESC
            )
            """
        )
        self._connection.execute(
            """
            CREATE INDEX IF NOT EXISTS remediation_draft_events_pull_by_repository_id
            ON remediation_draft_events(
                target_repository_id, draft_number, phase,
                remediation_event_id
            )
            """
        )
        self._connection.execute(
            "DROP TRIGGER IF EXISTS publication_completion_plans_prepared"
        )
        self._connection.execute(
            """
            CREATE TRIGGER publication_completion_plans_prepared
            BEFORE INSERT ON publication_completion_plan_items
            WHEN NOT EXISTS (
                SELECT 1
                FROM publication_events AS publication
                JOIN runs AS run ON run.run_id = publication.run_id
                JOIN event_revisions AS revision
                  ON revision.revision_id = NEW.event_revision_id
                WHERE publication.publication_key = NEW.publication_key
                  AND publication.phase = 'prepared'
                  AND publication.run_id = NEW.run_id
                  AND publication.publication_actor_id
                      = NEW.publication_actor_id
                  AND publication.publication_actor_type
                      = NEW.publication_actor_type
                  AND run.mode = NEW.action
                  AND revision.repository = publication.repository
                  AND revision.pr_number = publication.pr_number
                  AND revision.head_sha = publication.original_head_sha
                  AND revision.base_sha = publication.base_sha
                  AND NEW.occurred_at >= publication.occurred_at
            )
            BEGIN
                SELECT RAISE(
                    ABORT,
                    'publication completion plan requires exact prepared authority'
                );
            END
            """
        )
        for table in (
            "remediation_successor_intents",
            "remediation_successor_publications",
        ):
            successor_columns = {
                str(row["name"])
                for row in self._connection.execute(
                    f"PRAGMA table_info({table})"
                ).fetchall()
            }
            if "changed_paths_json" not in successor_columns:
                # Legacy successor rows did not retain the exact successor
                # commit paths. NULL is an intentional fail-closed marker;
                # recovery must never infer a narrower set from draft scope.
                self._connection.execute(
                    f"ALTER TABLE {table} ADD COLUMN changed_paths_json TEXT"
                )
            if "publication_actor_id" not in successor_columns:
                # Older successor rows did not retain the exact GitHub actor
                # authorized to publish the remediation PR. NULL remains an
                # explicit fail-closed legacy marker.
                self._connection.execute(
                    f"ALTER TABLE {table} ADD COLUMN publication_actor_id INTEGER"
                )
            if "publication_actor_type" not in successor_columns:
                self._connection.execute(
                    f"ALTER TABLE {table} ADD COLUMN publication_actor_type TEXT"
                )
        self._connection.execute(
            "DROP TRIGGER IF EXISTS remediation_successors_require_intent"
        )
        self._connection.execute(
            """
            CREATE TRIGGER remediation_successors_require_intent
            BEFORE INSERT ON remediation_successor_publications
            WHEN NOT EXISTS (
                SELECT 1 FROM remediation_successor_intents AS intent
                WHERE intent.intent_key = NEW.lineage_key
                  AND intent.draft_key = NEW.draft_key
                  AND intent.publication_key = NEW.publication_key
                  AND intent.run_id = NEW.run_id
                  AND intent.parent_candidate_sha = NEW.parent_candidate_sha
                  AND intent.successor_candidate_sha = NEW.successor_candidate_sha
                  AND intent.source_pulls_json = NEW.source_pulls_json
                  AND intent.edit_hashes_json = NEW.edit_hashes_json
                  AND intent.changed_paths_json = NEW.changed_paths_json
                  AND intent.actor_id = NEW.actor_id
                  AND intent.actor_type = NEW.actor_type
                  AND intent.publication_actor_id = NEW.publication_actor_id
                  AND intent.publication_actor_type = NEW.publication_actor_type
            )
            BEGIN
                SELECT RAISE(
                    ABORT,
                    'remediation successor requires exact prepared intent'
                );
            END
            """
        )
        self._connection.execute(
            "DROP TRIGGER IF EXISTS remediation_successor_intents_prepared"
        )
        self._connection.execute(
            """
            CREATE TRIGGER remediation_successor_intents_prepared
            BEFORE INSERT ON remediation_successor_intents
            WHEN NOT EXISTS (
                SELECT 1
                FROM publication_events AS publication
                JOIN remediation_draft_events AS draft
                  ON draft.draft_key = NEW.draft_key
                 AND draft.phase = 'draft_opened'
                WHERE publication.publication_key = NEW.publication_key
                  AND publication.phase = 'prepared'
                  AND publication.run_id = NEW.run_id
                  AND publication.repository = draft.target_repository
                  AND publication.pr_number = draft.draft_number
                  AND publication.original_head_sha = NEW.parent_candidate_sha
                  AND publication.commit_sha = NEW.successor_candidate_sha
                  AND publication.publication_actor_id
                      = NEW.publication_actor_id
                  AND publication.publication_actor_type
                      = NEW.publication_actor_type
                  AND NOT EXISTS (
                      SELECT 1 FROM remediation_resolution_events AS resolution
                      WHERE resolution.draft_key = NEW.draft_key
                  )
            )
            BEGIN
                SELECT RAISE(
                    ABORT,
                    'remediation successor intent requires prepared publication'
                );
            END
            """
        )
        self._connection.execute(
            """
            CREATE TRIGGER IF NOT EXISTS remediation_successor_intent_paths_safe
            BEFORE INSERT ON remediation_successor_intents
            WHEN NEW.changed_paths_json IS NULL
              OR length(CAST(NEW.changed_paths_json AS BLOB)) > 524288
              OR NOT json_valid(NEW.changed_paths_json)
              OR json_type(NEW.changed_paths_json) != 'array'
              OR json_array_length(NEW.changed_paths_json) NOT BETWEEN 1 AND 100
              OR EXISTS (
                  SELECT 1 FROM json_each(NEW.changed_paths_json)
                  WHERE type != 'text'
                     OR length(CAST(value AS BLOB)) = 0
                     OR length(CAST(value AS BLOB)) > 4096
                     OR substr(value, 1, 1) = '/'
                     OR instr(value, '\\') > 0
                     OR instr(value, char(0)) > 0
                     OR instr(value, char(10)) > 0
                     OR instr(value, char(13)) > 0
                     OR value IN ('.', '..')
                     OR value LIKE './%'
                     OR value LIKE '../%'
                     OR value LIKE '%/./%'
                     OR value LIKE '%/../%'
                     OR value LIKE '%/.'
                     OR value LIKE '%/..'
                     OR value LIKE '%//%'
              )
              OR (
                  SELECT COUNT(*) FROM json_each(NEW.changed_paths_json)
              ) != (
                  SELECT COUNT(DISTINCT value)
                  FROM json_each(NEW.changed_paths_json)
              )
            BEGIN
                SELECT RAISE(
                    ABORT,
                    'remediation successor intent paths are unsafe'
                );
            END
            """
        )
        self._connection.execute(
            """
            CREATE TRIGGER IF NOT EXISTS remediation_successor_paths_safe
            BEFORE INSERT ON remediation_successor_publications
            WHEN NEW.changed_paths_json IS NULL
              OR length(CAST(NEW.changed_paths_json AS BLOB)) > 524288
              OR NOT json_valid(NEW.changed_paths_json)
              OR json_type(NEW.changed_paths_json) != 'array'
              OR json_array_length(NEW.changed_paths_json) NOT BETWEEN 1 AND 100
              OR EXISTS (
                  SELECT 1 FROM json_each(NEW.changed_paths_json)
                  WHERE type != 'text'
                     OR length(CAST(value AS BLOB)) = 0
                     OR length(CAST(value AS BLOB)) > 4096
                     OR substr(value, 1, 1) = '/'
                     OR instr(value, '\\') > 0
                     OR instr(value, char(0)) > 0
                     OR instr(value, char(10)) > 0
                     OR instr(value, char(13)) > 0
                     OR value IN ('.', '..')
                     OR value LIKE './%'
                     OR value LIKE '../%'
                     OR value LIKE '%/./%'
                     OR value LIKE '%/../%'
                     OR value LIKE '%/.'
                     OR value LIKE '%/..'
                     OR value LIKE '%//%'
              )
              OR (
                  SELECT COUNT(*) FROM json_each(NEW.changed_paths_json)
              ) != (
                  SELECT COUNT(DISTINCT value)
                  FROM json_each(NEW.changed_paths_json)
              )
            BEGIN
                SELECT RAISE(
                    ABORT,
                    'remediation successor paths are unsafe'
                );
            END
            """
        )
        self._connection.execute(
            """
            CREATE TRIGGER IF NOT EXISTS remediation_successor_intent_actor_safe
            BEFORE INSERT ON remediation_successor_intents
            WHEN NEW.publication_actor_id IS NULL
              OR typeof(NEW.publication_actor_id) != 'integer'
              OR NEW.publication_actor_id <= 0
              OR NEW.publication_actor_type IS NULL
              OR NEW.publication_actor_type NOT IN ('User', 'Bot')
            BEGIN
                SELECT RAISE(
                    ABORT,
                    'remediation successor intent publication actor is unsafe'
                );
            END
            """
        )
        self._connection.execute(
            """
            CREATE TRIGGER IF NOT EXISTS remediation_successor_actor_safe
            BEFORE INSERT ON remediation_successor_publications
            WHEN NEW.publication_actor_id IS NULL
              OR typeof(NEW.publication_actor_id) != 'integer'
              OR NEW.publication_actor_id <= 0
              OR NEW.publication_actor_type IS NULL
              OR NEW.publication_actor_type NOT IN ('User', 'Bot')
            BEGIN
                SELECT RAISE(
                    ABORT,
                    'remediation successor publication actor is unsafe'
                );
            END
            """
        )
        if "event_revision_watermark" not in completion_columns:
            self._connection.execute(
                """
                ALTER TABLE historical_pull_completions
                ADD COLUMN event_revision_watermark INTEGER NOT NULL DEFAULT 0
                CHECK (event_revision_watermark >= 0)
                """
            )
        if "ignored_event_revision_ids_json" not in completion_columns:
            self._connection.execute(
                """
                ALTER TABLE historical_pull_completions
                ADD COLUMN ignored_event_revision_ids_json TEXT NOT NULL
                DEFAULT '[]'
                """
            )
        prevention_attestation_columns = {
            str(row["name"])
            for row in self._connection.execute(
                "PRAGMA table_info(prevention_candidate_attestations)"
            ).fetchall()
        }
        for column in (
            "source_repository_id",
            "target_repository_id",
            "push_repository_id",
        ):
            if column not in prevention_attestation_columns:
                # Pre-v5 prevention attestations did not expose immutable
                # repository IDs as first-class query keys. NULL remains a
                # fail-closed legacy marker; policy JSON is never trusted as a
                # migration oracle without reauthentication.
                self._connection.execute(
                    f"ALTER TABLE prevention_candidate_attestations "
                    f"ADD COLUMN {column} INTEGER"
                )
        remediation_edit_columns = {
            str(row["name"])
            for row in self._connection.execute(
                "PRAGMA table_info(remediation_draft_edit_events)"
            ).fetchall()
        }
        if "target_hash" not in remediation_edit_columns:
            # Schema v2 stored only the exact edit hash. That one-way digest
            # cannot be safely reverse-mapped to path+key during migration.
            # Retain those immutable rows as NULL; coverage treats any active
            # legacy row as a fail-closed conflict until it is abandoned.
            self._connection.execute(
                """
                ALTER TABLE remediation_draft_edit_events
                ADD COLUMN target_hash TEXT
                """
            )
        remediation_columns = {
            str(row["name"])
            for row in self._connection.execute(
                "PRAGMA table_info(remediation_draft_events)"
            ).fetchall()
        }
        if "branch_identity_version" not in remediation_columns:
            # Every pre-v5 draft key used the original, unversioned identity.
            self._connection.execute(
                """
                ALTER TABLE remediation_draft_events
                ADD COLUMN branch_identity_version INTEGER NOT NULL DEFAULT 1
                CHECK (branch_identity_version IN (1, 2))
                """
            )
        if "draft_pull_id" not in remediation_columns:
            # Earlier ledgers did not retain GitHub's immutable numeric pull
            # identity. NULL is deliberately preserved as a fail-closed legacy
            # marker; it must never be inferred from a branch or PR number.
            self._connection.execute(
                """
                ALTER TABLE remediation_draft_events
                ADD COLUMN draft_pull_id INTEGER CHECK (draft_pull_id > 0)
                """
            )
        self._connection.execute(
            """
            CREATE TRIGGER IF NOT EXISTS remediation_draft_open_identity
            BEFORE INSERT ON remediation_draft_events
            WHEN (
                NEW.phase = 'draft_opened'
                AND (NEW.draft_number IS NULL OR NEW.draft_pull_id IS NULL)
            ) OR (
                NEW.phase != 'draft_opened'
                AND (NEW.draft_number IS NOT NULL OR NEW.draft_pull_id IS NOT NULL)
            )
            BEGIN
                SELECT RAISE(
                    ABORT,
                    'remediation draft open identity is incomplete'
                );
            END
            """
        )
        # The remediation authority rule changed in schema v8 development.
        # Recreate it so an already-opened v8 database cannot retain the
        # obsolete propose-only trigger definition.
        self._connection.execute(
            "DROP TRIGGER IF EXISTS remediation_draft_events_run_authority"
        )
        for trigger_sql in (
            """
            CREATE TRIGGER IF NOT EXISTS prevention_draft_events_run_authority
            BEFORE INSERT ON prevention_draft_events
            WHEN NOT EXISTS (
                SELECT 1 FROM runs AS run
                WHERE run.run_id = NEW.run_id
                  AND run.repository = NEW.source_repository
                  AND run.mode = 'propose-prevention'
            )
            BEGIN
                SELECT RAISE(ABORT, 'prevention draft run authority mismatch');
            END
            """,
            """
            CREATE TRIGGER IF NOT EXISTS prevention_draft_events_identity
            BEFORE INSERT ON prevention_draft_events
            WHEN EXISTS (
                SELECT 1 FROM prevention_draft_events AS first
                WHERE first.draft_key = NEW.draft_key
                  AND (
                      first.run_id IS NOT NEW.run_id
                      OR first.source_repository IS NOT NEW.source_repository
                      OR first.target_repository IS NOT NEW.target_repository
                      OR first.target_base_branch IS NOT NEW.target_base_branch
                      OR first.target_base_sha IS NOT NEW.target_base_sha
                      OR first.push_repository IS NOT NEW.push_repository
                      OR first.branch IS NOT NEW.branch
                      OR first.candidate_sha IS NOT NEW.candidate_sha
                      OR first.evidence_hash IS NOT NEW.evidence_hash
                      OR first.title IS NOT NEW.title
                      OR first.body IS NOT NEW.body
                  )
            )
            BEGIN
                SELECT RAISE(ABORT, 'prevention draft identity mismatch');
            END
            """,
            """
            CREATE TRIGGER IF NOT EXISTS prevention_draft_events_transition
            BEFORE INSERT ON prevention_draft_events
            WHEN EXISTS (
                SELECT 1 FROM prevention_draft_events
                WHERE draft_key = NEW.draft_key
            ) AND NOT (
                (
                    (SELECT phase FROM prevention_draft_events
                     WHERE draft_key = NEW.draft_key
                     ORDER BY prevention_event_id DESC LIMIT 1) = 'validated'
                    AND NEW.phase IN ('pushed', 'draft_opened', 'abandoned')
                ) OR (
                    (SELECT phase FROM prevention_draft_events
                     WHERE draft_key = NEW.draft_key
                     ORDER BY prevention_event_id DESC LIMIT 1) = 'pushed'
                    AND NEW.phase IN ('draft_opened', 'abandoned')
                )
            )
            BEGIN
                SELECT RAISE(ABORT, 'prevention draft phase transition is invalid');
            END
            """,
            """
            CREATE TRIGGER IF NOT EXISTS remediation_draft_events_run_authority
            BEFORE INSERT ON remediation_draft_events
            WHEN NOT EXISTS (
                SELECT 1 FROM runs AS run
                WHERE run.run_id = NEW.run_id
                  AND run.repository = NEW.target_repository
                  AND run.mode IN (
                      'apply-owned-translations', 'propose-prevention'
                  )
            )
            BEGIN
                SELECT RAISE(ABORT, 'remediation draft run authority mismatch');
            END
            """,
            """
            CREATE TRIGGER IF NOT EXISTS remediation_draft_events_require_validated
            BEFORE INSERT ON remediation_draft_events
            WHEN NOT EXISTS (
                SELECT 1 FROM remediation_draft_events
                WHERE draft_key = NEW.draft_key
            ) AND NEW.phase != 'validated'
            BEGIN
                SELECT RAISE(
                    ABORT,
                    'remediation draft must begin with validated phase'
                );
            END
            """,
            """
            CREATE TRIGGER IF NOT EXISTS remediation_draft_events_identity
            BEFORE INSERT ON remediation_draft_events
            WHEN EXISTS (
                SELECT 1 FROM remediation_draft_events AS first
                WHERE first.draft_key = NEW.draft_key
                  AND (
                      first.branch_identity_version
                         IS NOT NEW.branch_identity_version
                      OR first.run_id IS NOT NEW.run_id
                      OR first.target_repository IS NOT NEW.target_repository
                      OR first.target_repository_id
                         IS NOT NEW.target_repository_id
                      OR first.target_base_branch
                         IS NOT NEW.target_base_branch
                      OR first.target_base_sha IS NOT NEW.target_base_sha
                      OR first.push_repository IS NOT NEW.push_repository
                      OR first.push_repository_id
                         IS NOT NEW.push_repository_id
                      OR first.branch IS NOT NEW.branch
                      OR first.candidate_sha IS NOT NEW.candidate_sha
                      OR first.evidence_hash IS NOT NEW.evidence_hash
                      OR first.batch_hash IS NOT NEW.batch_hash
                      OR first.source_pulls_json IS NOT NEW.source_pulls_json
                      OR first.event_revision_ids_json
                         IS NOT NEW.event_revision_ids_json
                      OR first.title IS NOT NEW.title
                      OR first.body IS NOT NEW.body
                  )
            )
            BEGIN
                SELECT RAISE(ABORT, 'remediation draft identity mismatch');
            END
            """,
            """
            CREATE TRIGGER IF NOT EXISTS remediation_draft_events_transition
            BEFORE INSERT ON remediation_draft_events
            WHEN EXISTS (
                SELECT 1 FROM remediation_draft_events
                WHERE draft_key = NEW.draft_key
            ) AND NOT (
                (
                    (SELECT phase FROM remediation_draft_events
                     WHERE draft_key = NEW.draft_key
                     ORDER BY remediation_event_id DESC LIMIT 1) = 'validated'
                    AND NEW.phase IN ('pushed', 'abandoned')
                ) OR (
                    (SELECT phase FROM remediation_draft_events
                     WHERE draft_key = NEW.draft_key
                     ORDER BY remediation_event_id DESC LIMIT 1) = 'pushed'
                    AND NEW.phase IN ('draft_opened', 'abandoned')
                )
            )
            BEGIN
                SELECT RAISE(ABORT, 'remediation draft phase transition is invalid');
            END
            """,
            """
            CREATE TRIGGER IF NOT EXISTS remediation_draft_events_resolved_terminal
            BEFORE INSERT ON remediation_draft_events
            WHEN EXISTS (
                SELECT 1 FROM remediation_resolution_events
                WHERE draft_key = NEW.draft_key
            )
            BEGIN
                SELECT RAISE(ABORT, 'remediation draft resolution is terminal');
            END
            """,
        ):
            self._connection.execute(trigger_sql)
        remote_columns = {
            str(row["name"])
            for row in self._connection.execute(
                "PRAGMA table_info(remediation_remote_observation_events)"
            ).fetchall()
        }
        for column in (
            "observed_head_sha",
            "closed_at",
            "merged_at",
        ):
            if column not in remote_columns:
                self._connection.execute(
                    f"ALTER TABLE remediation_remote_observation_events "
                    f"ADD COLUMN {column} TEXT"
                )
        # Older development schemas appended one row on every recovery poll.
        # Preserve their latest ordering point once, then use a single mutable
        # cursor per draft so repeated polling cannot grow the database without
        # bound.  The legacy table remains immutable audit history.
        self._connection.execute(
            """
            INSERT OR IGNORE INTO remediation_recovery_cursors (
                draft_key, recovery_rank, occurred_at
            )
            SELECT attempt.draft_key, attempt.recovery_attempt_id,
                   attempt.occurred_at
            FROM remediation_recovery_attempt_events AS attempt
            JOIN (
                SELECT draft_key, MAX(recovery_attempt_id) AS recovery_attempt_id
                FROM remediation_recovery_attempt_events
                GROUP BY draft_key
            ) AS latest
              ON latest.draft_key = attempt.draft_key
             AND latest.recovery_attempt_id = attempt.recovery_attempt_id
            """
        )
        self._connection.execute(
            """
            INSERT INTO event_current_observations (
                repository, pr_number, kind, event_id,
                event_revision_id, observed_at
            )
            SELECT current.repository, current.pr_number, current.kind,
                   current.event_id, current.revision_id, current.observed_at
            FROM event_revisions AS current
            WHERE current.revision_id = (
                SELECT MAX(candidate.revision_id)
                FROM event_revisions AS candidate
                WHERE candidate.repository = current.repository
                  AND candidate.pr_number = current.pr_number
                  AND candidate.kind = current.kind
                  AND candidate.event_id = current.event_id
            )
              AND NOT EXISTS (
                  SELECT 1 FROM event_current_observations AS observation
                  WHERE observation.repository = current.repository
                    AND observation.pr_number = current.pr_number
                    AND observation.kind = current.kind
                    AND observation.event_id = current.event_id
              )
            """
        )
        if publication_repository_id_added:
            self._connection.execute(
                "DROP TRIGGER IF EXISTS publication_events_no_update"
            )
            self._backfill_publication_repository_ids()
            self._connection.execute(
                """
                CREATE TRIGGER publication_events_no_update
                BEFORE UPDATE ON publication_events
                BEGIN
                    SELECT RAISE(ABORT, 'publication events are immutable');
                END
                """
            )
        self._connection.execute(
            """
            INSERT INTO historical_pull_completion_observations (
                repository, repository_id, pull_id, pr_number,
                policy_digest, authority_scope, completion_id, observed_at
            )
            SELECT latest.repository, latest.repository_id, latest.pull_id,
                   latest.pr_number, latest.policy_digest,
                   latest.authority_scope, latest.completion_id,
                   latest.completed_at
            FROM historical_pull_completions AS latest
            WHERE latest.completion_id = (
                SELECT MAX(candidate.completion_id)
                FROM historical_pull_completions AS candidate
                WHERE candidate.repository = latest.repository
                  AND candidate.repository_id = latest.repository_id
                  AND candidate.pull_id = latest.pull_id
                  AND candidate.pr_number = latest.pr_number
                  AND candidate.policy_digest = latest.policy_digest
                  AND candidate.authority_scope = latest.authority_scope
            )
              AND NOT EXISTS (
                  SELECT 1
                  FROM historical_pull_completion_observations AS observation
                  WHERE observation.repository = latest.repository
                    AND observation.repository_id = latest.repository_id
                    AND observation.pull_id = latest.pull_id
                    AND observation.pr_number = latest.pr_number
                    AND observation.policy_digest = latest.policy_digest
                    AND observation.authority_scope = latest.authority_scope
              )
            """
        )
        if previous_version == 1:
            # Version 1 was the only released schema that could create
            # prevention candidates without a full publication attestation.
            # Snapshot that finite set before the strict modern-ledger audit;
            # malformed members are handled by the bounded legacy isolation
            # path rather than being granted modern recovery authority.
            self._connection.execute(
                """
                INSERT OR IGNORE INTO prevention_legacy_candidate_events (
                    prevention_event_id
                )
                SELECT prevention_event_id
                FROM prevention_draft_events
                """
            )
        if previous_version < 10:
            # Widen only the reply-terminal reason enum, preserving every row.
            for statement in (
                """CREATE TABLE publication_reply_terminal_events_v10 (
                    publication_key TEXT PRIMARY KEY,
                    reason TEXT NOT NULL CHECK (reason IN (
                        'remediation_closed_unmerged', 'remediation_merged',
                        'trusted_feedback_changed'
                    )),
                    occurred_at TEXT NOT NULL
                )""",
                "INSERT INTO publication_reply_terminal_events_v10 "
                "SELECT * FROM publication_reply_terminal_events",
                "DROP TABLE publication_reply_terminal_events",
                "ALTER TABLE publication_reply_terminal_events_v10 "
                "RENAME TO publication_reply_terminal_events",
            ):
                self._connection.execute(statement)
        if previous_version < 8:
            self._audit_draft_event_ledgers()
        if previous_version < 5:
            self._migrate_legacy_remediation_coverage()
        self._connection.execute(
            """
            CREATE INDEX IF NOT EXISTS remediation_draft_edits_by_target
            ON remediation_draft_edit_events(target_hash, draft_key)
            """
        )
        self._connection.execute(
            """
            CREATE INDEX IF NOT EXISTS prevention_attestation_repository_ids
            ON prevention_candidate_attestations(
                source_repository_id, target_repository_id,
                push_repository_id, draft_key
            )
            """
        )
        self._connection.execute(
            """
            CREATE INDEX IF NOT EXISTS prevention_draft_evidence_key
            ON prevention_draft_events(evidence_hash, draft_key)
            """
        )
        self._connection.execute(
            """
            CREATE INDEX IF NOT EXISTS prevention_legacy_evidence_identity
            ON prevention_legacy_reconciliations(
                source_repository_id, target_repository_id,
                evidence_hash, disposition
            )
            """
        )
        self._connection.execute(
            """
            CREATE INDEX IF NOT EXISTS prevention_legacy_exact_evidence_identity
            ON prevention_legacy_exact_drafts(
                source_repository_id, target_repository_id,
                evidence_hash, legacy_event_id
            )
            """
        )
        self._connection.execute(
            """
            CREATE TRIGGER IF NOT EXISTS prevention_legacy_candidates_no_insert
            BEFORE INSERT ON prevention_legacy_candidate_events
            BEGIN
                SELECT RAISE(ABORT, 'legacy prevention candidate set is sealed');
            END
            """
        )
        self._connection.execute(
            """
            CREATE TRIGGER IF NOT EXISTS prevention_legacy_draft_events_no_append
            BEFORE INSERT ON prevention_draft_events
            WHEN EXISTS (
                SELECT 1
                FROM prevention_draft_events AS existing
                JOIN prevention_legacy_candidate_events AS legacy
                  ON legacy.prevention_event_id = existing.prevention_event_id
                WHERE existing.draft_key = NEW.draft_key
            )
            BEGIN
                SELECT RAISE(
                    ABORT,
                    'released-v1 prevention candidate is sealed'
                );
            END
            """
        )
        self._install_publication_reply_triggers()
        self._verify_database_integrity()
        self._connection.execute(f"PRAGMA user_version = {_SCHEMA_VERSION}")
        self._connection.commit()

    def _install_publication_reply_triggers(self) -> None:
        """Protect terminal accounting after transactional table migration."""
        for operation in ("UPDATE", "DELETE"):
            self._connection.execute(f"""
                CREATE TRIGGER IF NOT EXISTS publication_reply_terminals_no_{operation.lower()}
                BEFORE {operation} ON publication_reply_terminal_events
                BEGIN
                    SELECT RAISE(ABORT, 'publication reply terminals are immutable');
                END
            """)
        self._connection.execute("DROP TRIGGER IF EXISTS publication_reply_terminals_published")
        self._connection.execute("""
            CREATE TRIGGER publication_reply_terminals_published
            BEFORE INSERT ON publication_reply_terminal_events
            WHEN NOT EXISTS (
                SELECT 1 FROM publication_events AS publication
                LEFT JOIN remediation_successor_publications AS successor
                  ON successor.publication_key = publication.publication_key
                JOIN runs AS run ON run.run_id = publication.run_id
                WHERE publication.publication_key = NEW.publication_key
                  AND publication.phase = 'published'
                  AND run.status = 'completed'
                  AND (NEW.reason = 'trusted_feedback_changed'
                       OR successor.publication_key IS NOT NULL)
                  AND NOT EXISTS (
                      SELECT 1 FROM publication_completion_plan_items AS plan
                      WHERE plan.publication_key = publication.publication_key
                        AND NOT EXISTS (
                            SELECT 1 FROM actions AS action
                            WHERE action.run_id = plan.run_id
                              AND action.event_revision_id = plan.event_revision_id
                              AND action.action = plan.action
                              AND action.status = plan.status
                              AND action.details_json = plan.details_json
                        )
                  )
            )
            BEGIN
                SELECT RAISE(ABORT, 'publication reply terminal requires published successor');
            END
        """)

    def _backfill_publication_repository_ids(self) -> None:
        """Recover only bounded, exact modern publication repository IDs."""

        last_first_event_id = 0
        while True:
            candidates = self._connection.execute(
                """
                WITH missing AS (
                    SELECT publication_key,
                           MIN(publication_event_id) AS first_event_id
                    FROM publication_events
                    WHERE repository_id IS NULL
                    GROUP BY publication_key
                )
                SELECT publication_key, first_event_id
                FROM missing
                WHERE first_event_id > ?
                ORDER BY first_event_id
                LIMIT ?
                """,
                (last_first_event_id, _MAX_PENDING_PUBLICATION_WORKSET),
            ).fetchall()
            if not candidates:
                return
            for candidate in candidates:
                rows = self._connection.execute(
                    """
                    SELECT * FROM publication_events
                    WHERE publication_key = ?
                    ORDER BY publication_event_id
                    LIMIT 5
                    """,
                    (candidate["publication_key"],),
                ).fetchall()
                sources: list[OpenPullAuthorityReference] = []
                revision_sets: list[tuple[int, ...]] = []
                phase_history: list[str] = []
                identities: list[tuple[object, ...]] = []
                try:
                    if not rows or len(rows) > 4:
                        raise ValueError
                    for row in rows:
                        source = _open_pull_authority_from_json(row["open_source_json"])
                        revision_ids = _validated_revision_ids_json(
                            row["event_revision_ids_json"],
                            label="Publication migration",
                        )
                        occurred_at = _parse_datetime(row["occurred_at"])
                        key_payload = (
                            f"{row['repository']}\n{row['pr_number']}\n"
                            f"{row['original_head_sha']}\n{row['base_sha']}\n"
                            f"{row['commit_sha']}"
                        )
                        if (
                            source is None
                            or source.feedback_digest is None
                            or not revision_ids
                            or source.repository != row["repository"]
                            or source.pr_number != row["pr_number"]
                            or source.head_sha != row["original_head_sha"]
                            or source.base_sha != row["base_sha"]
                            or hashlib.sha256(key_payload.encode("utf-8")).hexdigest()
                            != row["publication_key"]
                            or occurred_at is None
                            or _serialize_datetime(occurred_at) != row["occurred_at"]
                        ):
                            raise ValueError
                        sources.append(source)
                        revision_sets.append(revision_ids)
                        phase_history.append(str(row["phase"]))
                        identities.append(
                            (
                                row["run_id"],
                                row["repository"],
                                row["pr_number"],
                                row["original_head_sha"],
                                row["base_sha"],
                                row["commit_sha"],
                                row["publication_actor_id"],
                                row["publication_actor_type"],
                                row["event_revision_ids_json"],
                                row["open_source_json"],
                            )
                        )
                    valid_phase_histories = {
                        ("prepared",),
                        ("prepared", "abandoned"),
                        ("prepared", "published"),
                        ("prepared", "published", "abandoned"),
                        ("prepared", "published", "replied"),
                    }
                    if (
                        len(set(sources)) != 1
                        or len(set(revision_sets)) != 1
                        or len(set(identities)) != 1
                        or tuple(phase_history) not in valid_phase_histories
                    ):
                        raise ValueError
                    run = self.get_run(str(rows[0]["run_id"]))
                    if run.repository != sources[0].repository or run.mode not in {
                        GuardianMode.APPLY_OWNED_TRANSLATIONS,
                        GuardianMode.PROPOSE_PREVENTION,
                    }:
                        raise ValueError
                    revision_rows: list[sqlite3.Row] = []
                    # A review comment may have been edited after this
                    # publication. Validate its immutable stored revisions,
                    # not today's mutable current-observation pointers.
                    for offset in range(
                        0,
                        len(revision_sets[0]),
                        _SQLITE_IN_QUERY_CHUNK,
                    ):
                        revision_chunk = revision_sets[0][
                            offset : offset + _SQLITE_IN_QUERY_CHUNK
                        ]
                        placeholders = ", ".join("?" for _item in revision_chunk)
                        revision_rows.extend(
                            self._connection.execute(
                                f"""
                                SELECT revision_id, repository, pr_number,
                                       head_sha, base_sha, deleted
                                FROM event_revisions
                                WHERE revision_id IN ({placeholders})
                                """,
                                revision_chunk,
                            ).fetchall()
                        )
                    source = sources[0]
                    if {int(row["revision_id"]) for row in revision_rows} != set(
                        revision_sets[0]
                    ) or any(
                        (
                            row["repository"],
                            int(row["pr_number"]),
                            row["head_sha"],
                            row["base_sha"],
                            int(row["deleted"]),
                        )
                        != (
                            source.repository,
                            source.pr_number,
                            source.head_sha,
                            source.base_sha,
                            0,
                        )
                        for row in revision_rows
                    ):
                        raise ValueError
                except (KeyError, TypeError, ValueError, RuntimeError, RecursionError):
                    continue
                self._connection.execute(
                    """
                    UPDATE publication_events
                    SET repository_id = ?
                    WHERE publication_key = ? AND repository_id IS NULL
                    """,
                    (sources[0].repository_id, candidate["publication_key"]),
                )
            last_first_event_id = int(candidates[-1]["first_event_id"])

    def _audit_draft_event_ledgers(self) -> None:
        """Reject legacy draft histories that current recovery cannot trust."""

        audits = (
            (
                """
                WITH ordered AS (
                    SELECT draft_key, phase, occurred_at,
                           ROW_NUMBER() OVER (
                               PARTITION BY draft_key
                               ORDER BY prevention_event_id
                           ) AS position,
                           LAG(phase) OVER (
                               PARTITION BY draft_key
                               ORDER BY prevention_event_id
                           ) AS prior_phase,
                           LAG(occurred_at) OVER (
                               PARTITION BY draft_key
                               ORDER BY prevention_event_id
                           ) AS prior_occurred_at
                    FROM prevention_draft_events AS event
                    WHERE NOT EXISTS (
                        SELECT 1
                        FROM prevention_legacy_candidate_events AS legacy
                        WHERE legacy.prevention_event_id = event.prevention_event_id
                    )
                )
                SELECT draft_key FROM ordered
                WHERE (position = 1 AND phase != 'validated')
                   OR (position > 1 AND NOT (
                       (prior_phase = 'validated' AND phase IN (
                           'pushed', 'draft_opened', 'abandoned'
                       ))
                       OR (prior_phase = 'pushed' AND phase IN (
                           'draft_opened', 'abandoned'
                       ))
                   ))
                   OR prior_occurred_at > occurred_at
                LIMIT 1
                """,
                "Prevention draft ledger has an invalid legacy phase sequence.",
            ),
            (
                """
                WITH ordered AS (
                    SELECT draft_key, phase, occurred_at,
                           ROW_NUMBER() OVER (
                               PARTITION BY draft_key
                               ORDER BY remediation_event_id
                           ) AS position,
                           LAG(phase) OVER (
                               PARTITION BY draft_key
                               ORDER BY remediation_event_id
                           ) AS prior_phase,
                           LAG(occurred_at) OVER (
                               PARTITION BY draft_key
                               ORDER BY remediation_event_id
                           ) AS prior_occurred_at
                    FROM remediation_draft_events
                )
                SELECT draft_key FROM ordered
                WHERE (position = 1 AND phase != 'validated')
                   OR (position > 1 AND NOT (
                       (prior_phase = 'validated' AND phase IN (
                           'pushed', 'abandoned'
                       ))
                       OR (prior_phase = 'pushed' AND phase IN (
                           'draft_opened', 'abandoned'
                       ))
                   ))
                   OR prior_occurred_at > occurred_at
                LIMIT 1
                """,
                "Remediation draft ledger has an invalid legacy phase sequence.",
            ),
            (
                """
                WITH first_ids AS (
                    SELECT candidate.draft_key,
                           MIN(candidate.prevention_event_id) AS first_id
                    FROM prevention_draft_events AS candidate
                    WHERE NOT EXISTS (
                        SELECT 1
                        FROM prevention_legacy_candidate_events AS legacy
                        WHERE legacy.prevention_event_id =
                              candidate.prevention_event_id
                    )
                    GROUP BY candidate.draft_key
                )
                SELECT event.draft_key
                FROM prevention_draft_events AS event
                JOIN first_ids USING (draft_key)
                JOIN prevention_draft_events AS first
                  ON first.prevention_event_id = first_ids.first_id
                WHERE NOT EXISTS (
                    SELECT 1
                    FROM prevention_legacy_candidate_events AS legacy
                    WHERE legacy.prevention_event_id = event.prevention_event_id
                )
                  AND event.prevention_event_id != first.prevention_event_id
                  AND (
                      event.run_id IS NOT first.run_id
                      OR event.source_repository IS NOT first.source_repository
                      OR event.target_repository IS NOT first.target_repository
                      OR event.target_base_branch IS NOT first.target_base_branch
                      OR event.target_base_sha IS NOT first.target_base_sha
                      OR event.push_repository IS NOT first.push_repository
                      OR event.branch IS NOT first.branch
                      OR event.candidate_sha IS NOT first.candidate_sha
                      OR event.evidence_hash IS NOT first.evidence_hash
                      OR event.title IS NOT first.title
                      OR event.body IS NOT first.body
                  )
                LIMIT 1
                """,
                "Prevention draft ledger has conflicting legacy identity.",
            ),
            (
                """
                WITH first_ids AS (
                    SELECT draft_key, MIN(remediation_event_id) AS first_id
                    FROM remediation_draft_events GROUP BY draft_key
                )
                SELECT event.draft_key
                FROM remediation_draft_events AS event
                JOIN first_ids USING (draft_key)
                JOIN remediation_draft_events AS first
                  ON first.remediation_event_id = first_ids.first_id
                WHERE event.remediation_event_id != first.remediation_event_id
                  AND (
                      event.branch_identity_version
                          IS NOT first.branch_identity_version
                      OR event.run_id IS NOT first.run_id
                      OR event.target_repository IS NOT first.target_repository
                      OR event.target_repository_id
                          IS NOT first.target_repository_id
                      OR event.target_base_branch
                          IS NOT first.target_base_branch
                      OR event.target_base_sha IS NOT first.target_base_sha
                      OR event.push_repository IS NOT first.push_repository
                      OR event.push_repository_id
                          IS NOT first.push_repository_id
                      OR event.branch IS NOT first.branch
                      OR event.candidate_sha IS NOT first.candidate_sha
                      OR event.evidence_hash IS NOT first.evidence_hash
                      OR event.batch_hash IS NOT first.batch_hash
                      OR event.source_pulls_json IS NOT first.source_pulls_json
                      OR event.event_revision_ids_json
                          IS NOT first.event_revision_ids_json
                      OR event.title IS NOT first.title
                      OR event.body IS NOT first.body
                  )
                LIMIT 1
                """,
                "Remediation draft ledger has conflicting legacy identity.",
            ),
            (
                """
                SELECT event.draft_key
                FROM prevention_draft_events AS event
                LEFT JOIN runs AS run ON run.run_id = event.run_id
                WHERE NOT EXISTS (
                    SELECT 1
                    FROM prevention_legacy_candidate_events AS legacy
                    WHERE legacy.prevention_event_id = event.prevention_event_id
                )
                  AND (
                      run.run_id IS NULL
                      OR run.repository IS NOT event.source_repository
                      OR run.mode IS NOT 'propose-prevention'
                  )
                LIMIT 1
                """,
                "Prevention draft ledger has invalid legacy run authority.",
            ),
            (
                """
                SELECT event.draft_key
                FROM remediation_draft_events AS event
                LEFT JOIN runs AS run ON run.run_id = event.run_id
                WHERE run.run_id IS NULL
                   OR run.repository IS NOT event.target_repository
                   OR run.mode NOT IN (
                       'apply-owned-translations', 'propose-prevention'
                   )
                LIMIT 1
                """,
                "Remediation draft ledger has invalid legacy run authority.",
            ),
            (
                """
                SELECT event.draft_key
                FROM remediation_draft_events AS event
                JOIN remediation_resolution_events AS resolution
                  ON resolution.draft_key = event.draft_key
                WHERE event.occurred_at > resolution.occurred_at
                LIMIT 1
                """,
                "Remediation draft ledger appended after a legacy resolution.",
            ),
        )
        for query, message in audits:
            if self._connection.execute(query).fetchone() is not None:
                raise RuntimeError(message)

    def _verify_database_integrity(self) -> None:
        """Perform bounded-output SQLite integrity checks before runtime."""

        if self._connection.execute("PRAGMA foreign_key_check").fetchone() is not None:
            raise RuntimeError("Guardian state database has a foreign-key violation.")
        row = self._connection.execute("PRAGMA quick_check(1)").fetchone()
        if row is None or len(row) != 1 or row[0] != "ok":
            raise RuntimeError("Guardian state database failed SQLite quick_check.")

    def _migrate_legacy_remediation_coverage(self) -> None:
        """Attest only legacy draft relationships recoverable from exact ledgers."""

        migrated_at = _now()
        last_event_id = 0
        while True:
            rows = self._connection.execute(
                """
                WITH latest AS (
                    SELECT draft.*,
                           ROW_NUMBER() OVER (
                               PARTITION BY draft_key
                               ORDER BY remediation_event_id DESC
                           ) AS guardian_row_number
                    FROM remediation_draft_events AS draft
                )
                SELECT latest.*,
                       checkpoint.occurred_at AS checkpoint_occurred_at,
                       resolution.resolution AS legacy_resolution,
                       resolution.occurred_at AS resolution_occurred_at
                FROM latest
                LEFT JOIN remediation_checkpoint_events AS checkpoint
                  ON checkpoint.draft_key = latest.draft_key
                LEFT JOIN remediation_resolution_events AS resolution
                  ON resolution.draft_key = latest.draft_key
                WHERE latest.guardian_row_number = 1
                  AND latest.remediation_event_id > ?
                  AND (
                      checkpoint.draft_key IS NOT NULL
                      OR resolution.draft_key IS NOT NULL
                  )
                ORDER BY latest.remediation_event_id
                LIMIT 100
                """,
                (last_event_id,),
            ).fetchall()
            if not rows:
                return
            for row in rows:
                self._migrate_legacy_remediation_coverage_row(
                    row=row,
                    migrated_at=migrated_at,
                )
            last_event_id = int(rows[-1]["remediation_event_id"])

    def _migrate_legacy_remediation_coverage_row(
        self,
        *,
        row: sqlite3.Row,
        migrated_at: datetime,
    ) -> None:
        """Migrate one bounded legacy remediation relationship."""

        draft = self._remediation_from_row(row)
        legacy_resolution = (
            None if row["legacy_resolution"] is None else str(row["legacy_resolution"])
        )
        migration_times = [migrated_at, draft.occurred_at]
        for column in ("checkpoint_occurred_at", "resolution_occurred_at"):
            if row[column] is not None:
                parsed = _parse_datetime(str(row[column]))
                if parsed is None:
                    raise RuntimeError(
                        "Legacy remediation ledger has a malformed timestamp."
                    )
                migration_times.append(parsed)
        coverage_at = max(migration_times)
        if legacy_resolution != "operator_quarantined":
            # A legacy checkpoint or merge does not prove which authority
            # snapshot justified its completion.  Leaving the completion
            # without coverage keeps it ineffective and, critically, lets
            # a later v5 run add a freshly attested coverage generation.
            return
        for source in draft.source_pulls:
            revision_ids = self._event_revision_ids_for_source_drafts(
                source=source,
                draft_keys=(draft.draft_key,),
                require_opened=False,
            )
            try:
                completion_id = self._completion_id_for_source(source)
            except RuntimeError:
                self._record_historical_pull_completion_in_transaction(
                    source=source,
                    event_revision_ids=revision_ids,
                    completed_at=coverage_at,
                )
                completion_id = self._completion_id_for_source(source)
            completion = self._connection.execute(
                """
                SELECT completed_at FROM historical_pull_completions
                WHERE completion_id = ?
                """,
                (completion_id,),
            ).fetchone()
            completion_at = (
                None
                if completion is None
                else _parse_datetime(str(completion["completed_at"]))
            )
            if completion_at is None:
                raise RuntimeError(
                    "Legacy remediation completion has a malformed timestamp."
                )
            self._record_remediation_coverage_group_in_transaction(
                completion_id=completion_id,
                authority_digest=source.authority_digest,
                reason=RemediationCoverageReason.MIGRATED_LEGACY,
                draft_keys=(draft.draft_key,),
                required_edit_hashes=(),
                occurred_at=max(coverage_at, completion_at),
            )

    def record_feedback_event(
        self,
        event: FeedbackEvent,
        *,
        observed_at: datetime | None = None,
    ) -> EventRevision:
        """Record a new immutable revision, or return an exact existing duplicate."""

        if event.pr_number <= 0:
            raise ValueError("pr_number must be positive.")
        observed = _serialize_datetime(observed_at or _now())
        body_hash = _body_hash(event.body)
        revision_hash = _revision_hash(event)
        identity_prefix = (
            event.repository,
            event.pr_number,
            event.kind,
            event.event_id,
        )
        identity_suffix = (event.head_sha, event.base_sha)
        identity = (*identity_prefix, revision_hash, *identity_suffix)

        with self._connection:
            row = self._connection.execute(
                """
                SELECT revision_id, author, author_id, author_type, locale, body_hash
                FROM event_revisions
                WHERE repository = ? AND pr_number = ? AND kind = ?
                  AND event_id = ? AND revision_hash = ? AND head_sha = ?
                  AND base_sha = ?
                """,
                identity,
            ).fetchone()
            if row is None:
                legacy_identity = (
                    *identity_prefix,
                    _legacy_revision_hash(event),
                    *identity_suffix,
                )
                legacy_row = self._connection.execute(
                    """
                    SELECT revision_id, author, author_id, author_type, locale, body_hash
                    FROM event_revisions
                    WHERE repository = ? AND pr_number = ? AND kind = ?
                      AND event_id = ? AND revision_hash = ? AND head_sha = ?
                      AND base_sha = ?
                    """,
                    legacy_identity,
                ).fetchone()
                if legacy_row is not None and (
                    int(legacy_row["author_id"]),
                    legacy_row["author_type"],
                    legacy_row["locale"],
                    legacy_row["body_hash"],
                ) == (
                    event.author_id,
                    event.author_type,
                    event.locale,
                    body_hash,
                ):
                    row = legacy_row
            is_new = False
            if row is None:
                cursor = self._connection.execute(
                    """
                    INSERT OR IGNORE INTO event_revisions (
                        repository, pr_number, kind, event_id, revision_hash,
                        head_sha, base_sha, author, author_id, author_type,
                        locale, body_hash, event_updated_at, path, line, html_url,
                        deleted, observed_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    identity
                    + (
                        event.author,
                        event.author_id,
                        event.author_type,
                        event.locale,
                        body_hash,
                        event.updated_at,
                        event.path,
                        event.line,
                        event.html_url,
                        int(event.deleted),
                        observed,
                    ),
                )
                is_new = cursor.rowcount == 1
                row = self._connection.execute(
                    """
                    SELECT revision_id
                    FROM event_revisions
                    WHERE repository = ? AND pr_number = ? AND kind = ?
                      AND event_id = ? AND revision_hash = ? AND head_sha = ?
                      AND base_sha = ?
                    """,
                    identity,
                ).fetchone()
            if row is None:  # pragma: no cover - protected by the transaction
                raise RuntimeError("Unable to read the recorded event revision.")
            revision_id = int(row["revision_id"])
            self._connection.execute(
                """
                INSERT OR IGNORE INTO event_raw_bodies (
                    event_revision_id, body, observed_at
                ) VALUES (?, ?, ?)
                """,
                (revision_id, event.body, observed),
            )
            raw_body = self._connection.execute(
                """
                SELECT body
                FROM event_raw_bodies
                WHERE event_revision_id = ?
                """,
                (revision_id,),
            ).fetchone()
            if raw_body is None or raw_body["body"] != event.body:
                raise RuntimeError("Event raw body identity collision.")
            self._connection.execute(
                """
                UPDATE event_raw_bodies
                SET observed_at = CASE
                    WHEN observed_at < ? THEN ?
                    ELSE observed_at
                END
                WHERE event_revision_id = ?
                """,
                (observed, observed, revision_id),
            )
            current = self._connection.execute(
                """
                SELECT event_revision_id
                FROM event_current_observations
                WHERE repository = ? AND pr_number = ? AND kind = ?
                  AND event_id = ?
                ORDER BY observation_id DESC
                LIMIT 1
                """,
                identity_prefix,
            ).fetchone()
            if current is None or int(current["event_revision_id"]) != revision_id:
                self._connection.execute(
                    """
                    INSERT INTO event_current_observations (
                        repository, pr_number, kind, event_id,
                        event_revision_id, observed_at
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (*identity_prefix, revision_id, observed),
                )

        revision = self.get_event_revision(revision_id)
        if revision is None:  # pragma: no cover - the row was read in this transaction
            raise RuntimeError("Recorded event revision disappeared.")
        return EventRevision(**{**revision.__dict__, "is_new": is_new})

    def get_event_revision(self, revision_id: int) -> EventRevision | None:
        """Return one revision; its raw body is None after retention cleanup."""

        row = self._connection.execute(
            """
            SELECT e.*, b.body
            FROM event_revisions AS e
            LEFT JOIN event_raw_bodies AS b
              ON b.event_revision_id = e.revision_id
            WHERE e.revision_id = ?
            """,
            (revision_id,),
        ).fetchone()
        if row is None:
            return None
        return self._event_revision_from_row(row)

    def pending_event_revisions(
        self,
        *,
        repository: str | None = None,
        pr_number: int | None = None,
        locale: str | None = None,
        mode: GuardianMode | str | None = None,
        policy_digest: str | None = None,
        limit: int = _MAX_PENDING_EVENT_WORKSET,
    ) -> tuple[EventRevision, ...]:
        """Return a bounded unresolved workset, oldest first.

        A prior lower-authority run must not suppress work after an operator
        explicitly escalates the configured mode. Passing no mode preserves the
        all-terminal-actions view used by audit callers. Callers terminalize a
        returned page before requesting the next one; this method never claims
        the returned tuple is the complete durable authority set.
        """

        if (
            isinstance(limit, bool)
            or not isinstance(limit, int)
            or not 1 <= limit <= _MAX_PENDING_EVENT_WORKSET
        ):
            raise ValueError("limit must be an integer from 1 through 500.")
        if pr_number is not None and (
            isinstance(pr_number, bool)
            or not isinstance(pr_number, int)
            or pr_number <= 0
        ):
            raise ValueError("pr_number must be a positive integer.")

        if policy_digest is not None and not re.fullmatch(
            r"[0-9a-f]{64}", policy_digest
        ):
            raise ValueError("policy_digest must be a lowercase SHA-256 digest.")
        terminal_statuses = tuple(sorted(_TERMINAL_ACTION_STATUSES))
        terminal_placeholders = ", ".join("?" for _ in terminal_statuses)
        parameters: list[Any] = list(terminal_statuses)
        if mode is None:
            mode_filter = ""
        else:
            requested_mode = GuardianMode(mode)
            resolving_modes = _MODE_RESOLUTION_AUTHORITY[requested_mode]
            placeholders = ", ".join("?" for _ in resolving_modes)
            mode_filter = f" AND r.mode IN ({placeholders})"
            parameters.extend(item.value for item in resolving_modes)
        policy_filter = ""
        if policy_digest is not None:
            policy_filter = """ AND (
                a.status != 'skipped'
                OR json_extract(a.details_json, '$.outcome')
                    IS NOT 'deterministic_policy_rejection'
                OR json_extract(a.details_json, '$.policy_digest') IS ?
            )"""
            parameters.append(policy_digest)
        filters = [
            f"""NOT EXISTS (
                SELECT 1 FROM actions AS a
                JOIN runs AS r ON r.run_id = a.run_id
                WHERE a.event_revision_id = e.revision_id
                  AND a.status IN ({terminal_placeholders})
                  {mode_filter}
                  {policy_filter}
            )"""
        ]
        if repository is not None:
            filters.append("e.repository = ?")
            parameters.append(repository)
        if pr_number is not None:
            filters.append("e.pr_number = ?")
            parameters.append(pr_number)
        if locale is not None:
            filters.append("e.locale = ?")
            parameters.append(locale)
        rows = self._connection.execute(
            f"""
            SELECT e.*, b.body
            FROM event_revisions AS e
            LEFT JOIN event_raw_bodies AS b
              ON b.event_revision_id = e.revision_id
            WHERE {" AND ".join(filters)}
            ORDER BY e.revision_id
            LIMIT ?
            """,
            (*parameters, limit),
        ).fetchall()
        return tuple(self._event_revision_from_row(row) for row in rows)

    def latest_event_revisions(
        self,
        *,
        repository: str | None = None,
        pr_number: int | None = None,
    ) -> tuple[EventRevision, ...]:
        """Return a complete, defensively bounded current feedback authority."""

        if pr_number is not None and (
            repository is None
            or isinstance(pr_number, bool)
            or not isinstance(pr_number, int)
            or pr_number <= 0
        ):
            raise ValueError(
                "pr_number requires a repository and must be a positive integer."
            )
        authority_bound = (
            _MAX_CURRENT_FEEDBACK_PER_PULL
            if pr_number is not None
            else _MAX_CURRENT_FEEDBACK_PER_REPOSITORY
        )

        filters: list[str] = []
        parameters: list[Any] = []
        if repository is not None:
            filters.append("observation.repository = ?")
            parameters.append(repository)
        if pr_number is not None:
            filters.append("observation.pr_number = ?")
            parameters.append(pr_number)
        observation_where = "WHERE " + " AND ".join(filters) if filters else ""
        rows = self._connection.execute(
            f"""
            SELECT e.*, b.body
            FROM (
                SELECT observation.event_revision_id, observation.repository,
                       observation.pr_number, observation.kind,
                       observation.event_id,
                       ROW_NUMBER() OVER (
                           PARTITION BY repository, pr_number, kind, event_id
                           ORDER BY observation_id DESC
                       ) AS guardian_row_number
                FROM event_current_observations AS observation
                {observation_where}
            ) AS latest
            JOIN event_revisions AS e
              ON e.revision_id = latest.event_revision_id
             AND e.repository = latest.repository
             AND e.pr_number = latest.pr_number
             AND e.kind = latest.kind
             AND e.event_id = latest.event_id
            LEFT JOIN event_raw_bodies AS b
              ON b.event_revision_id = e.revision_id
            WHERE latest.guardian_row_number = 1
            ORDER BY e.repository, e.pr_number, e.kind, e.event_id
            LIMIT ?
            """,
            (*parameters, authority_bound + 1),
        ).fetchall()
        if len(rows) > authority_bound:
            raise RuntimeError("Stored current feedback authority exceeds its bound.")
        return tuple(self._event_revision_from_row(row) for row in rows)

    @staticmethod
    def _validate_historical_pull_identity(
        *,
        repository: str,
        repository_id: int,
        pull_id: int,
        pull_revision_digest: str,
        policy_digest: str,
        authority_scope: HistoricalCheckScope | str,
        head_sha: str | None = None,
        base_sha: str | None = None,
        pr_number: int | None = None,
    ) -> HistoricalCheckScope:
        if (
            not isinstance(repository, str)
            or not _REPOSITORY_RE.fullmatch(repository)
            or any(component in {".", ".."} for component in repository.split("/"))
        ):
            raise ValueError("repository must use canonical owner/name form.")
        for field, value in (
            ("repository_id", repository_id),
            ("pull_id", pull_id),
            ("pr_number", pr_number),
        ):
            if value is not None and (
                isinstance(value, bool) or not isinstance(value, int) or value <= 0
            ):
                raise ValueError(f"{field} must be a positive integer.")
        if not isinstance(pull_revision_digest, str) or not _SHA256_RE.fullmatch(
            pull_revision_digest
        ):
            raise ValueError("pull_revision_digest must be a SHA-256 digest.")
        if not isinstance(policy_digest, str) or not _SHA256_RE.fullmatch(
            policy_digest
        ):
            raise ValueError("policy_digest must be a SHA-256 digest.")
        for field, value in (("head_sha", head_sha), ("base_sha", base_sha)):
            if value is not None and (
                not isinstance(value, str)
                or not re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", value)
            ):
                raise ValueError(f"{field} must be a full lowercase object ID.")
        try:
            return HistoricalCheckScope(authority_scope)
        except (TypeError, ValueError):
            raise ValueError(
                "authority_scope must be assessment, prevention, or remediation."
            ) from None

    def historical_pull_is_complete(
        self,
        *,
        repository: str,
        repository_id: int,
        pull_id: int,
        pull_revision_digest: str,
        policy_digest: str,
        authority_scope: HistoricalCheckScope | str,
    ) -> bool:
        """Return whether this exact historical pull was checked at this authority."""

        scope = self._validate_historical_pull_identity(
            repository=repository,
            repository_id=repository_id,
            pull_id=pull_id,
            pull_revision_digest=pull_revision_digest,
            policy_digest=policy_digest,
            authority_scope=authority_scope,
        )
        resolving_scopes = (
            (
                HistoricalCheckScope.ASSESSMENT.value,
                HistoricalCheckScope.PREVENTION.value,
            )
            if scope is HistoricalCheckScope.ASSESSMENT
            else (
                (HistoricalCheckScope.PREVENTION.value,)
                if scope is HistoricalCheckScope.PREVENTION
                else ()
            )
        )
        candidate_scopes = (
            *resolving_scopes,
            *(
                (HistoricalCheckScope.REMEDIATION.value,)
                if scope is not HistoricalCheckScope.PREVENTION
                else ()
            ),
        )
        for candidate_scope in candidate_scopes:
            current = self._connection.execute(
                """
                SELECT completion.completion_id,
                       completion.pull_revision_digest
                FROM (
                    SELECT *
                    FROM historical_pull_completion_observations
                    WHERE repository = ? AND repository_id = ? AND pull_id = ?
                      AND policy_digest = ? AND authority_scope = ?
                    ORDER BY observation_id DESC
                    LIMIT 1
                ) AS observation
                LEFT JOIN historical_pull_completions AS completion
                  ON completion.completion_id = observation.completion_id
                 AND completion.repository = observation.repository
                 AND completion.repository_id = observation.repository_id
                 AND completion.pull_id = observation.pull_id
                 AND completion.pr_number = observation.pr_number
                 AND completion.policy_digest = observation.policy_digest
                 AND completion.authority_scope = observation.authority_scope
                """,
                (
                    repository,
                    repository_id,
                    pull_id,
                    policy_digest,
                    candidate_scope,
                ),
            ).fetchone()
            if (
                current is None
                or current["completion_id"] is None
                or current["pull_revision_digest"] != pull_revision_digest
            ):
                continue
            if candidate_scope != HistoricalCheckScope.REMEDIATION.value:
                return True
            if self._remediation_completion_is_effective(
                completion_id=int(current["completion_id"])
            ):
                return True
        return False

    def record_historical_pull_completion(
        self,
        *,
        repository: str,
        repository_id: int,
        pull_id: int,
        pr_number: int,
        pull_revision_digest: str,
        policy_digest: str,
        head_sha: str,
        base_sha: str,
        event_revision_ids: Sequence[int] = (),
        ignored_event_revision_ids: Sequence[int] = (),
        authority_scope: HistoricalCheckScope | str,
        completed_at: datetime | None = None,
    ) -> bool:
        """Append one exact completion checkpoint, returning whether it was new."""

        return self._record_historical_pull_completion_impl(
            repository=repository,
            repository_id=repository_id,
            pull_id=pull_id,
            pr_number=pr_number,
            pull_revision_digest=pull_revision_digest,
            policy_digest=policy_digest,
            head_sha=head_sha,
            base_sha=base_sha,
            event_revision_ids=event_revision_ids,
            ignored_event_revision_ids=ignored_event_revision_ids,
            authority_scope=authority_scope,
            completed_at=completed_at,
            transaction_open=False,
        )

    def _record_historical_pull_completion_in_transaction(
        self,
        *,
        source: HistoricalPullReference,
        event_revision_ids: Sequence[int],
        completed_at: datetime,
    ) -> bool:
        """Insert one exact remediation completion inside the caller's transaction."""

        return self._record_historical_pull_completion_impl(
            repository=source.repository,
            repository_id=source.repository_id,
            pull_id=source.pull_id,
            pr_number=source.pr_number,
            pull_revision_digest=source.pull_revision_digest,
            policy_digest=source.policy_digest,
            head_sha=source.head_sha,
            base_sha=source.base_sha,
            event_revision_ids=event_revision_ids,
            ignored_event_revision_ids=(),
            authority_scope=HistoricalCheckScope.REMEDIATION,
            completed_at=completed_at,
            transaction_open=True,
        )

    def _record_historical_pull_completion_impl(
        self,
        *,
        repository: str,
        repository_id: int,
        pull_id: int,
        pr_number: int,
        pull_revision_digest: str,
        policy_digest: str,
        head_sha: str,
        base_sha: str,
        event_revision_ids: Sequence[int] = (),
        ignored_event_revision_ids: Sequence[int] = (),
        authority_scope: HistoricalCheckScope | str,
        completed_at: datetime | None = None,
        transaction_open: bool,
    ) -> bool:
        """Validate and append one exact completion checkpoint."""

        scope = self._validate_historical_pull_identity(
            repository=repository,
            repository_id=repository_id,
            pull_id=pull_id,
            pr_number=pr_number,
            pull_revision_digest=pull_revision_digest,
            policy_digest=policy_digest,
            head_sha=head_sha,
            base_sha=base_sha,
            authority_scope=authority_scope,
        )
        identity = (
            repository,
            repository_id,
            pull_id,
            pull_revision_digest,
            policy_digest,
            scope.value,
        )
        normalized_revision_ids = _bounded_sequence(
            event_revision_ids,
            limit=_MAX_CURRENT_FEEDBACK_PER_PULL,
            label="event_revision_ids",
        )
        normalized_ignored_revision_ids = _bounded_sequence(
            ignored_event_revision_ids,
            limit=_MAX_CURRENT_FEEDBACK_PER_PULL,
            label="ignored_event_revision_ids",
        )
        if (
            len(normalized_revision_ids) + len(normalized_ignored_revision_ids)
            > _MAX_CURRENT_FEEDBACK_PER_PULL
        ):
            raise ValueError(
                "Historical authority revisions exceed their bounded workset."
            )
        if any(
            len(set(values)) != len(values)
            or any(
                isinstance(value, bool)
                or not isinstance(value, int)
                or not 0 < value <= _SQLITE_MAX_INTEGER
                for value in values
            )
            for values in (
                normalized_revision_ids,
                normalized_ignored_revision_ids,
            )
        ):
            raise ValueError(
                "Historical authority revision IDs must be unique positive integers."
            )
        if set(normalized_revision_ids) & set(normalized_ignored_revision_ids):
            raise ValueError(
                "Selected and ignored historical authority revisions must be disjoint."
            )
        if (
            normalized_ignored_revision_ids
            and scope is not HistoricalCheckScope.ASSESSMENT
        ):
            raise ValueError(
                "Only an assessment completion may classify ignored authority."
            )
        normalized_revision_ids = tuple(sorted(normalized_revision_ids))
        normalized_ignored_revision_ids = tuple(sorted(normalized_ignored_revision_ids))
        authority_revision_ids = (
            normalized_revision_ids + normalized_ignored_revision_ids
        )
        if authority_revision_ids:
            revision_rows: list[sqlite3.Row] = []
            for offset in range(
                0,
                len(authority_revision_ids),
                _SQLITE_IN_QUERY_CHUNK,
            ):
                revision_chunk = authority_revision_ids[
                    offset : offset + _SQLITE_IN_QUERY_CHUNK
                ]
                placeholders = ", ".join("?" for _ in revision_chunk)
                revision_rows.extend(
                    self._connection.execute(
                        f"""
                        SELECT revision_id, repository, pr_number, head_sha, base_sha
                        FROM event_revisions
                        WHERE revision_id IN ({placeholders})
                        """,
                        revision_chunk,
                    ).fetchall()
                )
            if {int(row["revision_id"]) for row in revision_rows} != set(
                authority_revision_ids
            ) or any(
                (
                    row["repository"],
                    int(row["pr_number"]),
                    row["head_sha"],
                    row["base_sha"],
                )
                != (repository, pr_number, head_sha, base_sha)
                for row in revision_rows
            ):
                raise ValueError(
                    "event_revision_ids must match the exact historical pull snapshot."
                )
        revision_ids_json = json.dumps(normalized_revision_ids, separators=(",", ":"))
        ignored_revision_ids_json = json.dumps(
            normalized_ignored_revision_ids,
            separators=(",", ":"),
        )
        if any(
            len(value.encode("ascii")) > _MAX_PREVENTION_SOURCE_JSON_BYTES
            for value in (revision_ids_json, ignored_revision_ids_json)
        ):
            raise ValueError(
                "Historical authority revisions exceed their canonical byte bound."
            )
        observation_at = _serialize_datetime(completed_at or _now())
        transaction = nullcontext() if transaction_open else self._connection
        with transaction:
            self._connection.execute(
                """
                INSERT OR IGNORE INTO historical_pull_identities (
                    repository, repository_id, pull_id, pr_number, first_seen_at
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (
                    repository,
                    repository_id,
                    pull_id,
                    pr_number,
                    observation_at,
                ),
            )
            mapped = self._connection.execute(
                """
                SELECT pull_id, pr_number
                FROM historical_pull_identities
                WHERE repository = ? AND repository_id = ?
                  AND (pull_id = ? OR pr_number = ?)
                """,
                (repository, repository_id, pull_id, pr_number),
            ).fetchall()
            if len(mapped) != 1 or (
                int(mapped[0]["pull_id"]),
                int(mapped[0]["pr_number"]),
            ) != (pull_id, pr_number):
                raise RuntimeError("Historical pull identity collision.")
            existing = self._connection.execute(
                """
                SELECT completion_id, pr_number, head_sha, base_sha,
                       event_revision_ids_json,
                       ignored_event_revision_ids_json
                FROM historical_pull_completions
                WHERE repository = ? AND repository_id = ? AND pull_id = ?
                  AND pull_revision_digest = ? AND policy_digest = ?
                  AND authority_scope = ?
                """,
                identity,
            ).fetchone()
            if existing is not None:
                if (
                    int(existing["pr_number"]),
                    existing["head_sha"],
                    existing["base_sha"],
                    existing["event_revision_ids_json"],
                    existing["ignored_event_revision_ids_json"],
                ) != (
                    pr_number,
                    head_sha,
                    base_sha,
                    revision_ids_json,
                    ignored_revision_ids_json,
                ):
                    raise RuntimeError("Historical pull completion identity collision.")
                self._record_historical_completion_observation_in_transaction(
                    completion_id=int(existing["completion_id"]),
                    repository=repository,
                    repository_id=repository_id,
                    pull_id=pull_id,
                    pr_number=pr_number,
                    policy_digest=policy_digest,
                    authority_scope=scope.value,
                    observed_at=observation_at,
                )
                return False
            watermark_row = self._connection.execute(
                """
                SELECT COALESCE(MAX(revision_id), 0) AS revision_watermark
                FROM event_revisions
                WHERE repository = ? AND pr_number = ?
                """,
                (repository, pr_number),
            ).fetchone()
            if (
                watermark_row is None
            ):  # pragma: no cover - aggregate always returns a row
                raise RuntimeError("Unable to bind historical completion evidence.")
            event_revision_watermark = int(watermark_row["revision_watermark"])
            cursor = self._connection.execute(
                """
                INSERT OR IGNORE INTO historical_pull_completions (
                    repository, repository_id, pull_id, pr_number,
                    pull_revision_digest, policy_digest, authority_scope,
                    completed_at, head_sha, base_sha, event_revision_ids_json,
                    ignored_event_revision_ids_json,
                    event_revision_watermark
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    repository,
                    repository_id,
                    pull_id,
                    pr_number,
                    pull_revision_digest,
                    policy_digest,
                    scope.value,
                    observation_at,
                    head_sha,
                    base_sha,
                    revision_ids_json,
                    ignored_revision_ids_json,
                    event_revision_watermark,
                ),
            )
            row = self._connection.execute(
                """
                SELECT completion_id, pr_number, head_sha, base_sha,
                       event_revision_ids_json,
                       ignored_event_revision_ids_json,
                       event_revision_watermark
                FROM historical_pull_completions
                WHERE repository = ? AND repository_id = ? AND pull_id = ?
                  AND pull_revision_digest = ? AND policy_digest = ?
                  AND authority_scope = ?
                """,
                identity,
            ).fetchone()
            if row is None or (
                int(row["pr_number"]),
                row["head_sha"],
                row["base_sha"],
                row["event_revision_ids_json"],
                row["ignored_event_revision_ids_json"],
                int(row["event_revision_watermark"]),
            ) != (
                pr_number,
                head_sha,
                base_sha,
                revision_ids_json,
                ignored_revision_ids_json,
                event_revision_watermark,
            ):
                raise RuntimeError("Historical pull completion identity collision.")
            self._record_historical_completion_observation_in_transaction(
                completion_id=int(row["completion_id"]),
                repository=repository,
                repository_id=repository_id,
                pull_id=pull_id,
                pr_number=pr_number,
                policy_digest=policy_digest,
                authority_scope=scope.value,
                observed_at=observation_at,
            )
        return cursor.rowcount == 1

    def _record_historical_completion_observation_in_transaction(
        self,
        *,
        completion_id: int,
        repository: str,
        repository_id: int,
        pull_id: int,
        pr_number: int,
        policy_digest: str,
        authority_scope: str,
        observed_at: str,
    ) -> None:
        """Point one historical identity at the completion observed most recently."""

        latest = self._connection.execute(
            """
            SELECT completion_id
            FROM historical_pull_completion_observations
            WHERE repository = ? AND repository_id = ? AND pull_id = ?
              AND pr_number = ? AND policy_digest = ? AND authority_scope = ?
            ORDER BY observation_id DESC
            LIMIT 1
            """,
            (
                repository,
                repository_id,
                pull_id,
                pr_number,
                policy_digest,
                authority_scope,
            ),
        ).fetchone()
        if latest is not None and int(latest["completion_id"]) == completion_id:
            return
        self._connection.execute(
            """
            INSERT INTO historical_pull_completion_observations (
                repository, repository_id, pull_id, pr_number,
                policy_digest, authority_scope, completion_id, observed_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                repository,
                repository_id,
                pull_id,
                pr_number,
                policy_digest,
                authority_scope,
                completion_id,
                observed_at,
            ),
        )

    @staticmethod
    def _normalized_coverage_draft_keys(
        *,
        reason: RemediationCoverageReason,
        draft_keys: Sequence[str],
    ) -> tuple[str, ...]:
        normalized = tuple(draft_keys)
        if (
            len(normalized) > _MAX_REMEDIATION_SOURCE_COVERAGE_MEMBERS
            or any(
                not isinstance(draft_key, str) or not _SHA256_RE.fullmatch(draft_key)
                for draft_key in normalized
            )
            or len(set(normalized)) != len(normalized)
            or tuple(sorted(normalized)) != normalized
        ):
            raise ValueError(
                "coverage draft keys must be sorted, distinct SHA-256 digests "
                "with at most 100 members."
            )
        kind = _remediation_coverage_kind(reason)
        if (kind == "independent") != (not normalized):
            raise ValueError(
                "Independent coverage has no drafts; draft-backed coverage "
                "requires at least one draft."
            )
        return normalized

    @staticmethod
    def _normalized_required_edit_hashes(
        values: Sequence[str],
        *,
        required: bool,
    ) -> tuple[str, ...]:
        normalized = tuple(values)
        if (
            len(normalized) > _MAX_REMEDIATION_EDIT_HASHES
            or any(
                not isinstance(edit_hash, str) or not _SHA256_RE.fullmatch(edit_hash)
                for edit_hash in normalized
            )
            or len(set(normalized)) != len(normalized)
            or tuple(sorted(normalized)) != normalized
            or (required and not normalized)
        ):
            qualifier = "non-empty " if required else ""
            raise ValueError(
                f"required edit hashes must be a bounded {qualifier}sorted set "
                "of SHA-256 digests."
            )
        return normalized

    def _insert_remediation_coverage_members_in_transaction(
        self,
        *,
        coverage_group_id: int,
        draft_keys: Sequence[str],
    ) -> None:
        self._connection.executemany(
            """
            INSERT INTO remediation_source_coverage_members (
                coverage_group_id, member_position, draft_key
            ) VALUES (?, ?, ?)
            """,
            (
                (coverage_group_id, position, draft_key)
                for position, draft_key in enumerate(draft_keys)
            ),
        )

    def _insert_remediation_required_edits_in_transaction(
        self,
        *,
        coverage_group_id: int,
        required_edit_hashes: Sequence[str],
    ) -> None:
        self._connection.executemany(
            """
            INSERT INTO remediation_source_required_edit_events (
                coverage_group_id, member_position, edit_hash
            ) VALUES (?, ?, ?)
            """,
            (
                (coverage_group_id, position, edit_hash)
                for position, edit_hash in enumerate(required_edit_hashes)
            ),
        )

    def _record_remediation_coverage_group_in_transaction(
        self,
        *,
        completion_id: int,
        authority_digest: str,
        reason: RemediationCoverageReason | str,
        draft_keys: Sequence[str],
        required_edit_hashes: Sequence[str],
        occurred_at: datetime,
    ) -> tuple[int, bool]:
        normalized_reason = _remediation_coverage_reason(reason)
        if (
            not isinstance(authority_digest, str)
            or not _SHA256_RE.fullmatch(authority_digest)
            or (
                authority_digest == _LEGACY_UNATTESTED_AUTHORITY_DIGEST
                and normalized_reason
                not in {
                    RemediationCoverageReason.MIGRATED_LEGACY,
                    RemediationCoverageReason.OPERATOR_QUARANTINED,
                }
            )
        ):
            raise ValueError("Coverage requires an attested source authority digest.")
        normalized_keys = self._normalized_coverage_draft_keys(
            reason=normalized_reason,
            draft_keys=draft_keys,
        )
        required_hashes = self._normalized_required_edit_hashes(
            required_edit_hashes,
            required=(kind := _remediation_coverage_kind(normalized_reason))
            == "draft_backed"
            and normalized_reason
            not in {
                RemediationCoverageReason.OPERATOR_QUARANTINED,
                RemediationCoverageReason.MIGRATED_LEGACY,
            },
        )
        occurred = _serialize_datetime(occurred_at)
        completion = self._connection.execute(
            """
            SELECT completed_at, authority_scope
            FROM historical_pull_completions
            WHERE completion_id = ?
            """,
            (completion_id,),
        ).fetchone()
        if completion is None or completion["authority_scope"] != "remediation":
            raise ValueError("Coverage requires one exact remediation completion.")
        completed_at = _parse_datetime(completion["completed_at"])
        if completed_at is None or _parse_datetime(occurred) < completed_at:
            raise ValueError(
                "Coverage occurred_at must not precede its remediation completion."
            )
        latest = self._connection.execute(
            """
            SELECT occurred_at
            FROM remediation_source_coverage_groups
            WHERE completion_id = ?
            ORDER BY coverage_group_id DESC
            LIMIT 1
            """,
            (completion_id,),
        ).fetchone()
        if latest is not None:
            latest_at = _parse_datetime(latest["occurred_at"])
            if latest_at is None or _parse_datetime(occurred) < latest_at:
                raise ValueError(
                    "Coverage occurred_at must be monotonic for its completion."
                )
        existing_authorities = self._connection.execute(
            """
            SELECT DISTINCT authority_digest
            FROM remediation_source_coverage_groups
            WHERE completion_id = ?
            """,
            (completion_id,),
        ).fetchall()
        if any(
            row["authority_digest"] != authority_digest for row in existing_authorities
        ):
            raise RuntimeError(
                "Remediation source authority digest identity collision."
            )
        canonical_hash = _remediation_coverage_hash(
            kind=kind,
            reason=normalized_reason,
            draft_keys=normalized_keys,
            required_edit_hashes=required_hashes,
            authority_digest=authority_digest,
        )
        existing = self._connection.execute(
            """
            SELECT coverage_group_id, authority_digest, kind, reason,
                   member_count, occurred_at
            FROM remediation_source_coverage_groups
            WHERE completion_id = ? AND canonical_hash = ?
            """,
            (completion_id, canonical_hash),
        ).fetchone()
        if existing is not None:
            if (
                existing["kind"],
                existing["reason"],
                int(existing["member_count"]),
                existing["authority_digest"],
            ) != (
                kind,
                normalized_reason.value,
                len(normalized_keys),
                authority_digest,
            ):
                raise RuntimeError("Remediation source coverage identity collision.")
            return int(existing["coverage_group_id"]), False
        count_row = self._connection.execute(
            """
            SELECT COUNT(*) AS group_count
            FROM remediation_source_coverage_groups
            WHERE completion_id = ?
            """,
            (completion_id,),
        ).fetchone()
        if (
            count_row is None
            or int(count_row["group_count"]) >= _MAX_REMEDIATION_SOURCE_COVERAGE_GROUPS
        ):
            raise RuntimeError(
                "Remediation source coverage group count reached its safety bound."
            )
        cursor = self._connection.execute(
            """
            INSERT INTO remediation_source_coverage_groups (
                completion_id, authority_digest, kind, reason,
                canonical_hash, member_count, occurred_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                completion_id,
                authority_digest,
                kind,
                normalized_reason.value,
                canonical_hash,
                len(normalized_keys),
                occurred,
            ),
        )
        group_id = int(cursor.lastrowid)
        self._insert_remediation_coverage_members_in_transaction(
            coverage_group_id=group_id,
            draft_keys=normalized_keys,
        )
        self._insert_remediation_required_edits_in_transaction(
            coverage_group_id=group_id,
            required_edit_hashes=required_hashes,
        )
        return group_id, True

    def _completion_id_for_source(
        self,
        source: HistoricalPullReference,
    ) -> int:
        row = self._connection.execute(
            """
            SELECT completion_id
            FROM historical_pull_completions
            WHERE repository = ? AND repository_id = ? AND pull_id = ?
              AND pr_number = ? AND pull_revision_digest = ?
              AND policy_digest = ? AND authority_scope = 'remediation'
              AND head_sha = ? AND base_sha = ?
            """,
            (
                source.repository,
                source.repository_id,
                source.pull_id,
                source.pr_number,
                source.pull_revision_digest,
                source.policy_digest,
                source.head_sha,
                source.base_sha,
            ),
        ).fetchone()
        if row is None:
            raise RuntimeError("Exact remediation completion disappeared.")
        return int(row["completion_id"])

    def _coverage_group_from_row(
        self,
        row: sqlite3.Row,
    ) -> RemediationSourceCoverageGroup:
        try:
            reason = _remediation_coverage_reason(str(row["reason"]))
            kind = str(row["kind"])
            member_count = int(row["member_count"])
            group_id = int(row["coverage_group_id"])
            completion_id = int(row["completion_id"])
            occurred_at = _parse_datetime(row["coverage_occurred_at"])
            completion_at = _parse_datetime(row["completion_completed_at"])
            source = HistoricalPullReference(
                repository=str(row["repository"]),
                repository_id=int(row["repository_id"]),
                pull_id=int(row["pull_id"]),
                pr_number=int(row["pr_number"]),
                pull_revision_digest=str(row["pull_revision_digest"]),
                authority_digest=str(row["authority_digest"]),
                policy_digest=str(row["policy_digest"]),
                head_sha=str(row["head_sha"]),
                base_sha=str(row["base_sha"]),
            )
        except (KeyError, TypeError, ValueError):
            raise RuntimeError(
                "Remediation source coverage ledger is malformed."
            ) from None
        members = self._connection.execute(
            """
            SELECT member_position, draft_key
            FROM remediation_source_coverage_members
            WHERE coverage_group_id = ?
            ORDER BY member_position
            LIMIT ?
            """,
            (
                group_id,
                _MAX_REMEDIATION_SOURCE_COVERAGE_MEMBERS + 1,
            ),
        ).fetchall()
        draft_keys = tuple(str(member["draft_key"]) for member in members)
        positions = tuple(int(member["member_position"]) for member in members)
        required_rows = self._connection.execute(
            """
            SELECT member_position, edit_hash
            FROM remediation_source_required_edit_events
            WHERE coverage_group_id = ?
            ORDER BY member_position
            LIMIT ?
            """,
            (group_id, _MAX_REMEDIATION_EDIT_HASHES + 1),
        ).fetchall()
        required_edit_hashes = tuple(
            str(required["edit_hash"]) for required in required_rows
        )
        required_positions = tuple(
            int(required["member_position"]) for required in required_rows
        )
        expected_kind = _remediation_coverage_kind(reason)
        canonical_hash = str(row["canonical_hash"])
        authority_rows = self._connection.execute(
            """
            SELECT DISTINCT authority_digest
            FROM remediation_source_coverage_groups
            WHERE completion_id = ?
            LIMIT 2
            """,
            (completion_id,),
        ).fetchall()
        if (
            occurred_at is None
            or completion_at is None
            or occurred_at < completion_at
            or kind != expected_kind
            or not 0 <= member_count <= _MAX_REMEDIATION_SOURCE_COVERAGE_MEMBERS
            or len(members) != member_count
            or positions != tuple(range(member_count))
            or len(set(draft_keys)) != len(draft_keys)
            or tuple(sorted(draft_keys)) != draft_keys
            or any(not _SHA256_RE.fullmatch(key) for key in draft_keys)
            or len(required_rows) > _MAX_REMEDIATION_EDIT_HASHES
            or required_positions != tuple(range(len(required_rows)))
            or len(set(required_edit_hashes)) != len(required_edit_hashes)
            or tuple(sorted(required_edit_hashes)) != required_edit_hashes
            or any(
                not _SHA256_RE.fullmatch(edit_hash)
                for edit_hash in required_edit_hashes
            )
            or (kind == "independent") != (member_count == 0)
            or (kind == "independent" and bool(required_edit_hashes))
            or tuple(str(authority["authority_digest"]) for authority in authority_rows)
            != (source.authority_digest,)
            or (
                source.authority_digest == _LEGACY_UNATTESTED_AUTHORITY_DIGEST
                and reason
                not in {
                    RemediationCoverageReason.MIGRATED_LEGACY,
                    RemediationCoverageReason.OPERATOR_QUARANTINED,
                }
            )
            or canonical_hash
            != _remediation_coverage_hash(
                kind=kind,
                reason=reason,
                draft_keys=draft_keys,
                required_edit_hashes=required_edit_hashes,
                authority_digest=source.authority_digest,
            )
        ):
            raise RuntimeError("Remediation source coverage ledger is malformed.")
        effective = (
            kind == "independent"
            and source.authority_digest != _LEGACY_UNATTESTED_AUTHORITY_DIGEST
        )
        if kind == "draft_backed":
            covered_edit_hashes: set[str] = set()
            effective = bool(required_edit_hashes) or reason in {
                RemediationCoverageReason.OPERATOR_QUARANTINED,
                RemediationCoverageReason.MIGRATED_LEGACY,
            }
            for draft_key in draft_keys:
                draft = self.remediation_draft_by_key(draft_key=draft_key)
                if draft is None or occurred_at < draft.occurred_at:
                    raise RuntimeError(
                        "Remediation source coverage ledger is malformed."
                    )
                covered_edit_hashes.update(draft.edit_hashes)
                if (
                    draft.target_repository != source.repository
                    or draft.target_repository_id != source.repository_id
                    or (
                        reason is not RemediationCoverageReason.DRAFT_SEMANTIC_DEDUPE
                        and source not in draft.source_pulls
                    )
                ):
                    raise RuntimeError(
                        "Remediation source coverage ledger is malformed."
                    )
                if reason is RemediationCoverageReason.DRAFT_RECOVERED:
                    recovered_observation = self._connection.execute(
                        """
                        SELECT * FROM remediation_remote_observation_events
                        WHERE draft_key = ? AND observation = 'exact'
                          AND occurred_at <= ?
                        ORDER BY observation_id DESC
                        LIMIT 1
                        """,
                        (draft_key, _serialize_datetime(occurred_at)),
                    ).fetchone()
                    if recovered_observation is None:
                        raise RuntimeError(
                            "Remediation source coverage ledger is malformed."
                        )
                    self._remote_observation_from_row(recovered_observation)
                resolution = self.remediation_resolution(draft_key=draft_key)
                if resolution == "operator_quarantined":
                    member_effective = True
                elif (
                    resolution == "merged"
                    or source.authority_digest == _LEGACY_UNATTESTED_AUTHORITY_DIGEST
                ):
                    member_effective = False
                elif resolution is None and draft.phase == "draft_opened":
                    latest_remote = self.latest_remediation_remote_observation(
                        draft_key
                    )
                    member_effective = (
                        latest_remote is None or latest_remote.observation == "exact"
                    )
                else:
                    member_effective = False
                effective &= member_effective
            if reason is not RemediationCoverageReason.OPERATOR_QUARANTINED:
                effective &= set(required_edit_hashes) <= covered_edit_hashes
        return RemediationSourceCoverageGroup(
            coverage_group_id=group_id,
            completion_id=completion_id,
            source=source,
            kind=kind,
            reason=reason,
            draft_keys=draft_keys,
            required_edit_hashes=required_edit_hashes,
            member_count=member_count,
            canonical_hash=canonical_hash,
            occurred_at=occurred_at,
            effective=effective,
        )

    def _coverage_rows_for_completion(
        self,
        *,
        completion_id: int,
    ) -> tuple[sqlite3.Row, ...]:
        rows = self._connection.execute(
            """
            SELECT coverage.*, completion.repository,
                   completion.repository_id, completion.pull_id,
                   completion.pr_number, completion.pull_revision_digest,
                   completion.policy_digest, completion.head_sha,
                   completion.base_sha,
                   coverage.occurred_at AS coverage_occurred_at,
                   completion.completed_at AS completion_completed_at
            FROM remediation_source_coverage_groups AS coverage
            JOIN historical_pull_completions AS completion
              ON completion.completion_id = coverage.completion_id
            WHERE coverage.completion_id = ?
            ORDER BY coverage.coverage_group_id
            LIMIT ?
            """,
            (
                completion_id,
                _MAX_REMEDIATION_SOURCE_COVERAGE_GROUPS + 1,
            ),
        ).fetchall()
        if len(rows) > _MAX_REMEDIATION_SOURCE_COVERAGE_GROUPS:
            raise RuntimeError(
                "Remediation source coverage group count reached its safety bound."
            )
        return tuple(rows)

    def _remediation_completion_is_effective(self, *, completion_id: int) -> bool:
        groups = tuple(
            self._coverage_group_from_row(row)
            for row in self._coverage_rows_for_completion(completion_id=completion_id)
        )
        return any(group.effective for group in groups)

    def _event_revision_ids_for_source_drafts(
        self,
        *,
        source: HistoricalPullReference,
        draft_keys: Sequence[str],
        require_opened: bool,
        allow_merged: bool = False,
        require_exact_observation: bool = False,
        occurred_at: datetime | None = None,
    ) -> tuple[int, ...]:
        evidence_sets: list[tuple[int, ...]] = []
        for draft_key in draft_keys:
            draft = self.remediation_draft_by_key(draft_key=draft_key)
            if draft is None or source not in draft.source_pulls:
                raise ValueError(
                    "Every coverage draft must contain the exact source pull."
                )
            if require_opened:
                self._validate_draft_backed_coverage_member(
                    draft_key=draft_key,
                    source=source,
                    allow_merged=allow_merged,
                    require_exact_observation=require_exact_observation,
                    occurred_at=occurred_at,
                )
            matching_ids: list[int] = []
            for revision_id in draft.event_revision_ids:
                revision = self.get_event_revision(revision_id)
                if revision is None:
                    raise RuntimeError("Remediation draft evidence disappeared.")
                if (
                    revision.repository,
                    revision.pr_number,
                    revision.head_sha,
                    revision.base_sha,
                ) == (
                    source.repository,
                    source.pr_number,
                    source.head_sha,
                    source.base_sha,
                ):
                    matching_ids.append(revision_id)
            evidence_sets.append(tuple(sorted(matching_ids)))
        if not evidence_sets or any(
            evidence != evidence_sets[0] for evidence in evidence_sets[1:]
        ):
            raise ValueError("Coverage drafts disagree on the exact source evidence.")
        return evidence_sets[0]

    def _validate_draft_backed_coverage_member(
        self,
        *,
        draft_key: str,
        source: HistoricalPullReference,
        allow_merged: bool,
        require_exact_observation: bool,
        occurred_at: datetime | None = None,
    ) -> RemediationDraftRecord:
        draft = self.remediation_draft_by_key(draft_key=draft_key)
        resolution = self.remediation_resolution(draft_key=draft_key)
        if (
            draft is None
            or draft.phase != "draft_opened"
            or (
                resolution is not None and not (allow_merged and resolution == "merged")
            )
        ):
            raise ValueError(
                "Draft-backed completion requires an eligible opened remediation draft."
            )
        if (
            draft.target_repository != source.repository
            or draft.target_repository_id != source.repository_id
        ):
            raise ValueError(
                "Coverage draft must match the source repository identity."
            )
        if occurred_at is not None and occurred_at < draft.occurred_at:
            raise ValueError("Coverage occurred_at must not precede its opened draft.")
        if require_exact_observation:
            observation = self.latest_remediation_remote_observation(draft_key)
            if observation is None or observation.observation != "exact":
                raise ValueError(
                    "Recovered draft coverage requires an exact remote observation."
                )
            if (resolution == "merged") != (observation.is_merged is True):
                raise RuntimeError(
                    "Remediation remote lifecycle and resolution disagree."
                )
            if occurred_at is not None and occurred_at < observation.occurred_at:
                raise ValueError(
                    "Coverage occurred_at must not precede its exact remote observation."
                )
        else:
            observation = self.latest_remediation_remote_observation(draft_key)
            if observation is not None and observation.observation in {
                "not_found",
                "conflict",
            }:
                raise ValueError(
                    "Draft-backed coverage is blocked by unresolved remote "
                    "lifecycle evidence."
                )
        return draft

    def _coverage_record_by_id(
        self,
        *,
        coverage_group_id: int,
    ) -> RemediationSourceCoverageGroup:
        row = self._connection.execute(
            """
            SELECT coverage.*, completion.repository,
                   completion.repository_id, completion.pull_id,
                   completion.pr_number, completion.pull_revision_digest,
                   completion.policy_digest, completion.head_sha,
                   completion.base_sha,
                   coverage.occurred_at AS coverage_occurred_at,
                   completion.completed_at AS completion_completed_at
            FROM remediation_source_coverage_groups AS coverage
            JOIN historical_pull_completions AS completion
              ON completion.completion_id = coverage.completion_id
            WHERE coverage.coverage_group_id = ?
            """,
            (coverage_group_id,),
        ).fetchone()
        if row is None:
            raise RuntimeError("Remediation source coverage group disappeared.")
        return self._coverage_group_from_row(row)

    def record_independent_remediation_completion(
        self,
        source: HistoricalPullReference,
        reason: RemediationCoverageReason | str,
        *,
        event_revision_ids: Sequence[int] = (),
        occurred_at: datetime | None = None,
    ) -> RemediationSourceCoverageGroup:
        """Atomically attest a completion that needs no correction draft."""

        if not isinstance(source, HistoricalPullReference):
            raise TypeError("source must be a HistoricalPullReference.")
        if source.authority_digest == _LEGACY_UNATTESTED_AUTHORITY_DIGEST:
            raise ValueError("Independent remediation requires attested authority.")
        normalized_reason = _remediation_coverage_reason(reason)
        if normalized_reason not in _INDEPENDENT_REMEDIATION_REASONS:
            raise ValueError("Independent remediation reason is required.")
        occurred = occurred_at or _now()
        _serialize_datetime(occurred)
        with self._connection:
            self._record_historical_pull_completion_in_transaction(
                source=source,
                event_revision_ids=event_revision_ids,
                completed_at=occurred,
            )
            group_id, _created = self._record_remediation_coverage_group_in_transaction(
                completion_id=self._completion_id_for_source(source),
                authority_digest=source.authority_digest,
                reason=normalized_reason,
                draft_keys=(),
                required_edit_hashes=(),
                occurred_at=occurred,
            )
            record = self._coverage_record_by_id(coverage_group_id=group_id)
        return record

    def record_draft_backed_remediation_completions(
        self,
        coverage_by_source: Mapping[
            HistoricalPullReference,
            Sequence[str],
        ],
        reason: RemediationCoverageReason | str,
        *,
        required_edit_hashes_by_source: Mapping[
            HistoricalPullReference,
            Sequence[str],
        ],
        event_revision_ids_by_source: Mapping[
            HistoricalPullReference,
            Sequence[int],
        ]
        | None = None,
        checkpoint_draft_key: str | None = None,
        occurred_at: datetime | None = None,
    ) -> tuple[RemediationSourceCoverageGroup, ...]:
        """Atomically attest exact per-source progress through signed drafts."""

        normalized_reason = _remediation_coverage_reason(reason)
        if (
            normalized_reason not in _DRAFT_BACKED_REMEDIATION_REASONS
            or normalized_reason
            in {
                RemediationCoverageReason.OPERATOR_QUARANTINED,
                RemediationCoverageReason.MIGRATED_LEGACY,
            }
        ):
            raise ValueError("A publication draft-backed reason is required.")
        items = tuple(coverage_by_source.items())
        if (
            not items
            or len(items) > _MAX_REMEDIATION_SOURCE_COVERAGE_MEMBERS
            or any(
                not isinstance(source, HistoricalPullReference)
                or source.authority_digest == _LEGACY_UNATTESTED_AUTHORITY_DIGEST
                for source, _draft_keys in items
            )
        ):
            raise ValueError(
                "coverage_by_source must contain 1 through 100 exact sources."
            )
        if not isinstance(required_edit_hashes_by_source, Mapping) or set(
            required_edit_hashes_by_source
        ) != {source for source, _draft_keys in items}:
            raise ValueError(
                "required_edit_hashes_by_source must map every exact source."
            )
        items = tuple(
            sorted(
                items,
                key=lambda item: (
                    item[0].repository,
                    item[0].repository_id,
                    item[0].pull_id,
                    item[0].pr_number,
                    item[0].pull_revision_digest,
                    item[0].policy_digest,
                ),
            )
        )
        if normalized_reason is RemediationCoverageReason.DRAFT_SEMANTIC_DEDUPE:
            if not isinstance(event_revision_ids_by_source, Mapping) or set(
                event_revision_ids_by_source
            ) != {source for source, _draft_keys in items}:
                raise ValueError(
                    "Semantic-dedupe coverage requires exact event revisions "
                    "for every source."
                )
        elif event_revision_ids_by_source is not None:
            raise ValueError(
                "event_revision_ids_by_source is only valid for semantic dedupe."
            )
        occurred = occurred_at or _now()
        _serialize_datetime(occurred)
        normalized_items: list[
            tuple[
                HistoricalPullReference,
                tuple[str, ...],
                tuple[str, ...],
                tuple[int, ...],
            ]
        ] = []
        all_draft_keys: set[str] = set()
        for source, raw_draft_keys in items:
            draft_keys = self._normalized_coverage_draft_keys(
                reason=normalized_reason,
                draft_keys=tuple(raw_draft_keys),
            )
            required_edit_hashes = self._normalized_required_edit_hashes(
                tuple(required_edit_hashes_by_source[source]),
                required=True,
            )
            if normalized_reason is RemediationCoverageReason.DRAFT_SEMANTIC_DEDUPE:
                for draft_key in draft_keys:
                    self._validate_draft_backed_coverage_member(
                        draft_key=draft_key,
                        source=source,
                        allow_merged=False,
                        require_exact_observation=False,
                        occurred_at=occurred,
                    )
                revision_ids = tuple(event_revision_ids_by_source[source])
                self.validate_historical_remediation_evidence(
                    source_pulls=(source,),
                    event_revision_ids=revision_ids,
                )
            else:
                revision_ids = self._event_revision_ids_for_source_drafts(
                    source=source,
                    draft_keys=draft_keys,
                    require_opened=True,
                    allow_merged=(
                        normalized_reason is RemediationCoverageReason.DRAFT_RECOVERED
                    ),
                    require_exact_observation=(
                        normalized_reason is RemediationCoverageReason.DRAFT_RECOVERED
                    ),
                    occurred_at=occurred,
                )
            normalized_items.append(
                (source, draft_keys, required_edit_hashes, revision_ids)
            )
            all_draft_keys.update(draft_keys)
        if checkpoint_draft_key is not None:
            if checkpoint_draft_key not in all_draft_keys:
                raise ValueError(
                    "checkpoint_draft_key must belong to this exact coverage."
                )
        group_ids: list[int] = []
        with self._connection:
            for (
                source,
                draft_keys,
                required_edit_hashes,
                revision_ids,
            ) in normalized_items:
                self._record_historical_pull_completion_in_transaction(
                    source=source,
                    event_revision_ids=revision_ids,
                    completed_at=occurred,
                )
                group_id, _created = (
                    self._record_remediation_coverage_group_in_transaction(
                        completion_id=self._completion_id_for_source(source),
                        authority_digest=source.authority_digest,
                        reason=normalized_reason,
                        draft_keys=draft_keys,
                        required_edit_hashes=required_edit_hashes,
                        occurred_at=occurred,
                    )
                )
                group_ids.append(group_id)
            if checkpoint_draft_key is not None:
                self._record_remediation_checkpoint_in_transaction(
                    draft_key=checkpoint_draft_key,
                    occurred_at=occurred,
                )
            records = tuple(
                self._coverage_record_by_id(coverage_group_id=group_id)
                for group_id in group_ids
            )
        return records

    def remediation_source_coverage_for_draft(
        self,
        draft_key: str,
        *,
        limit: int = 100,
    ) -> tuple[RemediationSourceCoverageGroup, ...]:
        """Return bounded exact source coverage groups linked to one draft."""

        if not isinstance(draft_key, str) or not _SHA256_RE.fullmatch(draft_key):
            raise ValueError("draft_key must be a SHA-256 digest.")
        if (
            isinstance(limit, bool)
            or not isinstance(limit, int)
            or not 1 <= limit <= 100
        ):
            raise ValueError("limit must be an integer from 1 through 100.")
        rows = self._connection.execute(
            """
            SELECT DISTINCT coverage.*, completion.repository,
                   completion.repository_id, completion.pull_id,
                   completion.pr_number, completion.pull_revision_digest,
                   completion.policy_digest, completion.head_sha,
                   completion.base_sha,
                   coverage.occurred_at AS coverage_occurred_at,
                   completion.completed_at AS completion_completed_at
            FROM remediation_source_coverage_members AS member
            JOIN remediation_source_coverage_groups AS coverage
              ON coverage.coverage_group_id = member.coverage_group_id
            JOIN historical_pull_completions AS completion
              ON completion.completion_id = coverage.completion_id
            WHERE member.draft_key = ?
            ORDER BY coverage.coverage_group_id
            LIMIT ?
            """,
            (draft_key, limit),
        ).fetchall()
        return tuple(self._coverage_group_from_row(row) for row in rows)

    def remediation_source_coverage_count_for_draft(self, draft_key: str) -> int:
        """Return the exact number of source coverage groups linked to a draft."""

        if not isinstance(draft_key, str) or not _SHA256_RE.fullmatch(draft_key):
            raise ValueError("draft_key must be a SHA-256 digest.")
        row = self._connection.execute(
            """
            SELECT COUNT(DISTINCT coverage_group_id) AS coverage_count
            FROM remediation_source_coverage_members
            WHERE draft_key = ?
            """,
            (draft_key,),
        ).fetchone()
        if row is None:  # pragma: no cover - aggregate always returns one row
            raise RuntimeError("Unable to count remediation source coverage.")
        return int(row["coverage_count"])

    @staticmethod
    def _validate_historical_discovery_identity(
        *,
        repository: str,
        repository_id: int,
        policy_digest: str,
    ) -> None:
        if (
            not isinstance(repository, str)
            or not _REPOSITORY_RE.fullmatch(repository)
            or any(component in {".", ".."} for component in repository.split("/"))
        ):
            raise ValueError("repository must use canonical owner/name form.")
        if (
            isinstance(repository_id, bool)
            or not isinstance(repository_id, int)
            or repository_id <= 0
        ):
            raise ValueError("repository_id must be a positive integer.")
        if not isinstance(policy_digest, str) or not _SHA256_RE.fullmatch(
            policy_digest
        ):
            raise ValueError("policy_digest must be a SHA-256 digest.")

    @staticmethod
    def _historical_discovery_cursor_from_row(
        row: sqlite3.Row,
    ) -> HistoricalDiscoveryCursor:
        cycle_started_at = _parse_datetime(row["cycle_started_at"])
        recorded_at = _parse_datetime(row["recorded_at"])
        if cycle_started_at is None or recorded_at is None:  # pragma: no cover
            raise RuntimeError("Historical discovery cursor has no timestamp.")
        return HistoricalDiscoveryCursor(
            cursor_id=int(row["cursor_id"]),
            repository=str(row["repository"]),
            repository_id=int(row["repository_id"]),
            policy_digest=str(row["policy_digest"]),
            cycle_id=str(row["cycle_id"]),
            cycle_started_at=cycle_started_at,
            next_page=int(row["next_page"]),
            next_offset=int(row["next_offset"]),
            cycle_complete=bool(row["cycle_complete"]),
            recorded_at=recorded_at,
        )

    @staticmethod
    def _validate_historical_cycle_id(cycle_id: str) -> None:
        try:
            parsed_cycle_id = UUID(cycle_id)
        except (AttributeError, TypeError, ValueError):
            raise ValueError("cycle_id must be a canonical UUID.") from None
        if str(parsed_cycle_id) != cycle_id:
            raise ValueError("cycle_id must be a canonical UUID.")

    def _active_historical_discovery_cursor(
        self,
        *,
        repository: str,
        repository_id: int,
        policy_digest: str,
        cycle_id: str,
    ) -> HistoricalDiscoveryCursor:
        row = self._connection.execute(
            """
            SELECT * FROM historical_discovery_cursor_events
            WHERE repository = ? AND repository_id = ? AND policy_digest = ?
            ORDER BY cursor_id DESC
            LIMIT 1
            """,
            (repository, repository_id, policy_digest),
        ).fetchone()
        if row is None:
            raise RuntimeError("Historical discovery cycle is not active.")
        cursor = self._historical_discovery_cursor_from_row(row)
        if cursor.cycle_id != cycle_id or cursor.cycle_complete:
            raise RuntimeError("Historical discovery cycle is not active.")
        return cursor

    def get_historical_discovery_cursor(
        self,
        *,
        repository: str,
        repository_id: int,
        policy_digest: str,
    ) -> HistoricalDiscoveryCursor | None:
        """Return the latest append-only cursor for one exact policy."""

        self._validate_historical_discovery_identity(
            repository=repository,
            repository_id=repository_id,
            policy_digest=policy_digest,
        )
        row = self._connection.execute(
            """
            SELECT * FROM historical_discovery_cursor_events
            WHERE repository = ? AND repository_id = ? AND policy_digest = ?
            ORDER BY cursor_id DESC
            LIMIT 1
            """,
            (repository, repository_id, policy_digest),
        ).fetchone()
        if row is None:
            return None
        return self._historical_discovery_cursor_from_row(row)

    def historical_cycle_seen_pulls(
        self,
        *,
        repository: str,
        repository_id: int,
        policy_digest: str,
        cycle_id: str,
    ) -> tuple[tuple[int, int], ...]:
        """Return exact pull identities already advanced in one active cycle."""

        self._validate_historical_discovery_identity(
            repository=repository,
            repository_id=repository_id,
            policy_digest=policy_digest,
        )
        self._validate_historical_cycle_id(cycle_id)
        self._active_historical_discovery_cursor(
            repository=repository,
            repository_id=repository_id,
            policy_digest=policy_digest,
            cycle_id=cycle_id,
        )
        rows = self._connection.execute(
            """
            SELECT pull_id, pr_number
            FROM historical_cycle_seen_pull_events
            WHERE repository = ? AND repository_id = ? AND policy_digest = ?
              AND cycle_id = ?
            ORDER BY seen_event_id
            """,
            (repository, repository_id, policy_digest, cycle_id),
        ).fetchall()
        return tuple((int(row["pull_id"]), int(row["pr_number"])) for row in rows)

    def record_historical_cycle_seen_pull(
        self,
        *,
        repository: str,
        repository_id: int,
        policy_digest: str,
        cycle_id: str,
        pull_id: int,
        pr_number: int,
        seen_at: datetime | None = None,
    ) -> None:
        """Append one exact pull identity advanced in the active scan cycle."""

        self._validate_historical_discovery_identity(
            repository=repository,
            repository_id=repository_id,
            policy_digest=policy_digest,
        )
        self._validate_historical_cycle_id(cycle_id)
        for field, value in (("pull_id", pull_id), ("pr_number", pr_number)):
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ValueError(f"{field} must be a positive integer.")
        seen = _serialize_datetime(seen_at or _now())
        identity = (repository, repository_id, policy_digest, cycle_id)
        with self._connection:
            active_cursor = self._active_historical_discovery_cursor(
                repository=repository,
                repository_id=repository_id,
                policy_digest=policy_digest,
                cycle_id=cycle_id,
            )
            if _parse_datetime(seen) < active_cursor.cycle_started_at:
                raise ValueError("seen_at must not precede cycle_started_at.")
            rows = self._connection.execute(
                """
                SELECT pull_id, pr_number
                FROM historical_cycle_seen_pull_events
                WHERE repository = ? AND repository_id = ? AND policy_digest = ?
                  AND cycle_id = ? AND (pull_id = ? OR pr_number = ?)
                """,
                (*identity, pull_id, pr_number),
            ).fetchall()
            if rows:
                if len(rows) == 1 and (
                    int(rows[0]["pull_id"]),
                    int(rows[0]["pr_number"]),
                ) == (pull_id, pr_number):
                    return
                raise RuntimeError("Historical cycle seen-pull identity collision.")
            count_row = self._connection.execute(
                """
                SELECT COUNT(*) AS seen_count
                FROM historical_cycle_seen_pull_events
                WHERE repository = ? AND repository_id = ? AND policy_digest = ?
                  AND cycle_id = ?
                """,
                identity,
            ).fetchone()
            if (
                count_row is None  # pragma: no cover - aggregate always returns a row
                or int(count_row["seen_count"]) >= _MAX_HISTORICAL_CYCLE_SEEN_PULLS
            ):
                raise RuntimeError(
                    "Historical cycle seen-pull count reached its safety bound."
                )
            try:
                self._connection.execute(
                    """
                    INSERT INTO historical_cycle_seen_pull_events (
                        repository, repository_id, policy_digest, cycle_id,
                        pull_id, pr_number, seen_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (*identity, pull_id, pr_number, seen),
                )
            except sqlite3.IntegrityError as exc:
                if "UNIQUE constraint failed" in str(exc):
                    raise RuntimeError(
                        "Historical cycle seen-pull identity collision."
                    ) from None
                raise

    def pending_historical_pull_retries(
        self,
        *,
        repository: str,
        repository_id: int,
        policy_digest: str,
    ) -> tuple[tuple[int, int], ...]:
        """Return bounded pull identities with an unresolved transient failure."""

        self._validate_historical_discovery_identity(
            repository=repository,
            repository_id=repository_id,
            policy_digest=policy_digest,
        )
        rows = self._connection.execute(
            """
            WITH latest AS (
                SELECT retry_event_id, repository, repository_id, policy_digest,
                       pull_id, pr_number, phase,
                       ROW_NUMBER() OVER (
                           PARTITION BY pull_id
                           ORDER BY retry_event_id DESC
                       ) AS guardian_row_number
                FROM historical_pull_retry_events
                WHERE repository = ? AND repository_id = ? AND policy_digest = ?
            )
            SELECT retry_event_id, pull_id, pr_number
            FROM latest
            WHERE guardian_row_number = 1 AND phase = 'pending'
              AND NOT EXISTS (
                  SELECT 1
                  FROM historical_pull_retry_resolution_events AS resolution
                  WHERE resolution.repository = latest.repository
                    AND resolution.repository_id = latest.repository_id
                    AND resolution.policy_digest = latest.policy_digest
                    AND resolution.pull_id = latest.pull_id
                    AND resolution.pr_number = latest.pr_number
              )
            ORDER BY retry_event_id, pull_id
            LIMIT ?
            """,
            (
                repository,
                repository_id,
                policy_digest,
                _MAX_HISTORICAL_PULL_RETRIES + 1,
            ),
        ).fetchall()
        if len(rows) > _MAX_HISTORICAL_PULL_RETRIES:
            raise RuntimeError("Historical pull retry count reached its safety bound.")
        identities = tuple((int(row["pull_id"]), int(row["pr_number"])) for row in rows)
        if len({pull_id for pull_id, _number in identities}) != len(identities) or len(
            {number for _pull_id, number in identities}
        ) != len(identities):
            raise RuntimeError("Historical pull retry identity collision.")
        return identities

    def pending_historical_pull_retry_records(
        self,
        *,
        limit: int = _MAX_OPERATOR_LIST_ROWS,
    ) -> tuple[HistoricalPullRetryRecord, ...]:
        """Return a bounded redacted worklist across repository policies."""

        if (
            isinstance(limit, bool)
            or not isinstance(limit, int)
            or not 1 <= limit <= _MAX_OPERATOR_LIST_ROWS
        ):
            raise ValueError("limit must be an integer from 1 through 100.")
        rows = self._connection.execute(
            """
            WITH latest AS (
                SELECT retry_event_id, repository, repository_id, policy_digest,
                       pull_id, pr_number, phase, failure_type, occurred_at,
                       ROW_NUMBER() OVER (
                           PARTITION BY repository, repository_id, policy_digest,
                                        pull_id
                           ORDER BY retry_event_id DESC
                       ) AS guardian_row_number
                FROM historical_pull_retry_events
            )
            SELECT retry_event_id, repository, repository_id, policy_digest,
                   pull_id, pr_number, failure_type, occurred_at
            FROM latest
            WHERE guardian_row_number = 1 AND phase = 'pending'
              AND NOT EXISTS (
                  SELECT 1
                  FROM historical_pull_retry_resolution_events AS resolution
                  WHERE resolution.repository = latest.repository
                    AND resolution.repository_id = latest.repository_id
                    AND resolution.policy_digest = latest.policy_digest
                    AND resolution.pull_id = latest.pull_id
                    AND resolution.pr_number = latest.pr_number
              )
            ORDER BY retry_event_id, repository, pull_id
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        records: list[HistoricalPullRetryRecord] = []
        for row in rows:
            occurred_at = _parse_datetime(row["occurred_at"])
            failure_type = row["failure_type"]
            repository = str(row["repository"])
            repository_id = int(row["repository_id"])
            policy_digest = str(row["policy_digest"])
            pull_id = int(row["pull_id"])
            pr_number = int(row["pr_number"])
            try:
                self._validate_historical_discovery_identity(
                    repository=repository,
                    repository_id=repository_id,
                    policy_digest=policy_digest,
                )
            except (TypeError, ValueError):
                raise RuntimeError("Historical pull retry ledger is malformed.")
            if (
                occurred_at is None
                or pull_id <= 0
                or pr_number <= 0
                or not isinstance(failure_type, str)
                or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.]{0,199}", failure_type)
            ):
                raise RuntimeError("Historical pull retry ledger is malformed.")
            records.append(
                HistoricalPullRetryRecord(
                    retry_event_id=int(row["retry_event_id"]),
                    repository=repository,
                    repository_id=repository_id,
                    policy_digest=policy_digest,
                    pull_id=pull_id,
                    pr_number=pr_number,
                    failure_type=failure_type,
                    occurred_at=occurred_at,
                )
            )
        return tuple(records)

    def pending_historical_pull_retry_count(self) -> int:
        """Return the exact number of unresolved historical hydration failures."""

        row = self._connection.execute(
            """
            WITH latest AS (
                SELECT repository, repository_id, policy_digest, pull_id,
                       pr_number, phase,
                       ROW_NUMBER() OVER (
                           PARTITION BY repository, repository_id, policy_digest,
                                        pull_id
                           ORDER BY retry_event_id DESC
                       ) AS guardian_row_number
                FROM historical_pull_retry_events
            )
            SELECT COUNT(*) AS retry_count
            FROM latest
            WHERE guardian_row_number = 1 AND phase = 'pending'
              AND NOT EXISTS (
                  SELECT 1
                  FROM historical_pull_retry_resolution_events AS resolution
                  WHERE resolution.repository = latest.repository
                    AND resolution.repository_id = latest.repository_id
                    AND resolution.policy_digest = latest.policy_digest
                    AND resolution.pull_id = latest.pull_id
                    AND resolution.pr_number = latest.pr_number
              )
            """
        ).fetchone()
        if row is None:  # pragma: no cover - aggregate always returns one row
            raise RuntimeError("Unable to count historical pull retries.")
        return int(row["retry_count"])

    def operator_quarantined_historical_pull_retries(
        self,
        *,
        repository: str,
        repository_id: int,
        policy_digest: str,
    ) -> tuple[tuple[int, int], ...]:
        """Return exact retry identities an operator permanently quarantined."""

        self._validate_historical_discovery_identity(
            repository=repository,
            repository_id=repository_id,
            policy_digest=policy_digest,
        )
        rows = self._connection.execute(
            """
            SELECT pull_id, pr_number
            FROM historical_pull_retry_resolution_events
            WHERE repository = ? AND repository_id = ? AND policy_digest = ?
              AND resolution = 'operator_quarantined'
            ORDER BY resolution_event_id, pull_id
            LIMIT ?
            """,
            (
                repository,
                repository_id,
                policy_digest,
                _MAX_HISTORICAL_PULL_RETRY_RESOLUTIONS + 1,
            ),
        ).fetchall()
        if len(rows) > _MAX_HISTORICAL_PULL_RETRY_RESOLUTIONS:
            raise RuntimeError(
                "Historical pull retry resolution count reached its safety bound."
            )
        identities = tuple((int(row["pull_id"]), int(row["pr_number"])) for row in rows)
        if len({pull_id for pull_id, _number in identities}) != len(identities) or len(
            {number for _pull_id, number in identities}
        ) != len(identities):
            raise RuntimeError("Historical pull retry resolution identity collision.")
        return identities

    def operator_quarantined_historical_pull_retry_count(self) -> int:
        """Return the number of permanent, policy-scoped source-PR vetoes."""

        row = self._connection.execute(
            """
            SELECT COUNT(*) AS resolution_count
            FROM historical_pull_retry_resolution_events
            WHERE resolution = 'operator_quarantined'
            """
        ).fetchone()
        if row is None:  # pragma: no cover - aggregate always returns one row
            raise RuntimeError("Unable to count historical pull retry resolutions.")
        return int(row["resolution_count"])

    def historical_pull_retry_resolution(
        self,
        *,
        repository: str,
        repository_id: int,
        policy_digest: str,
        pull_id: int,
        pr_number: int,
    ) -> str | None:
        """Return the terminal operator resolution for one exact retry."""

        self._validate_historical_discovery_identity(
            repository=repository,
            repository_id=repository_id,
            policy_digest=policy_digest,
        )
        for field, value in (("pull_id", pull_id), ("pr_number", pr_number)):
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ValueError(f"{field} must be a positive integer.")
        row = self._connection.execute(
            """
            SELECT resolution
            FROM historical_pull_retry_resolution_events
            WHERE repository = ? AND repository_id = ? AND policy_digest = ?
              AND pull_id = ? AND pr_number = ?
            """,
            (repository, repository_id, policy_digest, pull_id, pr_number),
        ).fetchone()
        return None if row is None else str(row["resolution"])

    def record_historical_pull_retry_resolution(
        self,
        *,
        repository: str,
        repository_id: int,
        policy_digest: str,
        pull_id: int,
        pr_number: int,
        resolution: str,
        terminal_local_skip_acknowledged: bool,
        occurred_at: datetime | None = None,
    ) -> bool:
        """Append an explicitly acknowledged terminal operator quarantine."""

        self._validate_historical_discovery_identity(
            repository=repository,
            repository_id=repository_id,
            policy_digest=policy_digest,
        )
        for field, value in (("pull_id", pull_id), ("pr_number", pr_number)):
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ValueError(f"{field} must be a positive integer.")
        if resolution != "operator_quarantined":
            raise ValueError("resolution must be operator_quarantined.")
        if terminal_local_skip_acknowledged is not True:
            raise ValueError(
                "terminal_local_skip_acknowledged must be explicitly true."
            )
        occurred = _serialize_datetime(occurred_at or _now())
        identity = (repository, repository_id, policy_digest, pull_id, pr_number)
        with self._connection:
            latest = self._connection.execute(
                """
                SELECT pr_number, phase, occurred_at
                FROM historical_pull_retry_events
                WHERE repository = ? AND repository_id = ? AND policy_digest = ?
                  AND pull_id = ?
                ORDER BY retry_event_id DESC
                LIMIT 1
                """,
                (repository, repository_id, policy_digest, pull_id),
            ).fetchone()
            if (
                latest is None
                or int(latest["pr_number"]) != pr_number
                or latest["phase"] != "pending"
            ):
                raise ValueError(
                    "operator quarantine requires one exact pending historical retry."
                )
            latest_at = _parse_datetime(latest["occurred_at"])
            if latest_at is None or _parse_datetime(occurred) < latest_at:
                raise ValueError(
                    "occurred_at must not precede the pending retry event."
                )
            existing = self._connection.execute(
                """
                SELECT resolution
                FROM historical_pull_retry_resolution_events
                WHERE repository = ? AND repository_id = ? AND policy_digest = ?
                  AND pull_id = ? AND pr_number = ?
                """,
                identity,
            ).fetchone()
            if existing is not None:
                if existing["resolution"] != resolution:
                    raise RuntimeError(
                        "Historical pull retry resolution identity collision."
                    )
                return False
            resolution_count = self._connection.execute(
                """
                SELECT COUNT(*) AS resolution_count
                FROM historical_pull_retry_resolution_events
                WHERE repository = ? AND repository_id = ? AND policy_digest = ?
                """,
                identity[:3],
            ).fetchone()
            if (
                resolution_count is None
                or int(resolution_count["resolution_count"])
                >= _MAX_HISTORICAL_PULL_RETRY_RESOLUTIONS
            ):
                raise RuntimeError(
                    "Historical pull retry resolution count reached its safety bound."
                )
            cursor = self._connection.execute(
                """
                INSERT OR IGNORE INTO historical_pull_retry_resolution_events (
                    repository, repository_id, policy_digest, pull_id, pr_number,
                    resolution, occurred_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (*identity, resolution, occurred),
            )
            row = self._connection.execute(
                """
                SELECT resolution
                FROM historical_pull_retry_resolution_events
                WHERE repository = ? AND repository_id = ? AND policy_digest = ?
                  AND pull_id = ? AND pr_number = ?
                """,
                identity,
            ).fetchone()
            if row is None or row["resolution"] != resolution:
                raise RuntimeError(
                    "Historical pull retry resolution identity collision."
                )
        return cursor.rowcount == 1

    def record_historical_pull_retry(
        self,
        *,
        repository: str,
        repository_id: int,
        policy_digest: str,
        pull_id: int,
        pr_number: int,
        failure_type: str,
        failed_at: datetime | None = None,
    ) -> bool:
        """Durably quarantine one pull until a later successful retry."""

        self._validate_historical_discovery_identity(
            repository=repository,
            repository_id=repository_id,
            policy_digest=policy_digest,
        )
        for field, value in (("pull_id", pull_id), ("pr_number", pr_number)):
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ValueError(f"{field} must be a positive integer.")
        if not isinstance(failure_type, str) or not re.fullmatch(
            r"[A-Za-z_][A-Za-z0-9_.]{0,199}", failure_type
        ):
            raise ValueError("failure_type must be a bounded exception name.")
        occurred = _serialize_datetime(failed_at or _now())
        identity = (repository, repository_id, policy_digest, pull_id)
        with self._connection:
            self._connection.execute(
                """
                INSERT OR IGNORE INTO historical_pull_identities (
                    repository, repository_id, pull_id, pr_number, first_seen_at
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (repository, repository_id, pull_id, pr_number, occurred),
            )
            mapped = self._connection.execute(
                """
                SELECT pull_id, pr_number
                FROM historical_pull_identities
                WHERE repository = ? AND repository_id = ?
                  AND (pull_id = ? OR pr_number = ?)
                """,
                (repository, repository_id, pull_id, pr_number),
            ).fetchall()
            if len(mapped) != 1 or (
                int(mapped[0]["pull_id"]),
                int(mapped[0]["pr_number"]),
            ) != (pull_id, pr_number):
                raise RuntimeError("Historical pull retry identity collision.")
            latest = self._connection.execute(
                """
                SELECT pr_number, phase, occurred_at
                FROM historical_pull_retry_events
                WHERE repository = ? AND repository_id = ? AND policy_digest = ?
                  AND pull_id = ?
                ORDER BY retry_event_id DESC
                LIMIT 1
                """,
                identity,
            ).fetchone()
            if latest is not None:
                if int(latest["pr_number"]) != pr_number:
                    raise RuntimeError("Historical pull retry identity collision.")
                if latest["phase"] == "pending":
                    return False
                latest_at = _parse_datetime(latest["occurred_at"])
                if latest_at is None or _parse_datetime(occurred) < latest_at:
                    raise ValueError(
                        "failed_at must not precede the latest retry event."
                    )
            pending_count = self._connection.execute(
                """
                WITH latest AS (
                    SELECT repository, repository_id, policy_digest, pull_id,
                           pr_number, phase,
                           ROW_NUMBER() OVER (
                               PARTITION BY pull_id
                               ORDER BY retry_event_id DESC
                           ) AS guardian_row_number
                    FROM historical_pull_retry_events
                    WHERE repository = ? AND repository_id = ? AND policy_digest = ?
                )
                SELECT COUNT(*) AS pending_count
                FROM latest
                WHERE guardian_row_number = 1 AND phase = 'pending'
                  AND NOT EXISTS (
                      SELECT 1
                      FROM historical_pull_retry_resolution_events AS resolution
                      WHERE resolution.repository = latest.repository
                        AND resolution.repository_id = latest.repository_id
                        AND resolution.policy_digest = latest.policy_digest
                        AND resolution.pull_id = latest.pull_id
                        AND resolution.pr_number = latest.pr_number
                  )
                """,
                (repository, repository_id, policy_digest),
            ).fetchone()
            if (
                pending_count is None  # pragma: no cover - aggregate returns one row
                or int(pending_count["pending_count"]) >= _MAX_HISTORICAL_PULL_RETRIES
            ):
                raise RuntimeError(
                    "Historical pull retry count reached its safety bound."
                )
            self._connection.execute(
                """
                INSERT INTO historical_pull_retry_events (
                    repository, repository_id, policy_digest, pull_id, pr_number,
                    phase, failure_type, occurred_at
                ) VALUES (?, ?, ?, ?, ?, 'pending', ?, ?)
                """,
                (*identity, pr_number, failure_type, occurred),
            )
        return True

    def resolve_historical_pull_retry(
        self,
        *,
        repository: str,
        repository_id: int,
        policy_digest: str,
        pull_id: int,
        pr_number: int,
        resolved_at: datetime | None = None,
    ) -> bool:
        """Resolve an existing transient-failure quarantine, if any."""

        self._validate_historical_discovery_identity(
            repository=repository,
            repository_id=repository_id,
            policy_digest=policy_digest,
        )
        for field, value in (("pull_id", pull_id), ("pr_number", pr_number)):
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ValueError(f"{field} must be a positive integer.")
        occurred = _serialize_datetime(resolved_at or _now())
        identity = (repository, repository_id, policy_digest, pull_id)
        with self._connection:
            latest = self._connection.execute(
                """
                SELECT pr_number, phase, occurred_at
                FROM historical_pull_retry_events
                WHERE repository = ? AND repository_id = ? AND policy_digest = ?
                  AND pull_id = ?
                ORDER BY retry_event_id DESC
                LIMIT 1
                """,
                identity,
            ).fetchone()
            if latest is None:
                return False
            if int(latest["pr_number"]) != pr_number:
                raise RuntimeError("Historical pull retry identity collision.")
            if latest["phase"] == "resolved":
                return False
            latest_at = _parse_datetime(latest["occurred_at"])
            if latest_at is None or _parse_datetime(occurred) < latest_at:
                raise ValueError("resolved_at must not precede the latest retry event.")
            self._connection.execute(
                """
                INSERT INTO historical_pull_retry_events (
                    repository, repository_id, policy_digest, pull_id, pr_number,
                    phase, failure_type, occurred_at
                ) VALUES (?, ?, ?, ?, ?, 'resolved', NULL, ?)
                """,
                (*identity, pr_number, occurred),
            )
        return True

    def record_historical_discovery_progress(
        self,
        *,
        repository: str,
        repository_id: int,
        policy_digest: str,
        cycle_id: str,
        cycle_started_at: datetime,
        next_page: int,
        next_offset: int,
        cycle_complete: bool,
        expected_cursor_id: int | None,
        recorded_at: datetime | None = None,
    ) -> HistoricalDiscoveryCursor:
        """Append one CAS-protected bounded scan position."""

        self._validate_historical_discovery_identity(
            repository=repository,
            repository_id=repository_id,
            policy_digest=policy_digest,
        )
        self._validate_historical_cycle_id(cycle_id)
        if (
            isinstance(next_page, bool)
            or not isinstance(next_page, int)
            or not 1 <= next_page <= _MAX_HISTORICAL_DISCOVERY_PAGE
        ):
            raise ValueError("next_page must be an integer between 1 and 2147483647.")
        if (
            isinstance(next_offset, bool)
            or not isinstance(next_offset, int)
            or not 0 <= next_offset < 100
        ):
            raise ValueError("next_offset must be an integer between 0 and 99.")
        if not isinstance(cycle_complete, bool):
            raise ValueError("cycle_complete must be a boolean.")
        if cycle_complete and (next_page, next_offset) != (1, 0):
            raise ValueError("a complete cycle must reset its next position.")
        if expected_cursor_id is not None and (
            isinstance(expected_cursor_id, bool)
            or not isinstance(expected_cursor_id, int)
            or expected_cursor_id <= 0
        ):
            raise ValueError("expected_cursor_id must be a positive integer or None.")
        cycle_started = _serialize_datetime(cycle_started_at)
        recorded = _serialize_datetime(recorded_at or _now())
        if _parse_datetime(recorded) < _parse_datetime(cycle_started):
            raise ValueError("recorded_at must not precede cycle_started_at.")

        with self._connection:
            current_row = self._connection.execute(
                """
                SELECT * FROM historical_discovery_cursor_events
                WHERE repository = ? AND repository_id = ? AND policy_digest = ?
                ORDER BY cursor_id DESC
                LIMIT 1
                """,
                (repository, repository_id, policy_digest),
            ).fetchone()
            current = (
                None
                if current_row is None
                else self._historical_discovery_cursor_from_row(current_row)
            )
            current_id = None if current is None else current.cursor_id
            if current_id != expected_cursor_id:
                raise RuntimeError("Historical discovery cursor CAS collision.")
            if current is not None:
                same_cycle = current.cycle_id == cycle_id
                if current.cycle_complete:
                    if same_cycle or (next_page, next_offset) != (1, 0):
                        raise ValueError(
                            "a completed historical cycle must restart at page 1."
                        )
                elif not same_cycle or current.cycle_started_at != _parse_datetime(
                    cycle_started
                ):
                    raise ValueError(
                        "an incomplete historical cycle must retain its identity."
                    )
                elif not cycle_complete and (
                    next_page,
                    next_offset,
                ) <= (current.next_page, current.next_offset):
                    raise ValueError(
                        "an incomplete historical cursor must move strictly forward."
                    )
            try:
                cursor = self._connection.execute(
                    """
                    INSERT INTO historical_discovery_cursor_events (
                        repository, repository_id, policy_digest, cycle_id,
                        cycle_started_at, next_page, next_offset, cycle_complete,
                        previous_cursor_id, recorded_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        repository,
                        repository_id,
                        policy_digest,
                        cycle_id,
                        cycle_started,
                        next_page,
                        next_offset,
                        int(cycle_complete),
                        expected_cursor_id,
                        recorded,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                if "UNIQUE constraint failed" in str(exc):
                    raise RuntimeError(
                        "Historical discovery cursor CAS collision."
                    ) from None
                raise
            row = self._connection.execute(
                "SELECT * FROM historical_discovery_cursor_events WHERE cursor_id = ?",
                (cursor.lastrowid,),
            ).fetchone()
        if row is None:  # pragma: no cover - same transaction inserted it
            raise RuntimeError("Historical discovery cursor disappeared.")
        return self._historical_discovery_cursor_from_row(row)

    def validate_historical_remediation_evidence(
        self,
        *,
        source_pulls: Sequence[HistoricalPullReference],
        event_revision_ids: Sequence[int],
        feedback_urls: Sequence[str] | None = None,
        replacements: Sequence[ProposedReplacement] | None = None,
    ) -> str:
        """Validate and hash exact assessed evidence before remediation work."""

        pulls = _bounded_sequence(
            source_pulls,
            limit=_MAX_REMEDIATION_SOURCE_PULLS,
            label="source_pulls",
        )
        if (
            not pulls
            or any(not isinstance(item, HistoricalPullReference) for item in pulls)
            or len(set(pulls)) != len(pulls)
            or len({item.pull_id for item in pulls}) != len(pulls)
            or len({item.pr_number for item in pulls}) != len(pulls)
            or len({item.policy_digest for item in pulls}) != 1
        ):
            raise ValueError("source_pulls must contain unique exact assessed pulls.")
        pulls = tuple(
            sorted(
                pulls,
                key=lambda item: (
                    item.repository,
                    item.repository_id,
                    item.pull_id,
                    item.pr_number,
                    item.pull_revision_digest,
                    item.policy_digest,
                    item.head_sha,
                    item.base_sha,
                ),
            )
        )
        revision_ids = _bounded_sequence(
            event_revision_ids,
            limit=_MAX_REMEDIATION_SOURCE_REVISIONS,
            label="event_revision_ids",
        )
        if (
            not revision_ids
            or len(set(revision_ids)) != len(revision_ids)
            or any(
                isinstance(value, bool)
                or not isinstance(value, int)
                or not 0 < value <= _SQLITE_MAX_INTEGER
                for value in revision_ids
            )
        ):
            raise ValueError("event_revision_ids must be unique positive integers.")
        revision_ids = tuple(sorted(revision_ids))

        source_by_pair: dict[
            tuple[str, int],
            tuple[HistoricalPullReference, frozenset[int]],
        ] = {}
        for source in pulls:
            mapping = self._connection.execute(
                """
                SELECT pull_id, pr_number FROM historical_pull_identities
                WHERE repository = ? AND repository_id = ?
                  AND (pull_id = ? OR pr_number = ?)
                """,
                (
                    source.repository,
                    source.repository_id,
                    source.pull_id,
                    source.pr_number,
                ),
            ).fetchall()
            if len(mapping) != 1 or (
                int(mapping[0]["pull_id"]),
                int(mapping[0]["pr_number"]),
            ) != (source.pull_id, source.pr_number):
                raise ValueError("source pull has no exact durable identity mapping.")
            assessment = self._connection.execute(
                f"""
                SELECT head_sha, base_sha,
                       CASE
                           WHEN typeof(event_revision_ids_json) = 'text'
                            AND length(CAST(event_revision_ids_json AS BLOB)) <=
                                {_MAX_PREVENTION_SOURCE_JSON_BYTES}
                           THEN event_revision_ids_json
                       END AS event_revision_ids_json
                FROM historical_pull_completions
                WHERE repository = ? AND repository_id = ? AND pull_id = ?
                  AND pr_number = ? AND pull_revision_digest = ?
                  AND policy_digest = ? AND authority_scope = 'assessment'
                """,
                (
                    source.repository,
                    source.repository_id,
                    source.pull_id,
                    source.pr_number,
                    source.pull_revision_digest,
                    source.policy_digest,
                ),
            ).fetchone()
            if assessment is None or (
                assessment["head_sha"],
                assessment["base_sha"],
            ) != (source.head_sha, source.base_sha):
                raise ValueError(
                    "source pull has no exact prior assessment completion."
                )
            assessed_revision_ids = _validated_revision_ids_json(
                assessment["event_revision_ids_json"],
                label="Historical assessment completion",
            )
            if len(assessed_revision_ids) > _MAX_CURRENT_FEEDBACK_PER_PULL:
                raise RuntimeError(
                    "Historical assessment completion exceeds its feedback bound."
                )
            source_by_pair[(source.repository, source.pr_number)] = (
                source,
                frozenset(assessed_revision_ids),
            )

        rows: list[sqlite3.Row] = []
        for offset in range(0, len(revision_ids), _SQLITE_IN_QUERY_CHUNK):
            revision_chunk = revision_ids[offset : offset + _SQLITE_IN_QUERY_CHUNK]
            placeholders = ", ".join("?" for _ in revision_chunk)
            rows.extend(
                self._connection.execute(
                    f"""
                    SELECT * FROM event_revisions
                    WHERE revision_id IN ({placeholders})
                    ORDER BY revision_id
                    """,
                    revision_chunk,
                ).fetchall()
            )
        rows.sort(key=lambda row: int(row["revision_id"]))
        if {int(row["revision_id"]) for row in rows} != set(revision_ids):
            raise ValueError("event_revision_ids contain an unknown revision.")
        seen_pairs: set[tuple[str, int]] = set()
        seen_revision_ids: dict[tuple[str, int], set[int]] = {
            pair: set() for pair in source_by_pair
        }
        feedback_by_id: dict[str, sqlite3.Row] = {}
        stored_urls: list[str] = []
        for row in rows:
            pair = (str(row["repository"]), int(row["pr_number"]))
            source_evidence = source_by_pair.get(pair)
            if source_evidence is None:
                raise ValueError(
                    "event revision does not match its exact assessed pull snapshot."
                )
            source, assessed_revision_ids = source_evidence
            if int(row["revision_id"]) not in assessed_revision_ids or (
                row["head_sha"],
                row["base_sha"],
            ) != (source.head_sha, source.base_sha):
                raise ValueError(
                    "event revision does not match its exact assessed pull snapshot."
                )
            if bool(row["deleted"]):
                raise ValueError("deleted feedback cannot authorize remediation.")
            feedback_id = f"{row['kind']}:{row['event_id']}"
            if feedback_id in feedback_by_id:
                raise ValueError(
                    "event revisions contain an ambiguous feedback identity."
                )
            url = row["html_url"]
            if not isinstance(url, str) or not url:
                raise ValueError("every remediation event must retain its exact URL.")
            feedback_by_id[feedback_id] = row
            stored_urls.append(url)
            seen_pairs.add(pair)
            seen_revision_ids[pair].add(int(row["revision_id"]))
        if seen_pairs != set(source_by_pair):
            raise ValueError("every source pull must have exact event evidence.")
        if any(
            seen_revision_ids[pair] != set(assessed_ids)
            for pair, (_source, assessed_ids) in source_by_pair.items()
        ):
            raise ValueError(
                "event revisions must exactly match each assessed pull snapshot."
            )
        if len(set(stored_urls)) != len(stored_urls):
            raise ValueError("remediation event URLs must be unique.")
        normalized_urls = tuple(sorted(stored_urls))
        if feedback_urls is not None:
            supplied_urls = tuple(feedback_urls)
            if (
                any(not isinstance(value, str) for value in supplied_urls)
                or len(set(supplied_urls)) != len(supplied_urls)
                or tuple(sorted(supplied_urls)) != normalized_urls
            ):
                raise ValueError("feedback_urls do not match exact stored event URLs.")

        if replacements is not None:
            proposals = tuple(replacements)
            if not proposals or any(
                not isinstance(item, ProposedReplacement) for item in proposals
            ):
                raise ValueError("replacements must contain proposed replacements.")
            for proposal in proposals:
                event = feedback_by_id.get(proposal.feedback_id)
                if event is None or event["locale"] != proposal.locale:
                    raise ValueError(
                        "replacement feedback_id does not match exact event evidence."
                    )
        return _historical_remediation_evidence_hash(
            pulls,
            normalized_urls,
        )

    def validate_current_historical_remediation_evidence(
        self,
        *,
        source_pulls: Sequence[HistoricalPullReference],
        event_revision_ids: Sequence[int],
        feedback_urls: Sequence[str] | None = None,
        replacements: Sequence[ProposedReplacement] | None = None,
    ) -> str:
        """Validate exact evidence is still current in the durable ledger."""

        pulls = tuple(source_pulls)
        revision_ids = tuple(event_revision_ids)
        evidence_hash = self.validate_historical_remediation_evidence(
            source_pulls=pulls,
            event_revision_ids=revision_ids,
            feedback_urls=feedback_urls,
            replacements=replacements,
        )
        revision_rows: list[sqlite3.Row] = []
        for offset in range(0, len(revision_ids), _SQLITE_IN_QUERY_CHUNK):
            revision_chunk = revision_ids[offset : offset + _SQLITE_IN_QUERY_CHUNK]
            placeholders = ", ".join("?" for _ in revision_chunk)
            revision_rows.extend(
                self._connection.execute(
                    f"""
                    SELECT current.revision_id, current.repository,
                           current.pr_number, current.deleted,
                           (
                               SELECT latest.event_revision_id
                               FROM event_current_observations AS latest
                               WHERE latest.repository = current.repository
                                 AND latest.pr_number = current.pr_number
                                 AND latest.kind = current.kind
                                 AND latest.event_id = current.event_id
                               ORDER BY latest.observation_id DESC
                               LIMIT 1
                           ) AS latest_revision_id
                    FROM event_revisions AS current
                    WHERE current.revision_id IN ({placeholders})
                    """,
                    revision_chunk,
                ).fetchall()
            )
        if any(
            bool(row["deleted"])
            or int(row["revision_id"]) != int(row["latest_revision_id"])
            for row in revision_rows
        ):
            raise ValueError("remediation evidence has a superseded event revision.")

        revision_ids_by_pull: dict[tuple[str, int], list[int]] = {}
        for row in revision_rows:
            revision_ids_by_pull.setdefault(
                (str(row["repository"]), int(row["pr_number"])),
                [],
            ).append(int(row["revision_id"]))

        for source in pulls:
            latest_assessment = self._connection.execute(
                f"""
                SELECT completion.pull_revision_digest,
                       completion.head_sha, completion.base_sha,
                       CASE
                           WHEN typeof(completion.event_revision_ids_json) = 'text'
                            AND length(CAST(
                                completion.event_revision_ids_json AS BLOB
                            )) <=
                                {_MAX_PREVENTION_SOURCE_JSON_BYTES}
                           THEN completion.event_revision_ids_json
                       END AS event_revision_ids_json,
                       CASE
                           WHEN typeof(
                               completion.ignored_event_revision_ids_json
                           ) = 'text'
                            AND length(CAST(
                                completion.ignored_event_revision_ids_json
                                AS BLOB
                            )) <= {_MAX_PREVENTION_SOURCE_JSON_BYTES}
                           THEN completion.ignored_event_revision_ids_json
                       END AS ignored_event_revision_ids_json,
                       completion.event_revision_watermark
                FROM (
                    SELECT *
                    FROM historical_pull_completion_observations
                    WHERE repository = ? AND repository_id = ? AND pull_id = ?
                      AND pr_number = ? AND policy_digest = ?
                      AND authority_scope = 'assessment'
                    ORDER BY observation_id DESC
                    LIMIT 1
                ) AS observation
                LEFT JOIN historical_pull_completions AS completion
                  ON completion.completion_id = observation.completion_id
                 AND completion.repository = observation.repository
                 AND completion.repository_id = observation.repository_id
                 AND completion.pull_id = observation.pull_id
                 AND completion.pr_number = observation.pr_number
                 AND completion.policy_digest = observation.policy_digest
                 AND completion.authority_scope = observation.authority_scope
                """,
                (
                    source.repository,
                    source.repository_id,
                    source.pull_id,
                    source.pr_number,
                    source.policy_digest,
                ),
            ).fetchone()
            if latest_assessment is None:
                raise ValueError("source pull has no latest assessment completion.")
            latest_ids = _validated_revision_ids_json(
                latest_assessment["event_revision_ids_json"],
                label="Historical assessment completion",
            )
            ignored_ids = _validated_revision_ids_json(
                latest_assessment["ignored_event_revision_ids_json"],
                label="Historical assessment ignored authority",
            )
            if (
                set(latest_ids) & set(ignored_ids)
                or len(latest_ids) + len(ignored_ids) > _MAX_CURRENT_FEEDBACK_PER_PULL
            ):
                raise RuntimeError(
                    "Historical assessment authority classifications are malformed."
                )
            expected_ids = tuple(
                sorted(
                    revision_ids_by_pull.get(
                        (source.repository, source.pr_number),
                        [],
                    )
                )
            )
            if (
                latest_assessment["pull_revision_digest"] != source.pull_revision_digest
                or latest_assessment["head_sha"] != source.head_sha
                or latest_assessment["base_sha"] != source.base_sha
                or latest_ids != expected_ids
            ):
                raise ValueError(
                    "source pull evidence is not its latest assessment completion."
                )
            current_rows = self._connection.execute(
                """
                SELECT revision.revision_id, revision.deleted
                FROM (
                    SELECT observation.event_revision_id,
                           ROW_NUMBER() OVER (
                               PARTITION BY repository, pr_number, kind, event_id
                               ORDER BY observation_id DESC
                           ) AS guardian_row_number
                    FROM event_current_observations AS observation
                    WHERE observation.repository = ?
                      AND observation.pr_number = ?
                ) AS current
                JOIN event_revisions AS revision
                  ON revision.revision_id = current.event_revision_id
                WHERE current.guardian_row_number = 1
                ORDER BY revision.revision_id
                LIMIT ?
                """,
                (
                    source.repository,
                    source.pr_number,
                    _MAX_CURRENT_FEEDBACK_PER_PULL + 1,
                ),
            ).fetchall()
            if len(current_rows) > _MAX_CURRENT_FEEDBACK_PER_PULL:
                raise RuntimeError(
                    "Historical current feedback authority exceeds its bound."
                )
            if tuple(int(row["revision_id"]) for row in current_rows) != tuple(
                sorted((*latest_ids, *ignored_ids))
            ):
                raise ValueError(
                    "source pull evidence is no longer current in the durable ledger."
                )
        return evidence_hash

    @staticmethod
    def _event_revision_from_row(row: sqlite3.Row) -> EventRevision:
        observed_at = _parse_datetime(row["observed_at"])
        if observed_at is None:  # pragma: no cover - database constraint
            raise RuntimeError("Event revision has no observation timestamp.")
        return EventRevision(
            revision_id=int(row["revision_id"]),
            repository=row["repository"],
            pr_number=int(row["pr_number"]),
            kind=row["kind"],
            event_id=row["event_id"],
            author=row["author"],
            author_id=int(row["author_id"]),
            author_type=row["author_type"],
            locale=row["locale"],
            body_hash=row["body_hash"],
            revision_hash=row["revision_hash"],
            head_sha=row["head_sha"],
            base_sha=row["base_sha"],
            observed_at=observed_at,
            body=row["body"],
            updated_at=row["event_updated_at"],
            path=row["path"],
            line=int(row["line"]) if row["line"] is not None else None,
            html_url=row["html_url"],
            deleted=bool(row["deleted"]),
        )

    @staticmethod
    def _validate_lease(name: str, owner: str, ttl_seconds: int | None = None) -> None:
        if (
            not name
            or not owner
            or any(character in name + owner for character in "\r\n\x00")
        ):
            raise ValueError("Lease name and owner must be safe non-empty strings.")
        if ttl_seconds is not None and ttl_seconds <= 0:
            raise ValueError("Lease ttl_seconds must be positive.")

    def acquire_lease(
        self,
        *,
        name: str,
        owner: str,
        ttl_seconds: int,
        now: datetime | None = None,
    ) -> bool:
        """Acquire an expired or absent cross-process lease atomically."""

        self._validate_lease(name, owner, ttl_seconds)
        acquired_at = now or _now()
        acquired = _serialize_datetime(acquired_at)
        expires = _serialize_datetime(acquired_at + timedelta(seconds=ttl_seconds))
        with self._connection:
            self._connection.execute(
                "DELETE FROM leases WHERE name = ? AND expires_at <= ?",
                (name, acquired),
            )
            cursor = self._connection.execute(
                """
                INSERT OR IGNORE INTO leases (name, owner, acquired_at, expires_at)
                VALUES (?, ?, ?, ?)
                """,
                (name, owner, acquired, expires),
            )
        return cursor.rowcount == 1

    def refresh_lease(
        self,
        *,
        name: str,
        owner: str,
        ttl_seconds: int,
        now: datetime | None = None,
    ) -> bool:
        """Extend a live lease only when its exact owner still holds it."""

        self._validate_lease(name, owner, ttl_seconds)
        refreshed_at = now or _now()
        refreshed = _serialize_datetime(refreshed_at)
        expires = _serialize_datetime(refreshed_at + timedelta(seconds=ttl_seconds))
        with self._connection:
            cursor = self._connection.execute(
                """
                UPDATE leases SET expires_at = ?
                WHERE name = ? AND owner = ? AND expires_at > ?
                """,
                (expires, name, owner, refreshed),
            )
        return cursor.rowcount == 1

    def release_lease(self, *, name: str, owner: str) -> bool:
        """Release a lease only for its exact owner."""

        self._validate_lease(name, owner)
        with self._connection:
            cursor = self._connection.execute(
                "DELETE FROM leases WHERE name = ? AND owner = ?",
                (name, owner),
            )
        return cursor.rowcount == 1

    def start_run(
        self,
        *,
        repository: str,
        locale: str,
        mode: GuardianMode | str,
        started_at: datetime | None = None,
        run_id: str | None = None,
    ) -> str:
        """Start and return a uniquely identified guardian run."""

        normalized_mode = GuardianMode(mode)
        new_run_id = run_id or str(uuid4())
        if (
            not isinstance(new_run_id, str)
            or not new_run_id
            or len(new_run_id.encode("utf-8")) > _MAX_RUN_ID_BYTES
            or "\x00" in new_run_id
        ):
            raise ValueError("run_id must be a bounded non-empty string.")
        if (
            not isinstance(repository, str)
            or len(repository.encode("utf-8")) > _MAX_REPOSITORY_BYTES
            or not _REPOSITORY_RE.fullmatch(repository)
            or any(component in {".", ".."} for component in repository.split("/"))
        ):
            raise ValueError("repository must use bounded canonical owner/name form.")
        with self._connection:
            self._connection.execute(
                """
                INSERT INTO runs (
                    run_id, repository, locale, mode, status, started_at
                ) VALUES (?, ?, ?, ?, 'running', ?)
                """,
                (
                    new_run_id,
                    repository,
                    locale,
                    normalized_mode.value,
                    _serialize_datetime(started_at or _now()),
                ),
            )
        return new_run_id

    def finish_run(
        self,
        run_id: str,
        *,
        status: str,
        summary: str | None = None,
        finished_at: datetime | None = None,
    ) -> None:
        """Finish an existing run without silently accepting unknown IDs."""

        if status not in _RUN_STATUSES:
            raise ValueError(f"Unsupported run status {status!r}.")
        with self._connection:
            cursor = self._connection.execute(
                """
                UPDATE runs
                SET status = ?, finished_at = ?, summary = ?
                WHERE run_id = ? AND status = 'running'
                """,
                (
                    status,
                    _serialize_datetime(finished_at or _now()),
                    summary,
                    run_id,
                ),
            )
            if cursor.rowcount != 1:
                raise KeyError(f"Unknown or already-finished run {run_id!r}.")

    def get_run(self, run_id: str) -> RunRecord:
        """Return one run, raising for an unknown run ID."""

        row = self._connection.execute(
            "SELECT * FROM runs WHERE run_id = ?",
            (run_id,),
        ).fetchone()
        if row is None:
            raise KeyError(f"Unknown run {run_id!r}.")
        started_at = _parse_datetime(row["started_at"])
        if started_at is None:  # pragma: no cover - database constraint
            raise RuntimeError("Run has no start timestamp.")
        return RunRecord(
            run_id=row["run_id"],
            repository=row["repository"],
            locale=row["locale"],
            mode=GuardianMode(row["mode"]),
            status=row["status"],
            started_at=started_at,
            finished_at=_parse_datetime(row["finished_at"]),
            summary=row["summary"],
        )

    def _validate_draft_run_authority(
        self,
        *,
        run_id: str,
        repository: str,
        allowed_modes: frozenset[GuardianMode],
        label: str,
    ) -> None:
        """Bind a prevention/remediation ledger to its authoring run."""

        if (
            not isinstance(run_id, str)
            or not run_id
            or len(run_id.encode("utf-8")) > _MAX_RUN_ID_BYTES
            or "\x00" in run_id
        ):
            raise ValueError(f"{label} run authority does not match.")
        try:
            run = self.get_run(run_id)
        except (KeyError, TypeError, ValueError):
            raise ValueError(f"{label} run authority does not match.") from None
        if run.repository != repository or run.mode not in allowed_modes:
            raise ValueError(f"{label} run authority does not match.")

    def reconcile_incomplete_runs(
        self,
        *,
        before: datetime,
        reconciled_at: datetime | None = None,
    ) -> tuple[str, ...]:
        """Mark stale runs failed unless publication recovery still owns them.

        A prepared or published commit is a durable recovery cursor.  Failing
        its run before publication recovery would prevent the atomic reply
        finalizer from truthfully completing that run after it confirms the
        remote state.
        """

        cutoff = _serialize_datetime(before)
        rows = self._connection.execute(
            """
            SELECT run_id FROM runs AS run
            WHERE run.status = 'running' AND run.started_at < ?
              AND NOT EXISTS (
                  SELECT 1
                  FROM publication_events AS publication
                  LEFT JOIN publication_reply_terminal_events AS reply_terminal
                    ON reply_terminal.publication_key = publication.publication_key
                  WHERE publication.run_id = run.run_id
                    AND publication.publication_event_id = (
                        SELECT MAX(latest.publication_event_id)
                        FROM publication_events AS latest
                        WHERE latest.publication_key = publication.publication_key
                    )
                    AND publication.phase IN ('prepared', 'published')
                    AND reply_terminal.publication_key IS NULL
              )
            ORDER BY started_at, run_id
            """,
            (cutoff,),
        ).fetchall()
        run_ids = tuple(str(row["run_id"]) for row in rows)
        if not run_ids:
            return ()
        finished = _serialize_datetime(reconciled_at or _now())
        with self._connection:
            self._connection.executemany(
                """
                UPDATE runs
                SET status = 'failed', finished_at = ?,
                    summary = 'Recovered after an interrupted Guardian process.'
                WHERE run_id = ? AND status = 'running'
                """,
                ((finished, run_id) for run_id in run_ids),
            )
        return run_ids

    def record_action(
        self,
        *,
        run_id: str,
        event_revision_id: int,
        action: str,
        status: str,
        details: Mapping[str, Any] | None = None,
        occurred_at: datetime | None = None,
    ) -> int:
        """Append an auditable action; completed/skipped actions resolve a revision."""

        if status not in _ACTION_STATUSES:
            raise ValueError(f"Unsupported action status {status!r}.")
        with self._connection:
            cursor = self._connection.execute(
                """
                INSERT INTO actions (
                    run_id, event_revision_id, action, status,
                    details_json, occurred_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    run_id,
                    event_revision_id,
                    action,
                    status,
                    _canonical_json(details),
                    _serialize_datetime(occurred_at or _now()),
                ),
            )
        return int(cursor.lastrowid)

    def record_cost(
        self,
        *,
        run_id: str,
        amount_usd: Decimal | float | str,
        model: str,
        input_tokens: int = 0,
        output_tokens: int = 0,
        incurred_at: datetime | None = None,
    ) -> int:
        """Record USD cost exactly to microdollar precision."""

        micros = _amount_to_microusd(amount_usd)
        if input_tokens < 0 or output_tokens < 0:
            raise ValueError("Token counts must be non-negative.")
        if not model:
            raise ValueError("model must not be empty.")

        with self._connection:
            cursor = self._connection.execute(
                """
                INSERT INTO costs (
                    run_id, amount_microusd, model, input_tokens,
                    output_tokens, incurred_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    run_id,
                    micros,
                    model,
                    input_tokens,
                    output_tokens,
                    _serialize_datetime(incurred_at or _now()),
                ),
            )
        return int(cursor.lastrowid)

    def try_reserve_model_call(
        self,
        *,
        run_id: str,
        daily_limit: int,
        model: str,
        purpose: str,
        reserved_at: datetime | None = None,
    ) -> int | None:
        """Atomically reserve one provider call within a UTC daily cap."""

        if isinstance(daily_limit, bool) or daily_limit <= 0:
            raise ValueError("Daily model call limit must be a positive integer.")
        if not model or not purpose:
            raise ValueError("Model and purpose must not be empty.")
        timestamp = reserved_at or _now()
        serialized_timestamp = _serialize_datetime(timestamp)
        start = datetime.combine(
            timestamp.astimezone(_UTC).date(), time.min, tzinfo=_UTC
        )
        end = start + timedelta(days=1)
        serialized_start = _serialize_datetime(start)
        serialized_end = _serialize_datetime(end)
        try:
            self._connection.execute("BEGIN IMMEDIATE")
            row = self._connection.execute(
                """
                SELECT COUNT(*) AS committed
                FROM model_call_reservations
                WHERE reserved_at >= ? AND reserved_at < ?
                  AND status IN ('reserved', 'completed', 'unknown')
                """,
                (serialized_start, serialized_end),
            ).fetchone()
            if int(row["committed"]) >= daily_limit:
                self._connection.rollback()
                return None
            cursor = self._connection.execute(
                """
                INSERT INTO model_call_reservations (
                    run_id, model, purpose, status, reserved_at
                ) VALUES (?, ?, ?, 'reserved', ?)
                """,
                (run_id, model, purpose, serialized_timestamp),
            )
            self._connection.commit()
        except Exception:
            self._connection.rollback()
            raise
        return int(cursor.lastrowid)

    def finalize_model_call(
        self,
        call_id: int,
        *,
        status: str,
        finalized_at: datetime | None = None,
    ) -> None:
        """Finalize one call reservation without ever undercounting ambiguity."""

        if status not in {"completed", "unknown", "cancelled"}:
            raise ValueError("Model call status is invalid.")
        timestamp = _serialize_datetime(finalized_at or _now())
        with self._connection:
            cursor = self._connection.execute(
                """
                UPDATE model_call_reservations
                SET status = ?, finalized_at = ?
                WHERE call_id = ? AND status = 'reserved'
                """,
                (status, timestamp, call_id),
            )
            if cursor.rowcount != 1:
                raise KeyError(f"Unknown or finalized model call {call_id}.")

    def model_calls_committed_for_day(self, day: date) -> int:
        """Return completed, ambiguous, and in-flight calls for one UTC day."""

        start = datetime.combine(day, time.min, tzinfo=_UTC)
        end = start + timedelta(days=1)
        row = self._connection.execute(
            """
            SELECT COUNT(*) AS committed
            FROM model_call_reservations
            WHERE reserved_at >= ? AND reserved_at < ?
              AND status IN ('reserved', 'completed', 'unknown')
            """,
            (_serialize_datetime(start), _serialize_datetime(end)),
        ).fetchone()
        return int(row["committed"])

    def try_reserve_budget(
        self,
        *,
        run_id: str,
        amount_usd: Decimal | float | str,
        daily_limit_usd: Decimal | float | str,
        model: str,
        reserved_at: datetime | None = None,
    ) -> int | None:
        """Atomically reserve model spend without crossing the UTC daily threshold."""

        amount = _amount_to_microusd(amount_usd)
        limit = _amount_to_microusd(daily_limit_usd)
        if amount <= 0:
            raise ValueError("Budget reservation must be greater than zero.")
        if not model:
            raise ValueError("model must not be empty.")
        timestamp = reserved_at or _now()
        serialized_timestamp = _serialize_datetime(timestamp)
        start = datetime.combine(
            timestamp.astimezone(_UTC).date(), time.min, tzinfo=_UTC
        )
        end = start + timedelta(days=1)
        serialized_start = _serialize_datetime(start)
        serialized_end = _serialize_datetime(end)
        try:
            self._connection.execute("BEGIN IMMEDIATE")
            row = self._connection.execute(
                _COMMITTED_BUDGET_SQL,
                (
                    serialized_start,
                    serialized_end,
                    serialized_start,
                    serialized_end,
                ),
            ).fetchone()
            if int(row["committed"]) + amount > limit:
                self._connection.rollback()
                return None
            cursor = self._connection.execute(
                """
                INSERT INTO budget_reservations (
                    run_id, amount_microusd, model, status, reserved_at
                ) VALUES (?, ?, ?, 'reserved', ?)
                """,
                (run_id, amount, model, serialized_timestamp),
            )
            self._connection.commit()
        except Exception:
            self._connection.rollback()
            raise
        return int(cursor.lastrowid)

    def settle_budget_reservation(
        self,
        reservation_id: int,
        *,
        actual_cost_usd: Decimal | float | str,
        input_tokens: int = 0,
        output_tokens: int = 0,
        settled_at: datetime | None = None,
    ) -> None:
        """Replace a conservative reservation with reported actual model spend."""

        actual = _amount_to_microusd(actual_cost_usd)
        if input_tokens < 0 or output_tokens < 0:
            raise ValueError("Token counts must be non-negative.")
        settled = _serialize_datetime(settled_at or _now())
        try:
            self._connection.execute("BEGIN IMMEDIATE")
            row = self._connection.execute(
                """
                SELECT run_id, model FROM budget_reservations
                WHERE reservation_id = ? AND status IN ('reserved', 'unknown')
                """,
                (reservation_id,),
            ).fetchone()
            if row is None:
                raise KeyError(f"Unknown or settled reservation {reservation_id}.")
            self._connection.execute(
                """
                INSERT INTO costs (
                    run_id, amount_microusd, model, input_tokens,
                    output_tokens, incurred_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    row["run_id"],
                    actual,
                    row["model"],
                    input_tokens,
                    output_tokens,
                    settled,
                ),
            )
            self._connection.execute(
                """
                UPDATE budget_reservations
                SET status = 'settled', settled_at = ?
                WHERE reservation_id = ?
                """,
                (settled, reservation_id),
            )
            self._connection.commit()
        except Exception:
            self._connection.rollback()
            raise

    def mark_budget_reservation_unknown(
        self,
        reservation_id: int,
        *,
        marked_at: datetime | None = None,
    ) -> None:
        """Retain a conservative reservation when the provider reports no cost."""

        marked = _serialize_datetime(marked_at or _now())
        with self._connection:
            cursor = self._connection.execute(
                """
                UPDATE budget_reservations
                SET status = 'unknown', settled_at = ?
                WHERE reservation_id = ? AND status = 'reserved'
                """,
                (marked, reservation_id),
            )
            if cursor.rowcount != 1:
                raise KeyError(f"Unknown or finalized reservation {reservation_id}.")

    def cached_assessment_result(
        self,
        *,
        cache_key: str,
        repository: str,
        pr_number: int,
        head_sha: str,
        base_sha: str,
        model: str,
        reasoning_effort: str,
    ) -> str | None:
        """Return a decision only when its complete immutable identity matches."""

        if not re.fullmatch(r"[0-9a-f]{64}", cache_key):
            raise ValueError("assessment cache key must be a SHA-256 digest")
        row = self._connection.execute(
            "SELECT * FROM assessment_results WHERE cache_key = ?",
            (cache_key,),
        ).fetchone()
        if row is None:
            return None
        expected = (
            repository,
            pr_number,
            head_sha,
            base_sha,
            model,
            reasoning_effort,
        )
        actual = (
            row["repository"],
            int(row["pr_number"]),
            row["head_sha"],
            row["base_sha"],
            row["model"],
            row["reasoning_effort"],
        )
        if actual != expected:
            raise RuntimeError("assessment cache identity collision")
        return str(row["result_json"])

    def cache_assessment_and_settle_budget(
        self,
        *,
        cache_key: str,
        repository: str,
        pr_number: int,
        head_sha: str,
        base_sha: str,
        model: str,
        reasoning_effort: str,
        result_json: str,
        reservation_id: int,
        actual_cost_usd: Decimal | float | str | None,
        input_tokens: int,
        output_tokens: int,
        created_at: datetime | None = None,
    ) -> None:
        """Atomically retain a validated result and finalize its reservation."""

        _validate_assessment_metadata(
            cache_key=cache_key,
            repository=repository,
            pr_number=pr_number,
            head_sha=head_sha,
            base_sha=base_sha,
            model=model,
            reasoning_effort=reasoning_effort,
            result_json=result_json,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
        )
        actual_cost = (
            _amount_to_microusd(actual_cost_usd)
            if actual_cost_usd is not None
            else None
        )
        timestamp = _serialize_datetime(created_at or _now())
        try:
            self._connection.execute("BEGIN IMMEDIATE")
            reservation = self._connection.execute(
                """
                SELECT run_id, model FROM budget_reservations
                WHERE reservation_id = ? AND status = 'reserved'
                """,
                (reservation_id,),
            ).fetchone()
            if reservation is None or reservation["model"] != model:
                raise KeyError(f"Unknown or finalized reservation {reservation_id}.")
            _store_and_verify_assessment(
                self._connection,
                cache_key=cache_key,
                repository=repository,
                pr_number=pr_number,
                head_sha=head_sha,
                base_sha=base_sha,
                model=model,
                reasoning_effort=reasoning_effort,
                result_json=result_json,
                timestamp=timestamp,
            )
            if actual_cost is None:
                self._connection.execute(
                    """
                    UPDATE budget_reservations
                    SET status = 'unknown', settled_at = ?
                    WHERE reservation_id = ?
                    """,
                    (timestamp, reservation_id),
                )
            else:
                self._connection.execute(
                    """
                    INSERT INTO costs (
                        run_id, amount_microusd, model, input_tokens,
                        output_tokens, incurred_at
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        reservation["run_id"],
                        actual_cost,
                        model,
                        input_tokens,
                        output_tokens,
                        timestamp,
                    ),
                )
                self._connection.execute(
                    """
                    UPDATE budget_reservations
                    SET status = 'settled', settled_at = ?
                    WHERE reservation_id = ?
                    """,
                    (timestamp, reservation_id),
                )
            self._connection.commit()
        except Exception:
            self._connection.rollback()
            raise

    def cache_assessment_result(
        self,
        *,
        cache_key: str,
        repository: str,
        pr_number: int,
        head_sha: str,
        base_sha: str,
        model: str,
        reasoning_effort: str,
        result_json: str,
        created_at: datetime | None = None,
    ) -> None:
        """Durably cache a subscription-backed result without fake USD spend."""

        _validate_assessment_metadata(
            cache_key=cache_key,
            repository=repository,
            pr_number=pr_number,
            head_sha=head_sha,
            base_sha=base_sha,
            model=model,
            reasoning_effort=reasoning_effort,
            result_json=result_json,
        )
        timestamp = _serialize_datetime(created_at or _now())
        try:
            self._connection.execute("BEGIN IMMEDIATE")
            _store_and_verify_assessment(
                self._connection,
                cache_key=cache_key,
                repository=repository,
                pr_number=pr_number,
                head_sha=head_sha,
                base_sha=base_sha,
                model=model,
                reasoning_effort=reasoning_effort,
                result_json=result_json,
                timestamp=timestamp,
            )
            self._connection.commit()
        except Exception:
            self._connection.rollback()
            raise

    def cost_for_day(self, day: date) -> Decimal:
        """Return total model cost for one UTC calendar day."""

        start = datetime.combine(day, time.min, tzinfo=_UTC)
        end = start + timedelta(days=1)
        row = self._connection.execute(
            """
            SELECT COALESCE(SUM(amount_microusd), 0) AS total
            FROM costs
            WHERE incurred_at >= ? AND incurred_at < ?
            """,
            (_serialize_datetime(start), _serialize_datetime(end)),
        ).fetchone()
        return Decimal(int(row["total"])) / Decimal(1_000_000)

    def budget_committed_for_day(self, day: date) -> Decimal:
        """Return actual cost plus active conservative reservations for a UTC day."""

        start = datetime.combine(day, time.min, tzinfo=_UTC)
        end = start + timedelta(days=1)
        serialized_start = _serialize_datetime(start)
        serialized_end = _serialize_datetime(end)
        row = self._connection.execute(
            _COMMITTED_BUDGET_SQL,
            (
                serialized_start,
                serialized_end,
                serialized_start,
                serialized_end,
            ),
        ).fetchone()
        return Decimal(int(row["committed"])) / Decimal(1_000_000)

    def record_health(
        self,
        *,
        component: str,
        status: str,
        message: str,
        details: Mapping[str, Any] | None = None,
        checked_at: datetime | None = None,
    ) -> int:
        """Append one health observation."""

        with self._connection:
            cursor = self._connection.execute(
                """
                INSERT INTO health (
                    component, status, message, details_json, checked_at
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (
                    component,
                    status,
                    message,
                    _canonical_json(details),
                    _serialize_datetime(checked_at or _now()),
                ),
            )
        return int(cursor.lastrowid)

    def latest_health(self, component: str) -> HealthRecord | None:
        """Return the latest health observation for a component."""

        row = self._connection.execute(
            """
            SELECT * FROM health
            WHERE component = ?
            ORDER BY checked_at DESC, health_id DESC
            LIMIT 1
            """,
            (component,),
        ).fetchone()
        if row is None:
            return None
        raw_details = row["details_json"]
        try:
            details = loads_bounded_json(raw_details)
            if (
                not isinstance(details, Mapping)
                or _canonical_json(details) != raw_details
            ):
                raise ValueError
        except (TypeError, ValueError, RecursionError):
            raise RuntimeError("Health ledger contains malformed data.") from None
        checked_at = _parse_datetime(row["checked_at"])
        if checked_at is None:  # pragma: no cover - database constraint
            raise RuntimeError("Health record has no timestamp.")
        return HealthRecord(
            health_id=int(row["health_id"]),
            component=row["component"],
            status=row["status"],
            message=row["message"],
            details=details,
            checked_at=checked_at,
        )

    def status_snapshot(
        self,
        *,
        mode: GuardianMode | str,
        as_of: datetime | None = None,
    ) -> GuardianStateStatus:
        """Return one redacted, schema-aware aggregate operator snapshot."""

        normalized_mode = GuardianMode(mode)
        resolution_modes = tuple(
            item.value for item in _MODE_RESOLUTION_AUTHORITY[normalized_mode]
        )
        placeholders = ", ".join("?" for _ in resolution_modes)
        observed_at = as_of or _now()
        _serialize_datetime(observed_at)
        today_date = observed_at.astimezone(_UTC).date()
        today = today_date.isoformat()
        tomorrow = (today_date + timedelta(days=1)).isoformat()

        last_run_row = self._connection.execute(
            """
            SELECT finished_at FROM runs
            WHERE status = 'completed'
            ORDER BY finished_at DESC, run_id DESC
            LIMIT 1
            """
        ).fetchone()
        last_poll_row = self._connection.execute(
            """
            SELECT checked_at FROM health
            WHERE component = 'guardian' AND status = 'ok'
            ORDER BY checked_at DESC, health_id DESC LIMIT 1
            """
        ).fetchone()
        pending_row = self._connection.execute(
            f"""
            SELECT COUNT(*) AS pending_count FROM event_revisions AS e
            WHERE NOT EXISTS (
                SELECT 1 FROM actions AS a
                JOIN runs AS r ON r.run_id = a.run_id
                WHERE a.event_revision_id = e.revision_id
                  AND a.status IN ('completed', 'skipped')
                  AND r.mode IN ({placeholders})
            )
            """,
            resolution_modes,
        ).fetchone()
        actions = tuple(
            (str(row["status"]), int(row["action_count"]))
            for row in self._connection.execute(
                """
                SELECT status, COUNT(*) AS action_count
                FROM actions GROUP BY status ORDER BY status
                """
            ).fetchall()
        )
        health = tuple(
            (str(row["component"]), str(row["status"]))
            for row in self._connection.execute(
                """
                SELECT current.component, current.status
                FROM health AS current
                JOIN (
                    SELECT component, MAX(health_id) AS health_id
                    FROM health GROUP BY component
                ) AS latest ON latest.health_id = current.health_id
                ORDER BY current.component
                """
            ).fetchall()
        )
        committed_row = self._connection.execute(
            _COMMITTED_BUDGET_SQL,
            (today, tomorrow, today, tomorrow),
        ).fetchone()
        model_calls_row = self._connection.execute(
            """
            SELECT COUNT(*) AS call_count FROM model_call_reservations
            WHERE reserved_at >= ? AND reserved_at < ?
              AND status IN ('reserved', 'completed', 'unknown')
            """,
            (today, tomorrow),
        ).fetchone()
        prevention_row = self._connection.execute(
            f"""
            WITH bounded_events AS MATERIALIZED (
                SELECT p.prevention_event_id, p.draft_key, p.phase
                FROM prevention_draft_events AS p
                WHERE typeof(p.draft_key) = 'text'
                  AND length(CAST(p.draft_key AS BLOB)) <=
                      {_MAX_PREVENTION_INVALID_DRAFT_KEY_BYTES}
            ), latest AS (
                SELECT prevention_event_id, draft_key, phase,
                       ROW_NUMBER() OVER (
                           PARTITION BY p.draft_key
                           ORDER BY p.prevention_event_id DESC
                       ) AS guardian_row_number
                FROM bounded_events AS p
            )
            SELECT
                COALESCE(SUM(
                    latest.phase IN ('validated', 'pushed')
                    AND resolution.draft_key IS NULL
                    AND quarantine.prevention_event_id IS NULL
                    AND legacy_result.legacy_event_id IS NULL
                    AND legacy_exact.legacy_event_id IS NULL
                    AND legacy_invalid.legacy_event_id IS NULL
                    AND NOT EXISTS (
                        SELECT 1
                        FROM prevention_legacy_policy_deferrals AS deferral
                        WHERE deferral.legacy_event_id =
                              latest.prevention_event_id
                    )
                    AND NOT EXISTS (
                        SELECT 1
                        FROM prevention_legacy_deferral_exhaustions AS exhausted
                        WHERE exhausted.legacy_event_id =
                              latest.prevention_event_id
                    )
                    AND typeof(latest.draft_key) = 'text'
                    AND length(latest.draft_key) = 64
                    AND latest.draft_key NOT GLOB '*[^0-9a-f]*'
                ), 0) AS pending_count,
                COALESCE(SUM(
                    (
                        legacy_exact.legacy_event_id IS NOT NULL
                        OR (
                            quarantine.prevention_event_id IS NULL
                            AND legacy_invalid.legacy_event_id IS NULL
                            AND (
                                (
                                    latest.phase = 'draft_opened'
                                    AND legacy_candidate.prevention_event_id IS NULL
                                    AND legacy_result.legacy_event_id IS NULL
                                )
                                OR legacy_result.disposition = 'draft_opened'
                            )
                        )
                    )
                    AND typeof(latest.draft_key) = 'text'
                    AND length(latest.draft_key) = 64
                    AND latest.draft_key NOT GLOB '*[^0-9a-f]*'
                ), 0) AS opened_count,
                COALESCE(SUM(
                    legacy_exact.legacy_event_id IS NULL
                    AND (
                        (
                            latest.phase != 'draft_opened'
                            AND (
                                latest.phase = 'abandoned'
                                OR (
                                    resolution.resolution IS NOT NULL
                                    AND resolution.resolution !=
                                        'operator_quarantined'
                                )
                            )
                        )
                        OR quarantine.prevention_event_id IS NOT NULL
                        OR legacy_invalid.legacy_event_id IS NOT NULL
                        OR EXISTS (
                            SELECT 1
                            FROM prevention_legacy_policy_deferrals AS deferral
                            WHERE deferral.legacy_event_id =
                                  latest.prevention_event_id
                              AND legacy_result.legacy_event_id IS NULL
                        )
                        OR EXISTS (
                            SELECT 1
                            FROM prevention_legacy_deferral_exhaustions AS exhausted
                            WHERE exhausted.legacy_event_id =
                                  latest.prevention_event_id
                        )
                        OR (
                            latest.phase = 'draft_opened'
                            AND legacy_candidate.prevention_event_id IS NOT NULL
                            AND legacy_result.legacy_event_id IS NULL
                        )
                        OR (
                            legacy_result.legacy_event_id IS NOT NULL
                            AND legacy_result.disposition != 'draft_opened'
                        )
                        OR typeof(latest.draft_key) != 'text'
                        OR length(latest.draft_key) != 64
                        OR latest.draft_key GLOB '*[^0-9a-f]*'
                    )
                ), 0) + (
                    SELECT COUNT(*)
                    FROM prevention_draft_events AS unbounded
                    WHERE (
                        typeof(unbounded.draft_key) != 'text'
                        OR length(CAST(unbounded.draft_key AS BLOB)) >
                           {_MAX_PREVENTION_INVALID_DRAFT_KEY_BYTES}
                    )
                      AND unbounded.phase IN (
                          'validated', 'pushed', 'draft_opened', 'abandoned'
                      )
                      AND NOT EXISTS (
                          SELECT 1
                          FROM prevention_draft_events AS newer
                          WHERE newer.draft_key = unbounded.draft_key
                            AND newer.prevention_event_id >
                                unbounded.prevention_event_id
                      )
                      AND NOT EXISTS (
                          SELECT 1
                          FROM prevention_resolution_events AS resolution
                          WHERE resolution.draft_key = unbounded.draft_key
                            AND resolution.resolution = 'operator_quarantined'
                      )
                      AND NOT EXISTS (
                          SELECT 1
                          FROM prevention_draft_events AS terminal_event
                          JOIN prevention_legacy_exact_drafts AS legacy_exact
                            ON legacy_exact.legacy_event_id =
                               terminal_event.prevention_event_id
                          WHERE terminal_event.draft_key = unbounded.draft_key
                      )
                      AND NOT EXISTS (
                          SELECT 1
                          FROM prevention_draft_events AS terminal_event
                          JOIN prevention_legacy_reconciliations AS reconciliation
                            ON reconciliation.legacy_event_id =
                               terminal_event.prevention_event_id
                          WHERE terminal_event.draft_key = unbounded.draft_key
                            AND reconciliation.disposition = 'draft_opened'
                      )
                ) AS conflicted_count,
                COALESCE(SUM(
                    latest.phase != 'draft_opened'
                    AND legacy_exact.legacy_event_id IS NULL
                    AND resolution.resolution = 'operator_quarantined'
                ), 0) AS quarantined_count
            FROM latest
            LEFT JOIN prevention_resolution_events AS resolution
              ON resolution.draft_key = latest.draft_key
            LEFT JOIN prevention_invalid_record_quarantines AS quarantine
              ON quarantine.prevention_event_id = latest.prevention_event_id
            LEFT JOIN prevention_legacy_reconciliations AS legacy_result
              ON legacy_result.legacy_event_id = latest.prevention_event_id
            LEFT JOIN prevention_legacy_exact_drafts AS legacy_exact
              ON legacy_exact.legacy_event_id = latest.prevention_event_id
            LEFT JOIN prevention_legacy_candidate_events AS legacy_candidate
              ON legacy_candidate.prevention_event_id =
                 latest.prevention_event_id
            LEFT JOIN prevention_legacy_invalid_resolutions AS legacy_invalid
              ON legacy_invalid.legacy_event_id = latest.prevention_event_id
            WHERE latest.guardian_row_number = 1
            """
        ).fetchone()
        remediation_row = self._connection.execute(
            """
            WITH latest AS (
                SELECT draft_key, phase,
                       ROW_NUMBER() OVER (
                           PARTITION BY draft_key
                           ORDER BY remediation_event_id DESC
                       ) AS guardian_row_number
                FROM remediation_draft_events
            )
            SELECT
                COALESCE(SUM(
                    latest.phase IN ('validated', 'pushed')
                    AND resolution.draft_key IS NULL
                ), 0) AS pending_count,
                COALESCE(SUM(
                    latest.phase = 'draft_opened'
                    AND resolution.draft_key IS NULL
                ), 0) AS opened_count,
                COALESCE(SUM(
                    latest.phase = 'abandoned'
                    AND resolution.draft_key IS NULL
                ), 0) AS abandoned_count,
                COALESCE(SUM(
                    resolution.resolution = 'operator_quarantined'
                ), 0) AS quarantined_count,
                COALESCE(SUM(
                    resolution.resolution = 'merged'
                ), 0) AS merged_count
            FROM latest
            LEFT JOIN remediation_resolution_events AS resolution
              ON resolution.draft_key = latest.draft_key
            WHERE latest.guardian_row_number = 1
            """
        ).fetchone()
        remote_row = self._connection.execute(
            """
            WITH latest_remote AS (
                SELECT observation, state, is_merged,
                       ROW_NUMBER() OVER (
                           PARTITION BY draft_key
                           ORDER BY observation_id DESC
                       ) AS guardian_row_number
                FROM remediation_remote_observation_events
            )
            SELECT
                COALESCE(SUM(
                    observation = 'exact'
                    AND state = 'open'
                    AND is_merged = 0
                ), 0) AS exact_open_count,
                COALESCE(SUM(
                    observation = 'exact'
                    AND state = 'closed'
                    AND is_merged = 0
                ), 0) AS closed_unmerged_count,
                COALESCE(SUM(observation = 'not_found'), 0) AS not_found_count,
                COALESCE(SUM(observation = 'conflict'), 0) AS conflict_count
            FROM latest_remote
            WHERE guardian_row_number = 1
            """
        ).fetchone()
        if any(
            row is None
            for row in (
                pending_row,
                committed_row,
                model_calls_row,
                prevention_row,
                remediation_row,
                remote_row,
            )
        ):  # pragma: no cover - aggregates always return one row
            raise RuntimeError("Guardian status aggregation failed.")
        return GuardianStateStatus(
            last_successful_poll=(
                str(last_poll_row["checked_at"]) if last_poll_row else None
            ),
            last_completed_run=(
                str(last_run_row["finished_at"]) if last_run_row else None
            ),
            pending_revisions=int(pending_row["pending_count"]),
            actions=actions,
            health=health,
            committed_microusd_today=int(committed_row["committed"]),
            model_calls_today=int(model_calls_row["call_count"]),
            pending_historical_retries=self.pending_historical_pull_retry_count(),
            quarantined_historical_retries=(
                self.operator_quarantined_historical_pull_retry_count()
            ),
            pending_preventions=int(prevention_row["pending_count"]),
            opened_preventions=int(prevention_row["opened_count"]),
            conflicted_preventions=int(prevention_row["conflicted_count"]),
            quarantined_preventions=int(prevention_row["quarantined_count"]),
            pending_remediations=int(remediation_row["pending_count"]),
            opened_remediations=int(remediation_row["opened_count"]),
            abandoned_remediations=int(remediation_row["abandoned_count"]),
            quarantined_remediations=int(remediation_row["quarantined_count"]),
            merged_remediations=int(remediation_row["merged_count"]),
            remote_exact_open_remediations=int(remote_row["exact_open_count"]),
            remote_closed_unmerged_remediations=int(
                remote_row["closed_unmerged_count"]
            ),
            remote_not_found_remediations=int(remote_row["not_found_count"]),
            remote_conflict_remediations=int(remote_row["conflict_count"]),
        )

    @staticmethod
    def _publication_from_row(row: sqlite3.Row) -> PublicationRecord:
        try:
            publication_key = str(row["publication_key"])
            run_id = str(row["run_id"])
            repository = str(row["repository"])
            raw_repository_id = row["repository_id"]
            if raw_repository_id is not None and (
                isinstance(raw_repository_id, bool)
                or not isinstance(raw_repository_id, int)
            ):
                raise ValueError
            repository_id = raw_repository_id
            pr_number = int(row["pr_number"])
            original_head_sha = str(row["original_head_sha"])
            base_sha = str(row["base_sha"])
            commit_sha = str(row["commit_sha"])
            raw_publication_actor_id = row["publication_actor_id"]
            raw_publication_actor_type = row["publication_actor_type"]
            if raw_publication_actor_id is not None and (
                isinstance(raw_publication_actor_id, bool)
                or not isinstance(raw_publication_actor_id, int)
            ):
                raise ValueError
            if raw_publication_actor_type is not None and not isinstance(
                raw_publication_actor_type, str
            ):
                raise ValueError
            publication_actor_id = raw_publication_actor_id
            publication_actor_type = raw_publication_actor_type
            phase = str(row["phase"])
            event_ids = loads_bounded_json(row["event_revision_ids_json"])
            occurred_at = _parse_datetime(row["occurred_at"])
            raw_open_source = row["open_source_json"]
            open_source = (
                None
                if raw_open_source is None
                else _open_pull_authority_from_json(raw_open_source)
            )
            if raw_open_source is not None and open_source is None:
                raise ValueError
        except (KeyError, TypeError, ValueError, json.JSONDecodeError):
            raise RuntimeError("Publication ledger contains malformed data.")
        key_payload = (
            f"{repository}\n{pr_number}\n{original_head_sha}\n{base_sha}\n{commit_sha}"
        )
        if (
            not isinstance(event_ids, list)
            or not event_ids
            or len(event_ids) > _MAX_PREVENTION_SOURCE_REVISIONS
            or tuple(sorted(event_ids)) != tuple(event_ids)
            or len(set(event_ids)) != len(event_ids)
            or any(
                isinstance(value, bool)
                or not isinstance(value, int)
                or not 0 < value <= _SQLITE_MAX_INTEGER
                for value in event_ids
            )
            or occurred_at is None
            or _serialize_datetime(occurred_at) != row["occurred_at"]
            or not run_id
            or not _REPOSITORY_RE.fullmatch(repository)
            or (
                repository_id is not None
                and not 0 < repository_id <= _SQLITE_MAX_INTEGER
            )
            or not 0 < pr_number <= _SQLITE_MAX_INTEGER
            or (publication_actor_id is None) != (publication_actor_type is None)
            or (
                publication_actor_id is not None
                and (
                    not 0 < publication_actor_id <= _SQLITE_MAX_INTEGER
                    or publication_actor_type not in {"User", "Bot"}
                )
            )
            or any(
                not re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", value)
                for value in (original_head_sha, base_sha, commit_sha)
            )
            or phase not in {"prepared", "published", "replied", "abandoned"}
            or not _SHA256_RE.fullmatch(publication_key)
            or hashlib.sha256(key_payload.encode("utf-8")).hexdigest()
            != publication_key
            or (
                open_source is not None
                and (
                    open_source.feedback_digest is None
                    or open_source.repository != repository
                    or open_source.repository_id != repository_id
                    or open_source.pr_number != pr_number
                    or open_source.head_sha != original_head_sha
                    or open_source.base_sha != base_sha
                )
            )
            or (repository_id is None) != (open_source is None)
        ):
            raise RuntimeError("Publication ledger contains malformed data.")
        return PublicationRecord(
            publication_key=publication_key,
            run_id=run_id,
            repository=repository,
            repository_id=repository_id,
            pr_number=pr_number,
            original_head_sha=original_head_sha,
            base_sha=base_sha,
            commit_sha=commit_sha,
            publication_actor_id=publication_actor_id,
            publication_actor_type=publication_actor_type,
            event_revision_ids=tuple(event_ids),
            open_source=open_source,
            phase=phase,
            occurred_at=occurred_at,
        )

    def _record_publication_event_in_transaction(
        self,
        *,
        run_id: str,
        repository: str,
        pr_number: int,
        original_head_sha: str,
        base_sha: str,
        commit_sha: str,
        publication_actor_id: int,
        publication_actor_type: str,
        event_revision_ids: Sequence[int],
        phase: str,
        open_source: OpenPullAuthorityReference,
        occurred_at: datetime | None = None,
    ) -> str:
        """Append one publication phase without opening a transaction."""

        if phase not in {"prepared", "published", "replied", "abandoned"}:
            raise ValueError("Unsupported publication phase.")
        if pr_number <= 0:
            raise ValueError("pr_number must be positive.")
        if (
            isinstance(publication_actor_id, bool)
            or not isinstance(publication_actor_id, int)
            or not 0 < publication_actor_id <= _SQLITE_MAX_INTEGER
        ):
            raise ValueError("publication_actor_id must be a positive integer.")
        if not isinstance(
            publication_actor_type, str
        ) or publication_actor_type not in {"User", "Bot"}:
            raise ValueError("publication_actor_type must be User or Bot.")
        if not repository or any(character in repository for character in "\r\n\x00"):
            raise ValueError("repository must be a safe non-empty value.")
        sha_values = (original_head_sha, base_sha, commit_sha)
        if any(
            len(value) not in {40, 64}
            or any(character not in "0123456789abcdef" for character in value)
            for value in sha_values
        ):
            raise ValueError("Publication SHAs must be full lowercase object IDs.")
        normalized_ids = tuple(event_revision_ids)
        if (
            not normalized_ids
            or len(set(normalized_ids)) != len(normalized_ids)
            or any(
                isinstance(value, bool) or not isinstance(value, int) or value <= 0
                for value in normalized_ids
            )
        ):
            raise ValueError(
                "event_revision_ids must contain unique positive integers."
            )
        canonical_ids = tuple(sorted(normalized_ids))
        if not isinstance(open_source, OpenPullAuthorityReference):
            raise ValueError(
                "Publication requires exact open-pull authority before preparation."
            )
        if (
            open_source.feedback_digest is None
            or open_source.repository != repository
            or open_source.pr_number != pr_number
            or open_source.head_sha != original_head_sha
            or open_source.base_sha != base_sha
        ):
            raise ValueError(
                "Publication requires exact open-pull authority before preparation."
            )
        self.validate_prevention_source_attestation(
            source_repository=repository,
            open_source=open_source,
            source_pulls=(),
            event_revision_ids=canonical_ids,
        )
        open_source_json = _open_pull_authority_json(open_source)
        repository_id = open_source.repository_id
        key_payload = (
            f"{repository}\n{pr_number}\n{original_head_sha}\n{base_sha}\n{commit_sha}"
        )
        publication_key = hashlib.sha256(key_payload.encode("utf-8")).hexdigest()
        event_ids_json = json.dumps(canonical_ids, separators=(",", ":"))
        identity = (
            run_id,
            repository,
            repository_id,
            pr_number,
            original_head_sha,
            base_sha,
            commit_sha,
            publication_actor_id,
            publication_actor_type,
            event_ids_json,
            open_source_json,
        )
        existing = self._connection.execute(
            """
            SELECT run_id, repository, repository_id, pr_number, original_head_sha,
                   base_sha, commit_sha, publication_actor_id,
                   publication_actor_type, event_revision_ids_json,
                   open_source_json
            FROM publication_events
            WHERE publication_key = ?
            ORDER BY publication_event_id
            LIMIT 1
            """,
            (publication_key,),
        ).fetchone()
        timestamp = occurred_at or _now()
        if existing is not None and tuple(existing) != identity:
            raise ValueError(
                "Publication phase metadata does not match its first event."
            )
        latest = self._connection.execute(
            """
            SELECT phase, occurred_at FROM publication_events
            WHERE publication_key = ?
            ORDER BY publication_event_id DESC
            LIMIT 1
            """,
            (publication_key,),
        ).fetchone()
        if latest is None:
            if phase != "prepared":
                raise ValueError("Publication must begin in the prepared phase.")
            run = self.get_run(run_id)
            if (
                run.repository != repository
                or run.mode
                not in {
                    GuardianMode.APPLY_OWNED_TRANSLATIONS,
                    GuardianMode.PROPOSE_PREVENTION,
                }
                or run.status != "running"
            ):
                raise ValueError("Publication run authority does not match.")
        else:
            latest_at = _parse_datetime(str(latest["occurred_at"]))
            if latest_at is None or timestamp < latest_at:
                raise ValueError("Publication timestamps must be monotonic.")
            latest_phase = str(latest["phase"])
            valid_next_phases = {
                "prepared": {"prepared", "published", "abandoned"},
                "published": {"published", "replied", "abandoned"},
                "replied": {"replied"},
                "abandoned": {"abandoned"},
            }
            if phase not in valid_next_phases.get(latest_phase, set()):
                raise ValueError("Publication phase transition is invalid.")
        self._connection.execute(
            """
            INSERT OR IGNORE INTO publication_events (
                publication_key, run_id, repository, repository_id, pr_number,
                original_head_sha, base_sha, commit_sha,
                publication_actor_id, publication_actor_type,
                event_revision_ids_json, open_source_json, phase, occurred_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                publication_key,
                *identity,
                phase,
                _serialize_datetime(timestamp),
            ),
        )
        return publication_key

    def _publication_completion_plan_in_transaction(
        self,
        publication: PublicationRecord,
    ) -> tuple[tuple[int, str, str], ...]:
        """Load and verify the immutable action plan for one publication."""

        rows = self._connection.execute(
            """
            SELECT plan_index, run_id, publication_actor_id,
                   publication_actor_type, event_revision_id, action, status,
                   details_json, occurred_at
            FROM publication_completion_plan_items
            WHERE publication_key = ?
            ORDER BY plan_index
            LIMIT ?
            """,
            (publication.publication_key, _MAX_PENDING_EVENT_WORKSET + 1),
        ).fetchall()
        if not rows or len(rows) > _MAX_PENDING_EVENT_WORKSET:
            raise RuntimeError("Publication completion plan is missing or malformed.")
        prepared_row = self._connection.execute(
            """
            SELECT occurred_at FROM publication_events
            WHERE publication_key = ? AND phase = 'prepared'
            LIMIT 2
            """,
            (publication.publication_key,),
        ).fetchall()
        prepared_at = (
            None
            if len(prepared_row) != 1
            else _parse_datetime(str(prepared_row[0]["occurred_at"]))
        )
        if prepared_at is None:
            raise RuntimeError("Publication completion plan is missing or malformed.")
        run = self.get_run(publication.run_id)
        normalized: list[tuple[int, str, str]] = []
        for index, row in enumerate(rows):
            try:
                details = loads_bounded_json(row["details_json"])
                occurred_at = _parse_datetime(str(row["occurred_at"]))
                revision_id = int(row["event_revision_id"])
                status = str(row["status"])
                revision = self.get_event_revision(revision_id)
            except (TypeError, ValueError, json.JSONDecodeError):
                raise RuntimeError(
                    "Publication completion plan is missing or malformed."
                ) from None
            if (
                int(row["plan_index"]) != index
                or row["run_id"] != publication.run_id
                or row["publication_actor_id"] != publication.publication_actor_id
                or row["publication_actor_type"] != publication.publication_actor_type
                or row["action"] != run.mode.value
                or status not in _TERMINAL_ACTION_STATUSES
                or not isinstance(details, Mapping)
                or _canonical_json(details) != row["details_json"]
                or occurred_at is None
                or _serialize_datetime(occurred_at) != row["occurred_at"]
                or occurred_at < prepared_at
                or revision is None
                or revision.repository != publication.repository
                or revision.pr_number != publication.pr_number
                or revision.head_sha != publication.original_head_sha
                or revision.base_sha != publication.base_sha
            ):
                raise RuntimeError(
                    "Publication completion plan is missing or malformed."
                )
            normalized.append((revision_id, status, str(row["details_json"])))
        try:
            canonical = _normalized_publication_completion_actions(
                tuple(
                    (revision_id, status, loads_bounded_json(details_json))
                    for revision_id, status, details_json in normalized
                )
            )
        except (TypeError, ValueError, json.JSONDecodeError):
            raise RuntimeError(
                "Publication completion plan is missing or malformed."
            ) from None
        if canonical != tuple(normalized) or not set(
            publication.event_revision_ids
        ).issubset(item[0] for item in canonical):
            raise RuntimeError("Publication completion plan is missing or malformed.")
        return canonical

    def _record_publication_completion_plan_in_transaction(
        self,
        *,
        publication_key: str,
        completion_actions: Sequence[tuple[int, str, Mapping[str, Any]]],
        occurred_at: datetime,
    ) -> tuple[tuple[int, str, str], ...]:
        """Persist one exact completion plan beside its prepared publication."""

        normalized = _normalized_publication_completion_actions(completion_actions)
        publication_rows = self._connection.execute(
            """
            SELECT * FROM publication_events
            WHERE publication_key = ? AND phase = 'prepared'
            LIMIT 2
            """,
            (publication_key,),
        ).fetchall()
        if len(publication_rows) != 1:
            raise ValueError(
                "Publication completion plan requires one prepared publication."
            )
        publication = self._publication_from_row(publication_rows[0])
        if not set(publication.event_revision_ids).issubset(
            item[0] for item in normalized
        ):
            raise ValueError(
                "Publication completion plan is missing selected revisions."
            )
        run = self.get_run(publication.run_id)
        serialized_timestamp = _serialize_datetime(occurred_at)
        existing = self._connection.execute(
            """
            SELECT 1 FROM publication_completion_plan_items
            WHERE publication_key = ?
            LIMIT 1
            """,
            (publication_key,),
        ).fetchone()
        if existing is not None:
            recorded = self._publication_completion_plan_in_transaction(publication)
            if recorded != normalized:
                raise ValueError(
                    "Publication completion plan conflicts with prior evidence."
                )
            return recorded
        for index, (revision_id, status, details_json) in enumerate(normalized):
            self._connection.execute(
                """
                INSERT INTO publication_completion_plan_items (
                    publication_key, plan_index, run_id,
                    publication_actor_id, publication_actor_type,
                    event_revision_id, action, status, details_json, occurred_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    publication_key,
                    index,
                    publication.run_id,
                    publication.publication_actor_id,
                    publication.publication_actor_type,
                    revision_id,
                    run.mode.value,
                    status,
                    details_json,
                    serialized_timestamp,
                ),
            )
        return self._publication_completion_plan_in_transaction(publication)

    def record_publication_event(
        self,
        *,
        run_id: str,
        repository: str,
        pr_number: int,
        original_head_sha: str,
        base_sha: str,
        commit_sha: str,
        publication_actor_id: int,
        publication_actor_type: str,
        event_revision_ids: Sequence[int],
        phase: str,
        open_source: OpenPullAuthorityReference,
        completion_actions: Sequence[tuple[int, str, Mapping[str, Any]]] | None = None,
        occurred_at: datetime | None = None,
    ) -> str:
        """Append one idempotent phase for an exact signed commit publication."""

        if phase in {"replied", "abandoned"}:
            raise ValueError("Terminal phases require atomic publication finalization.")
        if (phase == "prepared") != (completion_actions is not None):
            raise ValueError(
                "The prepared phase requires exactly one completion action plan."
            )
        occurred = occurred_at or _now()
        with self._connection:
            publication_key = self._record_publication_event_in_transaction(
                run_id=run_id,
                repository=repository,
                pr_number=pr_number,
                original_head_sha=original_head_sha,
                base_sha=base_sha,
                commit_sha=commit_sha,
                publication_actor_id=publication_actor_id,
                publication_actor_type=publication_actor_type,
                event_revision_ids=event_revision_ids,
                open_source=open_source,
                phase=phase,
                occurred_at=occurred,
            )
            if completion_actions is not None:
                self._record_publication_completion_plan_in_transaction(
                    publication_key=publication_key,
                    completion_actions=completion_actions,
                    occurred_at=occurred,
                )
            return publication_key

    def _record_publication_plan_actions_in_transaction(
        self,
        *,
        publication: PublicationRecord,
        occurred_at: datetime,
        abandonment_reason: str | None = None,
    ) -> RunRecord:
        """Materialize one immutable plan as terminal action audit rows."""

        run = self.get_run(publication.run_id)
        completion_plan = self._publication_completion_plan_in_transaction(publication)
        serialized_timestamp = _serialize_datetime(occurred_at)
        for revision_id, planned_status, planned_details_json in completion_plan:
            status = "failed" if abandonment_reason is not None else planned_status
            details_json = (
                _canonical_json(
                    {
                        "outcome": "publication_abandoned",
                        "reason": abandonment_reason,
                    }
                )
                if abandonment_reason is not None
                else planned_details_json
            )
            existing = self._connection.execute(
                """
                SELECT action_id, status, details_json FROM actions
                WHERE run_id = ? AND event_revision_id = ? AND action = ?
                  AND status IN ('completed', 'skipped', 'failed')
                ORDER BY action_id
                LIMIT 2
                """,
                (publication.run_id, revision_id, run.mode.value),
            ).fetchall()
            if existing:
                if (
                    len(existing) != 1
                    or existing[0]["status"] != status
                    or existing[0]["details_json"] != details_json
                ):
                    raise ValueError(
                        "Publication action conflicts with prior terminal evidence."
                    )
                continue
            self._connection.execute(
                """
                INSERT INTO actions (
                    run_id, event_revision_id, action, status,
                    details_json, occurred_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    publication.run_id,
                    revision_id,
                    run.mode.value,
                    status,
                    details_json,
                    serialized_timestamp,
                ),
            )
        return run

    def finalize_replied_publication(
        self,
        *,
        publication_key: str,
        summary: str,
        occurred_at: datetime | None = None,
    ) -> PublicationRecord:
        """Atomically resolve a remotely replied-to commit publication.

        The publication remains in its recoverable ``published`` phase until
        every prepared completion-plan action and the owning run are durable. The
        terminal ``replied`` event is appended last in the same SQLite
        transaction, so neither a Python exception nor a process crash can
        expose a terminal publication with unfinished local work.
        """

        if not isinstance(publication_key, str) or not _SHA256_RE.fullmatch(
            publication_key
        ):
            raise ValueError("publication_key must be a SHA-256 digest.")
        if not isinstance(summary, str) or not summary or "\x00" in summary:
            raise ValueError("summary must be a safe non-empty value.")
        timestamp = occurred_at or _now()
        serialized_timestamp = _serialize_datetime(timestamp)

        with self._connection:
            publication_rows = self._connection.execute(
                """
                SELECT * FROM publication_events
                WHERE publication_key = ?
                ORDER BY publication_event_id DESC
                LIMIT 2
                """,
                (publication_key,),
            ).fetchall()
            if not publication_rows:
                raise ValueError("Publication finalization requires a publication.")
            publication = self._publication_from_row(publication_rows[0])
            if publication.phase != "published":
                raise ValueError(
                    "Publication finalization requires the latest published phase."
                )
            if (
                publication.publication_actor_id is None
                or publication.publication_actor_type is None
            ):
                raise RuntimeError(
                    "Publication finalization lacks durable actor authority."
                )
            if publication.open_source is None:
                raise ValueError(
                    "Publication finalization requires exact open-pull authority."
                )
            if timestamp < publication.occurred_at:
                raise ValueError(
                    "Publication finalization timestamp must be monotonic."
                )

            run_row = self._connection.execute(
                "SELECT * FROM runs WHERE run_id = ?",
                (publication.run_id,),
            ).fetchone()
            if run_row is None:
                raise RuntimeError("Publication run is unavailable.")
            run = self.get_run(publication.run_id)
            if run.repository != publication.repository:
                raise RuntimeError("Publication run identity is malformed.")
            if run.status not in {"running", "failed", "completed"}:
                raise ValueError("Publication run cannot be completed.")

            self._record_publication_plan_actions_in_transaction(
                publication=publication,
                occurred_at=timestamp,
            )

            if run.status != "completed":
                cursor = self._connection.execute(
                    """
                    UPDATE runs
                    SET status = 'completed', finished_at = ?, summary = ?
                    WHERE run_id = ? AND status IN ('running', 'failed')
                    """,
                    (serialized_timestamp, summary, publication.run_id),
                )
                if cursor.rowcount != 1:
                    raise RuntimeError("Publication run completion raced.")

            self._record_publication_event_in_transaction(
                run_id=publication.run_id,
                repository=publication.repository,
                pr_number=publication.pr_number,
                original_head_sha=publication.original_head_sha,
                base_sha=publication.base_sha,
                commit_sha=publication.commit_sha,
                publication_actor_id=publication.publication_actor_id,
                publication_actor_type=publication.publication_actor_type,
                event_revision_ids=publication.event_revision_ids,
                open_source=publication.open_source,
                phase="replied",
                occurred_at=timestamp,
            )

        replied = self.replied_publication_for_head(
            repository=publication.repository,
            repository_id=publication.repository_id,
            pr_number=publication.pr_number,
            head_sha=publication.commit_sha,
            publication_actor_id=publication.publication_actor_id,
            publication_actor_type=publication.publication_actor_type,
        )
        if replied is None:  # pragma: no cover - committed in this method
            raise RuntimeError("Finalized publication disappeared.")
        return replied

    def finalize_abandoned_publication(
        self,
        *,
        publication_key: str,
        reason: str,
        summary: str,
        occurred_at: datetime | None = None,
    ) -> PublicationRecord:
        """Atomically fail the full plan and terminalize an abandoned commit."""

        if not isinstance(publication_key, str) or not _SHA256_RE.fullmatch(
            publication_key
        ):
            raise ValueError("publication_key must be a SHA-256 digest.")
        for label, value in (("reason", reason), ("summary", summary)):
            if not isinstance(value, str) or not value or "\x00" in value:
                raise ValueError(f"{label} must be a safe non-empty value.")
        timestamp = occurred_at or _now()
        serialized_timestamp = _serialize_datetime(timestamp)
        with self._connection:
            rows = self._connection.execute(
                """
                SELECT * FROM publication_events
                WHERE publication_key = ?
                ORDER BY publication_event_id DESC
                LIMIT 2
                """,
                (publication_key,),
            ).fetchall()
            if not rows:
                raise ValueError("Publication abandonment requires a publication.")
            publication = self._publication_from_row(rows[0])
            if publication.phase not in {"prepared", "published"}:
                raise ValueError(
                    "Publication abandonment requires a pending publication."
                )
            if (
                publication.publication_actor_id is None
                or publication.publication_actor_type is None
            ):
                raise RuntimeError(
                    "Publication abandonment lacks durable actor authority."
                )
            if publication.open_source is None:
                raise ValueError(
                    "Publication abandonment requires exact open-pull authority."
                )
            if timestamp < publication.occurred_at:
                raise ValueError("Publication abandonment timestamp must be monotonic.")
            run = self._record_publication_plan_actions_in_transaction(
                publication=publication,
                occurred_at=timestamp,
                abandonment_reason=reason,
            )
            if run.status == "completed" or run.status == "cancelled":
                raise ValueError("A completed publication run cannot be abandoned.")
            if run.status != "failed":
                cursor = self._connection.execute(
                    """
                    UPDATE runs
                    SET status = 'failed', finished_at = ?, summary = ?
                    WHERE run_id = ? AND status = 'running'
                    """,
                    (serialized_timestamp, summary, publication.run_id),
                )
                if cursor.rowcount != 1:
                    raise RuntimeError("Publication run abandonment raced.")
            self._record_publication_event_in_transaction(
                run_id=publication.run_id,
                repository=publication.repository,
                pr_number=publication.pr_number,
                original_head_sha=publication.original_head_sha,
                base_sha=publication.base_sha,
                commit_sha=publication.commit_sha,
                publication_actor_id=publication.publication_actor_id,
                publication_actor_type=publication.publication_actor_type,
                event_revision_ids=publication.event_revision_ids,
                open_source=publication.open_source,
                phase="abandoned",
                occurred_at=timestamp,
            )
        row = self._connection.execute(
            """
            SELECT * FROM publication_events
            WHERE publication_key = ? AND phase = 'abandoned'
            """,
            (publication_key,),
        ).fetchone()
        if row is None:  # pragma: no cover - committed in this method
            raise RuntimeError("Abandoned publication disappeared.")
        return self._publication_from_row(row)

    def has_pending_publication_for_run(self, run_id: str) -> bool:
        """Return whether a run still owns a recoverable publication cursor."""

        if not isinstance(run_id, str) or not run_id:
            raise ValueError("run_id must be a non-empty string.")
        rows = self._connection.execute(
            """
            SELECT latest.* FROM (
                SELECT publication.*,
                       ROW_NUMBER() OVER (
                           PARTITION BY publication.publication_key
                           ORDER BY publication.publication_event_id DESC
                       ) AS guardian_row_number
                FROM publication_events AS publication
                WHERE publication.run_id = ?
            ) AS latest
            LEFT JOIN publication_reply_terminal_events AS reply_terminal
              ON reply_terminal.publication_key = latest.publication_key
            WHERE latest.guardian_row_number = 1
              AND latest.phase IN ('prepared', 'published')
              AND reply_terminal.publication_key IS NULL
            LIMIT 2
            """,
            (run_id,),
        ).fetchall()
        if len(rows) > 1:
            raise RuntimeError("A run owns multiple pending publications.")
        if rows:
            publication = self._publication_from_row(rows[0])
            if (
                publication.publication_actor_id is None
                or publication.publication_actor_type is None
            ):
                raise RuntimeError(
                    "Pending publication lacks durable publication-actor authority."
                )
        return bool(rows)

    def record_publication_completion_action(
        self,
        *,
        publication_key: str,
        event_revision_id: int,
        details: Mapping[str, Any],
        occurred_at: datetime | None = None,
    ) -> int:
        """Record one exact recovered-publication action at most once.

        Recovery can stop after this transaction commits but before its run or
        reply terminal is finalized.  Bind idempotency to the immutable
        publication, run, revision, action, and canonical details rather than
        appending a duplicate audit row on the next recovery.
        """

        if not isinstance(publication_key, str) or not _SHA256_RE.fullmatch(
            publication_key
        ):
            raise ValueError("publication_key must be a SHA-256 digest.")
        if (
            isinstance(event_revision_id, bool)
            or not isinstance(event_revision_id, int)
            or event_revision_id <= 0
        ):
            raise ValueError("event_revision_id must be a positive integer.")
        if not isinstance(details, Mapping):
            raise TypeError("details must be a mapping.")
        details_json = _canonical_json(details)
        timestamp = _serialize_datetime(occurred_at or _now())
        with self._connection:
            publication_rows = self._connection.execute(
                """
                SELECT * FROM publication_events
                WHERE publication_key = ? AND phase = 'published'
                ORDER BY publication_event_id
                LIMIT 2
                """,
                (publication_key,),
            ).fetchall()
            if len(publication_rows) != 1:
                raise ValueError(
                    "Publication completion action requires an exact published "
                    "publication."
                )
            publication = self._publication_from_row(publication_rows[0])
            if (
                publication.publication_actor_id is None
                or publication.publication_actor_type is None
            ):
                raise RuntimeError(
                    "Publication completion action lacks durable actor authority."
                )
            if event_revision_id not in publication.event_revision_ids:
                raise ValueError(
                    "Publication completion action revision is outside its evidence."
                )
            run = self.get_run(publication.run_id)
            action = run.mode.value
            existing = self._connection.execute(
                """
                SELECT action_id, details_json FROM actions
                WHERE run_id = ? AND event_revision_id = ?
                  AND action = ? AND status = 'completed'
                ORDER BY action_id
                LIMIT 2
                """,
                (publication.run_id, event_revision_id, action),
            ).fetchall()
            if existing:
                if len(existing) != 1 or existing[0]["details_json"] != details_json:
                    raise ValueError(
                        "Publication completion action conflicts with prior evidence."
                    )
                return int(existing[0]["action_id"])
            cursor = self._connection.execute(
                """
                INSERT INTO actions (
                    run_id, event_revision_id, action, status,
                    details_json, occurred_at
                ) VALUES (?, ?, ?, 'completed', ?, ?)
                """,
                (
                    publication.run_id,
                    event_revision_id,
                    action,
                    details_json,
                    timestamp,
                ),
            )
        return int(cursor.lastrowid)

    def publication_reply_terminal_reason(
        self,
        publication_key: str,
    ) -> str | None:
        """Return the durable reason an exact published successor needs no reply."""

        if not isinstance(publication_key, str) or not _SHA256_RE.fullmatch(
            publication_key
        ):
            raise ValueError("publication_key must be a SHA-256 digest.")
        row = self._connection.execute(
            """
            SELECT terminal.reason, terminal.occurred_at
            FROM publication_reply_terminal_events AS terminal
            LEFT JOIN remediation_successor_publications AS successor
              ON successor.publication_key = terminal.publication_key
            JOIN publication_events AS publication
              ON publication.publication_key = terminal.publication_key
             AND publication.phase = 'published'
            WHERE terminal.publication_key = ?
              AND (terminal.reason = 'trusted_feedback_changed'
                   OR successor.publication_key IS NOT NULL)
            LIMIT 2
            """,
            (publication_key,),
        ).fetchall()
        if not row:
            raw = self._connection.execute(
                """
                SELECT 1 FROM publication_reply_terminal_events
                WHERE publication_key = ?
                """,
                (publication_key,),
            ).fetchone()
            if raw is not None:
                raise RuntimeError("Publication reply terminal ledger is malformed.")
            return None
        if len(row) != 1:
            raise RuntimeError("Publication reply terminal ledger is malformed.")
        reason = str(row[0]["reason"])
        occurred_at = _parse_datetime(str(row[0]["occurred_at"]))
        if (
            reason not in _PUBLICATION_REPLY_TERMINAL_REASONS
            or occurred_at is None
            or _serialize_datetime(occurred_at) != row[0]["occurred_at"]
        ):
            raise RuntimeError("Publication reply terminal ledger is malformed.")
        return reason

    def _record_publication_reply_terminal_in_transaction(
        self,
        *,
        publication_key: str,
        reason: str,
        occurred_at: datetime,
    ) -> str:
        """Append a successor reply terminal without opening a transaction."""

        if not isinstance(publication_key, str) or not _SHA256_RE.fullmatch(
            publication_key
        ):
            raise ValueError("publication_key must be a SHA-256 digest.")
        if reason not in _PUBLICATION_REPLY_TERMINAL_REASONS:
            raise ValueError("Unsupported publication reply terminal reason.")
        serialized = _serialize_datetime(occurred_at)
        existing = self.publication_reply_terminal_reason(publication_key)
        if existing is not None:
            if existing != reason:
                raise ValueError("Publication reply is already terminal.")
            return existing
        published = self._connection.execute(
            """
            SELECT publication.occurred_at
            FROM publication_events AS publication
            LEFT JOIN remediation_successor_publications AS successor
              ON successor.publication_key = publication.publication_key
            WHERE publication.publication_key = ?
              AND publication.phase = 'published'
              AND (? = 'trusted_feedback_changed'
                   OR successor.publication_key IS NOT NULL)
            LIMIT 2
            """,
            (publication_key, reason),
        ).fetchall()
        if len(published) != 1:
            raise ValueError(
                "Publication reply terminal requires an exact published successor."
            )
        published_at = _parse_datetime(str(published[0]["occurred_at"]))
        if published_at is None or occurred_at < published_at:
            raise ValueError("Publication reply terminal timestamp must be monotonic.")
        self._connection.execute(
            """
            INSERT INTO publication_reply_terminal_events (
                publication_key, reason, occurred_at
            ) VALUES (?, ?, ?)
            """,
            (publication_key, reason, serialized),
        )
        return reason

    def record_publication_reply_terminal(
        self,
        *,
        publication_key: str,
        reason: str,
        occurred_at: datetime | None = None,
    ) -> str:
        """Reject terminal writes that bypass atomic local completion."""

        del publication_key, reason, occurred_at
        raise ValueError(
            "Publication reply terminals require atomic publication finalization."
        )

    def finalize_publication_reply_terminal(
        self,
        *,
        publication_key: str,
        reason: str,
        summary: str,
        occurred_at: datetime | None = None,
    ) -> str:
        """Atomically complete a successor whose reply is no longer applicable."""

        if not isinstance(publication_key, str) or not _SHA256_RE.fullmatch(
            publication_key
        ):
            raise ValueError("publication_key must be a SHA-256 digest.")
        if reason not in _PUBLICATION_REPLY_TERMINAL_REASONS:
            raise ValueError("Unsupported publication reply terminal reason.")
        if not isinstance(summary, str) or not summary or "\x00" in summary:
            raise ValueError("summary must be a safe non-empty value.")
        timestamp = occurred_at or _now()
        serialized_timestamp = _serialize_datetime(timestamp)
        with self._connection:
            rows = self._connection.execute(
                """
                SELECT publication.*
                FROM publication_events AS publication
                LEFT JOIN remediation_successor_publications AS successor
                  ON successor.publication_key = publication.publication_key
                WHERE publication.publication_key = ?
                  AND (? = 'trusted_feedback_changed'
                       OR successor.publication_key IS NOT NULL)
                ORDER BY publication.publication_event_id DESC
                LIMIT 2
                """,
                (publication_key, reason),
            ).fetchall()
            if not rows:
                raise ValueError(
                    "Publication reply terminal requires an exact successor."
                )
            publication = self._publication_from_row(rows[0])
            if (
                publication.publication_actor_id is None
                or publication.publication_actor_type is None
            ):
                raise RuntimeError(
                    "Publication reply terminal lacks durable actor authority."
                )
            if publication.phase != "published" or timestamp < publication.occurred_at:
                raise ValueError(
                    "Publication reply terminal requires a current published successor."
                )
            run = self._record_publication_plan_actions_in_transaction(
                publication=publication,
                occurred_at=timestamp,
            )
            if run.status not in {"running", "failed", "completed"}:
                raise ValueError("Publication run cannot be completed.")
            if run.status != "completed":
                cursor = self._connection.execute(
                    """
                    UPDATE runs
                    SET status = 'completed', finished_at = ?, summary = ?
                    WHERE run_id = ? AND status IN ('running', 'failed')
                    """,
                    (serialized_timestamp, summary, publication.run_id),
                )
                if cursor.rowcount != 1:
                    raise RuntimeError("Publication run completion raced.")
            return self._record_publication_reply_terminal_in_transaction(
                publication_key=publication_key,
                reason=reason,
                occurred_at=timestamp,
            )

    def pending_publications(
        self,
        *,
        repository: str | None = None,
        repository_id: int | None = None,
        limit: int = _MAX_PENDING_PUBLICATION_WORKSET,
    ) -> tuple[PublicationRecord, ...]:
        """Return a bounded oldest-first publication-recovery workset.

        The immutable ID is authoritative when both repository filters are given.
        """

        if (
            isinstance(limit, bool)
            or not isinstance(limit, int)
            or not 1 <= limit <= _MAX_PENDING_PUBLICATION_WORKSET
        ):
            raise ValueError("limit must be an integer from 1 through 100.")
        _validate_repository_id_filter(repository_id)

        if repository_id is not None and repository is not None:
            # Check legacy ambiguity globally and outside the bounded modern
            # workset. A NULL-ID row cannot be attributed after a repository
            # rename and must never hide behind 100 older exact-ID rows.
            ambiguous_legacy = self._connection.execute(
                """
                SELECT 1 FROM (
                    SELECT p.publication_key, p.phase,
                           ROW_NUMBER() OVER (
                               PARTITION BY publication_key
                               ORDER BY publication_event_id DESC
                           ) AS guardian_row_number
                    FROM publication_events AS p
                    WHERE p.repository_id IS NULL
                ) AS latest
                LEFT JOIN publication_reply_terminal_events AS reply_terminal
                  ON reply_terminal.publication_key = latest.publication_key
                WHERE latest.guardian_row_number = 1
                  AND latest.phase IN ('prepared', 'published')
                  AND reply_terminal.publication_key IS NULL
                LIMIT 1
                """,
            ).fetchone()
            if ambiguous_legacy is not None:
                raise RuntimeError(
                    "Pending publication lacks durable repository authority."
                )
            where = "WHERE repository_id = ?"
            parameters: tuple[object, ...] = (repository_id,)
        elif repository_id is not None:
            where = "WHERE repository_id = ?"
            parameters = (repository_id,)
        elif repository is not None:
            where = "WHERE repository = ?"
            parameters = (repository,)
        else:
            where = ""
            parameters = ()
        rows = self._connection.execute(
            f"""
            SELECT latest.* FROM (
                SELECT p.*,
                       ROW_NUMBER() OVER (
                           PARTITION BY publication_key
                           ORDER BY publication_event_id DESC
                       ) AS guardian_row_number
                FROM publication_events AS p
                {where}
            ) AS latest
            LEFT JOIN publication_reply_terminal_events AS reply_terminal
              ON reply_terminal.publication_key = latest.publication_key
            WHERE latest.guardian_row_number = 1
              AND latest.phase IN ('prepared', 'published')
              AND reply_terminal.publication_key IS NULL
            ORDER BY latest.publication_event_id
            LIMIT ?
            """,
            (*parameters, limit),
        ).fetchall()
        publications = tuple(self._publication_from_row(row) for row in rows)
        if any(
            publication.publication_actor_id is None
            or publication.publication_actor_type is None
            for publication in publications
        ):
            raise RuntimeError(
                "Pending publication lacks durable publication-actor authority."
            )
        if any(
            publication.repository_id is None or publication.open_source is None
            for publication in publications
        ):
            raise RuntimeError(
                "Pending publication lacks durable repository authority."
            )
        return publications

    def replied_publication_for_head(
        self,
        *,
        repository: str,
        repository_id: int | None = None,
        pr_number: int,
        head_sha: str,
        publication_actor_id: int,
        publication_actor_type: str,
    ) -> PublicationRecord | None:
        """Return an actor-bound replied publication for the exact current head.

        The immutable ID is authoritative when both repository filters are given.
        """

        if (
            isinstance(publication_actor_id, bool)
            or not isinstance(publication_actor_id, int)
            or not 0 < publication_actor_id <= _SQLITE_MAX_INTEGER
        ):
            raise ValueError("publication_actor_id must be a positive integer.")
        if not isinstance(
            publication_actor_type, str
        ) or publication_actor_type not in {"User", "Bot"}:
            raise ValueError("publication_actor_type must be User or Bot.")
        _validate_repository_id_filter(repository_id)

        if repository_id is None:
            repository_where = "p.repository = ?"
            repository_parameters: tuple[object, ...] = (repository,)
        else:
            # A legacy NULL-ID reply may belong to this repository under an old
            # route, so no mutable-name filter can exclude it safely. Check all
            # exact head/actor matches before trusting the immutable-ID lookup.
            ambiguous_legacy = self._connection.execute(
                """
                SELECT 1 FROM publication_events AS p
                WHERE p.repository_id IS NULL
                  AND p.pr_number = ? AND p.commit_sha = ?
                  AND p.phase = 'replied'
                  AND p.publication_actor_id = ?
                  AND p.publication_actor_type = ?
                LIMIT 1
                """,
                (
                    pr_number,
                    head_sha,
                    publication_actor_id,
                    publication_actor_type,
                ),
            ).fetchone()
            if ambiguous_legacy is not None:
                raise RuntimeError(
                    "Replied publication lacks durable repository authority."
                )
            repository_where = "p.repository_id = ?"
            repository_parameters = (repository_id,)

        row = self._connection.execute(
            f"""
            SELECT p.* FROM publication_events AS p
            WHERE {repository_where} AND p.pr_number = ? AND p.commit_sha = ?
              AND p.phase = 'replied'
              AND p.publication_actor_id = ?
              AND p.publication_actor_type = ?
            ORDER BY p.publication_event_id DESC
            LIMIT 1
            """,
            (
                *repository_parameters,
                pr_number,
                head_sha,
                publication_actor_id,
                publication_actor_type,
            ),
        ).fetchone()
        if row is None:
            return None
        publication = self._publication_from_row(row)
        if publication.repository_id is None or publication.open_source is None:
            raise RuntimeError(
                "Replied publication lacks durable repository authority."
            )
        return publication

    def _prevention_from_row(self, row: sqlite3.Row) -> PreventionDraftRecord:
        try:
            self._validate_draft_run_authority(
                run_id=row["run_id"],
                repository=row["source_repository"],
                allowed_modes=_PREVENTION_DRAFT_RUN_MODES,
                label="Prevention draft",
            )
            _validate_prevention_event_identity(
                source_repository=row["source_repository"],
                target_repository=row["target_repository"],
                target_base_branch=row["target_base_branch"],
                target_base_sha=row["target_base_sha"],
                push_repository=row["push_repository"],
                branch=row["branch"],
                candidate_sha=row["candidate_sha"],
                evidence_hash=row["evidence_hash"],
                title=row["title"],
                body=row["body"],
                phase=row["phase"],
                draft_number=row["draft_number"],
                draft_url=row["draft_url"],
            )
            occurred_at = _parse_datetime(row["occurred_at"])
            draft_key = str(row["draft_key"])
            source_policy_json = _validated_attestation_json(
                row["source_policy_json"],
                label="source_policy_json",
            )
            policy = _prevention_policy_from_json(source_policy_json)
            test_attestation_json = _validated_attestation_json(
                row["test_attestation_json"],
                label="test_attestation_json",
            )
            source_policy_digest = str(row["source_policy_digest"])
            test_attestation_digest = str(row["test_attestation_digest"])
            patch_hash = str(row["patch_hash"])
            open_source = _open_pull_authority_from_json(row["open_source_json"])
            if (
                occurred_at is None
                or occurred_at.tzinfo is None
                or occurred_at.utcoffset() is None
                or _serialize_datetime(occurred_at) != row["occurred_at"]
                or row["attestation_version"] != 3
                or policy.source_repository
                != (row["source_repository"], row["source_repository_id"])
                or policy.target_repository
                != (row["target_repository"], row["target_repository_id"])
                or policy.push_repository
                != (row["push_repository"], row["push_repository_id"])
                or policy.target_base_branch != row["target_base_branch"]
                or row["branch"]
                != (
                    f"{policy.push_branch_prefix}"
                    f"{row['target_base_sha'][:12]}-{row['evidence_hash']}"
                )
                or not _SHA256_RE.fullmatch(draft_key)
                or not _SHA256_RE.fullmatch(source_policy_digest)
                or not _SHA256_RE.fullmatch(test_attestation_digest)
                or not _SHA256_RE.fullmatch(patch_hash)
                or hashlib.sha256(source_policy_json.encode("ascii")).hexdigest()
                != source_policy_digest
                or hashlib.sha256(test_attestation_json.encode("ascii")).hexdigest()
                != test_attestation_digest
                or not isinstance(row["title"], str)
                or not row["title"]
                or len(row["title"].encode("utf-8")) > _MAX_PREVENTION_TITLE_BYTES
                or any(character in row["title"] for character in "\r\n\x00")
                or not isinstance(row["body"], str)
                or not row["body"]
                or len(row["body"].encode("utf-8")) > _MAX_PREVENTION_BODY_BYTES
                or "\x00" in row["body"]
                or not isinstance(row["patch_paths_json"], str)
                or len(row["patch_paths_json"].encode("utf-8"))
                > _MAX_PREVENTION_PATCH_JSON_BYTES
                or not isinstance(row["source_pulls_json"], str)
                or len(row["source_pulls_json"].encode("utf-8"))
                > _MAX_PREVENTION_SOURCE_JSON_BYTES
                or not isinstance(row["event_revision_ids_json"], str)
                or len(row["event_revision_ids_json"].encode("utf-8"))
                > _MAX_PREVENTION_SOURCE_JSON_BYTES
            ):
                raise ValueError
            _validate_prevention_test_attestation(
                test_attestation_json,
                policy=policy,
                target_base_sha=row["target_base_sha"],
                candidate_sha=row["candidate_sha"],
            )
            raw_paths = loads_bounded_json(row["patch_paths_json"])
            if (
                not isinstance(raw_paths, list)
                or not raw_paths
                or len(raw_paths) > _MAX_PREVENTION_PATCH_PATHS
                or any(
                    not isinstance(path, str)
                    or not path
                    or len(path.encode("utf-8")) > _MAX_PREVENTION_PATH_BYTES
                    or path.startswith("/")
                    or "\\" in path
                    or any(part in {"", ".", ".."} for part in path.split("/"))
                    or any(character in path for character in "\r\n\x00")
                    for path in raw_paths
                )
                or raw_paths != sorted(set(raw_paths))
                or _canonical_attestation_json(raw_paths) != row["patch_paths_json"]
            ):
                raise ValueError
            patch_paths = tuple(raw_paths)
            raw_pulls = loads_bounded_json(row["source_pulls_json"])
            raw_revision_ids = loads_bounded_json(row["event_revision_ids_json"])
            if (
                not isinstance(raw_pulls, list)
                or not isinstance(
                    raw_revision_ids,
                    list,
                )
                or len(raw_pulls) > _MAX_PREVENTION_SOURCE_PULLS
                or len(raw_revision_ids) > _MAX_PREVENTION_SOURCE_REVISIONS
            ):
                raise ValueError
            source_pulls = tuple(
                HistoricalPullReference(
                    repository=item["repository"],
                    repository_id=item["repository_id"],
                    pull_id=item["pull_id"],
                    pr_number=item["pr_number"],
                    pull_revision_digest=item["pull_revision_digest"],
                    authority_digest=item["authority_digest"],
                    policy_digest=item["policy_digest"],
                    head_sha=item["head_sha"],
                    base_sha=item["base_sha"],
                )
                for item in raw_pulls
                if isinstance(item, Mapping)
            )
            event_revision_ids = tuple(raw_revision_ids)
            if (
                len(source_pulls) != len(raw_pulls)
                or len(set(source_pulls)) != len(source_pulls)
                or (
                    source_pulls
                    and (
                        len({source.pull_id for source in source_pulls})
                        != len(source_pulls)
                        or len({source.pr_number for source in source_pulls})
                        != len(source_pulls)
                        or len({source.policy_digest for source in source_pulls}) != 1
                    )
                )
                or any(
                    source.repository != row["source_repository"]
                    or source.repository_id != row["source_repository_id"]
                    for source in source_pulls
                )
                or any(
                    isinstance(value, bool)
                    or not isinstance(value, int)
                    or not 0 < value <= _SQLITE_MAX_INTEGER
                    for value in event_revision_ids
                )
                or len(set(event_revision_ids)) != len(event_revision_ids)
                or tuple(sorted(event_revision_ids)) != event_revision_ids
                or (open_source is not None) == bool(source_pulls)
                or not event_revision_ids
                or (
                    open_source is not None
                    and (
                        open_source.repository != row["source_repository"]
                        or open_source.repository_id != row["source_repository_id"]
                    )
                )
                or _open_pull_authority_json(open_source) != row["open_source_json"]
                or _prevention_source_pulls_json(source_pulls)
                != row["source_pulls_json"]
                or _canonical_attestation_json(list(event_revision_ids))
                != row["event_revision_ids_json"]
            ):
                raise ValueError
            expected_key = _prevention_draft_key(
                run_id=row["run_id"],
                source_repository=row["source_repository"],
                target_repository=row["target_repository"],
                target_base_branch=row["target_base_branch"],
                target_base_sha=row["target_base_sha"],
                push_repository=row["push_repository"],
                branch=row["branch"],
                candidate_sha=row["candidate_sha"],
                evidence_hash=row["evidence_hash"],
                source_policy_json=source_policy_json,
                source_policy_digest=source_policy_digest,
                patch_paths_json=row["patch_paths_json"],
                patch_hash=patch_hash,
                test_attestation_json=test_attestation_json,
                test_attestation_digest=test_attestation_digest,
                open_source_json=row["open_source_json"],
                source_pulls_json=row["source_pulls_json"],
                event_revision_ids_json=row["event_revision_ids_json"],
                title=row["title"],
                body=row["body"],
            )
            if expected_key != draft_key:
                raise ValueError
        except (KeyError, TypeError, ValueError, json.JSONDecodeError, RecursionError):
            raise RuntimeError(
                "Prevention draft ledger contains malformed data."
            ) from None
        return PreventionDraftRecord(
            draft_key=draft_key,
            run_id=row["run_id"],
            source_repository=row["source_repository"],
            source_repository_id=int(row["source_repository_id"]),
            target_repository=row["target_repository"],
            target_repository_id=int(row["target_repository_id"]),
            target_base_branch=row["target_base_branch"],
            target_base_sha=row["target_base_sha"],
            push_repository=row["push_repository"],
            push_repository_id=int(row["push_repository_id"]),
            branch=row["branch"],
            candidate_sha=row["candidate_sha"],
            evidence_hash=row["evidence_hash"],
            source_policy_json=source_policy_json,
            source_policy_digest=source_policy_digest,
            patch_paths=patch_paths,
            patch_hash=patch_hash,
            test_attestation_json=test_attestation_json,
            test_attestation_digest=test_attestation_digest,
            open_source=open_source,
            source_pulls=source_pulls,
            event_revision_ids=event_revision_ids,
            title=row["title"],
            body=row["body"],
            phase=row["phase"],
            draft_number=(
                int(row["draft_number"]) if row["draft_number"] is not None else None
            ),
            draft_url=row["draft_url"],
            occurred_at=occurred_at,
        )

    def _legacy_prevention_from_rows(
        self,
        rows: Sequence[sqlite3.Row],
    ) -> LegacyPreventionDraftRecord:
        """Validate a migration-marked v1 ledger without granting publish authority."""

        try:
            if not rows or len(rows) > 4:
                raise ValueError
            first = rows[0]
            draft_key = first["draft_key"]
            run_id = first["run_id"]
            if (
                not isinstance(draft_key, str)
                or not _SHA256_RE.fullmatch(draft_key)
                or not isinstance(run_id, str)
                or not run_id
                or len(run_id.encode("utf-8")) > _MAX_RUN_ID_BYTES
                or "\x00" in run_id
            ):
                raise ValueError
            self._validate_draft_run_authority(
                run_id=run_id,
                repository=first["source_repository"],
                allowed_modes=_PREVENTION_DRAFT_RUN_MODES,
                label="Legacy prevention draft",
            )
            identity = tuple(
                first[field]
                for field in (
                    "run_id",
                    "source_repository",
                    "target_repository",
                    "target_base_branch",
                    "target_base_sha",
                    "push_repository",
                    "branch",
                    "candidate_sha",
                    "evidence_hash",
                    "title",
                    "body",
                )
            )
            phases: list[str] = []
            timestamps: list[datetime] = []
            for row in rows:
                _validate_prevention_event_identity(
                    source_repository=row["source_repository"],
                    target_repository=row["target_repository"],
                    target_base_branch=row["target_base_branch"],
                    target_base_sha=row["target_base_sha"],
                    push_repository=row["push_repository"],
                    branch=row["branch"],
                    candidate_sha=row["candidate_sha"],
                    evidence_hash=row["evidence_hash"],
                    title=row["title"],
                    body=row["body"],
                    phase=row["phase"],
                    draft_number=row["draft_number"],
                    draft_url=row["draft_url"],
                    title_max_bytes=_MAX_LEGACY_PREVENTION_TITLE_BYTES,
                )
                if len(str(row["title"])) > 120:
                    raise ValueError
                if (
                    tuple(
                        row[field]
                        for field in (
                            "run_id",
                            "source_repository",
                            "target_repository",
                            "target_base_branch",
                            "target_base_sha",
                            "push_repository",
                            "branch",
                            "candidate_sha",
                            "evidence_hash",
                            "title",
                            "body",
                        )
                    )
                    != identity
                ):
                    raise ValueError
                parsed_at = _parse_datetime(row["occurred_at"])
                if (
                    parsed_at is None
                    or parsed_at.tzinfo is None
                    or parsed_at.utcoffset() is None
                    or _serialize_datetime(parsed_at) != row["occurred_at"]
                    or not isinstance(row["prevention_event_id"], int)
                    or int(row["prevention_event_id"]) <= 0
                ):
                    raise ValueError
                phases.append(str(row["phase"]))
                timestamps.append(parsed_at)
            if tuple(phases) not in {
                ("validated",),
                ("validated", "pushed"),
                ("validated", "draft_opened"),
                ("validated", "pushed", "draft_opened"),
                ("validated", "abandoned"),
                ("validated", "pushed", "abandoned"),
            } or timestamps != sorted(timestamps):
                raise ValueError
            expected_key = _legacy_prevention_draft_key(
                source_repository=first["source_repository"],
                target_repository=first["target_repository"],
                target_base_branch=first["target_base_branch"],
                target_base_sha=first["target_base_sha"],
                candidate_sha=first["candidate_sha"],
                evidence_hash=first["evidence_hash"],
            )
            branch_suffix = (
                f"{str(first['target_base_sha'])[:12]}-{first['evidence_hash']}"
            )
            if (
                expected_key != draft_key
                or not str(first["branch"]).endswith(branch_suffix)
                or str(first["branch"]) == branch_suffix
            ):
                raise ValueError
        except (TypeError, ValueError):
            raise RuntimeError(
                "Legacy prevention draft ledger contains malformed data."
            ) from None
        latest = rows[-1]
        return LegacyPreventionDraftRecord(
            prevention_event_id=int(latest["prevention_event_id"]),
            draft_key=draft_key,
            run_id=run_id,
            source_repository=str(latest["source_repository"]),
            target_repository=str(latest["target_repository"]),
            target_base_branch=str(latest["target_base_branch"]),
            target_base_sha=str(latest["target_base_sha"]),
            push_repository=str(latest["push_repository"]),
            branch=str(latest["branch"]),
            candidate_sha=str(latest["candidate_sha"]),
            evidence_hash=str(latest["evidence_hash"]),
            title=str(latest["title"]),
            body=str(latest["body"]),
            phase=str(latest["phase"]),
            draft_number=(
                int(latest["draft_number"])
                if latest["draft_number"] is not None
                else None
            ),
            draft_url=(
                str(latest["draft_url"]) if latest["draft_url"] is not None else None
            ),
            occurred_at=timestamps[-1],
        )

    def legacy_prevention_draft_by_key(
        self,
        draft_key: str,
    ) -> LegacyPreventionDraftRecord | None:
        """Return a migration-marked v1 candidate for GET-only reconciliation."""

        if not isinstance(draft_key, str) or not _SHA256_RE.fullmatch(draft_key):
            raise ValueError("draft_key must be a SHA-256 digest.")
        preflight = self._connection.execute(
            f"""
            SELECT COUNT(*) AS event_count,
                   COALESCE(SUM(legacy.prevention_event_id IS NOT NULL), 0)
                       AS legacy_count,
                   COALESCE(SUM(attestation.draft_key IS NOT NULL), 0)
                       AS attestation_count,
                   COALESCE(SUM(
                       typeof(event.draft_key) != 'text'
                       OR length(CAST(event.draft_key AS BLOB)) != 64
                       OR typeof(event.run_id) != 'text'
                       OR length(CAST(event.run_id AS BLOB)) > {_MAX_RUN_ID_BYTES}
                       OR typeof(event.source_repository) != 'text'
                       OR length(CAST(event.source_repository AS BLOB)) >
                          {_MAX_REPOSITORY_BYTES}
                       OR typeof(event.target_repository) != 'text'
                       OR length(CAST(event.target_repository AS BLOB)) >
                          {_MAX_REPOSITORY_BYTES}
                       OR typeof(event.target_base_branch) != 'text'
                       OR length(CAST(event.target_base_branch AS BLOB)) > 255
                       OR typeof(event.target_base_sha) != 'text'
                       OR length(CAST(event.target_base_sha AS BLOB)) > 64
                       OR typeof(event.push_repository) != 'text'
                       OR length(CAST(event.push_repository AS BLOB)) >
                          {_MAX_REPOSITORY_BYTES}
                       OR typeof(event.branch) != 'text'
                       OR length(CAST(event.branch AS BLOB)) > 255
                       OR typeof(event.candidate_sha) != 'text'
                       OR length(CAST(event.candidate_sha AS BLOB)) > 64
                       OR typeof(event.evidence_hash) != 'text'
                       OR length(CAST(event.evidence_hash AS BLOB)) != 64
                       OR typeof(event.title) != 'text'
                       OR length(CAST(event.title AS BLOB)) >
                          {_MAX_LEGACY_PREVENTION_TITLE_BYTES}
                       OR typeof(event.body) != 'text'
                       OR length(CAST(event.body AS BLOB)) >
                          {_MAX_PREVENTION_BODY_BYTES}
                       OR typeof(event.phase) != 'text'
                       OR length(CAST(event.phase AS BLOB)) > 32
                       OR (
                           event.draft_number IS NOT NULL
                           AND typeof(event.draft_number) != 'integer'
                       )
                       OR (
                           event.draft_url IS NOT NULL
                           AND (
                               typeof(event.draft_url) != 'text'
                               OR length(CAST(event.draft_url AS BLOB)) >
                                  {_MAX_PREVENTION_URL_BYTES}
                           )
                       )
                       OR typeof(event.occurred_at) != 'text'
                       OR length(CAST(event.occurred_at AS BLOB)) > 64
                   ), 0) AS malformed_count
            FROM prevention_draft_events AS event
            LEFT JOIN prevention_legacy_candidate_events AS legacy
              ON legacy.prevention_event_id = event.prevention_event_id
            LEFT JOIN prevention_candidate_attestations AS attestation
              ON attestation.draft_key = event.draft_key
            WHERE event.draft_key = ?
            """,
            (draft_key,),
        ).fetchone()
        if preflight is None:  # pragma: no cover - aggregate always returns a row
            raise RuntimeError("Legacy prevention preflight failed.")
        event_count = int(preflight["event_count"])
        legacy_count = int(preflight["legacy_count"])
        if event_count == 0 or legacy_count == 0:
            return None
        if (
            event_count > 4
            or legacy_count != event_count
            or int(preflight["attestation_count"]) != 0
            or int(preflight["malformed_count"]) != 0
        ):
            raise RuntimeError(
                "Legacy prevention draft ledger contains malformed data."
            )
        rows = self._connection.execute(
            """
            SELECT event.*
            FROM prevention_draft_events AS event
            JOIN prevention_legacy_candidate_events AS legacy
              ON legacy.prevention_event_id = event.prevention_event_id
            LEFT JOIN prevention_candidate_attestations AS attestation
              ON attestation.draft_key = event.draft_key
            WHERE event.draft_key = ? AND attestation.draft_key IS NULL
            ORDER BY event.prevention_event_id
            LIMIT 5
            """,
            (draft_key,),
        ).fetchall()
        if len(rows) != event_count:
            raise RuntimeError("Legacy prevention draft ledger is not immutable.")
        return self._legacy_prevention_from_rows(rows)

    def record_legacy_prevention_reconciliation(
        self,
        *,
        record: LegacyPreventionDraftRecord,
        source_repository_id: int,
        target_repository_id: int | None,
        push_repository_id: int | None,
        source_policy_digest: str,
        disposition: str,
        draft_number: int | None = None,
        draft_url: str | None = None,
        occurred_at: datetime | None = None,
    ) -> None:
        """Terminalize a v1 candidate after a bounded, read-only remote check."""

        if not isinstance(record, LegacyPreventionDraftRecord):
            raise TypeError("record must be a legacy prevention draft.")
        if (
            isinstance(source_repository_id, bool)
            or not isinstance(source_repository_id, int)
            or not 0 < source_repository_id <= _SQLITE_MAX_INTEGER
        ):
            raise ValueError("source repository ID must be a positive integer.")
        optional_repository_ids = (target_repository_id, push_repository_id)
        if any(
            repository_id is not None
            and (
                isinstance(repository_id, bool)
                or not isinstance(repository_id, int)
                or not 0 < repository_id <= _SQLITE_MAX_INTEGER
            )
            for repository_id in optional_repository_ids
        ) or (
            disposition != "policy_changed"
            and any(repository_id is None for repository_id in optional_repository_ids)
        ):
            raise ValueError("target and push repository IDs are malformed.")
        if not isinstance(source_policy_digest, str) or not _SHA256_RE.fullmatch(
            source_policy_digest
        ):
            raise ValueError("source_policy_digest must be a SHA-256 digest.")
        if disposition not in {
            "draft_opened",
            "not_found",
            "remote_conflict",
            "policy_changed",
            "recovery_exhausted",
        }:
            raise ValueError("Unsupported legacy prevention disposition.")
        if disposition == "draft_opened":
            if (
                isinstance(draft_number, bool)
                or not isinstance(draft_number, int)
                or not 0 < draft_number <= _SQLITE_MAX_INTEGER
                or not isinstance(draft_url, str)
                or not draft_url
                or len(draft_url.encode("utf-8")) > _MAX_PREVENTION_URL_BYTES
                or any(character in draft_url for character in "\r\n\x00")
            ):
                raise ValueError("An opened legacy draft needs its number and URL.")
        elif draft_number is not None or draft_url is not None:
            raise ValueError("Only an opened legacy draft may store PR metadata.")
        current = self.legacy_prevention_draft_by_key(record.draft_key)
        if current != record:
            raise ValueError("Legacy prevention draft changed before reconciliation.")
        if (
            disposition == "draft_opened"
            and record.phase == "draft_opened"
            and (record.draft_number != draft_number or record.draft_url != draft_url)
        ):
            raise ValueError(
                "Legacy exact prevention draft conflicts with its released record."
            )
        timestamp = _serialize_datetime(occurred_at or _now())
        identity = (
            record.draft_key,
            source_repository_id,
            target_repository_id,
            push_repository_id,
            source_policy_digest,
            record.evidence_hash,
            disposition,
            draft_number,
            draft_url,
        )
        with self._connection:
            if disposition == "draft_opened":
                exact_identity = (
                    record.draft_key,
                    source_repository_id,
                    target_repository_id,
                    push_repository_id,
                    source_policy_digest,
                    record.evidence_hash,
                    draft_number,
                    draft_url,
                )
                exact_existing = self._connection.execute(
                    """
                    SELECT draft_key, source_repository_id, target_repository_id,
                           push_repository_id, source_policy_digest, evidence_hash,
                           draft_number, draft_url
                    FROM prevention_legacy_exact_drafts
                    WHERE legacy_event_id = ?
                    """,
                    (record.prevention_event_id,),
                ).fetchone()
                if exact_existing is not None:
                    if tuple(exact_existing) != exact_identity:
                        raise ValueError("Legacy exact prevention draft is immutable.")
                    return
                released_exact = self._connection.execute(
                    """
                    SELECT draft_key, source_repository_id, target_repository_id,
                           push_repository_id, source_policy_digest, evidence_hash,
                           disposition, draft_number, draft_url
                    FROM prevention_legacy_reconciliations
                    WHERE legacy_event_id = ? AND disposition = 'draft_opened'
                    """,
                    (record.prevention_event_id,),
                ).fetchone()
                if released_exact is not None:
                    if tuple(released_exact) != identity:
                        raise ValueError("Legacy exact prevention draft is immutable.")
                    return
                self._connection.execute(
                    """
                    INSERT INTO prevention_legacy_exact_drafts (
                        legacy_event_id, draft_key, source_repository_id,
                        target_repository_id, push_repository_id,
                        source_policy_digest, evidence_hash, draft_number,
                        draft_url, occurred_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        record.prevention_event_id,
                        *exact_identity,
                        timestamp,
                    ),
                )
                return
            existing = self._connection.execute(
                """
                SELECT draft_key, source_repository_id, target_repository_id,
                       push_repository_id, source_policy_digest, evidence_hash,
                       disposition, draft_number, draft_url
                FROM prevention_legacy_reconciliations
                WHERE legacy_event_id = ?
                """,
                (record.prevention_event_id,),
            ).fetchone()
            if existing is not None:
                if tuple(existing) != identity:
                    raise ValueError(
                        "Legacy prevention reconciliation is already terminal."
                    )
                return
            if (
                self._connection.execute(
                    """
                SELECT 1 FROM prevention_legacy_invalid_resolutions
                WHERE legacy_event_id = ?
                UNION ALL
                SELECT 1 FROM prevention_legacy_exact_drafts
                WHERE legacy_event_id = ?
                UNION ALL
                SELECT 1 FROM prevention_legacy_deferral_exhaustions
                WHERE legacy_event_id = ?
                UNION ALL
                SELECT 1 FROM prevention_resolution_events
                WHERE draft_key = ?
                UNION ALL
                SELECT 1 FROM prevention_invalid_record_quarantines
                WHERE prevention_event_id = ?
                LIMIT 1
                """,
                    (
                        record.prevention_event_id,
                        record.prevention_event_id,
                        record.prevention_event_id,
                        record.draft_key,
                        record.prevention_event_id,
                    ),
                ).fetchone()
                is not None
            ):
                raise ValueError("Legacy prevention recovery is already terminal.")
            self._connection.execute(
                """
                INSERT INTO prevention_legacy_reconciliations (
                    legacy_event_id, draft_key, source_repository_id,
                    target_repository_id, push_repository_id,
                    source_policy_digest, evidence_hash, disposition,
                    draft_number, draft_url, occurred_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    record.prevention_event_id,
                    *identity,
                    timestamp,
                ),
            )

    def resolve_invalid_legacy_prevention_record(
        self,
        *,
        draft_key: str,
        occurred_at: datetime | None = None,
    ) -> str:
        """Terminalize one malformed migration-marked v1 record without a cap."""

        if not isinstance(draft_key, str) or not _SHA256_RE.fullmatch(draft_key):
            raise ValueError("draft_key must be a SHA-256 digest.")
        digest = hashlib.sha256(draft_key.encode("ascii")).hexdigest()
        timestamp = _serialize_datetime(occurred_at or _now())
        with self._connection:
            latest = self._connection.execute(
                """
                SELECT event.prevention_event_id
                FROM prevention_draft_events AS event
                JOIN prevention_legacy_candidate_events AS legacy
                  ON legacy.prevention_event_id = event.prevention_event_id
                LEFT JOIN prevention_candidate_attestations AS attestation
                  ON attestation.draft_key = event.draft_key
                WHERE event.draft_key = ?
                  AND attestation.draft_key IS NULL
                ORDER BY event.prevention_event_id DESC
                LIMIT 1
                """,
                (draft_key,),
            ).fetchone()
            if latest is None:
                raise ValueError("No migration-marked legacy record exists.")
            event_id = int(latest["prevention_event_id"])
            existing = self._connection.execute(
                """
                SELECT draft_key_digest
                FROM prevention_legacy_invalid_resolutions
                WHERE legacy_event_id = ?
                """,
                (event_id,),
            ).fetchone()
            if existing is not None:
                if existing["draft_key_digest"] != digest:
                    raise RuntimeError("Legacy invalid resolution is malformed.")
                return digest
            if (
                self._connection.execute(
                    """
                SELECT 1 FROM prevention_legacy_reconciliations
                WHERE legacy_event_id = ?
                UNION ALL
                SELECT 1 FROM prevention_legacy_exact_drafts
                WHERE legacy_event_id = ?
                UNION ALL
                SELECT 1 FROM prevention_legacy_deferral_exhaustions
                WHERE legacy_event_id = ?
                UNION ALL
                SELECT 1
                FROM prevention_draft_events AS event
                JOIN prevention_resolution_events AS resolution
                  ON resolution.draft_key = event.draft_key
                WHERE event.prevention_event_id = ?
                UNION ALL
                SELECT 1 FROM prevention_invalid_record_quarantines
                WHERE prevention_event_id = ?
                LIMIT 1
                """,
                    (event_id, event_id, event_id, event_id, event_id),
                ).fetchone()
                is not None
            ):
                raise ValueError("Legacy prevention recovery is terminal.")
            self._connection.execute(
                """
                INSERT INTO prevention_legacy_invalid_resolutions (
                    legacy_event_id, draft_key_digest, occurred_at
                ) VALUES (?, ?, ?)
                """,
                (event_id, digest, timestamp),
            )
        return digest

    def defer_legacy_prevention_for_policy(
        self,
        *,
        record: LegacyPreventionDraftRecord,
        source_policy_digest: str,
        source_repository_id: int,
        target_repository_id: int | None,
        push_repository_id: int | None,
        occurred_at: datetime | None = None,
    ) -> str:
        """Defer one v1 row for this exact policy without releasing its claim."""

        if not isinstance(record, LegacyPreventionDraftRecord):
            raise TypeError("record must be a legacy prevention draft.")
        if not isinstance(source_policy_digest, str) or not _SHA256_RE.fullmatch(
            source_policy_digest
        ):
            raise ValueError("source_policy_digest must be a SHA-256 digest.")
        repository_ids = (
            source_repository_id,
            target_repository_id,
            push_repository_id,
        )
        if (
            isinstance(source_repository_id, bool)
            or not isinstance(source_repository_id, int)
            or not 0 < source_repository_id <= _SQLITE_MAX_INTEGER
            or any(
                repository_id is not None
                and (
                    isinstance(repository_id, bool)
                    or not isinstance(repository_id, int)
                    or not 0 < repository_id <= _SQLITE_MAX_INTEGER
                )
                for repository_id in repository_ids[1:]
            )
        ):
            raise ValueError("repository IDs are malformed.")
        current = self.legacy_prevention_draft_by_key(record.draft_key)
        if current != record:
            raise ValueError("Legacy prevention draft changed before deferral.")
        identity = (
            source_repository_id,
            target_repository_id,
            push_repository_id,
            record.evidence_hash,
            "policy_unavailable",
        )
        timestamp = _serialize_datetime(occurred_at or _now())
        with self._connection:
            if (
                self._connection.execute(
                    """
                SELECT 1 FROM prevention_legacy_reconciliations
                WHERE legacy_event_id = ?
                """,
                    (record.prevention_event_id,),
                ).fetchone()
                is not None
                or self._connection.execute(
                    """
                SELECT 1 FROM prevention_legacy_exact_drafts
                WHERE legacy_event_id = ?
                """,
                    (record.prevention_event_id,),
                ).fetchone()
                is not None
                or self._connection.execute(
                    """
                SELECT 1 FROM prevention_legacy_invalid_resolutions
                WHERE legacy_event_id = ?
                """,
                    (record.prevention_event_id,),
                ).fetchone()
                is not None
                or self._connection.execute(
                    """
                SELECT 1 FROM prevention_invalid_record_quarantines
                WHERE prevention_event_id = ?
                """,
                    (record.prevention_event_id,),
                ).fetchone()
                is not None
            ):
                raise ValueError("Legacy prevention recovery is already terminal.")
            existing = self._connection.execute(
                """
                SELECT source_repository_id, target_repository_id,
                       push_repository_id, evidence_hash, reason
                FROM prevention_legacy_policy_deferrals
                WHERE legacy_event_id = ? AND source_policy_digest = ?
                """,
                (record.prevention_event_id, source_policy_digest),
            ).fetchone()
            if existing is not None:
                if tuple(existing) != identity:
                    raise ValueError("Legacy prevention deferral is immutable.")
                return "existing"
            exhausted = self._connection.execute(
                """
                SELECT 1 FROM prevention_legacy_deferral_exhaustions
                WHERE legacy_event_id = ?
                """,
                (record.prevention_event_id,),
            ).fetchone()
            if exhausted is not None:
                return "exhausted"
            count = self._connection.execute(
                """
                SELECT COUNT(*) AS deferral_count
                FROM prevention_legacy_policy_deferrals
                WHERE legacy_event_id = ?
                """,
                (record.prevention_event_id,),
            ).fetchone()
            if count is None:  # pragma: no cover - aggregate always returns one row
                raise RuntimeError("Legacy prevention deferral count failed.")
            if int(count["deferral_count"]) >= _MAX_PREVENTION_LEGACY_POLICY_DEFERRALS:
                self._connection.execute(
                    """
                    INSERT INTO prevention_legacy_deferral_exhaustions (
                        legacy_event_id, occurred_at
                    ) VALUES (?, ?)
                    """,
                    (record.prevention_event_id, timestamp),
                )
                return "exhausted"
            self._connection.execute(
                """
                INSERT INTO prevention_legacy_policy_deferrals (
                    legacy_event_id, source_policy_digest,
                    source_repository_id, target_repository_id,
                    push_repository_id, evidence_hash, reason, occurred_at
                ) VALUES (?, ?, ?, ?, ?, ?, 'policy_unavailable', ?)
                """,
                (
                    record.prevention_event_id,
                    source_policy_digest,
                    source_repository_id,
                    target_repository_id,
                    push_repository_id,
                    record.evidence_hash,
                    timestamp,
                ),
            )
        return "inserted"

    def record_prevention_draft_event(
        self,
        *,
        run_id: str,
        source_repository: str,
        target_repository: str,
        target_base_branch: str,
        target_base_sha: str,
        push_repository: str,
        branch: str,
        candidate_sha: str,
        evidence_hash: str,
        source_policy_json: str,
        source_policy_digest: str,
        patch_paths: Sequence[str],
        patch_hash: str,
        test_attestation_json: str,
        test_attestation_digest: str,
        open_source: OpenPullAuthorityReference | None,
        source_pulls: Sequence[HistoricalPullReference],
        event_revision_ids: Sequence[int],
        title: str,
        body: str,
        phase: str,
        draft_number: int | None = None,
        draft_url: str | None = None,
        occurred_at: datetime | None = None,
    ) -> str:
        """Append one idempotent prevention publication phase."""

        if (
            not isinstance(run_id, str)
            or not run_id
            or len(run_id.encode("utf-8")) > _MAX_RUN_ID_BYTES
            or "\x00" in run_id
        ):
            raise ValueError("run_id must be a bounded non-empty string.")
        _validate_prevention_event_identity(
            source_repository=source_repository,
            target_repository=target_repository,
            target_base_branch=target_base_branch,
            target_base_sha=target_base_sha,
            push_repository=push_repository,
            branch=branch,
            candidate_sha=candidate_sha,
            evidence_hash=evidence_hash,
            title=title,
            body=body,
            phase=phase,
            draft_number=draft_number,
            draft_url=draft_url,
        )
        if phase not in {"validated", "pushed", "draft_opened", "abandoned"}:
            raise ValueError("Unsupported prevention draft phase.")
        if any(
            not isinstance(value, str)
            or not _REPOSITORY_RE.fullmatch(value)
            or any(component in {".", ".."} for component in value.split("/"))
            for value in (
                source_repository,
                target_repository,
                push_repository,
            )
        ):
            raise ValueError("Prevention repositories must use owner/name form.")
        self._validate_draft_run_authority(
            run_id=run_id,
            repository=source_repository,
            allowed_modes=_PREVENTION_DRAFT_RUN_MODES,
            label="Prevention draft",
        )
        if any(
            not re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", value)
            for value in (target_base_sha, candidate_sha)
        ):
            raise ValueError("Prevention SHAs must be full lowercase object IDs.")
        for value, label in (
            (evidence_hash, "evidence_hash"),
            (source_policy_digest, "source_policy_digest"),
            (patch_hash, "patch_hash"),
            (test_attestation_digest, "test_attestation_digest"),
        ):
            if not isinstance(value, str) or not _SHA256_RE.fullmatch(value):
                raise ValueError(f"{label} must be a SHA-256 digest.")
        for value, label in (
            (target_base_branch, "target_base_branch"),
            (branch, "branch"),
        ):
            if not value or any(character in value for character in "\r\n\x00"):
                raise ValueError(f"{label} must be a safe non-empty value.")
        if (
            not isinstance(title, str)
            or not title
            or len(title.encode("utf-8")) > _MAX_PREVENTION_TITLE_BYTES
            or any(character in title for character in "\r\n\x00")
        ):
            raise ValueError("title must be a bounded safe non-empty value.")
        if (
            not isinstance(body, str)
            or not body
            or len(body.encode("utf-8")) > _MAX_PREVENTION_BODY_BYTES
            or "\x00" in body
        ):
            raise ValueError("body must be a bounded non-empty value without NUL.")
        if phase == "draft_opened":
            if (
                isinstance(draft_number, bool)
                or not isinstance(draft_number, int)
                or draft_number <= 0
                or not draft_url
                or any(character in draft_url for character in "\r\n\x00")
            ):
                raise ValueError("An opened prevention draft needs its number and URL.")
        elif draft_number is not None or draft_url is not None:
            raise ValueError("Only an opened prevention draft may store PR metadata.")

        source_policy_json = _validated_attestation_json(
            source_policy_json,
            label="source_policy_json",
        )
        policy = _prevention_policy_from_json(source_policy_json)
        if (
            policy.source_repository[0] != source_repository
            or policy.target_repository[0] != target_repository
            or policy.push_repository[0] != push_repository
            or policy.target_base_branch != target_base_branch
            or branch
            != f"{policy.push_branch_prefix}{target_base_sha[:12]}-{evidence_hash}"
        ):
            raise ValueError(
                "Prevention repositories must match their exact policy identities."
            )
        source_repository_id = policy.source_repository[1]
        target_repository_id = policy.target_repository[1]
        push_repository_id = policy.push_repository[1]
        test_attestation_json = _validated_attestation_json(
            test_attestation_json,
            label="test_attestation_json",
        )
        if (
            hashlib.sha256(source_policy_json.encode("ascii")).hexdigest()
            != source_policy_digest
        ):
            raise ValueError("source_policy_digest does not match its policy.")
        if (
            hashlib.sha256(test_attestation_json.encode("ascii")).hexdigest()
            != test_attestation_digest
        ):
            raise ValueError("test_attestation_digest does not match its evidence.")
        _validate_prevention_test_attestation(
            test_attestation_json,
            policy=policy,
            target_base_sha=target_base_sha,
            candidate_sha=candidate_sha,
        )
        if len(patch_paths) > _MAX_PREVENTION_PATCH_PATHS:
            raise ValueError("patch_paths must contain bounded safe repository paths.")
        supplied_paths = tuple(patch_paths)
        if (
            not supplied_paths
            or any(
                not isinstance(path, str)
                or not path
                or len(path.encode("utf-8")) > _MAX_PREVENTION_PATH_BYTES
                or path.startswith("/")
                or "\\" in path
                or any(part in {"", ".", ".."} for part in path.split("/"))
                or any(character in path for character in "\r\n\x00")
                for path in supplied_paths
            )
            or len(set(supplied_paths)) != len(supplied_paths)
        ):
            raise ValueError("patch_paths must contain bounded safe repository paths.")
        normalized_paths = tuple(sorted(supplied_paths))
        patch_paths_json = _canonical_attestation_json(list(normalized_paths))
        if len(patch_paths_json.encode("ascii")) > _MAX_PREVENTION_PATCH_JSON_BYTES:
            raise ValueError("patch_paths exceed their canonical byte bound.")

        if (
            len(source_pulls) > _MAX_PREVENTION_SOURCE_PULLS
            or len(event_revision_ids) > _MAX_PREVENTION_SOURCE_REVISIONS
        ):
            raise ValueError("Prevention source authority exceeds its bounded workset.")
        supplied_pulls = tuple(source_pulls)
        supplied_revision_ids = tuple(event_revision_ids)
        if (
            (
                open_source is not None
                and not isinstance(open_source, OpenPullAuthorityReference)
            )
            or any(
                not isinstance(item, HistoricalPullReference) for item in supplied_pulls
            )
            or any(
                isinstance(value, bool)
                or not isinstance(value, int)
                or not 0 < value <= _SQLITE_MAX_INTEGER
                for value in supplied_revision_ids
            )
        ):
            raise ValueError(
                "Prevention sources and revisions must be exact and paired."
            )
        normalized_pulls = tuple(
            sorted(
                supplied_pulls,
                key=lambda item: (
                    item.repository,
                    item.repository_id,
                    item.pull_id,
                    item.pr_number,
                    item.pull_revision_digest,
                    item.policy_digest,
                ),
            )
        )
        normalized_revision_ids = tuple(sorted(supplied_revision_ids))
        if (
            len(set(normalized_pulls)) != len(normalized_pulls)
            or any(item.repository != source_repository for item in normalized_pulls)
            or len(set(normalized_revision_ids)) != len(normalized_revision_ids)
            or (open_source is not None) == bool(normalized_pulls)
            or not normalized_revision_ids
            or (open_source is not None and open_source.repository != source_repository)
        ):
            raise ValueError(
                "Prevention sources and revisions must be exact and paired."
            )
        if phase == "validated":
            # Currentness authorizes creation of the immutable candidate. Later
            # phases only attest remote facts about that already-bound identity;
            # rechecking currentness here could orphan a PR created just before
            # a feedback edit/delete raced with the local ledger write.
            self.validate_prevention_source_attestation(
                source_repository=source_repository,
                open_source=open_source,
                source_pulls=normalized_pulls,
                event_revision_ids=normalized_revision_ids,
            )
        open_source_json = _open_pull_authority_json(open_source)
        source_pulls_json = _prevention_source_pulls_json(normalized_pulls)
        event_revision_ids_json = _canonical_attestation_json(
            list(normalized_revision_ids)
        )
        if (
            len(source_pulls_json.encode("ascii")) > _MAX_PREVENTION_SOURCE_JSON_BYTES
            or len(event_revision_ids_json.encode("ascii"))
            > _MAX_PREVENTION_SOURCE_JSON_BYTES
        ):
            raise ValueError("Prevention source attestation exceeds its byte bound.")
        draft_key = _prevention_draft_key(
            run_id=run_id,
            source_repository=source_repository,
            target_repository=target_repository,
            target_base_branch=target_base_branch,
            target_base_sha=target_base_sha,
            push_repository=push_repository,
            branch=branch,
            candidate_sha=candidate_sha,
            evidence_hash=evidence_hash,
            source_policy_json=source_policy_json,
            source_policy_digest=source_policy_digest,
            patch_paths_json=patch_paths_json,
            patch_hash=patch_hash,
            test_attestation_json=test_attestation_json,
            test_attestation_digest=test_attestation_digest,
            open_source_json=open_source_json,
            source_pulls_json=source_pulls_json,
            event_revision_ids_json=event_revision_ids_json,
            title=title,
            body=body,
        )
        identity = (
            run_id,
            source_repository,
            target_repository,
            target_base_branch,
            target_base_sha,
            push_repository,
            branch,
            candidate_sha,
            evidence_hash,
            title,
            body,
        )
        with self._connection:
            attestation_identity = (
                3,
                source_repository_id,
                target_repository_id,
                push_repository_id,
                source_policy_json,
                source_policy_digest,
                patch_paths_json,
                patch_hash,
                test_attestation_json,
                test_attestation_digest,
                open_source_json,
                source_pulls_json,
                event_revision_ids_json,
            )
            existing_attestation = self._connection.execute(
                """
                SELECT attestation_version, source_repository_id,
                       target_repository_id, push_repository_id, source_policy_json,
                       source_policy_digest, patch_paths_json, patch_hash,
                       test_attestation_json, test_attestation_digest,
                       open_source_json, source_pulls_json,
                       event_revision_ids_json
                FROM prevention_candidate_attestations
                WHERE draft_key = ?
                """,
                (draft_key,),
            ).fetchone()
            if (
                existing_attestation is not None
                and tuple(existing_attestation) != attestation_identity
            ):
                raise ValueError(
                    "Prevention attestation does not match its first event."
                )
            self._connection.execute(
                """
                INSERT OR IGNORE INTO prevention_candidate_attestations (
                    draft_key, attestation_version, source_repository_id,
                    target_repository_id, push_repository_id, source_policy_json,
                    source_policy_digest, patch_paths_json, patch_hash,
                    test_attestation_json, test_attestation_digest,
                    open_source_json, source_pulls_json,
                    event_revision_ids_json, occurred_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    draft_key,
                    *attestation_identity,
                    _serialize_datetime(occurred_at or _now()),
                ),
            )
            existing = self._connection.execute(
                """
                SELECT run_id, source_repository, target_repository,
                       target_base_branch, target_base_sha, push_repository,
                       branch, candidate_sha, evidence_hash, title, body
                FROM prevention_draft_events
                WHERE draft_key = ?
                ORDER BY prevention_event_id
                LIMIT 1
                """,
                (draft_key,),
            ).fetchone()
            if existing is not None and tuple(existing) != identity:
                raise ValueError(
                    "Prevention phase metadata does not match its first event."
                )
            same_phase = self._connection.execute(
                """
                SELECT run_id, source_repository, target_repository,
                       target_base_branch, target_base_sha, push_repository,
                       branch, candidate_sha, evidence_hash, title, body,
                       draft_number, draft_url
                FROM prevention_draft_events
                WHERE draft_key = ? AND phase = ?
                """,
                (draft_key, phase),
            ).fetchone()
            phase_identity = (*identity, draft_number, draft_url)
            if same_phase is not None:
                if tuple(same_phase) != phase_identity:
                    raise ValueError(
                        "Prevention phase metadata does not match its first event."
                    )
                return draft_key
            if (
                self._connection.execute(
                    """
                SELECT 1 FROM prevention_resolution_events
                WHERE draft_key = ?
                """,
                    (draft_key,),
                ).fetchone()
                is not None
                and phase != "draft_opened"
            ):
                raise ValueError("Prevention draft resolution is terminal.")
            latest = self._connection.execute(
                """
                SELECT phase FROM prevention_draft_events
                WHERE draft_key = ?
                ORDER BY prevention_event_id DESC
                LIMIT 1
                """,
                (draft_key,),
            ).fetchone()
            allowed_next = {
                "validated": {"pushed", "draft_opened", "abandoned"},
                "pushed": {"draft_opened", "abandoned"},
                "draft_opened": set(),
                "abandoned": set(),
            }
            if (
                latest is None
                and phase != "validated"
                or latest is not None
                and phase not in allowed_next[str(latest["phase"])]
            ):
                raise ValueError("Prevention draft phase transition is invalid.")
            self._connection.execute(
                """
                INSERT OR IGNORE INTO prevention_draft_events (
                    draft_key, run_id, source_repository, target_repository,
                    target_base_branch, target_base_sha, push_repository,
                    branch, candidate_sha, evidence_hash, title, body, phase,
                    draft_number, draft_url, occurred_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    draft_key,
                    *identity,
                    phase,
                    draft_number,
                    draft_url,
                    _serialize_datetime(occurred_at or _now()),
                ),
            )
        return draft_key

    def pending_prevention_drafts(
        self,
        *,
        source_repository: str | None = None,
        source_repository_id: int | None = None,
        limit: int = 100,
    ) -> tuple[PreventionDraftRecord, ...]:
        """Return a bounded set of prevention candidates needing recovery."""

        if (
            isinstance(limit, bool)
            or not isinstance(limit, int)
            or not 1 <= limit <= 100
        ):
            raise ValueError("limit must be an integer from 1 through 100.")
        if source_repository_id is not None and (
            isinstance(source_repository_id, bool)
            or not isinstance(source_repository_id, int)
            or not 0 < source_repository_id <= _SQLITE_MAX_INTEGER
        ):
            raise ValueError("source_repository_id must be a positive integer.")
        if source_repository_id is not None and source_repository is not None:
            where = """WHERE (
                attestation.source_repository_id = ?
                OR (
                    attestation.source_repository_id IS NULL
                    AND p.source_repository = ?
                )
            )"""
            parameters: tuple[object, ...] = (
                source_repository_id,
                source_repository,
            )
        elif source_repository_id is not None:
            where = "WHERE attestation.source_repository_id = ?"
            parameters = (source_repository_id,)
        elif source_repository is not None:
            where = "WHERE p.source_repository = ?"
            parameters = (source_repository,)
        else:
            where = ""
            parameters = ()
        rows = self._connection.execute(
            f"""
            SELECT latest.draft_key FROM (
                SELECT p.prevention_event_id, p.draft_key, p.phase,
                       ROW_NUMBER() OVER (
                           PARTITION BY p.draft_key
                           ORDER BY p.prevention_event_id DESC
                       ) AS guardian_row_number
                FROM prevention_draft_events AS p
                LEFT JOIN prevention_candidate_attestations AS attestation
                  ON attestation.draft_key = p.draft_key
                {where}
            ) AS latest
            JOIN prevention_candidate_attestations AS attestation
              ON attestation.draft_key = latest.draft_key
            WHERE latest.guardian_row_number = 1
              AND latest.phase IN ('validated', 'pushed')
              AND typeof(latest.draft_key) = 'text'
              AND length(latest.draft_key) = 64
              AND latest.draft_key NOT GLOB '*[^0-9a-f]*'
              AND NOT EXISTS (
                  SELECT 1 FROM prevention_resolution_events AS resolution
                  WHERE resolution.draft_key = latest.draft_key
              )
              AND NOT EXISTS (
                  SELECT 1
                  FROM prevention_invalid_record_quarantines AS quarantine
                  WHERE quarantine.prevention_event_id =
                        latest.prevention_event_id
            )
            ORDER BY latest.prevention_event_id
            LIMIT ?
            """,
            (*parameters, limit + 1),
        ).fetchall()
        if len(rows) > limit:
            raise RuntimeError("Pending prevention draft read exceeds its bound.")
        records: list[PreventionDraftRecord] = []
        for row in rows:
            record = self.prevention_draft_by_key(str(row["draft_key"]))
            if record is None or record.phase not in {"validated", "pushed"}:
                raise RuntimeError(
                    "Pending prevention draft changed during inspection."
                )
            records.append(record)
        return tuple(records)

    def validate_prevention_source_attestation(
        self,
        *,
        source_repository: str,
        open_source: OpenPullAuthorityReference | None,
        source_pulls: Sequence[HistoricalPullReference],
        event_revision_ids: Sequence[int],
    ) -> None:
        """Validate the complete exact source set before prevention authoring."""

        if (
            len(source_pulls) > _MAX_PREVENTION_SOURCE_PULLS
            or len(event_revision_ids) > _MAX_PREVENTION_SOURCE_REVISIONS
        ):
            raise ValueError("Prevention source authority exceeds its bounded workset.")
        pulls = tuple(source_pulls)
        revision_ids = tuple(event_revision_ids)
        if (
            not _REPOSITORY_RE.fullmatch(source_repository)
            or (
                open_source is not None
                and not isinstance(open_source, OpenPullAuthorityReference)
            )
            or any(not isinstance(item, HistoricalPullReference) for item in pulls)
            or len(pulls) > _MAX_PREVENTION_SOURCE_PULLS
            or len(revision_ids) > _MAX_PREVENTION_SOURCE_REVISIONS
            or any(
                isinstance(value, bool)
                or not isinstance(value, int)
                or not 0 < value <= _SQLITE_MAX_INTEGER
                for value in revision_ids
            )
        ):
            raise ValueError("Prevention sources and revisions are malformed.")
        normalized_pulls = tuple(
            sorted(
                pulls,
                key=lambda item: (
                    item.repository,
                    item.repository_id,
                    item.pull_id,
                    item.pr_number,
                    item.pull_revision_digest,
                    item.policy_digest,
                ),
            )
        )
        normalized_revision_ids = tuple(sorted(revision_ids))
        if (
            len(set(normalized_pulls)) != len(normalized_pulls)
            or any(item.repository != source_repository for item in normalized_pulls)
            or len(set(normalized_revision_ids)) != len(normalized_revision_ids)
            or (open_source is not None) == bool(normalized_pulls)
            or not normalized_revision_ids
            or (open_source is not None and open_source.repository != source_repository)
        ):
            raise ValueError(
                "Prevention sources and revisions must be exact and paired."
            )
        source_pulls_json = _prevention_source_pulls_json(normalized_pulls)
        revision_ids_json = _canonical_attestation_json(list(normalized_revision_ids))
        if (
            len(source_pulls_json.encode("ascii")) > _MAX_PREVENTION_SOURCE_JSON_BYTES
            or len(revision_ids_json.encode("ascii"))
            > _MAX_PREVENTION_SOURCE_JSON_BYTES
        ):
            raise ValueError("Prevention source attestation exceeds its byte bound.")
        if normalized_pulls:
            self.validate_current_historical_remediation_evidence(
                source_pulls=normalized_pulls,
                event_revision_ids=normalized_revision_ids,
            )
            return
        if open_source is None:  # pragma: no cover - exclusive source check above
            raise ValueError("Prevention requires an exact source.")
        revision_rows: list[sqlite3.Row] = []
        for offset in range(
            0,
            len(normalized_revision_ids),
            _SQLITE_IN_QUERY_CHUNK,
        ):
            revision_chunk = normalized_revision_ids[
                offset : offset + _SQLITE_IN_QUERY_CHUNK
            ]
            placeholders = ", ".join("?" for _value in revision_chunk)
            revision_rows.extend(
                self._connection.execute(
                    f"""
                    SELECT current.revision_id, current.repository,
                           current.pr_number, current.head_sha, current.base_sha,
                           current.deleted,
                           (
                               SELECT latest.event_revision_id
                               FROM event_current_observations AS latest
                               WHERE latest.repository = current.repository
                                 AND latest.pr_number = current.pr_number
                                 AND latest.kind = current.kind
                                 AND latest.event_id = current.event_id
                               ORDER BY latest.observation_id DESC
                               LIMIT 1
                           ) AS latest_revision_id
                    FROM event_revisions AS current
                    WHERE current.revision_id IN ({placeholders})
                    """,
                    revision_chunk,
                ).fetchall()
            )
        if {int(row["revision_id"]) for row in revision_rows} != set(
            normalized_revision_ids
        ) or any(
            (
                row["repository"],
                int(row["pr_number"]),
                row["head_sha"],
                row["base_sha"],
                int(row["deleted"]),
                int(row["latest_revision_id"]),
            )
            != (
                open_source.repository,
                open_source.pr_number,
                open_source.head_sha,
                open_source.base_sha,
                0,
                int(row["revision_id"]),
            )
            for row in revision_rows
        ):
            raise ValueError(
                "event_revision_ids must match the exact open pull snapshot."
            )

    def validate_prevention_evidence_bindings(
        self,
        *,
        source_repository: str,
        feedback_revision_ids: Sequence[tuple[str, int]],
    ) -> None:
        """Require every claimed feedback ID to name its exact stored revision."""

        if len(feedback_revision_ids) > _MAX_PREVENTION_CANDIDATE_HASHES:
            raise ValueError("Prevention evidence bindings are malformed.")
        bindings = tuple(feedback_revision_ids)
        if (
            not _REPOSITORY_RE.fullmatch(source_repository)
            or not bindings
            or len(bindings) > _MAX_PREVENTION_CANDIDATE_HASHES
            or len({feedback_id for feedback_id, _revision_id in bindings})
            != len(bindings)
            or len({revision_id for _feedback_id, revision_id in bindings})
            != len(bindings)
            or any(
                not isinstance(feedback_id, str)
                or not feedback_id
                or len(feedback_id.encode("utf-8")) > 512
                or any(character in feedback_id for character in "\r\n\x00")
                or isinstance(revision_id, bool)
                or not isinstance(revision_id, int)
                or not 0 < revision_id <= _SQLITE_MAX_INTEGER
                for feedback_id, revision_id in bindings
            )
        ):
            raise ValueError("Prevention evidence bindings are malformed.")
        placeholders = ", ".join("?" for _binding in bindings)
        rows = self._connection.execute(
            f"""
            SELECT revision_id, repository, kind, event_id
            FROM event_revisions
            WHERE revision_id IN ({placeholders})
            """,
            tuple(revision_id for _feedback_id, revision_id in bindings),
        ).fetchall()
        observed = {
            int(row["revision_id"]): (
                str(row["repository"]),
                f"{row['kind']}:{row['event_id']}",
            )
            for row in rows
        }
        if any(
            observed.get(revision_id) != (source_repository, feedback_id)
            for feedback_id, revision_id in bindings
        ):
            raise ValueError(
                "Prevention evidence feedback IDs do not match their exact revisions."
            )

    def pending_prevention_draft_keys_for_recovery(
        self,
        *,
        source_repository: str | None = None,
        source_repository_id: int | None = None,
        source_policy_digest: str | None = None,
        limit: int = 100,
    ) -> tuple[str, ...]:
        """Return a bounded rotating workset without parsing candidate payloads."""

        if (
            isinstance(limit, bool)
            or not isinstance(limit, int)
            or not 1 <= limit <= 100
        ):
            raise ValueError("limit must be an integer from 1 through 100.")
        if source_repository_id is not None and (
            isinstance(source_repository_id, bool)
            or not isinstance(source_repository_id, int)
            or not 0 < source_repository_id <= _SQLITE_MAX_INTEGER
        ):
            raise ValueError("source_repository_id must be a positive integer.")
        if source_policy_digest is not None and (
            not isinstance(source_policy_digest, str)
            or not _SHA256_RE.fullmatch(source_policy_digest)
        ):
            raise ValueError("source_policy_digest must be a SHA-256 digest.")
        if source_repository_id is not None and source_repository is not None:
            event_source = f"""
                SELECT event.prevention_event_id, event.draft_key, event.phase
                FROM prevention_candidate_attestations AS attestation
                     INDEXED BY prevention_attestation_repository_ids
                JOIN prevention_draft_events AS event
                  ON event.draft_key = attestation.draft_key
                WHERE attestation.source_repository_id = ?
                  AND typeof(event.draft_key) = 'text'
                  AND length(CAST(event.draft_key AS BLOB)) <=
                      {_MAX_PREVENTION_INVALID_DRAFT_KEY_BYTES}
                UNION ALL
                SELECT event.prevention_event_id, event.draft_key, event.phase
                FROM prevention_draft_events AS event
                     INDEXED BY prevention_draft_events_pending
                LEFT JOIN prevention_candidate_attestations AS attestation
                  ON attestation.draft_key = event.draft_key
                WHERE event.source_repository = ?
                  AND attestation.draft_key IS NULL
                  AND typeof(event.draft_key) = 'text'
                  AND length(CAST(event.draft_key AS BLOB)) <=
                      {_MAX_PREVENTION_INVALID_DRAFT_KEY_BYTES}
            """
            parameters: tuple[object, ...] = (
                source_repository_id,
                source_repository,
            )
        elif source_repository_id is not None:
            event_source = f"""
                SELECT event.prevention_event_id, event.draft_key, event.phase
                FROM prevention_candidate_attestations AS attestation
                     INDEXED BY prevention_attestation_repository_ids
                JOIN prevention_draft_events AS event
                  ON event.draft_key = attestation.draft_key
                WHERE attestation.source_repository_id = ?
                  AND typeof(event.draft_key) = 'text'
                  AND length(CAST(event.draft_key AS BLOB)) <=
                      {_MAX_PREVENTION_INVALID_DRAFT_KEY_BYTES}
            """
            parameters = (source_repository_id,)
        elif source_repository is not None:
            event_source = f"""
                SELECT event.prevention_event_id, event.draft_key, event.phase
                FROM prevention_draft_events AS event
                     INDEXED BY prevention_draft_events_pending
                WHERE event.source_repository = ?
                  AND typeof(event.draft_key) = 'text'
                  AND length(CAST(event.draft_key AS BLOB)) <=
                      {_MAX_PREVENTION_INVALID_DRAFT_KEY_BYTES}
            """
            parameters = (source_repository,)
        else:
            event_source = f"""
                SELECT event.prevention_event_id, event.draft_key, event.phase
                FROM prevention_draft_events AS event
                     INDEXED BY prevention_draft_events_pending
                WHERE typeof(event.draft_key) = 'text'
                  AND length(CAST(event.draft_key AS BLOB)) <=
                      {_MAX_PREVENTION_INVALID_DRAFT_KEY_BYTES}
            """
            parameters = ()
        deferral_clause = (
            """
              AND NOT EXISTS (
                  SELECT 1
                  FROM prevention_legacy_policy_deferrals AS legacy_deferral
                  WHERE legacy_deferral.legacy_event_id =
                        latest.prevention_event_id
                    AND legacy_deferral.source_policy_digest = ?
              )
            """
            if source_policy_digest is not None
            else ""
        )
        deferral_parameters: tuple[object, ...] = (
            (source_policy_digest,) if source_policy_digest is not None else ()
        )
        rows = self._connection.execute(
            f"""
            WITH eligible AS MATERIALIZED (
                {event_source}
            ), latest AS (
                SELECT p.prevention_event_id, p.draft_key, p.phase,
                       ROW_NUMBER() OVER (
                           PARTITION BY p.draft_key
                           ORDER BY p.prevention_event_id DESC
                       ) AS guardian_row_number
                FROM eligible AS p
            ), relevant_keys AS MATERIALIZED (
                SELECT DISTINCT draft_key FROM eligible
            ), attempts AS (
                SELECT attempt.draft_key,
                       MAX(attempt.recovery_attempt_id) AS last_attempt_id
                FROM relevant_keys
                JOIN prevention_recovery_attempt_events AS attempt
                  ON attempt.draft_key = relevant_keys.draft_key
                WHERE typeof(attempt.draft_key) = 'text'
                  AND length(attempt.draft_key) = 64
                  AND attempt.draft_key NOT GLOB '*[^0-9a-f]*'
                GROUP BY attempt.draft_key
            )
            SELECT latest.draft_key FROM latest
            LEFT JOIN attempts ON attempts.draft_key = latest.draft_key
            WHERE latest.guardian_row_number = 1
              AND (
                  latest.phase IN ('validated', 'pushed')
                  OR (
                      latest.phase = 'draft_opened'
                      AND EXISTS (
                          SELECT 1
                          FROM prevention_legacy_candidate_events AS legacy
                          WHERE legacy.prevention_event_id =
                                latest.prevention_event_id
                      )
                  )
              )
              AND NOT EXISTS (
                  SELECT 1 FROM prevention_resolution_events AS resolution
                  WHERE resolution.draft_key = latest.draft_key
              )
              AND NOT EXISTS (
                  SELECT 1
                  FROM prevention_invalid_record_quarantines AS quarantine
                  WHERE quarantine.prevention_event_id =
                        latest.prevention_event_id
              )
              AND NOT EXISTS (
                  SELECT 1
                  FROM prevention_legacy_reconciliations AS legacy_result
                  WHERE legacy_result.legacy_event_id =
                        latest.prevention_event_id
              )
              AND NOT EXISTS (
                  SELECT 1
                  FROM prevention_legacy_exact_drafts AS legacy_exact
                  WHERE legacy_exact.legacy_event_id =
                        latest.prevention_event_id
              )
              AND NOT EXISTS (
                  SELECT 1
                  FROM prevention_legacy_invalid_resolutions AS legacy_invalid
                  WHERE legacy_invalid.legacy_event_id =
                        latest.prevention_event_id
              )
              AND NOT EXISTS (
                  SELECT 1
                  FROM prevention_legacy_deferral_exhaustions AS exhausted
                  WHERE exhausted.legacy_event_id = latest.prevention_event_id
              )
              {deferral_clause}
              AND (
                  (
                      typeof(latest.draft_key) = 'text'
                      AND length(latest.draft_key) = 64
                      AND latest.draft_key NOT GLOB '*[^0-9a-f]*'
                  )
                  OR (
                      typeof(latest.draft_key) = 'text'
                      AND length(CAST(latest.draft_key AS BLOB)) <=
                          {_MAX_PREVENTION_INVALID_DRAFT_KEY_BYTES}
                      AND (
                          SELECT COUNT(*)
                          FROM prevention_invalid_record_quarantines
                      ) < {_MAX_PREVENTION_INVALID_QUARANTINES}
                  )
              )
            ORDER BY COALESCE(attempts.last_attempt_id, 0),
                     latest.prevention_event_id
            LIMIT ?
            """,
            (*parameters, *deferral_parameters, limit),
        ).fetchall()
        return tuple(str(row["draft_key"]) for row in rows)

    def has_recoverable_prevention_drafts(
        self,
        *,
        source_repository: str,
        source_repository_id: int,
        source_policy_digest: str | None = None,
    ) -> bool:
        """Return whether bounded recovery has addressable or quarantinable work."""

        if not _REPOSITORY_RE.fullmatch(source_repository):
            raise ValueError("source_repository must use owner/name form.")
        if (
            isinstance(source_repository_id, bool)
            or not isinstance(source_repository_id, int)
            or not 0 < source_repository_id <= _SQLITE_MAX_INTEGER
        ):
            raise ValueError("source_repository_id must be a positive integer.")
        if source_policy_digest is not None and (
            not isinstance(source_policy_digest, str)
            or not _SHA256_RE.fullmatch(source_policy_digest)
        ):
            raise ValueError("source_policy_digest must be a SHA-256 digest.")
        deferral_clause = (
            """
              AND NOT EXISTS (
                  SELECT 1
                  FROM prevention_legacy_policy_deferrals AS legacy_deferral
                  WHERE legacy_deferral.legacy_event_id =
                        latest.prevention_event_id
                    AND legacy_deferral.source_policy_digest = ?
              )
            """
            if source_policy_digest is not None
            else ""
        )
        deferral_parameters: tuple[object, ...] = (
            (source_policy_digest,) if source_policy_digest is not None else ()
        )
        row = self._connection.execute(
            f"""
            WITH eligible AS MATERIALIZED (
                SELECT event.prevention_event_id, event.draft_key, event.phase
                FROM prevention_candidate_attestations AS attestation
                     INDEXED BY prevention_attestation_repository_ids
                JOIN prevention_draft_events AS event
                  ON event.draft_key = attestation.draft_key
                WHERE attestation.source_repository_id = ?
                  AND typeof(event.draft_key) = 'text'
                  AND length(CAST(event.draft_key AS BLOB)) <=
                      {_MAX_PREVENTION_INVALID_DRAFT_KEY_BYTES}
                UNION ALL
                SELECT event.prevention_event_id, event.draft_key, event.phase
                FROM prevention_draft_events AS event
                     INDEXED BY prevention_draft_events_pending
                LEFT JOIN prevention_candidate_attestations AS attestation
                  ON attestation.draft_key = event.draft_key
                WHERE event.source_repository = ?
                  AND attestation.draft_key IS NULL
                  AND typeof(event.draft_key) = 'text'
                  AND length(CAST(event.draft_key AS BLOB)) <=
                      {_MAX_PREVENTION_INVALID_DRAFT_KEY_BYTES}
            ), latest AS (
                SELECT p.prevention_event_id, p.draft_key, p.phase,
                       ROW_NUMBER() OVER (
                           PARTITION BY p.draft_key
                           ORDER BY p.prevention_event_id DESC
                       ) AS guardian_row_number
                FROM eligible AS p
            )
            SELECT 1 FROM latest
            WHERE latest.guardian_row_number = 1
              AND (
                  latest.phase IN ('validated', 'pushed')
                  OR (
                      latest.phase = 'draft_opened'
                      AND EXISTS (
                          SELECT 1
                          FROM prevention_legacy_candidate_events AS legacy
                          WHERE legacy.prevention_event_id =
                                latest.prevention_event_id
                      )
                  )
              )
              AND NOT EXISTS (
                  SELECT 1 FROM prevention_resolution_events AS resolution
                  WHERE resolution.draft_key = latest.draft_key
              )
              AND NOT EXISTS (
                  SELECT 1
                  FROM prevention_invalid_record_quarantines AS quarantine
                  WHERE quarantine.prevention_event_id =
                        latest.prevention_event_id
              )
              AND NOT EXISTS (
                  SELECT 1
                  FROM prevention_legacy_reconciliations AS legacy_result
                  WHERE legacy_result.legacy_event_id =
                        latest.prevention_event_id
              )
              AND NOT EXISTS (
                  SELECT 1
                  FROM prevention_legacy_exact_drafts AS legacy_exact
                  WHERE legacy_exact.legacy_event_id =
                        latest.prevention_event_id
              )
              AND NOT EXISTS (
                  SELECT 1
                  FROM prevention_legacy_invalid_resolutions AS legacy_invalid
                  WHERE legacy_invalid.legacy_event_id =
                        latest.prevention_event_id
              )
              AND NOT EXISTS (
                  SELECT 1
                  FROM prevention_legacy_deferral_exhaustions AS exhausted
                  WHERE exhausted.legacy_event_id = latest.prevention_event_id
              )
              {deferral_clause}
              AND (
                  (
                      typeof(latest.draft_key) = 'text'
                      AND length(latest.draft_key) = 64
                      AND latest.draft_key NOT GLOB '*[^0-9a-f]*'
                  )
                  OR (
                      typeof(latest.draft_key) = 'text'
                      AND length(CAST(latest.draft_key AS BLOB)) <=
                          {_MAX_PREVENTION_INVALID_DRAFT_KEY_BYTES}
                      AND (
                      SELECT COUNT(*)
                      FROM prevention_invalid_record_quarantines
                      ) < {_MAX_PREVENTION_INVALID_QUARANTINES}
                  )
                  OR (
                      (
                          typeof(latest.draft_key) != 'text'
                          OR length(CAST(latest.draft_key AS BLOB)) >
                             {_MAX_PREVENTION_INVALID_DRAFT_KEY_BYTES}
                      )
                      AND (
                          SELECT COUNT(*)
                          FROM prevention_invalid_record_quarantines
                      ) < {_MAX_PREVENTION_INVALID_QUARANTINES}
                  )
              )
            LIMIT 1
            """,
            (
                source_repository_id,
                source_repository,
                *deferral_parameters,
            ),
        ).fetchone()
        if row is not None:
            return True
        if (
            self._connection.execute(
                f"""
            SELECT 1
            FROM prevention_draft_events AS event
            LEFT JOIN prevention_candidate_attestations AS attestation
              ON attestation.draft_key = event.draft_key
            WHERE (
                    (
                        attestation.draft_key IS NOT NULL
                        AND attestation.source_repository_id = ?
                    )
                    OR (
                        attestation.draft_key IS NULL
                        AND event.source_repository = ?
                    )
                  )
              AND (
                  typeof(event.draft_key) != 'text'
                  OR length(CAST(event.draft_key AS BLOB)) >
                     {_MAX_PREVENTION_INVALID_DRAFT_KEY_BYTES}
              )
              AND (
                  event.phase IN ('validated', 'pushed')
                  OR (
                      event.phase = 'draft_opened'
                      AND EXISTS (
                          SELECT 1
                          FROM prevention_legacy_candidate_events AS legacy
                          WHERE legacy.prevention_event_id =
                                event.prevention_event_id
                      )
                  )
              )
              AND NOT EXISTS (
                  SELECT 1
                  FROM prevention_invalid_record_quarantines AS quarantine
                  WHERE quarantine.prevention_event_id =
                        event.prevention_event_id
              )
              AND NOT EXISTS (
                  SELECT 1
                  FROM prevention_draft_events AS newer
                  WHERE newer.draft_key = event.draft_key
                    AND newer.prevention_event_id > event.prevention_event_id
              )
              AND NOT EXISTS (
                  SELECT 1 FROM prevention_resolution_events AS resolution
                  WHERE resolution.draft_key = event.draft_key
              )
              AND NOT EXISTS (
                  SELECT 1
                  FROM prevention_draft_events AS terminal_event
                  LEFT JOIN prevention_invalid_record_quarantines AS quarantine
                    ON quarantine.prevention_event_id =
                       terminal_event.prevention_event_id
                  LEFT JOIN prevention_legacy_reconciliations AS reconciliation
                    ON reconciliation.legacy_event_id =
                       terminal_event.prevention_event_id
                  LEFT JOIN prevention_legacy_invalid_resolutions AS invalid
                    ON invalid.legacy_event_id = terminal_event.prevention_event_id
                  LEFT JOIN prevention_legacy_deferral_exhaustions AS exhausted
                    ON exhausted.legacy_event_id = terminal_event.prevention_event_id
                  LEFT JOIN prevention_legacy_exact_drafts AS legacy_exact
                    ON legacy_exact.legacy_event_id =
                       terminal_event.prevention_event_id
                  WHERE terminal_event.draft_key = event.draft_key
                    AND (
                        quarantine.prevention_event_id IS NOT NULL
                        OR reconciliation.legacy_event_id IS NOT NULL
                        OR invalid.legacy_event_id IS NOT NULL
                        OR exhausted.legacy_event_id IS NOT NULL
                        OR legacy_exact.legacy_event_id IS NOT NULL
                    )
              )
              AND (
                  SELECT COUNT(*)
                  FROM prevention_invalid_record_quarantines
              ) < {_MAX_PREVENTION_INVALID_QUARANTINES}
            LIMIT 1
            """,
                (source_repository_id, source_repository),
            ).fetchone()
            is not None
        ):
            return True
        return False

    def quarantine_unaddressable_prevention_records(
        self,
        *,
        source_repository: str,
        source_repository_id: int,
        occurred_at: datetime | None = None,
        limit: int = 100,
        before_mutation: Callable[[], None] | None = None,
    ) -> tuple[str, ...]:
        """Isolate unbounded/non-text keys by event ID without exposing bytes."""

        if not _REPOSITORY_RE.fullmatch(source_repository):
            raise ValueError("source_repository must use owner/name form.")
        if (
            isinstance(source_repository_id, bool)
            or not isinstance(source_repository_id, int)
            or not 0 < source_repository_id <= _SQLITE_MAX_INTEGER
        ):
            raise ValueError("source_repository_id must be a positive integer.")
        if (
            isinstance(limit, bool)
            or not isinstance(limit, int)
            or not 1 <= limit <= 100
        ):
            raise ValueError("limit must be an integer from 1 through 100.")
        if before_mutation is not None and not callable(before_mutation):
            raise TypeError("before_mutation must be callable.")
        timestamp = _serialize_datetime(occurred_at or _now())
        with self._connection:
            count = self._connection.execute(
                """
                SELECT COUNT(*) AS quarantine_count
                FROM prevention_invalid_record_quarantines
                """
            ).fetchone()
            if count is None:  # pragma: no cover - aggregate always returns one row
                raise RuntimeError("Invalid prevention quarantine count failed.")
            remaining = _MAX_PREVENTION_INVALID_QUARANTINES - int(
                count["quarantine_count"]
            )
            if remaining <= 0:
                return ()
            rows = self._connection.execute(
                f"""
                SELECT event.prevention_event_id,
                       typeof(event.draft_key) AS storage_type,
                       length(CAST(event.draft_key AS BLOB)) AS byte_length,
                       hex(substr(CAST(event.draft_key AS BLOB), 1, 4096)) AS key_prefix
                FROM prevention_draft_events AS event
                LEFT JOIN prevention_candidate_attestations AS attestation
                  ON attestation.draft_key = event.draft_key
                WHERE (
                        (
                            attestation.draft_key IS NOT NULL
                            AND attestation.source_repository_id = ?
                        )
                        OR (
                            attestation.draft_key IS NULL
                            AND event.source_repository = ?
                        )
                      )
                  AND (
                      event.phase IN ('validated', 'pushed')
                      OR (
                          event.phase = 'draft_opened'
                          AND EXISTS (
                              SELECT 1
                              FROM prevention_legacy_candidate_events AS legacy
                              WHERE legacy.prevention_event_id =
                                    event.prevention_event_id
                          )
                      )
                  )
                  AND (
                      typeof(event.draft_key) != 'text'
                      OR length(CAST(event.draft_key AS BLOB)) >
                         {_MAX_PREVENTION_INVALID_DRAFT_KEY_BYTES}
                  )
                  AND NOT EXISTS (
                      SELECT 1
                      FROM prevention_invalid_record_quarantines AS quarantine
                      WHERE quarantine.prevention_event_id =
                            event.prevention_event_id
                  )
                  AND NOT EXISTS (
                      SELECT 1
                      FROM prevention_draft_events AS newer
                      WHERE newer.draft_key = event.draft_key
                        AND newer.prevention_event_id >
                            event.prevention_event_id
                  )
                  AND NOT EXISTS (
                      SELECT 1 FROM prevention_resolution_events AS resolution
                      WHERE resolution.draft_key = event.draft_key
                  )
                  AND NOT EXISTS (
                      SELECT 1
                      FROM prevention_draft_events AS terminal_event
                      LEFT JOIN prevention_invalid_record_quarantines AS quarantine
                        ON quarantine.prevention_event_id =
                           terminal_event.prevention_event_id
                      LEFT JOIN prevention_legacy_reconciliations AS reconciliation
                        ON reconciliation.legacy_event_id =
                           terminal_event.prevention_event_id
                      LEFT JOIN prevention_legacy_invalid_resolutions AS invalid
                        ON invalid.legacy_event_id =
                           terminal_event.prevention_event_id
                      LEFT JOIN prevention_legacy_deferral_exhaustions AS exhausted
                        ON exhausted.legacy_event_id =
                           terminal_event.prevention_event_id
                      LEFT JOIN prevention_legacy_exact_drafts AS legacy_exact
                        ON legacy_exact.legacy_event_id =
                           terminal_event.prevention_event_id
                      WHERE terminal_event.draft_key = event.draft_key
                        AND (
                            quarantine.prevention_event_id IS NOT NULL
                            OR reconciliation.legacy_event_id IS NOT NULL
                            OR invalid.legacy_event_id IS NOT NULL
                            OR exhausted.legacy_event_id IS NOT NULL
                            OR legacy_exact.legacy_event_id IS NOT NULL
                        )
                  )
                ORDER BY event.prevention_event_id
                LIMIT ?
                """,
                (source_repository_id, source_repository, min(limit, remaining)),
            ).fetchall()
            if rows and before_mutation is not None:
                before_mutation()
            digests: list[str] = []
            for row in rows:
                prefix = bytes.fromhex(str(row["key_prefix"]))
                digest = hashlib.sha256(
                    (f"sqlite-{row['storage_type']}:{int(row['byte_length'])}:").encode(
                        "ascii"
                    )
                    + prefix
                ).hexdigest()
                self._connection.execute(
                    """
                    INSERT INTO prevention_invalid_record_quarantines (
                        prevention_event_id, draft_key_digest, occurred_at
                    ) VALUES (?, ?, ?)
                    """,
                    (int(row["prevention_event_id"]), digest, timestamp),
                )
                digests.append(digest)
        return tuple(digests)

    def quarantine_invalid_prevention_record(
        self,
        *,
        draft_key: str,
        occurred_at: datetime | None = None,
    ) -> str:
        """Durably isolate a legacy pending row whose key cannot be addressed safely."""

        if not isinstance(draft_key, str):
            raise ValueError("draft_key must be text.")
        if len(draft_key.encode("utf-8")) > _MAX_PREVENTION_INVALID_DRAFT_KEY_BYTES:
            raise ValueError("draft_key must be bounded text.")
        draft_key_digest = hashlib.sha256(draft_key.encode("utf-8")).hexdigest()
        timestamp = _serialize_datetime(occurred_at or _now())
        with self._connection:
            latest = self._connection.execute(
                """
                SELECT event.prevention_event_id, event.phase,
                       legacy.prevention_event_id AS legacy_event_id
                FROM prevention_draft_events AS event
                LEFT JOIN prevention_legacy_candidate_events AS legacy
                  ON legacy.prevention_event_id = event.prevention_event_id
                WHERE event.draft_key = ?
                ORDER BY event.prevention_event_id DESC
                LIMIT 1
                """,
                (draft_key,),
            ).fetchone()
            if latest is None or (
                latest["phase"] not in {"validated", "pushed"}
                and not (
                    latest["phase"] == "draft_opened"
                    and latest["legacy_event_id"] is not None
                )
            ):
                raise ValueError(
                    "Only a malformed pending prevention draft can be quarantined."
                )
            existing = self._connection.execute(
                """
                SELECT draft_key_digest
                FROM prevention_invalid_record_quarantines
                WHERE prevention_event_id = ?
                """,
                (int(latest["prevention_event_id"]),),
            ).fetchone()
            if existing is not None:
                if existing["draft_key_digest"] != draft_key_digest:
                    raise RuntimeError("Invalid prevention quarantine is malformed.")
                return draft_key_digest
            count = self._connection.execute(
                """
                SELECT COUNT(*) AS quarantine_count
                FROM prevention_invalid_record_quarantines
                """
            ).fetchone()
            if count is None:  # pragma: no cover - aggregate always returns one row
                raise RuntimeError("Invalid prevention quarantine count failed.")
            if int(count["quarantine_count"]) >= _MAX_PREVENTION_INVALID_QUARANTINES:
                # The malformed ledger row remains durable evidence. Recovery excludes
                # further malformed rows after the bounded operator quarantine is full.
                return draft_key_digest
            self._connection.execute(
                """
                INSERT INTO prevention_invalid_record_quarantines (
                    prevention_event_id, draft_key_digest, occurred_at
                ) VALUES (?, ?, ?)
                """,
                (
                    int(latest["prevention_event_id"]),
                    draft_key_digest,
                    timestamp,
                ),
            )
        return draft_key_digest

    def prevention_draft_by_key(self, draft_key: str) -> PreventionDraftRecord | None:
        """Load and integrity-check one exact prevention candidate."""

        if not isinstance(draft_key, str) or not _SHA256_RE.fullmatch(draft_key):
            raise ValueError("draft_key must be a SHA-256 digest.")
        # Do not materialize attacker-controlled or corrupt legacy payloads until
        # SQLite has proved every variable-width column fits its documented bound.
        # Pin the event ID so a concurrent append cannot swap in a different row
        # between this preflight and the full read.
        preflight = self._connection.execute(
            f"""
            SELECT event.prevention_event_id,
                   (
                     typeof(event.draft_key) = 'text'
                     AND length(CAST(event.draft_key AS BLOB)) = 64
                     AND typeof(event.run_id) = 'text'
                     AND length(CAST(event.run_id AS BLOB)) <= {_MAX_RUN_ID_BYTES}
                     AND typeof(event.source_repository) = 'text'
                     AND length(CAST(event.source_repository AS BLOB)) <=
                         {_MAX_REPOSITORY_BYTES}
                     AND typeof(event.target_repository) = 'text'
                     AND length(CAST(event.target_repository AS BLOB)) <=
                         {_MAX_REPOSITORY_BYTES}
                     AND typeof(event.target_base_branch) = 'text'
                     AND length(CAST(event.target_base_branch AS BLOB)) <= 255
                     AND typeof(event.target_base_sha) = 'text'
                     AND length(CAST(event.target_base_sha AS BLOB)) <= 64
                     AND typeof(event.push_repository) = 'text'
                     AND length(CAST(event.push_repository AS BLOB)) <=
                         {_MAX_REPOSITORY_BYTES}
                     AND typeof(event.branch) = 'text'
                     AND length(CAST(event.branch AS BLOB)) <= 255
                     AND typeof(event.candidate_sha) = 'text'
                     AND length(CAST(event.candidate_sha AS BLOB)) <= 64
                     AND typeof(event.evidence_hash) = 'text'
                     AND length(CAST(event.evidence_hash AS BLOB)) = 64
                     AND typeof(event.title) = 'text'
                     AND length(CAST(event.title AS BLOB)) <=
                         {_MAX_PREVENTION_TITLE_BYTES}
                     AND typeof(event.body) = 'text'
                     AND length(CAST(event.body AS BLOB)) <=
                         {_MAX_PREVENTION_BODY_BYTES}
                     AND typeof(event.phase) = 'text'
                     AND length(CAST(event.phase AS BLOB)) <= 32
                     AND (
                         event.draft_number IS NULL
                         OR typeof(event.draft_number) = 'integer'
                     )
                     AND (
                         event.draft_url IS NULL
                         OR (
                             typeof(event.draft_url) = 'text'
                             AND length(CAST(event.draft_url AS BLOB)) <=
                                 {_MAX_PREVENTION_URL_BYTES}
                         )
                     )
                     AND typeof(event.occurred_at) = 'text'
                     AND length(CAST(event.occurred_at AS BLOB)) <= 64
                     AND typeof(attestation.draft_key) = 'text'
                     AND length(CAST(attestation.draft_key AS BLOB)) = 64
                     AND typeof(attestation.attestation_version) = 'integer'
                     AND typeof(attestation.source_repository_id) = 'integer'
                     AND attestation.source_repository_id > 0
                     AND typeof(attestation.target_repository_id) = 'integer'
                     AND attestation.target_repository_id > 0
                     AND typeof(attestation.push_repository_id) = 'integer'
                     AND attestation.push_repository_id > 0
                     AND typeof(attestation.source_policy_json) = 'text'
                     AND length(CAST(attestation.source_policy_json AS BLOB)) <=
                         {_MAX_PREVENTION_ATTESTATION_BYTES}
                     AND typeof(attestation.source_policy_digest) = 'text'
                     AND length(CAST(attestation.source_policy_digest AS BLOB)) = 64
                     AND typeof(attestation.patch_paths_json) = 'text'
                     AND length(CAST(attestation.patch_paths_json AS BLOB)) <=
                         {_MAX_PREVENTION_PATCH_JSON_BYTES}
                     AND typeof(attestation.patch_hash) = 'text'
                     AND length(CAST(attestation.patch_hash AS BLOB)) = 64
                     AND typeof(attestation.test_attestation_json) = 'text'
                     AND length(CAST(attestation.test_attestation_json AS BLOB)) <=
                         {_MAX_PREVENTION_ATTESTATION_BYTES}
                     AND typeof(attestation.test_attestation_digest) = 'text'
                     AND length(CAST(attestation.test_attestation_digest AS BLOB)) = 64
                     AND typeof(attestation.open_source_json) = 'text'
                     AND length(CAST(attestation.open_source_json AS BLOB)) <=
                         {_MAX_PREVENTION_ATTESTATION_BYTES}
                     AND typeof(attestation.source_pulls_json) = 'text'
                     AND length(CAST(attestation.source_pulls_json AS BLOB)) <=
                         {_MAX_PREVENTION_SOURCE_JSON_BYTES}
                     AND typeof(attestation.event_revision_ids_json) = 'text'
                     AND length(CAST(attestation.event_revision_ids_json AS BLOB)) <=
                         {_MAX_PREVENTION_SOURCE_JSON_BYTES}
                     AND typeof(attestation.occurred_at) = 'text'
                     AND length(CAST(attestation.occurred_at AS BLOB)) <= 64
                   ) AS payload_is_bounded
            FROM prevention_draft_events AS event
            LEFT JOIN prevention_candidate_attestations AS attestation
              ON attestation.draft_key = event.draft_key
            WHERE event.draft_key = ?
            ORDER BY event.prevention_event_id DESC
            LIMIT 1
            """,
            (draft_key,),
        ).fetchone()
        if preflight is None:
            return None
        if not bool(preflight["payload_is_bounded"]):
            raise RuntimeError("Prevention draft ledger contains malformed data.")
        row = self._connection.execute(
            """
            SELECT event.*, attestation.*
            FROM prevention_draft_events AS event
            LEFT JOIN prevention_candidate_attestations AS attestation
              ON attestation.draft_key = event.draft_key
            WHERE event.prevention_event_id = ?
            """,
            (int(preflight["prevention_event_id"]),),
        ).fetchone()
        if row is None:  # pragma: no cover - append-only row disappeared externally
            raise RuntimeError("Prevention draft ledger changed during inspection.")
        return self._prevention_from_row(row)

    def record_prevention_recovery_attempt(
        self,
        *,
        draft_key: str,
        occurred_at: datetime | None = None,
    ) -> PreventionRecoveryAttemptDisposition:
        """Persist a rotation point before a lookup and classify its retry budget."""

        if not isinstance(draft_key, str) or not _SHA256_RE.fullmatch(draft_key):
            raise ValueError("draft_key must be a SHA-256 digest.")
        with self._connection:
            latest = self._connection.execute(
                """
                SELECT event.prevention_event_id, event.phase,
                       legacy.prevention_event_id AS legacy_event_id,
                       legacy_result.legacy_event_id AS reconciled_event_id,
                       legacy_exact.legacy_event_id AS exact_event_id,
                       quarantine.prevention_event_id AS quarantined_event_id,
                       legacy_invalid.legacy_event_id AS invalid_event_id,
                       exhausted.legacy_event_id AS exhausted_event_id
                FROM prevention_draft_events AS event
                LEFT JOIN prevention_legacy_candidate_events AS legacy
                  ON legacy.prevention_event_id = event.prevention_event_id
                LEFT JOIN prevention_legacy_reconciliations AS legacy_result
                  ON legacy_result.legacy_event_id = event.prevention_event_id
                LEFT JOIN prevention_legacy_exact_drafts AS legacy_exact
                  ON legacy_exact.legacy_event_id = event.prevention_event_id
                LEFT JOIN prevention_invalid_record_quarantines AS quarantine
                  ON quarantine.prevention_event_id = event.prevention_event_id
                LEFT JOIN prevention_legacy_invalid_resolutions AS legacy_invalid
                  ON legacy_invalid.legacy_event_id = event.prevention_event_id
                LEFT JOIN prevention_legacy_deferral_exhaustions AS exhausted
                  ON exhausted.legacy_event_id = event.prevention_event_id
                WHERE event.draft_key = ?
                ORDER BY event.prevention_event_id DESC
                LIMIT 1
                """,
                (draft_key,),
            ).fetchone()
            resolution = self._connection.execute(
                "SELECT 1 FROM prevention_resolution_events WHERE draft_key = ?",
                (draft_key,),
            ).fetchone()
            if (
                latest is None
                or (
                    latest["phase"] not in {"validated", "pushed"}
                    and not (
                        latest["phase"] == "draft_opened"
                        and latest["legacy_event_id"] is not None
                    )
                )
                or resolution is not None
                or latest["reconciled_event_id"] is not None
                or latest["exact_event_id"] is not None
                or latest["quarantined_event_id"] is not None
                or latest["invalid_event_id"] is not None
                or latest["exhausted_event_id"] is not None
            ):
                raise ValueError("Only a pending prevention draft can be attempted.")
            attempt_count = self._connection.execute(
                """
                SELECT COUNT(*) AS attempt_count
                FROM prevention_recovery_attempt_events
                WHERE draft_key = ?
                """,
                (draft_key,),
            ).fetchone()
            if (
                attempt_count is None
            ):  # pragma: no cover - aggregate always returns one row
                raise RuntimeError("Prevention recovery attempt count failed.")
            prior_attempts = int(attempt_count["attempt_count"])
            if prior_attempts == _MAX_PREVENTION_RECOVERY_ATTEMPTS + 1:
                # A process may have died after durably starting the final
                # exact lookup. Resume that same final observation without
                # appending an unbounded stream of crash markers.
                return PreventionRecoveryAttemptDisposition.FINAL
            if prior_attempts > _MAX_PREVENTION_RECOVERY_ATTEMPTS + 1:
                return PreventionRecoveryAttemptDisposition.EXHAUSTED
            self._connection.execute(
                """
                INSERT INTO prevention_recovery_attempt_events (
                    draft_key, occurred_at
                ) VALUES (?, ?)
                """,
                (draft_key, _serialize_datetime(occurred_at or _now())),
            )
        if prior_attempts == _MAX_PREVENTION_RECOVERY_ATTEMPTS:
            return PreventionRecoveryAttemptDisposition.FINAL
        return PreventionRecoveryAttemptDisposition.RETRYABLE

    def record_prevention_resolution(
        self,
        *,
        draft_key: str,
        resolution: str,
        terminal_local_skip_acknowledged: bool = False,
        occurred_at: datetime | None = None,
    ) -> PreventionResolutionRecord:
        """Record one idempotent terminal conflict or operator quarantine."""

        allowed = {
            "base_moved",
            "branch_missing",
            "branch_modified",
            "invalid_record",
            "policy_changed",
            "recovery_exhausted",
            "remote_conflict",
            "source_authority_changed",
            "operator_quarantined",
        }
        if resolution not in allowed:
            raise ValueError("Unsupported prevention resolution.")
        valid_draft_key = isinstance(draft_key, str) and bool(
            _SHA256_RE.fullmatch(draft_key)
        )
        if not valid_draft_key and (
            resolution != "invalid_record"
            or not isinstance(draft_key, str)
            or not draft_key
            or len(draft_key.encode("utf-8")) > _MAX_PREVENTION_INVALID_DRAFT_KEY_BYTES
        ):
            raise ValueError("draft_key must be a SHA-256 digest.")
        if (
            resolution == "operator_quarantined"
            and terminal_local_skip_acknowledged is not True
        ):
            raise ValueError(
                "Operator quarantine requires explicit terminal local-skip "
                "acknowledgement."
            )
        if (
            resolution != "operator_quarantined"
            and terminal_local_skip_acknowledged is not False
        ):
            raise ValueError(
                "Only operator quarantine accepts local-skip acknowledgement."
            )
        timestamp = _serialize_datetime(occurred_at or _now())
        with self._connection:
            latest = self._connection.execute(
                """
                SELECT phase FROM prevention_draft_events
                WHERE draft_key = ?
                ORDER BY prevention_event_id DESC
                LIMIT 1
                """,
                (draft_key,),
            ).fetchone()
            if latest is None:
                raise ValueError("Prevention draft does not exist.")
            if (
                self._connection.execute(
                    """
                SELECT 1
                FROM prevention_draft_events AS event
                JOIN prevention_legacy_candidate_events AS legacy
                  ON legacy.prevention_event_id = event.prevention_event_id
                WHERE event.draft_key = ?
                LIMIT 1
                """,
                    (draft_key,),
                ).fetchone()
                is not None
            ):
                raise ValueError(
                    "Released-v1 prevention uses its reconciliation ledger."
                )
            existing = self._connection.execute(
                """
                SELECT * FROM prevention_resolution_events WHERE draft_key = ?
                """,
                (draft_key,),
            ).fetchone()
            if existing is not None:
                if existing["resolution"] != resolution:
                    raise ValueError("Prevention resolution is already terminal.")
                parsed = _parse_datetime(existing["occurred_at"])
                if parsed is None:  # pragma: no cover - database constraint
                    raise RuntimeError("Prevention resolution has no timestamp.")
                return PreventionResolutionRecord(
                    resolution_id=int(existing["resolution_id"]),
                    draft_key=draft_key,
                    resolution=resolution,
                    occurred_at=parsed,
                )
            if latest["phase"] not in {"validated", "pushed"}:
                raise ValueError("Only a pending prevention draft can be resolved.")
            cursor = self._connection.execute(
                """
                INSERT INTO prevention_resolution_events (
                    draft_key, resolution, occurred_at
                ) VALUES (?, ?, ?)
                """,
                (draft_key, resolution, timestamp),
            )
        return PreventionResolutionRecord(
            resolution_id=int(cursor.lastrowid),
            draft_key=draft_key,
            resolution=resolution,
            occurred_at=_parse_datetime(timestamp) or (occurred_at or _now()),
        )

    def prevention_resolution(
        self, draft_key: str
    ) -> PreventionResolutionRecord | None:
        """Return the terminal resolution for one prevention attempt."""

        if (
            not isinstance(draft_key, str)
            or not draft_key
            or len(draft_key.encode("utf-8")) > _MAX_PREVENTION_INVALID_DRAFT_KEY_BYTES
        ):
            raise ValueError("draft_key must be a bounded non-empty value.")
        row = self._connection.execute(
            """
            SELECT resolution.*
            FROM prevention_resolution_events AS resolution
            WHERE resolution.draft_key = ?
              AND NOT EXISTS (
                  SELECT 1 FROM prevention_draft_events AS opened
                  WHERE opened.draft_key = resolution.draft_key
                    AND opened.phase = 'draft_opened'
              )
            """,
            (draft_key,),
        ).fetchone()
        if row is None:
            return None
        occurred_at = _parse_datetime(row["occurred_at"])
        if occurred_at is None:  # pragma: no cover - database constraint
            raise RuntimeError("Prevention resolution has no timestamp.")
        return PreventionResolutionRecord(
            resolution_id=int(row["resolution_id"]),
            draft_key=str(row["draft_key"]),
            resolution=str(row["resolution"]),
            occurred_at=occurred_at,
        )

    def claimed_prevention_evidence_hashes(
        self,
        *,
        source_repository_id: int,
        target_repository_id: int,
        evidence_hashes: Sequence[str],
        source_repository: str | None = None,
    ) -> frozenset[str]:
        """Return a bounded subset already authored, pending, or terminal."""

        if len(evidence_hashes) > _MAX_PREVENTION_CANDIDATE_HASHES:
            raise ValueError(
                "evidence_hashes must be at most 100 unique SHA-256 digests."
            )
        candidates = tuple(evidence_hashes)
        if (
            len(candidates) > _MAX_PREVENTION_CANDIDATE_HASHES
            or len(set(candidates)) != len(candidates)
            or any(
                not isinstance(evidence_hash, str)
                or not _SHA256_RE.fullmatch(evidence_hash)
                for evidence_hash in candidates
            )
        ):
            raise ValueError(
                "evidence_hashes must be at most 100 unique SHA-256 digests."
            )
        if any(
            isinstance(repository_id, bool)
            or not isinstance(repository_id, int)
            or not 0 < repository_id <= _SQLITE_MAX_INTEGER
            for repository_id in (source_repository_id, target_repository_id)
        ):
            raise ValueError("repository IDs must be positive integers.")
        if source_repository is not None and (
            not isinstance(source_repository, str)
            or not _REPOSITORY_RE.fullmatch(source_repository)
        ):
            raise ValueError("source_repository must use owner/name form.")
        if not candidates:
            return frozenset()
        placeholders = ", ".join("?" for _ in candidates)
        rows = self._connection.execute(
            f"""
            SELECT DISTINCT event.evidence_hash
            FROM prevention_draft_events AS event
            JOIN prevention_candidate_attestations AS attestation
              ON attestation.draft_key = event.draft_key
            WHERE attestation.source_repository_id = ?
              AND attestation.target_repository_id = ?
              AND event.evidence_hash IN ({placeholders})
            UNION
            SELECT legacy.evidence_hash
            FROM prevention_legacy_reconciliations AS legacy
            WHERE legacy.source_repository_id = ?
              AND legacy.target_repository_id = ?
              AND legacy.disposition IN (
                  'draft_opened', 'not_found', 'remote_conflict',
                  'recovery_exhausted'
              )
              AND legacy.evidence_hash IN ({placeholders})
            UNION
            SELECT legacy_exact.evidence_hash
            FROM prevention_legacy_exact_drafts AS legacy_exact
            WHERE legacy_exact.source_repository_id = ?
              AND legacy_exact.target_repository_id = ?
              AND legacy_exact.evidence_hash IN ({placeholders})
            """,
            (
                source_repository_id,
                target_repository_id,
                *candidates,
                source_repository_id,
                target_repository_id,
                *candidates,
                source_repository_id,
                target_repository_id,
                *candidates,
            ),
        ).fetchall()
        claimed = {str(row["evidence_hash"]) for row in rows}
        if source_repository is not None:
            # Released-v1 rows did not persist numeric repository IDs. Keep
            # their exact source-name evidence claimed while read-only
            # reconciliation is pending or terminal, including when the
            # current prevention target policy differs. This fail-closed claim
            # prevents the same feedback from reaching a second model/POST.
            legacy_rows = self._connection.execute(
                f"""
                WITH bounded_legacy AS MATERIALIZED (
                    SELECT event.prevention_event_id, event.draft_key,
                           event.evidence_hash, event.phase
                    FROM prevention_draft_events AS event
                    JOIN prevention_legacy_candidate_events AS legacy
                      ON legacy.prevention_event_id = event.prevention_event_id
                    WHERE event.source_repository = ?
                      AND typeof(event.draft_key) = 'text'
                      AND length(event.draft_key) = 64
                      AND event.draft_key NOT GLOB '*[^0-9a-f]*'
                      AND typeof(event.evidence_hash) = 'text'
                      AND length(event.evidence_hash) = 64
                      AND event.evidence_hash NOT GLOB '*[^0-9a-f]*'
                      AND event.evidence_hash IN ({placeholders})
                ), latest AS (
                    SELECT bounded_legacy.*,
                           ROW_NUMBER() OVER (
                               PARTITION BY bounded_legacy.draft_key
                               ORDER BY bounded_legacy.prevention_event_id DESC
                           ) AS guardian_row_number
                    FROM bounded_legacy
                )
                SELECT DISTINCT evidence_hash
                FROM latest
                WHERE guardian_row_number = 1
                  AND phase IN (
                      'validated', 'pushed', 'draft_opened', 'abandoned'
                  )
                """,
                (source_repository, *candidates),
            ).fetchall()
            claimed.update(str(row["evidence_hash"]) for row in legacy_rows)
        return frozenset(claimed)

    def opened_prevention_evidence_hashes(
        self,
        *,
        source_repository_id: int,
        target_repository_id: int,
        limit: int = 100,
    ) -> frozenset[str]:
        """Return a bounded set of opened prevention deduplication hashes."""

        if any(
            isinstance(repository_id, bool)
            or not isinstance(repository_id, int)
            or not 0 < repository_id <= _SQLITE_MAX_INTEGER
            for repository_id in (source_repository_id, target_repository_id)
        ):
            raise ValueError("repository IDs must be positive integers.")
        if (
            isinstance(limit, bool)
            or not isinstance(limit, int)
            or not 1 <= limit <= 100
        ):
            raise ValueError("limit must be an integer from 1 through 100.")
        rows = self._connection.execute(
            """
            SELECT evidence_hash FROM (
                SELECT DISTINCT event.evidence_hash
                FROM prevention_draft_events AS event
                JOIN prevention_candidate_attestations AS attestation
                  ON attestation.draft_key = event.draft_key
                WHERE attestation.source_repository_id = ?
                  AND attestation.target_repository_id = ?
                  AND event.phase = 'draft_opened'
                UNION
                SELECT legacy.evidence_hash
                FROM prevention_legacy_reconciliations AS legacy
                WHERE legacy.source_repository_id = ?
                  AND legacy.target_repository_id = ?
                  AND legacy.disposition = 'draft_opened'
                UNION
                SELECT legacy_exact.evidence_hash
                FROM prevention_legacy_exact_drafts AS legacy_exact
                WHERE legacy_exact.source_repository_id = ?
                  AND legacy_exact.target_repository_id = ?
            )
            LIMIT ?
            """,
            (
                source_repository_id,
                target_repository_id,
                source_repository_id,
                target_repository_id,
                source_repository_id,
                target_repository_id,
                limit + 1,
            ),
        ).fetchall()
        if len(rows) > limit:
            raise RuntimeError("Opened prevention evidence read exceeds its bound.")
        hashes = frozenset(str(row["evidence_hash"]) for row in rows)
        if any(not _SHA256_RE.fullmatch(item) for item in hashes):
            raise RuntimeError("Opened prevention evidence is malformed.")
        return hashes

    def _remediation_from_row(self, row: sqlite3.Row) -> RemediationDraftRecord:
        occurred_at = _parse_datetime(row["occurred_at"])
        if occurred_at is None:  # pragma: no cover - database constraint
            raise RuntimeError("Remediation draft event has no timestamp.")
        try:
            self._validate_draft_run_authority(
                run_id=row["run_id"],
                repository=row["target_repository"],
                allowed_modes=_REMEDIATION_DRAFT_RUN_MODES,
                label="Remediation draft",
            )
            draft_key = str(row["draft_key"])
            branch_identity_version = int(row["branch_identity_version"])
            if not _SHA256_RE.fullmatch(draft_key) or branch_identity_version not in {
                1,
                2,
            }:
                raise ValueError
            source_pulls_json = row["source_pulls_json"]
            event_revision_ids_json = row["event_revision_ids_json"]
            if (
                not isinstance(source_pulls_json, str)
                or len(source_pulls_json.encode("utf-8"))
                > _MAX_REMEDIATION_SOURCE_JSON_BYTES
                or not isinstance(event_revision_ids_json, str)
                or len(event_revision_ids_json.encode("utf-8"))
                > _MAX_REMEDIATION_SOURCE_JSON_BYTES
            ):
                raise ValueError
            raw_pulls = loads_bounded_json(source_pulls_json)
            raw_revision_ids = loads_bounded_json(event_revision_ids_json)
            if (
                not isinstance(raw_pulls, list)
                or not isinstance(
                    raw_revision_ids,
                    list,
                )
                or len(raw_pulls) > _MAX_REMEDIATION_SOURCE_PULLS
                or len(raw_revision_ids) > _MAX_REMEDIATION_SOURCE_REVISIONS
            ):
                raise ValueError
            source_pulls = tuple(
                HistoricalPullReference(
                    repository=item["repository"],
                    repository_id=item["repository_id"],
                    pull_id=item["pull_id"],
                    pr_number=item["pr_number"],
                    pull_revision_digest=item["pull_revision_digest"],
                    authority_digest=(
                        item["authority_digest"]
                        if "authority_digest" in item
                        else (
                            _LEGACY_UNATTESTED_AUTHORITY_DIGEST
                            if branch_identity_version == 1
                            else None
                        )
                    ),
                    policy_digest=item["policy_digest"],
                    head_sha=item["head_sha"],
                    base_sha=item["base_sha"],
                )
                for item in raw_pulls
                if isinstance(item, Mapping)
            )
            if len(source_pulls) != len(raw_pulls):
                raise ValueError
            event_revision_ids = tuple(raw_revision_ids)
            if any(
                isinstance(value, bool) or not isinstance(value, int) or value <= 0
                for value in event_revision_ids
            ):
                raise ValueError
            if (
                not source_pulls
                or len(set(source_pulls)) != len(source_pulls)
                or len({source.pull_id for source in source_pulls}) != len(source_pulls)
                or len({source.pr_number for source in source_pulls})
                != len(source_pulls)
                or len({source.policy_digest for source in source_pulls}) != 1
                or len(set(event_revision_ids)) != len(event_revision_ids)
                or tuple(sorted(event_revision_ids)) != event_revision_ids
            ):
                raise ValueError
            path_rows = self._connection.execute(
                """
                SELECT changed_paths_json
                FROM remediation_draft_path_attestations
                WHERE draft_key = ?
                LIMIT 2
                """,
                (row["draft_key"],),
            ).fetchall()
            changed_paths: tuple[str, ...] | None = None
            if path_rows:
                if len(path_rows) != 1:
                    raise ValueError
                raw_paths_json = path_rows[0]["changed_paths_json"]
                if (
                    not isinstance(raw_paths_json, str)
                    or len(raw_paths_json.encode("utf-8"))
                    > _MAX_REMEDIATION_PATHS_JSON_BYTES
                ):
                    raise ValueError
                raw_paths = loads_bounded_json(raw_paths_json)
                if not isinstance(raw_paths, list):
                    raise ValueError
                changed_paths, canonical_paths_json = (
                    _validated_remediation_changed_paths(raw_paths)
                )
                if canonical_paths_json != raw_paths_json:
                    raise ValueError
            edit_rows = self._connection.execute(
                """
                SELECT edit_hash, target_hash FROM remediation_draft_edit_events
                WHERE draft_key = ?
                ORDER BY edit_hash
                LIMIT ?
                """,
                (row["draft_key"], _MAX_REMEDIATION_EDIT_HASHES + 1),
            ).fetchall()
            edit_hashes = tuple(str(item["edit_hash"]) for item in edit_rows)
            edit_target_hashes = tuple(
                (str(item["edit_hash"]), str(item["target_hash"]))
                for item in edit_rows
                if item["target_hash"] is not None
            )
            if (
                not edit_hashes
                or len(edit_hashes) > _MAX_REMEDIATION_EDIT_HASHES
                or len(set(edit_hashes)) != len(edit_hashes)
                or any(not _SHA256_RE.fullmatch(value) for value in edit_hashes)
                or remediation_batch_hash(edit_hashes) != row["batch_hash"]
                or (
                    edit_target_hashes
                    and (
                        len(edit_target_hashes) != len(edit_hashes)
                        or len({target for _edit, target in edit_target_hashes})
                        != len(edit_target_hashes)
                        or any(
                            not _SHA256_RE.fullmatch(target)
                            for _edit, target in edit_target_hashes
                        )
                    )
                )
            ):
                raise ValueError
        except (KeyError, TypeError, ValueError, json.JSONDecodeError):
            raise RuntimeError(
                "Remediation draft ledger contains malformed data."
            ) from None
        return RemediationDraftRecord(
            draft_key=draft_key,
            branch_identity_version=branch_identity_version,
            run_id=row["run_id"],
            target_repository=row["target_repository"],
            target_repository_id=int(row["target_repository_id"]),
            target_base_branch=row["target_base_branch"],
            target_base_sha=row["target_base_sha"],
            push_repository=row["push_repository"],
            push_repository_id=int(row["push_repository_id"]),
            branch=row["branch"],
            candidate_sha=row["candidate_sha"],
            evidence_hash=row["evidence_hash"],
            batch_hash=row["batch_hash"],
            edit_hashes=edit_hashes,
            edit_target_hashes=edit_target_hashes,
            source_pulls=source_pulls,
            event_revision_ids=event_revision_ids,
            changed_paths=changed_paths,
            title=row["title"],
            body=row["body"],
            phase=row["phase"],
            draft_number=(
                int(row["draft_number"]) if row["draft_number"] is not None else None
            ),
            draft_pull_id=(
                int(row["draft_pull_id"]) if row["draft_pull_id"] is not None else None
            ),
            draft_url=row["draft_url"],
            occurred_at=occurred_at,
        )

    def record_remediation_draft_event(
        self,
        *,
        run_id: str,
        target_repository: str,
        target_repository_id: int,
        target_base_branch: str,
        target_base_sha: str,
        push_repository: str,
        push_repository_id: int,
        branch: str,
        candidate_sha: str,
        evidence_hash: str,
        batch_hash: str,
        edit_hashes: Sequence[str],
        edit_target_hashes: Sequence[tuple[str, str]],
        source_pulls: Sequence[HistoricalPullReference],
        event_revision_ids: Sequence[int],
        changed_paths: Sequence[str],
        title: str,
        body: str,
        phase: str,
        draft_number: int | None = None,
        draft_pull_id: int | None = None,
        draft_url: str | None = None,
        occurred_at: datetime | None = None,
        branch_identity_version: int = 2,
    ) -> str:
        """Append one idempotent phase for an exact remediation draft."""

        if phase not in {"validated", "pushed", "draft_opened", "abandoned"}:
            raise ValueError("Unsupported remediation draft phase.")
        if (
            isinstance(branch_identity_version, bool)
            or not isinstance(branch_identity_version, int)
            or branch_identity_version not in {1, 2}
        ):
            raise ValueError("branch_identity_version must be 1 or 2.")
        for repository_name, label in (
            (target_repository, "target_repository"),
            (push_repository, "push_repository"),
        ):
            if (
                not isinstance(repository_name, str)
                or not _REPOSITORY_RE.fullmatch(repository_name)
                or any(
                    component in {".", ".."} for component in repository_name.split("/")
                )
            ):
                raise ValueError(f"{label} must use canonical owner/name form.")
        self._validate_draft_run_authority(
            run_id=run_id,
            repository=target_repository,
            allowed_modes=_REMEDIATION_DRAFT_RUN_MODES,
            label="Remediation draft",
        )
        for label, repository_id in (
            ("target_repository_id", target_repository_id),
            ("push_repository_id", push_repository_id),
        ):
            if (
                isinstance(repository_id, bool)
                or not isinstance(repository_id, int)
                or repository_id <= 0
            ):
                raise ValueError(f"{label} must be a positive integer.")
        same_name = target_repository.casefold() == push_repository.casefold()
        same_id = target_repository_id == push_repository_id
        if same_name != same_id:
            raise ValueError("Remediation has an ambiguous repository identity.")
        if any(
            not isinstance(value, str)
            or not re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", value)
            for value in (target_base_sha, candidate_sha)
        ):
            raise ValueError("Remediation SHAs must be full lowercase object IDs.")
        for value, label in (
            (evidence_hash, "evidence_hash"),
            (batch_hash, "batch_hash"),
        ):
            if not isinstance(value, str) or not _SHA256_RE.fullmatch(value):
                raise ValueError(f"{label} must be a SHA-256 digest.")
        supplied_edit_hashes = _bounded_sequence(
            edit_hashes,
            limit=_MAX_REMEDIATION_EDIT_HASHES,
            label="edit_hashes",
        )
        normalized_edit_hashes = tuple(sorted(supplied_edit_hashes))
        if remediation_batch_hash(normalized_edit_hashes) != batch_hash:
            raise ValueError("batch_hash does not match its exact remediation edits.")
        raw_edit_targets = _bounded_sequence(
            edit_target_hashes,
            limit=_MAX_REMEDIATION_EDIT_HASHES,
            label="edit_target_hashes",
        )
        if any(
            not isinstance(item, tuple)
            or len(item) != 2
            or any(
                not isinstance(value, str) or not _SHA256_RE.fullmatch(value)
                for value in item
            )
            for item in raw_edit_targets
        ):
            raise ValueError(
                "edit_target_hashes must map every edit to one unique target."
            )
        normalized_edit_targets = tuple(sorted(raw_edit_targets))
        if normalized_edit_targets:
            if (
                len(normalized_edit_targets) != len(normalized_edit_hashes)
                or tuple(edit for edit, _target in normalized_edit_targets)
                != normalized_edit_hashes
                or len({target for _edit, target in normalized_edit_targets})
                != len(normalized_edit_targets)
            ):
                raise ValueError(
                    "edit_target_hashes must map every edit to one unique target."
                )
        for value, label in (
            (target_base_branch, "target_base_branch"),
            (branch, "branch"),
            (title, "title"),
        ):
            if (
                not isinstance(value, str)
                or not value
                or any(character in value for character in "\r\n\x00")
            ):
                raise ValueError(f"{label} must be a safe non-empty value.")
        if not isinstance(body, str) or not body or "\x00" in body:
            raise ValueError("body must be non-empty and contain no NUL.")
        _normalized_paths, changed_paths_json = _validated_remediation_changed_paths(
            changed_paths
        )
        if phase == "draft_opened":
            if (
                isinstance(draft_number, bool)
                or not isinstance(draft_number, int)
                or draft_number <= 0
                or isinstance(draft_pull_id, bool)
                or not isinstance(draft_pull_id, int)
                or draft_pull_id <= 0
                or not isinstance(draft_url, str)
                or not draft_url
                or any(character in draft_url for character in "\r\n\x00")
            ):
                raise ValueError(
                    "An opened remediation draft needs its number and URL."
                )
        elif (
            draft_number is not None
            or draft_pull_id is not None
            or draft_url is not None
        ):
            raise ValueError("Only an opened remediation draft may store PR metadata.")

        normalized_pulls = _bounded_sequence(
            source_pulls,
            limit=_MAX_REMEDIATION_SOURCE_PULLS,
            label="source_pulls",
        )
        pull_identities = tuple(
            (
                item.repository,
                item.repository_id,
                item.pull_id,
                item.pr_number,
            )
            for item in normalized_pulls
            if isinstance(item, HistoricalPullReference)
        )
        if (
            not normalized_pulls
            or any(
                not isinstance(item, HistoricalPullReference)
                for item in normalized_pulls
            )
            or len(set(normalized_pulls)) != len(normalized_pulls)
            or len(set(pull_identities)) != len(normalized_pulls)
            or len({item.pull_id for item in normalized_pulls}) != len(normalized_pulls)
            or len({item.pr_number for item in normalized_pulls})
            != len(normalized_pulls)
            or len({item.policy_digest for item in normalized_pulls}) != 1
            or (
                branch_identity_version == 2
                and any(
                    item.authority_digest == _LEGACY_UNATTESTED_AUTHORITY_DIGEST
                    for item in normalized_pulls
                )
            )
        ):
            raise ValueError("source_pulls must contain unique historical identities.")
        normalized_pulls = tuple(
            sorted(
                normalized_pulls,
                key=lambda item: (
                    item.repository,
                    item.repository_id,
                    item.pull_id,
                    item.pr_number,
                    item.pull_revision_digest,
                    item.policy_digest,
                    item.head_sha,
                    item.base_sha,
                ),
            )
        )
        if any(
            item.repository != target_repository
            or item.repository_id != target_repository_id
            for item in normalized_pulls
        ):
            raise ValueError(
                "Every source pull must match the exact remediation target."
            )

        normalized_revision_ids = _bounded_sequence(
            event_revision_ids,
            limit=_MAX_REMEDIATION_SOURCE_REVISIONS,
            label="event_revision_ids",
        )
        if (
            not normalized_revision_ids
            or len(set(normalized_revision_ids)) != len(normalized_revision_ids)
            or any(
                isinstance(value, bool) or not isinstance(value, int) or value <= 0
                for value in normalized_revision_ids
            )
        ):
            raise ValueError(
                "event_revision_ids must contain unique positive integers."
            )
        normalized_revision_ids = tuple(sorted(normalized_revision_ids))
        exact_evidence_hash = self.validate_historical_remediation_evidence(
            source_pulls=normalized_pulls,
            event_revision_ids=normalized_revision_ids,
        )
        if exact_evidence_hash != evidence_hash:
            raise ValueError(
                "evidence_hash does not match exact stored remediation evidence."
            )

        source_pulls_json = json.dumps(
            [
                {
                    **(
                        {"authority_digest": item.authority_digest}
                        if item.authority_digest != _LEGACY_UNATTESTED_AUTHORITY_DIGEST
                        else {}
                    ),
                    "base_sha": item.base_sha,
                    "head_sha": item.head_sha,
                    "policy_digest": item.policy_digest,
                    "pr_number": item.pr_number,
                    "pull_id": item.pull_id,
                    "pull_revision_digest": item.pull_revision_digest,
                    "repository": item.repository,
                    "repository_id": item.repository_id,
                }
                for item in normalized_pulls
            ],
            separators=(",", ":"),
            sort_keys=True,
        )
        event_revision_ids_json = json.dumps(
            normalized_revision_ids,
            separators=(",", ":"),
        )
        if (
            len(source_pulls_json.encode("utf-8")) > _MAX_REMEDIATION_SOURCE_JSON_BYTES
            or len(event_revision_ids_json.encode("utf-8"))
            > _MAX_REMEDIATION_SOURCE_JSON_BYTES
        ):
            raise ValueError("Remediation source authority exceeds its byte bound.")
        legacy_key_payload = (
            f"{run_id}\n{target_repository}\n{target_repository_id}\n{target_base_branch}\n"
            f"{target_base_sha}\n{push_repository}\n{push_repository_id}\n"
            f"{candidate_sha}\n{evidence_hash}\n{batch_hash}"
        )
        key_payload = (
            legacy_key_payload
            if branch_identity_version == 1
            else (
                "branch-identity-v2\n"
                f"{normalized_pulls[0].policy_digest}\n{legacy_key_payload}"
            )
        )
        draft_key = hashlib.sha256(key_payload.encode("utf-8")).hexdigest()
        identity = (
            branch_identity_version,
            run_id,
            target_repository,
            target_repository_id,
            target_base_branch,
            target_base_sha,
            push_repository,
            push_repository_id,
            branch,
            candidate_sha,
            evidence_hash,
            batch_hash,
            source_pulls_json,
            event_revision_ids_json,
            title,
            body,
        )
        event_occurred_at = occurred_at or _now()
        serialized_occurred_at = _serialize_datetime(event_occurred_at)
        with self._connection:
            first = self._connection.execute(
                """
                SELECT branch_identity_version, run_id, target_repository,
                       target_repository_id,
                       target_base_branch, target_base_sha, push_repository,
                       push_repository_id, branch, candidate_sha, evidence_hash,
                       batch_hash, source_pulls_json, event_revision_ids_json,
                       title, body
                FROM remediation_draft_events
                WHERE draft_key = ?
                ORDER BY remediation_event_id
                LIMIT 1
                """,
                (draft_key,),
            ).fetchone()
            if first is not None and tuple(first) != identity:
                raise ValueError(
                    "Remediation phase metadata does not match its first event."
                )
            stored_path_row = self._connection.execute(
                """
                SELECT changed_paths_json
                FROM remediation_draft_path_attestations
                WHERE draft_key = ?
                """,
                (draft_key,),
            ).fetchone()
            if first is not None and (
                stored_path_row is None
                or stored_path_row["changed_paths_json"] != changed_paths_json
            ):
                raise ValueError(
                    "Remediation paths do not match their first exact attestation."
                )
            if first is None and stored_path_row is not None:
                raise ValueError("Remediation path attestation has no draft event.")
            stored_edit_rows = self._connection.execute(
                """
                SELECT edit_hash, target_hash FROM remediation_draft_edit_events
                WHERE draft_key = ?
                ORDER BY edit_hash
                """,
                (draft_key,),
            ).fetchall()
            stored_edit_hashes = tuple(
                str(row["edit_hash"]) for row in stored_edit_rows
            )
            stored_edit_targets = tuple(
                (str(row["edit_hash"]), str(row["target_hash"]))
                for row in stored_edit_rows
                if row["target_hash"] is not None
            )
            if first is not None and stored_edit_hashes != normalized_edit_hashes:
                raise ValueError(
                    "Remediation edit metadata does not match its first event."
                )
            if first is None and not normalized_edit_targets:
                raise ValueError(
                    "A new remediation attempt requires exact edit target metadata."
                )
            if first is not None and stored_edit_targets != normalized_edit_targets:
                raise ValueError(
                    "Remediation edit targets do not match their first event."
                )

            existing_phase = self._connection.execute(
                """
                SELECT draft_number, draft_pull_id, draft_url
                FROM remediation_draft_events
                WHERE draft_key = ? AND phase = ?
                """,
                (draft_key, phase),
            ).fetchone()
            if existing_phase is not None:
                if tuple(existing_phase) != (
                    draft_number,
                    draft_pull_id,
                    draft_url,
                ):
                    raise ValueError(
                        "Remediation phase PR metadata does not match its first event."
                    )
                return draft_key

            latest = self._connection.execute(
                """
                SELECT phase, occurred_at FROM remediation_draft_events
                WHERE draft_key = ?
                ORDER BY remediation_event_id DESC
                LIMIT 1
                """,
                (draft_key,),
            ).fetchone()
            latest_phase = str(latest["phase"]) if latest is not None else None
            allowed_next = {
                None: {"validated"},
                "validated": {"pushed", "abandoned"},
                "pushed": {"draft_opened", "abandoned"},
                "draft_opened": set(),
                "abandoned": set(),
            }
            if phase not in allowed_next[latest_phase]:
                raise ValueError("Invalid remediation draft phase transition.")
            if latest is not None:
                latest_occurred_at = _parse_datetime(latest["occurred_at"])
                if latest_occurred_at is None or event_occurred_at < latest_occurred_at:
                    raise ValueError(
                        "occurred_at must be monotonic for a remediation draft."
                    )

            self._connection.execute(
                """
                INSERT INTO remediation_draft_events (
                    draft_key, branch_identity_version, run_id,
                    target_repository, target_repository_id,
                    target_base_branch, target_base_sha, push_repository,
                    push_repository_id, branch, candidate_sha, evidence_hash,
                    batch_hash, source_pulls_json, event_revision_ids_json,
                    title, body, phase, draft_number, draft_pull_id, draft_url,
                    occurred_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    draft_key,
                    *identity,
                    phase,
                    draft_number,
                    draft_pull_id,
                    draft_url,
                    serialized_occurred_at,
                ),
            )
            if first is None:
                self._connection.execute(
                    """
                    INSERT INTO remediation_draft_path_attestations (
                        draft_key, changed_paths_json
                    ) VALUES (?, ?)
                    """,
                    (draft_key, changed_paths_json),
                )
                self._connection.executemany(
                    """
                    INSERT INTO remediation_draft_edit_events (
                        draft_key, edit_hash, target_hash
                    ) VALUES (?, ?, ?)
                    """,
                    (
                        (draft_key, edit_hash, target_hash)
                        for edit_hash, target_hash in normalized_edit_targets
                    ),
                )
        return draft_key

    def _latest_remediation_drafts(
        self,
        *,
        repository: str | None,
        phases: Sequence[str],
        limit: int | None = None,
    ) -> tuple[RemediationDraftRecord, ...]:
        if limit is not None and (
            isinstance(limit, bool)
            or not isinstance(limit, int)
            or not 1 <= limit <= _MAX_OPERATOR_LIST_ROWS
        ):
            raise ValueError("limit must be an integer from 1 through 100.")
        where = "WHERE target_repository = ?" if repository is not None else ""
        parameters: tuple[object, ...] = (repository,) if repository is not None else ()
        phase_placeholders = ", ".join("?" for _ in phases)
        limit_clause = "LIMIT ?" if limit is not None else ""
        limit_parameters: tuple[object, ...] = (limit,) if limit is not None else ()
        rows = self._connection.execute(
            f"""
            SELECT latest.* FROM (
                SELECT r.*,
                       ROW_NUMBER() OVER (
                           PARTITION BY draft_key
                           ORDER BY remediation_event_id DESC
                       ) AS guardian_row_number
                FROM remediation_draft_events AS r
                {where}
            ) AS latest
            WHERE latest.guardian_row_number = 1
              AND latest.phase IN ({phase_placeholders})
              AND NOT EXISTS (
                  SELECT 1 FROM remediation_resolution_events AS resolution
                  WHERE resolution.draft_key = latest.draft_key
              )
            ORDER BY latest.remediation_event_id
            {limit_clause}
            """,
            (*parameters, *phases, *limit_parameters),
        ).fetchall()
        return tuple(self._remediation_from_row(row) for row in rows)

    def active_remediation_drafts_for_operator(
        self,
        *,
        limit: int = _MAX_OPERATOR_LIST_ROWS,
    ) -> tuple[RemediationDraftRecord, ...]:
        """Return a bounded oldest-first list of active correction attempts."""

        return self._latest_remediation_drafts(
            repository=None,
            phases=("validated", "pushed", "draft_opened"),
            limit=limit,
        )

    def remediation_drafts_for_operator(
        self,
        *,
        limit: int = _MAX_OPERATOR_LIST_ROWS,
    ) -> tuple[RemediationDraftRecord, ...]:
        """Return bounded active-first attempts, including terminal history."""

        if (
            isinstance(limit, bool)
            or not isinstance(limit, int)
            or not 1 <= limit <= _MAX_OPERATOR_LIST_ROWS
        ):
            raise ValueError("limit must be an integer from 1 through 100.")
        rows = self._connection.execute(
            """
            WITH latest AS (
                SELECT r.*,
                       ROW_NUMBER() OVER (
                           PARTITION BY draft_key
                           ORDER BY remediation_event_id DESC
                       ) AS guardian_row_number
                FROM remediation_draft_events AS r
            )
            SELECT latest.*
            FROM latest
            LEFT JOIN remediation_resolution_events AS resolution
              ON resolution.draft_key = latest.draft_key
            WHERE latest.guardian_row_number = 1
            ORDER BY
                CASE
                    WHEN latest.phase IN ('validated', 'pushed', 'draft_opened')
                         AND resolution.draft_key IS NULL
                    THEN 0 ELSE 1
                END,
                CASE
                    WHEN latest.phase IN ('validated', 'pushed', 'draft_opened')
                         AND resolution.draft_key IS NULL
                    THEN latest.remediation_event_id
                END ASC,
                CASE
                    WHEN latest.phase = 'abandoned'
                         OR resolution.draft_key IS NOT NULL
                    THEN COALESCE(resolution.occurred_at, latest.occurred_at)
                END DESC,
                latest.remediation_event_id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        return tuple(self._remediation_from_row(row) for row in rows)

    def remediation_draft_count_for_operator(self) -> int:
        """Return the exact number of local remediation attempts."""

        row = self._connection.execute(
            "SELECT COUNT(DISTINCT draft_key) AS draft_count "
            "FROM remediation_draft_events"
        ).fetchone()
        if row is None:  # pragma: no cover - aggregate always returns one row
            raise RuntimeError("Unable to count remediation attempts.")
        return int(row["draft_count"])

    def active_remediation_draft_count(self) -> int:
        """Return the exact number of unresolved remediation attempts."""

        row = self._connection.execute(
            """
            WITH latest AS (
                SELECT draft_key, phase,
                       ROW_NUMBER() OVER (
                           PARTITION BY draft_key
                           ORDER BY remediation_event_id DESC
                       ) AS guardian_row_number
                FROM remediation_draft_events
            )
            SELECT COUNT(*) AS draft_count
            FROM latest
            WHERE guardian_row_number = 1
              AND phase IN ('validated', 'pushed', 'draft_opened')
              AND NOT EXISTS (
                  SELECT 1 FROM remediation_resolution_events AS resolution
                  WHERE resolution.draft_key = latest.draft_key
              )
            """
        ).fetchone()
        if row is None:  # pragma: no cover - aggregate always returns one row
            raise RuntimeError("Unable to count active remediation attempts.")
        return int(row["draft_count"])

    def pending_remediation_drafts(
        self,
        *,
        repository: str | None = None,
    ) -> tuple[RemediationDraftRecord, ...]:
        """Return validated or pushed remediation candidates needing recovery."""

        return self._latest_remediation_drafts(
            repository=repository,
            phases=("validated", "pushed"),
        )

    def active_remediation_drafts_for_identity(
        self,
        *,
        repository: str,
        repository_id: int,
        batch_hash: str,
    ) -> tuple[RemediationDraftRecord, ...]:
        """Return bounded active attempts for one semantic remediation batch."""

        if (
            not isinstance(repository, str)
            or not _REPOSITORY_RE.fullmatch(repository)
            or any(component in {".", ".."} for component in repository.split("/"))
        ):
            raise ValueError("repository must use canonical owner/name form.")
        if (
            isinstance(repository_id, bool)
            or not isinstance(repository_id, int)
            or repository_id <= 0
        ):
            raise ValueError("repository_id must be a positive integer.")
        if not isinstance(batch_hash, str) or not _SHA256_RE.fullmatch(batch_hash):
            raise ValueError("batch_hash must be a SHA-256 digest.")
        rows = self._connection.execute(
            """
            SELECT latest.* FROM (
                SELECT r.*,
                       ROW_NUMBER() OVER (
                           PARTITION BY draft_key
                           ORDER BY remediation_event_id DESC
                       ) AS guardian_row_number
                FROM remediation_draft_events AS r
                WHERE target_repository = ? AND target_repository_id = ?
                  AND batch_hash = ?
            ) AS latest
            WHERE latest.guardian_row_number = 1
              AND latest.phase IN ('validated', 'pushed', 'draft_opened')
              AND NOT EXISTS (
                  SELECT 1 FROM remediation_resolution_events AS resolution
                  WHERE resolution.draft_key = latest.draft_key
              )
            ORDER BY latest.remediation_event_id
            LIMIT 101
            """,
            (repository, repository_id, batch_hash),
        ).fetchall()
        if len(rows) > 100:
            raise RuntimeError("Remediation branch attempt count exceeded its bound.")
        return tuple(self._remediation_from_row(row) for row in rows)

    def remediation_edit_coverage(
        self,
        *,
        target_repository: str,
        target_repository_id: int,
        edit_target_hashes: Sequence[tuple[str, str]],
    ) -> RemediationEditCoverage:
        """Classify exact coverage and same-target conflicts for semantic edits."""

        if (
            not isinstance(target_repository, str)
            or not _REPOSITORY_RE.fullmatch(target_repository)
            or any(
                component in {".", ".."} for component in target_repository.split("/")
            )
        ):
            raise ValueError("target_repository must use canonical owner/name form.")
        if (
            isinstance(target_repository_id, bool)
            or not isinstance(target_repository_id, int)
            or target_repository_id <= 0
        ):
            raise ValueError("target_repository_id must be a positive integer.")
        raw_mappings = tuple(edit_target_hashes)
        if (
            not raw_mappings
            or len(raw_mappings) > _MAX_REMEDIATION_EDIT_HASHES
            or any(
                not isinstance(item, tuple)
                or len(item) != 2
                or any(
                    not isinstance(value, str) or not _SHA256_RE.fullmatch(value)
                    for value in item
                )
                for item in raw_mappings
            )
        ):
            raise ValueError(
                "edit_target_hashes must contain bounded SHA-256 digest pairs."
            )
        normalized = tuple(sorted(raw_mappings))
        requested_edits = tuple(edit for edit, _target in normalized)
        requested_targets = tuple(target for _edit, target in normalized)
        if len(set(requested_edits)) != len(requested_edits) or len(
            set(requested_targets)
        ) != len(requested_targets):
            raise ValueError(
                "edit_target_hashes must map unique edits to unique targets."
            )
        target_to_edit = dict(zip(requested_targets, requested_edits, strict=True))
        edit_to_target = dict(normalized)
        edit_placeholders = ", ".join("?" for _ in requested_edits)
        target_placeholders = ", ".join("?" for _ in requested_targets)
        rows = self._connection.execute(
            f"""
            WITH latest AS (
                SELECT r.*,
                       ROW_NUMBER() OVER (
                           PARTITION BY draft_key
                           ORDER BY remediation_event_id DESC
                       ) AS guardian_row_number
                FROM remediation_draft_events AS r
                WHERE (
                    target_repository COLLATE NOCASE = ? COLLATE NOCASE
                    OR target_repository_id = ?
                )
            ), latest_remote AS (
                SELECT remote.*,
                       ROW_NUMBER() OVER (
                           PARTITION BY draft_key
                           ORDER BY observation_id DESC
                       ) AS guardian_row_number
                FROM remediation_remote_observation_events AS remote
            )
            SELECT edits.edit_hash, edits.target_hash, latest.draft_key,
                   latest.target_repository, latest.target_repository_id,
                   latest.phase, remote.observation AS remote_observation
            FROM latest
            JOIN remediation_draft_edit_events AS edits
              ON edits.draft_key = latest.draft_key
            LEFT JOIN latest_remote AS remote
              ON remote.draft_key = latest.draft_key
             AND remote.guardian_row_number = 1
            WHERE latest.guardian_row_number = 1
              AND latest.phase IN ('validated', 'pushed', 'draft_opened')
              AND NOT EXISTS (
                  SELECT 1 FROM remediation_resolution_events AS resolution
                  WHERE resolution.draft_key = latest.draft_key
              )
              AND (
                  edits.edit_hash IN ({edit_placeholders})
                  OR edits.target_hash IN ({target_placeholders})
              )
            ORDER BY latest.remediation_event_id, edits.edit_hash
            LIMIT ?
            """,
            (
                target_repository,
                target_repository_id,
                *requested_edits,
                *requested_targets,
                _MAX_REMEDIATION_COVERAGE_ROWS + 1,
            ),
        ).fetchall()
        if len(rows) > _MAX_REMEDIATION_COVERAGE_ROWS:
            raise RuntimeError("Remediation edit coverage exceeded its bound.")
        identity_conflict = self._connection.execute(
            """
            WITH latest AS (
                SELECT r.*,
                       ROW_NUMBER() OVER (
                           PARTITION BY draft_key
                           ORDER BY remediation_event_id DESC
                       ) AS guardian_row_number
                FROM remediation_draft_events AS r
                WHERE (
                    target_repository COLLATE NOCASE = ? COLLATE NOCASE
                    OR target_repository_id = ?
                )
            )
            SELECT 1 FROM latest
            WHERE guardian_row_number = 1
              AND phase IN ('validated', 'pushed', 'draft_opened')
              AND NOT EXISTS (
                  SELECT 1 FROM remediation_resolution_events AS resolution
                  WHERE resolution.draft_key = latest.draft_key
              )
              AND (
                  target_repository != ?
                  OR target_repository_id != ?
              )
            LIMIT 1
            """,
            (
                target_repository,
                target_repository_id,
                target_repository,
                target_repository_id,
            ),
        ).fetchone()
        unmapped_active = self._connection.execute(
            """
            WITH latest AS (
                SELECT r.*,
                       ROW_NUMBER() OVER (
                           PARTITION BY draft_key
                           ORDER BY remediation_event_id DESC
                       ) AS guardian_row_number
                FROM remediation_draft_events AS r
                WHERE target_repository = ? AND target_repository_id = ?
            )
            SELECT 1 FROM latest
            JOIN remediation_draft_edit_events AS edits
              ON edits.draft_key = latest.draft_key
            WHERE latest.guardian_row_number = 1
              AND latest.phase IN ('validated', 'pushed', 'draft_opened')
              AND NOT EXISTS (
                  SELECT 1 FROM remediation_resolution_events AS resolution
                  WHERE resolution.draft_key = latest.draft_key
              )
              AND edits.target_hash IS NULL
            LIMIT 1
            """,
            (target_repository, target_repository_id),
        ).fetchone()
        opened: set[str] = set()
        pending: set[str] = set()
        incompatible: set[str] = set()
        conflicting: set[str] = set()
        opened_drafts: dict[str, set[str]] = {}
        for row in rows:
            edit_hash = str(row["edit_hash"])
            target_hash = (
                str(row["target_hash"]) if row["target_hash"] is not None else None
            )
            if (
                row["target_repository"] != target_repository
                or int(row["target_repository_id"]) != target_repository_id
            ):
                if edit_hash in edit_to_target:
                    incompatible.add(edit_hash)
                continue
            if edit_hash in edit_to_target:
                if target_hash != edit_to_target[edit_hash]:
                    incompatible.add(edit_hash)
                    continue
                if row["remote_observation"] == "conflict" or (
                    row["remote_observation"] == "not_found"
                    and row["phase"] == "draft_opened"
                ):
                    incompatible.add(edit_hash)
                    continue
                if row["phase"] == "draft_opened":
                    opened.add(edit_hash)
                    opened_drafts.setdefault(edit_hash, set()).add(
                        str(row["draft_key"])
                    )
                else:
                    pending.add(edit_hash)
            if (
                target_hash in target_to_edit
                and edit_hash != target_to_edit[target_hash]
            ):
                conflicting.add(target_to_edit[target_hash])
        return RemediationEditCoverage(
            opened_edit_hashes=frozenset(opened),
            pending_edit_hashes=frozenset(pending),
            incompatible_edit_hashes=frozenset(incompatible),
            conflicting_edit_hashes=frozenset(conflicting),
            opened_draft_keys_by_edit_hash={
                edit_hash: tuple(sorted(draft_keys))
                for edit_hash, draft_keys in sorted(opened_drafts.items())
            },
            repository_identity_conflict=identity_conflict is not None,
            unmapped_active_conflict=unmapped_active is not None,
        )

    def pending_remediation_drafts_for_recovery(
        self,
        *,
        repository: str | None = None,
        repository_id: int | None = None,
        limit: int = 100,
    ) -> tuple[RemediationDraftRecord, ...]:
        """Return a bounded, least-recently-attempted pending workset.

        The immutable ID is authoritative when both repository filters are given.
        """

        if (
            isinstance(limit, bool)
            or not isinstance(limit, int)
            or not 1 <= limit <= 100
        ):
            raise ValueError("limit must be an integer from 1 through 100.")
        _validate_repository_id_filter(repository_id)
        if repository_id is not None:
            where = "WHERE target_repository_id = ?"
            parameters: tuple[object, ...] = (repository_id,)
        elif repository is not None:
            where = "WHERE target_repository = ?"
            parameters = (repository,)
        else:
            where = ""
            parameters = ()
        rows = self._connection.execute(
            f"""
            WITH latest AS (
                SELECT r.*,
                       ROW_NUMBER() OVER (
                           PARTITION BY draft_key
                           ORDER BY remediation_event_id DESC
                       ) AS guardian_row_number
                FROM remediation_draft_events AS r
                {where}
            )
            SELECT latest.*
            FROM latest
            LEFT JOIN remediation_recovery_cursors AS recovery
              ON recovery.draft_key = latest.draft_key
            WHERE latest.guardian_row_number = 1
              AND latest.phase IN ('validated', 'pushed')
              AND NOT EXISTS (
                  SELECT 1 FROM remediation_resolution_events AS resolution
                  WHERE resolution.draft_key = latest.draft_key
              )
            ORDER BY COALESCE(recovery.recovery_rank, 0),
                     latest.remediation_event_id
            LIMIT ?
            """,
            (*parameters, limit),
        ).fetchall()
        return tuple(self._remediation_from_row(row) for row in rows)

    def record_remediation_recovery_attempt(
        self,
        *,
        draft_key: str,
        occurred_at: datetime | None = None,
    ) -> None:
        """Advance one bounded durable rotation cursor before remote recovery."""

        if not isinstance(draft_key, str) or not _SHA256_RE.fullmatch(draft_key):
            raise ValueError("draft_key must be a SHA-256 digest.")
        with self._connection:
            latest = self._connection.execute(
                """
                SELECT phase FROM remediation_draft_events
                WHERE draft_key = ?
                ORDER BY remediation_event_id DESC
                LIMIT 1
                """,
                (draft_key,),
            ).fetchone()
            resolution = self._connection.execute(
                """
                SELECT 1 FROM remediation_resolution_events
                WHERE draft_key = ?
                """,
                (draft_key,),
            ).fetchone()
            if (
                resolution is not None
                or latest is None
                or latest["phase"]
                not in {
                    "validated",
                    "pushed",
                    "draft_opened",
                }
            ):
                raise ValueError("Only an active remediation draft can be attempted.")
            rank_row = self._connection.execute(
                """
                SELECT COALESCE(MAX(recovery_rank), 0) AS recovery_rank
                FROM remediation_recovery_cursors
                """
            ).fetchone()
            if rank_row is None:  # pragma: no cover - aggregate returns one row
                raise RuntimeError("Unable to advance remediation recovery cursor.")
            next_rank = int(rank_row["recovery_rank"]) + 1
            if next_rank > _SQLITE_MAX_INTEGER:
                raise RuntimeError("Remediation recovery cursor is exhausted.")
            self._connection.execute(
                """
                INSERT INTO remediation_recovery_cursors (
                    draft_key, recovery_rank, occurred_at
                ) VALUES (?, ?, ?)
                ON CONFLICT(draft_key) DO UPDATE SET
                    recovery_rank = excluded.recovery_rank,
                    occurred_at = excluded.occurred_at
                """,
                (
                    draft_key,
                    next_rank,
                    _serialize_datetime(occurred_at or _now()),
                ),
            )

    def remediation_draft_by_key(
        self,
        *,
        draft_key: str,
    ) -> RemediationDraftRecord | None:
        """Return the latest exact remediation ledger row, including resolved rows."""

        if not isinstance(draft_key, str) or not _SHA256_RE.fullmatch(draft_key):
            raise ValueError("draft_key must be a SHA-256 digest.")
        row = self._connection.execute(
            """
            SELECT * FROM remediation_draft_events
            WHERE draft_key = ?
            ORDER BY remediation_event_id DESC
            LIMIT 1
            """,
            (draft_key,),
        ).fetchone()
        return None if row is None else self._remediation_from_row(row)

    def remediation_resolution(self, *, draft_key: str) -> str | None:
        """Return an append-only terminal resolution for one remediation attempt."""

        if not isinstance(draft_key, str) or not _SHA256_RE.fullmatch(draft_key):
            raise ValueError("draft_key must be a SHA-256 digest.")
        row = self._connection.execute(
            """
            SELECT resolution FROM remediation_resolution_events
            WHERE draft_key = ?
            """,
            (draft_key,),
        ).fetchone()
        return None if row is None else str(row["resolution"])

    def record_remediation_resolution(
        self,
        *,
        draft_key: str,
        resolution: str,
        terminal_local_skip_acknowledged: bool | None = None,
        occurred_at: datetime | None = None,
    ) -> bool:
        """Record an acknowledged operator quarantine.

        Merged resolution is accepted only through an exact atomic remote
        observation so the lifecycle evidence and resolution cannot diverge.
        """

        if not isinstance(draft_key, str) or not _SHA256_RE.fullmatch(draft_key):
            raise ValueError("draft_key must be a SHA-256 digest.")
        if resolution == "merged":
            raise ValueError(
                "Merged resolution requires an exact atomic remote observation."
            )
        if resolution != "operator_quarantined":
            raise ValueError("Unsupported remediation resolution.")
        return self.record_remediation_quarantine(
            draft_key=draft_key,
            terminal_local_skip_acknowledged=terminal_local_skip_acknowledged,
            occurred_at=occurred_at,
        )

    def _record_remediation_resolution_in_transaction(
        self,
        *,
        draft_key: str,
        resolution: str,
        occurred_at: datetime,
    ) -> bool:
        if resolution not in {"merged", "operator_quarantined"}:
            raise ValueError("Unsupported remediation resolution.")
        existing = self._connection.execute(
            """
            SELECT resolution FROM remediation_resolution_events
            WHERE draft_key = ?
            """,
            (draft_key,),
        ).fetchone()
        if existing is not None:
            if existing["resolution"] != resolution:
                raise ValueError(
                    "Remediation attempt already has a different resolution."
                )
            return False
        latest = self._connection.execute(
            """
            SELECT phase, occurred_at FROM remediation_draft_events
            WHERE draft_key = ?
            ORDER BY remediation_event_id DESC
            LIMIT 1
            """,
            (draft_key,),
        ).fetchone()
        if latest is None or latest["phase"] not in {
            "validated",
            "pushed",
            "draft_opened",
        }:
            raise ValueError("Only an active remediation attempt can be resolved.")
        if resolution == "merged" and latest["phase"] != "draft_opened":
            raise ValueError("Only an opened remediation draft can be merged.")
        latest_at = _parse_datetime(latest["occurred_at"])
        if latest_at is None or occurred_at < latest_at:
            raise ValueError(
                "occurred_at must not precede the latest remediation event."
            )
        latest_remote = self._connection.execute(
            """
            SELECT occurred_at FROM remediation_remote_observation_events
            WHERE draft_key = ?
            ORDER BY observation_id DESC
            LIMIT 1
            """,
            (draft_key,),
        ).fetchone()
        latest_remote_at = (
            None
            if latest_remote is None
            else _parse_datetime(str(latest_remote["occurred_at"]))
        )
        if latest_remote is not None and (
            latest_remote_at is None or occurred_at < latest_remote_at
        ):
            raise ValueError(
                "occurred_at must not precede the latest remote observation."
            )
        self._connection.execute(
            """
            INSERT INTO remediation_resolution_events (
                draft_key, resolution, occurred_at
            ) VALUES (?, ?, ?)
            """,
            (draft_key, resolution, _serialize_datetime(occurred_at)),
        )
        return True

    def record_remediation_quarantine(
        self,
        *,
        draft_key: str,
        terminal_local_skip_acknowledged: bool | None,
        occurred_at: datetime | None = None,
    ) -> bool:
        """Atomically attest every source and terminally skip one exact attempt."""

        if not isinstance(draft_key, str) or not _SHA256_RE.fullmatch(draft_key):
            raise ValueError("draft_key must be a SHA-256 digest.")
        if terminal_local_skip_acknowledged is not True:
            raise ValueError(
                "terminal_local_skip_acknowledged must be explicitly true."
            )
        draft = self.remediation_draft_by_key(draft_key=draft_key)
        if draft is None or draft.phase not in {
            "validated",
            "pushed",
            "draft_opened",
        }:
            raise ValueError("Only an active remediation attempt can be quarantined.")
        occurred = occurred_at or _now()
        coverage_inputs = tuple(
            (
                source,
                self._event_revision_ids_for_source_drafts(
                    source=source,
                    draft_keys=(draft_key,),
                    require_opened=False,
                ),
            )
            for source in draft.source_pulls
        )
        with self._connection:
            for source, revision_ids in coverage_inputs:
                self._record_historical_pull_completion_in_transaction(
                    source=source,
                    event_revision_ids=revision_ids,
                    completed_at=occurred,
                )
                self._record_remediation_coverage_group_in_transaction(
                    completion_id=self._completion_id_for_source(source),
                    authority_digest=source.authority_digest,
                    reason=RemediationCoverageReason.OPERATOR_QUARANTINED,
                    draft_keys=(draft_key,),
                    required_edit_hashes=draft.edit_hashes,
                    occurred_at=occurred,
                )
            created = self._record_remediation_resolution_in_transaction(
                draft_key=draft_key,
                resolution="operator_quarantined",
                occurred_at=occurred,
            )
        return created

    def remediation_draft_for_pull(
        self,
        *,
        repository: str,
        repository_id: int,
        pr_number: int,
    ) -> RemediationDraftRecord | None:
        """Return the single Guardian remediation owning an exact pull request."""

        self._validate_historical_pull_identity(
            repository=repository,
            repository_id=repository_id,
            pull_id=1,
            pr_number=pr_number,
            pull_revision_digest="0" * 64,
            policy_digest="0" * 64,
            authority_scope=HistoricalCheckScope.REMEDIATION,
        )
        _validate_repository_id_filter(repository_id)
        rows = self._connection.execute(
            """
            SELECT * FROM remediation_draft_events
            WHERE target_repository_id = ?
              AND phase = 'draft_opened' AND draft_number = ?
            ORDER BY remediation_event_id
            LIMIT 2
            """,
            (repository_id, pr_number),
        ).fetchall()
        if len(rows) > 1:
            raise RuntimeError(
                "Multiple remediation drafts claim the same exact pull request."
            )
        return None if not rows else self._remediation_from_row(rows[0])

    def _remediation_successor_entry_from_row(
        self,
        row: sqlite3.Row,
        *,
        key_column: str,
        malformed_message: str,
    ) -> _RemediationSuccessorEntry:
        try:
            source_pulls_json = row["source_pulls_json"]
            edit_hashes_json = row["edit_hashes_json"]
            changed_paths_json = row["changed_paths_json"]
            if (
                not isinstance(source_pulls_json, str)
                or len(source_pulls_json.encode("utf-8"))
                > _MAX_REMEDIATION_SOURCE_JSON_BYTES
                or not isinstance(edit_hashes_json, str)
                or len(edit_hashes_json.encode("utf-8"))
                > _MAX_REMEDIATION_SOURCE_JSON_BYTES
                or not isinstance(changed_paths_json, str)
                or len(changed_paths_json.encode("utf-8"))
                > _MAX_REMEDIATION_PATHS_JSON_BYTES
            ):
                raise ValueError
            source_pulls_raw = loads_bounded_json(source_pulls_json)
            edit_hashes_raw = loads_bounded_json(edit_hashes_json)
            changed_paths_raw = loads_bounded_json(changed_paths_json)
            occurred_at = _parse_datetime(str(row["occurred_at"]))
            if (
                not isinstance(source_pulls_raw, list)
                or not isinstance(edit_hashes_raw, list)
                or not isinstance(changed_paths_raw, list)
                or len(source_pulls_raw) > _MAX_REMEDIATION_SOURCE_PULLS
                or len(edit_hashes_raw) > _MAX_REMEDIATION_EDIT_HASHES
                or occurred_at is None
            ):
                raise ValueError
            source_pulls = tuple(
                _historical_pull_reference_from_json(_canonical_attestation_json(item))
                for item in source_pulls_raw
                if isinstance(item, Mapping)
            )
            edit_hashes = tuple(edit_hashes_raw)
            changed_paths, canonical_paths_json = _validated_remediation_changed_paths(
                changed_paths_raw
            )
            entry_key = str(row[key_column])
            draft_key = str(row["draft_key"])
            publication_key = str(row["publication_key"])
            run_id = str(row["run_id"])
            parent_candidate_sha = str(row["parent_candidate_sha"])
            successor_candidate_sha = str(row["successor_candidate_sha"])
            actor_id = int(row["actor_id"])
            actor_type = str(row["actor_type"])
            publication_actor_id = int(row["publication_actor_id"])
            publication_actor_type = str(row["publication_actor_type"])
            if (
                len(source_pulls) != len(source_pulls_raw)
                or not source_pulls
                or tuple(
                    sorted(
                        source_pulls,
                        key=lambda item: (
                            item.repository,
                            item.repository_id,
                            item.pull_id,
                            item.pr_number,
                            item.pull_revision_digest,
                            item.policy_digest,
                        ),
                    )
                )
                != source_pulls
                or not edit_hashes
                or len(edit_hashes) > _MAX_REMEDIATION_EDIT_HASHES
                or tuple(sorted(edit_hashes)) != edit_hashes
                or len(set(edit_hashes)) != len(edit_hashes)
                or any(
                    not isinstance(value, str) or not _SHA256_RE.fullmatch(value)
                    for value in edit_hashes
                )
                or canonical_paths_json != changed_paths_json
                or not _SHA256_RE.fullmatch(entry_key)
                or not _SHA256_RE.fullmatch(draft_key)
                or not _SHA256_RE.fullmatch(publication_key)
                or not re.fullmatch(
                    r"(?:[0-9a-f]{40}|[0-9a-f]{64})",
                    parent_candidate_sha,
                )
                or not re.fullmatch(
                    r"(?:[0-9a-f]{40}|[0-9a-f]{64})",
                    successor_candidate_sha,
                )
                or parent_candidate_sha == successor_candidate_sha
                or actor_id <= 0
                or not actor_type
                or len(actor_type.encode("utf-8")) > 64
                or any(character in actor_type for character in "\r\n\x00")
                or publication_actor_id <= 0
                or publication_actor_type not in {"User", "Bot"}
            ):
                raise ValueError
            payload = {
                "actor_id": actor_id,
                "actor_type": actor_type,
                "publication_actor_id": publication_actor_id,
                "publication_actor_type": publication_actor_type,
                "draft_key": draft_key,
                "edit_hashes": list(edit_hashes),
                "changed_paths": list(changed_paths),
                "parent_candidate_sha": parent_candidate_sha,
                "publication_key": publication_key,
                "run_id": run_id,
                "source_pulls": source_pulls_raw,
                "successor_candidate_sha": successor_candidate_sha,
            }
            if (
                hashlib.sha256(
                    _canonical_attestation_json(payload).encode("ascii")
                ).hexdigest()
                != entry_key
            ):
                raise ValueError
        except (KeyError, TypeError, ValueError, json.JSONDecodeError):
            raise RuntimeError(malformed_message) from None
        return _RemediationSuccessorEntry(
            key=entry_key,
            draft_key=draft_key,
            publication_key=publication_key,
            run_id=run_id,
            parent_candidate_sha=parent_candidate_sha,
            successor_candidate_sha=successor_candidate_sha,
            source_pulls=source_pulls,
            edit_hashes=edit_hashes,
            changed_paths=changed_paths,
            actor_id=actor_id,
            actor_type=actor_type,
            publication_actor_id=publication_actor_id,
            publication_actor_type=publication_actor_type,
            occurred_at=occurred_at,
        )

    def _remediation_successor_from_row(
        self,
        row: sqlite3.Row,
    ) -> RemediationSuccessorPublication:
        entry = self._remediation_successor_entry_from_row(
            row,
            key_column="lineage_key",
            malformed_message=(
                "Remediation successor publication ledger is malformed."
            ),
        )
        return RemediationSuccessorPublication(
            lineage_key=entry.key,
            draft_key=entry.draft_key,
            publication_key=entry.publication_key,
            run_id=entry.run_id,
            parent_candidate_sha=entry.parent_candidate_sha,
            successor_candidate_sha=entry.successor_candidate_sha,
            source_pulls=entry.source_pulls,
            edit_hashes=entry.edit_hashes,
            changed_paths=entry.changed_paths,
            actor_id=entry.actor_id,
            actor_type=entry.actor_type,
            publication_actor_id=entry.publication_actor_id,
            publication_actor_type=entry.publication_actor_type,
            occurred_at=entry.occurred_at,
        )

    def _remediation_successor_intent_from_row(
        self,
        row: sqlite3.Row,
    ) -> RemediationSuccessorIntent:
        entry = self._remediation_successor_entry_from_row(
            row,
            key_column="intent_key",
            malformed_message="Remediation successor intent ledger is malformed.",
        )
        return RemediationSuccessorIntent(
            intent_key=entry.key,
            draft_key=entry.draft_key,
            publication_key=entry.publication_key,
            run_id=entry.run_id,
            parent_candidate_sha=entry.parent_candidate_sha,
            successor_candidate_sha=entry.successor_candidate_sha,
            source_pulls=entry.source_pulls,
            edit_hashes=entry.edit_hashes,
            changed_paths=entry.changed_paths,
            actor_id=entry.actor_id,
            actor_type=entry.actor_type,
            publication_actor_id=entry.publication_actor_id,
            publication_actor_type=entry.publication_actor_type,
            occurred_at=entry.occurred_at,
        )

    def _validated_remediation_successor_inputs(
        self,
        *,
        draft_key: str,
        source_pulls: Sequence[HistoricalPullReference],
        edit_hashes: Sequence[str],
        changed_paths: Sequence[str],
        actor_id: int,
        actor_type: str,
        publication_actor_id: int,
        publication_actor_type: str,
    ) -> tuple[
        RemediationDraftRecord,
        tuple[HistoricalPullReference, ...],
        tuple[str, ...],
        tuple[str, ...],
    ]:
        draft = self.remediation_draft_by_key(draft_key=draft_key)
        if draft is None or draft.phase != "draft_opened":
            raise ValueError("Successor publication requires an opened remediation.")
        if self.remediation_resolution(draft_key=draft_key) is not None:
            raise ValueError("Resolved remediation cannot receive a successor.")
        raw_sources = _bounded_sequence(
            source_pulls,
            limit=_MAX_REMEDIATION_SOURCE_PULLS,
            label="source_pulls",
        )
        if not raw_sources or any(
            not isinstance(source, HistoricalPullReference) for source in raw_sources
        ):
            raise ValueError(
                "Successor source set must contain exact historical references."
            )
        supplied_sources = tuple(
            sorted(
                raw_sources,
                key=lambda item: (
                    item.repository,
                    item.repository_id,
                    item.pull_id,
                    item.pr_number,
                    item.pull_revision_digest,
                    item.policy_digest,
                ),
            )
        )
        if supplied_sources != draft.source_pulls:
            raise ValueError("Successor source set must match the remediation ledger.")
        raw_edits = _bounded_sequence(
            edit_hashes,
            limit=_MAX_REMEDIATION_EDIT_HASHES,
            label="edit_hashes",
        )
        if (
            not raw_edits
            or len(raw_edits) > _MAX_REMEDIATION_EDIT_HASHES
            or any(
                not isinstance(value, str) or not _SHA256_RE.fullmatch(value)
                for value in raw_edits
            )
        ):
            raise ValueError("edit_hashes must contain bounded unique SHA-256 values.")
        normalized_edits = tuple(sorted(raw_edits))
        if len(set(normalized_edits)) != len(normalized_edits):
            raise ValueError("edit_hashes must contain bounded unique SHA-256 values.")
        normalized_paths, _changed_paths_json = _validated_remediation_changed_paths(
            changed_paths
        )
        if draft.changed_paths is None or not set(normalized_paths).issubset(
            draft.changed_paths
        ):
            raise ValueError(
                "Successor paths must be a subset of the opened remediation paths."
            )
        if isinstance(actor_id, bool) or not isinstance(actor_id, int) or actor_id <= 0:
            raise ValueError("actor_id must be a positive integer.")
        if (
            not isinstance(actor_type, str)
            or not actor_type
            or len(actor_type.encode("utf-8")) > 64
            or any(character in actor_type for character in "\r\n\x00")
        ):
            raise ValueError("actor_type must be a safe non-empty value.")
        if (
            isinstance(publication_actor_id, bool)
            or not isinstance(publication_actor_id, int)
            or publication_actor_id <= 0
        ):
            raise ValueError("publication_actor_id must be a positive integer.")
        if publication_actor_type not in {"User", "Bot"}:
            raise ValueError("publication_actor_type must be User or Bot.")
        return draft, supplied_sources, normalized_edits, normalized_paths

    @staticmethod
    def _remediation_successor_payload(
        *,
        draft_key: str,
        publication_key: str,
        run_id: str,
        parent_candidate_sha: str,
        successor_candidate_sha: str,
        source_pulls_json: str,
        edit_hashes: Sequence[str],
        changed_paths: Sequence[str],
        actor_id: int,
        actor_type: str,
        publication_actor_id: int,
        publication_actor_type: str,
    ) -> dict[str, object]:
        return {
            "actor_id": actor_id,
            "actor_type": actor_type,
            "publication_actor_id": publication_actor_id,
            "publication_actor_type": publication_actor_type,
            "draft_key": draft_key,
            "edit_hashes": list(edit_hashes),
            "changed_paths": list(changed_paths),
            "parent_candidate_sha": parent_candidate_sha,
            "publication_key": publication_key,
            "run_id": run_id,
            "source_pulls": json.loads(source_pulls_json),
            "successor_candidate_sha": successor_candidate_sha,
        }

    def _validate_successor_publication_evidence(
        self,
        *,
        draft: RemediationDraftRecord,
        publication: PublicationRecord,
        actor_id: int,
        actor_type: str,
    ) -> None:
        authority = publication.open_source
        revisions = tuple(
            self.get_event_revision(revision_id)
            for revision_id in publication.event_revision_ids
        )
        if (
            authority is None
            or authority.feedback_digest is None
            or authority.repository != draft.target_repository
            or authority.repository_id != draft.target_repository_id
            or authority.pull_id != draft.draft_pull_id
            or authority.pr_number != draft.draft_number
            or authority.head_sha != publication.original_head_sha
            or authority.base_sha != publication.base_sha
            or any(
                revision is None
                or revision.repository != draft.target_repository
                or revision.pr_number != draft.draft_number
                or revision.head_sha != publication.original_head_sha
                or revision.base_sha != publication.base_sha
                for revision in revisions
            )
            or not any(
                revision is not None
                and revision.author_id == actor_id
                and revision.author_type == actor_type
                for revision in revisions
            )
        ):
            raise ValueError("Successor publication lacks exact open-pull evidence.")

    def remediation_successor_intent(
        self,
        *,
        publication_key: str,
    ) -> RemediationSuccessorIntent | None:
        """Return durable successor metadata used by crash recovery."""

        if not isinstance(publication_key, str) or not _SHA256_RE.fullmatch(
            publication_key
        ):
            raise ValueError("publication_key must be a SHA-256 digest.")
        row = self._connection.execute(
            """
            SELECT * FROM remediation_successor_intents
            WHERE publication_key = ?
            """,
            (publication_key,),
        ).fetchone()
        if row is None:
            return None
        intent = self._remediation_successor_intent_from_row(row)
        draft = self.remediation_draft_by_key(draft_key=intent.draft_key)
        publication_row = self._connection.execute(
            """
            SELECT * FROM publication_events
            WHERE publication_key = ? AND phase = 'prepared'
            """,
            (publication_key,),
        ).fetchone()
        publication = (
            None
            if publication_row is None
            else self._publication_from_row(publication_row)
        )
        if (
            draft is None
            or publication is None
            or intent.source_pulls != draft.source_pulls
            or publication.run_id != intent.run_id
            or publication.repository != draft.target_repository
            or publication.pr_number != draft.draft_number
            or publication.original_head_sha != intent.parent_candidate_sha
            or publication.commit_sha != intent.successor_candidate_sha
            or publication.publication_actor_id != intent.publication_actor_id
            or publication.publication_actor_type != intent.publication_actor_type
            or publication.occurred_at > intent.occurred_at
        ):
            raise RuntimeError("Remediation successor intent ledger is malformed.")
        try:
            self._validate_successor_publication_evidence(
                draft=draft,
                publication=publication,
                actor_id=intent.actor_id,
                actor_type=intent.actor_type,
            )
        except ValueError:
            raise RuntimeError(
                "Remediation successor intent ledger is malformed."
            ) from None
        return intent

    def remediation_successor_publications(
        self,
        *,
        draft_key: str,
    ) -> tuple[RemediationSuccessorPublication, ...]:
        """Return and validate the signed, linear successor chain for a draft."""

        draft = self.remediation_draft_by_key(draft_key=draft_key)
        if draft is None:
            raise ValueError("Unknown remediation draft key.")
        rows = self._connection.execute(
            """
            SELECT * FROM remediation_successor_publications
            WHERE draft_key = ?
            ORDER BY successor_id
            LIMIT ?
            """,
            (draft_key, _MAX_REMEDIATION_SUCCESSORS + 1),
        ).fetchall()
        if len(rows) > _MAX_REMEDIATION_SUCCESSORS:
            raise RuntimeError(
                "Remediation successor publication count reached its safety bound."
            )
        successors = tuple(self._remediation_successor_from_row(row) for row in rows)
        expected_parent = draft.candidate_sha
        for successor in successors:
            intent = self.remediation_successor_intent(
                publication_key=successor.publication_key
            )
            publication_row = self._connection.execute(
                """
                SELECT * FROM publication_events
                WHERE publication_key = ?
                  AND phase IN ('published', 'replied')
                ORDER BY publication_event_id
                LIMIT 1
                """,
                (successor.publication_key,),
            ).fetchone()
            publication = (
                None
                if publication_row is None
                else self._publication_from_row(publication_row)
            )
            if (
                successor.parent_candidate_sha != expected_parent
                or successor.source_pulls != draft.source_pulls
                or intent is None
                or intent.intent_key != successor.lineage_key
                or intent.draft_key != successor.draft_key
                or intent.run_id != successor.run_id
                or intent.parent_candidate_sha != successor.parent_candidate_sha
                or intent.successor_candidate_sha != successor.successor_candidate_sha
                or intent.source_pulls != successor.source_pulls
                or intent.edit_hashes != successor.edit_hashes
                or intent.changed_paths != successor.changed_paths
                or intent.actor_id != successor.actor_id
                or intent.actor_type != successor.actor_type
                or intent.publication_actor_id != successor.publication_actor_id
                or intent.publication_actor_type != successor.publication_actor_type
                or intent.occurred_at > successor.occurred_at
                or publication is None
                or publication.phase not in {"published", "replied"}
                or publication.run_id != successor.run_id
                or publication.repository != draft.target_repository
                or publication.pr_number != draft.draft_number
                or publication.original_head_sha != successor.parent_candidate_sha
                or publication.commit_sha != successor.successor_candidate_sha
                or publication.publication_actor_id != successor.publication_actor_id
                or publication.publication_actor_type
                != successor.publication_actor_type
                or publication.occurred_at > successor.occurred_at
            ):
                raise RuntimeError(
                    "Remediation successor publication ledger is malformed."
                )
            try:
                self._validate_successor_publication_evidence(
                    draft=draft,
                    publication=publication,
                    actor_id=successor.actor_id,
                    actor_type=successor.actor_type,
                )
            except ValueError:
                raise RuntimeError(
                    "Remediation successor publication ledger is malformed."
                ) from None
            expected_parent = successor.successor_candidate_sha
        return successors

    def remediation_candidate_tip(self, draft_key: str) -> str:
        """Return the only head authorized by a remediation publication chain."""

        draft = self.remediation_draft_by_key(draft_key=draft_key)
        if draft is None:
            raise ValueError("Unknown remediation draft key.")
        successors = self.remediation_successor_publications(draft_key=draft_key)
        return (
            draft.candidate_sha
            if not successors
            else successors[-1].successor_candidate_sha
        )

    def _record_remediation_successor_intent_in_transaction(
        self,
        *,
        draft: RemediationDraftRecord,
        publication_key: str,
        source_pulls: tuple[HistoricalPullReference, ...],
        edit_hashes: tuple[str, ...],
        changed_paths: tuple[str, ...],
        actor_id: int,
        actor_type: str,
        publication_actor_id: int,
        publication_actor_type: str,
        occurred_at: datetime,
    ) -> RemediationSuccessorIntent:
        publication_row = self._connection.execute(
            """
            SELECT * FROM publication_events
            WHERE publication_key = ? AND phase = 'prepared'
            """,
            (publication_key,),
        ).fetchone()
        publication = (
            None
            if publication_row is None
            else self._publication_from_row(publication_row)
        )
        if publication is None:
            raise ValueError(
                "Successor intent requires the exact prepared publication."
            )
        sources_json = _prevention_source_pulls_json(source_pulls)
        payload = self._remediation_successor_payload(
            draft_key=draft.draft_key,
            publication_key=publication_key,
            run_id=publication.run_id,
            parent_candidate_sha=publication.original_head_sha,
            successor_candidate_sha=publication.commit_sha,
            source_pulls_json=sources_json,
            edit_hashes=edit_hashes,
            changed_paths=changed_paths,
            actor_id=actor_id,
            actor_type=actor_type,
            publication_actor_id=publication_actor_id,
            publication_actor_type=publication_actor_type,
        )
        intent_key = hashlib.sha256(
            _canonical_attestation_json(payload).encode("ascii")
        ).hexdigest()
        existing_row = self._connection.execute(
            """
            SELECT * FROM remediation_successor_intents
            WHERE publication_key = ?
            """,
            (publication_key,),
        ).fetchone()
        if existing_row is not None:
            existing = self._remediation_successor_intent_from_row(existing_row)
            if (
                existing.intent_key != intent_key
                or existing.draft_key != draft.draft_key
                or existing.source_pulls != source_pulls
                or existing.edit_hashes != edit_hashes
                or existing.changed_paths != changed_paths
                or existing.actor_id != actor_id
                or existing.actor_type != actor_type
                or existing.publication_actor_id != publication_actor_id
                or existing.publication_actor_type != publication_actor_type
            ):
                raise ValueError(
                    "Successor intent metadata does not match its first event."
                )
            return existing
        parent = self.remediation_candidate_tip(draft.draft_key)
        if (
            publication.repository != draft.target_repository
            or publication.pr_number != draft.draft_number
            or publication.original_head_sha != parent
            or publication.commit_sha == parent
            or publication.publication_actor_id != publication_actor_id
            or publication.publication_actor_type != publication_actor_type
            or publication.occurred_at > occurred_at
        ):
            raise ValueError(
                "Publication does not prove the exact next remediation head."
            )
        self._validate_successor_publication_evidence(
            draft=draft,
            publication=publication,
            actor_id=actor_id,
            actor_type=actor_type,
        )
        self._connection.execute(
            """
            INSERT INTO remediation_successor_intents (
                intent_key, draft_key, publication_key, run_id,
                parent_candidate_sha, successor_candidate_sha,
                source_pulls_json, edit_hashes_json, changed_paths_json,
                actor_id, actor_type, publication_actor_id,
                publication_actor_type,
                occurred_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                intent_key,
                draft.draft_key,
                publication_key,
                publication.run_id,
                parent,
                publication.commit_sha,
                sources_json,
                _canonical_attestation_json(list(edit_hashes)),
                _canonical_attestation_json(list(changed_paths)),
                actor_id,
                actor_type,
                publication_actor_id,
                publication_actor_type,
                _serialize_datetime(occurred_at),
            ),
        )
        intent = self.remediation_successor_intent(publication_key=publication_key)
        if intent is None:  # pragma: no cover - the insert above is authoritative
            raise RuntimeError("Failed to persist remediation successor intent.")
        return intent

    def _record_remediation_successor_publication_in_transaction(
        self,
        *,
        draft: RemediationDraftRecord,
        publication_key: str,
        source_pulls: tuple[HistoricalPullReference, ...],
        edit_hashes: tuple[str, ...],
        changed_paths: tuple[str, ...],
        actor_id: int,
        actor_type: str,
        publication_actor_id: int,
        publication_actor_type: str,
        occurred_at: datetime,
    ) -> RemediationSuccessorPublication:
        intent = self.remediation_successor_intent(publication_key=publication_key)
        if intent is None:
            raise ValueError(
                "Successor publication requires a durable prepared intent."
            )
        if (
            intent.draft_key != draft.draft_key
            or intent.source_pulls != source_pulls
            or intent.edit_hashes != edit_hashes
            or intent.changed_paths != changed_paths
            or intent.actor_id != actor_id
            or intent.actor_type != actor_type
            or intent.publication_actor_id != publication_actor_id
            or intent.publication_actor_type != publication_actor_type
        ):
            raise ValueError(
                "Successor publication metadata does not match its prepared intent."
            )
        existing_row = self._connection.execute(
            """
            SELECT * FROM remediation_successor_publications
            WHERE publication_key = ?
            """,
            (publication_key,),
        ).fetchone()
        if existing_row is not None:
            existing = self._remediation_successor_from_row(existing_row)
            if existing.lineage_key != intent.intent_key:
                raise ValueError(
                    "Successor publication metadata does not match its first event."
                )
            self.remediation_successor_publications(draft_key=draft.draft_key)
            return existing
        publication_row = self._connection.execute(
            """
            SELECT * FROM publication_events
            WHERE publication_key = ?
              AND phase IN ('published', 'replied')
            ORDER BY publication_event_id
            LIMIT 1
            """,
            (publication_key,),
        ).fetchone()
        publication = (
            None
            if publication_row is None
            else self._publication_from_row(publication_row)
        )
        parent = self.remediation_candidate_tip(draft.draft_key)
        if (
            publication is None
            or publication.repository != draft.target_repository
            or publication.pr_number != draft.draft_number
            or publication.original_head_sha != parent
            or publication.commit_sha == parent
            or publication.original_head_sha != intent.parent_candidate_sha
            or publication.commit_sha != intent.successor_candidate_sha
            or publication.publication_actor_id != publication_actor_id
            or publication.publication_actor_type != publication_actor_type
            or publication.occurred_at > occurred_at
            or intent.occurred_at > occurred_at
        ):
            raise ValueError(
                "Publication does not prove the exact next remediation head."
            )
        self._validate_successor_publication_evidence(
            draft=draft,
            publication=publication,
            actor_id=actor_id,
            actor_type=actor_type,
        )
        sources_json = _prevention_source_pulls_json(source_pulls)
        payload = self._remediation_successor_payload(
            draft_key=draft.draft_key,
            publication_key=publication_key,
            run_id=publication.run_id,
            parent_candidate_sha=parent,
            successor_candidate_sha=publication.commit_sha,
            source_pulls_json=sources_json,
            edit_hashes=edit_hashes,
            changed_paths=changed_paths,
            actor_id=actor_id,
            actor_type=actor_type,
            publication_actor_id=publication_actor_id,
            publication_actor_type=publication_actor_type,
        )
        lineage_key = hashlib.sha256(
            _canonical_attestation_json(payload).encode("ascii")
        ).hexdigest()
        if lineage_key != intent.intent_key:
            raise ValueError(
                "Published successor does not match its durable prepared intent."
            )
        self._connection.execute(
            """
            INSERT INTO remediation_successor_publications (
                lineage_key, draft_key, publication_key, run_id,
                parent_candidate_sha, successor_candidate_sha,
                source_pulls_json, edit_hashes_json, changed_paths_json,
                actor_id, actor_type, publication_actor_id,
                publication_actor_type,
                occurred_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                lineage_key,
                draft.draft_key,
                publication_key,
                publication.run_id,
                parent,
                publication.commit_sha,
                sources_json,
                _canonical_attestation_json(list(edit_hashes)),
                _canonical_attestation_json(list(changed_paths)),
                actor_id,
                actor_type,
                publication_actor_id,
                publication_actor_type,
                _serialize_datetime(occurred_at),
            ),
        )
        return self.remediation_successor_publications(draft_key=draft.draft_key)[-1]

    def record_remediation_successor_publication_event(
        self,
        *,
        run_id: str,
        repository: str,
        pr_number: int,
        original_head_sha: str,
        base_sha: str,
        commit_sha: str,
        event_revision_ids: Sequence[int],
        open_source: OpenPullAuthorityReference | None,
        phase: str,
        draft_key: str,
        source_pulls: Sequence[HistoricalPullReference],
        edit_hashes: Sequence[str],
        changed_paths: Sequence[str],
        actor_id: int,
        actor_type: str,
        publication_actor_id: int,
        publication_actor_type: str,
        completion_actions: Sequence[tuple[int, str, Mapping[str, Any]]] | None = None,
        occurred_at: datetime | None = None,
    ) -> RemediationSuccessorIntent | RemediationSuccessorPublication:
        """Atomically prepare or publish one exact remediation successor."""

        if phase not in {"prepared", "published"}:
            raise ValueError(
                "Remediation successor publication phase must be prepared or published."
            )
        if (phase == "prepared") != (completion_actions is not None):
            raise ValueError(
                "Prepared remediation successors require one completion action plan."
            )
        draft, normalized_sources, normalized_edits, normalized_paths = (
            self._validated_remediation_successor_inputs(
                draft_key=draft_key,
                source_pulls=source_pulls,
                edit_hashes=edit_hashes,
                changed_paths=changed_paths,
                actor_id=actor_id,
                actor_type=actor_type,
                publication_actor_id=publication_actor_id,
                publication_actor_type=publication_actor_type,
            )
        )
        occurred = occurred_at or _now()
        with self._connection:
            publication_key = self._record_publication_event_in_transaction(
                run_id=run_id,
                repository=repository,
                pr_number=pr_number,
                original_head_sha=original_head_sha,
                base_sha=base_sha,
                commit_sha=commit_sha,
                publication_actor_id=publication_actor_id,
                publication_actor_type=publication_actor_type,
                event_revision_ids=event_revision_ids,
                phase=phase,
                open_source=open_source,
                occurred_at=occurred,
            )
            if phase == "prepared":
                assert completion_actions is not None
                self._record_publication_completion_plan_in_transaction(
                    publication_key=publication_key,
                    completion_actions=completion_actions,
                    occurred_at=occurred,
                )
                return self._record_remediation_successor_intent_in_transaction(
                    draft=draft,
                    publication_key=publication_key,
                    source_pulls=normalized_sources,
                    edit_hashes=normalized_edits,
                    changed_paths=normalized_paths,
                    actor_id=actor_id,
                    actor_type=actor_type,
                    publication_actor_id=publication_actor_id,
                    publication_actor_type=publication_actor_type,
                    occurred_at=occurred,
                )
            return self._record_remediation_successor_publication_in_transaction(
                draft=draft,
                publication_key=publication_key,
                source_pulls=normalized_sources,
                edit_hashes=normalized_edits,
                changed_paths=normalized_paths,
                actor_id=actor_id,
                actor_type=actor_type,
                publication_actor_id=publication_actor_id,
                publication_actor_type=publication_actor_type,
                occurred_at=occurred,
            )

    def record_remediation_successor_publication(
        self,
        *,
        draft_key: str,
        publication_key: str,
        source_pulls: Sequence[HistoricalPullReference],
        edit_hashes: Sequence[str],
        changed_paths: Sequence[str],
        actor_id: int,
        actor_type: str,
        publication_actor_id: int,
        publication_actor_type: str,
        occurred_at: datetime | None = None,
    ) -> RemediationSuccessorPublication:
        """Finalize a published successor that already has a durable intent."""

        if not isinstance(publication_key, str) or not _SHA256_RE.fullmatch(
            publication_key
        ):
            raise ValueError("publication_key must be a SHA-256 digest.")
        draft, normalized_sources, normalized_edits, normalized_paths = (
            self._validated_remediation_successor_inputs(
                draft_key=draft_key,
                source_pulls=source_pulls,
                edit_hashes=edit_hashes,
                changed_paths=changed_paths,
                actor_id=actor_id,
                actor_type=actor_type,
                publication_actor_id=publication_actor_id,
                publication_actor_type=publication_actor_type,
            )
        )
        with self._connection:
            return self._record_remediation_successor_publication_in_transaction(
                draft=draft,
                publication_key=publication_key,
                source_pulls=normalized_sources,
                edit_hashes=normalized_edits,
                changed_paths=normalized_paths,
                actor_id=actor_id,
                actor_type=actor_type,
                publication_actor_id=publication_actor_id,
                publication_actor_type=publication_actor_type,
                occurred_at=occurred_at or _now(),
            )

    def _bounded_remediation_coverages_linked_to_draft(
        self,
        draft_key: str,
    ) -> tuple[RemediationSourceCoverageGroup, ...]:
        """Load every bounded source-coverage group linked to one draft."""

        rows = self._connection.execute(
            """
            SELECT DISTINCT coverage.*, completion.repository,
                   completion.repository_id, completion.pull_id,
                   completion.pr_number, completion.pull_revision_digest,
                   completion.policy_digest, completion.head_sha,
                   completion.base_sha,
                   coverage.occurred_at AS coverage_occurred_at,
                   completion.completed_at AS completion_completed_at
            FROM remediation_source_coverage_members AS member
            JOIN remediation_source_coverage_groups AS coverage
              ON coverage.coverage_group_id = member.coverage_group_id
            JOIN historical_pull_completions AS completion
              ON completion.completion_id = coverage.completion_id
            WHERE member.draft_key = ?
            ORDER BY coverage.coverage_group_id
            LIMIT ?
            """,
            (draft_key, _MAX_REMEDIATION_MERGE_REVALIDATIONS + 1),
        ).fetchall()
        if len(rows) > _MAX_REMEDIATION_MERGE_REVALIDATIONS:
            raise RuntimeError(
                "Remediation draft source coverage reached its safety bound."
            )
        return tuple(self._coverage_group_from_row(row) for row in rows)

    def _remediation_completion_revision_ids(
        self,
        source: HistoricalPullReference,
    ) -> tuple[int, ...]:
        row = self._connection.execute(
            f"""
            SELECT pr_number, head_sha, base_sha,
                   CASE
                       WHEN typeof(event_revision_ids_json) = 'text'
                        AND length(CAST(event_revision_ids_json AS BLOB)) <=
                            {_MAX_REMEDIATION_SOURCE_EVENT_REVISIONS_JSON_BYTES}
                       THEN event_revision_ids_json
                   END AS event_revision_ids_json
            FROM historical_pull_completions
            WHERE repository = ? AND repository_id = ? AND pull_id = ?
              AND pr_number = ? AND pull_revision_digest = ?
              AND policy_digest = ? AND authority_scope = 'remediation'
            """,
            (
                source.repository,
                source.repository_id,
                source.pull_id,
                source.pr_number,
                source.pull_revision_digest,
                source.policy_digest,
            ),
        ).fetchone()
        if row is None or (row["head_sha"], row["base_sha"]) != (
            source.head_sha,
            source.base_sha,
        ):
            raise RuntimeError("Merged remediation source completion disappeared.")
        revision_ids = _validated_revision_ids_json(
            row["event_revision_ids_json"],
            label="Merged remediation source completion",
        )
        if (
            not revision_ids
            or len(revision_ids) > _MAX_REMEDIATION_SOURCE_EVENT_REVISIONS
        ):
            raise RuntimeError(
                "Merged remediation source completion exceeds its evidence bound."
            )
        self.validate_historical_remediation_evidence(
            source_pulls=(source,),
            event_revision_ids=revision_ids,
        )
        return revision_ids

    @staticmethod
    def _merge_revalidation_key(
        *,
        draft_key: str,
        source: HistoricalPullReference,
    ) -> str:
        return hashlib.sha256(
            _canonical_attestation_json(
                {
                    "draft_key": draft_key,
                    "source": json.loads(_historical_pull_reference_json(source)),
                }
            ).encode("ascii")
        ).hexdigest()

    def _merged_revalidation_from_row(
        self,
        row: sqlite3.Row,
    ) -> MergedRemediationRevalidation:
        try:
            revalidation_key = str(row["revalidation_key"])
            draft_key = str(row["draft_key"])
            source = _historical_pull_reference_from_json(row["source_json"])
            revision_ids_json = row["event_revision_ids_json"]
            if (
                not isinstance(revision_ids_json, str)
                or len(revision_ids_json.encode("utf-8"))
                > _MAX_REMEDIATION_SOURCE_EVENT_REVISIONS_JSON_BYTES
            ):
                raise ValueError
            raw_revision_ids = loads_bounded_json(revision_ids_json)
            phase = str(row["phase"])
            occurred_at = _parse_datetime(str(row["occurred_at"]))
            if (
                not _SHA256_RE.fullmatch(revalidation_key)
                or not _SHA256_RE.fullmatch(draft_key)
                or not isinstance(raw_revision_ids, list)
                or not raw_revision_ids
                or len(raw_revision_ids) > _MAX_REMEDIATION_SOURCE_EVENT_REVISIONS
                or tuple(sorted(raw_revision_ids)) != tuple(raw_revision_ids)
                or len(set(raw_revision_ids)) != len(raw_revision_ids)
                or any(
                    isinstance(value, bool) or not isinstance(value, int) or value <= 0
                    for value in raw_revision_ids
                )
                or phase
                not in {"pending", "attempted", "resolved", "no_longer_applicable"}
                or occurred_at is None
                or self._merge_revalidation_key(
                    draft_key=draft_key,
                    source=source,
                )
                != revalidation_key
                or _merged_revalidation_revision_ids_json(raw_revision_ids)
                != revision_ids_json
            ):
                raise ValueError
            draft = self.remediation_draft_by_key(draft_key=draft_key)
            if draft is None:
                raise ValueError
            if source in draft.source_pulls:
                exact_ids = self._event_revision_ids_for_source_drafts(
                    source=source,
                    draft_keys=(draft_key,),
                    require_opened=False,
                )
            else:
                linked_coverages = self._bounded_remediation_coverages_linked_to_draft(
                    draft_key
                )
                semantic_coverages = tuple(
                    coverage
                    for coverage in linked_coverages
                    if coverage.source == source
                    and coverage.reason
                    is RemediationCoverageReason.DRAFT_SEMANTIC_DEDUPE
                )
                if not semantic_coverages or any(
                    coverage.occurred_at > occurred_at
                    for coverage in semantic_coverages
                ):
                    raise ValueError
                exact_ids = self._remediation_completion_revision_ids(source)
            if tuple(raw_revision_ids) != exact_ids or occurred_at < draft.occurred_at:
                raise ValueError
        except (TypeError, ValueError, json.JSONDecodeError, RecursionError):
            raise RuntimeError(
                "Merged remediation revalidation ledger is malformed."
            ) from None
        return MergedRemediationRevalidation(
            revalidation_key=revalidation_key,
            draft_key=draft_key,
            source=source,
            event_revision_ids=tuple(raw_revision_ids),
            phase=phase,
            occurred_at=occurred_at,
        )

    def _enqueue_merged_remediation_revalidations_in_transaction(
        self,
        *,
        draft: RemediationDraftRecord,
        occurred_at: datetime,
    ) -> None:
        revision_ids_by_source = {
            source: self._event_revision_ids_for_source_drafts(
                source=source,
                draft_keys=(draft.draft_key,),
                require_opened=False,
            )
            for source in draft.source_pulls
        }
        for coverage in self._bounded_remediation_coverages_linked_to_draft(
            draft.draft_key
        ):
            if not coverage.effective:
                continue
            coverage_revision_ids = self._remediation_completion_revision_ids(
                coverage.source
            )
            existing_revision_ids = revision_ids_by_source.setdefault(
                coverage.source,
                coverage_revision_ids,
            )
            if existing_revision_ids != coverage_revision_ids:
                raise RuntimeError(
                    "Remediation draft source coverage evidence disagrees."
                )
        if len(revision_ids_by_source) > _MAX_REMEDIATION_MERGE_REVALIDATIONS:
            raise RuntimeError(
                "Remediation draft merge revalidation reached its safety bound."
            )
        for source, revision_ids in sorted(
            revision_ids_by_source.items(),
            key=lambda item: (
                item[0].repository,
                item[0].repository_id,
                item[0].pull_id,
                item[0].pr_number,
                item[0].pull_revision_digest,
                item[0].policy_digest,
            ),
        ):
            try:
                revision_ids_json = _merged_revalidation_revision_ids_json(revision_ids)
            except ValueError as exc:
                raise RuntimeError(
                    "Remediation draft merge revalidation evidence reached its "
                    "safety bound."
                ) from exc
            revalidation_key = self._merge_revalidation_key(
                draft_key=draft.draft_key,
                source=source,
            )
            row = self._connection.execute(
                """
                SELECT * FROM remediation_merge_revalidation_events
                WHERE revalidation_key = ?
                ORDER BY merge_revalidation_event_id DESC
                LIMIT 1
                """,
                (revalidation_key,),
            ).fetchone()
            if row is not None:
                self._merged_revalidation_from_row(row)
                continue
            self._connection.execute(
                """
                INSERT INTO remediation_merge_revalidation_events (
                    revalidation_key, draft_key, source_json,
                    event_revision_ids_json, phase, occurred_at
                ) VALUES (?, ?, ?, ?, 'pending', ?)
                """,
                (
                    revalidation_key,
                    draft.draft_key,
                    _historical_pull_reference_json(source),
                    revision_ids_json,
                    _serialize_datetime(occurred_at),
                ),
            )

    def pending_merged_remediation_revalidations(
        self,
        *,
        repository: str | None = None,
        repository_id: int | None = None,
        limit: int = 100,
    ) -> tuple[MergedRemediationRevalidation, ...]:
        """Return a bounded, rotating workset of merged-source revalidations.

        The immutable ID is authoritative when both repository filters are given.
        """

        if (
            isinstance(limit, bool)
            or not isinstance(limit, int)
            or not 1 <= limit <= 100
        ):
            raise ValueError("limit must be an integer from 1 through 100.")
        _validate_repository_id_filter(repository_id)
        if repository_id is not None:
            where = "WHERE draft.target_repository_id = ?"
            parameters: tuple[object, ...] = (repository_id,)
        elif repository is not None:
            where = "WHERE draft.target_repository = ?"
            parameters = (repository,)
        else:
            where = ""
            parameters = ()
        rows = self._connection.execute(
            f"""
            WITH latest_queue AS (
                SELECT queue.*,
                       ROW_NUMBER() OVER (
                           PARTITION BY revalidation_key
                           ORDER BY merge_revalidation_event_id DESC
                       ) AS guardian_row_number
                FROM remediation_merge_revalidation_events AS queue
            ), latest_drafts AS (
                SELECT draft.*,
                       ROW_NUMBER() OVER (
                           PARTITION BY draft_key
                           ORDER BY remediation_event_id DESC
                       ) AS guardian_row_number
                FROM remediation_draft_events AS draft
                {where}
            )
            SELECT latest_queue.*
            FROM latest_queue
            JOIN latest_drafts AS draft
              ON draft.draft_key = latest_queue.draft_key
             AND draft.guardian_row_number = 1
            WHERE latest_queue.guardian_row_number = 1
              AND latest_queue.phase IN ('pending', 'attempted')
              AND EXISTS (
                  SELECT 1 FROM remediation_resolution_events AS resolution
                  WHERE resolution.draft_key = latest_queue.draft_key
                    AND resolution.resolution = 'merged'
              )
            ORDER BY latest_queue.merge_revalidation_event_id
            LIMIT ?
            """,
            (*parameters, limit),
        ).fetchall()
        return tuple(self._merged_revalidation_from_row(row) for row in rows)

    def _record_merged_remediation_revalidation_phase(
        self,
        *,
        revalidation_key: str,
        phase: str,
        occurred_at: datetime | None,
    ) -> MergedRemediationRevalidation:
        if not isinstance(revalidation_key, str) or not _SHA256_RE.fullmatch(
            revalidation_key
        ):
            raise ValueError("revalidation_key must be a SHA-256 digest.")
        if phase not in {"attempted", "resolved", "no_longer_applicable"}:
            raise ValueError("Unsupported merge revalidation phase.")
        latest_row = self._connection.execute(
            """
            SELECT * FROM remediation_merge_revalidation_events
            WHERE revalidation_key = ?
            ORDER BY merge_revalidation_event_id DESC
            LIMIT 1
            """,
            (revalidation_key,),
        ).fetchone()
        if latest_row is None:
            raise ValueError("Unknown merged remediation revalidation.")
        latest = self._merged_revalidation_from_row(latest_row)
        occurred = occurred_at or _now()
        _serialize_datetime(occurred)
        if occurred < latest.occurred_at:
            raise ValueError("Merge revalidation timestamps must be monotonic.")
        if latest.phase in {"resolved", "no_longer_applicable"}:
            if latest.phase != phase:
                raise ValueError("Merged remediation revalidation is terminal.")
            return latest
        if phase == "attempted" and latest.phase not in {"pending", "attempted"}:
            raise ValueError("Invalid merged remediation revalidation transition.")
        with self._connection:
            cursor = self._connection.execute(
                """
                INSERT INTO remediation_merge_revalidation_events (
                    revalidation_key, draft_key, source_json,
                    event_revision_ids_json, phase, occurred_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    revalidation_key,
                    latest.draft_key,
                    _historical_pull_reference_json(latest.source),
                    _merged_revalidation_revision_ids_json(latest.event_revision_ids),
                    phase,
                    _serialize_datetime(occurred),
                ),
            )
        row = self._connection.execute(
            """
            SELECT * FROM remediation_merge_revalidation_events
            WHERE merge_revalidation_event_id = ?
            """,
            (cursor.lastrowid,),
        ).fetchone()
        if row is None:
            raise RuntimeError("Merged remediation revalidation disappeared.")
        return self._merged_revalidation_from_row(row)

    def record_merged_remediation_revalidation_attempt(
        self,
        *,
        revalidation_key: str,
        occurred_at: datetime | None = None,
    ) -> MergedRemediationRevalidation:
        """Rotate one durable merged-source item before current-base work."""

        return self._record_merged_remediation_revalidation_phase(
            revalidation_key=revalidation_key,
            phase="attempted",
            occurred_at=occurred_at,
        )

    def resolve_merged_remediation_revalidation(
        self,
        *,
        revalidation_key: str,
        outcome: str,
        occurred_at: datetime | None = None,
    ) -> MergedRemediationRevalidation:
        """Acknowledge current-base resolution of one queued source."""

        if outcome not in {"resolved", "no_longer_applicable"}:
            raise ValueError("Unsupported merge revalidation outcome.")
        return self._record_merged_remediation_revalidation_phase(
            revalidation_key=revalidation_key,
            phase=outcome,
            occurred_at=occurred_at,
        )

    @staticmethod
    def _validate_remote_observation_metadata(
        *,
        observation: str,
        state: str | None,
        is_draft: bool | None,
        is_merged: bool | None,
        pr_number: int | None,
        pr_url: str | None,
        observed_base_sha: str | None,
        observed_head_sha: str | None,
        closed_at: str | None,
        merged_at: str | None,
    ) -> None:
        if observation not in {"exact", "not_found", "conflict"}:
            raise ValueError("observation must be exact, not_found, or conflict.")
        values = (
            state,
            is_draft,
            is_merged,
            pr_number,
            pr_url,
            observed_base_sha,
            observed_head_sha,
        )
        if observation == "not_found":
            if any(value is not None for value in (*values, closed_at, merged_at)):
                raise ValueError("not_found observation must not invent PR metadata.")
            return
        supplied = tuple(value is not None for value in values)
        if observation == "exact" and not all(supplied):
            raise ValueError("exact observation requires complete PR metadata.")
        if observation == "conflict" and any(supplied) and not all(supplied):
            raise ValueError(
                "conflict observation metadata must be complete or entirely absent."
            )
        if not any(supplied):
            if closed_at is not None or merged_at is not None:
                raise ValueError(
                    "conflict observation metadata must be complete or entirely absent."
                )
            return
        if state not in {"open", "closed"}:
            raise ValueError("remote state must be open or closed.")
        if not isinstance(is_draft, bool) or not isinstance(is_merged, bool):
            raise ValueError("remote draft and merged flags must be booleans.")
        if (
            isinstance(pr_number, bool)
            or not isinstance(pr_number, int)
            or pr_number <= 0
        ):
            raise ValueError("remote pr_number must be a positive integer.")
        if (
            not isinstance(pr_url, str)
            or not pr_url
            or any(character in pr_url for character in "\r\n\x00")
        ):
            raise ValueError("remote pr_url must be a safe non-empty value.")
        for value, label in (
            (observed_base_sha, "observed_base_sha"),
            (observed_head_sha, "observed_head_sha"),
        ):
            if not isinstance(value, str) or not re.fullmatch(
                r"(?:[0-9a-f]{40}|[0-9a-f]{64})",
                value,
            ):
                raise ValueError(f"{label} must be a full object ID.")
        if is_merged and (state != "closed" or is_draft is not False):
            raise ValueError(
                "A merged remote pull request must be closed and non-draft."
            )
        parsed_closed = GuardianState._remote_lifecycle_timestamp(
            closed_at,
            label="closed_at",
        )
        parsed_merged = GuardianState._remote_lifecycle_timestamp(
            merged_at,
            label="merged_at",
        )
        if (state == "open") != (parsed_closed is None):
            raise ValueError("remote closed_at does not match its state.")
        if (is_merged is True) != (parsed_merged is not None):
            raise ValueError("remote merged_at does not match its merged flag.")
        if parsed_merged is not None and (
            parsed_closed is None or parsed_merged > parsed_closed
        ):
            raise ValueError("remote merged_at must not follow closed_at.")

    @staticmethod
    def _remote_lifecycle_timestamp(
        value: str | None,
        *,
        label: str,
    ) -> datetime | None:
        if value is None:
            return None
        if (
            not isinstance(value, str)
            or not value
            or len(value) > 64
            or any(character in value for character in "\r\n\x00")
        ):
            raise ValueError(f"{label} must be a bounded UTC timestamp.")
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            raise ValueError(f"{label} must be a bounded UTC timestamp.") from None
        if (
            parsed.tzinfo is None
            or parsed.utcoffset() is None
            or parsed.utcoffset() != _UTC.utcoffset(None)
        ):
            raise ValueError(f"{label} must be a bounded UTC timestamp.")
        return parsed

    def _remote_observation_from_row(
        self,
        row: sqlite3.Row,
    ) -> RemediationRemoteObservation:
        try:
            occurred_at = _parse_datetime(row["occurred_at"])
            draft_key = str(row["draft_key"])
            observation_id = int(row["observation_id"])
            observation = str(row["observation"])
            state = None if row["state"] is None else str(row["state"])
            is_draft = None if row["is_draft"] is None else bool(int(row["is_draft"]))
            is_merged = (
                None if row["is_merged"] is None else bool(int(row["is_merged"]))
            )
            pr_number = None if row["pr_number"] is None else int(row["pr_number"])
            pr_url = None if row["pr_url"] is None else str(row["pr_url"])
            observed_base_sha = (
                None
                if row["observed_base_sha"] is None
                else str(row["observed_base_sha"])
            )
            observed_head_sha = (
                None
                if row["observed_head_sha"] is None
                else str(row["observed_head_sha"])
            )
            closed_at = None if row["closed_at"] is None else str(row["closed_at"])
            merged_at = None if row["merged_at"] is None else str(row["merged_at"])
            self._validate_remote_observation_metadata(
                observation=observation,
                state=state,
                is_draft=is_draft,
                is_merged=is_merged,
                pr_number=pr_number,
                pr_url=pr_url,
                observed_base_sha=observed_base_sha,
                observed_head_sha=observed_head_sha,
                closed_at=closed_at,
                merged_at=merged_at,
            )
        except (TypeError, ValueError):
            raise RuntimeError(
                "Remediation remote observation ledger is malformed."
            ) from None
        first_event = None
        opened_event = None
        if _SHA256_RE.fullmatch(draft_key):
            first_event = self._connection.execute(
                """
                SELECT occurred_at FROM remediation_draft_events
                WHERE draft_key = ?
                ORDER BY remediation_event_id
                LIMIT 1
                """,
                (draft_key,),
            ).fetchone()
            if observation == "exact":
                opened_event = self._connection.execute(
                    """
                    SELECT occurred_at FROM remediation_draft_events
                    WHERE draft_key = ? AND phase = 'draft_opened'
                      AND draft_number = ? AND draft_url = ?
                    LIMIT 1
                    """,
                    (draft_key, pr_number, pr_url),
                ).fetchone()
        first_occurred_at = (
            None if first_event is None else _parse_datetime(first_event["occurred_at"])
        )
        opened_occurred_at = (
            None
            if opened_event is None
            else _parse_datetime(opened_event["occurred_at"])
        )
        if (
            occurred_at is None
            or observation_id <= 0
            or first_occurred_at is None
            or occurred_at < first_occurred_at
            or (
                observation == "exact"
                and (opened_occurred_at is None or occurred_at < opened_occurred_at)
            )
        ):
            raise RuntimeError("Remediation remote observation ledger is malformed.")
        return RemediationRemoteObservation(
            observation_id=observation_id,
            draft_key=draft_key,
            observation=observation,
            state=state,
            is_draft=is_draft,
            is_merged=is_merged,
            pr_number=pr_number,
            pr_url=pr_url,
            observed_base_sha=observed_base_sha,
            observed_head_sha=observed_head_sha,
            closed_at=closed_at,
            merged_at=merged_at,
            occurred_at=occurred_at,
        )

    def record_remediation_remote_observation(
        self,
        *,
        draft_key: str,
        observation: str,
        state: str | None = None,
        is_draft: bool | None = None,
        is_merged: bool | None = None,
        pr_number: int | None = None,
        pr_url: str | None = None,
        observed_base_sha: str | None = None,
        observed_head_sha: str | None = None,
        closed_at: str | None = None,
        merged_at: str | None = None,
        observed_at: datetime | None = None,
    ) -> RemediationRemoteObservation:
        """Append one exact lifecycle observation; merge resolution is atomic."""

        if not isinstance(draft_key, str) or not _SHA256_RE.fullmatch(draft_key):
            raise ValueError("draft_key must be a SHA-256 digest.")
        self._validate_remote_observation_metadata(
            observation=observation,
            state=state,
            is_draft=is_draft,
            is_merged=is_merged,
            pr_number=pr_number,
            pr_url=pr_url,
            observed_base_sha=observed_base_sha,
            observed_head_sha=observed_head_sha,
            closed_at=closed_at,
            merged_at=merged_at,
        )
        draft = self.remediation_draft_by_key(draft_key=draft_key)
        if draft is None:
            raise ValueError("Unknown remediation draft key.")
        if observation == "exact" and (
            draft.phase != "draft_opened"
            or draft.draft_number != pr_number
            or draft.draft_url != pr_url
            or observed_head_sha != self.remediation_candidate_tip(draft_key)
        ):
            raise ValueError(
                "Exact observation does not match the opened remediation draft."
            )
        observed = observed_at or _now()
        observed_serialized = _serialize_datetime(observed)
        if observed < draft.occurred_at:
            raise ValueError(
                "observed_at must not precede the latest remediation event."
            )
        with self._connection:
            latest_row = self._connection.execute(
                """
                SELECT * FROM remediation_remote_observation_events
                WHERE draft_key = ?
                ORDER BY observation_id DESC
                LIMIT 1
                """,
                (draft_key,),
            ).fetchone()
            latest = (
                None
                if latest_row is None
                else self._remote_observation_from_row(latest_row)
            )
            if latest is not None and observed < latest.occurred_at:
                raise ValueError(
                    "observed_at must be monotonic for a remediation draft."
                )
            if latest is not None and (
                latest.observation,
                latest.state,
                latest.is_draft,
                latest.is_merged,
                latest.pr_number,
                latest.pr_url,
                latest.observed_base_sha,
                latest.observed_head_sha,
                latest.closed_at,
                latest.merged_at,
            ) == (
                observation,
                state,
                is_draft,
                is_merged,
                pr_number,
                pr_url,
                observed_base_sha,
                observed_head_sha,
                closed_at,
                merged_at,
            ):
                if (
                    is_merged is True
                    and self.remediation_resolution(draft_key=draft_key) != "merged"
                ):
                    raise RuntimeError(
                        "Merged remote observation is missing its atomic resolution."
                    )
                return latest
            if self.remediation_resolution(draft_key=draft_key) is not None:
                raise ValueError("Resolved remediation remote lifecycle is terminal.")
            count_row = self._connection.execute(
                """
                SELECT COUNT(*) AS observation_count
                FROM remediation_remote_observation_events
                WHERE draft_key = ?
                """,
                (draft_key,),
            ).fetchone()
            if (
                count_row is None
                or int(count_row["observation_count"])
                >= _MAX_REMEDIATION_REMOTE_OBSERVATIONS
            ):
                raise RuntimeError(
                    "Remediation remote observation count reached its safety bound."
                )
            cursor = self._connection.execute(
                """
                INSERT INTO remediation_remote_observation_events (
                    draft_key, observation, state, is_draft, is_merged,
                    pr_number, pr_url, observed_base_sha, observed_head_sha,
                    closed_at, merged_at, occurred_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    draft_key,
                    observation,
                    state,
                    None if is_draft is None else int(is_draft),
                    None if is_merged is None else int(is_merged),
                    pr_number,
                    pr_url,
                    observed_base_sha,
                    observed_head_sha,
                    closed_at,
                    merged_at,
                    observed_serialized,
                ),
            )
            if observation == "exact" and is_merged is True:
                self._enqueue_merged_remediation_revalidations_in_transaction(
                    draft=draft,
                    occurred_at=observed,
                )
                self._record_remediation_resolution_in_transaction(
                    draft_key=draft_key,
                    resolution="merged",
                    occurred_at=observed,
                )
        row = self._connection.execute(
            """
            SELECT * FROM remediation_remote_observation_events
            WHERE observation_id = ?
            """,
            (cursor.lastrowid,),
        ).fetchone()
        if row is None:
            raise RuntimeError("Remediation remote observation disappeared.")
        return self._remote_observation_from_row(row)

    def latest_remediation_remote_observation(
        self,
        draft_key: str,
    ) -> RemediationRemoteObservation | None:
        """Return the latest append-only remote observation for one draft."""

        if not isinstance(draft_key, str) or not _SHA256_RE.fullmatch(draft_key):
            raise ValueError("draft_key must be a SHA-256 digest.")
        row = self._connection.execute(
            """
            SELECT * FROM remediation_remote_observation_events
            WHERE draft_key = ?
            ORDER BY observation_id DESC
            LIMIT 1
            """,
            (draft_key,),
        ).fetchone()
        return None if row is None else self._remote_observation_from_row(row)

    def opened_remediation_drafts_for_reconciliation(
        self,
        *,
        repository: str | None = None,
        repository_id: int | None = None,
        limit: int = 100,
    ) -> tuple[RemediationDraftRecord, ...]:
        """Return least-recently-checked active correction PRs for lifecycle checks.

        The immutable ID is authoritative when both repository filters are given.
        """

        if (
            isinstance(limit, bool)
            or not isinstance(limit, int)
            or not 1 <= limit <= 100
        ):
            raise ValueError("limit must be an integer from 1 through 100.")
        _validate_repository_id_filter(repository_id)
        if repository_id is not None:
            where = "WHERE target_repository_id = ?"
            parameters: tuple[object, ...] = (repository_id,)
        elif repository is not None:
            where = "WHERE target_repository = ?"
            parameters = (repository,)
        else:
            where = ""
            parameters = ()
        rows = self._connection.execute(
            f"""
            WITH latest AS (
                SELECT r.*,
                       ROW_NUMBER() OVER (
                           PARTITION BY draft_key
                           ORDER BY remediation_event_id DESC
                       ) AS guardian_row_number
                FROM remediation_draft_events AS r
                {where}
            )
            SELECT latest.*
            FROM latest
            LEFT JOIN remediation_recovery_cursors AS recovery
              ON recovery.draft_key = latest.draft_key
            WHERE latest.guardian_row_number = 1
              AND latest.phase = 'draft_opened'
              AND NOT EXISTS (
                  SELECT 1 FROM remediation_resolution_events AS resolution
                  WHERE resolution.draft_key = latest.draft_key
              )
            ORDER BY COALESCE(recovery.recovery_rank, 0),
                     latest.remediation_event_id
            LIMIT ?
            """,
            (*parameters, limit),
        ).fetchall()
        return tuple(self._remediation_from_row(row) for row in rows)

    def terminal_remediation_drafts(
        self,
        *,
        repository: str | None = None,
    ) -> tuple[RemediationDraftRecord, ...]:
        """Return exact opened or abandoned terminal remediation candidates."""

        return self._latest_remediation_drafts(
            repository=repository,
            phases=("draft_opened", "abandoned"),
        )

    def opened_remediation_drafts(
        self,
        *,
        repository: str | None = None,
    ) -> tuple[RemediationDraftRecord, ...]:
        """Return exact remediation candidates known to have a review PR."""

        return self._latest_remediation_drafts(
            repository=repository,
            phases=("draft_opened",),
        )

    def uncheckpointed_opened_remediation_drafts(
        self,
        *,
        repository: str | None = None,
        limit: int = 100,
    ) -> tuple[RemediationDraftRecord, ...]:
        """Return a bounded workset of opened drafts lacking a checkpoint marker."""

        if (
            isinstance(limit, bool)
            or not isinstance(limit, int)
            or not 1 <= limit <= 100
        ):
            raise ValueError("limit must be an integer from 1 through 100.")
        where = "WHERE target_repository = ?" if repository is not None else ""
        parameters: tuple[object, ...] = (repository,) if repository is not None else ()
        rows = self._connection.execute(
            f"""
            SELECT latest.* FROM (
                SELECT r.*,
                       ROW_NUMBER() OVER (
                           PARTITION BY draft_key
                           ORDER BY remediation_event_id DESC
                       ) AS guardian_row_number
                FROM remediation_draft_events AS r
                {where}
            ) AS latest
            LEFT JOIN remediation_checkpoint_events AS checkpoint
              ON checkpoint.draft_key = latest.draft_key
            WHERE latest.guardian_row_number = 1
              AND latest.phase = 'draft_opened'
              AND NOT EXISTS (
                  SELECT 1 FROM remediation_resolution_events AS resolution
                  WHERE resolution.draft_key = latest.draft_key
              )
              AND checkpoint.draft_key IS NULL
            ORDER BY latest.remediation_event_id
            LIMIT ?
            """,
            (*parameters, limit),
        ).fetchall()
        return tuple(self._remediation_from_row(row) for row in rows)

    def record_remediation_checkpoint(
        self,
        *,
        draft_key: str,
        occurred_at: datetime | None = None,
    ) -> bool:
        """Mark one opened draft's bounded checkpoint recovery resolved."""

        if not isinstance(draft_key, str) or not _SHA256_RE.fullmatch(draft_key):
            raise ValueError("draft_key must be a SHA-256 digest.")
        with self._connection:
            return self._record_remediation_checkpoint_in_transaction(
                draft_key=draft_key,
                occurred_at=occurred_at or _now(),
            )

    def _record_remediation_checkpoint_in_transaction(
        self,
        *,
        draft_key: str,
        occurred_at: datetime,
    ) -> bool:
        latest = self._connection.execute(
            """
            SELECT phase, occurred_at FROM remediation_draft_events
            WHERE draft_key = ?
            ORDER BY remediation_event_id DESC
            LIMIT 1
            """,
            (draft_key,),
        ).fetchone()
        if latest is None or latest["phase"] != "draft_opened":
            raise ValueError("Only an opened remediation draft can be checkpointed.")
        latest_at = _parse_datetime(latest["occurred_at"])
        if latest_at is None or occurred_at < latest_at:
            raise ValueError(
                "occurred_at must not precede the latest remediation event."
            )
        cursor = self._connection.execute(
            """
            INSERT OR IGNORE INTO remediation_checkpoint_events (
                draft_key, occurred_at
            ) VALUES (?, ?)
            """,
            (draft_key, _serialize_datetime(occurred_at)),
        )
        return cursor.rowcount == 1

    def opened_remediation_evidence_hashes(
        self,
        *,
        repository: str,
    ) -> frozenset[str]:
        """Return evidence hashes with a durable human-review correction PR."""

        return frozenset(
            record.evidence_hash
            for record in self.opened_remediation_drafts(repository=repository)
        )

    def purge_raw_event_bodies(self, *, before: datetime) -> int:
        """Delete expired raw bodies while retaining immutable revision hashes."""

        with self._connection:
            cursor = self._connection.execute(
                "DELETE FROM event_raw_bodies WHERE observed_at < ?",
                (_serialize_datetime(before),),
            )
        return cursor.rowcount

    def purge_assessment_results(self, *, before: datetime) -> int:
        """Delete cached decisions when the corresponding raw-retention window ends."""

        with self._connection:
            cursor = self._connection.execute(
                "DELETE FROM assessment_results WHERE created_at < ?",
                (_serialize_datetime(before),),
            )
        return cursor.rowcount
