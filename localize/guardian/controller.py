"""One bounded, revision-aware orchestration pass for Localize Guardian.

The controller is intentionally dependency-injected at every credential or
network boundary.  It coordinates trusted primitives, but does not itself know
how an operator retrieves a GitHub token or a Codex API key.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field, fields, is_dataclass, replace
from datetime import datetime, timedelta, timezone
from enum import Enum
from fnmatch import fnmatchcase
import hashlib
from itertools import islice
import json
from pathlib import Path, PurePosixPath
import re
import stat
import tempfile
from typing import ContextManager, Protocol
from uuid import uuid4

import yaml

from localize.formats import get_localization_adapter
from localize.guardian.authorization import (
    AuthorizedFeedback,
    IntakePolicyError,
    authorize_feedback,
    authorize_historical_feedback,
)
from localize.guardian.codex import (
    CodexAuthenticationError,
    CodexCapacityError,
    CodexResult,
    CodexTask,
    CodexUsage,
    RESULT_SCHEMA_PATH,
    parse_cached_codex_result,
    serialize_codex_result,
    to_guardian_assessments,
)
from localize.guardian.deadline import PollDeadline, PollDeadlineExceeded
from localize.guardian.evidence import EVIDENCE_CONTRACT_VERSION, EvidenceBundle, build_evidence_bundle
from localize.guardian.github import (
    BaseRevisionSnapshot,
    ChangedFile,
    ClosedPullScanItem,
    ClosedPullScanPosition,
    ClosedPullScanResult,
    FeedbackKind,
    FeedbackRevision,
    GitHubAuthenticationError,
    GitHubWriteBroker,
    OpenPullPathAuthority,
    OpenPullPathIdentity,
    PolicyViolation,
    PullRequestFeedbackSnapshot,
    PullRequestSnapshot,
)
from localize.guardian.models import (
    CodexAuthMode,
    FeedbackEvent,
    GuardianAssessment,
    GuardianConfig,
    GuardianMode,
    HistoricalCheckScope,
    PipelineConfigSnapshot,
    PipelineConfigSource,
    ProposedReplacement,
    RecurrenceCandidate,
    RepositoryPolicy,
    pipeline_config_bundle_digest,
)
from localize.guardian.path_globs import matches_any_path_glob
from localize.guardian.policy import PatchPolicyError, PatchResult, apply_replacements
from localize.guardian.prevention_runtime import (
    PreventionBatchOutcome,
    PreventionLeaseLostError,
    PreventionRuntimeError,
    PreventionSourceAuthorityError,
)
from localize.guardian.state import (
    EventRevision,
    GuardianState,
    HistoricalPullReference,
    OpenPullAuthorityReference,
    RemediationCoverageReason,
    feedback_revision_hash,
    remediation_batch_hash,
    remediation_edit_hash,
    remediation_target_hash,
)
from localize.guardian.remediation import (
    RemediationBaseSnapshot,
    RemediationBatchOutcome,
    RemediationDraftResult,
    RemediationOpenPullAuthorityError,
    RemediationRemoteConflictError,
    RemediationSourceAuthorityError,
)
from localize.guardian.workspace import (
    ExactRevision,
    GuardianWorkspace,
    HistoricalRevision,
    HistoricalWorkspace,
)
from localize.localization_profiles import (
    LocalizationProfile,
    load_localization_profiles,
)


_UTC = timezone.utc


class _PublishedFeedbackChanged(PreventionSourceAuthorityError):
    """The exact published PR is still authorized, but its review text changed."""


_SUPPORTED_CHANGED_FILE_STATUSES = frozenset({"added", "modified"})
_ASSESSMENT_PROMPT = (
    "Read INSTRUCTIONS.md and the complete sanitized evidence bundle. "
    "Assess every manifest feedback ID exactly once and write only the "
    "schema-conforming result."
)
_HISTORICAL_ASSESSMENT_PROMPT = (
    "Read INSTRUCTIONS.md and the complete sanitized evidence bundle. "
    "This is a closed-pull-request assessment: the review feedback and diff "
    "are historical evidence only, while localization.json contains the exact "
    "source and target values from the independently captured current base. "
    "Determine independently whether each historical defect still exists on "
    "that current base. Propose a replacement only when it still exists, and "
    "echo the exact current target as expected_value. Base the proposal only on "
    "the exact current source shown there; the controller binds source_value "
    "from that trusted evidence rather than accepting it from model output. "
    "Assess every manifest feedback ID exactly once and write only the "
    "schema-conforming result."
)
_REMEDIATION_FAIRNESS_COMPONENT = "guardian-remediation-fairness"
_MAX_REMEDIATION_CHANGED_PATHS = 100
_MAX_OPEN_AUTHORITY_PULLS = 200
_MAX_OPEN_AUTHORITY_AFFECTED_PATHS_PER_PULL = 2 * 500
_MAX_OPEN_AUTHORITY_CHANGED_PATHS = (
    _MAX_OPEN_AUTHORITY_PULLS * _MAX_OPEN_AUTHORITY_AFFECTED_PATHS_PER_PULL
)
_MAX_REPOSITORY_PATH_BYTES = 4096


def _bounded_repository_paths(
    values: Sequence[str],
    *,
    limit: int,
    label: str,
    allow_empty: bool,
) -> tuple[str, ...]:
    """Materialize canonical safe relative paths without trusting a provider."""

    if isinstance(values, (str, bytes)):
        raise RemediationOpenPullAuthorityError(f"{label} are malformed.")
    try:
        paths = tuple(islice(iter(values), limit + 1))
    except TypeError:
        raise RemediationOpenPullAuthorityError(f"{label} are malformed.") from None
    invalid_item = any(
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
        len(paths) > limit
        or (not allow_empty and not paths)
        or invalid_item
        or len(set(paths)) != len(paths)
    ):
        raise RemediationOpenPullAuthorityError(
            f"{label} are malformed or exceed their safety bound."
        )
    return tuple(sorted(paths))


def _assert_no_open_translation_overlap(
    *,
    policy: RepositoryPolicy,
    candidate_paths: Sequence[str],
    authorities: Sequence[OpenPullPathAuthority],
    excluded_pull: OpenPullPathIdentity | None,
) -> None:
    """Reject every overlapping allowed open PR except one exact self identity."""

    paths = _bounded_repository_paths(
        candidate_paths,
        limit=_MAX_REMEDIATION_CHANGED_PATHS,
        label="Remediation candidate paths",
        allow_empty=False,
    )
    if excluded_pull is not None:
        backfill = policy.closed_pr_backfill
        remediation = backfill.remediation if backfill is not None else None
        if (
            not isinstance(excluded_pull, OpenPullPathIdentity)
            or remediation is None
            or excluded_pull.repository != policy.base_repo
            or excluded_pull.repository_id != policy.base_repo_id
            or excluded_pull.head_repository != remediation.push_repository.full_name
            or excluded_pull.head_repository_id != remediation.push_repository.id
            or not excluded_pull.head_ref.startswith(remediation.push_branch_prefix)
            or excluded_pull.head_ref == remediation.push_branch_prefix
            or not any(
                fnmatchcase(excluded_pull.head_ref, pattern)
                for pattern in policy.allowed_branch_globs
            )
        ):
            raise RemediationOpenPullAuthorityError(
                "Remediation open-pull exclusion is not configured publication "
                "authority."
            )
    if isinstance(authorities, (str, bytes)):
        raise RemediationOpenPullAuthorityError("Open-PR path authority is malformed.")
    try:
        bounded = tuple(islice(iter(authorities), _MAX_OPEN_AUTHORITY_PULLS + 1))
    except TypeError:
        raise RemediationOpenPullAuthorityError(
            "Open-PR path authority is malformed."
        ) from None
    if len(bounded) > _MAX_OPEN_AUTHORITY_PULLS or any(
        not isinstance(item, OpenPullPathAuthority) for item in bounded
    ):
        raise RemediationOpenPullAuthorityError(
            "Open-PR path authority is malformed or unbounded."
        )
    identities = tuple(item.identity for item in bounded)
    if len(set(identities)) != len(identities) or any(
        identity.repository != policy.base_repo
        or identity.repository_id != policy.base_repo_id
        for identity in identities
    ):
        raise RemediationOpenPullAuthorityError(
            "Open-PR path authority escaped its repository."
        )
    total_paths = sum(len(item.changed_paths) for item in bounded)
    if total_paths > _MAX_OPEN_AUTHORITY_CHANGED_PATHS:
        raise RemediationOpenPullAuthorityError(
            "Open-PR path authority exceeded its safety bound."
        )
    excluded_seen = False
    requested = frozenset(paths)
    for item in bounded:
        if excluded_pull is not None and item.identity == excluded_pull:
            excluded_seen = True
            continue
        if requested.intersection(item.changed_paths):
            raise RemediationOpenPullAuthorityError(
                "An open pull request overlaps the historical remediation paths."
            )
    if excluded_pull is not None and not excluded_seen:
        raise RemediationOpenPullAuthorityError(
            "The exact remediation pull is absent from open-PR authority."
        )


def _rotate_policies_after_repository(
    policies: Sequence[RepositoryPolicy],
    repository: str | None,
) -> tuple[RepositoryPolicy, ...]:
    ordered = tuple(policies)
    if repository is None:
        return ordered
    for index, policy in enumerate(ordered):
        if policy.base_repo == repository:
            return (*ordered[index + 1 :], *ordered[: index + 1])
    return ordered


_ASSESSMENT_CACHE_VERSION = 1
_HISTORICAL_CONTROLLER_VERSION = 3


def _assessment_cache_key(
    bundle: EvidenceBundle,
    *,
    model: str,
    reasoning_effort: str,
    prompt: str,
) -> str:
    schema_hash = hashlib.sha256(RESULT_SCHEMA_PATH.read_bytes()).hexdigest()
    identity = json.dumps(
        {
            "cache_version": _ASSESSMENT_CACHE_VERSION,
            "evidence_hash": bundle.evidence_hash,
            "model": model,
            "prompt": prompt,
            "reasoning_effort": reasoning_effort,
            "schema_hash": schema_hash,
        },
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    )
    return hashlib.sha256(identity.encode("utf-8")).hexdigest()


class SnapshotProvider(Protocol):
    """Read-only GitHub intake supplied by the runtime credential boundary."""

    def __call__(
        self,
        policy: RepositoryPolicy,
        previous_feedback: tuple[FeedbackRevision, ...],
    ) -> Sequence[PullRequestFeedbackSnapshot]: ...


class CheckoutFactory(Protocol):
    """Materialize one exact base or head revision."""

    def __call__(
        self, revision: ExactRevision | HistoricalRevision
    ) -> ContextManager[GuardianWorkspace | HistoricalWorkspace]: ...


class HistoricalSnapshotProvider(Protocol):
    """Read-only, checkpoint-aware closed pull-request intake."""

    def __call__(
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
    ) -> ClosedPullScanResult: ...


class HistoricalSourceSnapshotProvider(Protocol):
    """Rehydrate exact closed remediation sources at a write boundary."""

    def __call__(
        self,
        policy: RepositoryPolicy,
        sources: tuple[HistoricalPullReference, ...],
    ) -> tuple[PullRequestFeedbackSnapshot, ...]: ...


class HistoricalCheckoutFactory(Protocol):
    """Materialize an immutable historical commit or upstream pull ref."""

    def __call__(
        self,
        revision: HistoricalRevision,
    ) -> ContextManager[HistoricalWorkspace]: ...


class CurrentBaseProvider(Protocol):
    """Capture the current configured base through a read-only API client."""

    def __call__(self, policy: RepositoryPolicy) -> BaseRevisionSnapshot: ...


class CodexRunner(Protocol):
    """Minimum driver surface used by the controller."""

    model: str

    def run(
        self,
        task: CodexTask,
        *,
        api_key: str | None = None,
        attempt_observer: Callable[[int, str, CodexUsage | None], None] | None = None,
        success_observer: Callable[[int, CodexUsage | None, CodexResult], None]
        | None = None,
    ) -> CodexResult: ...


class WriteBrokerFactory(Protocol):
    """Create the narrow GitHub broker for one already-authorized policy."""

    def __call__(self, policy: RepositoryPolicy) -> GitHubWriteBroker: ...


class PreventionRunner(Protocol):
    """Narrow draft-only prevention surface supplied by production wiring."""

    def begin_poll(self) -> None: ...

    def recover_orphans(
        self,
        *,
        configured_policies: Sequence[RepositoryPolicy],
        observed_at: datetime,
        require_live_lease: Callable[[], None],
    ) -> PreventionBatchOutcome: ...

    def recover(
        self,
        *,
        policy: RepositoryPolicy,
        observed_at: datetime,
        require_live_lease: Callable[[], None],
        require_current_base_unchanged: Callable[[], None],
        require_exact_open_source_authority: Callable[
            [OpenPullAuthorityReference, Sequence[int]], None
        ]
        | None = None,
        require_exact_sources_still_closed: Callable[
            [Sequence[HistoricalPullReference], Sequence[int]], None
        ]
        | None = None,
    ) -> PreventionBatchOutcome: ...

    def propose(
        self,
        *,
        policy: RepositoryPolicy,
        recurrence_candidates: Sequence[RecurrenceCandidate],
        evidence_revision_ids: Mapping[str, int],
        run_id: str,
        observed_at: datetime,
        require_live_lease: Callable[[], None],
        require_cleanup_lease: Callable[[], None] | None = None,
        require_current_base_unchanged: Callable[[], None],
        open_source: OpenPullAuthorityReference | None = None,
        source_pulls: Sequence[HistoricalPullReference] = (),
        source_event_revision_ids: Sequence[int] = (),
        require_exact_open_source_authority: Callable[
            [OpenPullAuthorityReference, Sequence[int]], None
        ]
        | None = None,
        require_exact_sources_still_closed: Callable[
            [Sequence[HistoricalPullReference], Sequence[int]], None
        ]
        | None = None,
    ) -> PreventionBatchOutcome: ...


class RemediationRunner(Protocol):
    """Narrow draft-only publisher for current-base historical corrections."""

    def begin_poll(self) -> None: ...

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
    ) -> RemediationDraftResult: ...

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
    ) -> RemediationBatchOutcome: ...

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
    ) -> RemediationBatchOutcome: ...


@dataclass(frozen=True)
class PollOutcome:
    """Secret-free summary of one bounded poll."""

    lease_acquired: bool
    repositories_polled: int = 0
    pull_requests_seen: int = 0
    historical_repositories_polled: int = 0
    historical_pull_requests_seen: int = 0
    historical_pull_requests_completed: int = 0
    historical_policy_rejections: int = 0
    historical_items_deferred: int = 0
    feedback_revisions_recorded: int = 0
    runs_started: int = 0
    runs_completed: int = 0
    runs_failed: int = 0
    prepared_value_edits: int = 0
    applied_commits: tuple[str, ...] = ()
    prevention_drafts_created: int = 0
    prevention_items_skipped: int = 0
    prevention_items_deferred: int = 0
    prevention_failures: tuple[str, ...] = ()
    remediation_drafts_created: int = 0
    remediation_items_deferred: int = 0
    remediation_failures: tuple[str, ...] = ()
    authentication_circuit_open: bool = False
    model_circuit_open: bool = False
    raw_bodies_purged: int = 0
    failures: tuple[str, ...] = ()


@dataclass
class _PollAccumulator:
    lease_acquired: bool = True
    repositories_polled: int = 0
    pull_requests_seen: int = 0
    historical_repositories_polled: int = 0
    historical_pull_requests_seen: int = 0
    historical_pull_requests_completed: int = 0
    historical_policy_rejections: int = 0
    historical_items_deferred: int = 0
    feedback_revisions_recorded: int = 0
    runs_started: int = 0
    runs_completed: int = 0
    runs_failed: int = 0
    prepared_value_edits: int = 0
    applied_commits: list[str] = field(default_factory=list)
    prevention_drafts_created: int = 0
    prevention_items_skipped: int = 0
    prevention_items_deferred: int = 0
    prevention_failures: list[str] = field(default_factory=list)
    remediation_drafts_created: int = 0
    remediation_items_deferred: int = 0
    remediation_failures: list[str] = field(default_factory=list)
    authentication_circuit_open: bool = False
    model_circuit_open: bool = False
    raw_bodies_purged: int = 0
    failures: list[str] = field(default_factory=list)

    def freeze(self) -> PollOutcome:
        return PollOutcome(
            lease_acquired=self.lease_acquired,
            repositories_polled=self.repositories_polled,
            pull_requests_seen=self.pull_requests_seen,
            historical_repositories_polled=self.historical_repositories_polled,
            historical_pull_requests_seen=self.historical_pull_requests_seen,
            historical_pull_requests_completed=(
                self.historical_pull_requests_completed
            ),
            historical_policy_rejections=self.historical_policy_rejections,
            historical_items_deferred=self.historical_items_deferred,
            feedback_revisions_recorded=self.feedback_revisions_recorded,
            runs_started=self.runs_started,
            runs_completed=self.runs_completed,
            runs_failed=self.runs_failed,
            prepared_value_edits=self.prepared_value_edits,
            applied_commits=tuple(self.applied_commits),
            prevention_drafts_created=self.prevention_drafts_created,
            prevention_items_skipped=self.prevention_items_skipped,
            prevention_items_deferred=self.prevention_items_deferred,
            prevention_failures=tuple(self.prevention_failures),
            remediation_drafts_created=self.remediation_drafts_created,
            remediation_items_deferred=self.remediation_items_deferred,
            remediation_failures=tuple(self.remediation_failures),
            authentication_circuit_open=self.authentication_circuit_open,
            model_circuit_open=self.model_circuit_open,
            raw_bodies_purged=self.raw_bodies_purged,
            failures=tuple(self.failures),
        )


@dataclass(frozen=True)
class _TargetScope:
    config_path: Path
    config_root: Path
    source_root: Path
    config_bundle_digest: str | None
    path_locales: Mapping[str, str]
    changed_files: Mapping[str, ChangedFile]


@dataclass(frozen=True)
class _HistoricalAssessment:
    snapshot: PullRequestFeedbackSnapshot
    pull_revision_digest: str
    authority_digest: str
    policy_digest: str
    run_id: str
    events: tuple[FeedbackEvent, ...]
    revisions: tuple[EventRevision, ...]
    assessments: tuple[GuardianAssessment, ...]
    current_scope: _TargetScope
    replacements: tuple[ProposedReplacement, ...]
    recurrence_candidates: tuple[RecurrenceCandidate, ...]
    feedback_urls: tuple[str, ...]
    deferred_replacements: int = 0


@dataclass(frozen=True)
class _HistoricalIntake:
    """Authorized immutable history inputs prepared by one old-base checkout."""

    old_scope: _TargetScope
    historical_head: HistoricalRevision
    authorized: AuthorizedFeedback
    tombstones: tuple[FeedbackEvent, ...]
    historical_digest: str


@dataclass(frozen=True)
class _CurrentLocalizationIdentity:
    """Canonical current evidence identity and its assessable target paths."""

    digest: str
    applicable_paths: frozenset[str]

    @property
    def applicable(self) -> bool:
        """Return whether at least one target remains assessable."""

        return bool(self.applicable_paths)


class _HistoricalPolicyRejection(RuntimeError):
    """A stable intake-policy rejection resolved by the current policy digest."""


class _UnmappedLocalizationTarget(ValueError):
    """A changed path no longer maps to exactly one configured target locale."""


class _HistoricalNoAction(RuntimeError):
    """The exact current base no longer contains an applicable target."""


class _HistoricalCurrentBaseChanged(RuntimeError):
    """The trusted current-base snapshot changed before terminal completion."""


class _AuthenticationCircuit(RuntimeError):
    """Internal signal that no more model calls may run in this poll."""


class _ModelCircuit(RuntimeError):
    """Internal signal that provider capacity cannot recover during this poll."""


class _BudgetUnavailable(RuntimeError):
    """Internal signal raised before an unbudgeted model attempt can start."""


class _ModelCallLimitUnavailable(RuntimeError):
    """Internal signal raised before exceeding the daily provider-call cap."""


class _HistoricalLimitDeferred(RuntimeError):
    """Internal signal to stop history while retaining the first deferred cursor."""


class _ModelCredentialUnavailable(RuntimeError):
    """Internal signal that the model credential helper failed closed."""


class _LeaseLost(RuntimeError):
    """Internal circuit breaker forbidding all later state and remote writes."""


class _PublicationRecoveryManualRequired(RuntimeError):
    """A remotely present legacy commit has no safe recovery provenance."""


class _PublicationRecoveryBacklog(RuntimeError):
    """Bounded publication recovery must finish before new repository work."""


def _safe_failure_name(error: BaseException) -> str:
    """Return an audit-safe failure identifier without untrusted text."""

    return type(error).__name__


def _validated_retry_source_batches(
    value: object,
) -> tuple[tuple[HistoricalPullReference, ...], ...]:
    """Validate the coordinator's single atomic source-recovery group."""

    message = "Remediation runner returned a malformed outcome."
    if not isinstance(value, tuple) or len(value) > 1:
        raise TypeError(message)

    flattened: list[HistoricalPullReference] = []
    for batch in value:
        if not isinstance(batch, tuple) or not batch:
            raise TypeError(message)
        if any(not isinstance(source, HistoricalPullReference) for source in batch):
            raise TypeError(message)
        flattened.extend(batch)
    if len(flattened) > 100:
        raise TypeError(message)

    exact_identities: set[tuple[str, int, int, int]] = set()
    repository_ids: dict[str, int] = {}
    repository_names: dict[int, str] = {}
    numbers_by_pull: dict[tuple[str, int, int], int] = {}
    pulls_by_number: dict[tuple[str, int, int], int] = {}
    for source in flattened:
        exact_identity = (
            source.repository,
            source.repository_id,
            source.pull_id,
            source.pr_number,
        )
        pull_identity = (
            source.repository,
            source.repository_id,
            source.pull_id,
        )
        number_identity = (
            source.repository,
            source.repository_id,
            source.pr_number,
        )
        if (
            exact_identity in exact_identities
            or repository_ids.setdefault(
                source.repository,
                source.repository_id,
            )
            != source.repository_id
            or repository_names.setdefault(
                source.repository_id,
                source.repository,
            )
            != source.repository
            or numbers_by_pull.setdefault(pull_identity, source.pr_number)
            != source.pr_number
            or pulls_by_number.setdefault(number_identity, source.pull_id)
            != source.pull_id
        ):
            raise TypeError(message)
        exact_identities.add(exact_identity)
    return value


def _utc_now() -> datetime:
    return datetime.now(_UTC)


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("Guardian controller clock must be timezone-aware.")
    return value.astimezone(_UTC)


def _split_repository(full_name: str) -> tuple[str, str]:
    parts = full_name.split("/")
    if len(parts) != 2 or not all(parts):
        raise ValueError("Repository identity must use owner/name form.")
    return parts[0], parts[1]


def _exact_revisions(
    policy: RepositoryPolicy,
    snapshot: PullRequestFeedbackSnapshot,
    *,
    github_host: str,
) -> tuple[HistoricalRevision, ExactRevision]:
    """Pin a read-only historical base and a live-authorized writable head."""
    pull = snapshot.pull_request
    base_owner, base_name = _split_repository(policy.base_repo)
    head_owner, head_name = _split_repository(pull.head_repository)
    base = HistoricalRevision(
        host=github_host,
        owner=base_owner,
        repository=base_name,
        sha=pull.base_sha,
    )
    head = ExactRevision(
        host=github_host,
        owner=head_owner,
        repository=head_name,
        ref=f"refs/heads/{pull.head_ref}",
        sha=pull.head_sha,
    )
    return base, head


def _canonical_digest_value(value: object) -> object:
    """Convert typed policy data into a deterministic JSON value."""

    if isinstance(value, Enum):
        return value.value
    if is_dataclass(value) and not isinstance(value, type):
        return {
            item.name: _canonical_digest_value(getattr(value, item.name))
            for item in fields(value)
        }
    if isinstance(value, Mapping):
        if any(not isinstance(key, str) for key in value):
            raise TypeError("Canonical digest mappings require string keys.")
        return {key: _canonical_digest_value(value[key]) for key in sorted(value)}
    if isinstance(value, (tuple, list)):
        return [_canonical_digest_value(item) for item in value]
    if isinstance(value, Path):
        return value.as_posix()
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    raise TypeError("Canonical digest input contains an unsupported value.")


def _canonical_digest(value: object) -> str:
    encoded = json.dumps(
        _canonical_digest_value(value),
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _patch_policy_digest(
    config: GuardianConfig, policy: RepositoryPolicy, scope: _TargetScope
) -> str:
    """Keep rejected proposals retryable when their trusted policy changes."""
    return _canonical_digest(
        {
            "version": 1,
            "repository_policy": policy,
            "mode": config.mode,
            "max_value_edits": config.limits.max_value_edits_per_run,
            "minimum_confidence": config.limits.min_apply_confidence,
            "replacement_locale_authority_version": 1,
            "evidence_contract_version": EVIDENCE_CONTRACT_VERSION,
            "pipeline_config_bundle": scope.config_bundle_digest,
        }
    )


def _historical_pull_revision_digest(
    _policy: RepositoryPolicy,
    snapshot: PullRequestFeedbackSnapshot,
    *,
    feedback_events: Sequence[FeedbackEvent] = (),
) -> str:
    """Bind checkpoints to authority state and exactly authorized feedback."""

    feedback: list[dict[str, object]] = []
    for revision in feedback_events:
        # Deletion tombstones are durable audit facts, not current authority.
        # Including them would make the authority digest depend on whether the
        # Guardian happened to observe an object before it was deleted.  Only
        # currently live, authorized feedback may authorize a mutation.
        if revision.deleted:
            continue
        item = {
            field.name: getattr(revision, field.name)
            for field in fields(revision)
            if field.name != "author"
        }
        feedback.append(item)
    feedback.sort(
        key=lambda item: (
            str(item["kind"]),
            str(item["event_id"]),
            str(item["updated_at"]),
        )
    )

    pull = snapshot.pull_request
    pull_authority = {
        "repository": pull.repository,
        "base_repository_id": pull.base_repository_id,
        "pull_id": pull.pull_id,
        "number": pull.number,
        "state": pull.state,
        "created_at": pull.created_at,
        "author_id": pull.author_id,
        "author_type": pull.author_type,
        "head_sha": pull.head_sha,
        "head_ref": pull.head_ref,
        "head_owner_id": pull.head_owner_id,
        "head_owner_type": pull.head_owner_type,
        "head_repository": pull.head_repository,
        "head_repository_id": pull.head_repository_id,
        "base_sha": pull.base_sha,
        "base_ref": pull.base_ref,
    }
    changed_files = sorted(
        snapshot.changed_files,
        key=lambda item: (
            item.path,
            item.status,
            item.sha,
            item.previous_path or "",
        ),
    )
    return _canonical_digest(
        {
            "repository_identity": snapshot.repository_identity,
            "pull_authority": pull_authority,
            "changed_files": changed_files,
            "trusted_feedback": feedback,
        }
    )


def _open_pull_feedback_digest(
    snapshot: PullRequestFeedbackSnapshot,
    *,
    feedback_events: Sequence[FeedbackEvent],
) -> str:
    """Bind trusted feedback while allowing only Guardian's known head advance."""

    feedback: list[dict[str, object]] = []
    for event in feedback_events:
        if event.deleted:
            continue
        feedback.append(
            {
                field.name: getattr(event, field.name)
                for field in fields(event)
                if field.name not in {"author", "head_sha", "base_sha"}
            }
        )
    feedback.sort(
        key=lambda item: (
            str(item["kind"]),
            str(item["event_id"]),
            str(item["updated_at"]),
        )
    )
    pull = snapshot.pull_request
    return _canonical_digest(
        {
            "repository_identity": snapshot.repository_identity,
            "pull_authority": {
                "repository": pull.repository,
                "base_repository_id": pull.base_repository_id,
                "pull_id": pull.pull_id,
                "number": pull.number,
                "state": pull.state,
                "created_at": pull.created_at,
                "author_id": pull.author_id,
                "author_type": pull.author_type,
                "head_ref": pull.head_ref,
                "head_owner_id": pull.head_owner_id,
                "head_owner_type": pull.head_owner_type,
                "head_repository": pull.head_repository,
                "head_repository_id": pull.head_repository_id,
                "base_ref": pull.base_ref,
            },
            "trusted_feedback": feedback,
        }
    )


def _repository_route_alias(
    snapshot: PullRequestFeedbackSnapshot,
    *,
    repository: str,
) -> PullRequestFeedbackSnapshot:
    """Recreate durable authority hashes across a base-repository rename.

    GitHub's immutable repository ID remains authoritative, but several API
    display fields and feedback URLs adopt the current owner/name route.  This
    helper is used only for hashing already-authorized live evidence; network
    reads always use the current policy route.
    """

    current = snapshot.repository_identity.full_name
    pull = snapshot.pull_request
    if (
        snapshot.repository_identity.repository_id != pull.base_repository_id
        or pull.repository != current
    ):
        raise ValueError("Snapshot repository identity is inconsistent.")

    route_marker = f"/{current}/"
    alias_marker = f"/{repository}/"

    def alias_url(value: str) -> str:
        return value.replace(route_marker, alias_marker, 1)

    return replace(
        snapshot,
        repository_identity=replace(
            snapshot.repository_identity,
            full_name=repository,
        ),
        pull_request=replace(
            pull,
            repository=repository,
            html_url=alias_url(pull.html_url),
            head_repository=(
                repository
                if pull.head_repository_id == pull.base_repository_id
                else pull.head_repository
            ),
            base_repository=(
                repository
                if pull.base_repository in {"", current}
                else pull.base_repository
            ),
        ),
        feedback=tuple(
            replace(
                item,
                repository=repository,
                html_url=alias_url(item.html_url),
            )
            for item in snapshot.feedback
        ),
    )


def _feedback_repository_alias(
    events: Sequence[FeedbackEvent],
    *,
    current_repository: str,
    repository: str,
) -> tuple[FeedbackEvent, ...]:
    """Normalize authorized feedback display routes for durable hashing."""

    marker = f"/{current_repository}/"
    replacement = f"/{repository}/"
    return tuple(
        replace(
            event,
            repository=repository,
            html_url=(
                None
                if event.html_url is None
                else event.html_url.replace(marker, replacement, 1)
            ),
        )
        for event in events
    )


def _historical_policy_digest(
    *,
    config: GuardianConfig,
    policy: RepositoryPolicy,
    model: str,
    pipeline_config_bundle_digest: str,
) -> str:
    """Bind completion to all authority and assessment inputs."""

    return _canonical_digest(
        {
            "assessment": {
                "minimum_confidence": config.limits.min_apply_confidence,
                "model": model,
                "reasoning_effort": config.runtime.codex_reasoning_effort,
            },
            "controller_implementation_version": _HISTORICAL_CONTROLLER_VERSION,
            "mode": config.mode,
            "pipeline_config_bundle": pipeline_config_bundle_digest,
            "repository_policy": policy,
        }
    )


def _required_historical_scopes(
    config: GuardianConfig,
    policy: RepositoryPolicy,
) -> tuple[HistoricalCheckScope, ...]:
    scopes = [HistoricalCheckScope.ASSESSMENT]
    if (
        config.mode is GuardianMode.PROPOSE_PREVENTION
        and config.limits.max_prevention_drafts_per_run > 0
    ):
        scopes.append(HistoricalCheckScope.PREVENTION)
    backfill = policy.closed_pr_backfill
    if (
        config.mode
        in {
            GuardianMode.APPLY_OWNED_TRANSLATIONS,
            GuardianMode.PROPOSE_PREVENTION,
        }
        and backfill is not None
        and backfill.remediation is not None
        and config.limits.max_remediation_drafts_per_run > 0
    ):
        scopes.append(HistoricalCheckScope.REMEDIATION)
    return tuple(scopes)


def _historical_revisions(
    policy: RepositoryPolicy,
    snapshot: PullRequestFeedbackSnapshot,
    *,
    github_host: str,
) -> tuple[HistoricalRevision, HistoricalRevision]:
    owner, repository = _split_repository(policy.base_repo)
    pull = snapshot.pull_request
    return (
        HistoricalRevision(
            host=github_host,
            owner=owner,
            repository=repository,
            sha=pull.base_sha,
        ),
        HistoricalRevision(
            host=github_host,
            owner=owner,
            repository=repository,
            sha=pull.head_sha,
            pull_number=pull.number,
        ),
    )


def _current_exact_revision(
    policy: RepositoryPolicy,
    snapshot: BaseRevisionSnapshot,
    *,
    github_host: str,
) -> ExactRevision:
    identity = snapshot.repository_identity
    if (
        identity.full_name != policy.base_repo
        or identity.repository_id != policy.base_repo_id
        or snapshot.branch != policy.base_branch
    ):
        raise ValueError("Current base snapshot does not match repository policy.")
    if identity.private and not policy.private_repo_model_opt_in:
        raise _HistoricalPolicyRejection(
            "Current private repository has no model-processing opt-in."
        )
    owner, repository = _split_repository(policy.base_repo)
    return ExactRevision(
        host=github_host,
        owner=owner,
        repository=repository,
        ref=f"refs/heads/{policy.base_branch}",
        sha=snapshot.sha,
    )


def _trusted_file(root: Path, relative_path: str) -> Path:
    pure = PurePosixPath(relative_path)
    if pure.is_absolute() or any(part in {"", ".", ".."} for part in pure.parts):
        raise ValueError("Trusted pipeline config path is unsafe.")
    current = root
    for part in pure.parts:
        current = current / part
        if current.is_symlink():
            raise ValueError("Trusted pipeline config path contains a symbolic link.")
    resolved_root = root.resolve()
    resolved = current.resolve()
    try:
        resolved.relative_to(resolved_root)
    except ValueError as exc:
        raise ValueError(
            "Trusted pipeline config escapes the exact base checkout."
        ) from exc
    if not resolved.is_file():
        raise ValueError("Trusted pipeline config is not a regular file.")
    return resolved


def _base_pipeline_config_bundle_digest(
    *,
    config_root: Path,
    config_relative_path: str,
) -> str:
    """Hash the exact trusted base config and the glossary it resolves."""

    config_path = _trusted_file(config_root, config_relative_path)
    try:
        config_bytes = config_path.read_bytes()
        config_payload = yaml.safe_load(config_bytes)
    except (OSError, UnicodeDecodeError, yaml.YAMLError) as exc:
        raise ValueError("Trusted pipeline config could not be loaded.") from exc
    if not isinstance(config_payload, Mapping):
        raise ValueError("Trusted pipeline config must contain a mapping.")

    configured_glossary = config_payload.get("glossary_file_path")
    if configured_glossary is not None and not isinstance(configured_glossary, str):
        raise ValueError("Trusted pipeline glossary path must be a string.")
    glossary_relative = PurePosixPath(configured_glossary or "glossary.json")
    if (
        glossary_relative.is_absolute()
        or any(part in {"", ".", ".."} for part in glossary_relative.parts)
        or "\\" in glossary_relative.as_posix()
    ):
        raise ValueError("Trusted pipeline glossary path is unsafe.")
    config_relative = PurePosixPath(config_relative_path)
    resolved_glossary_relative = PurePosixPath(
        *config_relative.parent.parts,
        *glossary_relative.parts,
    )
    glossary_candidate = config_root.joinpath(*resolved_glossary_relative.parts)
    explicit_glossary = configured_glossary is not None
    glossary_bytes: bytes | None = None
    if (
        explicit_glossary
        or glossary_candidate.exists()
        or glossary_candidate.is_symlink()
    ):
        glossary_path = _trusted_file(
            config_root,
            resolved_glossary_relative.as_posix(),
        )
        try:
            glossary_bytes = glossary_path.read_bytes()
            glossary_payload = json.loads(glossary_bytes.decode("utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("Trusted pipeline glossary could not be loaded.") from exc
        if not isinstance(glossary_payload, dict):
            raise ValueError("Trusted pipeline glossary must contain an object.")

    files = {config_relative.as_posix(): config_bytes}
    if glossary_bytes is not None:
        files[resolved_glossary_relative.as_posix()] = glossary_bytes
    return pipeline_config_bundle_digest(files)


def _load_base_profiles(
    config_path: Path,
    *,
    expected_source_locale: str,
) -> tuple[tuple[LocalizationProfile, ...], tuple[str, ...]]:
    try:
        config = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, yaml.YAMLError) as exc:
        raise ValueError("Trusted pipeline config could not be loaded.") from exc
    if not isinstance(config, Mapping):
        raise ValueError("Trusted pipeline config must contain a mapping.")
    raw_locales = config.get("supported_locales")
    if not isinstance(raw_locales, list):
        raise ValueError("Trusted pipeline config supported_locales must be a list.")
    locale_codes: list[str] = []
    for item in raw_locales:
        if isinstance(item, str) and item:
            locale_codes.append(item)
        elif isinstance(item, Mapping) and isinstance(item.get("code"), str):
            code = str(item["code"])
            if code:
                locale_codes.append(code)
    if not locale_codes:
        raise ValueError("Trusted pipeline config has no target locales.")
    try:
        profiles = load_localization_profiles(config)
    except (TypeError, ValueError) as exc:
        raise ValueError(
            "Trusted pipeline config has invalid localization profiles."
        ) from exc
    if str(config.get("source_locale") or "en") != expected_source_locale or any(
        profile.localization_layout.source_locale != expected_source_locale
        for profile in profiles
    ):
        raise ValueError(
            "Trusted pipeline config source locale does not match Guardian policy."
        )
    return profiles, tuple(dict.fromkeys(locale_codes))


def _canonical_changed_path(path: str) -> str:
    if (
        not path
        or "\\" in path
        or any(ord(character) < 32 or ord(character) == 127 for character in path)
    ):
        raise ValueError("Pull request contains an unsafe changed path.")
    pure = PurePosixPath(path)
    if (
        pure.is_absolute()
        or pure.as_posix() != path
        or any(part in {"", ".", ".."} for part in pure.parts)
    ):
        raise ValueError("Pull request contains an unsafe changed path.")
    return path


def _target_scope(
    *,
    base_root: Path,
    policy: RepositoryPolicy,
    changed_files: Sequence[ChangedFile],
    operator_pipeline_config: PipelineConfigSnapshot | None = None,
    base_config_bundle_digest: str | None = None,
    allow_unmapped_paths: bool = False,
) -> _TargetScope:
    if policy.pipeline_config_source is PipelineConfigSource.BASE:
        config_root = base_root
        config_path = _trusted_file(base_root, policy.pipeline_config_path)
        config_bundle_digest = base_config_bundle_digest
    else:
        if operator_pipeline_config is None:
            raise ValueError("Operator pipeline config snapshot is unavailable.")
        config_root = operator_pipeline_config.config_root
        try:
            relative_config = operator_pipeline_config.config_path.relative_to(
                config_root
            ).as_posix()
        except ValueError:
            raise ValueError(
                "Operator pipeline config snapshot escapes its private root."
            ) from None
        config_path = _trusted_file(config_root, relative_config)
        config_bundle_digest = operator_pipeline_config.bundle_digest
    profiles, locale_codes = _load_base_profiles(
        config_path,
        expected_source_locale=policy.source_locale,
    )
    if not changed_files:
        raise ValueError("Pull request has no changed files.")

    path_locales: dict[str, str] = {}
    files_by_path: dict[str, ChangedFile] = {}
    for changed_file in changed_files:
        path = _canonical_changed_path(changed_file.path)
        if path in files_by_path:
            raise ValueError("Pull request repeats a changed path.")
        if (
            changed_file.status not in _SUPPORTED_CHANGED_FILE_STATUSES
            or changed_file.previous_path is not None
        ):
            raise ValueError("Pull request uses an unsupported changed-file operation.")
        if not matches_any_path_glob(path, policy.allowed_path_globs):
            raise ValueError("Pull request changes a path outside Guardian policy.")

        matches: list[str] = []
        for profile in profiles:
            layout = profile.localization_layout
            file_format = profile.localization_format
            if not layout.is_target_file(path, locale_codes, file_format):
                continue
            locale = layout.extract_locale(path, locale_codes, file_format)
            if locale and locale != policy.source_locale:
                matches.append(locale)
        if len(matches) != 1:
            if allow_unmapped_paths:
                continue
            raise _UnmappedLocalizationTarget(
                "Every pull-request path must identify exactly one target locale."
            )
        path_locales[path] = matches[0]
        files_by_path[path] = changed_file
    return _TargetScope(
        config_path=config_path,
        config_root=config_root,
        source_root=base_root,
        config_bundle_digest=config_bundle_digest,
        path_locales=path_locales,
        changed_files=files_by_path,
    )


def _historical_target_scope(
    *,
    base_root: Path,
    policy: RepositoryPolicy,
    changed_files: Sequence[ChangedFile],
    operator_pipeline_config: PipelineConfigSnapshot | None,
) -> _TargetScope:
    """Separate stable PR-policy rejection from transient config I/O."""

    _preflight_historical_changed_files(policy, changed_files)
    try:
        return _target_scope(
            base_root=base_root,
            policy=policy,
            changed_files=changed_files,
            operator_pipeline_config=operator_pipeline_config,
        )
    except _UnmappedLocalizationTarget as exc:
        raise _HistoricalPolicyRejection(str(exc)) from None


def _preflight_historical_changed_files(
    policy: RepositoryPolicy,
    changed_files: Sequence[ChangedFile],
) -> None:
    """Reject stable path/status policy violations without touching a checkout."""

    if not changed_files:
        raise _HistoricalPolicyRejection("Historical pull has no changed files.")
    seen: set[str] = set()
    for changed_file in changed_files:
        try:
            path = _canonical_changed_path(changed_file.path)
        except ValueError as exc:
            raise _HistoricalPolicyRejection(str(exc)) from None
        if path in seen:
            raise _HistoricalPolicyRejection("Historical pull repeats a changed path.")
        seen.add(path)
        if (
            changed_file.status not in _SUPPORTED_CHANGED_FILE_STATUSES
            or changed_file.previous_path is not None
        ):
            raise _HistoricalPolicyRejection(
                "Historical pull uses an unsupported changed-file operation."
            )
        if not matches_any_path_glob(path, policy.allowed_path_globs):
            raise _HistoricalPolicyRejection(
                "Historical pull changes a path outside Guardian policy."
            )


def _historical_regular_target_paths(
    root: Path,
    paths: Sequence[str],
) -> frozenset[str]:
    """Return API-reported targets that are regular files in the old head."""

    resolved_root = root.resolve(strict=True)
    regular_paths: set[str] = set()
    for path in paths:
        pure = PurePosixPath(_canonical_changed_path(path))
        candidate = root.joinpath(*pure.parts)
        current = root
        try:
            for component in pure.parts[:-1]:
                current = current / component
                metadata = current.lstat()
                if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
                    break
            else:
                metadata = candidate.lstat()
                if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                    continue
                try:
                    candidate.resolve(strict=True).relative_to(resolved_root)
                except ValueError:
                    continue
                regular_paths.add(path)
        except FileNotFoundError:
            continue
        except OSError:
            raise
    return frozenset(regular_paths)


def _current_historical_target_scope(
    *,
    base_root: Path,
    policy: RepositoryPolicy,
    old_scope: _TargetScope,
    operator_pipeline_config: PipelineConfigSnapshot | None,
    base_config_bundle_digest: str | None,
) -> tuple[_TargetScope, dict[str, str]]:
    """Map current targets independently without weakening intake policy."""

    current_scope = _target_scope(
        base_root=base_root,
        policy=policy,
        changed_files=tuple(old_scope.changed_files.values()),
        operator_pipeline_config=operator_pipeline_config,
        base_config_bundle_digest=base_config_bundle_digest,
        allow_unmapped_paths=True,
    )
    unavailable: dict[str, str] = {}
    retained_locales: dict[str, str] = {}
    retained_files: dict[str, ChangedFile] = {}
    for path, historical_locale in old_scope.path_locales.items():
        current_locale = current_scope.path_locales.get(path)
        if current_locale is None:
            unavailable[path] = "unmapped"
            continue
        if current_locale != historical_locale:
            unavailable[path] = "locale_changed"
            continue
        retained_locales[path] = current_locale
        retained_files[path] = current_scope.changed_files[path]
    return (
        _TargetScope(
            config_path=current_scope.config_path,
            config_root=current_scope.config_root,
            source_root=current_scope.source_root,
            config_bundle_digest=current_scope.config_bundle_digest,
            path_locales=retained_locales,
            changed_files=retained_files,
        ),
        unavailable,
    )


def _current_localization_content_digest(
    *,
    root: Path,
    scope: _TargetScope,
    policy: RepositoryPolicy,
    events: Sequence[FeedbackEvent],
    historical_path_locales: Mapping[str, str] | None = None,
    unavailable_paths: Mapping[str, str] | None = None,
) -> _CurrentLocalizationIdentity:
    """Hash the canonical current evidence visible to authorized feedback."""

    profiles, locale_codes = _load_base_profiles(
        scope.config_path,
        expected_source_locale=policy.source_locale,
    )
    path_locales = historical_path_locales or scope.path_locales
    unavailable_paths = unavailable_paths or {}
    relevant_paths: set[str] = set()
    for event in events:
        if event.path is not None:
            if path_locales.get(event.path) != event.locale:
                raise ValueError(
                    "Authorized historical feedback no longer matches its target."
                )
            relevant_paths.add(event.path)
            continue
        relevant_paths.update(
            path for path, locale in path_locales.items() if locale == event.locale
        )
    if not relevant_paths:
        raise ValueError("Historical feedback has no relevant current target files.")

    max_file_bytes = 2 * 1024 * 1024

    def content_identity(relative_path: str) -> tuple[Path | None, dict[str, object]]:
        try:
            path = _trusted_file(root, relative_path)
        except ValueError:
            return None, {"status": "unavailable"}
        try:
            size = path.stat(follow_symlinks=False).st_size
            if size > max_file_bytes:
                return None, {"size": size, "status": "oversize"}
            raw = path.read_bytes()
            if len(raw) > max_file_bytes:
                return None, {"size": len(raw), "status": "oversize"}
            return path, {"status": "regular"}
        except OSError as exc:
            raise ValueError("Current localization input could not be read.") from exc

    payload: list[dict[str, object]] = []
    applicable_paths: set[str] = set()
    for target_path in sorted(relevant_paths):
        if target_path in unavailable_paths:
            payload.append(
                {
                    "locale": path_locales[target_path],
                    "path": target_path,
                    "status": unavailable_paths[target_path],
                }
            )
            continue
        locale = scope.path_locales[target_path]
        matches = tuple(
            profile
            for profile in profiles
            if profile.localization_layout.is_target_file(
                target_path,
                locale_codes,
                profile.localization_format,
            )
            and profile.localization_layout.extract_locale(
                target_path,
                locale_codes,
                profile.localization_format,
            )
            == locale
        )
        if len(matches) != 1:
            raise ValueError("Current target has an ambiguous localization profile.")
        source_path = matches[0].localization_layout.source_path_for_target(
            target_path,
            locale_codes,
            matches[0].localization_format,
        )
        target_file, target_identity = content_identity(target_path)
        source_file, source_identity = content_identity(source_path)
        item: dict[str, object] = {
            "format": matches[0].localization_format.id,
            "locale": locale,
            "path": target_path,
            "source_path": source_path,
        }
        if target_file is None or source_file is None:
            item["target"] = target_identity
            item["source"] = source_identity
            payload.append(item)
            continue
        adapter = get_localization_adapter(matches[0].localization_format)
        try:
            _target_lines, target_values = adapter.parse_file(str(target_file))
            _source_lines, source_values = adapter.parse_file(str(source_file))
        except (OSError, UnicodeDecodeError, ValueError):
            try:
                target_hash = hashlib.sha256(target_file.read_bytes()).hexdigest()
                source_hash = hashlib.sha256(source_file.read_bytes()).hexdigest()
            except OSError as exc:
                raise ValueError(
                    "Current localization input could not be read."
                ) from exc
            item["target"] = {
                "sha256": target_hash,
                "status": "unparseable",
            }
            item["source"] = {
                "sha256": source_hash,
                "status": "unparseable",
            }
            payload.append(item)
            continue
        item["entries"] = {
            key: {
                "source": source_values[key],
                "target": target_values[key],
            }
            for key in sorted(set(source_values) & set(target_values))
        }
        item["source_values"] = dict(source_values)
        item["target_values"] = dict(target_values)
        payload.append(item)
        applicable_paths.add(target_path)
    return _CurrentLocalizationIdentity(
        digest=_canonical_digest(payload),
        applicable_paths=frozenset(applicable_paths),
    )


def _partition_historical_events(
    events: Sequence[FeedbackEvent],
    *,
    path_locales: Mapping[str, str],
    applicable_paths: frozenset[str],
) -> tuple[tuple[FeedbackEvent, ...], tuple[FeedbackEvent, ...]]:
    """Partition events by whether any exact target in their scope is usable."""

    applicable: list[FeedbackEvent] = []
    inapplicable: list[FeedbackEvent] = []
    for event in events:
        if event.path is not None:
            event_is_applicable = (
                path_locales.get(event.path) == event.locale
                and event.path in applicable_paths
            )
        else:
            event_is_applicable = any(
                path in applicable_paths and locale == event.locale
                for path, locale in path_locales.items()
            )
        (applicable if event_is_applicable else inapplicable).append(event)
    return tuple(applicable), tuple(inapplicable)


def _stored_feedback(
    revisions: Sequence[EventRevision],
) -> tuple[FeedbackRevision, ...]:
    previous: list[FeedbackRevision] = []
    for revision in revisions:
        try:
            kind = FeedbackKind(revision.kind)
        except ValueError:
            continue
        timestamp = revision.updated_at or revision.observed_at.isoformat()
        previous.append(
            FeedbackRevision(
                repository=revision.repository,
                pull_number=revision.pr_number,
                kind=kind,
                source_id=revision.event_id,
                node_id=None,
                author_login=revision.author,
                author_id=revision.author_id,
                author_type=revision.author_type,
                body=revision.body or "",
                created_at=timestamp,
                updated_at=timestamp,
                html_url=revision.html_url or "",
                path=revision.path,
                line=revision.line,
                commit_id=revision.head_sha,
                deleted=revision.deleted,
            )
        )
    return tuple(previous)


def _trusted_tombstones(
    *,
    policy: RepositoryPolicy,
    snapshot: PullRequestFeedbackSnapshot,
    previous: Sequence[EventRevision],
) -> tuple[FeedbackEvent, ...]:
    previous_by_object = {
        (revision.kind, revision.event_id): revision for revision in previous
    }
    pull = snapshot.pull_request
    events: list[FeedbackEvent] = []
    for revision in snapshot.feedback:
        if not revision.deleted:
            continue
        prior = previous_by_object.get((revision.kind.value, revision.source_id))
        if prior is None or prior.deleted or revision.author_id is None:
            continue
        trusted_actor = policy.trusted_reviewer_by_id(prior.locale, revision.author_id)
        if trusted_actor is None:
            trusted_actor = policy.trusted_bot_by_id(prior.locale, revision.author_id)
        if trusted_actor is None or trusted_actor.type != revision.author_type:
            continue
        events.append(
            FeedbackEvent(
                repository=policy.base_repo,
                pr_number=pull.number,
                kind=revision.kind.value,
                event_id=revision.source_id,
                author=revision.author_login,
                author_id=revision.author_id,
                author_type=revision.author_type,
                body="",
                head_sha=pull.head_sha,
                base_sha=pull.base_sha,
                locale=prior.locale,
                updated_at=revision.updated_at,
                path=revision.path if revision.path is not None else prior.path,
                line=revision.line if revision.line is not None else prior.line,
                html_url=revision.html_url or prior.html_url,
                deleted=True,
            )
        )
    return tuple(events)


def _diff_text(
    paths: Sequence[str],
    changed_files: Mapping[str, ChangedFile],
) -> str:
    sections: list[str] = []
    for path in sorted(paths):
        patch = changed_files[path].patch
        sections.append(
            f"diff --git a/{path} b/{path}\n"
            + (patch.rstrip("\n") + "\n" if patch else "[patch unavailable]\n")
        )
    return "".join(sections)


def _source_values(bundle: EvidenceBundle) -> dict[tuple[str, str], str]:
    try:
        payload = json.loads(
            (bundle.root / "localization.json").read_text(encoding="utf-8")
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(
            "Controller-generated localization evidence is unreadable."
        ) from exc
    result: dict[tuple[str, str], str] = {}
    if not isinstance(payload, list):
        raise ValueError("Controller-generated localization evidence is malformed.")
    for file_data in payload:
        if not isinstance(file_data, Mapping):
            raise ValueError("Controller-generated localization evidence is malformed.")
        path = file_data.get("path")
        entries = file_data.get("entries")
        if not isinstance(path, str) or not isinstance(entries, Mapping):
            raise ValueError("Controller-generated localization evidence is malformed.")
        for key, values in entries.items():
            if (
                not isinstance(key, str)
                or not isinstance(values, Mapping)
                or not isinstance(values.get("source"), str)
            ):
                raise ValueError(
                    "Controller-generated localization evidence is malformed."
                )
            result[(path, key)] = str(values["source"])
    return result


def _localization_values(
    bundle: EvidenceBundle,
) -> dict[tuple[str, str], tuple[str, str]]:
    """Read the exact current source/target pairs written into evidence."""

    try:
        payload = json.loads(
            (bundle.root / "localization.json").read_text(encoding="utf-8")
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(
            "Controller-generated localization evidence is unreadable."
        ) from exc
    if not isinstance(payload, list):
        raise ValueError("Controller-generated localization evidence is malformed.")
    result: dict[tuple[str, str], tuple[str, str]] = {}
    for file_data in payload:
        if not isinstance(file_data, Mapping):
            raise ValueError("Controller-generated localization evidence is malformed.")
        path = file_data.get("path")
        entries = file_data.get("entries")
        if not isinstance(path, str) or not isinstance(entries, Mapping):
            raise ValueError("Controller-generated localization evidence is malformed.")
        for key, values in entries.items():
            if (
                not isinstance(key, str)
                or not isinstance(values, Mapping)
                or not isinstance(values.get("source"), str)
                or not isinstance(values.get("target"), str)
            ):
                raise ValueError(
                    "Controller-generated localization evidence is malformed."
                )
            identity = (path, key)
            if identity in result:
                raise ValueError(
                    "Controller-generated localization evidence repeats a target."
                )
            result[identity] = (
                str(values["source"]),
                str(values["target"]),
            )
    return result


def _replacement_target_locales(
    policy: RepositoryPolicy,
    events: Sequence[FeedbackEvent],
    path_locales: Mapping[str, str],
) -> dict[str, dict[str, str]]:
    """Bind target locales to the pinned author's per-locale permissions."""
    authorized: dict[str, dict[str, str]] = {}
    for event in events:
        targets: dict[str, str] = {}
        if event.author_id is not None:
            for path, locale in path_locales.items():
                actors = (
                    policy.trusted_reviewer_by_id(locale, event.author_id),
                    policy.trusted_bot_by_id(locale, event.author_id),
                )
                if any(actor is not None and actor.type == event.author_type for actor in actors):
                    targets[path] = locale
        authorized[event.feedback_id] = targets
    return authorized


def _eligible_replacements(
    assessments: Sequence[GuardianAssessment],
    *,
    minimum_confidence: float,
    excluded_feedback_ids: frozenset[str] = frozenset(),
) -> tuple[ProposedReplacement, ...]:
    return tuple(
        replacement
        for assessment in assessments
        if assessment.feedback_id not in excluded_feedback_ids
        and assessment.verdict == "apply"
        and assessment.confidence >= minimum_confidence
        for replacement in assessment.replacements
        if replacement.confidence >= minimum_confidence
    )


def _validated_historical_replacements(
    assessments: Sequence[GuardianAssessment],
    *,
    current_values: Mapping[tuple[str, str], tuple[str, str]],
    minimum_confidence: float,
) -> tuple[tuple[ProposedReplacement, ...], int]:
    """Accept only proposals that repeat both exact current evidence values."""

    accepted: list[ProposedReplacement] = []
    deferred = 0
    for replacement in _eligible_replacements(
        assessments,
        minimum_confidence=minimum_confidence,
    ):
        values = current_values.get((replacement.path, replacement.key))
        if values is None:
            deferred += 1
            continue
        source_value, target_value = values
        if (
            replacement.expected_value != target_value
            or replacement.source_value != source_value
        ):
            deferred += 1
            continue
        if replacement.proposed_value == target_value:
            continue
        accepted.append(replacement)
    return tuple(accepted), deferred


def _dedupe_historical_replacements(
    work: Sequence[_HistoricalAssessment],
) -> tuple[
    tuple[ProposedReplacement, ...],
    frozenset[int],
]:
    """Stable-dedupe agreement and remove every conflicting target."""

    grouped: dict[
        tuple[str, str],
        list[tuple[_HistoricalAssessment, ProposedReplacement]],
    ] = {}
    for item in work:
        for replacement in item.replacements:
            grouped.setdefault((replacement.path, replacement.key), []).append(
                (item, replacement)
            )

    selected: list[ProposedReplacement] = []
    conflicted_pull_ids: set[int] = set()
    for entries in grouped.values():
        signatures = {
            (
                replacement.locale,
                replacement.expected_value,
                replacement.proposed_value,
                replacement.source_value,
            )
            for _item, replacement in entries
        }
        if len(signatures) != 1:
            conflicted_pull_ids.update(
                item.snapshot.pull_request.pull_id for item, _replacement in entries
            )
            continue
        selected.append(entries[0][1])
    return tuple(selected), frozenset(conflicted_pull_ids)


def _lease_ttl_seconds(config: GuardianConfig) -> int:
    """Outlive any one bounded operation plus scheduling and cleanup slack."""

    timeout = config.limits.run_timeout_seconds
    return max(timeout * 2, timeout + 300)


def _validated_historical_scan_items(
    result: ClosedPullScanResult,
    *,
    max_hydration_attempts: int,
) -> tuple[ClosedPullScanItem, ...]:
    """Validate one bounded restart-safe result from the GitHub adapter."""

    if not isinstance(result, ClosedPullScanResult):
        raise TypeError("Historical provider returned malformed scan data.")
    if not isinstance(result.cycle_complete, bool):
        raise TypeError("Historical provider returned malformed cycle state.")
    if len(result.items) > max_hydration_attempts:
        raise ValueError("Historical provider exceeded the hydration-attempt bound.")
    attempts = 0
    identities: set[tuple[int, int]] = set()
    numbers_by_id: dict[int, int] = {}
    ids_by_number: dict[int, int] = {}
    for item in result.items:
        if not isinstance(item, ClosedPullScanItem) or not isinstance(
            item.position,
            ClosedPullScanPosition,
        ):
            raise TypeError("Historical provider returned malformed scan data.")
        position = item.position
        if (
            isinstance(position.page, bool)
            or not isinstance(position.page, int)
            or not 1 <= position.page <= 100
            or isinstance(position.offset, bool)
            or not isinstance(position.offset, int)
            or not 0 <= position.offset < 100
            or position.cycle_complete
        ):
            raise ValueError("Historical provider returned an invalid scan position.")
        if (
            not item.hydration_attempted
            or (item.snapshot is None) == (item.failure_type is None)
            or isinstance(item.pull_id, bool)
            or not isinstance(item.pull_id, int)
            or item.pull_id <= 0
            or isinstance(item.pull_number, bool)
            or not isinstance(item.pull_number, int)
            or item.pull_number <= 0
        ):
            raise TypeError("Historical hydration outcome is malformed.")
        attempts += 1
        identity = (item.pull_id, item.pull_number)
        if identity in identities:
            raise ValueError("Historical provider repeated a pull identity.")
        if (
            item.pull_id in numbers_by_id
            and numbers_by_id[item.pull_id] != item.pull_number
        ) or (
            item.pull_number in ids_by_number
            and ids_by_number[item.pull_number] != item.pull_id
        ):
            raise ValueError("Historical provider returned an identity collision.")
        identities.add(identity)
        numbers_by_id[item.pull_id] = item.pull_number
        ids_by_number[item.pull_number] = item.pull_id
        if item.snapshot is not None:
            pull = item.snapshot.pull_request
            if (item.pull_id, item.pull_number) != (pull.pull_id, pull.number):
                raise ValueError("Historical scan item identity is inconsistent.")
        if item.failure_type is not None and not re.fullmatch(
            r"[A-Za-z_][A-Za-z0-9_]{0,127}",
            item.failure_type,
        ):
            raise ValueError("Historical provider returned an unsafe failure type.")
    if result.hydration_attempts != attempts or attempts > max_hydration_attempts:
        raise ValueError("Historical provider exceeded the hydration-attempt bound.")
    return result.items


class GuardianController:
    """Coordinate one safe polling pass across the configured repositories."""

    def __init__(
        self,
        *,
        config: GuardianConfig,
        state: GuardianState,
        snapshot_provider: SnapshotProvider,
        checkout_factory: CheckoutFactory,
        codex_driver: CodexRunner,
        model_credential_provider: Callable[[], str | None] | None = None,
        write_broker_factory: WriteBrokerFactory | None = None,
        prevention_runner: PreventionRunner | None = None,
        historical_snapshot_provider: HistoricalSnapshotProvider | None = None,
        historical_source_snapshot_provider: HistoricalSourceSnapshotProvider
        | None = None,
        historical_checkout_factory: HistoricalCheckoutFactory | None = None,
        current_base_provider: CurrentBaseProvider | None = None,
        remediation_runner: RemediationRunner | None = None,
        publish_credential_environment: Callable[[], Mapping[str, str]] | None = None,
        evidence_root: Path | None = None,
        now: Callable[[], datetime] = _utc_now,
        evidence_builder: Callable[..., EvidenceBundle] = build_evidence_bundle,
        replacement_applier: Callable[..., PatchResult] = apply_replacements,
        assessment_converter: Callable[
            ..., tuple[GuardianAssessment, ...]
        ] = to_guardian_assessments,
        github_host: str = "github.com",
        signing_key: str | None = None,
        signing_environment: Mapping[str, str] | None = None,
        operator_pipeline_configs: Mapping[str, PipelineConfigSnapshot] | None = None,
        publication_actor_preflight: Callable[[], None] | None = None,
        deadline: PollDeadline | None = None,
    ) -> None:
        if (
            config.mode
            in {
                GuardianMode.APPLY_OWNED_TRANSLATIONS,
                GuardianMode.PROPOSE_PREVENTION,
            }
            and write_broker_factory is None
        ):
            raise ValueError(
                "Apply-capable Guardian modes require a write broker factory."
            )
        if config.mode is GuardianMode.PROPOSE_PREVENTION and prevention_runner is None:
            raise ValueError("Propose-prevention mode requires a prevention runner.")
        historical_policies = tuple(
            policy
            for policy in config.repositories
            if policy.closed_pr_backfill is not None
        )
        if historical_policies and (
            historical_snapshot_provider is None
            or historical_checkout_factory is None
            or current_base_provider is None
        ):
            raise ValueError(
                "Closed-PR backfill requires historical intake, historical "
                "checkout, and current-base providers."
            )
        remediation_enabled = any(
            HistoricalCheckScope.REMEDIATION
            in _required_historical_scopes(config, policy)
            for policy in historical_policies
        )
        historical_prevention_enabled = any(
            HistoricalCheckScope.PREVENTION
            in _required_historical_scopes(config, policy)
            for policy in historical_policies
        )
        if remediation_enabled and remediation_runner is None:
            raise ValueError(
                "Apply-capable closed-PR remediation requires a remediation runner."
            )
        if (
            remediation_enabled or historical_prevention_enabled
        ) and historical_source_snapshot_provider is None:
            raise ValueError(
                "Closed-PR mutations require an exact source revalidation provider."
            )
        if config.enabled_publication_actors and publication_actor_preflight is None:
            raise ValueError(
                "Enabled publication policies require a pre-poll actor preflight."
            )
        self.config = config
        self.state = state
        self.snapshot_provider = snapshot_provider
        self.checkout_factory = checkout_factory
        self.codex_driver = codex_driver
        self.model_credential_provider = model_credential_provider
        self.write_broker_factory = write_broker_factory
        self.prevention_runner = prevention_runner
        self.historical_snapshot_provider = historical_snapshot_provider
        self.historical_source_snapshot_provider = historical_source_snapshot_provider
        self.historical_checkout_factory = historical_checkout_factory
        self.current_base_provider = current_base_provider
        self.remediation_runner = remediation_runner
        self.publish_credential_environment = publish_credential_environment
        self.evidence_root = evidence_root
        self.now = now
        self.evidence_builder = evidence_builder
        self.replacement_applier = replacement_applier
        self.assessment_converter = assessment_converter
        self.github_host = github_host
        self.signing_key = (
            signing_key if signing_key is not None else config.runtime.signing_key
        )
        self.signing_environment = signing_environment
        self.operator_pipeline_configs = dict(operator_pipeline_configs or {})
        self.publication_actor_preflight = publication_actor_preflight
        self.deadline = deadline

    def _require_no_open_translation_overlap(
        self,
        *,
        policy: RepositoryPolicy,
        candidate_paths: Sequence[str],
        excluded_pull: OpenPullPathIdentity | None,
        require_live_lease: Callable[[], None],
    ) -> None:
        """Refresh and validate complete open-PR path authority before a write."""

        paths = _bounded_repository_paths(
            candidate_paths,
            limit=_MAX_REMEDIATION_CHANGED_PATHS,
            label="Remediation candidate paths",
            allow_empty=False,
        )
        collect = getattr(
            self.snapshot_provider,
            "collect_open_changed_paths",
            None,
        )
        if not callable(collect):
            raise RemediationOpenPullAuthorityError(
                "Complete open-PR path revalidation is unavailable."
            )
        require_live_lease()
        try:
            authorities = collect(policy)
            _assert_no_open_translation_overlap(
                policy=policy,
                candidate_paths=paths,
                authorities=authorities,
                excluded_pull=excluded_pull,
            )
        except (
            _LeaseLost,
            PreventionLeaseLostError,
            PollDeadlineExceeded,
            GitHubAuthenticationError,
            RemediationOpenPullAuthorityError,
        ):
            raise
        except Exception as exc:
            raise RemediationOpenPullAuthorityError(
                "Complete open-PR path revalidation failed closed."
            ) from exc
        require_live_lease()

    def poll_once(self) -> PollOutcome:
        """Run one finite poll, never retrying at the orchestration layer."""

        observed_at = _as_utc(self.now())
        owner = str(uuid4())
        lease_name = "guardian:poll"
        acquired = self.state.acquire_lease(
            name=lease_name,
            owner=owner,
            ttl_seconds=_lease_ttl_seconds(self.config),
            now=observed_at,
        )
        if not acquired:
            return PollOutcome(lease_acquired=False)

        outcome = _PollAccumulator()
        lease_lost = False
        open_poll_succeeded: set[str] = set()
        open_changed_paths: dict[str, frozenset[str]] = {}
        try:
            if self.publication_actor_preflight is not None:
                try:
                    self.publication_actor_preflight()
                except PollDeadlineExceeded:
                    raise
                except GitHubAuthenticationError:
                    outcome.authentication_circuit_open = True
                    self.state.record_health(
                        component="github",
                        status="failed",
                        message=(
                            "GitHub publication actor preflight failed; no poll "
                            "writes were attempted."
                        ),
                        details={"circuit_open": True},
                        checked_at=observed_at,
                    )
                except Exception as exc:
                    outcome.authentication_circuit_open = True
                    outcome.failures.append(_safe_failure_name(exc))
                    self.state.record_health(
                        component="controller",
                        status="failed",
                        message=("GitHub publication actor preflight failed closed."),
                        details={"failure_type": _safe_failure_name(exc)},
                        checked_at=observed_at,
                    )
            self.state.reconcile_incomplete_runs(
                before=observed_at
                - timedelta(seconds=self.config.limits.run_timeout_seconds),
                reconciled_at=observed_at,
            )
            if (
                self.config.mode is GuardianMode.PROPOSE_PREVENTION
                and not outcome.authentication_circuit_open
            ):
                # Constructor enforces this dependency for the only mode that
                # may use it.
                assert self.prevention_runner is not None
                self.prevention_runner.begin_poll()
                try:
                    self._require_live_lease(owner)
                    self._record_prevention_outcome(
                        self.prevention_runner.recover_orphans(
                            configured_policies=self.config.repositories,
                            observed_at=observed_at,
                            require_live_lease=lambda: self._require_live_lease(owner),
                        ),
                        outcome=outcome,
                    )
                except PollDeadlineExceeded:
                    raise
                except (_LeaseLost, PreventionLeaseLostError):
                    lease_lost = True
                    outcome.failures.append("LeaseLost")
                except GitHubAuthenticationError:
                    outcome.authentication_circuit_open = True
                    try:
                        self._require_live_lease(owner)
                    except _LeaseLost:
                        lease_lost = True
                        outcome.failures.append("LeaseLost")
                    else:
                        self.state.record_health(
                            component="github",
                            status="failed",
                            message=(
                                "Orphan prevention recovery authentication failed; "
                                "further GitHub calls stopped."
                            ),
                            details={"circuit_open": True},
                            checked_at=observed_at,
                        )
                except Exception as exc:
                    failure = _safe_failure_name(exc)
                    outcome.failures.append(failure)
                    outcome.prevention_failures.append(failure)
                    try:
                        self._require_live_lease(owner)
                    except _LeaseLost:
                        lease_lost = True
                        outcome.failures.append("LeaseLost")
                    else:
                        self.state.record_health(
                            component="controller",
                            status="failed",
                            message="Guardian orphan prevention recovery failed closed.",
                            details={"failure_type": failure},
                            checked_at=observed_at,
                        )
            for policy in self.config.repositories:
                if (
                    lease_lost
                    or outcome.authentication_circuit_open
                    or outcome.model_circuit_open
                ):
                    break
                try:
                    self._require_live_lease(owner)
                    if self.config.mode is GuardianMode.PROPOSE_PREVENTION:
                        assert self.prevention_runner is not None

                        def require_exact_open_source_authority(
                            source: OpenPullAuthorityReference,
                            revision_ids: Sequence[int],
                        ) -> None:
                            self._require_exact_open_source_authority(
                                policy=policy,
                                source=source,
                                event_revision_ids=revision_ids,
                                require_live_lease=lambda: self._require_live_lease(
                                    owner
                                ),
                            )

                        def require_exact_sources_still_closed(
                            sources: Sequence[HistoricalPullReference],
                            revision_ids: Sequence[int],
                        ) -> None:
                            if (
                                self.historical_source_snapshot_provider is None
                                or self.historical_checkout_factory is None
                            ):
                                raise PreventionSourceAuthorityError(
                                    "Exact historical prevention revalidation is "
                                    "unavailable."
                                )
                            self._require_exact_historical_sources_still_closed(
                                policy=policy,
                                sources=sources,
                                event_revision_ids=revision_ids,
                                operator_config=self.operator_pipeline_configs.get(
                                    policy.base_repo
                                ),
                                require_live_lease=lambda: self._require_live_lease(
                                    owner
                                ),
                            )

                        self._record_prevention_outcome(
                            self.prevention_runner.recover(
                                policy=policy,
                                observed_at=observed_at,
                                require_live_lease=lambda: self._require_live_lease(
                                    owner
                                ),
                                require_current_base_unchanged=lambda: (
                                    self._require_live_lease(owner)
                                ),
                                require_exact_open_source_authority=(
                                    require_exact_open_source_authority
                                ),
                                require_exact_sources_still_closed=(
                                    require_exact_sources_still_closed
                                ),
                            ),
                            outcome=outcome,
                        )
                    previous_revisions = (
                        ()
                        if getattr(
                            self.snapshot_provider,
                            "loads_previous_feedback_per_pull",
                            False,
                        )
                        else self.state.latest_event_revisions(
                            repository=policy.base_repo
                        )
                    )
                    snapshots = tuple(
                        self.snapshot_provider(
                            policy,
                            _stored_feedback(previous_revisions),
                        )
                    )
                    self._require_live_lease(owner)
                    outcome.repositories_polled += 1
                    self._recover_publications(
                        policy=policy,
                        snapshots=snapshots,
                        observed_at=observed_at,
                        lease_owner=owner,
                    )
                    if self.state.pending_publications(
                        repository=policy.base_repo,
                        repository_id=policy.base_repo_id,
                        limit=1,
                    ):
                        raise _PublicationRecoveryBacklog(
                            "Publication recovery remains after the bounded workset."
                        )
                    for snapshot in snapshots:
                        outcome.pull_requests_seen += 1
                        self._process_snapshot(
                            policy=policy,
                            snapshot=snapshot,
                            observed_at=observed_at,
                            lease_owner=owner,
                            outcome=outcome,
                        )
                    # Historical writes are safe only after this poll obtained
                    # and processed a complete open-PR view for the same
                    # repository.  Retain the open target scope so closed
                    # evidence cannot race a still-open translation PR.
                    open_poll_succeeded.add(policy.base_repo)
                    open_changed_paths[policy.base_repo] = frozenset(
                        changed.path
                        for snapshot in snapshots
                        for changed in snapshot.changed_files
                    )
                except (_LeaseLost, PreventionLeaseLostError):
                    lease_lost = True
                    outcome.failures.append("LeaseLost")
                    break
                except PollDeadlineExceeded:
                    if "PollDeadlineExceeded" not in outcome.failures:
                        outcome.failures.append("PollDeadlineExceeded")
                    break
                except _AuthenticationCircuit:
                    outcome.authentication_circuit_open = True
                except _ModelCircuit:
                    outcome.model_circuit_open = True
                except GitHubAuthenticationError:
                    outcome.authentication_circuit_open = True
                    self.state.record_health(
                        component="github",
                        status="failed",
                        message=(
                            "GitHub authentication failed; further GitHub calls "
                            "stopped."
                        ),
                        details={"circuit_open": True},
                        checked_at=observed_at,
                    )
                except Exception as exc:
                    outcome.failures.append(_safe_failure_name(exc))
                    self.state.record_health(
                        component="controller",
                        status="failed",
                        message="Guardian repository poll failed closed.",
                        details={"failure_type": _safe_failure_name(exc)},
                        checked_at=observed_at,
                    )
            if (
                not lease_lost
                and "PollDeadlineExceeded" not in outcome.failures
                and not outcome.authentication_circuit_open
                and not outcome.model_circuit_open
            ):
                history_ready = True
                if self.remediation_runner is not None:
                    try:
                        self.remediation_runner.begin_poll()
                    except PollDeadlineExceeded:
                        raise
                    except GitHubAuthenticationError:
                        outcome.authentication_circuit_open = True
                        history_ready = False
                        self.state.record_health(
                            component="github",
                            status="failed",
                            message=(
                                "Historical remediation authentication failed; "
                                "further GitHub calls stopped."
                            ),
                            details={"circuit_open": True},
                            checked_at=observed_at,
                        )
                    except Exception as exc:
                        failure = _safe_failure_name(exc)
                        outcome.failures.append(failure)
                        outcome.remediation_failures.append(failure)
                        history_ready = False
                        self.state.record_health(
                            component="controller",
                            status="failed",
                            message="Guardian historical phase failed to initialize.",
                            details={"failure_type": failure},
                            checked_at=observed_at,
                        )
                historical_policies: tuple[RepositoryPolicy, ...] = (
                    self.config.repositories if history_ready else ()
                )
                if self.remediation_runner is not None and historical_policies:
                    cursor = self.state.latest_health(_REMEDIATION_FAIRNESS_COMPONENT)
                    cursor_repository = (
                        cursor.details.get("last_published_repository")
                        if cursor is not None
                        else None
                    )
                    historical_policies = _rotate_policies_after_repository(
                        historical_policies,
                        (
                            cursor_repository
                            if isinstance(cursor_repository, str)
                            else None
                        ),
                    )
                for policy in historical_policies:
                    if policy.closed_pr_backfill is None:
                        continue
                    if policy.base_repo not in open_poll_succeeded:
                        continue
                    if (
                        outcome.authentication_circuit_open
                        or outcome.model_circuit_open
                    ):
                        break
                    try:
                        drafts_before = outcome.remediation_drafts_created
                        self._process_historical_policy(
                            policy=policy,
                            observed_at=observed_at,
                            lease_owner=owner,
                            outcome=outcome,
                            open_changed_paths=open_changed_paths.get(
                                policy.base_repo,
                                frozenset(),
                            ),
                        )
                        if outcome.remediation_drafts_created > drafts_before:
                            self.state.record_health(
                                component=_REMEDIATION_FAIRNESS_COMPONENT,
                                status="ok",
                                message=(
                                    "Historical remediation publication cursor "
                                    "advanced."
                                ),
                                details={
                                    "last_published_repository": policy.base_repo,
                                },
                                checked_at=observed_at,
                            )
                    except (_LeaseLost, PreventionLeaseLostError):
                        lease_lost = True
                        outcome.failures.append("LeaseLost")
                        break
                    except PollDeadlineExceeded:
                        if "PollDeadlineExceeded" not in outcome.failures:
                            outcome.failures.append("PollDeadlineExceeded")
                        break
                    except _HistoricalLimitDeferred:
                        break
                    except _AuthenticationCircuit:
                        outcome.authentication_circuit_open = True
                    except _ModelCircuit:
                        outcome.model_circuit_open = True
                    except GitHubAuthenticationError:
                        outcome.authentication_circuit_open = True
                        self.state.record_health(
                            component="github",
                            status="failed",
                            message=(
                                "Historical GitHub authentication failed; further "
                                "GitHub calls stopped."
                            ),
                            details={"circuit_open": True},
                            checked_at=observed_at,
                        )
                    except Exception as exc:
                        outcome.failures.append(_safe_failure_name(exc))
                        self.state.record_health(
                            component="controller",
                            status="failed",
                            message="Guardian historical poll failed closed.",
                            details={"failure_type": _safe_failure_name(exc)},
                            checked_at=observed_at,
                        )
        except PollDeadlineExceeded:
            if "PollDeadlineExceeded" not in outcome.failures:
                outcome.failures.append("PollDeadlineExceeded")
        finally:
            try:
                if not lease_lost:
                    try:
                        self._refresh_live_lease(owner)
                    except _LeaseLost:
                        lease_lost = True
                        outcome.failures.append("LeaseLost")
                if not lease_lost:
                    retention_cutoff = observed_at - timedelta(
                        days=self.config.limits.raw_retention_days
                    )
                    outcome.raw_bodies_purged = self.state.purge_raw_event_bodies(
                        before=retention_cutoff
                    )
                    self.state.purge_assessment_results(before=retention_cutoff)
                    try:
                        self._refresh_live_lease(owner)
                    except _LeaseLost:
                        lease_lost = True
                        outcome.failures.append("LeaseLost")
                if not lease_lost:
                    poll_ok = (
                        not outcome.failures
                        and not outcome.prevention_failures
                        and not outcome.remediation_failures
                        and not outcome.authentication_circuit_open
                        and not outcome.model_circuit_open
                        and outcome.runs_failed == 0
                    )
                    self.state.record_health(
                        component="guardian",
                        status="ok" if poll_ok else "failed",
                        message=(
                            "Guardian bounded poll completed."
                            if poll_ok
                            else "Guardian bounded poll completed with failed work."
                        ),
                        details={
                            "repositories_polled": outcome.repositories_polled,
                            "pull_requests_seen": outcome.pull_requests_seen,
                            "historical_pull_requests_seen": (
                                outcome.historical_pull_requests_seen
                            ),
                            "historical_pull_requests_completed": (
                                outcome.historical_pull_requests_completed
                            ),
                            "historical_policy_rejections": (
                                outcome.historical_policy_rejections
                            ),
                            "runs_failed": outcome.runs_failed,
                            "prevention_drafts_created": (
                                outcome.prevention_drafts_created
                            ),
                            "prevention_items_deferred": (
                                outcome.prevention_items_deferred
                            ),
                            "prevention_failures": tuple(outcome.prevention_failures),
                            "remediation_drafts_created": (
                                outcome.remediation_drafts_created
                            ),
                            "remediation_items_deferred": (
                                outcome.remediation_items_deferred
                            ),
                            "remediation_failures": tuple(outcome.remediation_failures),
                            "authentication_circuit_open": (
                                outcome.authentication_circuit_open
                            ),
                            "model_circuit_open": outcome.model_circuit_open,
                            "failure_types": tuple(outcome.failures),
                        },
                        checked_at=observed_at,
                    )
            finally:
                self.state.release_lease(name=lease_name, owner=owner)
        return outcome.freeze()

    def _historical_checkpoint(
        self,
        *,
        policy: RepositoryPolicy,
        snapshot: PullRequestFeedbackSnapshot,
        pull_revision_digest: str,
        policy_digest: str,
        scope: HistoricalCheckScope,
        observed_at: datetime,
        event_revision_ids: Sequence[int] = (),
        ignored_event_revision_ids: Sequence[int] = (),
        remediation_reason: RemediationCoverageReason | None = None,
        authority_digest: str | None = None,
        require_exact_sources_still_closed: Callable[
            [Sequence[HistoricalPullReference], Sequence[int]], None
        ]
        | None = None,
    ) -> None:
        pull = snapshot.pull_request
        if scope is HistoricalCheckScope.REMEDIATION:
            if ignored_event_revision_ids:
                raise ValueError(
                    "Remediation completion cannot classify ignored authority."
                )
            if remediation_reason is None or authority_digest is None:
                raise ValueError(
                    "Remediation completion requires an explicit reason and "
                    "authority digest."
                )
            source = HistoricalPullReference(
                repository=policy.base_repo,
                repository_id=policy.base_repo_id,
                pull_id=pull.pull_id,
                pr_number=pull.number,
                pull_revision_digest=pull_revision_digest,
                authority_digest=authority_digest,
                policy_digest=policy_digest,
                head_sha=pull.head_sha,
                base_sha=pull.base_sha,
            )
            if require_exact_sources_still_closed is None:
                raise ValueError(
                    "Remediation completion requires exact source revalidation."
                )
            require_exact_sources_still_closed((source,), event_revision_ids)
            self.state.record_independent_remediation_completion(
                source,
                remediation_reason,
                event_revision_ids=event_revision_ids,
                occurred_at=observed_at,
            )
            return
        if (
            remediation_reason is not None
            or authority_digest is not None
            or require_exact_sources_still_closed is not None
        ):
            raise ValueError(
                "Remediation completion metadata is invalid for this scope."
            )
        self.state.record_historical_pull_completion(
            repository=policy.base_repo,
            repository_id=policy.base_repo_id,
            pull_id=pull.pull_id,
            pr_number=pull.number,
            pull_revision_digest=pull_revision_digest,
            policy_digest=policy_digest,
            head_sha=pull.head_sha,
            base_sha=pull.base_sha,
            event_revision_ids=event_revision_ids,
            ignored_event_revision_ids=ignored_event_revision_ids,
            authority_scope=scope,
            completed_at=observed_at,
        )

    def _historical_checkpoint_all(
        self,
        *,
        policy: RepositoryPolicy,
        snapshot: PullRequestFeedbackSnapshot,
        pull_revision_digest: str,
        policy_digest: str,
        scopes: Sequence[HistoricalCheckScope],
        observed_at: datetime,
        remediation_reason: RemediationCoverageReason | None = None,
        authority_digest: str | None = None,
        require_exact_sources_still_closed: Callable[
            [Sequence[HistoricalPullReference], Sequence[int]], None
        ]
        | None = None,
    ) -> None:
        for scope in scopes:
            if self.state.historical_pull_is_complete(
                repository=policy.base_repo,
                repository_id=policy.base_repo_id,
                pull_id=snapshot.pull_request.pull_id,
                pull_revision_digest=pull_revision_digest,
                policy_digest=policy_digest,
                authority_scope=scope,
            ):
                continue
            self._historical_checkpoint(
                policy=policy,
                snapshot=snapshot,
                pull_revision_digest=pull_revision_digest,
                policy_digest=policy_digest,
                scope=scope,
                observed_at=observed_at,
                remediation_reason=(
                    remediation_reason
                    if scope is HistoricalCheckScope.REMEDIATION
                    else None
                ),
                authority_digest=(
                    authority_digest
                    if scope is HistoricalCheckScope.REMEDIATION
                    else None
                ),
                require_exact_sources_still_closed=(
                    require_exact_sources_still_closed
                    if scope is HistoricalCheckScope.REMEDIATION
                    else None
                ),
            )

    def _prepare_historical_intake(
        self,
        *,
        policy: RepositoryPolicy,
        snapshot: PullRequestFeedbackSnapshot,
        operator_config: PipelineConfigSnapshot | None,
        lease_owner: str,
    ) -> _HistoricalIntake:
        """Authorize and hash history using one exact old-base checkout."""

        assert self.historical_checkout_factory is not None
        historical_base, historical_head = _historical_revisions(
            policy,
            snapshot,
            github_host=self.github_host,
        )
        self._require_live_lease(lease_owner)
        with self.historical_checkout_factory(historical_base) as base_workspace:
            old_scope = _historical_target_scope(
                base_root=base_workspace.path,
                policy=policy,
                changed_files=snapshot.changed_files,
                operator_pipeline_config=operator_config,
            )
            try:
                authorized = authorize_historical_feedback(
                    policy=policy,
                    snapshot=snapshot,
                    path_locales=old_scope.path_locales,
                    changed_locales=tuple(sorted(set(old_scope.path_locales.values()))),
                )
            except IntakePolicyError as exc:
                raise _HistoricalPolicyRejection(str(exc)) from None
            previous = self.state.latest_event_revisions(
                repository=policy.base_repo,
                pr_number=snapshot.pull_request.number,
            )
            tombstones = _trusted_tombstones(
                policy=policy,
                snapshot=snapshot,
                previous=previous,
            )
            if not authorized.events and not tombstones:
                raise _HistoricalPolicyRejection(
                    "Historical pull contains no authorized feedback."
                )
            return _HistoricalIntake(
                old_scope=old_scope,
                historical_head=historical_head,
                authorized=authorized,
                tombstones=tombstones,
                historical_digest=_historical_pull_revision_digest(
                    policy,
                    snapshot,
                    feedback_events=(*authorized.events, *tombstones),
                ),
            )

    @staticmethod
    def _open_pull_authority_reference(
        *,
        policy: RepositoryPolicy,
        snapshot: PullRequestFeedbackSnapshot,
        authorized: AuthorizedFeedback,
        authority_repository: str | None = None,
    ) -> OpenPullAuthorityReference:
        """Bind prevention evidence to the complete live trusted open snapshot."""

        repository = authority_repository or policy.base_repo
        digest_snapshot = (
            snapshot
            if repository == snapshot.repository_identity.full_name
            else _repository_route_alias(snapshot, repository=repository)
        )
        digest_events = (
            authorized.events
            if repository == snapshot.repository_identity.full_name
            else _feedback_repository_alias(
                authorized.events,
                current_repository=snapshot.repository_identity.full_name,
                repository=repository,
            )
        )
        pull = snapshot.pull_request
        return OpenPullAuthorityReference(
            repository=repository,
            repository_id=policy.base_repo_id,
            pull_id=pull.pull_id,
            pr_number=pull.number,
            authority_digest=_historical_pull_revision_digest(
                policy,
                digest_snapshot,
                feedback_events=digest_events,
            ),
            head_sha=pull.head_sha,
            base_sha=pull.base_sha,
            feedback_digest=_open_pull_feedback_digest(
                digest_snapshot,
                feedback_events=digest_events,
            ),
        )

    def _require_exact_open_source_authority(
        self,
        *,
        policy: RepositoryPolicy,
        source: OpenPullAuthorityReference,
        event_revision_ids: Sequence[int],
        require_live_lease: Callable[[], None],
        expected_current_head_sha: str | None = None,
    ) -> None:
        """Rehydrate and reauthorize one complete open source before mutation."""

        try:
            if source.repository_id != policy.base_repo_id:
                raise ValueError
            if expected_current_head_sha in {None, source.head_sha}:
                self.state.validate_prevention_source_attestation(
                    source_repository=source.repository,
                    open_source=source,
                    source_pulls=(),
                    event_revision_ids=event_revision_ids,
                )
            else:
                revision_ids = tuple(event_revision_ids)
                revisions = tuple(
                    self.state.get_event_revision(revision_id)
                    for revision_id in revision_ids
                )
                if (
                    not revision_ids
                    or len(set(revision_ids)) != len(revision_ids)
                    or any(
                        revision is None
                        or revision.repository != source.repository
                        or revision.pr_number != source.pr_number
                        or revision.head_sha != source.head_sha
                        or revision.base_sha != source.base_sha
                        or revision.deleted
                        for revision in revisions
                    )
                ):
                    raise ValueError
        except (TypeError, ValueError, RuntimeError) as exc:
            raise PreventionSourceAuthorityError(
                "Durable open prevention evidence is no longer exact."
            ) from exc

        revalidate = getattr(
            self.snapshot_provider,
            "revalidate_open_pull_request",
            None,
        )
        if not callable(revalidate):
            raise PreventionSourceAuthorityError(
                "Exact open-source revalidation is unavailable."
            )
        require_live_lease()
        routed_source = (
            source
            if source.repository == policy.base_repo
            else replace(source, repository=policy.base_repo)
        )
        try:
            fresh = revalidate(policy, routed_source)
        except (
            _LeaseLost,
            PreventionLeaseLostError,
            PollDeadlineExceeded,
            GitHubAuthenticationError,
        ):
            raise
        except Exception as exc:
            raise PreventionSourceAuthorityError(
                "The open prevention source is no longer authorized."
            ) from exc
        require_live_lease()
        try:
            if not isinstance(fresh, PullRequestFeedbackSnapshot):
                raise TypeError("Exact open-source snapshot is malformed.")
            base_revision, _head_revision = _exact_revisions(
                policy,
                fresh,
                github_host=self.github_host,
            )
            with self.checkout_factory(base_revision) as base_workspace:
                scope = _target_scope(
                    base_root=base_workspace.path,
                    policy=policy,
                    changed_files=fresh.changed_files,
                    operator_pipeline_config=self.operator_pipeline_configs.get(
                        policy.base_repo
                    ),
                )
                authorized = authorize_feedback(
                    policy=policy,
                    snapshot=fresh,
                    path_locales=scope.path_locales,
                    changed_locales=tuple(sorted(set(scope.path_locales.values()))),
                )
            current = self._open_pull_authority_reference(
                policy=policy,
                snapshot=fresh,
                authorized=authorized,
                authority_repository=source.repository,
            )
        except (
            _LeaseLost,
            PreventionLeaseLostError,
            PollDeadlineExceeded,
            GitHubAuthenticationError,
        ):
            raise
        except Exception as exc:
            raise PreventionSourceAuthorityError(
                "The open prevention source no longer has the same authority."
            ) from exc
        expected_head = expected_current_head_sha or source.head_sha
        if fresh.pull_request.head_sha != expected_head:
            raise PreventionSourceAuthorityError(
                "The open prevention source head changed after assessment."
            )
        same_original_authority = expected_head == source.head_sha and current == source
        same_feedback_after_guardian_push = bool(
            expected_head != source.head_sha
            and source.feedback_digest is not None
            and current.feedback_digest == source.feedback_digest
            and current.repository == source.repository
            and current.repository_id == source.repository_id
            and current.pull_id == source.pull_id
            and current.pr_number == source.pr_number
            and current.base_sha == source.base_sha
        )
        if not (same_original_authority or same_feedback_after_guardian_push):
            if (
                expected_head != source.head_sha
                and current.repository == source.repository
                and current.repository_id == source.repository_id
                and current.pull_id == source.pull_id
                and current.pr_number == source.pr_number
                and current.base_sha == source.base_sha
            ):
                raise _PublishedFeedbackChanged(
                    "Trusted feedback changed after the confirmed Guardian push."
                )
            raise PreventionSourceAuthorityError(
                "The open prevention source changed after assessment."
            )

        # Materializing and inspecting the trusted base checkout above can be
        # slow. Hydrate the exact pull once more afterward and derive its
        # authority from the already trusted scope, so a lifecycle, revision,
        # changed-file, or trusted-feedback race cannot authorize a write from
        # the earlier snapshot.
        require_live_lease()
        try:
            final_fresh = revalidate(policy, routed_source)
        except (
            _LeaseLost,
            PreventionLeaseLostError,
            PollDeadlineExceeded,
            GitHubAuthenticationError,
        ):
            raise
        except Exception as exc:
            raise PreventionSourceAuthorityError(
                "The open prevention source is no longer authorized."
            ) from exc
        require_live_lease()
        try:
            if not isinstance(final_fresh, PullRequestFeedbackSnapshot):
                raise TypeError("Exact open-source snapshot is malformed.")
            _exact_revisions(
                policy,
                final_fresh,
                github_host=self.github_host,
            )
            final_authorized = authorize_feedback(
                policy=policy,
                snapshot=final_fresh,
                path_locales=scope.path_locales,
                changed_locales=tuple(sorted(set(scope.path_locales.values()))),
            )
            final_current = self._open_pull_authority_reference(
                policy=policy,
                snapshot=final_fresh,
                authorized=final_authorized,
                authority_repository=source.repository,
            )
        except (
            _LeaseLost,
            PreventionLeaseLostError,
            PollDeadlineExceeded,
            GitHubAuthenticationError,
        ):
            raise
        except Exception as exc:
            raise PreventionSourceAuthorityError(
                "The open prevention source no longer has the same authority."
            ) from exc
        if (
            final_fresh.pull_request.head_sha != expected_head
            or final_current != current
        ):
            raise PreventionSourceAuthorityError(
                "The open prevention source changed during authority validation."
            )
        require_live_lease()

    def _require_exact_historical_sources_still_closed(
        self,
        *,
        policy: RepositoryPolicy,
        sources: Sequence[HistoricalPullReference],
        event_revision_ids: Sequence[int],
        operator_config: PipelineConfigSnapshot | None,
        require_live_lease: Callable[[], None],
    ) -> None:
        """Reauthorize the complete exact source set at a mutation boundary."""

        source_tuple = tuple(sources)
        revision_ids = tuple(event_revision_ids)
        try:
            _validated_retry_source_batches((source_tuple,))
            if len(set(revision_ids)) != len(revision_ids) or any(
                isinstance(revision_id, bool)
                or not isinstance(revision_id, int)
                or revision_id <= 0
                for revision_id in revision_ids
            ):
                raise ValueError("Remediation event revisions are malformed.")
            if any(
                source.repository_id != policy.base_repo_id for source in source_tuple
            ):
                raise ValueError("Remediation source escaped repository policy.")
            if revision_ids:
                self.state.validate_current_historical_remediation_evidence(
                    source_pulls=source_tuple,
                    event_revision_ids=revision_ids,
                )
        except (TypeError, ValueError) as exc:
            raise RemediationSourceAuthorityError(
                "Durable remediation source evidence is no longer exact."
            ) from exc

        quarantined = frozenset(
            self.state.operator_quarantined_historical_pull_retries(
                repository=source_tuple[0].repository,
                repository_id=policy.base_repo_id,
                policy_digest=source_tuple[0].policy_digest,
            )
        )
        if any(
            (source.pull_id, source.pr_number) in quarantined for source in source_tuple
        ):
            raise RemediationSourceAuthorityError(
                "A remediation source is under operator quarantine."
            )

        revisions: list[EventRevision] = []
        for revision_id in revision_ids:
            revision = self.state.get_event_revision(revision_id)
            if revision is None:
                raise RemediationSourceAuthorityError(
                    "Durable remediation source evidence disappeared."
                )
            revisions.append(revision)
        revisions_by_pull: dict[tuple[str, int], list[EventRevision]] = {
            (source.repository, source.pr_number): [] for source in source_tuple
        }
        for revision in revisions:
            key = (revision.repository, revision.pr_number)
            if key not in revisions_by_pull:
                raise RemediationSourceAuthorityError(
                    "Durable feedback escaped the exact remediation source set."
                )
            revisions_by_pull[key].append(revision)
        if not revision_ids:
            for source in source_tuple:
                revisions_by_pull[(source.repository, source.pr_number)].extend(
                    self.state.latest_event_revisions(
                        repository=source.repository,
                        pr_number=source.pr_number,
                    )
                )

        assert self.historical_source_snapshot_provider is not None
        require_live_lease()
        try:
            fresh = self.historical_source_snapshot_provider(policy, source_tuple)
        except PolicyViolation as exc:
            raise RemediationSourceAuthorityError(
                "A remediation source is no longer closed and authorized."
            ) from exc
        require_live_lease()
        if not isinstance(fresh, tuple) or len(fresh) != len(source_tuple):
            raise RemediationSourceAuthorityError(
                "Exact source revalidation returned an incomplete snapshot set."
            )

        snapshots: dict[tuple[int, int], PullRequestFeedbackSnapshot] = {}
        for snapshot in fresh:
            if not isinstance(snapshot, PullRequestFeedbackSnapshot):
                raise RemediationSourceAuthorityError(
                    "Exact source revalidation returned malformed evidence."
                )
            identity = (
                snapshot.pull_request.pull_id,
                snapshot.pull_request.number,
            )
            if identity in snapshots:
                raise RemediationSourceAuthorityError(
                    "Exact source revalidation repeated a pull identity."
                )
            snapshots[identity] = snapshot

        for source in source_tuple:
            snapshot = snapshots.get((source.pull_id, source.pr_number))
            if snapshot is None:
                raise RemediationSourceAuthorityError(
                    "Exact source revalidation changed a pull identity."
                )
            pull = snapshot.pull_request
            if pull.head_sha != source.head_sha or pull.base_sha != source.base_sha:
                raise RemediationSourceAuthorityError(
                    "Exact source revalidation changed a pull revision."
                )
            previous = tuple(revisions_by_pull[(source.repository, source.pr_number)])
            try:
                historical_base, _historical_head = _historical_revisions(
                    policy,
                    snapshot,
                    github_host=self.github_host,
                )
                assert self.historical_checkout_factory is not None
                require_live_lease()
                with self.historical_checkout_factory(
                    historical_base
                ) as base_workspace:
                    scope = _historical_target_scope(
                        base_root=base_workspace.path,
                        policy=policy,
                        changed_files=snapshot.changed_files,
                        operator_pipeline_config=operator_config,
                    )
                    current_feedback = list(snapshot.feedback)
                    current_keys = {
                        (revision.kind.value, revision.source_id)
                        for revision in current_feedback
                    }
                    for prior in previous:
                        key = (prior.kind, prior.event_id)
                        if key in current_keys:
                            continue
                        stored = _stored_feedback((prior,))
                        if len(stored) != 1:
                            raise ValueError("Stored feedback kind is unsupported.")
                        current_feedback.append(
                            replace(stored[0], body="", deleted=True)
                        )
                    snapshot_with_tombstones = replace(
                        snapshot,
                        feedback=tuple(
                            sorted(
                                current_feedback,
                                key=lambda revision: (
                                    revision.kind.value,
                                    int(revision.source_id),
                                    revision.revision_id,
                                ),
                            )
                        ),
                    )
                    authorized = authorize_historical_feedback(
                        policy=policy,
                        snapshot=snapshot_with_tombstones,
                        path_locales=scope.path_locales,
                        changed_locales=tuple(sorted(set(scope.path_locales.values()))),
                    )
                tombstones = list(
                    _trusted_tombstones(
                        policy=policy,
                        snapshot=snapshot_with_tombstones,
                        previous=previous,
                    )
                )
                raw_by_key = {
                    (revision.kind.value, revision.source_id): revision
                    for revision in snapshot_with_tombstones.feedback
                }
                for prior in previous:
                    if not prior.deleted:
                        continue
                    raw = raw_by_key.get((prior.kind, prior.event_id))
                    if raw is not None and not raw.deleted:
                        continue
                    tombstones.append(
                        FeedbackEvent(
                            repository=prior.repository,
                            pr_number=prior.pr_number,
                            kind=prior.kind,
                            event_id=prior.event_id,
                            author=prior.author,
                            author_id=prior.author_id,
                            author_type=prior.author_type,
                            body="",
                            head_sha=prior.head_sha,
                            base_sha=prior.base_sha,
                            locale=prior.locale,
                            updated_at=prior.updated_at,
                            path=prior.path,
                            line=prior.line,
                            html_url=prior.html_url,
                            deleted=True,
                        )
                    )
                digest_snapshot = (
                    snapshot
                    if source.repository == snapshot.repository_identity.full_name
                    else _repository_route_alias(
                        snapshot,
                        repository=source.repository,
                    )
                )
                digest_events = _feedback_repository_alias(
                    (*authorized.events, *tombstones),
                    current_repository=snapshot.repository_identity.full_name,
                    repository=source.repository,
                )
                digest = _historical_pull_revision_digest(
                    policy,
                    digest_snapshot,
                    feedback_events=digest_events,
                )
            except (
                IntakePolicyError,
                TypeError,
                ValueError,
                _HistoricalPolicyRejection,
            ) as exc:
                digest_snapshot = (
                    snapshot
                    if source.repository == snapshot.repository_identity.full_name
                    else _repository_route_alias(
                        snapshot,
                        repository=source.repository,
                    )
                )
                digest = _historical_pull_revision_digest(policy, digest_snapshot)
                if digest == source.authority_digest:
                    continue
                raise RemediationSourceAuthorityError(
                    "A remediation source no longer has the same authority."
                ) from exc
            if digest != source.authority_digest:
                raise RemediationSourceAuthorityError(
                    "A remediation source changed after assessment."
                )

        # Historical base checkouts and authorization above are bounded but
        # potentially slow. Rehydrate the complete exact source set after that
        # local preparation and require field-for-field typed snapshot stability
        # before permitting the caller's remote mutation.
        require_live_lease()
        try:
            final_fresh = self.historical_source_snapshot_provider(
                policy,
                source_tuple,
            )
        except PolicyViolation as exc:
            raise RemediationSourceAuthorityError(
                "A remediation source is no longer closed and authorized."
            ) from exc
        require_live_lease()
        if not isinstance(final_fresh, tuple) or len(final_fresh) != len(source_tuple):
            raise RemediationSourceAuthorityError(
                "Final source revalidation returned an incomplete snapshot set."
            )
        final_snapshots: dict[tuple[int, int], PullRequestFeedbackSnapshot] = {}
        for snapshot in final_fresh:
            if not isinstance(snapshot, PullRequestFeedbackSnapshot):
                raise RemediationSourceAuthorityError(
                    "Final source revalidation returned malformed evidence."
                )
            identity = (
                snapshot.pull_request.pull_id,
                snapshot.pull_request.number,
            )
            if identity in final_snapshots:
                raise RemediationSourceAuthorityError(
                    "Final source revalidation repeated a pull identity."
                )
            final_snapshots[identity] = snapshot
        if final_snapshots != snapshots:
            raise RemediationSourceAuthorityError(
                "A remediation source changed during authority validation."
            )
        require_live_lease()

    def _record_historical_terminal_status(
        self,
        *,
        policy: RepositoryPolicy,
        snapshot: PullRequestFeedbackSnapshot,
        outcome_name: str,
        observed_at: datetime,
    ) -> None:
        self.state.record_health(
            component="guardian_history",
            status="ok",
            message="Guardian historical item reached a terminal policy outcome.",
            details={
                "outcome": outcome_name,
                "repository": policy.base_repo,
                "repository_id": policy.base_repo_id,
                "pr_number": snapshot.pull_request.number,
                "pull_id": snapshot.pull_request.pull_id,
            },
            checked_at=observed_at,
        )

    def _historical_is_complete(
        self,
        *,
        policy: RepositoryPolicy,
        pull: PullRequestSnapshot,
        pull_revision_digest: str,
        policy_digest: str,
        scopes: Sequence[HistoricalCheckScope],
    ) -> bool:
        return all(
            self.state.historical_pull_is_complete(
                repository=policy.base_repo,
                repository_id=policy.base_repo_id,
                pull_id=pull.pull_id,
                pull_revision_digest=pull_revision_digest,
                policy_digest=policy_digest,
                authority_scope=scope,
            )
            for scope in scopes
        )

    @staticmethod
    def _remediation_outcome(
        result: RemediationBatchOutcome,
        *,
        outcome: _PollAccumulator,
    ) -> tuple[bool, tuple[tuple[HistoricalPullReference, ...], ...]]:
        """Validate and record one bounded remediation coordinator result."""

        if not isinstance(result, RemediationBatchOutcome):
            raise TypeError("Remediation runner returned a malformed outcome.")
        drafts = tuple(result.drafts)
        deferred = result.deferred
        abandoned = result.abandoned
        failures = tuple(getattr(result, "failures", ()))
        retry_batches = _validated_retry_source_batches(result.retry_source_batches)
        if (
            isinstance(deferred, bool)
            or not isinstance(deferred, int)
            or deferred < 0
            or isinstance(abandoned, bool)
            or not isinstance(abandoned, int)
            or abandoned < 0
            or any(not isinstance(item, str) or not item for item in failures)
        ):
            raise TypeError("Remediation runner returned a malformed outcome.")
        created = 0
        for draft in drafts:
            draft_created = getattr(draft, "created", None)
            if not isinstance(draft_created, bool):
                raise TypeError("Remediation runner returned a malformed draft.")
            created += int(draft_created)
        outcome.remediation_drafts_created += created
        outcome.remediation_items_deferred += deferred + abandoned
        outcome.remediation_failures.extend(failures)
        return (
            deferred == 0 and abandoned == 0 and not failures,
            retry_batches,
        )

    def _process_historical_policy(
        self,
        *,
        policy: RepositoryPolicy,
        observed_at: datetime,
        lease_owner: str,
        outcome: _PollAccumulator,
        open_changed_paths: frozenset[str],
    ) -> None:
        backfill = policy.closed_pr_backfill
        if backfill is None:  # pragma: no cover - caller filters this
            return
        assert self.historical_snapshot_provider is not None
        assert self.historical_checkout_factory is not None
        assert self.current_base_provider is not None
        scopes = _required_historical_scopes(self.config, policy)
        operator_config = self.operator_pipeline_configs.get(policy.base_repo)

        def require_live_lease() -> None:
            self._require_live_lease(lease_owner)

        def require_cleanup_lease() -> None:
            self._refresh_live_lease(lease_owner)

        require_live_lease()
        current_snapshot = self.current_base_provider(policy)
        current_revision = _current_exact_revision(
            policy,
            current_snapshot,
            github_host=self.github_host,
        )

        def require_current_base_unchanged() -> None:
            """Fail closed if current-base authority moved during this intake."""

            require_live_lease()
            fresh_snapshot = self.current_base_provider(policy)
            try:
                fresh_revision = _current_exact_revision(
                    policy,
                    fresh_snapshot,
                    github_host=self.github_host,
                )
            except (ValueError, _HistoricalPolicyRejection) as exc:
                raise _HistoricalCurrentBaseChanged(
                    "Current base authority changed during historical processing."
                ) from exc
            require_live_lease()
            if fresh_snapshot != current_snapshot or fresh_revision != current_revision:
                raise _HistoricalCurrentBaseChanged(
                    "Current base changed during historical processing."
                )

        with self.checkout_factory(current_revision) as current_workspace:
            if policy.pipeline_config_source is PipelineConfigSource.BASE:
                config_bundle_digest = _base_pipeline_config_bundle_digest(
                    config_root=current_workspace.path,
                    config_relative_path=policy.pipeline_config_path,
                )
            else:
                if operator_config is None:
                    raise ValueError(
                        "Operator pipeline config snapshot is unavailable."
                    )
                config_bundle_digest = operator_config.bundle_digest
            policy_digest = _historical_policy_digest(
                config=self.config,
                policy=policy,
                model=self.codex_driver.model,
                pipeline_config_bundle_digest=config_bundle_digest,
            )

            def require_exact_sources_still_closed(
                sources: Sequence[HistoricalPullReference],
                event_revision_ids: Sequence[int],
            ) -> None:
                # Destination authority is checked first so the complete source
                # snapshot remains the final remote read before a publication
                # callback returns. Callers perform only local lease/deadline
                # checks after this guard and before the mutation.
                require_current_base_unchanged()
                self._require_exact_historical_sources_still_closed(
                    policy=policy,
                    sources=sources,
                    event_revision_ids=event_revision_ids,
                    operator_config=operator_config,
                    require_live_lease=require_live_lease,
                )

            def require_no_open_translation_overlap(
                candidate_paths: Sequence[str],
                excluded_pull: OpenPullPathIdentity | None = None,
            ) -> None:
                """Re-read complete open-PR path authority at a write boundary."""

                self._require_no_open_translation_overlap(
                    policy=policy,
                    candidate_paths=candidate_paths,
                    excluded_pull=excluded_pull,
                    require_live_lease=require_live_lease,
                )

            retry_batches: tuple[tuple[HistoricalPullReference, ...], ...] = ()
            if HistoricalCheckScope.REMEDIATION in scopes:
                assert self.remediation_runner is not None
                try:
                    recovery = self.remediation_runner.recover(
                        policy=policy,
                        observed_at=observed_at,
                        policy_digest=policy_digest,
                        require_live_lease=require_live_lease,
                        require_current_base_unchanged=(require_current_base_unchanged),
                        require_exact_sources_still_closed=(
                            require_exact_sources_still_closed
                        ),
                        require_no_open_translation_overlap=(
                            require_no_open_translation_overlap
                        ),
                    )
                    _terminal, retry_batches = self._remediation_outcome(
                        recovery,
                        outcome=outcome,
                    )
                    if any(
                        source.repository_id != policy.base_repo_id
                        for batch in retry_batches
                        for source in batch
                    ):
                        raise TypeError(
                            "Remediation recovery returned a foreign source pull."
                        )
                except GitHubAuthenticationError:
                    raise
                except (_LeaseLost, PreventionLeaseLostError):
                    raise
                except PollDeadlineExceeded:
                    raise
                except Exception as exc:
                    outcome.remediation_failures.append(_safe_failure_name(exc))
                    raise

            cursor = self.state.get_historical_discovery_cursor(
                repository=policy.base_repo,
                repository_id=policy.base_repo_id,
                policy_digest=policy_digest,
            )
            if cursor is None or cursor.cycle_complete:
                cycle_id = str(uuid4())
                cycle_started_at = observed_at
                cursor = self.state.record_historical_discovery_progress(
                    repository=policy.base_repo,
                    repository_id=policy.base_repo_id,
                    policy_digest=policy_digest,
                    cycle_id=cycle_id,
                    cycle_started_at=cycle_started_at,
                    next_page=1,
                    next_offset=0,
                    cycle_complete=False,
                    expected_cursor_id=(None if cursor is None else cursor.cursor_id),
                    recorded_at=observed_at,
                )
            else:
                cycle_id = cursor.cycle_id
                cycle_started_at = cursor.cycle_started_at

            seen_pulls = self.state.historical_cycle_seen_pulls(
                repository=policy.base_repo,
                repository_id=policy.base_repo_id,
                policy_digest=policy_digest,
                cycle_id=cycle_id,
            )
            selected_retry_sources = retry_batches[0] if retry_batches else ()
            selected_remediation_group = tuple(
                (source.pull_id, source.pr_number) for source in selected_retry_sources
            )
            selected_remediation_identities = frozenset(selected_remediation_group)
            cycle_seen_set = frozenset(seen_pulls)
            operator_quarantined = (
                self.state.operator_quarantined_historical_pull_retries(
                    repository=policy.base_repo,
                    repository_id=policy.base_repo_id,
                    policy_digest=policy_digest,
                )
            )
            pending_retries = self.state.pending_historical_pull_retries(
                repository=policy.base_repo,
                repository_id=policy.base_repo_id,
                policy_digest=policy_digest,
            )
            excluded_pulls = tuple(
                identity
                for identity in operator_quarantined
                if identity not in selected_remediation_identities
            )
            seen_pull_set = frozenset((*seen_pulls, *excluded_pulls))
            if selected_remediation_group and not all(
                identity in cycle_seen_set for identity in selected_remediation_group
            ):
                priority_pull_groups = (selected_remediation_group,)
            else:
                pending_retry = next(
                    (
                        identity
                        for identity in pending_retries
                        if identity not in seen_pull_set
                    ),
                    None,
                )
                priority_pull_groups = (
                    ((pending_retry,),) if pending_retry is not None else ()
                )
            previous_revisions = (
                ()
                if getattr(
                    self.snapshot_provider,
                    "loads_previous_feedback_per_pull",
                    False,
                )
                else self.state.latest_event_revisions(repository=policy.base_repo)
            )
            scan_result = self.historical_snapshot_provider(
                policy,
                _stored_feedback(previous_revisions),
                cutoff=cycle_started_at - timedelta(days=backfill.lookback_days),
                upper_bound=cycle_started_at,
                max_prs_per_poll=backfill.max_prs_per_poll,
                seen_pulls=seen_pulls,
                excluded_pulls=excluded_pulls,
                priority_pull_groups=priority_pull_groups,
            )
            scan_items = _validated_historical_scan_items(
                scan_result,
                max_hydration_attempts=backfill.max_prs_per_poll,
            )
            outcome.historical_repositories_polled += 1

            advanceable = [False] * len(scan_items)
            persisted_indices: set[int] = set()

            def persist_ready_items() -> None:
                for scan_index, ready in enumerate(advanceable):
                    if not ready or scan_index in persisted_indices:
                        continue
                    item = scan_items[scan_index]
                    assert item.pull_id is not None
                    assert item.pull_number is not None
                    self.state.record_historical_cycle_seen_pull(
                        repository=policy.base_repo,
                        repository_id=policy.base_repo_id,
                        policy_digest=policy_digest,
                        cycle_id=cycle_id,
                        pull_id=item.pull_id,
                        pr_number=item.pull_number,
                        seen_at=observed_at,
                    )
                    persisted_indices.add(scan_index)

            def quarantine_retry(
                *,
                pull_id: int,
                pr_number: int,
                failure_type: str,
            ) -> None:
                self.state.record_historical_pull_retry(
                    repository=policy.base_repo,
                    repository_id=policy.base_repo_id,
                    policy_digest=policy_digest,
                    pull_id=pull_id,
                    pr_number=pr_number,
                    failure_type=failure_type,
                    failed_at=observed_at,
                )

            def resolve_retry(pull: PullRequestSnapshot) -> None:
                self.state.resolve_historical_pull_retry(
                    repository=policy.base_repo,
                    repository_id=policy.base_repo_id,
                    policy_digest=policy_digest,
                    pull_id=pull.pull_id,
                    pr_number=pull.number,
                    resolved_at=observed_at,
                )

            candidates: list[tuple[int, PullRequestFeedbackSnapshot]] = []
            for scan_index, scan_item in enumerate(scan_items):
                if scan_item.snapshot is None:
                    if scan_item.failure_type is not None:
                        outcome.failures.append(scan_item.failure_type)
                        assert scan_item.pull_id is not None
                        assert scan_item.pull_number is not None
                        if (
                            scan_item.pull_id,
                            scan_item.pull_number,
                        ) not in selected_remediation_identities:
                            quarantine_retry(
                                pull_id=scan_item.pull_id,
                                pr_number=scan_item.pull_number,
                                failure_type=scan_item.failure_type,
                            )
                        self.state.record_health(
                            component="guardian_history_discovery",
                            status="failed",
                            message=(
                                "Guardian skipped one failed historical hydration."
                            ),
                            details={
                                "failure_type": scan_item.failure_type,
                                "repository": policy.base_repo,
                                "pull_id": scan_item.pull_id,
                                "pr_number": scan_item.pull_number,
                            },
                            checked_at=observed_at,
                        )
                    advanceable[scan_index] = True
                    persist_ready_items()
                    continue
                snapshot = scan_item.snapshot
                try:
                    _preflight_historical_changed_files(
                        policy,
                        snapshot.changed_files,
                    )
                except _HistoricalPolicyRejection:
                    pull_digest = _historical_pull_revision_digest(policy, snapshot)
                    if self._historical_is_complete(
                        policy=policy,
                        pull=snapshot.pull_request,
                        pull_revision_digest=pull_digest,
                        policy_digest=policy_digest,
                        scopes=scopes,
                    ):
                        resolve_retry(snapshot.pull_request)
                        advanceable[scan_index] = True
                        persist_ready_items()
                        continue
                    outcome.historical_pull_requests_seen += 1
                    require_current_base_unchanged()
                    self._historical_checkpoint_all(
                        policy=policy,
                        snapshot=snapshot,
                        pull_revision_digest=pull_digest,
                        policy_digest=policy_digest,
                        scopes=scopes,
                        observed_at=observed_at,
                        remediation_reason=(
                            RemediationCoverageReason.INDEPENDENT_POLICY_REJECTED
                        ),
                        authority_digest=pull_digest,
                        require_exact_sources_still_closed=(
                            require_exact_sources_still_closed
                        ),
                    )
                    outcome.historical_policy_rejections += 1
                    outcome.historical_pull_requests_completed += 1
                    self._record_historical_terminal_status(
                        policy=policy,
                        snapshot=snapshot,
                        outcome_name="policy_rejected",
                        observed_at=observed_at,
                    )
                    resolve_retry(snapshot.pull_request)
                    advanceable[scan_index] = True
                    persist_ready_items()
                    continue
                candidates.append((scan_index, snapshot))

            work: list[tuple[int, _HistoricalAssessment]] = []
            limit_deferred = False
            for candidate_index, (scan_index, snapshot) in enumerate(candidates):
                try:
                    # Exact locale authorization depends on the immutable old-base
                    # config. Completed candidates therefore require this one bounded
                    # checkout, but never the historical head or a fresh model call.
                    intake = self._prepare_historical_intake(
                        policy=policy,
                        snapshot=snapshot,
                        operator_config=operator_config,
                        lease_owner=lease_owner,
                    )
                except _HistoricalPolicyRejection:
                    pull_digest = _historical_pull_revision_digest(policy, snapshot)
                    if self._historical_is_complete(
                        policy=policy,
                        pull=snapshot.pull_request,
                        pull_revision_digest=pull_digest,
                        policy_digest=policy_digest,
                        scopes=scopes,
                    ):
                        resolve_retry(snapshot.pull_request)
                        advanceable[scan_index] = True
                        persist_ready_items()
                        continue
                    outcome.historical_pull_requests_seen += 1
                    require_current_base_unchanged()
                    self._historical_checkpoint_all(
                        policy=policy,
                        snapshot=snapshot,
                        pull_revision_digest=pull_digest,
                        policy_digest=policy_digest,
                        scopes=scopes,
                        observed_at=observed_at,
                        remediation_reason=(
                            RemediationCoverageReason.INDEPENDENT_POLICY_REJECTED
                        ),
                        authority_digest=pull_digest,
                        require_exact_sources_still_closed=(
                            require_exact_sources_still_closed
                        ),
                    )
                    outcome.historical_policy_rejections += 1
                    outcome.historical_pull_requests_completed += 1
                    self._record_historical_terminal_status(
                        policy=policy,
                        snapshot=snapshot,
                        outcome_name="policy_rejected",
                        observed_at=observed_at,
                    )
                    resolve_retry(snapshot.pull_request)
                    advanceable[scan_index] = True
                    persist_ready_items()
                    continue
                except (_LeaseLost, PreventionLeaseLostError):
                    raise
                except PollDeadlineExceeded:
                    raise
                except Exception as exc:
                    outcome.historical_pull_requests_seen += 1
                    failure_type = _safe_failure_name(exc)
                    outcome.failures.append(failure_type)
                    quarantine_retry(
                        pull_id=snapshot.pull_request.pull_id,
                        pr_number=snapshot.pull_request.number,
                        failure_type=failure_type,
                    )
                    advanceable[scan_index] = True
                    persist_ready_items()
                    continue
                current_scope: _TargetScope | None = None
                current_applicable_paths: frozenset[str] = frozenset()
                if intake.authorized.events:
                    try:
                        current_scope, unavailable_paths = (
                            _current_historical_target_scope(
                                base_root=current_workspace.path,
                                policy=policy,
                                old_scope=intake.old_scope,
                                operator_pipeline_config=operator_config,
                                base_config_bundle_digest=config_bundle_digest,
                            )
                        )
                    except ValueError as exc:
                        outcome.historical_pull_requests_seen += 1
                        failure_type = _safe_failure_name(exc)
                        outcome.failures.append(failure_type)
                        quarantine_retry(
                            pull_id=snapshot.pull_request.pull_id,
                            pr_number=snapshot.pull_request.number,
                            failure_type=failure_type,
                        )
                        advanceable[scan_index] = True
                        persist_ready_items()
                        continue
                    else:
                        current_identity = _current_localization_content_digest(
                            root=current_workspace.path,
                            scope=current_scope,
                            policy=policy,
                            events=intake.authorized.events,
                            historical_path_locales=(intake.old_scope.path_locales),
                            unavailable_paths=unavailable_paths,
                        )
                        current_applicable_paths = current_identity.applicable_paths
                        pull_digest = _canonical_digest(
                            {
                                "historical": intake.historical_digest,
                                "current_localization": current_identity.digest,
                            }
                        )
                else:
                    pull_digest = intake.historical_digest
                if self._historical_is_complete(
                    policy=policy,
                    pull=snapshot.pull_request,
                    pull_revision_digest=pull_digest,
                    policy_digest=policy_digest,
                    scopes=scopes,
                ):
                    require_current_base_unchanged()
                    resolve_retry(snapshot.pull_request)
                    advanceable[scan_index] = True
                    persist_ready_items()
                    continue
                outcome.historical_pull_requests_seen += 1
                try:
                    assessed = self._assess_historical_snapshot(
                        policy=policy,
                        snapshot=snapshot,
                        intake=intake,
                        pull_revision_digest=pull_digest,
                        policy_digest=policy_digest,
                        current_scope=current_scope,
                        current_applicable_paths=current_applicable_paths,
                        current_workspace=current_workspace,
                        observed_at=observed_at,
                        lease_owner=lease_owner,
                        outcome=outcome,
                        require_current_base_unchanged=(require_current_base_unchanged),
                    )
                except _HistoricalPolicyRejection:
                    require_current_base_unchanged()
                    self._historical_checkpoint_all(
                        policy=policy,
                        snapshot=snapshot,
                        pull_revision_digest=pull_digest,
                        policy_digest=policy_digest,
                        scopes=scopes,
                        observed_at=observed_at,
                        remediation_reason=(
                            RemediationCoverageReason.INDEPENDENT_POLICY_REJECTED
                        ),
                        authority_digest=intake.historical_digest,
                        require_exact_sources_still_closed=(
                            require_exact_sources_still_closed
                        ),
                    )
                    outcome.historical_policy_rejections += 1
                    outcome.historical_pull_requests_completed += 1
                    self._record_historical_terminal_status(
                        policy=policy,
                        snapshot=snapshot,
                        outcome_name="policy_rejected",
                        observed_at=observed_at,
                    )
                    resolve_retry(snapshot.pull_request)
                    advanceable[scan_index] = True
                    persist_ready_items()
                except _HistoricalNoAction:
                    require_current_base_unchanged()
                    self._historical_checkpoint_all(
                        policy=policy,
                        snapshot=snapshot,
                        pull_revision_digest=pull_digest,
                        policy_digest=policy_digest,
                        scopes=scopes,
                        observed_at=observed_at,
                        remediation_reason=(
                            RemediationCoverageReason.INDEPENDENT_NO_ACTION
                        ),
                        authority_digest=intake.historical_digest,
                        require_exact_sources_still_closed=(
                            require_exact_sources_still_closed
                        ),
                    )
                    outcome.historical_pull_requests_completed += 1
                    self._record_historical_terminal_status(
                        policy=policy,
                        snapshot=snapshot,
                        outcome_name="no_action",
                        observed_at=observed_at,
                    )
                    resolve_retry(snapshot.pull_request)
                    advanceable[scan_index] = True
                    persist_ready_items()
                except _HistoricalLimitDeferred:
                    outcome.historical_items_deferred += (
                        len(candidates) - candidate_index
                    )
                    limit_deferred = True
                    break
                except (_AuthenticationCircuit, _ModelCircuit):
                    raise
                except (_LeaseLost, PreventionLeaseLostError):
                    raise
                except PollDeadlineExceeded:
                    raise
                except Exception as exc:
                    failure_type = _safe_failure_name(exc)
                    outcome.failures.append(failure_type)
                    quarantine_retry(
                        pull_id=snapshot.pull_request.pull_id,
                        pr_number=snapshot.pull_request.number,
                        failure_type=failure_type,
                    )
                    advanceable[scan_index] = True
                    persist_ready_items()
                else:
                    work.append((scan_index, assessed))

            if work:
                assessed_work = tuple(item for _index, item in work)
                remediation_retry_ids: set[int] = set()
                self._finish_historical_prevention(
                    policy=policy,
                    work=assessed_work,
                    scopes=scopes,
                    observed_at=observed_at,
                    require_live_lease=require_live_lease,
                    require_cleanup_lease=require_cleanup_lease,
                    require_current_base_unchanged=require_current_base_unchanged,
                    require_exact_sources_still_closed=(
                        require_exact_sources_still_closed
                    ),
                    outcome=outcome,
                )
                self._finish_historical_remediation(
                    policy=policy,
                    current_snapshot=current_snapshot,
                    current_revision=current_revision,
                    current_workspace=current_workspace,
                    work=assessed_work,
                    scopes=scopes,
                    observed_at=observed_at,
                    require_live_lease=require_live_lease,
                    require_current_base_unchanged=require_current_base_unchanged,
                    outcome=outcome,
                    recovery_retry_sources=selected_retry_sources,
                    retry_immediately=remediation_retry_ids,
                    require_exact_sources_still_closed=(
                        require_exact_sources_still_closed
                    ),
                    require_no_open_translation_overlap=(
                        require_no_open_translation_overlap
                    ),
                    open_changed_paths=open_changed_paths,
                )

                for scan_index, item in work:
                    if self._historical_is_complete(
                        policy=policy,
                        pull=item.snapshot.pull_request,
                        pull_revision_digest=item.pull_revision_digest,
                        policy_digest=item.policy_digest,
                        scopes=scopes,
                    ):
                        outcome.historical_pull_requests_completed += 1
                        resolve_retry(item.snapshot.pull_request)
                    else:
                        quarantine_retry(
                            pull_id=item.snapshot.pull_request.pull_id,
                            pr_number=item.snapshot.pull_request.number,
                            failure_type="HistoricalScopeIncomplete",
                        )
                    if item.snapshot.pull_request.pull_id not in remediation_retry_ids:
                        advanceable[scan_index] = True
                persist_ready_items()
            if limit_deferred:
                raise _HistoricalLimitDeferred
            current_pending_retries = self.state.pending_historical_pull_retries(
                repository=policy.base_repo,
                repository_id=policy.base_repo_id,
                policy_digest=policy_digest,
            )
            cycle_covered_pulls = cycle_seen_set.union(
                (
                    scan_items[index].pull_id,
                    scan_items[index].pull_number,
                )
                for index in persisted_indices
            )
            retries_covered = all(
                identity in cycle_covered_pulls for identity in current_pending_retries
            )
            if (
                scan_result.cycle_complete
                and len(persisted_indices) == len(scan_items)
                and retries_covered
            ):
                self.state.record_historical_discovery_progress(
                    repository=policy.base_repo,
                    repository_id=policy.base_repo_id,
                    policy_digest=policy_digest,
                    cycle_id=cycle_id,
                    cycle_started_at=cycle_started_at,
                    next_page=1,
                    next_offset=0,
                    cycle_complete=True,
                    expected_cursor_id=cursor.cursor_id,
                    recorded_at=observed_at,
                )

    def _assess_historical_snapshot(
        self,
        *,
        policy: RepositoryPolicy,
        snapshot: PullRequestFeedbackSnapshot,
        intake: _HistoricalIntake,
        pull_revision_digest: str,
        policy_digest: str,
        current_scope: _TargetScope | None,
        current_applicable_paths: frozenset[str],
        current_workspace: GuardianWorkspace,
        observed_at: datetime,
        lease_owner: str,
        outcome: _PollAccumulator,
        require_current_base_unchanged: Callable[[], None],
    ) -> _HistoricalAssessment:
        assert self.historical_checkout_factory is not None
        historical_head = intake.historical_head
        self._require_live_lease(lease_owner)
        old_scope = intake.old_scope
        authorized = intake.authorized
        tombstones = intake.tombstones
        # The old-base checkout used to prepare ``intake`` is already closed.
        with self.historical_checkout_factory(historical_head) as head_workspace:
            historical_regular_paths = _historical_regular_target_paths(
                head_workspace.path,
                tuple(old_scope.path_locales),
            )

            if not authorized.events:
                tombstone_records: list[tuple[FeedbackEvent, EventRevision]] = []
                for event in tombstones:
                    revision = self.state.record_feedback_event(
                        event,
                        observed_at=observed_at,
                    )
                    if revision.is_new:
                        outcome.feedback_revisions_recorded += 1
                    tombstone_records.append((event, revision))
                locale_label = ",".join(
                    sorted({event.locale for event, _revision in tombstone_records})
                )
                run_id = self.state.start_run(
                    repository=policy.base_repo,
                    locale=locale_label,
                    mode=self.config.mode,
                    started_at=observed_at,
                )
                outcome.runs_started += 1
                for _event, revision in tombstone_records:
                    self.state.record_action(
                        run_id=run_id,
                        event_revision_id=revision.revision_id,
                        action=self.config.mode.value,
                        status="skipped",
                        details={"outcome": "deleted"},
                        occurred_at=observed_at,
                    )
                self.state.finish_run(
                    run_id,
                    status="completed",
                    summary="Resolved deleted historical feedback without a model call.",
                    finished_at=observed_at,
                )
                outcome.runs_completed += 1
                raise _HistoricalNoAction

            assert current_scope is not None
            assessable_paths = frozenset(
                current_applicable_paths & historical_regular_paths
            )
            assessable_events, inapplicable_events = _partition_historical_events(
                authorized.events,
                path_locales=old_scope.path_locales,
                applicable_paths=assessable_paths,
            )
            tombstone_records = []
            for event in tombstones:
                revision = self.state.record_feedback_event(
                    event,
                    observed_at=observed_at,
                )
                if revision.is_new:
                    outcome.feedback_revisions_recorded += 1
                tombstone_records.append((event, revision))
            recorded: list[tuple[FeedbackEvent, EventRevision]] = []
            for event in authorized.events:
                revision = self.state.record_feedback_event(
                    event,
                    observed_at=observed_at,
                )
                if revision.is_new:
                    outcome.feedback_revisions_recorded += 1
                recorded.append((event, revision))
            assessable_ids = {event.feedback_id for event in assessable_events}
            inapplicable_ids = {event.feedback_id for event in inapplicable_events}
            assessable_records = tuple(
                (event, revision)
                for event, revision in recorded
                if event.feedback_id in assessable_ids
            )
            inapplicable_records = tuple(
                (event, revision)
                for event, revision in recorded
                if event.feedback_id in inapplicable_ids
            )
            events = tuple(event for event, _revision in assessable_records)
            revisions = tuple(revision for _event, revision in assessable_records)
            locale_label = ",".join(
                sorted(
                    {
                        event.locale
                        for event, _revision in (
                            *recorded,
                            *tombstone_records,
                        )
                    }
                )
            )
            run_id = self.state.start_run(
                repository=policy.base_repo,
                locale=locale_label,
                mode=self.config.mode,
                started_at=observed_at,
            )
            outcome.runs_started += 1
            for _event, revision in tombstone_records:
                self.state.record_action(
                    run_id=run_id,
                    event_revision_id=revision.revision_id,
                    action=self.config.mode.value,
                    status="skipped",
                    details={"outcome": "deleted"},
                    occurred_at=observed_at,
                )
            for _event, revision in inapplicable_records:
                self.state.record_action(
                    run_id=run_id,
                    event_revision_id=revision.revision_id,
                    action=self.config.mode.value,
                    status="skipped",
                    details={"outcome": "historical_target_inapplicable"},
                    occurred_at=observed_at,
                )
            if not events:
                self.state.finish_run(
                    run_id,
                    status="completed",
                    summary=(
                        "Resolved inapplicable historical feedback without "
                        "a model call."
                    ),
                    finished_at=observed_at,
                )
                outcome.runs_completed += 1
                if current_applicable_paths and not assessable_paths:
                    raise _HistoricalPolicyRejection
                raise _HistoricalNoAction
            try:
                changed_paths_set: set[str] = set()
                for event in events:
                    if event.path is not None:
                        changed_paths_set.add(event.path)
                    else:
                        changed_paths_set.update(
                            path
                            for path, locale in old_scope.path_locales.items()
                            if path in assessable_paths and locale == event.locale
                        )
                changed_paths = tuple(sorted(changed_paths_set))
                evidence_parent = self.evidence_root
                if evidence_parent is not None:
                    evidence_parent.mkdir(
                        parents=True,
                        exist_ok=True,
                        mode=0o700,
                    )
                with tempfile.TemporaryDirectory(
                    prefix="localize-guardian-history-evidence-",
                    dir=evidence_parent,
                ) as temporary_directory:
                    evidence_kwargs: dict[str, str] = {}
                    if current_scope.config_bundle_digest is not None:
                        evidence_kwargs["trusted_config_bundle_digest"] = (
                            current_scope.config_bundle_digest
                        )
                    bundle = self.evidence_builder(
                        destination=Path(temporary_directory) / "bundle",
                        repo_root=current_workspace.path,
                        trusted_pipeline_config_path=current_scope.config_path,
                        repository=policy.base_repo,
                        pr_number=snapshot.pull_request.number,
                        head_sha=snapshot.pull_request.head_sha,
                        base_sha=snapshot.pull_request.base_sha,
                        feedback=events,
                        changed_paths=changed_paths,
                        allowed_path_globs=policy.allowed_path_globs,
                        diff_text=_diff_text(
                            changed_paths,
                            old_scope.changed_files,
                        ),
                        trusted_config_root=current_scope.config_root,
                        trusted_source_root=current_workspace.path,
                        expected_source_locale=policy.source_locale,
                        **evidence_kwargs,
                    )
                    result = self._assessment_result(
                        bundle=bundle,
                        policy=policy,
                        snapshot=snapshot,
                        run_id=run_id,
                        prompt=_HISTORICAL_ASSESSMENT_PROMPT,
                    )
                    self._require_live_lease(lease_owner)
                    assessments = self.assessment_converter(
                        result,
                        feedback_events=events,
                        source_values=_source_values(bundle),
                        target_locales_by_feedback=_replacement_target_locales(
                            policy, events, current_scope.path_locales,
                        ),
                    )
                    replacements, deferred = _validated_historical_replacements(
                        assessments,
                        current_values=_localization_values(bundle),
                        minimum_confidence=(self.config.limits.min_apply_confidence),
                    )
            except (_BudgetUnavailable, _ModelCallLimitUnavailable) as exc:
                outcome_name = (
                    "historical_daily_budget_unavailable"
                    if isinstance(exc, _BudgetUnavailable)
                    else "historical_daily_model_call_limit_unavailable"
                )
                for _event, revision in assessable_records:
                    self.state.record_action(
                        run_id=run_id,
                        event_revision_id=revision.revision_id,
                        action=self.config.mode.value,
                        status="skipped",
                        details={"outcome": outcome_name},
                        occurred_at=observed_at,
                    )
                self.state.finish_run(
                    run_id,
                    status="cancelled",
                    summary="Historical assessment deferred by a daily model limit.",
                    finished_at=observed_at,
                )
                raise _HistoricalLimitDeferred from None
            except _ModelCredentialUnavailable:
                self._fail_actions(
                    run_id=run_id,
                    revisions=revisions,
                    outcome_name="historical_model_credential_unavailable",
                    observed_at=observed_at,
                )
                self.state.finish_run(
                    run_id,
                    status="failed",
                    summary="Historical model credential failed closed.",
                    finished_at=observed_at,
                )
                outcome.runs_failed += 1
                raise _AuthenticationCircuit from None
            except CodexAuthenticationError:
                self._fail_actions(
                    run_id=run_id,
                    revisions=revisions,
                    outcome_name="historical_codex_authentication_failed",
                    observed_at=observed_at,
                )
                self.state.finish_run(
                    run_id,
                    status="failed",
                    summary="Historical Codex authentication failed closed.",
                    finished_at=observed_at,
                )
                outcome.runs_failed += 1
                raise _AuthenticationCircuit from None
            except CodexCapacityError:
                self._fail_actions(
                    run_id=run_id,
                    revisions=revisions,
                    outcome_name="historical_codex_capacity_unavailable",
                    observed_at=observed_at,
                )
                self.state.finish_run(
                    run_id,
                    status="failed",
                    summary="Historical Codex capacity failed closed.",
                    finished_at=observed_at,
                )
                outcome.runs_failed += 1
                raise _ModelCircuit from None
            except (_LeaseLost, PreventionLeaseLostError):
                raise
            except Exception:
                self._fail_actions(
                    run_id=run_id,
                    revisions=revisions,
                    outcome_name="historical_assessment_failure",
                    observed_at=observed_at,
                )
                self.state.finish_run(
                    run_id,
                    status="failed",
                    summary="Historical assessment failed closed.",
                    finished_at=observed_at,
                )
                outcome.runs_failed += 1
                raise

            for assessment, (_event, revision) in zip(
                assessments,
                assessable_records,
                strict=True,
            ):
                self.state.record_action(
                    run_id=run_id,
                    event_revision_id=revision.revision_id,
                    action=self.config.mode.value,
                    status="completed",
                    details={
                        "outcome": "historical_assessed",
                        "verdict": assessment.verdict,
                        "confidence": assessment.confidence,
                        "eligible_replacements": sum(
                            1
                            for replacement in replacements
                            if replacement.feedback_id == assessment.feedback_id
                        ),
                        "recurrence_candidates": len(assessment.recurrence_candidates),
                    },
                    occurred_at=observed_at,
                )
            self.state.finish_run(
                run_id,
                status="completed",
                summary="Historical assessment completed within authority.",
                finished_at=observed_at,
            )
            outcome.runs_completed += 1
            outcome.historical_items_deferred += deferred
            require_current_base_unchanged()
            self._historical_checkpoint(
                policy=policy,
                snapshot=snapshot,
                pull_revision_digest=pull_revision_digest,
                policy_digest=policy_digest,
                scope=HistoricalCheckScope.ASSESSMENT,
                observed_at=observed_at,
                event_revision_ids=tuple(
                    revision.revision_id for revision in revisions
                ),
                ignored_event_revision_ids=tuple(
                    revision.revision_id
                    for _event, revision in (
                        *inapplicable_records,
                        *tombstone_records,
                    )
                ),
            )
            recurrence_candidates = tuple(
                candidate
                for assessment in assessments
                for candidate in assessment.recurrence_candidates
            )
            return _HistoricalAssessment(
                snapshot=snapshot,
                pull_revision_digest=pull_revision_digest,
                authority_digest=intake.historical_digest,
                policy_digest=policy_digest,
                run_id=run_id,
                events=events,
                revisions=revisions,
                assessments=tuple(assessments),
                current_scope=current_scope,
                replacements=replacements,
                recurrence_candidates=recurrence_candidates,
                feedback_urls=tuple(
                    dict.fromkeys(
                        event.html_url for event in events if event.html_url is not None
                    )
                ),
                deferred_replacements=deferred,
            )

    def _finish_historical_prevention(
        self,
        *,
        policy: RepositoryPolicy,
        work: Sequence[_HistoricalAssessment],
        scopes: Sequence[HistoricalCheckScope],
        observed_at: datetime,
        require_live_lease: Callable[[], None],
        require_cleanup_lease: Callable[[], None],
        require_current_base_unchanged: Callable[[], None],
        require_exact_sources_still_closed: Callable[
            [Sequence[HistoricalPullReference], Sequence[int]], None
        ],
        outcome: _PollAccumulator,
    ) -> None:
        if HistoricalCheckScope.PREVENTION not in scopes:
            return
        work = tuple(
            item
            for item in work
            if not self._historical_is_complete(
                policy=policy,
                pull=item.snapshot.pull_request,
                pull_revision_digest=item.pull_revision_digest,
                policy_digest=item.policy_digest,
                scopes=(HistoricalCheckScope.PREVENTION,),
            )
        )
        if not work:
            return

        def source_reference(
            item: _HistoricalAssessment,
        ) -> HistoricalPullReference:
            pull = item.snapshot.pull_request
            return HistoricalPullReference(
                repository=policy.base_repo,
                repository_id=policy.base_repo_id,
                pull_id=pull.pull_id,
                pr_number=pull.number,
                pull_revision_digest=item.pull_revision_digest,
                authority_digest=item.authority_digest,
                policy_digest=item.policy_digest,
                head_sha=pull.head_sha,
                base_sha=pull.base_sha,
            )

        def source_revision_ids(item: _HistoricalAssessment) -> tuple[int, ...]:
            return tuple(revision.revision_id for revision in item.revisions)

        without_candidates = tuple(
            item for item in work if not item.recurrence_candidates
        )
        for item in without_candidates:
            require_current_base_unchanged()
            require_exact_sources_still_closed(
                (source_reference(item),),
                source_revision_ids(item),
            )
            self._historical_checkpoint(
                policy=policy,
                snapshot=item.snapshot,
                pull_revision_digest=item.pull_revision_digest,
                policy_digest=item.policy_digest,
                scope=HistoricalCheckScope.PREVENTION,
                observed_at=observed_at,
            )
        candidate_work = tuple(item for item in work if item.recurrence_candidates)
        if not candidate_work:
            return
        revision_ids: dict[str, int] = {}
        for item in candidate_work:
            for event, revision in zip(item.events, item.revisions, strict=True):
                prior = revision_ids.setdefault(
                    event.feedback_id,
                    revision.revision_id,
                )
                if prior != revision.revision_id:
                    outcome.prevention_items_deferred += len(candidate_work)
                    return
        candidates = tuple(
            dict.fromkeys(
                candidate
                for item in candidate_work
                for candidate in item.recurrence_candidates
            )
        )
        assert self.prevention_runner is not None
        candidate_sources = tuple(source_reference(item) for item in candidate_work)
        candidate_revision_ids = tuple(
            sorted(
                revision.revision_id
                for item in candidate_work
                for revision in item.revisions
            )
        )
        try:
            require_current_base_unchanged()
            result = self.prevention_runner.propose(
                policy=policy,
                recurrence_candidates=candidates,
                evidence_revision_ids=revision_ids,
                run_id=candidate_work[0].run_id,
                observed_at=observed_at,
                require_live_lease=require_live_lease,
                require_cleanup_lease=require_cleanup_lease,
                require_current_base_unchanged=require_current_base_unchanged,
                source_pulls=candidate_sources,
                source_event_revision_ids=candidate_revision_ids,
                require_exact_sources_still_closed=(require_exact_sources_still_closed),
            )
        except CodexAuthenticationError:
            raise _AuthenticationCircuit from None
        except CodexCapacityError:
            raise _ModelCircuit from None
        except PollDeadlineExceeded:
            raise
        except GitHubAuthenticationError:
            raise
        except (_LeaseLost, PreventionLeaseLostError):
            raise
        except Exception as exc:
            outcome.prevention_failures.append(_safe_failure_name(exc))
            return
        self._record_prevention_outcome(result, outcome=outcome)
        if result.failures or result.deferred:
            return
        for item in candidate_work:
            require_current_base_unchanged()
            require_exact_sources_still_closed(
                (source_reference(item),),
                source_revision_ids(item),
            )
            self._historical_checkpoint(
                policy=policy,
                snapshot=item.snapshot,
                pull_revision_digest=item.pull_revision_digest,
                policy_digest=item.policy_digest,
                scope=HistoricalCheckScope.PREVENTION,
                observed_at=observed_at,
            )

    def _finish_historical_remediation(
        self,
        *,
        policy: RepositoryPolicy,
        current_snapshot: BaseRevisionSnapshot,
        current_revision: ExactRevision,
        current_workspace: GuardianWorkspace,
        work: Sequence[_HistoricalAssessment],
        scopes: Sequence[HistoricalCheckScope],
        observed_at: datetime,
        require_live_lease: Callable[[], None],
        require_current_base_unchanged: Callable[[], None],
        outcome: _PollAccumulator,
        recovery_retry_sources: Sequence[HistoricalPullReference],
        retry_immediately: set[int],
        require_exact_sources_still_closed: Callable[
            [Sequence[HistoricalPullReference], Sequence[int]], None
        ],
        require_no_open_translation_overlap: Callable[
            [Sequence[str], OpenPullPathIdentity | None], None
        ],
        open_changed_paths: frozenset[str],
    ) -> None:
        retry_source_keys = {
            (
                source.repository,
                source.repository_id,
                source.pull_id,
                source.pr_number,
                source.head_sha,
                source.base_sha,
            )
            for source in recovery_retry_sources
        }
        if HistoricalCheckScope.REMEDIATION in scopes:
            work = tuple(
                item
                for item in work
                if not self._historical_is_complete(
                    policy=policy,
                    pull=item.snapshot.pull_request,
                    pull_revision_digest=item.pull_revision_digest,
                    policy_digest=item.policy_digest,
                    scopes=(HistoricalCheckScope.REMEDIATION,),
                )
            )
            if not work:
                return
        overlapping_pull_ids = {
            item.snapshot.pull_request.pull_id
            for item in work
            if any(
                replacement.path in open_changed_paths
                for replacement in item.replacements
            )
        }
        if overlapping_pull_ids:
            outcome.remediation_items_deferred += len(overlapping_pull_ids)
            work = tuple(
                item
                for item in work
                if item.snapshot.pull_request.pull_id not in overlapping_pull_ids
            )
            if not work:
                return
        replacements, conflicted_pull_ids = _dedupe_historical_replacements(work)
        if conflicted_pull_ids:
            outcome.historical_items_deferred += len(conflicted_pull_ids)

        if HistoricalCheckScope.REMEDIATION not in scopes:
            if self.config.mode is GuardianMode.PREPARE and replacements:
                try:
                    patch = self.replacement_applier(
                        repo_root=current_workspace.path,
                        pipeline_config_path=work[0].current_scope.config_path,
                        allowed_paths=policy.allowed_path_globs,
                        replacements=replacements,
                        max_changes=self.config.limits.max_value_edits_per_run,
                        trusted_config_root=work[0].current_scope.config_root,
                        trusted_source_root=current_workspace.path,
                        expected_source_locale=policy.source_locale,
                    )
                except PatchPolicyError:
                    outcome.historical_items_deferred += len(replacements)
                else:
                    outcome.prepared_value_edits += len(patch.changed_keys)
            return

        outcome.remediation_items_deferred += len(conflicted_pull_ids)

        no_action = tuple(
            item
            for item in work
            if not item.replacements and item.deferred_replacements == 0
        )
        for item in no_action:
            require_current_base_unchanged()
            self._historical_checkpoint(
                policy=policy,
                snapshot=item.snapshot,
                pull_revision_digest=item.pull_revision_digest,
                policy_digest=item.policy_digest,
                scope=HistoricalCheckScope.REMEDIATION,
                observed_at=observed_at,
                event_revision_ids=tuple(
                    revision.revision_id for revision in item.revisions
                ),
                remediation_reason=(RemediationCoverageReason.INDEPENDENT_NO_ACTION),
                authority_digest=item.authority_digest,
                require_exact_sources_still_closed=(require_exact_sources_still_closed),
            )
        for item in work:
            if item.deferred_replacements:
                outcome.remediation_items_deferred += item.deferred_replacements

        actionable = tuple(
            item
            for item in work
            if item.snapshot.pull_request.pull_id not in conflicted_pull_ids
            and item.deferred_replacements == 0
            and item.replacements
        )
        if not actionable or not replacements:
            return

        def source_key(item: _HistoricalAssessment) -> tuple[object, ...]:
            pull = item.snapshot.pull_request
            return (
                policy.base_repo,
                policy.base_repo_id,
                pull.pull_id,
                pull.number,
                pull.head_sha,
                pull.base_sha,
            )

        def source_reference(
            item: _HistoricalAssessment,
        ) -> HistoricalPullReference:
            pull = item.snapshot.pull_request
            return HistoricalPullReference(
                repository=policy.base_repo,
                repository_id=policy.base_repo_id,
                pull_id=pull.pull_id,
                pr_number=pull.number,
                pull_revision_digest=item.pull_revision_digest,
                authority_digest=item.authority_digest,
                policy_digest=item.policy_digest,
                head_sha=pull.head_sha,
                base_sha=pull.base_sha,
            )

        def source_revision_ids(
            item: _HistoricalAssessment,
        ) -> tuple[int, ...]:
            return tuple(revision.revision_id for revision in item.revisions)

        actionable_targets = {
            (replacement.path, replacement.key)
            for item in actionable
            for replacement in item.replacements
        }
        eligible_replacements = tuple(
            replacement
            for replacement in replacements
            if (replacement.path, replacement.key) in actionable_targets
        )
        if not eligible_replacements:
            return
        edit_target_hashes = tuple(
            sorted(
                (
                    remediation_edit_hash(replacement),
                    remediation_target_hash(replacement),
                )
                for replacement in eligible_replacements
            )
        )
        coverage = self.state.remediation_edit_coverage(
            target_repository=policy.base_repo,
            target_repository_id=policy.base_repo_id,
            edit_target_hashes=edit_target_hashes,
        )
        requested_hashes = frozenset(edit for edit, _target in edit_target_hashes)
        coverage_sets = (
            coverage.opened_edit_hashes,
            coverage.pending_edit_hashes,
            coverage.incompatible_edit_hashes,
            coverage.conflicting_edit_hashes,
        )
        if any(not values <= requested_hashes for values in coverage_sets):
            raise RuntimeError("Remediation coverage escaped the requested edit set.")
        if coverage.repository_identity_conflict or coverage.unmapped_active_conflict:
            outcome.remediation_items_deferred += len(actionable)
            return

        ambiguous_hashes = coverage.opened_edit_hashes & coverage.pending_edit_hashes
        unmapped_or_ambiguous_opened_hashes = frozenset(
            edit_hash
            for edit_hash in coverage.opened_edit_hashes
            if len(tuple(coverage.opened_draft_keys_by_edit_hash.get(edit_hash, ())))
            != 1
        )
        blocked_hashes = (
            coverage.incompatible_edit_hashes
            | coverage.conflicting_edit_hashes
            | ambiguous_hashes
            | unmapped_or_ambiguous_opened_hashes
        )
        blocked_pull_ids = {
            item.snapshot.pull_request.pull_id
            for item in actionable
            if any(
                remediation_edit_hash(replacement) in blocked_hashes
                for replacement in item.replacements
            )
        }
        blocked_pull_ids.update(
            item.snapshot.pull_request.pull_id
            for item in actionable
            if source_key(item) not in retry_source_keys
            and any(
                remediation_edit_hash(replacement) in coverage.pending_edit_hashes
                for replacement in item.replacements
            )
        )
        if blocked_pull_ids:
            outcome.remediation_items_deferred += len(blocked_pull_ids)
            actionable = tuple(
                item
                for item in actionable
                if item.snapshot.pull_request.pull_id not in blocked_pull_ids
            )
        if not actionable:
            return

        # A directly rehydrated recovery batch gets the repository's one
        # publication opportunity before unrelated new work. The coordinator
        # still requires an exact active batch before it can reuse a branch.
        if coverage.pending_edit_hashes:
            pending_recovery = tuple(
                item
                for item in actionable
                if source_key(item) in retry_source_keys
                and any(
                    remediation_edit_hash(replacement) in coverage.pending_edit_hashes
                    for replacement in item.replacements
                )
            )
            if pending_recovery:
                pending_ids = {
                    item.snapshot.pull_request.pull_id for item in pending_recovery
                }
                retry_immediately.update(
                    item.snapshot.pull_request.pull_id
                    for item in actionable
                    if item.snapshot.pull_request.pull_id not in pending_ids
                )
                actionable = pending_recovery

        opened_only = tuple(
            item
            for item in actionable
            if all(
                remediation_edit_hash(replacement) in coverage.opened_edit_hashes
                for replacement in item.replacements
            )
        )
        if opened_only:
            coverage_by_source: dict[HistoricalPullReference, tuple[str, ...]] = {}
            revision_ids_by_source: dict[HistoricalPullReference, tuple[int, ...]] = {}
            required_edit_hashes_by_source: dict[
                HistoricalPullReference, tuple[str, ...]
            ] = {}
            for item in opened_only:
                source = source_reference(item)
                draft_keys = tuple(
                    sorted(
                        {
                            coverage.opened_draft_keys_by_edit_hash[
                                remediation_edit_hash(replacement)
                            ][0]
                            for replacement in item.replacements
                        }
                    )
                )
                coverage_by_source[source] = draft_keys
                revision_ids_by_source[source] = source_revision_ids(item)
                required_edit_hashes_by_source[source] = tuple(
                    sorted(
                        remediation_edit_hash(replacement)
                        for replacement in item.replacements
                    )
                )
            all_revision_ids = tuple(
                sorted(
                    revision_id
                    for revision_ids in revision_ids_by_source.values()
                    for revision_id in revision_ids
                )
            )
            require_exact_sources_still_closed(
                tuple(coverage_by_source),
                all_revision_ids,
            )
            self.state.record_draft_backed_remediation_completions(
                coverage_by_source,
                RemediationCoverageReason.DRAFT_SEMANTIC_DEDUPE,
                required_edit_hashes_by_source=required_edit_hashes_by_source,
                event_revision_ids_by_source=revision_ids_by_source,
                occurred_at=observed_at,
            )
        opened_only_ids = {item.snapshot.pull_request.pull_id for item in opened_only}
        actionable = tuple(
            item
            for item in actionable
            if item.snapshot.pull_request.pull_id not in opened_only_ids
        )
        if not actionable:
            return
        actionable_targets = {
            (replacement.path, replacement.key)
            for item in actionable
            for replacement in item.replacements
            if remediation_edit_hash(replacement) not in coverage.opened_edit_hashes
        }
        eligible_replacements = tuple(
            replacement
            for replacement in replacements
            if (replacement.path, replacement.key) in actionable_targets
            and remediation_edit_hash(replacement) not in coverage.opened_edit_hashes
        )
        if not eligible_replacements:
            return
        max_changes = self.config.limits.max_value_edits_per_run
        selected = eligible_replacements[:max_changes]
        if not selected:
            outcome.remediation_items_deferred += len(actionable)
            return
        selected_targets = {
            (replacement.path, replacement.key) for replacement in selected
        }
        participating = tuple(
            item
            for item in actionable
            if any(
                (replacement.path, replacement.key) in selected_targets
                for replacement in item.replacements
            )
        )
        # The representative proposal must itself come from a participating
        # pull. A stable-deduped target may initially have been represented by
        # an otherwise deferred pull that happened to agree with this batch.
        selected = tuple(
            next(
                candidate
                for item in participating
                for candidate in item.replacements
                if (candidate.path, candidate.key)
                == (replacement.path, replacement.key)
            )
            for replacement in selected
        )
        if not participating or not selected:
            return
        participating_ids = {
            item.snapshot.pull_request.pull_id for item in participating
        }
        deferred_pull_ids = {
            item.snapshot.pull_request.pull_id
            for item in actionable
            if item.snapshot.pull_request.pull_id not in participating_ids
            or any(
                (replacement.path, replacement.key) not in selected_targets
                for replacement in item.replacements
                if remediation_edit_hash(replacement) not in coverage.opened_edit_hashes
            )
        }
        outcome.remediation_items_deferred += len(deferred_pull_ids)
        try:
            patch_result = self.replacement_applier(
                repo_root=current_workspace.path,
                pipeline_config_path=work[0].current_scope.config_path,
                allowed_paths=policy.allowed_path_globs,
                replacements=selected,
                max_changes=max_changes,
                trusted_config_root=work[0].current_scope.config_root,
                trusted_source_root=current_workspace.path,
                expected_source_locale=policy.source_locale,
            )
        except PatchPolicyError:
            outcome.remediation_items_deferred += len(participating)
            return
        outcome.prepared_value_edits += len(patch_result.changed_keys)
        if not patch_result.changed_files:
            selected_hashes = frozenset(
                remediation_edit_hash(replacement) for replacement in selected
            )
            independently_complete = tuple(
                item
                for item in participating
                if {
                    remediation_edit_hash(replacement)
                    for replacement in item.replacements
                    if remediation_edit_hash(replacement)
                    not in coverage.opened_edit_hashes
                }
                <= selected_hashes
            )
            for item in independently_complete:
                require_current_base_unchanged()
                self._historical_checkpoint(
                    policy=policy,
                    snapshot=item.snapshot,
                    pull_revision_digest=item.pull_revision_digest,
                    policy_digest=item.policy_digest,
                    scope=HistoricalCheckScope.REMEDIATION,
                    observed_at=observed_at,
                    event_revision_ids=tuple(
                        revision.revision_id for revision in item.revisions
                    ),
                    remediation_reason=(
                        RemediationCoverageReason.INDEPENDENT_ALREADY_CURRENT
                    ),
                    authority_digest=item.authority_digest,
                    require_exact_sources_still_closed=(
                        require_exact_sources_still_closed
                    ),
                )
            return

        assert self.remediation_runner is not None
        closed_policy = policy.closed_pr_backfill
        assert closed_policy is not None
        remediation_policy = closed_policy.remediation
        assert remediation_policy is not None
        base = RemediationBaseSnapshot(
            revision=current_revision,
            target_repository_id=policy.base_repo_id,
            push_repository_id=remediation_policy.push_repository.id,
            private=current_snapshot.repository_identity.private,
        )
        source_pulls = tuple(source_reference(item) for item in participating)
        prior_draft_keys_by_source = {
            source_reference(item): tuple(
                sorted(
                    {
                        coverage.opened_draft_keys_by_edit_hash[
                            remediation_edit_hash(replacement)
                        ][0]
                        for replacement in item.replacements
                        if remediation_edit_hash(replacement)
                        in coverage.opened_edit_hashes
                    }
                )
            )
            for item in participating
        }
        required_edit_hashes_by_source = {
            source_reference(item): tuple(
                sorted(
                    {
                        remediation_edit_hash(replacement)
                        for replacement in item.replacements
                    }
                )
            )
            for item in participating
        }
        event_revision_ids = tuple(
            revision.revision_id
            for item in participating
            for revision in item.revisions
        )
        feedback_urls = tuple(
            dict.fromkeys(
                feedback_url
                for item in participating
                for feedback_url in item.feedback_urls
            )
        )
        recovery_attempt = all(
            source_key(item) in retry_source_keys for item in participating
        )
        selected_edit_hashes = tuple(
            sorted(remediation_edit_hash(replacement) for replacement in selected)
        )
        selected_batch_hash = remediation_batch_hash(selected_edit_hashes)

        def active_exact_batch_exists() -> bool:
            return bool(
                self.state.active_remediation_drafts_for_identity(
                    repository=policy.base_repo,
                    repository_id=policy.base_repo_id,
                    batch_hash=selected_batch_hash,
                )
            )

        try:
            require_current_base_unchanged()
            published = self.remediation_runner.publish(
                policy=policy,
                base=base,
                workspace=current_workspace,
                patch_result=patch_result,
                replacements=selected,
                source_pulls=source_pulls,
                event_revision_ids=event_revision_ids,
                feedback_urls=feedback_urls,
                run_id=participating[0].run_id,
                observed_at=observed_at,
                require_live_lease=require_live_lease,
                require_current_base_unchanged=(require_current_base_unchanged),
                require_exact_sources_still_closed=(require_exact_sources_still_closed),
                require_no_open_translation_overlap=(
                    require_no_open_translation_overlap
                ),
                prior_draft_keys_by_source=prior_draft_keys_by_source,
                required_edit_hashes_by_source=required_edit_hashes_by_source,
            )
            terminal, _retry_sources = self._remediation_outcome(
                published,
                outcome=outcome,
            )
        except GitHubAuthenticationError:
            raise
        except (_LeaseLost, PreventionLeaseLostError):
            raise
        except PollDeadlineExceeded:
            raise
        except RemediationSourceAuthorityError as exc:
            outcome.remediation_failures.append(_safe_failure_name(exc))
            return
        except Exception as exc:
            outcome.remediation_failures.append(_safe_failure_name(exc))
            if not recovery_attempt and active_exact_batch_exists():
                retry_immediately.update(
                    item.snapshot.pull_request.pull_id for item in participating
                )
            return
        if not terminal:
            if not recovery_attempt and active_exact_batch_exists():
                retry_immediately.update(
                    item.snapshot.pull_request.pull_id for item in participating
                )
            return

    def _recover_publications(
        self,
        *,
        policy: RepositoryPolicy,
        snapshots: Sequence[PullRequestFeedbackSnapshot],
        observed_at: datetime,
        lease_owner: str,
    ) -> None:
        """Finish an idempotent reply after a confirmed push or process crash."""

        if (
            self.config.mode
            not in {
                GuardianMode.APPLY_OWNED_TRANSLATIONS,
                GuardianMode.PROPOSE_PREVENTION,
            }
            or self.write_broker_factory is None
        ):
            return
        publication_actor = policy.publication_actor
        if publication_actor is None:  # pragma: no cover - config invariant
            raise _PublicationRecoveryManualRequired(
                "Publication recovery lacks a configured publication actor."
            )
        try:
            pending_publications = self.state.pending_publications(
                repository=policy.base_repo,
                repository_id=policy.base_repo_id,
            )
        except (TypeError, ValueError, RuntimeError) as exc:
            raise _PublicationRecoveryManualRequired(
                "Pending publication authority is unavailable or malformed."
            ) from exc
        snapshots_by_pr = {
            snapshot.pull_request.number: snapshot for snapshot in snapshots
        }
        for publication in pending_publications:
            self._require_live_lease(lease_owner)
            if (
                publication.publication_actor_id is None
                or publication.publication_actor_type is None
                or publication.publication_actor_id != publication_actor.id
                or publication.publication_actor_type != publication_actor.type
            ):
                raise _PublicationRecoveryManualRequired(
                    "Pending publication actor no longer matches repository policy."
                )
            remediation_draft = self.state.remediation_draft_for_pull(
                repository=policy.base_repo,
                repository_id=policy.base_repo_id,
                pr_number=publication.pr_number,
            )
            try:
                successor_intent = (
                    self.state.remediation_successor_intent(
                        publication_key=publication.publication_key
                    )
                    if remediation_draft is not None
                    else None
                )
            except (TypeError, ValueError, RuntimeError) as exc:
                raise _PublicationRecoveryManualRequired(
                    "Remediation successor intent is unavailable or malformed."
                ) from exc
            metadata = {
                "run_id": publication.run_id,
                "repository": publication.repository,
                "pr_number": publication.pr_number,
                "original_head_sha": publication.original_head_sha,
                "base_sha": publication.base_sha,
                "commit_sha": publication.commit_sha,
                "publication_actor_id": publication.publication_actor_id,
                "publication_actor_type": publication.publication_actor_type,
                "event_revision_ids": publication.event_revision_ids,
                "open_source": publication.open_source,
                "occurred_at": observed_at,
            }

            def abandon(reason: str) -> None:
                self._require_live_lease(lease_owner)
                self.state.finalize_abandoned_publication(
                    publication_key=publication.publication_key,
                    reason=reason,
                    summary="Abandoned a publication outside current PR authority.",
                    occurred_at=observed_at,
                )

            if remediation_draft is not None:
                if successor_intent is None:
                    raise _PublicationRecoveryManualRequired(
                        "A remediation successor is remote without durable intent."
                    )
                if (
                    publication.open_source is None
                    or publication.open_source.feedback_digest is None
                ):
                    raise _PublicationRecoveryManualRequired(
                        "A remediation successor lacks durable open-pull authority."
                    )
                if self.remediation_runner is None:
                    raise _PublicationRecoveryManualRequired(
                        "Exact remediation successor recovery is unavailable."
                    )
                remediation_policy = (
                    None
                    if policy.closed_pr_backfill is None
                    else policy.closed_pr_backfill.remediation
                )
                if (
                    remediation_policy is None
                    or successor_intent.publication_actor_id
                    != remediation_policy.publication_actor.id
                    or successor_intent.publication_actor_type
                    != remediation_policy.publication_actor.type
                ):
                    raise _PublicationRecoveryManualRequired(
                        "Remediation successor publication actor changed."
                    )
                try:
                    exact_remediation = (
                        self.remediation_runner.revalidate_successor_pull(
                            policy=policy,
                            publication_key=publication.publication_key,
                            expected_remote_head_sha=publication.commit_sha,
                            expected_base_sha=publication.base_sha,
                            require_open=False,
                            require_live_lease=lambda: self._require_live_lease(
                                lease_owner
                            ),
                            require_no_open_translation_overlap=lambda paths,
                            excluded: self._require_no_open_translation_overlap(
                                policy=policy,
                                candidate_paths=paths,
                                excluded_pull=excluded,
                                require_live_lease=lambda: self._require_live_lease(
                                    lease_owner
                                ),
                            ),
                        )
                    )
                except RemediationRemoteConflictError:
                    # A prepared row may legitimately predate the branch push.
                    # Only the exact unchanged parent PR can retire that intent;
                    # all other conflicts remain pending for manual inspection.
                    try:
                        parent = self.remediation_runner.revalidate_successor_pull(
                            policy=policy,
                            publication_key=publication.publication_key,
                            expected_remote_head_sha=publication.original_head_sha,
                            expected_base_sha=publication.base_sha,
                            require_open=False,
                            require_live_lease=lambda: self._require_live_lease(
                                lease_owner
                            ),
                            require_no_open_translation_overlap=lambda paths,
                            excluded: self._require_no_open_translation_overlap(
                                policy=policy,
                                candidate_paths=paths,
                                excluded_pull=excluded,
                                require_live_lease=lambda: self._require_live_lease(
                                    lease_owner
                                ),
                            ),
                        )
                    except RemediationRemoteConflictError:
                        raise
                    if parent.candidate_sha != publication.original_head_sha:
                        raise _PublicationRecoveryManualRequired(
                            "Remediation successor recovery returned ambiguous lineage."
                        )
                    abandon("guardian_commit_not_present")
                    continue
                self._require_live_lease(lease_owner)
                self.state.record_remediation_successor_publication_event(
                    **metadata,
                    phase="published",
                    draft_key=successor_intent.draft_key,
                    source_pulls=successor_intent.source_pulls,
                    edit_hashes=successor_intent.edit_hashes,
                    changed_paths=successor_intent.changed_paths,
                    actor_id=successor_intent.actor_id,
                    actor_type=successor_intent.actor_type,
                )
                if exact_remediation.state == "closed":
                    # The push is part of the immutable successor chain, but a
                    # status comment has independent open-PR authority. Retire
                    # only that reply path and never write to the closed PR.
                    reply_terminal_reason = (
                        "remediation_merged"
                        if exact_remediation.merged
                        else "remediation_closed_unmerged"
                    )
                    self._require_live_lease(lease_owner)
                    self.state.finalize_publication_reply_terminal(
                        publication_key=publication.publication_key,
                        reason=reply_terminal_reason,
                        summary=(
                            "Recovered a confirmed Guardian publication; "
                            "the remediation pull was already closed."
                        ),
                        occurred_at=observed_at,
                    )
                    continue
            else:
                if (
                    publication.open_source is None
                    or publication.open_source.feedback_digest is None
                ):
                    raise _PublicationRecoveryManualRequired(
                        "Publication recovery lacks durable open-pull authority."
                    )
                snapshot = snapshots_by_pr.get(publication.pr_number)
                if snapshot is None:
                    abandon("pull_request_not_open_or_authorized")
                    continue
                pull = snapshot.pull_request
                if pull.head_sha == publication.original_head_sha:
                    abandon("guardian_commit_not_present")
                    continue
                if pull.head_sha != publication.commit_sha:
                    abandon("pull_request_head_moved")
                    continue
                if pull.base_sha != publication.base_sha:
                    abandon("pull_request_base_moved")
                    continue

            assert publication.open_source is not None
            try:
                self._require_exact_open_source_authority(
                    policy=policy,
                    source=publication.open_source,
                    event_revision_ids=publication.event_revision_ids,
                    require_live_lease=lambda: self._require_live_lease(lease_owner),
                    expected_current_head_sha=publication.commit_sha,
                )
            except _PublishedFeedbackChanged:
                self._require_live_lease(lease_owner)
                self.state.finalize_publication_reply_terminal(
                    publication_key=publication.publication_key,
                    reason="trusted_feedback_changed",
                    summary="Recovered published correction; changed feedback suppressed reply.",
                    occurred_at=observed_at,
                )
                continue
            except PreventionSourceAuthorityError:
                abandon("trusted_feedback_changed_before_reply")
                continue

            broker = self.write_broker_factory(policy)

            def revalidate_reply_authority() -> None:
                self._require_live_lease(lease_owner)
                if remediation_draft is not None:
                    assert self.remediation_runner is not None
                    self.remediation_runner.revalidate_successor_pull(
                        policy=policy,
                        publication_key=publication.publication_key,
                        expected_remote_head_sha=publication.commit_sha,
                        expected_base_sha=publication.base_sha,
                        require_open=True,
                        require_live_lease=lambda: self._require_live_lease(
                            lease_owner
                        ),
                        require_no_open_translation_overlap=lambda paths,
                        excluded: self._require_no_open_translation_overlap(
                            policy=policy,
                            candidate_paths=paths,
                            excluded_pull=excluded,
                            require_live_lease=lambda: self._require_live_lease(
                                lease_owner
                            ),
                        ),
                    )
                self._require_exact_open_source_authority(
                    policy=policy,
                    source=publication.open_source,
                    event_revision_ids=publication.event_revision_ids,
                    require_live_lease=lambda: self._require_live_lease(lease_owner),
                    expected_current_head_sha=publication.commit_sha,
                )

            self._require_live_lease(lease_owner)
            broker.post_commit_reply(
                pull_number=publication.pr_number,
                expected_head_sha=publication.commit_sha,
                expected_base_sha=publication.base_sha,
                commit_sha=publication.commit_sha,
                action_id=publication.publication_key,
                event_revision_id=str(min(publication.event_revision_ids)),
                expected_actor=publication_actor,
                before_create=revalidate_reply_authority,
            )
            self._require_live_lease(lease_owner)
            self.state.finalize_replied_publication(
                publication_key=publication.publication_key,
                summary="Recovered a confirmed Guardian publication.",
                occurred_at=observed_at,
            )

    def _process_snapshot(
        self,
        *,
        policy: RepositoryPolicy,
        snapshot: PullRequestFeedbackSnapshot,
        observed_at: datetime,
        lease_owner: str,
        outcome: _PollAccumulator,
    ) -> None:
        """Authorize and process one exact PR under the shared poll lease."""
        self._require_live_lease(lease_owner)
        base_revision, head_revision = _exact_revisions(
            policy,
            snapshot,
            github_host=self.github_host,
        )
        previous = self.state.latest_event_revisions(
            repository=policy.base_repo,
            pr_number=snapshot.pull_request.number,
        )
        with self.checkout_factory(base_revision) as base_workspace:
            base_config_bundle_digest = (
                _base_pipeline_config_bundle_digest(
                    config_root=base_workspace.path,
                    config_relative_path=policy.pipeline_config_path,
                )
                if policy.pipeline_config_source is PipelineConfigSource.BASE
                else None
            )
            scope = _target_scope(
                base_root=base_workspace.path,
                policy=policy,
                changed_files=snapshot.changed_files,
                operator_pipeline_config=self.operator_pipeline_configs.get(
                    policy.base_repo
                ),
                base_config_bundle_digest=base_config_bundle_digest,
            )
            authorized = authorize_feedback(
                policy=policy,
                snapshot=snapshot,
                path_locales=scope.path_locales,
                changed_locales=tuple(sorted(set(scope.path_locales.values()))),
            )
            open_source = self._open_pull_authority_reference(
                policy=policy,
                snapshot=snapshot,
                authorized=authorized,
            )
            current_events = (
                *authorized.events,
                *_trusted_tombstones(
                    policy=policy,
                    snapshot=snapshot,
                    previous=previous,
                ),
            )
            publication_actor = policy.publication_actor
            replied_publication = (
                None
                if publication_actor is None
                else self.state.replied_publication_for_head(
                    repository=policy.base_repo,
                    repository_id=policy.base_repo_id,
                    pr_number=snapshot.pull_request.number,
                    head_sha=snapshot.pull_request.head_sha,
                    publication_actor_id=publication_actor.id,
                    publication_actor_type=publication_actor.type,
                )
            )
            addressed_signatures: set[tuple[str, str, str]] = set()
            translation_applied_signatures: set[tuple[str, str, str]] = set()
            if replied_publication is not None:
                publication_mode = self.state.get_run(replied_publication.run_id).mode
                signature_target = (
                    translation_applied_signatures
                    if self.config.mode is GuardianMode.PROPOSE_PREVENTION
                    and publication_mode is GuardianMode.APPLY_OWNED_TRANSLATIONS
                    else addressed_signatures
                )
                for revision_id in replied_publication.event_revision_ids:
                    prior_revision = self.state.get_event_revision(revision_id)
                    if prior_revision is not None:
                        signature_target.add(
                            (
                                prior_revision.kind,
                                prior_revision.event_id,
                                prior_revision.revision_hash,
                            )
                        )
            current: dict[tuple[str, str], tuple[FeedbackEvent, EventRevision]] = {}
            for event in current_events:
                revision = self.state.record_feedback_event(
                    event,
                    observed_at=observed_at,
                )
                if revision.is_new:
                    outcome.feedback_revisions_recorded += 1
                current[(event.kind, event.event_id)] = (event, revision)

            if (
                replied_publication is not None
                and replied_publication.repository != policy.base_repo
            ):
                # A GitHub repository rename changes feedback URLs but not the
                # underlying review objects. Match the current-route revision
                # to the exact old-route content identity already covered by
                # the replied publication, while persisting new observations
                # under the current policy route.
                for event, revision in current.values():
                    aliased_event = _feedback_repository_alias(
                        (event,),
                        current_repository=policy.base_repo,
                        repository=replied_publication.repository,
                    )[0]
                    aliased_signature = (
                        event.kind,
                        event.event_id,
                        feedback_revision_hash(aliased_event),
                    )
                    current_signature = (
                        event.kind,
                        event.event_id,
                        revision.revision_hash,
                    )
                    if aliased_signature in addressed_signatures:
                        addressed_signatures.add(current_signature)
                    if aliased_signature in translation_applied_signatures:
                        translation_applied_signatures.add(current_signature)

            pending = tuple(
                revision
                for revision in self.state.pending_event_revisions(
                    repository=policy.base_repo,
                    pr_number=snapshot.pull_request.number,
                    mode=self.config.mode,
                    policy_digest=_patch_policy_digest(self.config, policy, scope),
                )
            )
            current_revision_ids = {
                revision.revision_id for _event, revision in current.values()
            }
            superseded = tuple(
                revision
                for revision in pending
                if (revision.kind, revision.event_id) in current
                and revision.revision_id not in current_revision_ids
            )
            current_pending = tuple(
                (event, revision)
                for event, revision in current.values()
                if revision.revision_id
                in {pending_revision.revision_id for pending_revision in pending}
            )
            if not superseded and not current_pending:
                return

            locale_label = ",".join(
                sorted(
                    {
                        revision.locale
                        for revision in (
                            *superseded,
                            *(item[1] for item in current_pending),
                        )
                    }
                )
            )
            run_id = self.state.start_run(
                repository=policy.base_repo,
                locale=locale_label,
                mode=self.config.mode,
                started_at=observed_at,
            )
            outcome.runs_started += 1
            for revision in superseded:
                self.state.record_action(
                    run_id=run_id,
                    event_revision_id=revision.revision_id,
                    action=self.config.mode.value,
                    status="skipped",
                    details={"outcome": "superseded_revision"},
                    occurred_at=observed_at,
                )

            deleted = tuple(
                (event, revision)
                for event, revision in current_pending
                if event.deleted
            )
            already_addressed = tuple(
                (event, revision)
                for event, revision in current_pending
                if (
                    event.kind,
                    event.event_id,
                    revision.revision_hash,
                )
                in addressed_signatures
            )
            actionable = tuple(
                (event, revision)
                for event, revision in current_pending
                if not event.deleted
                and revision.revision_id
                not in {item[1].revision_id for item in already_addressed}
            )
            translation_suppressed_feedback_ids = frozenset(
                event.feedback_id
                for event, revision in actionable
                if (
                    event.kind,
                    event.event_id,
                    revision.revision_hash,
                )
                in translation_applied_signatures
            )
            for _event, revision in deleted:
                self.state.record_action(
                    run_id=run_id,
                    event_revision_id=revision.revision_id,
                    action=self.config.mode.value,
                    status="skipped",
                    details={"outcome": "deleted"},
                    occurred_at=observed_at,
                )
            for _event, revision in already_addressed:
                self.state.record_action(
                    run_id=run_id,
                    event_revision_id=revision.revision_id,
                    action=self.config.mode.value,
                    status="skipped",
                    details={"outcome": "already_applied_by_guardian"},
                    occurred_at=observed_at,
                )
            if not actionable:
                self.state.finish_run(
                    run_id,
                    status="completed",
                    summary=(
                        "Resolved only superseded, deleted, or already-applied "
                        "feedback revisions."
                    ),
                    finished_at=observed_at,
                )
                outcome.runs_completed += 1
                return

            try:
                with self.checkout_factory(head_revision) as head_workspace:
                    self._assess_and_act(
                        policy=policy,
                        snapshot=snapshot,
                        scope=scope,
                        base_workspace=base_workspace,
                        head_workspace=head_workspace,
                        actionable=actionable,
                        open_source=open_source,
                        translation_suppressed_feedback_ids=(
                            translation_suppressed_feedback_ids
                        ),
                        run_id=run_id,
                        observed_at=observed_at,
                        require_live_lease=lambda: self._require_live_lease(
                            lease_owner
                        ),
                        lease_owner=lease_owner,
                        outcome=outcome,
                    )
            except (_LeaseLost, PreventionLeaseLostError):
                raise
            except Exception:
                # Checkout/materialization can fail before _assess_and_act owns
                # the run. Never strand it as running; that would suppress a
                # truthful immediate status until the next stale-run sweep.
                if (
                    self.state.get_run(run_id).status == "running"
                    and not self.state.has_pending_publication_for_run(run_id)
                ):
                    self._fail_actions(
                        run_id=run_id,
                        revisions=tuple(revision for _event, revision in actionable),
                        outcome_name="head_checkout_failure",
                        observed_at=observed_at,
                    )
                    self.state.finish_run(
                        run_id,
                        status="failed",
                        summary="Exact head checkout failed closed.",
                        finished_at=observed_at,
                    )
                    outcome.runs_failed += 1
                raise

    def _assessment_result(
        self,
        *,
        bundle: EvidenceBundle,
        policy: RepositoryPolicy,
        snapshot: PullRequestFeedbackSnapshot,
        run_id: str,
        prompt: str = _ASSESSMENT_PROMPT,
    ) -> CodexResult:
        model = self.codex_driver.model
        reasoning_effort = self.config.runtime.codex_reasoning_effort
        cache_key = _assessment_cache_key(
            bundle,
            model=model,
            reasoning_effort=reasoning_effort,
            prompt=prompt,
        )
        cached = self.state.cached_assessment_result(
            cache_key=cache_key,
            repository=policy.base_repo,
            pr_number=snapshot.pull_request.number,
            head_sha=snapshot.pull_request.head_sha,
            base_sha=snapshot.pull_request.base_sha,
            model=model,
            reasoning_effort=reasoning_effort,
        )
        if cached is not None:
            return parse_cached_codex_result(cached)

        api_key = None
        if self.config.runtime.codex_auth_mode is CodexAuthMode.API_KEY:
            if self.model_credential_provider is None:
                raise _ModelCredentialUnavailable
            try:
                api_key = self.model_credential_provider()
            except PollDeadlineExceeded:
                raise
            except Exception:
                raise _ModelCredentialUnavailable from None

        attempt_reservations: dict[int, int] = {}
        attempt_calls: dict[int, int] = {}
        api_billed = self.config.runtime.codex_auth_mode is CodexAuthMode.API_KEY

        def account_attempt(
            attempt: int,
            phase: str,
            usage: CodexUsage | None,
        ) -> None:
            accounted_at = _as_utc(self.now())
            if phase == "started":
                call_id = self.state.try_reserve_model_call(
                    run_id=run_id,
                    daily_limit=self.config.limits.max_model_calls_per_day,
                    model=model,
                    reserved_at=accounted_at,
                    purpose="assessment",
                )
                if call_id is None:
                    raise _ModelCallLimitUnavailable(
                        "Daily model call limit was unavailable."
                    )
                attempt_calls[attempt] = call_id
                if not api_billed:
                    return
                reservation_usd = self.config.limits.model_call_reservation_usd
                daily_limit_usd = self.config.limits.daily_cost_limit_usd
                if reservation_usd is None or daily_limit_usd is None:
                    raise RuntimeError("API billing limits are not configured.")
                reservation_id = self.state.try_reserve_budget(
                    run_id=run_id,
                    amount_usd=reservation_usd,
                    daily_limit_usd=daily_limit_usd,
                    model=model,
                    reserved_at=accounted_at,
                )
                if reservation_id is None:
                    self.state.finalize_model_call(
                        call_id,
                        status="cancelled",
                        finalized_at=accounted_at,
                    )
                    attempt_calls.pop(attempt, None)
                    raise _BudgetUnavailable("Daily model budget was unavailable.")
                attempt_reservations[attempt] = reservation_id
                return
            if phase == "succeeded":
                if attempt in attempt_calls or attempt in attempt_reservations:
                    raise RuntimeError(
                        "Codex success was not durably cached before completion."
                    )
                return

            call_id = attempt_calls.pop(attempt, None)
            if call_id is None:
                raise RuntimeError(
                    "Codex attempt finished without a model call reservation."
                )
            self.state.finalize_model_call(
                call_id,
                status="cancelled" if phase == "not_started" else "unknown",
                finalized_at=accounted_at,
            )
            if not api_billed:
                return
            reservation_id = attempt_reservations.pop(attempt, None)
            if reservation_id is None:
                raise RuntimeError(
                    "Codex attempt finished without a budget reservation."
                )
            if phase == "not_started":
                self.state.settle_budget_reservation(
                    reservation_id,
                    actual_cost_usd=0,
                    settled_at=accounted_at,
                )
            elif usage is not None and usage.cost_usd is not None:
                self.state.settle_budget_reservation(
                    reservation_id,
                    actual_cost_usd=usage.cost_usd,
                    input_tokens=usage.input_tokens or 0,
                    output_tokens=usage.output_tokens or 0,
                    settled_at=accounted_at,
                )
            else:
                self.state.mark_budget_reservation_unknown(
                    reservation_id,
                    marked_at=accounted_at,
                )

        def persist_success(
            attempt: int,
            usage: CodexUsage | None,
            result: CodexResult,
        ) -> None:
            call_id = attempt_calls.pop(attempt, None)
            if call_id is None:
                raise RuntimeError(
                    "Codex success has no matching model call reservation."
                )
            serialized_result = serialize_codex_result(result)
            created_at = _as_utc(self.now())
            if not api_billed:
                self.state.cache_assessment_result(
                    cache_key=cache_key,
                    repository=policy.base_repo,
                    pr_number=snapshot.pull_request.number,
                    head_sha=snapshot.pull_request.head_sha,
                    base_sha=snapshot.pull_request.base_sha,
                    model=model,
                    reasoning_effort=reasoning_effort,
                    result_json=serialized_result,
                    created_at=created_at,
                )
                self.state.finalize_model_call(
                    call_id,
                    status="completed",
                    finalized_at=created_at,
                )
                return
            reservation_id = attempt_reservations.pop(attempt, None)
            if reservation_id is None:
                raise RuntimeError("Codex success has no matching budget reservation.")
            self.state.cache_assessment_and_settle_budget(
                cache_key=cache_key,
                repository=policy.base_repo,
                pr_number=snapshot.pull_request.number,
                head_sha=snapshot.pull_request.head_sha,
                base_sha=snapshot.pull_request.base_sha,
                model=model,
                reasoning_effort=reasoning_effort,
                result_json=serialized_result,
                reservation_id=reservation_id,
                actual_cost_usd=(usage.cost_usd if usage is not None else None),
                input_tokens=(usage.input_tokens or 0 if usage is not None else 0),
                output_tokens=(usage.output_tokens or 0 if usage is not None else 0),
                created_at=created_at,
            )
            self.state.finalize_model_call(
                call_id,
                status="completed",
                finalized_at=created_at,
            )

        return self.codex_driver.run(
            CodexTask(
                prompt=prompt,
                evidence_dir=bundle.root,
            ),
            api_key=api_key,
            attempt_observer=account_attempt,
            success_observer=persist_success,
        )

    def _assess_and_act(
        self,
        *,
        policy: RepositoryPolicy,
        snapshot: PullRequestFeedbackSnapshot,
        scope: _TargetScope,
        base_workspace: GuardianWorkspace | HistoricalWorkspace,
        head_workspace: GuardianWorkspace,
        actionable: Sequence[tuple[FeedbackEvent, EventRevision]],
        open_source: OpenPullAuthorityReference,
        translation_suppressed_feedback_ids: frozenset[str],
        run_id: str,
        observed_at: datetime,
        require_live_lease: Callable[[], None],
        lease_owner: str,
        outcome: _PollAccumulator,
    ) -> None:
        """Assess trusted feedback and apply only policy-validated replacements."""
        events = tuple(event for event, _revision in actionable)
        revisions = tuple(revision for _event, revision in actionable)
        event_locales = {event.locale for event in events}
        changed_paths = tuple(
            sorted(
                path
                for path, locale in scope.path_locales.items()
                if locale in event_locales
            )
        )
        try:
            evidence_parent = self.evidence_root
            if evidence_parent is not None:
                evidence_parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            with tempfile.TemporaryDirectory(
                prefix="localize-guardian-evidence-",
                dir=evidence_parent,
            ) as temporary_directory:
                evidence_kwargs = {}
                if scope.config_bundle_digest is not None:
                    evidence_kwargs["trusted_config_bundle_digest"] = (
                        scope.config_bundle_digest
                    )
                bundle = self.evidence_builder(
                    destination=Path(temporary_directory) / "bundle",
                    repo_root=head_workspace.path,
                    trusted_pipeline_config_path=scope.config_path,
                    repository=policy.base_repo,
                    pr_number=snapshot.pull_request.number,
                    head_sha=snapshot.pull_request.head_sha,
                    base_sha=snapshot.pull_request.base_sha,
                    feedback=events,
                    changed_paths=changed_paths,
                    allowed_path_globs=policy.allowed_path_globs,
                    diff_text=_diff_text(changed_paths, scope.changed_files),
                    trusted_config_root=scope.config_root,
                    trusted_source_root=scope.source_root,
                    expected_source_locale=policy.source_locale,
                    **evidence_kwargs,
                )
                try:
                    result = self._assessment_result(
                        bundle=bundle,
                        policy=policy,
                        snapshot=snapshot,
                        run_id=run_id,
                    )
                except _ModelCredentialUnavailable:
                    self._fail_actions(
                        run_id=run_id,
                        revisions=revisions,
                        outcome_name="model_credential_unavailable",
                        observed_at=observed_at,
                    )
                    self.state.finish_run(
                        run_id,
                        status="failed",
                        summary="Model credential helper failed; circuit opened.",
                        finished_at=observed_at,
                    )
                    outcome.runs_failed += 1
                    self.state.record_health(
                        component="codex",
                        status="failed",
                        message=(
                            "Model credential helper failed; further model calls stopped."
                        ),
                        details={"circuit_open": True},
                        checked_at=observed_at,
                    )
                    raise _AuthenticationCircuit from None
                except _BudgetUnavailable:
                    self._fail_actions(
                        run_id=run_id,
                        revisions=revisions,
                        outcome_name="daily_budget_unavailable",
                        observed_at=observed_at,
                    )
                    self.state.finish_run(
                        run_id,
                        status="failed",
                        summary="Daily model budget was unavailable.",
                        finished_at=observed_at,
                    )
                    outcome.runs_failed += 1
                    return
                except _ModelCallLimitUnavailable:
                    self._fail_actions(
                        run_id=run_id,
                        revisions=revisions,
                        outcome_name="daily_model_call_limit_unavailable",
                        observed_at=observed_at,
                    )
                    self.state.finish_run(
                        run_id,
                        status="failed",
                        summary="Daily model call limit was unavailable.",
                        finished_at=observed_at,
                    )
                    outcome.runs_failed += 1
                    return
                except CodexAuthenticationError:
                    self._fail_actions(
                        run_id=run_id,
                        revisions=revisions,
                        outcome_name="codex_authentication_failed",
                        observed_at=observed_at,
                    )
                    self.state.finish_run(
                        run_id,
                        status="failed",
                        summary="Codex authentication failed; circuit opened.",
                        finished_at=observed_at,
                    )
                    outcome.runs_failed += 1
                    self.state.record_health(
                        component="codex",
                        status="failed",
                        message="Codex authentication failed; further model calls stopped.",
                        details={"circuit_open": True},
                        checked_at=observed_at,
                    )
                    raise _AuthenticationCircuit from None
                except CodexCapacityError:
                    self._fail_actions(
                        run_id=run_id,
                        revisions=revisions,
                        outcome_name="codex_capacity_unavailable",
                        observed_at=observed_at,
                    )
                    self.state.finish_run(
                        run_id,
                        status="failed",
                        summary="Codex capacity was unavailable; circuit opened.",
                        finished_at=observed_at,
                    )
                    outcome.runs_failed += 1
                    self.state.record_health(
                        component="codex",
                        status="failed",
                        message="Codex capacity unavailable; further model calls stopped.",
                        details={"circuit_open": True, "reason": "capacity"},
                        checked_at=observed_at,
                    )
                    raise _ModelCircuit from None

                self._require_live_lease(lease_owner)
                assessments = self.assessment_converter(
                    result,
                    feedback_events=events,
                    source_values=_source_values(bundle),
                    target_locales_by_feedback=_replacement_target_locales(
                        policy, events, scope.path_locales
                    ),
                )

            recurrence_candidates = tuple(
                candidate
                for assessment in assessments
                for candidate in assessment.recurrence_candidates
            )
            if (
                self.config.mode is GuardianMode.PROPOSE_PREVENTION
                and recurrence_candidates
            ):
                assert self.prevention_runner is not None
                try:
                    prevention_outcome = self.prevention_runner.propose(
                        policy=policy,
                        recurrence_candidates=recurrence_candidates,
                        evidence_revision_ids={
                            event.feedback_id: revision.revision_id
                            for event, revision in actionable
                        },
                        run_id=run_id,
                        observed_at=observed_at,
                        require_live_lease=require_live_lease,
                        require_cleanup_lease=lambda: self._refresh_live_lease(
                            lease_owner
                        ),
                        require_current_base_unchanged=require_live_lease,
                        open_source=open_source,
                        source_event_revision_ids=tuple(
                            revision.revision_id for _event, revision in actionable
                        ),
                        require_exact_open_source_authority=lambda source,
                        revision_ids: (
                            self._require_exact_open_source_authority(
                                policy=policy,
                                source=source,
                                event_revision_ids=revision_ids,
                                require_live_lease=require_live_lease,
                            )
                        ),
                    )
                except CodexAuthenticationError:
                    self._fail_actions(
                        run_id=run_id,
                        revisions=revisions,
                        outcome_name="prevention_codex_authentication_failed",
                        observed_at=observed_at,
                    )
                    self.state.finish_run(
                        run_id,
                        status="failed",
                        summary=(
                            "Prevention Codex authentication failed; circuit opened."
                        ),
                        finished_at=observed_at,
                    )
                    outcome.runs_failed += 1
                    self.state.record_health(
                        component="codex",
                        status="failed",
                        message=(
                            "Prevention Codex authentication failed; further model "
                            "calls stopped."
                        ),
                        details={"circuit_open": True},
                        checked_at=observed_at,
                    )
                    raise _AuthenticationCircuit from None
                except CodexCapacityError:
                    self._fail_actions(
                        run_id=run_id,
                        revisions=revisions,
                        outcome_name="prevention_codex_capacity_unavailable",
                        observed_at=observed_at,
                    )
                    self.state.finish_run(
                        run_id,
                        status="failed",
                        summary=(
                            "Prevention Codex capacity was unavailable; circuit opened."
                        ),
                        finished_at=observed_at,
                    )
                    outcome.runs_failed += 1
                    self.state.record_health(
                        component="codex",
                        status="failed",
                        message=(
                            "Prevention Codex capacity unavailable; further model "
                            "calls stopped."
                        ),
                        details={"circuit_open": True, "reason": "capacity"},
                        checked_at=observed_at,
                    )
                    raise _ModelCircuit from None
                self._record_prevention_outcome(
                    prevention_outcome,
                    outcome=outcome,
                )
                if prevention_outcome.failures or prevention_outcome.deferred:
                    # Leave the feedback revisions retryable. Successful drafts
                    # are durably deduplicated, so a later run can continue the
                    # remaining bounded candidates without duplicating them.
                    raise PreventionRuntimeError(
                        "Prevention candidates remain incomplete."
                    )

            replacements = _eligible_replacements(
                assessments,
                minimum_confidence=self.config.limits.min_apply_confidence,
                excluded_feedback_ids=translation_suppressed_feedback_ids,
            )
            patch_result = PatchResult(changed_files=(), changed_keys=())
            if self.config.mode is not GuardianMode.OBSERVE and replacements:
                patch_result = self.replacement_applier(
                    repo_root=head_workspace.path,
                    pipeline_config_path=scope.config_path,
                    allowed_paths=policy.allowed_path_globs,
                    replacements=replacements,
                    max_changes=self.config.limits.max_value_edits_per_run,
                    trusted_config_root=scope.config_root,
                    trusted_source_root=scope.source_root,
                    expected_source_locale=policy.source_locale,
                )
                outcome.prepared_value_edits += len(patch_result.changed_keys)

            commit_sha: str | None = None
            if (
                self.config.mode
                in {
                    GuardianMode.APPLY_OWNED_TRANSLATIONS,
                    GuardianMode.PROPOSE_PREVENTION,
                }
                and patch_result.changed_files
            ):
                commit_sha = self._publish_translation_commit(
                    policy=policy,
                    snapshot=snapshot,
                    workspace=head_workspace,
                    patch_result=patch_result,
                    replacements=replacements,
                    assessments=assessments,
                    actionable=actionable,
                    open_source=open_source,
                    translation_suppressed_feedback_ids=(
                        translation_suppressed_feedback_ids
                    ),
                    run_id=run_id,
                    lease_owner=lease_owner,
                    observed_at=observed_at,
                )
                outcome.applied_commits.append(commit_sha)

            if commit_sha is None:
                self._complete_actions(
                    run_id=run_id,
                    actionable=actionable,
                    assessments=assessments,
                    changed_keys=patch_result.changed_keys,
                    commit_sha=commit_sha,
                    translation_suppressed_feedback_ids=(
                        translation_suppressed_feedback_ids
                    ),
                    observed_at=observed_at,
                )
                self.state.finish_run(
                    run_id,
                    status="completed",
                    summary=(
                        "Guardian assessment completed within configured authority."
                    ),
                    finished_at=observed_at,
                )
            outcome.runs_completed += 1
        except (_AuthenticationCircuit, _ModelCircuit):
            raise
        except PatchPolicyError as exc:
            for revision in revisions:
                self.state.record_action(
                    run_id=run_id,
                    event_revision_id=revision.revision_id,
                    action=self.config.mode.value,
                    status="skipped",
                    details={
                        "outcome": "deterministic_policy_rejection",
                        "reason": str(exc)[:512],
                        "policy_digest": _patch_policy_digest(
                            self.config, policy, scope
                        ),
                    },
                    occurred_at=observed_at,
                )
            self.state.finish_run(
                run_id,
                status="completed",
                summary="Model proposal was rejected by deterministic policy.",
                finished_at=observed_at,
            )
            outcome.runs_completed += 1
        except (_LeaseLost, PreventionLeaseLostError):
            raise
        except Exception as exc:
            if self.state.has_pending_publication_for_run(run_id):
                # A prepared or published cursor owns truthful recovery. Do not
                # append failure rows ahead of recovery's atomic local finalizer.
                outcome.runs_failed += 1
                raise exc
            self._fail_actions(
                run_id=run_id,
                revisions=revisions,
                outcome_name="orchestration_failure",
                observed_at=observed_at,
            )
            self.state.finish_run(
                run_id,
                status="failed",
                summary="Guardian action failed closed.",
                finished_at=observed_at,
            )
            outcome.runs_failed += 1
            raise exc

    @staticmethod
    def _record_prevention_outcome(
        result: PreventionBatchOutcome,
        *,
        outcome: _PollAccumulator,
    ) -> None:
        outcome.prevention_drafts_created += sum(
            1 for draft in result.drafts if draft.created
        )
        outcome.prevention_items_skipped += result.skipped
        outcome.prevention_items_deferred += result.deferred
        outcome.prevention_failures.extend(result.failures)

    def _require_live_lease(self, owner: str) -> None:
        if self.deadline is not None:
            self.deadline.require_remaining()
        self._refresh_live_lease(owner)

    def _refresh_live_lease(self, owner: str) -> None:
        if not self.state.refresh_lease(
            name="guardian:poll",
            owner=owner,
            ttl_seconds=_lease_ttl_seconds(self.config),
            now=_as_utc(self.now()),
        ):
            raise _LeaseLost("Guardian poll lease was lost.")

    def _publish_translation_commit(
        self,
        *,
        policy: RepositoryPolicy,
        snapshot: PullRequestFeedbackSnapshot,
        workspace: GuardianWorkspace,
        patch_result: PatchResult,
        replacements: Sequence[ProposedReplacement],
        assessments: Sequence[GuardianAssessment],
        actionable: Sequence[tuple[FeedbackEvent, EventRevision]],
        open_source: OpenPullAuthorityReference,
        translation_suppressed_feedback_ids: frozenset[str],
        run_id: str,
        lease_owner: str,
        observed_at: datetime | None = None,
    ) -> str:
        """Publish signed edits and separately account for the authorized status reply."""
        if (
            self.write_broker_factory is None
        ):  # Constructor enforces this mode boundary.
            raise RuntimeError("Write broker is unavailable.")
        publication_actor = policy.publication_actor
        if publication_actor is None:  # pragma: no cover - config invariant
            raise RuntimeError("Publication actor is unavailable.")
        publication_time = observed_at or _as_utc(self.now())
        changed_targets = frozenset(patch_result.changed_keys)
        selected_feedback_ids = {
            assessment.feedback_id
            for assessment in assessments
            if assessment.verdict == "apply"
            and assessment.feedback_id not in translation_suppressed_feedback_ids
            and assessment.confidence >= self.config.limits.min_apply_confidence
            and any(
                (replacement.path, replacement.key) in changed_targets
                for replacement in assessment.replacements
            )
        }
        selected = tuple(
            (event, revision)
            for event, revision in actionable
            if event.feedback_id in selected_feedback_ids
        )
        published_replacements = tuple(
            replacement
            for replacement in replacements
            if replacement.feedback_id in selected_feedback_ids
            and (replacement.path, replacement.key) in changed_targets
        )
        if (
            not selected
            or not published_replacements
            or {
                (replacement.path, replacement.key)
                for replacement in published_replacements
            }
            != changed_targets
        ):
            raise RuntimeError(
                "Published translation paths lack exact selected feedback evidence."
            )
        feedback_urls = tuple(
            dict.fromkeys(
                event.html_url
                for event, _revision in selected
                if event.html_url is not None
            )
        )
        selected_revision_ids = tuple(
            revision.revision_id for _event, revision in selected
        )
        commit = workspace.commit_validated_changes(
            author_email=(
                f"{publication_actor.id}+{publication_actor.login}@users.noreply.github.com"
            ),
            expected_paths=patch_result.changed_files,
            pull_number=snapshot.pull_request.number,
            feedback_urls=feedback_urls,
            feedback_repository=policy.base_repo,
            sign=True,
            signing_key=self.signing_key,
            signing_environment=self.signing_environment,
        )
        completion_actions = self._completion_action_details(
            actionable=actionable,
            assessments=assessments,
            changed_keys=patch_result.changed_keys,
            commit_sha=commit.commit_sha,
            translation_suppressed_feedback_ids=(translation_suppressed_feedback_ids),
        )
        publication_metadata = {
            "run_id": run_id,
            "repository": policy.base_repo,
            "pr_number": snapshot.pull_request.number,
            "original_head_sha": snapshot.pull_request.head_sha,
            "base_sha": snapshot.pull_request.base_sha,
            "commit_sha": commit.commit_sha,
            "publication_actor_id": publication_actor.id,
            "publication_actor_type": publication_actor.type,
            "event_revision_ids": selected_revision_ids,
            "open_source": open_source,
            "occurred_at": publication_time,
        }
        remediation_draft = self.state.remediation_draft_for_pull(
            repository=policy.base_repo,
            repository_id=policy.base_repo_id,
            pr_number=snapshot.pull_request.number,
        )
        successor_metadata: dict[str, object] | None = None
        if remediation_draft is not None:
            if self.remediation_runner is None:
                raise _PublicationRecoveryManualRequired(
                    "Exact remediation successor publication is unavailable."
                )
            remediation_policy = (
                None
                if policy.closed_pr_backfill is None
                else policy.closed_pr_backfill.remediation
            )
            if remediation_policy is None:
                raise _PublicationRecoveryManualRequired(
                    "Remediation successor publication policy is unavailable."
                )
            marker_event, marker_record = min(
                selected,
                key=lambda item: item[1].revision_id,
            )
            successor_metadata = {
                "draft_key": remediation_draft.draft_key,
                "source_pulls": remediation_draft.source_pulls,
                "edit_hashes": tuple(
                    sorted(
                        {
                            remediation_edit_hash(replacement)
                            for replacement in published_replacements
                        }
                    )
                ),
                "changed_paths": commit.changed_paths,
                "actor_id": marker_event.author_id,
                "actor_type": marker_event.author_type,
            }
            self._require_live_lease(lease_owner)
            prepared = self.state.record_remediation_successor_publication_event(
                **publication_metadata,
                **successor_metadata,
                phase="prepared",
                completion_actions=completion_actions,
            )
            publication_key = prepared.publication_key
        else:
            self._require_live_lease(lease_owner)
            publication_key = self.state.record_publication_event(
                **publication_metadata,
                phase="prepared",
                completion_actions=completion_actions,
            )
        broker = self.write_broker_factory(policy)
        # This is deliberately adjacent to publication. The workspace then
        # performs its own exact expected-old ref CAS before the push.
        self._require_live_lease(lease_owner)
        broker.verify_pull(
            pull_number=snapshot.pull_request.number,
            expected_head_sha=snapshot.pull_request.head_sha,
            expected_base_sha=snapshot.pull_request.base_sha,
            expected_actor=publication_actor,
        )

        def revalidate_before_push() -> None:
            self._require_live_lease(lease_owner)
            broker.verify_pull(
                pull_number=snapshot.pull_request.number,
                expected_head_sha=snapshot.pull_request.head_sha,
                expected_base_sha=snapshot.pull_request.base_sha,
                expected_actor=publication_actor,
            )
            if remediation_draft is not None:
                assert self.remediation_runner is not None
                self.remediation_runner.revalidate_successor_pull(
                    policy=policy,
                    publication_key=publication_key,
                    expected_remote_head_sha=snapshot.pull_request.head_sha,
                    expected_base_sha=snapshot.pull_request.base_sha,
                    require_open=True,
                    require_live_lease=lambda: self._require_live_lease(lease_owner),
                    require_no_open_translation_overlap=lambda paths,
                    excluded: self._require_no_open_translation_overlap(
                        policy=policy,
                        candidate_paths=paths,
                        excluded_pull=excluded,
                        require_live_lease=lambda: self._require_live_lease(
                            lease_owner
                        ),
                    ),
                )
            self._require_exact_open_source_authority(
                policy=policy,
                source=open_source,
                event_revision_ids=selected_revision_ids,
                require_live_lease=lambda: self._require_live_lease(lease_owner),
            )

        publication = workspace.publish_commit(
            commit,
            credential_environment=self.publish_credential_environment,
            require_signature=True,
            signing_key=self.signing_key,
            signing_environment=self.signing_environment,
            before_push=revalidate_before_push,
        )
        self._require_live_lease(lease_owner)
        if successor_metadata is None:
            self.state.record_publication_event(
                **publication_metadata,
                phase="published",
            )
        else:
            self.state.record_remediation_successor_publication_event(
                **publication_metadata,
                **successor_metadata,
                phase="published",
            )
        marker_revision = min(revision.revision_id for _event, revision in selected)

        def revalidate_reply_authority() -> None:
            if remediation_draft is not None:
                assert self.remediation_runner is not None
                self.remediation_runner.revalidate_successor_pull(
                    policy=policy,
                    publication_key=publication_key,
                    expected_remote_head_sha=publication.commit_sha,
                    expected_base_sha=snapshot.pull_request.base_sha,
                    require_open=True,
                    require_live_lease=lambda: self._require_live_lease(lease_owner),
                    require_no_open_translation_overlap=lambda paths,
                    excluded: self._require_no_open_translation_overlap(
                        policy=policy,
                        candidate_paths=paths,
                        excluded_pull=excluded,
                        require_live_lease=lambda: self._require_live_lease(
                            lease_owner
                        ),
                    ),
                )
            self._require_exact_open_source_authority(
                policy=policy,
                source=open_source,
                event_revision_ids=selected_revision_ids,
                require_live_lease=lambda: self._require_live_lease(lease_owner),
                expected_current_head_sha=publication.commit_sha,
            )

        self._require_live_lease(lease_owner)
        try:
            broker.post_commit_reply(
                pull_number=snapshot.pull_request.number,
                expected_head_sha=publication.commit_sha,
                expected_base_sha=snapshot.pull_request.base_sha,
                commit_sha=publication.commit_sha,
                action_id=publication_key,
                event_revision_id=str(marker_revision),
                expected_actor=publication_actor,
                before_create=revalidate_reply_authority,
            )
        except _PublishedFeedbackChanged:
            self._require_live_lease(lease_owner)
            self.state.finalize_publication_reply_terminal(
                publication_key=publication_key,
                reason="trusted_feedback_changed",
                summary="Published correction; changed feedback suppressed reply.",
                occurred_at=publication_time,
            )
            return publication.commit_sha
        self._require_live_lease(lease_owner)
        self.state.finalize_replied_publication(
            publication_key=publication_key,
            summary="Guardian assessment completed within configured authority.",
            occurred_at=publication_time,
        )
        return publication.commit_sha

    def _fail_actions(
        self,
        *,
        run_id: str,
        revisions: Sequence[EventRevision],
        outcome_name: str,
        observed_at: datetime,
    ) -> None:
        for revision in revisions:
            self.state.record_action(
                run_id=run_id,
                event_revision_id=revision.revision_id,
                action=self.config.mode.value,
                status="failed",
                details={"outcome": outcome_name},
                occurred_at=observed_at,
            )

    def _complete_actions(
        self,
        *,
        run_id: str,
        actionable: Sequence[tuple[FeedbackEvent, EventRevision]],
        assessments: Sequence[GuardianAssessment],
        changed_keys: Sequence[tuple[str, str]],
        commit_sha: str | None,
        translation_suppressed_feedback_ids: frozenset[str],
        observed_at: datetime,
    ) -> None:
        for revision_id, status, details in self._completion_action_details(
            actionable=actionable,
            assessments=assessments,
            changed_keys=changed_keys,
            commit_sha=commit_sha,
            translation_suppressed_feedback_ids=(translation_suppressed_feedback_ids),
        ):
            self.state.record_action(
                run_id=run_id,
                event_revision_id=revision_id,
                action=self.config.mode.value,
                status=status,
                details=details,
                occurred_at=observed_at,
            )

    def _completion_action_details(
        self,
        *,
        actionable: Sequence[tuple[FeedbackEvent, EventRevision]],
        assessments: Sequence[GuardianAssessment],
        changed_keys: Sequence[tuple[str, str]],
        commit_sha: str | None,
        translation_suppressed_feedback_ids: frozenset[str],
    ) -> tuple[tuple[int, str, Mapping[str, object]], ...]:
        """Build exact action rows for normal and atomic publication completion."""

        assessments_by_id = {
            assessment.feedback_id: assessment for assessment in assessments
        }
        changed_key_set = set(changed_keys)
        completion_actions: list[tuple[int, str, Mapping[str, object]]] = []
        for event, revision in actionable:
            assessment = assessments_by_id[event.feedback_id]
            eligible = (
                event.feedback_id not in translation_suppressed_feedback_ids
                and assessment.verdict == "apply"
                and assessment.confidence >= self.config.limits.min_apply_confidence
                and bool(assessment.replacements)
            )
            assessment_keys = {
                (replacement.path, replacement.key)
                for replacement in assessment.replacements
            }
            applied_keys = changed_key_set & assessment_keys if eligible else set()
            completion_actions.append(
                (
                    revision.revision_id,
                    "completed",
                    {
                        "outcome": (
                            "applied"
                            if commit_sha is not None and applied_keys
                            else "prepared"
                            if applied_keys
                            else "would_apply"
                            if self.config.mode is GuardianMode.OBSERVE and eligible
                            else "prevention_assessed_after_translation"
                            if event.feedback_id in translation_suppressed_feedback_ids
                            else "no_eligible_change"
                        ),
                        "verdict": assessment.verdict,
                        "confidence": assessment.confidence,
                        "changed_keys": len(applied_keys),
                        "commit_sha": commit_sha if applied_keys else None,
                        "recurrence_candidates": len(assessment.recurrence_candidates),
                    },
                )
            )
        return tuple(completion_actions)


def run_once(*, config_path: Path, scheduled: bool = False) -> int:
    """Lazily enter the production runtime without creating an import cycle."""

    from localize.guardian.runtime import run_once as runtime_run_once

    return runtime_run_once(config_path=config_path, scheduled=scheduled)


__all__ = (
    "CheckoutFactory",
    "CodexRunner",
    "CurrentBaseProvider",
    "GuardianController",
    "HistoricalCheckoutFactory",
    "HistoricalSnapshotProvider",
    "PollOutcome",
    "PreventionRunner",
    "RemediationRunner",
    "SnapshotProvider",
    "WriteBrokerFactory",
    "run_once",
)
