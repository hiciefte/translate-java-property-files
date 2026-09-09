"""Orchestration tests for one bounded Localize Guardian poll."""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from decimal import Decimal
import hashlib
import json
from pathlib import Path
import shutil
import sqlite3
from typing import Iterator

import pytest
import yaml

from localize.guardian import controller as guardian_controller
from localize.guardian.authorization import (
    authorize_feedback,
    authorize_historical_feedback,
)
from localize.guardian.codex import (
    CodexAuthenticationError,
    CodexCapacityError,
    CodexResult,
    CodexUsage,
    GuardianFeedbackDecision,
    GuardianRecurrenceCandidate,
    GuardianReplacement,
)
from localize.guardian.controller import GuardianController
from localize.guardian.deadline import PollDeadline, PollDeadlineExceeded
from localize.guardian.github import (
    BaseRevisionSnapshot,
    ChangedFile,
    ClosedPullScanItem,
    ClosedPullScanPosition,
    ClosedPullScanResult,
    CodeRabbitCoverage,
    CodeRabbitCoverageStatus,
    FeedbackKind,
    FeedbackRevision,
    GitHubAuthenticationError,
    GitHubRepositoryIdentity,
    OpenPullPathAuthority,
    OpenPullPathIdentity,
    PolicyViolation,
    PullRequestFeedbackSnapshot,
    PullRequestSnapshot,
)
from localize.guardian.models import (
    AllowedHeadRepository,
    ClosedPrBackfillPolicy,
    CodexAuthMode,
    ExactRepository,
    FeedbackEvent,
    GuardianAssessment,
    GuardianConfig,
    GuardianLimits,
    GuardianMode,
    GuardianRuntime,
    HistoricalCheckScope,
    HistoricalRemediationPolicy,
    PipelineConfigSnapshot,
    PipelineConfigSource,
    PreventionPolicy,
    ProposedReplacement,
    RepositoryPolicy,
    TrustedActor,
)
from localize.guardian.policy import PatchResult
from localize.guardian.evidence import build_evidence_bundle
from localize.guardian.policy import apply_replacements
from localize.guardian.state import (
    GuardianState,
    HistoricalPullReference,
    OpenPullAuthorityReference,
    RemediationCoverageReason,
    RemediationEditCoverage,
    remediation_batch_hash,
    remediation_edit_hash,
    remediation_target_hash,
)
from localize.guardian.prevention_runtime import (
    PreventionBatchOutcome,
    PreventionDraftResult,
    PreventionLeaseLostError,
)
from localize.guardian.remediation import (
    RemediationBatchOutcome,
    RemediationDraftResult,
    RemediationOpenPullAuthorityError,
    RemediationRemoteConflictError,
    RemediationSourceAuthorityError,
)
from localize.guardian.workspace import (
    CommitResult,
    HistoricalRevision,
    HistoricalWorkspace,
    PublicationResult,
)


UTC = timezone.utc
NOW = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
BASE_SHA = "b" * 40
HEAD_SHA = "a" * 40
COMMIT_SHA = "c" * 40


def _insert_legacy_publication(
    database: Path,
    *,
    run_id: str,
    repository: str,
    pr_number: int,
    original_head_sha: str,
    base_sha: str,
    commit_sha: str,
    event_revision_ids: tuple[int, ...],
    occurred_at: datetime,
    phase: str = "prepared",
) -> str:
    """Seed a pre-v8 publication, then exercise the v7-to-current migration."""

    assert phase in {"prepared", "replied"}
    payload = (
        f"{repository}\n{pr_number}\n{original_head_sha}\n{base_sha}\n{commit_sha}"
    )
    publication_key = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    with sqlite3.connect(database) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 10
        # Restore the pre-v8 table shape while the production connection is
        # closed. The next GuardianState open performs the real v7 -> v8
        # migration and reinstalls every dropped production trigger.
        for trigger in (
            "publication_events_first_prepared",
            "publication_events_identity",
            "publication_events_monotonic",
            "publication_events_transition",
            "publication_events_published_plan",
            "publication_events_replied_complete",
            "publication_events_abandoned_complete",
            "publication_events_actor_safe",
            "publication_events_repository_id_safe",
            "publication_completion_plans_prepared",
            "remediation_successor_intents_prepared",
        ):
            connection.execute(f"DROP TRIGGER {trigger}")  # noqa: S608
        connection.execute("DROP INDEX publication_events_pending_by_repository_id")
        connection.execute("DROP INDEX publication_events_replied_by_repository_id")
        connection.execute(
            "ALTER TABLE publication_completion_plan_items "
            "DROP COLUMN publication_actor_type"
        )
        connection.execute(
            "ALTER TABLE publication_completion_plan_items "
            "DROP COLUMN publication_actor_id"
        )
        connection.execute(
            "ALTER TABLE publication_events DROP COLUMN publication_actor_type"
        )
        connection.execute(
            "ALTER TABLE publication_events DROP COLUMN publication_actor_id"
        )
        connection.execute("ALTER TABLE publication_events DROP COLUMN repository_id")
        connection.execute("PRAGMA user_version = 7")
        connection.execute(
            """
            INSERT INTO publication_events (
                publication_key, run_id, repository, pr_number,
                original_head_sha, base_sha, commit_sha,
                event_revision_ids_json, phase, occurred_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                publication_key,
                run_id,
                repository,
                pr_number,
                original_head_sha,
                base_sha,
                commit_sha,
                json.dumps(event_revision_ids, separators=(",", ":")),
                phase,
                occurred_at.astimezone(UTC)
                .isoformat(timespec="microseconds")
                .replace("+00:00", "Z"),
            ),
        )
    return publication_key


TARGET_PATH = "l10n/messages_ru.properties"
SECOND_TARGET_PATH = "l10n/errors_ru.properties"


def _write_tree(root: Path, *, head_config_source_locale: str = "en") -> None:
    (root / ".localize").mkdir(parents=True)
    (root / "l10n").mkdir()
    config = {
        "target_project_root": ".",
        "input_folder": "l10n",
        "source_locale": head_config_source_locale,
        "supported_locales": [{"code": "ru", "name": "Russian"}],
        "localization_format": "java_properties",
        "localization_layout": {
            "id": "suffix",
            "base_name": "messages",
            "source_locale": head_config_source_locale,
        },
        "placeholder_profile": "java-indexed",
        "glossary_file_path": "glossary.json",
    }
    (root / ".localize/config.yaml").write_text(
        yaml.safe_dump(config),
        encoding="utf-8",
    )
    (root / ".localize/glossary.json").write_text(
        json.dumps({"ru": {}}),
        encoding="utf-8",
    )
    (root / "l10n/messages_en.properties").write_text(
        "greeting=Push to %0 was rejected (%1). %2 %3\n",
        encoding="utf-8",
    )
    (root / TARGET_PATH).write_text(
        "greeting=Старый %0 был отклонён (%1). %2 %3\n",
        encoding="utf-8",
    )


def _add_second_localization_target(root: Path) -> None:
    config_path = root / ".localize/config.yaml"
    config = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    config["localization_formats"] = [
        {
            "id": "java_properties",
            "layout": {"id": "suffix", "base_name": "messages"},
        },
        {
            "id": "java_properties",
            "layout": {"id": "suffix", "base_name": "errors"},
        },
    ]
    config_path.write_text(yaml.safe_dump(config), encoding="utf-8")
    (root / "l10n/errors_en.properties").write_text(
        "failure=Connection failed\n",
        encoding="utf-8",
    )
    (root / SECOND_TARGET_PATH).write_text(
        "failure=Старое сообщение об ошибке\n",
        encoding="utf-8",
    )


def _policy(*, repository: str = "acme/widgets") -> RepositoryPolicy:
    return RepositoryPolicy(
        base_repo=repository,
        base_repo_id=42,
        base_branch="main",
        allowed_pr_authors=(TrustedActor("translation-service", 8, "Bot"),),
        allowed_head_owners=(TrustedActor("contributor", 7, "User"),),
        allowed_head_repositories=(AllowedHeadRepository("contributor/widgets", 84),),
        allowed_branch_globs=("localize/*",),
        allowed_path_globs=("l10n/*.properties",),
        pipeline_config_path=".localize/config.yaml",
        source_locale="en",
        publication_actor=TrustedActor("translation-service", 8, "User"),
        trusted_reviewers={
            "ru": (TrustedActor("native-reviewer", 101, "User"),),
        },
        trusted_bots={},
    )


def _prevention_policy() -> PreventionPolicy:
    return PreventionPolicy(
        target_repository=ExactRepository("guardian/pipeline", 501),
        target_base_branch="main",
        push_repository=ExactRepository("guardian/pipeline", 501),
        push_branch_prefix="guardian/prevention-",
        publication_actor=TrustedActor("translation-service", 8, "User"),
        allowed_code_path_globs=("localize/*.py",),
        allowed_test_path_globs=("tests/**/*.py",),
        focused_test_argv=(
            ("/opt/localize/venv/bin/pytest", "tests/unit/test_rule.py", "-q"),
        ),
        sandbox_argv_prefix=("/usr/bin/guardian-sandbox-wrapper",),
        max_changed_files=4,
        max_changed_bytes=16_384,
    )


def _historical_policy(*, remediation: bool = False) -> RepositoryPolicy:
    remediation_policy = (
        HistoricalRemediationPolicy(
            push_repository=ExactRepository("contributor/widgets", 84),
            push_branch_prefix="localize/remediation-",
            publication_actor=TrustedActor("translation-service", 8, "User"),
        )
        if remediation
        else None
    )
    return replace(
        _policy(),
        allowed_branch_globs=(
            ("localize/*", "localize/remediation-*") if remediation else ("localize/*",)
        ),
        closed_pr_backfill=ClosedPrBackfillPolicy(
            lookback_days=90,
            max_prs_per_poll=10,
            remediation=remediation_policy,
        ),
    )


def _open_pull_path_identity(**overrides: object) -> OpenPullPathIdentity:
    values: dict[str, object] = {
        "repository": "acme/widgets",
        "repository_id": 42,
        "pull_id": 9001,
        "number": 91,
        "head_repository": "contributor/widgets",
        "head_repository_id": 84,
        "head_ref": "localize/remediation-candidate",
        "head_sha": "9" * 40,
    }
    values.update(overrides)
    return OpenPullPathIdentity(**values)  # type: ignore[arg-type]


def test_open_translation_overlap_authority_allows_only_nonoverlap() -> None:
    policy = _historical_policy(remediation=True)
    authority = OpenPullPathAuthority(
        _open_pull_path_identity(),
        (SECOND_TARGET_PATH,),
    )

    guardian_controller._assert_no_open_translation_overlap(
        policy=policy,
        candidate_paths=(TARGET_PATH,),
        authorities=(authority,),
        excluded_pull=None,
    )

    with pytest.raises(RemediationOpenPullAuthorityError, match="overlaps"):
        guardian_controller._assert_no_open_translation_overlap(
            policy=policy,
            candidate_paths=(SECOND_TARGET_PATH,),
            authorities=(authority,),
            excluded_pull=None,
        )


def test_open_translation_overlap_rejects_rename_source_path() -> None:
    policy = _historical_policy(remediation=True)
    renamed_from = TARGET_PATH
    renamed_to = SECOND_TARGET_PATH
    authority = OpenPullPathAuthority(
        _open_pull_path_identity(),
        (renamed_from, renamed_to),
    )

    with pytest.raises(RemediationOpenPullAuthorityError, match="overlaps"):
        guardian_controller._assert_no_open_translation_overlap(
            policy=policy,
            candidate_paths=(renamed_from,),
            authorities=(authority,),
            excluded_pull=None,
        )


@pytest.mark.parametrize(
    "changed_identity",
    (
        {"head_sha": "8" * 40},
        {"head_repository_id": 85},
        {"pull_id": 9002},
    ),
    ids=("head-sha", "head-repository-id", "pull-id"),
)
def test_open_translation_overlap_excludes_only_the_exact_attested_pull(
    changed_identity: dict[str, object],
) -> None:
    policy = _historical_policy(remediation=True)
    exact = _open_pull_path_identity()
    changed = replace(exact, **changed_identity)
    overlapping = OpenPullPathAuthority(changed, (TARGET_PATH,))

    with pytest.raises(
        RemediationOpenPullAuthorityError,
        match="overlaps|absent",
    ):
        guardian_controller._assert_no_open_translation_overlap(
            policy=policy,
            candidate_paths=(TARGET_PATH,),
            authorities=(overlapping,),
            excluded_pull=exact,
        )

    guardian_controller._assert_no_open_translation_overlap(
        policy=policy,
        candidate_paths=(TARGET_PATH,),
        authorities=(OpenPullPathAuthority(exact, (TARGET_PATH,)),),
        excluded_pull=exact,
    )


def test_deleted_fork_open_pull_still_blocks_overlapping_remediation() -> None:
    unknown_head = _open_pull_path_identity(
        head_repository="",
        head_repository_id=None,
    )

    with pytest.raises(RemediationOpenPullAuthorityError, match="overlaps"):
        guardian_controller._assert_no_open_translation_overlap(
            policy=_historical_policy(remediation=True),
            candidate_paths=(TARGET_PATH,),
            authorities=(OpenPullPathAuthority(unknown_head, (TARGET_PATH,)),),
            excluded_pull=None,
        )


def test_open_translation_overlap_authority_enforces_runtime_bounds() -> None:
    policy = _historical_policy(remediation=True)
    too_many_pulls = tuple(
        OpenPullPathAuthority(
            _open_pull_path_identity(pull_id=10_000 + index, number=1000 + index),
            (),
        )
        for index in range(201)
    )

    with pytest.raises(RemediationOpenPullAuthorityError, match="unbounded"):
        guardian_controller._assert_no_open_translation_overlap(
            policy=policy,
            candidate_paths=(TARGET_PATH,),
            authorities=too_many_pulls,
            excluded_pull=None,
        )
    with pytest.raises(RemediationOpenPullAuthorityError, match="safety bound"):
        guardian_controller._assert_no_open_translation_overlap(
            policy=policy,
            candidate_paths=tuple(
                f"l10n/messages_{index}.properties" for index in range(101)
            ),
            authorities=(),
            excluded_pull=None,
        )


def test_open_translation_overlap_accepts_bounded_rename_heavy_authority() -> None:
    policy = _historical_policy(remediation=True)
    affected_paths = tuple(
        f"l10n/open_pull_path_{index}.properties" for index in range(1000)
    )
    authorities = tuple(
        OpenPullPathAuthority(
            _open_pull_path_identity(pull_id=10_000 + index, number=1000 + index),
            affected_paths,
        )
        for index in range(101)
    )

    guardian_controller._assert_no_open_translation_overlap(
        policy=policy,
        candidate_paths=(TARGET_PATH,),
        authorities=authorities,
        excluded_pull=None,
    )


def test_controller_open_translation_overlap_refresh_fails_closed() -> None:
    class RaisingProvider:
        @staticmethod
        def collect_open_changed_paths(_policy: RepositoryPolicy):
            def broken_authority():
                yield OpenPullPathAuthority(
                    _open_pull_path_identity(),
                    (SECOND_TARGET_PATH,),
                )
                raise RuntimeError("incomplete pagination")

            return broken_authority()

    controller = object.__new__(GuardianController)
    controller.snapshot_provider = RaisingProvider()
    lease_checks = 0

    def require_live_lease() -> None:
        nonlocal lease_checks
        lease_checks += 1

    with pytest.raises(
        RemediationOpenPullAuthorityError,
        match="revalidation failed closed",
    ):
        controller._require_no_open_translation_overlap(
            policy=_historical_policy(remediation=True),
            candidate_paths=(TARGET_PATH,),
            excluded_pull=None,
            require_live_lease=require_live_lease,
        )

    assert lease_checks == 1


def _config(
    mode: GuardianMode,
    *,
    policies: tuple[RepositoryPolicy, ...] | None = None,
    limits: GuardianLimits | None = None,
) -> GuardianConfig:
    configured_policies = policies
    if configured_policies is None:
        default_policy = _policy()
        if mode is GuardianMode.PROPOSE_PREVENTION:
            default_policy = replace(
                default_policy,
                prevention=_prevention_policy(),
            )
        configured_policies = (default_policy,)
    return GuardianConfig(
        repositories=configured_policies,
        mode=mode,
        limits=limits
        or GuardianLimits(
            daily_cost_limit_usd=2,
            model_call_reservation_usd=1,
            raw_retention_days=90,
            max_remediation_drafts_per_run=1,
        ),
        runtime=GuardianRuntime(
            codex_auth_mode=CodexAuthMode.API_KEY,
            codex_api_key_command=("/opt/bin/model-token",),
        ),
    )


def _consume_test_budget(state: GuardianState) -> None:
    run_id = state.start_run(
        repository="acme/widgets",
        locale="ru",
        mode=GuardianMode.OBSERVE,
        started_at=NOW,
    )
    reservation = state.try_reserve_budget(
        run_id=run_id,
        amount_usd=1,
        daily_limit_usd=1,
        model="budget-fixture",
        reserved_at=NOW,
    )
    assert reservation is not None
    state.settle_budget_reservation(
        reservation,
        actual_cost_usd=1,
        settled_at=NOW,
    )
    state.finish_run(run_id, status="completed", finished_at=NOW)


def _pull(**overrides: object) -> PullRequestSnapshot:
    values: dict[str, object] = {
        "repository": "acme/widgets",
        "base_repository_id": 42,
        "pull_id": 500,
        "number": 12,
        "state": "open",
        "html_url": "https://github.com/acme/widgets/pull/12",
        "created_at": "2026-08-30T08:00:00Z",
        "updated_at": "2026-08-30T10:00:00Z",
        "author_login": "translation-service",
        "author_id": 8,
        "author_type": "Bot",
        "head_sha": HEAD_SHA,
        "head_ref": "localize/russian",
        "head_owner": "contributor",
        "head_owner_id": 7,
        "head_owner_type": "User",
        "head_repository": "contributor/widgets",
        "head_repository_id": 84,
        "base_sha": BASE_SHA,
        "base_ref": "main",
    }
    values.update(overrides)
    return PullRequestSnapshot(**values)  # type: ignore[arg-type]


def _retry_source(**overrides: object) -> HistoricalPullReference:
    values: dict[str, object] = {
        "repository": "acme/widgets",
        "repository_id": 42,
        "pull_id": 500,
        "pr_number": 12,
        "pull_revision_digest": "1" * 64,
        "authority_digest": "5" * 64,
        "policy_digest": "2" * 64,
        "head_sha": HEAD_SHA,
        "base_sha": BASE_SHA,
    }
    values.update(overrides)
    return HistoricalPullReference(**values)  # type: ignore[arg-type]


def _record_open_remediation_draft(
    state: GuardianState,
    *,
    candidate_sha: str = HEAD_SHA,
    draft_number: int = 91,
) -> tuple[str, HistoricalPullReference]:
    """Seed one fully attested remediation PR for successor tests."""

    source_event = FeedbackEvent(
        repository="acme/widgets",
        pr_number=12,
        kind="review_comment",
        event_id="source-44",
        author="native-reviewer",
        author_id=101,
        author_type="User",
        body="Use the reviewed historical wording.",
        head_sha=HEAD_SHA,
        base_sha=BASE_SHA,
        locale="ru",
        path=TARGET_PATH,
        html_url=("https://github.com/acme/widgets/pull/12#discussion_rsource-44"),
    )
    source_revision = state.record_feedback_event(source_event, observed_at=NOW)
    source = _retry_source(
        pull_revision_digest="3" * 64,
        authority_digest="3" * 64,
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
        event_revision_ids=(source_revision.revision_id,),
        authority_scope=HistoricalCheckScope.ASSESSMENT,
        completed_at=NOW,
    )
    evidence_hash = state.validate_historical_remediation_evidence(
        source_pulls=(source,),
        event_revision_ids=(source_revision.revision_id,),
    )
    source_run_id = state.start_run(
        repository="acme/widgets",
        locale="ru",
        mode=GuardianMode.PROPOSE_PREVENTION,
        started_at=NOW,
    )
    original_edit = ProposedReplacement(
        feedback_id=source_event.feedback_id,
        path=TARGET_PATH,
        key="greeting",
        locale="ru",
        expected_value="before",
        proposed_value="candidate",
        confidence=0.99,
        evidence=(source_event.feedback_id,),
    )
    edit_hash = remediation_edit_hash(original_edit)
    metadata = {
        "run_id": source_run_id,
        "target_repository": "acme/widgets",
        "target_repository_id": 42,
        "target_base_branch": "main",
        "target_base_sha": BASE_SHA,
        "push_repository": "acme/widgets",
        "push_repository_id": 42,
        "branch": f"guardian/remediation-{'4' * 64}",
        "candidate_sha": candidate_sha,
        "evidence_hash": evidence_hash,
        "batch_hash": remediation_batch_hash((edit_hash,)),
        "edit_hashes": (edit_hash,),
        "edit_target_hashes": ((edit_hash, remediation_target_hash(original_edit)),),
        "source_pulls": (source,),
        "event_revision_ids": (source_revision.revision_id,),
        "changed_paths": (TARGET_PATH,),
        "title": "Review historical localization correction",
        "body": "Signed remediation candidate for human review.\n",
        "occurred_at": NOW,
    }
    draft_key = state.record_remediation_draft_event(
        **metadata,
        phase="validated",
    )
    state.record_remediation_draft_event(**metadata, phase="pushed")
    state.record_remediation_draft_event(
        **metadata,
        phase="draft_opened",
        draft_number=draft_number,
        draft_pull_id=900,
        draft_url=f"https://github.com/acme/widgets/pull/{draft_number}",
    )
    return draft_key, source


def _feedback(
    *,
    body: str = "Use the idiomatic wording.",
    updated_at: str = "2026-08-30T10:00:00Z",
    pull_number: int = 12,
    source_id: str = "44",
) -> FeedbackRevision:
    return FeedbackRevision(
        repository="acme/widgets",
        pull_number=pull_number,
        kind=FeedbackKind.REVIEW_COMMENT,
        source_id=source_id,
        node_id=f"node-{source_id}",
        author_login="native-reviewer",
        author_id=101,
        author_type="User",
        body=body,
        created_at="2026-08-30T09:00:00Z",
        updated_at=updated_at,
        html_url=(
            "https://github.com/acme/widgets/pull/"
            f"{pull_number}#discussion_r{source_id}"
        ),
        path=TARGET_PATH,
        line=1,
    )


def _snapshot(
    *,
    feedback: tuple[FeedbackRevision, ...] | None = None,
    pull: PullRequestSnapshot | None = None,
    changed_files: tuple[ChangedFile, ...] | None = None,
) -> PullRequestFeedbackSnapshot:
    return PullRequestFeedbackSnapshot(
        repository_identity=GitHubRepositoryIdentity(
            full_name="acme/widgets",
            repository_id=42,
            private=False,
        ),
        pull_request=pull or _pull(),
        feedback=feedback if feedback is not None else (_feedback(),),
        coderabbit=CodeRabbitCoverage(CodeRabbitCoverageStatus.REVIEWED),
        changed_files=changed_files
        if changed_files is not None
        else (
            ChangedFile(
                path=TARGET_PATH,
                status="modified",
                sha="d" * 40,
                patch="@@ -1 +1 @@\n-old\n+new",
            ),
        ),
    )


def test_open_pull_base_is_read_only_while_head_requires_current_ref() -> None:
    """A moving base branch must not invalidate the reviewed base snapshot."""
    snapshot = _snapshot()
    base, head = guardian_controller._exact_revisions(
        _policy(), snapshot, github_host="github.com"
    )
    assert isinstance(base, HistoricalRevision)
    assert base.sha == snapshot.pull_request.base_sha
    assert isinstance(head, guardian_controller.ExactRevision)
    assert head.sha == snapshot.pull_request.head_sha
    assert head.ref == f"refs/heads/{snapshot.pull_request.head_ref}"


def test_replacement_locales_require_actor_authority_for_each_target() -> None:
    """Cross-locale comments must not expand a reviewer's locale allowlist."""
    event = FeedbackEvent(
        repository="acme/widgets", pr_number=12, kind="review_comment", event_id="44",
        author="native-reviewer", author_id=101, author_type="User", body="Fix both.",
        head_sha=HEAD_SHA, base_sha=BASE_SHA, locale="ru",
    )
    paths = {"l10n/app_ru.properties": "ru", "l10n/app_cs.properties": "cs"}
    policy = _policy()
    assert guardian_controller._replacement_target_locales(policy, (event,), paths) == {
        event.feedback_id: {"l10n/app_ru.properties": "ru"}
    }
    both = replace(policy, trusted_reviewers={
        "ru": policy.trusted_reviewers["ru"], "cs": policy.trusted_reviewers["ru"]
    })
    assert guardian_controller._replacement_target_locales(both, (event,), paths) == {
        event.feedback_id: paths
    }
    for invalid in (replace(event, author_id=None), replace(event, author_type="Bot")):
        assert guardian_controller._replacement_target_locales(both, (invalid,), paths) == {
            event.feedback_id: {}
        }


def _authorized_historical_digest(
    policy: RepositoryPolicy,
    snapshot: PullRequestFeedbackSnapshot,
) -> str:
    authorized = authorize_historical_feedback(
        policy=policy,
        snapshot=snapshot,
        path_locales={TARGET_PATH: "ru"},
        changed_locales=("ru",),
    )
    return guardian_controller._historical_pull_revision_digest(
        policy,
        snapshot,
        feedback_events=authorized.events,
    )


def test_historical_authority_digest_excludes_deletion_tombstones() -> None:
    policy = _historical_policy(remediation=True)
    snapshot = _snapshot(pull=_pull(state="closed"))
    authorized = authorize_historical_feedback(
        policy=policy,
        snapshot=snapshot,
        path_locales={TARGET_PATH: "ru"},
        changed_locales=("ru",),
    )
    live = authorized.events[0]
    tombstone = replace(
        live,
        event_id="45",
        body="",
        deleted=True,
        updated_at="2026-08-30T11:00:00Z",
    )

    live_digest = guardian_controller._historical_pull_revision_digest(
        policy,
        snapshot,
        feedback_events=(live,),
    )
    with_tombstone = guardian_controller._historical_pull_revision_digest(
        policy,
        snapshot,
        feedback_events=(live, tombstone),
    )

    assert with_tombstone == live_digest


class FakeSnapshotProvider:
    def __init__(
        self,
        snapshots: tuple[PullRequestFeedbackSnapshot, ...],
        *,
        sequence: list[str] | None = None,
    ) -> None:
        self.snapshots = snapshots
        self.sequence = sequence
        self.calls: list[tuple[str, tuple[FeedbackRevision, ...]]] = []

    def __call__(
        self,
        policy: RepositoryPolicy,
        previous_feedback: tuple[FeedbackRevision, ...],
    ) -> tuple[PullRequestFeedbackSnapshot, ...]:
        self.calls.append((policy.base_repo, previous_feedback))
        return tuple(
            snapshot
            for snapshot in self.snapshots
            if snapshot.pull_request.repository == policy.base_repo
        )

    def revalidate_open_pull_request(
        self,
        policy: RepositoryPolicy,
        source: OpenPullAuthorityReference,
    ) -> PullRequestFeedbackSnapshot:
        matches = tuple(
            snapshot
            for snapshot in self.snapshots
            if snapshot.pull_request.repository == policy.base_repo
            and (
                snapshot.pull_request.pull_id,
                snapshot.pull_request.number,
            )
            == (source.pull_id, source.pr_number)
            and snapshot.pull_request.state == "open"
        )
        if len(matches) != 1:
            raise PolicyViolation("exact open pull is unavailable")
        snapshot = matches[0]
        if self.sequence is None or "publish" not in self.sequence:
            return snapshot
        return replace(
            snapshot,
            pull_request=replace(snapshot.pull_request, head_sha=COMMIT_SHA),
        )


class FakeHistoricalSnapshotProvider:
    def __init__(
        self,
        snapshots: tuple[PullRequestFeedbackSnapshot, ...],
        *,
        sequence: list[str] | None = None,
    ) -> None:
        self.snapshots = snapshots
        self.sequence = sequence
        self.calls: list[dict[str, object]] = []
        self.exact_calls: list[dict[str, object]] = []

    def revalidate(
        self,
        policy: RepositoryPolicy,
        sources: tuple[HistoricalPullReference, ...],
    ) -> tuple[PullRequestFeedbackSnapshot, ...]:
        self.exact_calls.append({"policy": policy, "sources": sources})
        by_identity = {
            (
                snapshot.pull_request.pull_id,
                snapshot.pull_request.number,
            ): snapshot
            for snapshot in self.snapshots
            if snapshot.pull_request.repository == policy.base_repo
        }
        return tuple(
            by_identity[(source.pull_id, source.pr_number)] for source in sources
        )

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
    ) -> ClosedPullScanResult:
        if self.sequence is not None:
            self.sequence.append(f"history:{policy.base_repo}")
        self.calls.append(
            {
                "policy": policy,
                "previous_feedback": previous_feedback,
                "cutoff": cutoff,
                "upper_bound": upper_bound,
                "max_prs_per_poll": max_prs_per_poll,
                "seen_pulls": seen_pulls,
                "priority_pull_groups": priority_pull_groups,
            }
        )
        repository_snapshots = tuple(
            snapshot
            for snapshot in self.snapshots
            if snapshot.pull_request.repository == policy.base_repo
        )
        seen = set((*seen_pulls, *excluded_pulls))
        candidates = tuple(
            snapshot
            for snapshot in repository_snapshots
            if (
                snapshot.pull_request.pull_id,
                snapshot.pull_request.number,
            )
            not in seen
        )
        by_identity = {
            (
                snapshot.pull_request.pull_id,
                snapshot.pull_request.number,
            ): snapshot
            for snapshot in repository_snapshots
        }
        priority_group = priority_pull_groups[0] if priority_pull_groups else ()
        priority_snapshots = (
            tuple(by_identity[identity] for identity in priority_group)
            if priority_group
            and not all(identity in seen for identity in priority_group)
            else ()
        )
        priority_identities = set(priority_group)
        ordered = tuple(
            dict.fromkeys(
                (
                    *priority_snapshots,
                    *(
                        snapshot
                        for snapshot in candidates
                        if (
                            snapshot.pull_request.pull_id,
                            snapshot.pull_request.number,
                        )
                        not in priority_identities
                    ),
                )
            )
        )
        selected = ordered[:max_prs_per_poll]
        if not selected:
            return ClosedPullScanResult(
                items=(),
                hydration_attempts=0,
                cycle_complete=True,
            )
        items: list[ClosedPullScanItem] = []
        for index, snapshot in enumerate(selected):
            items.append(
                ClosedPullScanItem(
                    position=ClosedPullScanPosition(1, index),
                    snapshot=snapshot,
                    pull_id=snapshot.pull_request.pull_id,
                    pull_number=snapshot.pull_request.number,
                    hydration_attempted=True,
                )
            )
        return ClosedPullScanResult(
            items=tuple(items),
            hydration_attempts=len(items),
            cycle_complete=len(selected) == len(ordered),
        )


class LookbackEdgeHistoricalSnapshotProvider:
    """Expose one pull only on discovery day or through durable priority."""

    def __init__(
        self,
        snapshot: PullRequestFeedbackSnapshot,
        *,
        fail_first_hydration: bool = False,
    ) -> None:
        self.snapshot = snapshot
        self.fail_first_hydration = fail_first_hydration
        self.calls: list[dict[str, object]] = []

    def revalidate(
        self,
        policy: RepositoryPolicy,
        sources: tuple[HistoricalPullReference, ...],
    ) -> tuple[PullRequestFeedbackSnapshot, ...]:
        pull = self.snapshot.pull_request
        if pull.repository != policy.base_repo:
            return ()
        if sources != (
            next(
                source
                for source in sources
                if (source.pull_id, source.pr_number) == (pull.pull_id, pull.number)
            ),
        ):
            raise AssertionError("unexpected exact source set")
        return (self.snapshot,)

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
    ) -> ClosedPullScanResult:
        del policy, previous_feedback, excluded_pulls
        self.calls.append(
            {
                "cutoff": cutoff,
                "upper_bound": upper_bound,
                "max_prs_per_poll": max_prs_per_poll,
                "seen_pulls": seen_pulls,
                "priority_pull_groups": priority_pull_groups,
            }
        )
        pull = self.snapshot.pull_request
        identity = (pull.pull_id, pull.number)
        if len(self.calls) == 1 and self.fail_first_hydration:
            return ClosedPullScanResult(
                items=(
                    ClosedPullScanItem(
                        position=ClosedPullScanPosition(1, 0),
                        pull_id=pull.pull_id,
                        pull_number=pull.number,
                        failure_type="GitHubAPIError",
                        hydration_attempted=True,
                    ),
                ),
                hydration_attempts=1,
                cycle_complete=True,
            )
        if len(self.calls) > 1 and priority_pull_groups != ((identity,),):
            return ClosedPullScanResult(
                items=(),
                hydration_attempts=0,
                cycle_complete=True,
            )
        return ClosedPullScanResult(
            items=(
                ClosedPullScanItem(
                    position=ClosedPullScanPosition(1, 0),
                    snapshot=self.snapshot,
                    pull_id=pull.pull_id,
                    pull_number=pull.number,
                    hydration_attempted=True,
                ),
            ),
            hydration_attempts=1,
            cycle_complete=True,
        )


class LeaseProbeSnapshotProvider(FakeSnapshotProvider):
    def __init__(
        self,
        snapshots: tuple[PullRequestFeedbackSnapshot, ...],
        *,
        state_path: Path,
        probe_at: datetime,
    ) -> None:
        super().__init__(snapshots)
        self.state_path = state_path
        self.probe_at = probe_at
        self.rival_acquired: bool | None = None

    def __call__(
        self,
        policy: RepositoryPolicy,
        previous_feedback: tuple[FeedbackRevision, ...],
    ) -> tuple[PullRequestFeedbackSnapshot, ...]:
        with GuardianState(self.state_path) as rival:
            self.rival_acquired = rival.acquire_lease(
                name="guardian:poll",
                owner="rival",
                ttl_seconds=30,
                now=self.probe_at,
            )
        return super().__call__(policy, previous_feedback)


class FakeCodexDriver:
    model = "test-model"

    def __init__(
        self, *, confidence: float = 0.99, error: Exception | None = None
    ) -> None:
        self.confidence = confidence
        self.error = error
        self.calls = []
        self.api_keys: list[str | None] = []

    def run(
        self,
        task,
        *,
        api_key: str | None = None,
        attempt_observer=None,
        success_observer=None,
    ) -> CodexResult:
        if attempt_observer is not None:
            attempt_observer(1, "started", None)
        self.calls.append(task)
        self.api_keys.append(api_key)
        if self.error is not None:
            if attempt_observer is not None:
                attempt_observer(1, "failed", None)
            raise self.error
        manifest = json.loads((task.evidence_dir / "manifest.json").read_text())
        feedback_id = manifest["feedback_ids"][0]
        result = CodexResult(
            schema_version=1,
            summary="One safe value correction.",
            feedback=(
                GuardianFeedbackDecision(
                    feedback_id=feedback_id,
                    verdict="apply",
                    confidence=self.confidence,
                    rationale="The proposed wording is more idiomatic.",
                    replacements=(
                        GuardianReplacement(
                            path=TARGET_PATH,
                            key="greeting",
                            expected_value="Старый %0 был отклонён (%1). %2 %3",
                            proposed_value="Отправка в %0 отклонена (%1). %2 %3",
                        ),
                    ),
                ),
            ),
            recurrence_candidates=(),
            attempts=1,
            usage=CodexUsage(input_tokens=100, output_tokens=20, cost_usd=0.25),
        )
        if success_observer is not None:
            success_observer(1, result.usage, result)
        if attempt_observer is not None:
            attempt_observer(1, "succeeded", result.usage)
        return result


class TwoReplacementCodexDriver(FakeCodexDriver):
    """Return one existing and one additional current-base correction."""

    @staticmethod
    def _with_alpha(result: CodexResult) -> CodexResult:
        decision = result.feedback[0]
        return replace(
            result,
            feedback=(
                replace(
                    decision,
                    replacements=(
                        *decision.replacements,
                        GuardianReplacement(
                            path=TARGET_PATH,
                            key="alpha",
                            expected_value="Старый альфа",
                            proposed_value="Исправленный альфа",
                        ),
                    ),
                ),
            ),
        )

    def run(
        self,
        task,
        *,
        api_key=None,
        attempt_observer=None,
        success_observer=None,
    ) -> CodexResult:
        transformed: CodexResult | None = None

        def persist(attempt, usage, result):
            nonlocal transformed
            transformed = self._with_alpha(result)
            if success_observer is not None:
                success_observer(attempt, usage, transformed)

        result = super().run(
            task,
            api_key=api_key,
            attempt_observer=attempt_observer,
            success_observer=persist,
        )
        return transformed or self._with_alpha(result)


class RecurrenceCodexDriver(FakeCodexDriver):
    def run(
        self,
        task,
        *,
        api_key: str | None = None,
        attempt_observer=None,
        success_observer=None,
    ) -> CodexResult:
        transformed: CodexResult | None = None

        def persist_recurrence(attempt, usage, result):
            nonlocal transformed
            feedback_id = result.feedback[0].feedback_id
            transformed = replace(
                result,
                recurrence_candidates=(
                    GuardianRecurrenceCandidate(
                        scope="pipeline_code",
                        summary="Reject this review defect before publication.",
                        evidence_feedback_ids=(feedback_id,),
                    ),
                ),
            )
            if success_observer is not None:
                success_observer(attempt, usage, transformed)

        result = super().run(
            task,
            api_key=api_key,
            attempt_observer=attempt_observer,
            success_observer=persist_recurrence,
        )
        feedback_id = result.feedback[0].feedback_id
        return transformed or replace(
            result,
            recurrence_candidates=(
                GuardianRecurrenceCandidate(
                    scope="pipeline_code",
                    summary="Reject this review defect before publication.",
                    evidence_feedback_ids=(feedback_id,),
                ),
            ),
        )


class RetryingCodexDriver(FakeCodexDriver):
    def run(
        self,
        task,
        *,
        api_key: str | None = None,
        attempt_observer=None,
        success_observer=None,
    ) -> CodexResult:
        assert attempt_observer is not None
        attempt_observer(1, "started", None)
        attempt_observer(
            1,
            "failed",
            CodexUsage(input_tokens=40, output_tokens=5, cost_usd=0.10),
        )
        result = super().run(
            task,
            api_key=api_key,
            attempt_observer=lambda _attempt, phase, usage: attempt_observer(
                2, phase, usage
            ),
            success_observer=(
                None
                if success_observer is None
                else lambda _attempt, usage, successful: success_observer(
                    2, usage, successful
                )
            ),
        )
        return replace(result, attempts=2)


class FakePreventionRunner:
    def __init__(
        self,
        *,
        result: PreventionBatchOutcome | None = None,
        error: Exception | None = None,
        orphan_result: PreventionBatchOutcome | None = None,
        orphan_error: Exception | None = None,
        sequence: list[str] | None = None,
    ) -> None:
        self.result = result or PreventionBatchOutcome()
        self.error = error
        self.orphan_result = orphan_result or PreventionBatchOutcome()
        self.orphan_error = orphan_error
        self.sequence = sequence
        self.begin_calls = 0
        self.recover_orphan_calls: list[dict[str, object]] = []
        self.recover_calls: list[dict[str, object]] = []
        self.propose_calls: list[dict[str, object]] = []

    def begin_poll(self) -> None:
        self.begin_calls += 1

    def recover_orphans(self, **kwargs: object) -> PreventionBatchOutcome:
        self.recover_orphan_calls.append(dict(kwargs))
        if self.orphan_error is not None:
            raise self.orphan_error
        return self.orphan_result

    def recover(self, **kwargs: object) -> PreventionBatchOutcome:
        self.recover_calls.append(dict(kwargs))
        return PreventionBatchOutcome()

    def propose(self, **kwargs: object) -> PreventionBatchOutcome:
        self.propose_calls.append(dict(kwargs))
        if self.sequence is not None:
            self.sequence.append("prevention")
        if self.error is not None:
            raise self.error
        return self.result


@dataclass
class FakeWorkspace:
    path: Path
    original_sha: str
    sequence: list[str]
    commits: int = 0
    publications: int = 0
    author_email: str | None = None

    def commit_validated_changes(self, **kwargs) -> CommitResult:
        """Capture the signing contract and return the deterministic test commit."""
        self.sequence.append("commit")
        self.commits += 1
        self.author_email = kwargs.get("author_email")
        assert kwargs["sign"] is True
        assert kwargs["expected_paths"] == (TARGET_PATH,)
        return CommitResult(
            commit_sha=COMMIT_SHA,
            parent_sha=self.original_sha,
            changed_paths=(TARGET_PATH,),
            signature_verified=True,
        )

    def publish_commit(self, commit: CommitResult, **kwargs) -> PublicationResult:
        assert commit.commit_sha == COMMIT_SHA
        assert kwargs["require_signature"] is True
        kwargs["before_push"]()
        self.sequence.append("publish")
        self.publications += 1
        return PublicationResult(
            ref="refs/heads/localize/russian",
            previous_sha=self.original_sha,
            commit_sha=commit.commit_sha,
        )


class FakeCheckoutFactory:
    def __init__(
        self, base_tree: Path, head_tree: Path, tmp_path: Path, sequence: list[str]
    ) -> None:
        self.base_tree = base_tree
        self.head_tree = head_tree
        self.tmp_path = tmp_path
        self.sequence = sequence
        self.workspaces: list[FakeWorkspace] = []
        self.counter = 0

    @contextmanager
    def __call__(self, revision) -> Iterator[FakeWorkspace]:
        self.counter += 1
        source = self.base_tree if revision.owner == "acme" else self.head_tree
        destination = self.tmp_path / f"checkout-{self.counter}"
        shutil.copytree(source, destination)
        workspace = FakeWorkspace(destination, revision.sha, self.sequence)
        self.workspaces.append(workspace)
        try:
            yield workspace
        finally:
            shutil.rmtree(destination)


class FakeHistoricalCheckoutFactory:
    def __init__(
        self,
        base_tree: Path,
        head_tree: Path,
        tmp_path: Path,
        *,
        sequence: list[str] | None = None,
        fail_once: Exception | None = None,
    ) -> None:
        self.base_tree = base_tree
        self.head_tree = head_tree
        self.tmp_path = tmp_path
        self.sequence = sequence
        self.fail_once = fail_once
        self.revisions: list[HistoricalRevision] = []
        self.counter = 0

    @contextmanager
    def __call__(
        self,
        revision: HistoricalRevision,
    ) -> Iterator[HistoricalWorkspace]:
        self.revisions.append(revision)
        if self.fail_once is not None:
            error = self.fail_once
            self.fail_once = None
            raise error
        self.counter += 1
        source = self.head_tree if revision.pull_number is not None else self.base_tree
        destination = self.tmp_path / f"historical-checkout-{self.counter}"
        shutil.copytree(source, destination)
        if self.sequence is not None:
            kind = "head" if revision.pull_number is not None else "base"
            self.sequence.append(f"historical-checkout:{kind}")
        try:
            yield HistoricalWorkspace(destination, revision)
        finally:
            shutil.rmtree(destination)


class FakeCurrentBaseProvider:
    def __init__(
        self,
        *,
        sequence: list[str] | None = None,
        sha: str = "e" * 40,
    ) -> None:
        self.sequence = sequence
        self.sha = sha
        self.calls: list[RepositoryPolicy] = []

    def __call__(self, policy: RepositoryPolicy) -> BaseRevisionSnapshot:
        self.calls.append(policy)
        if self.sequence is not None:
            self.sequence.append(f"current:{policy.base_repo}")
        return BaseRevisionSnapshot(
            repository_identity=GitHubRepositoryIdentity(
                full_name=policy.base_repo,
                repository_id=policy.base_repo_id,
                private=False,
            ),
            branch=policy.base_branch,
            sha=self.sha,
        )


class FakeRemediationRunner:
    def __init__(
        self,
        *,
        publish_result: RemediationBatchOutcome | None = None,
        recover_result: RemediationBatchOutcome | None = None,
        begin_error: Exception | None = None,
        recover_error: Exception | None = None,
        publish_error: Exception | None = None,
        successor_result: RemediationDraftResult | None = None,
        successor_error: Exception | None = None,
        sequence: list[str] | None = None,
    ) -> None:
        self.publish_result = publish_result or RemediationBatchOutcome()
        self.recover_result = recover_result or RemediationBatchOutcome()
        self.begin_error = begin_error
        self.recover_error = recover_error
        self.publish_error = publish_error
        self.successor_result = successor_result
        self.successor_error = successor_error
        self.sequence = sequence
        self.begin_calls = 0
        self.recover_calls: list[dict[str, object]] = []
        self.publish_calls: list[dict[str, object]] = []
        self.successor_calls: list[dict[str, object]] = []
        self.state: GuardianState | None = None

    def begin_poll(self) -> None:
        self.begin_calls += 1
        if self.begin_error is not None:
            raise self.begin_error

    def revalidate_successor_pull(self, **kwargs: object) -> RemediationDraftResult:
        self.successor_calls.append(dict(kwargs))
        if self.successor_error is not None:
            raise self.successor_error
        if self.successor_result is not None:
            return replace(
                self.successor_result,
                candidate_sha=str(kwargs["expected_remote_head_sha"]),
            )
        return RemediationDraftResult(
            number=91,
            html_url="https://github.com/acme/widgets/pull/91",
            candidate_sha=str(kwargs["expected_remote_head_sha"]),
            created=False,
            base_sha=str(kwargs["expected_base_sha"]),
        )

    def recover(self, **kwargs: object) -> RemediationBatchOutcome:
        if self.sequence is not None:
            policy = kwargs["policy"]
            assert isinstance(policy, RepositoryPolicy)
            self.sequence.append(f"remediation-recover:{policy.base_repo}")
        self.recover_calls.append(dict(kwargs))
        if self.recover_error is not None:
            raise self.recover_error
        return self.recover_result

    def publish(self, **kwargs: object) -> RemediationBatchOutcome:
        if self.sequence is not None:
            self.sequence.append("remediation-publish")
        self.publish_calls.append(dict(kwargs))
        if self.publish_error is not None:
            raise self.publish_error
        if (
            self.state is not None
            and not self.publish_result.deferred
            and not self.publish_result.abandoned
            and not getattr(self.publish_result, "failures", ())
        ):
            observed_at = kwargs["observed_at"]
            assert isinstance(observed_at, datetime)
            source_pulls = tuple(kwargs["source_pulls"])
            revision_ids = tuple(kwargs["event_revision_ids"])
            require_exact_sources = kwargs["require_exact_sources_still_closed"]
            assert callable(require_exact_sources)
            require_exact_sources(source_pulls, revision_ids)
            for source in source_pulls:
                self.state.record_independent_remediation_completion(
                    source,
                    RemediationCoverageReason.INDEPENDENT_ALREADY_CURRENT,
                    occurred_at=observed_at,
                )
        return self.publish_result


def test_remediation_outcome_validates_atomic_retry_groups() -> None:
    first = _retry_source()
    second = _retry_source(
        pull_id=501,
        pr_number=13,
        pull_revision_digest="3" * 64,
        head_sha="e" * 40,
    )
    accumulator = guardian_controller._PollAccumulator()

    terminal, batches = GuardianController._remediation_outcome(
        RemediationBatchOutcome(retry_source_batches=((first, second),)),
        outcome=accumulator,
    )

    assert terminal is True
    assert batches == ((first, second),)
    malformed_batches: tuple[object, ...] = (
        [],
        (first,),
        ((),),
        (((first,),),),
        ((first, replace(first, pull_revision_digest="4" * 64)),),
        ((first, replace(first, pr_number=13)),),
        ((first, replace(first, pull_id=501)),),
        ((first,), (second,)),
    )
    for malformed in malformed_batches:
        with pytest.raises(
            TypeError,
            match="Remediation runner returned a malformed outcome",
        ):
            GuardianController._remediation_outcome(
                RemediationBatchOutcome(
                    retry_source_batches=malformed,  # type: ignore[arg-type]
                ),
                outcome=guardian_controller._PollAccumulator(),
            )


def test_historical_remediation_repository_order_rotates_after_last_publisher() -> None:
    policies = tuple(
        _policy(repository=repository)
        for repository in ("acme/first", "acme/second", "acme/third")
    )

    first_poll = guardian_controller._rotate_policies_after_repository(
        policies,
        None,
    )
    second_poll = guardian_controller._rotate_policies_after_repository(
        policies,
        "acme/first",
    )
    third_poll = guardian_controller._rotate_policies_after_repository(
        policies,
        "acme/second",
    )

    assert [policy.base_repo for policy in first_poll] == [
        "acme/first",
        "acme/second",
        "acme/third",
    ]
    assert [policy.base_repo for policy in second_poll] == [
        "acme/second",
        "acme/third",
        "acme/first",
    ]
    assert [policy.base_repo for policy in third_poll] == [
        "acme/third",
        "acme/first",
        "acme/second",
    ]


class FakeBroker:
    def __init__(self, sequence: list[str]) -> None:
        self.sequence = sequence
        self.verify_calls = []
        self.verify_error_on_call: int | None = None
        self.reply_calls = []
        self.reply_error: Exception | None = None

    def verify_pull(self, **kwargs):
        self.sequence.append("verify")
        self.verify_calls.append(kwargs)
        if self.verify_error_on_call == len(self.verify_calls):
            raise RuntimeError("fresh pull authority changed")
        return _pull()

    def post_commit_reply(self, **kwargs):
        self.sequence.append("reply")
        self.reply_calls.append(kwargs)
        if self.reply_error is not None:
            raise self.reply_error
        kwargs["before_create"]()
        assert kwargs["expected_head_sha"] == COMMIT_SHA
        assert kwargs["commit_sha"] == COMMIT_SHA
        return object()


@pytest.fixture
def runtime(tmp_path: Path):
    base = tmp_path / "base-template"
    head = tmp_path / "head-template"
    base.mkdir()
    head.mkdir()
    _write_tree(base)
    # The untrusted head config is deliberately incompatible. The controller
    # and its source string has hostile placeholder drift. The controller must
    # use the exact base config and source while validating head target files.
    _write_tree(head, head_config_source_locale="xx")
    (head / "l10n/messages_en.properties").write_text(
        "greeting=Untrusted source rewrite %9\n",
        encoding="utf-8",
    )
    sequence: list[str] = []
    checkout = FakeCheckoutFactory(base, head, tmp_path, sequence)
    provider = FakeSnapshotProvider((_snapshot(),), sequence=sequence)
    broker = FakeBroker(sequence)
    return base, head, checkout, provider, broker, sequence


def _controller(
    *,
    tmp_path: Path,
    state: GuardianState,
    config: GuardianConfig,
    checkout: FakeCheckoutFactory,
    provider: FakeSnapshotProvider,
    driver: FakeCodexDriver,
    broker: FakeBroker,
    prevention_runner: FakePreventionRunner | None = None,
    historical_snapshot_provider: FakeHistoricalSnapshotProvider | None = None,
    historical_checkout_factory: FakeHistoricalCheckoutFactory | None = None,
    current_base_provider: FakeCurrentBaseProvider | None = None,
    remediation_runner: FakeRemediationRunner | None = None,
    historical_source_snapshot_provider=None,
    operator_pipeline_configs: dict[str, PipelineConfigSnapshot] | None = None,
    evidence_builder=build_evidence_bundle,
    replacement_applier=apply_replacements,
    now=None,
    publication_actor_preflight=None,
    deadline: PollDeadline | None = None,
) -> GuardianController:
    if remediation_runner is not None:
        remediation_runner.state = state
    if (
        remediation_runner is not None or prevention_runner is not None
    ) and historical_snapshot_provider is not None:
        if historical_source_snapshot_provider is None:
            historical_source_snapshot_provider = (
                historical_snapshot_provider.revalidate
            )
    return GuardianController(
        config=config,
        state=state,
        snapshot_provider=provider,
        checkout_factory=checkout,
        codex_driver=driver,
        model_credential_provider=lambda: "scoped-model-key",
        write_broker_factory=lambda _policy: broker,
        prevention_runner=prevention_runner,
        historical_snapshot_provider=historical_snapshot_provider,
        historical_source_snapshot_provider=(historical_source_snapshot_provider),
        historical_checkout_factory=historical_checkout_factory,
        current_base_provider=current_base_provider,
        remediation_runner=remediation_runner,
        publish_credential_environment=lambda: {"GIT_ASKPASS": "/safe/helper"},
        evidence_root=tmp_path / "evidence",
        now=now or (lambda: NOW),
        operator_pipeline_configs=operator_pipeline_configs,
        evidence_builder=evidence_builder,
        replacement_applier=replacement_applier,
        publication_actor_preflight=(publication_actor_preflight or (lambda: None)),
        deadline=deadline,
    )


def test_operator_pipeline_config_uses_snapshot_with_exact_base_sources(
    tmp_path: Path,
    runtime,
) -> None:
    base, _head, checkout, provider, broker, _sequence = runtime
    operator_root = tmp_path / "operator-snapshot"
    operator_root.mkdir()
    operator_config = operator_root / "config.yaml"
    shutil.copy2(base / ".localize/config.yaml", operator_config)
    shutil.copy2(base / ".localize/glossary.json", operator_root / "glossary.json")
    snapshot = PipelineConfigSnapshot(
        config_root=operator_root,
        config_path=operator_config,
        bundle_digest="d" * 64,
    )
    policy = replace(
        _policy(),
        pipeline_config_source=PipelineConfigSource.OPERATOR,
        pipeline_config_path="config.yaml",
    )
    evidence_calls: list[dict[str, object]] = []
    apply_calls: list[dict[str, object]] = []

    def evidence_spy(**kwargs):
        evidence_calls.append(dict(kwargs))
        return build_evidence_bundle(**kwargs)

    def apply_spy(**kwargs):
        apply_calls.append(dict(kwargs))
        return apply_replacements(**kwargs)

    with GuardianState(tmp_path / "state.sqlite3") as state:
        outcome = _controller(
            tmp_path=tmp_path,
            state=state,
            config=_config(GuardianMode.PREPARE, policies=(policy,)),
            checkout=checkout,
            provider=provider,
            driver=FakeCodexDriver(),
            broker=broker,
            operator_pipeline_configs={policy.base_repo: snapshot},
            evidence_builder=evidence_spy,
            replacement_applier=apply_spy,
        ).poll_once()

    assert outcome.runs_completed == 1
    assert evidence_calls[0]["trusted_pipeline_config_path"] == operator_config
    assert evidence_calls[0]["trusted_config_root"] == operator_root
    assert evidence_calls[0]["trusted_source_root"].name == "checkout-1"
    assert evidence_calls[0]["trusted_config_bundle_digest"] == "d" * 64
    assert apply_calls[0]["pipeline_config_path"] == operator_config
    assert apply_calls[0]["trusted_config_root"] == operator_root
    assert apply_calls[0]["trusted_source_root"].name == "checkout-1"


def test_propose_prevention_runs_before_translation_publish_and_records_draft(
    tmp_path: Path, runtime
) -> None:
    _base, _head, checkout, provider, broker, sequence = runtime
    prevention = FakePreventionRunner(
        result=PreventionBatchOutcome(
            drafts=(
                PreventionDraftResult(
                    number=91,
                    html_url="https://github.com/guardian/pipeline/pull/91",
                    candidate_sha="e" * 40,
                    created=True,
                ),
            ),
        ),
        sequence=sequence,
    )
    policy = replace(_policy(), prevention=_prevention_policy())
    with GuardianState(tmp_path / "state.sqlite3") as state:
        outcome = _controller(
            tmp_path=tmp_path,
            state=state,
            config=_config(GuardianMode.PROPOSE_PREVENTION, policies=(policy,)),
            checkout=checkout,
            provider=provider,
            driver=RecurrenceCodexDriver(),
            broker=broker,
            prevention_runner=prevention,
        ).poll_once()

        assert outcome.runs_completed == 1
        assert outcome.prevention_drafts_created == 1
        assert outcome.prevention_failures == ()
        assert prevention.begin_calls == 1
        assert len(prevention.recover_orphan_calls) == 1
        assert prevention.recover_orphan_calls[0]["configured_policies"] == (policy,)
        assert len(prevention.recover_calls) == 1
        assert len(prevention.propose_calls) == 1
        propose = prevention.propose_calls[0]
        assert propose["policy"] == policy
        assert propose["evidence_revision_ids"] == {"review_comment:44": 1}
        assert isinstance(propose["open_source"], OpenPullAuthorityReference)
        assert propose["source_event_revision_ids"] == (1,)
        assert callable(propose["require_exact_open_source_authority"])
        assert sequence == [
            "prevention",
            "commit",
            "verify",
            "verify",
            "publish",
            "reply",
        ]


@pytest.mark.parametrize("race", ("edited", "deleted", "added"))
def test_open_prevention_revalidates_complete_trusted_authority_before_write(
    race: str,
    tmp_path: Path,
    runtime,
) -> None:
    _base, _head, checkout, provider, broker, sequence = runtime
    original = provider.snapshots[0]
    feedback = list(original.feedback)
    if race == "edited":
        feedback[0] = replace(
            feedback[0],
            body="Use a newly edited idiomatic wording.",
            updated_at="2026-08-30T10:01:00Z",
        )
    elif race == "deleted":
        feedback[0] = replace(
            feedback[0],
            body="",
            deleted=True,
            updated_at="2026-08-30T10:01:00Z",
        )
    else:
        feedback.append(
            _feedback(
                body="Also prevent this related recurrence.",
                updated_at="2026-08-30T10:01:00Z",
                source_id="45",
            )
        )
    raced = replace(original, feedback=tuple(feedback))

    class RacingProvider(FakeSnapshotProvider):
        revalidation_calls = 0

        def revalidate_open_pull_request(self, policy, source):
            del policy, source
            self.revalidation_calls += 1
            return original if self.revalidation_calls == 1 else raced

    class RevalidatingPrevention(FakePreventionRunner):
        def propose(self, **kwargs: object) -> PreventionBatchOutcome:
            callback = kwargs["require_exact_open_source_authority"]
            assert callable(callback)
            callback(
                kwargs["open_source"],
                kwargs["source_event_revision_ids"],
            )
            return super().propose(**kwargs)

    prevention = RevalidatingPrevention(sequence=sequence)
    policy = replace(_policy(), prevention=_prevention_policy())
    racing_provider = RacingProvider((original,))
    with GuardianState(tmp_path / "state.sqlite3") as state:
        outcome = _controller(
            tmp_path=tmp_path,
            state=state,
            config=_config(GuardianMode.PROPOSE_PREVENTION, policies=(policy,)),
            checkout=checkout,
            provider=racing_provider,
            driver=RecurrenceCodexDriver(),
            broker=broker,
            prevention_runner=prevention,
        ).poll_once()

    assert outcome.runs_failed == 1
    assert outcome.applied_commits == ()
    assert outcome.prevention_drafts_created == 0
    assert outcome.failures == ("PreventionSourceAuthorityError",)
    assert sequence == []
    assert broker.verify_calls == []
    assert broker.reply_calls == []
    assert racing_provider.revalidation_calls == 2


@pytest.mark.parametrize("race", ("edited", "deleted", "added"))
def test_translation_push_revalidates_complete_trusted_authority(
    race: str,
    tmp_path: Path,
    runtime,
) -> None:
    _base, _head, checkout, provider, broker, sequence = runtime
    original = provider.snapshots[0]
    feedback = list(original.feedback)
    if race == "edited":
        feedback[0] = replace(
            feedback[0],
            body="Use a newly edited idiomatic wording.",
            updated_at="2026-08-30T10:01:00Z",
        )
    elif race == "deleted":
        feedback[0] = replace(
            feedback[0],
            body="",
            deleted=True,
            updated_at="2026-08-30T10:01:00Z",
        )
    else:
        feedback.append(
            _feedback(
                body="Also apply this related correction.",
                updated_at="2026-08-30T10:01:00Z",
                source_id="45",
            )
        )
    raced = replace(original, feedback=tuple(feedback))

    class RacingProvider(FakeSnapshotProvider):
        def revalidate_open_pull_request(self, policy, source):
            del policy, source
            return raced

    with GuardianState(tmp_path / "state.sqlite3") as state:
        outcome = _controller(
            tmp_path=tmp_path,
            state=state,
            config=_config(GuardianMode.APPLY_OWNED_TRANSLATIONS),
            checkout=checkout,
            provider=RacingProvider((original,)),
            driver=FakeCodexDriver(),
            broker=broker,
        ).poll_once()

    assert outcome.runs_failed == 1
    assert outcome.applied_commits == ()
    assert outcome.failures == ("PreventionSourceAuthorityError",)
    assert sequence == ["commit", "verify", "verify"]
    assert broker.reply_calls == []
    assert all(workspace.publications == 0 for workspace in checkout.workspaces)


def test_translation_publication_excludes_prevention_suppressed_revisions(
    tmp_path: Path,
) -> None:
    sequence: list[str] = []
    broker = FakeBroker(sequence)
    workspace = FakeWorkspace(tmp_path, HEAD_SHA, sequence)
    suppressed = FeedbackEvent(
        repository="acme/widgets",
        pr_number=12,
        kind="review_comment",
        event_id="44",
        author="native-reviewer",
        author_id=101,
        author_type="User",
        body="Previously applied translation advice.",
        head_sha=HEAD_SHA,
        base_sha=BASE_SHA,
        locale="ru",
        path=TARGET_PATH,
        html_url="https://github.com/acme/widgets/pull/12#discussion_r44",
    )
    included = replace(
        suppressed,
        event_id="45",
        body="New translation advice.",
        html_url="https://github.com/acme/widgets/pull/12#discussion_r45",
    )

    def assessment(event: FeedbackEvent) -> GuardianAssessment:
        return GuardianAssessment(
            feedback_id=event.feedback_id,
            verdict="apply",
            confidence=0.99,
            rationale="Validated translation correction.",
            replacements=(
                ProposedReplacement(
                    feedback_id=event.feedback_id,
                    path=TARGET_PATH,
                    key="greeting",
                    locale="ru",
                    expected_value="old",
                    proposed_value="new",
                    confidence=0.99,
                    evidence=(event.feedback_id,),
                ),
            ),
        )

    with GuardianState(tmp_path / "state.sqlite3") as state:
        suppressed_revision = state.record_feedback_event(suppressed, observed_at=NOW)
        included_revision = state.record_feedback_event(included, observed_at=NOW)
        run_id = state.start_run(
            repository="acme/widgets",
            locale="ru",
            mode=GuardianMode.PROPOSE_PREVENTION,
            started_at=NOW,
        )
        assert state.acquire_lease(
            name="guardian:poll",
            owner="test-owner",
            ttl_seconds=60,
            now=NOW,
        )
        controller = GuardianController(
            config=_config(GuardianMode.PROPOSE_PREVENTION),
            state=state,
            snapshot_provider=FakeSnapshotProvider(()),
            checkout_factory=None,  # type: ignore[arg-type]
            codex_driver=FakeCodexDriver(),
            model_credential_provider=lambda: "scoped-model-key",
            write_broker_factory=lambda _policy: broker,
            prevention_runner=FakePreventionRunner(),
            publish_credential_environment=lambda: {},
            now=lambda: NOW,
            publication_actor_preflight=lambda: None,
        )
        controller._require_exact_open_source_authority = (  # type: ignore[method-assign]
            lambda **_kwargs: None
        )

        controller._publish_translation_commit(
            policy=_policy(),
            snapshot=_snapshot(),
            workspace=workspace,  # type: ignore[arg-type]
            patch_result=PatchResult(
                changed_files=(TARGET_PATH,),
                changed_keys=((TARGET_PATH, "greeting"),),
            ),
            replacements=(assessment(included).replacements[0],),
            assessments=(assessment(suppressed), assessment(included)),
            actionable=(
                (suppressed, suppressed_revision),
                (included, included_revision),
            ),
            open_source=OpenPullAuthorityReference(
                repository="acme/widgets",
                repository_id=42,
                pull_id=1200,
                pr_number=12,
                authority_digest="1" * 64,
                head_sha=HEAD_SHA,
                base_sha=BASE_SHA,
                feedback_digest="2" * 64,
            ),
            translation_suppressed_feedback_ids=frozenset({suppressed.feedback_id}),
            run_id=run_id,
            lease_owner="test-owner",
        )

        publication_actor = _policy().publication_actor
        assert publication_actor is not None
        publication = state.replied_publication_for_head(
            repository="acme/widgets",
            pr_number=12,
            head_sha=COMMIT_SHA,
            publication_actor_id=publication_actor.id,
            publication_actor_type=publication_actor.type,
        )
        assert publication is not None
        assert publication.event_revision_ids == (included_revision.revision_id,)
        assert broker.reply_calls[0]["event_revision_id"] == str(
            included_revision.revision_id
        )


@pytest.mark.parametrize(
    "crash_point",
    ("after_push", "after_post", "after_atomic_commit"),
)
def test_ordinary_publication_recovery_completes_the_full_prepared_plan_once(
    crash_point: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sequence: list[str] = []
    broker = FakeBroker(sequence)
    workspace = FakeWorkspace(tmp_path, HEAD_SHA, sequence)
    selected = FeedbackEvent(
        repository="acme/widgets",
        pr_number=12,
        kind="review_comment",
        event_id="atomic-selected",
        author="native-reviewer",
        author_id=101,
        author_type="User",
        body="Apply this exact correction.",
        head_sha=HEAD_SHA,
        base_sha=BASE_SHA,
        locale="ru",
        path=TARGET_PATH,
        html_url="https://github.com/acme/widgets/pull/12#discussion_atomic-selected",
    )
    no_change = replace(
        selected,
        event_id="atomic-no-change",
        body="This second review item needs no repository change.",
        html_url="https://github.com/acme/widgets/pull/12#discussion_atomic-no-change",
    )
    replacement = ProposedReplacement(
        feedback_id=selected.feedback_id,
        path=TARGET_PATH,
        key="greeting",
        locale="ru",
        expected_value="old",
        proposed_value="new",
        confidence=0.99,
        evidence=(selected.feedback_id,),
    )
    assessments = (
        GuardianAssessment(
            feedback_id=selected.feedback_id,
            verdict="apply",
            confidence=0.99,
            rationale="Apply the selected correction.",
            replacements=(replacement,),
        ),
        GuardianAssessment(
            feedback_id=no_change.feedback_id,
            verdict="reject",
            confidence=0.98,
            rationale="No repository change is required.",
        ),
    )

    class SimulatedProcessCrash(BaseException):
        pass

    with GuardianState(tmp_path / "state.sqlite3") as state:
        selected_revision = state.record_feedback_event(selected, observed_at=NOW)
        no_change_revision = state.record_feedback_event(no_change, observed_at=NOW)
        run_id = state.start_run(
            repository="acme/widgets",
            locale="ru",
            mode=GuardianMode.APPLY_OWNED_TRANSLATIONS,
            started_at=NOW,
        )
        assert state.acquire_lease(
            name="guardian:poll",
            owner="test-owner",
            ttl_seconds=60,
            now=NOW,
        )
        controller = GuardianController(
            config=_config(GuardianMode.APPLY_OWNED_TRANSLATIONS),
            state=state,
            snapshot_provider=FakeSnapshotProvider(()),
            checkout_factory=None,  # type: ignore[arg-type]
            codex_driver=FakeCodexDriver(),
            write_broker_factory=lambda _policy: broker,
            publish_credential_environment=lambda: {},
            now=lambda: NOW,
            publication_actor_preflight=lambda: None,
        )
        controller._require_exact_open_source_authority = (  # type: ignore[method-assign]
            lambda **_kwargs: None
        )
        original_finalizer = state.finalize_replied_publication
        expected_error: type[BaseException]
        if crash_point == "after_push":
            broker.reply_error = RuntimeError("crash after push")
            expected_error = RuntimeError
        elif crash_point == "after_post":

            def crash_before_atomic_finalizer(**_kwargs: object) -> None:
                raise RuntimeError("crash after remote reply")

            monkeypatch.setattr(
                state,
                "finalize_replied_publication",
                crash_before_atomic_finalizer,
            )
            expected_error = RuntimeError
        else:

            def commit_then_crash(**kwargs: object) -> None:
                original_finalizer(**kwargs)
                raise SimulatedProcessCrash

            monkeypatch.setattr(
                state,
                "finalize_replied_publication",
                commit_then_crash,
            )
            expected_error = SimulatedProcessCrash

        with pytest.raises(expected_error):
            controller._publish_translation_commit(
                policy=_policy(),
                snapshot=_snapshot(),
                workspace=workspace,  # type: ignore[arg-type]
                patch_result=PatchResult(
                    changed_files=(TARGET_PATH,),
                    changed_keys=((TARGET_PATH, "greeting"),),
                ),
                replacements=(replacement,),
                assessments=assessments,
                actionable=(
                    (selected, selected_revision),
                    (no_change, no_change_revision),
                ),
                open_source=OpenPullAuthorityReference(
                    repository="acme/widgets",
                    repository_id=42,
                    pull_id=1200,
                    pr_number=12,
                    authority_digest="1" * 64,
                    head_sha=HEAD_SHA,
                    base_sha=BASE_SHA,
                    feedback_digest="2" * 64,
                ),
                translation_suppressed_feedback_ids=frozenset(),
                run_id=run_id,
                lease_owner="test-owner",
                observed_at=NOW,
            )

        plan_rows = state._connection.execute(  # noqa: SLF001
            "SELECT event_revision_id FROM publication_completion_plan_items "
            "WHERE run_id = ? ORDER BY event_revision_id",
            (run_id,),
        ).fetchall()
        assert [row["event_revision_id"] for row in plan_rows] == [
            selected_revision.revision_id,
            no_change_revision.revision_id,
        ]
        if crash_point == "after_atomic_commit":
            assert state.pending_publications() == ()
            assert state.get_run(run_id).status == "completed"
        else:
            assert state.pending_publications()[0].phase == "published"
            assert state.get_run(run_id).status == "running"
            assert (
                state._connection.execute(  # noqa: SLF001
                    "SELECT COUNT(*) FROM actions WHERE run_id = ?",
                    (run_id,),
                ).fetchone()[0]
                == 0
            )

        broker.reply_error = None
        monkeypatch.setattr(
            state,
            "finalize_replied_publication",
            original_finalizer,
        )
        controller._recover_publications(
            policy=_policy(),
            snapshots=(_snapshot(pull=_pull(head_sha=COMMIT_SHA)),),
            observed_at=NOW,
            lease_owner="test-owner",
        )

        assert state.pending_publications() == ()
        assert state.get_run(run_id).status == "completed"
        actions = state._connection.execute(  # noqa: SLF001
            "SELECT event_revision_id, status, details_json FROM actions "
            "WHERE run_id = ? ORDER BY event_revision_id",
            (run_id,),
        ).fetchall()
        assert [
            (row["event_revision_id"], row["status"], json.loads(row["details_json"]))
            for row in actions
        ] == [
            (
                selected_revision.revision_id,
                "completed",
                {
                    "changed_keys": 1,
                    "commit_sha": COMMIT_SHA,
                    "confidence": 0.99,
                    "outcome": "applied",
                    "recurrence_candidates": 0,
                    "verdict": "apply",
                },
            ),
            (
                no_change_revision.revision_id,
                "completed",
                {
                    "changed_keys": 0,
                    "commit_sha": None,
                    "confidence": 0.98,
                    "outcome": "no_eligible_change",
                    "recurrence_candidates": 0,
                    "verdict": "reject",
                },
            ),
        ]


def test_translation_publication_checks_source_after_each_successor_refresh(
    tmp_path: Path,
) -> None:
    sequence: list[str] = []
    authority_order: list[tuple[str, str]] = []
    authority_generation = {"value": 0}
    broker = FakeBroker(sequence)
    workspace = FakeWorkspace(tmp_path, HEAD_SHA, sequence)

    class MutatingRemediationRunner(FakeRemediationRunner):
        def revalidate_successor_pull(self, **kwargs: object) -> RemediationDraftResult:
            authority_generation["value"] += 1
            authority_order.append(
                ("remediation", str(kwargs["expected_remote_head_sha"]))
            )
            return super().revalidate_successor_pull(**kwargs)

    remediation = MutatingRemediationRunner()
    correction = FeedbackEvent(
        repository="acme/widgets",
        pr_number=91,
        kind="review_comment",
        event_id="successor-45",
        author="native-reviewer",
        author_id=101,
        author_type="User",
        body="Adjust the remediation before it is merged.",
        head_sha=HEAD_SHA,
        base_sha=BASE_SHA,
        locale="ru",
        path=TARGET_PATH,
        html_url=("https://github.com/acme/widgets/pull/91#discussion_rsuccessor-45"),
    )
    replacement = ProposedReplacement(
        feedback_id=correction.feedback_id,
        path=TARGET_PATH,
        key="greeting",
        locale="ru",
        expected_value="candidate",
        proposed_value="reviewed candidate",
        confidence=0.99,
        evidence=(correction.feedback_id,),
    )
    assessment = GuardianAssessment(
        feedback_id=correction.feedback_id,
        verdict="apply",
        confidence=0.99,
        rationale="Apply the trusted remediation review.",
        replacements=(replacement,),
    )

    with GuardianState(tmp_path / "state.sqlite3") as state:
        draft_key, source = _record_open_remediation_draft(state)
        revision = state.record_feedback_event(correction, observed_at=NOW)
        run_id = state.start_run(
            repository="acme/widgets",
            locale="ru",
            mode=GuardianMode.APPLY_OWNED_TRANSLATIONS,
            started_at=NOW,
        )
        assert state.acquire_lease(
            name="guardian:poll",
            owner="test-owner",
            ttl_seconds=60,
            now=NOW,
        )
        controller = GuardianController(
            config=_config(GuardianMode.APPLY_OWNED_TRANSLATIONS),
            state=state,
            snapshot_provider=FakeSnapshotProvider(()),
            checkout_factory=None,  # type: ignore[arg-type]
            codex_driver=FakeCodexDriver(),
            model_credential_provider=lambda: "scoped-model-key",
            write_broker_factory=lambda _policy: broker,
            remediation_runner=remediation,
            publish_credential_environment=lambda: {},
            now=lambda: NOW,
            publication_actor_preflight=lambda: None,
        )

        def require_refreshed_source(**kwargs: object) -> None:
            expected_head = str(kwargs.get("expected_current_head_sha") or HEAD_SHA)
            # A slow successor/overlap refresh may mutate source authority. The
            # exact source check must observe each post-refresh generation.
            assert authority_generation["value"] == 1 + sum(
                kind == "source" for kind, _head in authority_order
            )
            assert authority_order[-1] == ("remediation", expected_head)
            authority_order.append(("source", expected_head))

        controller._require_exact_open_source_authority = (  # type: ignore[method-assign]
            require_refreshed_source
        )
        snapshot = _snapshot(
            pull=_pull(
                pull_id=900,
                number=91,
                html_url="https://github.com/acme/widgets/pull/91",
            ),
            feedback=(),
        )

        commit_sha = controller._publish_translation_commit(
            policy=_historical_policy(remediation=True),
            snapshot=snapshot,
            workspace=workspace,  # type: ignore[arg-type]
            patch_result=PatchResult(
                changed_files=(TARGET_PATH,),
                changed_keys=((TARGET_PATH, "greeting"),),
            ),
            replacements=(replacement,),
            assessments=(assessment,),
            actionable=((correction, revision),),
            open_source=OpenPullAuthorityReference(
                repository="acme/widgets",
                repository_id=42,
                pull_id=900,
                pr_number=91,
                authority_digest="1" * 64,
                head_sha=HEAD_SHA,
                base_sha=BASE_SHA,
                feedback_digest="2" * 64,
            ),
            translation_suppressed_feedback_ids=frozenset(),
            run_id=run_id,
            lease_owner="test-owner",
        )

        successors = state.remediation_successor_publications(draft_key=draft_key)
        assert commit_sha == COMMIT_SHA
        assert len(successors) == 1
        assert successors[0].parent_candidate_sha == HEAD_SHA
        assert successors[0].successor_candidate_sha == COMMIT_SHA
        assert successors[0].source_pulls == (source,)
        assert successors[0].edit_hashes == (remediation_edit_hash(replacement),)
        assert successors[0].changed_paths == (TARGET_PATH,)
        assert successors[0].actor_id == correction.author_id
        assert successors[0].publication_actor_id == 8
        assert successors[0].publication_actor_type == "User"
        assert state.remediation_candidate_tip(draft_key) == COMMIT_SHA
        assert state.pending_publications() == ()

    assert sequence == ["commit", "verify", "verify", "publish", "reply"]
    assert [
        call["expected_remote_head_sha"] for call in remediation.successor_calls
    ] == [HEAD_SHA, COMMIT_SHA]
    assert authority_order == [
        ("remediation", HEAD_SHA),
        ("source", HEAD_SHA),
        ("remediation", COMMIT_SHA),
        ("source", COMMIT_SHA),
    ]
    assert all(
        callable(call["require_no_open_translation_overlap"])
        for call in remediation.successor_calls
    )


def test_reopened_remediation_is_rejected_immediately_before_successor_push(
    tmp_path: Path,
) -> None:
    sequence: list[str] = []
    broker = FakeBroker(sequence)
    workspace = FakeWorkspace(tmp_path, HEAD_SHA, sequence)
    correction = FeedbackEvent(
        repository="acme/widgets",
        pr_number=91,
        kind="review_comment",
        event_id="reopened-successor",
        author="native-reviewer",
        author_id=101,
        author_type="User",
        body="Review this correction before publication.",
        head_sha=HEAD_SHA,
        base_sha=BASE_SHA,
        locale="ru",
        path=TARGET_PATH,
    )
    replacement = ProposedReplacement(
        feedback_id=correction.feedback_id,
        path=TARGET_PATH,
        key="greeting",
        locale="ru",
        expected_value="candidate",
        proposed_value="reviewed candidate",
        confidence=0.99,
        evidence=(correction.feedback_id,),
    )
    assessment = GuardianAssessment(
        feedback_id=correction.feedback_id,
        verdict="apply",
        confidence=0.99,
        rationale="Apply the trusted remediation review.",
        replacements=(replacement,),
    )
    remediation = FakeRemediationRunner(
        successor_error=RemediationRemoteConflictError(
            "remediation was closed unmerged and reopened"
        )
    )

    with GuardianState(tmp_path / "state.sqlite3") as state:
        _record_open_remediation_draft(state)
        revision = state.record_feedback_event(correction, observed_at=NOW)
        run_id = state.start_run(
            repository="acme/widgets",
            locale="ru",
            mode=GuardianMode.APPLY_OWNED_TRANSLATIONS,
            started_at=NOW,
        )
        assert state.acquire_lease(
            name="guardian:poll",
            owner="test-owner",
            ttl_seconds=60,
            now=NOW,
        )
        controller = GuardianController(
            config=_config(GuardianMode.APPLY_OWNED_TRANSLATIONS),
            state=state,
            snapshot_provider=FakeSnapshotProvider(()),
            checkout_factory=None,  # type: ignore[arg-type]
            codex_driver=FakeCodexDriver(),
            write_broker_factory=lambda _policy: broker,
            remediation_runner=remediation,
            publish_credential_environment=lambda: {},
            now=lambda: NOW,
            publication_actor_preflight=lambda: None,
        )
        controller._require_exact_open_source_authority = (  # type: ignore[method-assign]
            lambda **_kwargs: None
        )

        with pytest.raises(RemediationRemoteConflictError, match="reopened"):
            controller._publish_translation_commit(
                policy=_historical_policy(remediation=True),
                snapshot=_snapshot(
                    pull=_pull(
                        pull_id=900,
                        number=91,
                        html_url="https://github.com/acme/widgets/pull/91",
                    ),
                    feedback=(),
                ),
                workspace=workspace,  # type: ignore[arg-type]
                patch_result=PatchResult(
                    changed_files=(TARGET_PATH,),
                    changed_keys=((TARGET_PATH, "greeting"),),
                ),
                replacements=(replacement,),
                assessments=(assessment,),
                actionable=((correction, revision),),
                open_source=OpenPullAuthorityReference(
                    repository="acme/widgets",
                    repository_id=42,
                    pull_id=900,
                    pr_number=91,
                    authority_digest="1" * 64,
                    head_sha=HEAD_SHA,
                    base_sha=BASE_SHA,
                    feedback_digest="2" * 64,
                ),
                translation_suppressed_feedback_ids=frozenset(),
                run_id=run_id,
                lease_owner="test-owner",
            )

        assert len(remediation.successor_calls) == 1
        assert remediation.successor_calls[0]["require_open"] is True
        assert remediation.successor_calls[0]["expected_remote_head_sha"] == HEAD_SHA
        assert sequence == ["commit", "verify", "verify"]
        assert broker.reply_calls == []
        assert state.pending_publications()[0].phase == "prepared"


def test_recovery_checks_source_after_each_successor_refresh_and_uses_full_plan(
    tmp_path: Path,
) -> None:
    sequence: list[str] = []
    authority_order: list[tuple[str, bool]] = []
    authority_generation = {"value": 0}
    broker = FakeBroker(sequence)

    class MutatingRemediationRunner(FakeRemediationRunner):
        def revalidate_successor_pull(self, **kwargs: object) -> RemediationDraftResult:
            authority_generation["value"] += 1
            authority_order.append(("remediation", bool(kwargs["require_open"])))
            return super().revalidate_successor_pull(**kwargs)

    remediation = MutatingRemediationRunner()
    correction = FeedbackEvent(
        repository="acme/widgets",
        pr_number=91,
        kind="review_comment",
        event_id="successor-46",
        author="native-reviewer",
        author_id=101,
        author_type="User",
        body="Use the final remediation wording.",
        head_sha=HEAD_SHA,
        base_sha=BASE_SHA,
        locale="ru",
        path=TARGET_PATH,
        html_url=("https://github.com/acme/widgets/pull/91#discussion_rsuccessor-46"),
    )
    replacement = ProposedReplacement(
        feedback_id=correction.feedback_id,
        path=TARGET_PATH,
        key="greeting",
        locale="ru",
        expected_value="candidate",
        proposed_value="final candidate",
        confidence=0.99,
        evidence=(correction.feedback_id,),
    )

    with GuardianState(tmp_path / "state.sqlite3") as state:
        draft_key, source = _record_open_remediation_draft(state)
        revision = state.record_feedback_event(correction, observed_at=NOW)
        no_change_revision = state.record_feedback_event(
            replace(
                correction,
                event_id="successor-46-no-change",
                body="No repository change is needed.",
                html_url=None,
            ),
            observed_at=NOW,
        )
        run_id = state.start_run(
            repository="acme/widgets",
            locale="ru",
            mode=GuardianMode.APPLY_OWNED_TRANSLATIONS,
            started_at=NOW,
        )
        prepared = state.record_remediation_successor_publication_event(
            run_id=run_id,
            repository="acme/widgets",
            pr_number=91,
            original_head_sha=HEAD_SHA,
            base_sha=BASE_SHA,
            commit_sha=COMMIT_SHA,
            event_revision_ids=(revision.revision_id,),
            open_source=OpenPullAuthorityReference(
                repository="acme/widgets",
                repository_id=42,
                pull_id=900,
                pr_number=91,
                authority_digest="1" * 64,
                head_sha=HEAD_SHA,
                base_sha=BASE_SHA,
                feedback_digest="2" * 64,
            ),
            phase="prepared",
            draft_key=draft_key,
            source_pulls=(source,),
            changed_paths=(TARGET_PATH,),
            edit_hashes=(remediation_edit_hash(replacement),),
            actor_id=correction.author_id,
            actor_type=correction.author_type,
            publication_actor_id=8,
            publication_actor_type="User",
            completion_actions=(
                (revision.revision_id, "completed", {"outcome": "applied"}),
                (
                    no_change_revision.revision_id,
                    "completed",
                    {"outcome": "no_eligible_change"},
                ),
            ),
            occurred_at=NOW,
        )
        assert state.acquire_lease(
            name="guardian:poll",
            owner="test-owner",
            ttl_seconds=60,
            now=NOW,
        )
        controller = GuardianController(
            config=_config(GuardianMode.APPLY_OWNED_TRANSLATIONS),
            state=state,
            snapshot_provider=FakeSnapshotProvider(()),
            checkout_factory=None,  # type: ignore[arg-type]
            codex_driver=FakeCodexDriver(),
            model_credential_provider=lambda: "scoped-model-key",
            write_broker_factory=lambda _policy: broker,
            remediation_runner=remediation,
            publish_credential_environment=lambda: {},
            now=lambda: NOW,
            publication_actor_preflight=lambda: None,
        )

        def require_refreshed_source(**_kwargs: object) -> None:
            assert authority_generation["value"] == 1 + sum(
                kind == "source" for kind, _requires_open in authority_order
            )
            assert authority_order[-1][0] == "remediation"
            authority_order.append(("source", authority_order[-1][1]))

        controller._require_exact_open_source_authority = (  # type: ignore[method-assign]
            require_refreshed_source
        )
        pushed_snapshot = _snapshot(
            pull=_pull(
                pull_id=900,
                number=91,
                html_url="https://github.com/acme/widgets/pull/91",
                head_sha=COMMIT_SHA,
            ),
            feedback=(),
        )

        controller._recover_publications(
            policy=_historical_policy(remediation=True),
            snapshots=(pushed_snapshot,),
            observed_at=NOW,
            lease_owner="test-owner",
        )

        successors = state.remediation_successor_publications(draft_key=draft_key)
        assert len(successors) == 1
        assert successors[0].publication_key == prepared.publication_key
        assert successors[0].successor_candidate_sha == COMMIT_SHA
        assert successors[0].changed_paths == (TARGET_PATH,)
        assert state.pending_publications() == ()
        actions = state._connection.execute(  # noqa: SLF001
            "SELECT details_json FROM actions WHERE run_id = ? "
            "ORDER BY event_revision_id",
            (run_id,),
        ).fetchall()
        assert [json.loads(row["details_json"]) for row in actions] == [
            {"outcome": "applied"},
            {"outcome": "no_eligible_change"},
        ]

    assert sequence == ["reply"]
    assert authority_order == [
        ("remediation", False),
        ("source", False),
        ("remediation", True),
        ("source", True),
    ]


@pytest.mark.parametrize("merged", (False, True), ids=("closed-unmerged", "merged"))
@pytest.mark.parametrize(
    "crash_after",
    (None, "lineage", "atomic_before_commit", "atomic_after_commit"),
    ids=("no-crash", "lineage-crash", "atomic-rollback", "atomic-committed"),
)
def test_recovers_successor_lineage_after_remediation_closes_without_reply(
    merged: bool,
    crash_after: str | None,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sequence: list[str] = []
    broker = FakeBroker(sequence)
    correction = FeedbackEvent(
        repository="acme/widgets",
        pr_number=91,
        kind="review_comment",
        event_id="closed-successor",
        author="native-reviewer",
        author_id=101,
        author_type="User",
        body="Use the final reviewed wording.",
        head_sha=HEAD_SHA,
        base_sha=BASE_SHA,
        locale="ru",
        path=TARGET_PATH,
    )
    replacement = ProposedReplacement(
        feedback_id=correction.feedback_id,
        path=TARGET_PATH,
        key="greeting",
        locale="ru",
        expected_value="candidate",
        proposed_value="final candidate",
        confidence=0.99,
        evidence=(correction.feedback_id,),
    )
    remediation = FakeRemediationRunner(
        successor_result=RemediationDraftResult(
            number=91,
            html_url="https://github.com/acme/widgets/pull/91",
            candidate_sha=COMMIT_SHA,
            created=False,
            state="closed",
            merged=merged,
            draft=False,
            base_sha=BASE_SHA,
            closed_at="2026-08-30T12:01:00Z",
            merged_at="2026-08-30T12:00:59Z" if merged else None,
        )
    )

    with GuardianState(tmp_path / "state.sqlite3") as state:
        draft_key, source = _record_open_remediation_draft(state)
        revision = state.record_feedback_event(correction, observed_at=NOW)
        no_change_revision = state.record_feedback_event(
            replace(
                correction,
                event_id="closed-successor-no-change",
                body="No repository change is needed.",
                html_url=None,
            ),
            observed_at=NOW,
        )
        run_id = state.start_run(
            repository="acme/widgets",
            locale="ru",
            mode=GuardianMode.APPLY_OWNED_TRANSLATIONS,
            started_at=NOW,
        )
        prepared = state.record_remediation_successor_publication_event(
            run_id=run_id,
            repository="acme/widgets",
            pr_number=91,
            original_head_sha=HEAD_SHA,
            base_sha=BASE_SHA,
            commit_sha=COMMIT_SHA,
            event_revision_ids=(revision.revision_id,),
            open_source=OpenPullAuthorityReference(
                repository="acme/widgets",
                repository_id=42,
                pull_id=900,
                pr_number=91,
                authority_digest="1" * 64,
                head_sha=HEAD_SHA,
                base_sha=BASE_SHA,
                feedback_digest="2" * 64,
            ),
            phase="prepared",
            draft_key=draft_key,
            source_pulls=(source,),
            edit_hashes=(remediation_edit_hash(replacement),),
            changed_paths=(TARGET_PATH,),
            actor_id=correction.author_id,
            actor_type=correction.author_type,
            publication_actor_id=8,
            publication_actor_type="User",
            completion_actions=(
                (
                    revision.revision_id,
                    "completed",
                    {
                        "changed_keys": 1,
                        "commit_sha": COMMIT_SHA,
                        "confidence": 0.99,
                        "outcome": "applied",
                        "recurrence_candidates": 0,
                        "verdict": "apply",
                    },
                ),
                (
                    no_change_revision.revision_id,
                    "completed",
                    {
                        "changed_keys": 0,
                        "commit_sha": None,
                        "confidence": 0.99,
                        "outcome": "no_eligible_change",
                        "recurrence_candidates": 0,
                        "verdict": "no_change",
                    },
                ),
            ),
            occurred_at=NOW,
        )
        assert state.acquire_lease(
            name="guardian:poll",
            owner="test-owner",
            ttl_seconds=60,
            now=NOW,
        )
        controller = GuardianController(
            config=_config(GuardianMode.APPLY_OWNED_TRANSLATIONS),
            state=state,
            snapshot_provider=FakeSnapshotProvider(()),
            checkout_factory=None,  # type: ignore[arg-type]
            codex_driver=FakeCodexDriver(),
            write_broker_factory=lambda _policy: broker,
            remediation_runner=remediation,
            publish_credential_environment=lambda: {},
            now=lambda: NOW,
            publication_actor_preflight=lambda: None,
        )

        original_method = None
        crash_method = None
        if crash_after is not None:
            if crash_after == "lineage":
                crash_method = "record_remediation_successor_publication_event"
            elif crash_after == "atomic_before_commit":
                crash_method = "_record_publication_reply_terminal_in_transaction"
            else:
                crash_method = "finalize_publication_reply_terminal"
            original_method = getattr(state, crash_method)

            def commit_then_crash(*args, **kwargs):
                original_method(*args, **kwargs)
                raise RuntimeError(f"crash after {crash_after}")

            monkeypatch.setattr(state, crash_method, commit_then_crash)
            with pytest.raises(RuntimeError, match=f"crash after {crash_after}"):
                controller._recover_publications(
                    policy=_historical_policy(remediation=True),
                    snapshots=(),
                    observed_at=NOW,
                    lease_owner="test-owner",
                )
            monkeypatch.setattr(state, crash_method, original_method)

        controller._recover_publications(
            policy=_historical_policy(remediation=True),
            snapshots=(),
            observed_at=NOW,
            lease_owner="test-owner",
        )

        successors = state.remediation_successor_publications(draft_key=draft_key)
        assert len(successors) == 1
        assert successors[0].publication_key == prepared.publication_key
        assert successors[0].successor_candidate_sha == COMMIT_SHA
        assert successors[0].changed_paths == (TARGET_PATH,)
        assert state.remediation_candidate_tip(draft_key) == COMMIT_SHA
        assert state.pending_publications() == ()
        assert state.publication_reply_terminal_reason(prepared.publication_key) == (
            "remediation_merged" if merged else "remediation_closed_unmerged"
        )
        publication_phases = state._connection.execute(  # noqa: SLF001
            "SELECT phase FROM publication_events WHERE publication_key = ? "
            "ORDER BY publication_event_id",
            (prepared.publication_key,),
        ).fetchall()
        assert [row["phase"] for row in publication_phases] == [
            "prepared",
            "published",
        ]
        assert state.get_run(run_id).status == "completed"
        actions = state._connection.execute(  # noqa: SLF001
            "SELECT status, details_json FROM actions WHERE run_id = ? "
            "ORDER BY event_revision_id",
            (run_id,),
        ).fetchall()
        assert [
            (row["status"], json.loads(row["details_json"])) for row in actions
        ] == [
            (
                "completed",
                {
                    "changed_keys": 1,
                    "commit_sha": COMMIT_SHA,
                    "confidence": 0.99,
                    "outcome": "applied",
                    "recurrence_candidates": 0,
                    "verdict": "apply",
                },
            ),
            (
                "completed",
                {
                    "changed_keys": 0,
                    "commit_sha": None,
                    "confidence": 0.99,
                    "outcome": "no_eligible_change",
                    "recurrence_candidates": 0,
                    "verdict": "no_change",
                },
            ),
        ]

        # The terminal row is the restart boundary. A later recovery must not
        # rehydrate or contact the already-closed pull, nor duplicate local
        # completion evidence.
        controller._recover_publications(
            policy=_historical_policy(remediation=True),
            snapshots=(),
            observed_at=NOW + timedelta(minutes=1),
            lease_owner="test-owner",
        )
        repeated_actions = state._connection.execute(  # noqa: SLF001
            "SELECT status, details_json FROM actions WHERE run_id = ?",
            (run_id,),
        ).fetchall()
        assert [tuple(row) for row in repeated_actions] == [
            tuple(row) for row in actions
        ]

    assert broker.reply_calls == []
    assert sequence == []
    expected_revalidations = 1 if crash_after in {None, "atomic_after_commit"} else 2
    assert len(remediation.successor_calls) == expected_revalidations
    assert remediation.successor_calls[0]["require_open"] is False


def test_refuses_to_infer_actor_or_lineage_for_a_legacy_prepared_push(
    tmp_path: Path,
) -> None:
    """Legacy records must not gain inferred publication or successor authority."""
    sequence: list[str] = []
    broker = FakeBroker(sequence)
    database = tmp_path / "state.sqlite3"
    correction = FeedbackEvent(
        repository="acme/widgets",
        pr_number=91,
        kind="review_comment",
        event_id="legacy-successor",
        author="native-reviewer",
        author_id=101,
        author_type="User",
        body="A correction whose lineage was not prepared.",
        head_sha=HEAD_SHA,
        base_sha=BASE_SHA,
        locale="ru",
        path=TARGET_PATH,
        html_url=(
            "https://github.com/acme/widgets/pull/91#discussion_rlegacy-successor"
        ),
    )

    with GuardianState(database) as state:
        draft_key, _source = _record_open_remediation_draft(state)
        revision = state.record_feedback_event(correction, observed_at=NOW)
        run_id = state.start_run(
            repository="acme/widgets",
            locale="ru",
            mode=GuardianMode.APPLY_OWNED_TRANSLATIONS,
            started_at=NOW,
        )
    publication_key = _insert_legacy_publication(
        database,
        run_id=run_id,
        repository="acme/widgets",
        pr_number=91,
        original_head_sha=HEAD_SHA,
        base_sha=BASE_SHA,
        commit_sha=COMMIT_SHA,
        event_revision_ids=(revision.revision_id,),
        occurred_at=NOW,
    )

    with GuardianState(database) as state:
        assert (
            state._connection.execute(  # noqa: SLF001
                "PRAGMA user_version"
            ).fetchone()[0]
            == 10
        )
        installed_triggers = {
            row["name"]
            for row in state._connection.execute(  # noqa: SLF001
                "SELECT name FROM sqlite_master WHERE type = 'trigger'"
            )
        }
        assert "publication_events_actor_safe" in installed_triggers
        row = state._connection.execute(  # noqa: SLF001
            "SELECT * FROM publication_events WHERE publication_key = ?",
            (publication_key,),
        ).fetchone()
        publication = state._publication_from_row(row)  # noqa: SLF001
        assert publication.publication_actor_id is None
        assert publication.publication_actor_type is None
        assert state.acquire_lease(
            name="guardian:poll",
            owner="test-owner",
            ttl_seconds=60,
            now=NOW,
        )
        controller = GuardianController(
            config=_config(GuardianMode.APPLY_OWNED_TRANSLATIONS),
            state=state,
            snapshot_provider=FakeSnapshotProvider(()),
            checkout_factory=None,  # type: ignore[arg-type]
            codex_driver=FakeCodexDriver(),
            model_credential_provider=lambda: "scoped-model-key",
            write_broker_factory=lambda _policy: broker,
            publish_credential_environment=lambda: {},
            now=lambda: NOW,
            publication_actor_preflight=lambda: None,
        )
        pushed_snapshot = _snapshot(
            pull=_pull(
                pull_id=900,
                number=91,
                html_url="https://github.com/acme/widgets/pull/91",
                head_sha=COMMIT_SHA,
            ),
            feedback=(),
        )

        with pytest.raises(
            guardian_controller._PublicationRecoveryManualRequired,
            match="publication authority is unavailable or malformed",
        ):
            controller._recover_publications(
                policy=_policy(),
                snapshots=(pushed_snapshot,),
                observed_at=NOW,
                lease_owner="test-owner",
            )

        with pytest.raises(RuntimeError, match="durable publication-actor"):
            state.pending_publications()
        assert state.remediation_candidate_tip(draft_key) == HEAD_SHA

    assert broker.reply_calls == []
    assert sequence == []


def test_refuses_to_infer_actor_or_open_authority_for_a_legacy_publication(
    tmp_path: Path,
) -> None:
    """Fail closed when a legacy publication lacks durable actor and PR evidence."""
    sequence: list[str] = []
    broker = FakeBroker(sequence)
    database = tmp_path / "state.sqlite3"
    with GuardianState(database) as state:
        revision = state.record_feedback_event(
            FeedbackEvent(
                repository="acme/widgets",
                pr_number=12,
                kind="review_comment",
                event_id="legacy-44",
                author="native-reviewer",
                author_id=101,
                author_type="User",
                body="Use the reviewed wording.",
                head_sha=HEAD_SHA,
                base_sha=BASE_SHA,
                locale="ru",
                path=TARGET_PATH,
            ),
            observed_at=NOW,
        )
        run_id = state.start_run(
            repository="acme/widgets",
            locale="ru",
            mode=GuardianMode.APPLY_OWNED_TRANSLATIONS,
            started_at=NOW,
        )
    publication_key = _insert_legacy_publication(
        database,
        run_id=run_id,
        repository="acme/widgets",
        pr_number=12,
        original_head_sha=HEAD_SHA,
        base_sha=BASE_SHA,
        commit_sha=COMMIT_SHA,
        event_revision_ids=(revision.revision_id,),
        occurred_at=NOW,
    )

    with GuardianState(database) as state:
        assert (
            state._connection.execute(  # noqa: SLF001
                "PRAGMA user_version"
            ).fetchone()[0]
            == 10
        )
        installed_triggers = {
            row["name"]
            for row in state._connection.execute(  # noqa: SLF001
                "SELECT name FROM sqlite_master WHERE type = 'trigger'"
            )
        }
        assert "publication_events_actor_safe" in installed_triggers
        row = state._connection.execute(  # noqa: SLF001
            "SELECT * FROM publication_events WHERE publication_key = ?",
            (publication_key,),
        ).fetchone()
        publication = state._publication_from_row(row)  # noqa: SLF001
        assert publication.publication_actor_id is None
        assert publication.publication_actor_type is None
        assert publication.open_source is None
        assert state.acquire_lease(
            name="guardian:poll",
            owner="test-owner",
            ttl_seconds=60,
            now=NOW,
        )
        controller = GuardianController(
            config=_config(GuardianMode.APPLY_OWNED_TRANSLATIONS),
            state=state,
            snapshot_provider=FakeSnapshotProvider(()),
            checkout_factory=None,  # type: ignore[arg-type]
            codex_driver=FakeCodexDriver(),
            write_broker_factory=lambda _policy: broker,
            publish_credential_environment=lambda: {},
            now=lambda: NOW,
            publication_actor_preflight=lambda: None,
        )

        with pytest.raises(
            guardian_controller._PublicationRecoveryManualRequired,
            match="publication authority is unavailable or malformed",
        ):
            controller._recover_publications(
                policy=_policy(),
                snapshots=(_snapshot(pull=_pull(head_sha=COMMIT_SHA)),),
                observed_at=NOW,
                lease_owner="test-owner",
            )

        with pytest.raises(RuntimeError, match="durable publication-actor"):
            state.pending_publications()
        assert broker.reply_calls == []
        assert sequence == []


def test_propose_prevention_authentication_failure_opens_poll_circuit(
    tmp_path: Path, runtime
) -> None:
    _base, _head, checkout, provider, broker, sequence = runtime
    prevention = FakePreventionRunner(
        error=CodexAuthenticationError("secret model detail"),
        sequence=sequence,
    )
    policy = replace(_policy(), prevention=_prevention_policy())
    with GuardianState(tmp_path / "state.sqlite3") as state:
        outcome = _controller(
            tmp_path=tmp_path,
            state=state,
            config=_config(GuardianMode.PROPOSE_PREVENTION, policies=(policy,)),
            checkout=checkout,
            provider=provider,
            driver=RecurrenceCodexDriver(),
            broker=broker,
            prevention_runner=prevention,
        ).poll_once()

        assert outcome.authentication_circuit_open is True
        assert outcome.runs_failed == 1
        assert outcome.applied_commits == ()
        assert sequence == ["prevention"]
        assert state.pending_event_revisions(mode=GuardianMode.PROPOSE_PREVENTION)


def test_apply_then_propose_assesses_recurrence_without_reapplying_translation(
    tmp_path: Path, runtime
) -> None:
    _base, _head, checkout, provider, broker, sequence = runtime
    policy = replace(_policy(), prevention=_prevention_policy())
    prevention = FakePreventionRunner(sequence=sequence)
    with GuardianState(tmp_path / "state.sqlite3") as state:
        applied = _controller(
            tmp_path=tmp_path,
            state=state,
            config=_config(GuardianMode.APPLY_OWNED_TRANSLATIONS, policies=(policy,)),
            checkout=checkout,
            provider=provider,
            driver=FakeCodexDriver(),
            broker=broker,
        ).poll_once()
        assert applied.applied_commits == (COMMIT_SHA,)

        sequence.clear()
        provider.snapshots = (_snapshot(pull=_pull(head_sha=COMMIT_SHA)),)
        recurrence_driver = RecurrenceCodexDriver()
        proposed = _controller(
            tmp_path=tmp_path,
            state=state,
            config=_config(GuardianMode.PROPOSE_PREVENTION, policies=(policy,)),
            checkout=checkout,
            provider=provider,
            driver=recurrence_driver,
            broker=broker,
            prevention_runner=prevention,
        ).poll_once()

        assert proposed.runs_completed == 1
        assert proposed.applied_commits == ()
        assert len(recurrence_driver.calls) == 1
        assert len(prevention.propose_calls) == 1
        assert sequence == ["prevention"]
        assert state.pending_event_revisions(mode=GuardianMode.PROPOSE_PREVENTION) == ()


def test_github_authentication_failure_stops_later_repositories(
    tmp_path: Path, runtime
) -> None:
    _base, _head, checkout, _provider, broker, _sequence = runtime
    calls: list[str] = []

    def failing_provider(policy, _previous):
        calls.append(policy.base_repo)
        raise GitHubAuthenticationError("redacted auth failure")

    policies = (_policy(repository="acme/first"), _policy(repository="acme/second"))
    with GuardianState(tmp_path / "state.sqlite3") as state:
        outcome = _controller(
            tmp_path=tmp_path,
            state=state,
            config=_config(GuardianMode.OBSERVE, policies=policies),
            checkout=checkout,
            provider=failing_provider,  # type: ignore[arg-type]
            driver=FakeCodexDriver(),
            broker=broker,
        ).poll_once()

    assert outcome.authentication_circuit_open is True
    assert calls == ["acme/first"]
    assert outcome.repositories_polled == 0


def test_publication_actor_preflight_blocks_every_remote_write(
    tmp_path: Path,
    runtime,
) -> None:
    base, head, checkout, provider, broker, _sequence = runtime
    policy = _historical_policy(remediation=True)
    remediation = FakeRemediationRunner()

    def fail_actor() -> None:
        raise GitHubAuthenticationError("wrong credential actor")

    with GuardianState(tmp_path / "state.sqlite3") as state:
        outcome = _controller(
            tmp_path=tmp_path,
            state=state,
            config=_config(
                GuardianMode.APPLY_OWNED_TRANSLATIONS,
                policies=(policy,),
                limits=GuardianLimits(max_remediation_drafts_per_run=1),
            ),
            checkout=checkout,
            provider=provider,
            driver=FakeCodexDriver(),
            broker=broker,
            historical_snapshot_provider=FakeHistoricalSnapshotProvider(
                (_snapshot(pull=_pull(state="closed")),)
            ),
            historical_checkout_factory=FakeHistoricalCheckoutFactory(
                base,
                head,
                tmp_path,
            ),
            current_base_provider=FakeCurrentBaseProvider(),
            remediation_runner=remediation,
            publication_actor_preflight=fail_actor,
        ).poll_once()

    assert outcome.authentication_circuit_open is True
    assert outcome.repositories_polled == 0
    assert provider.calls == []
    assert broker.verify_calls == []
    assert broker.reply_calls == []
    assert remediation.begin_calls == 0
    assert remediation.recover_calls == []
    assert remediation.publish_calls == []


def test_publication_actor_preflight_blocks_prevention_orphan_recovery(
    tmp_path: Path,
    runtime,
) -> None:
    _base, _head, checkout, provider, broker, _sequence = runtime
    policy = replace(_policy(), prevention=_prevention_policy())
    prevention = FakePreventionRunner()

    def fail_actor() -> None:
        raise GitHubAuthenticationError("wrong credential actor")

    with GuardianState(tmp_path / "state.sqlite3") as state:
        outcome = _controller(
            tmp_path=tmp_path,
            state=state,
            config=_config(GuardianMode.PROPOSE_PREVENTION, policies=(policy,)),
            checkout=checkout,
            provider=provider,
            driver=FakeCodexDriver(),
            broker=broker,
            prevention_runner=prevention,
            publication_actor_preflight=fail_actor,
        ).poll_once()

    assert outcome.authentication_circuit_open is True
    assert outcome.repositories_polled == 0
    assert provider.calls == []
    assert broker.verify_calls == []
    assert broker.reply_calls == []
    assert prevention.begin_calls == 0
    assert prevention.recover_orphan_calls == []
    assert prevention.recover_calls == []
    assert prevention.propose_calls == []


def test_incomplete_prevention_candidate_leaves_feedback_retryable(
    tmp_path: Path, runtime
) -> None:
    _base, _head, checkout, provider, broker, sequence = runtime
    prevention = FakePreventionRunner(
        result=PreventionBatchOutcome(
            deferred=1,
            failures=("PreventionPolicyError",),
        ),
        sequence=sequence,
    )
    policy = replace(_policy(), prevention=_prevention_policy())
    with GuardianState(tmp_path / "state.sqlite3") as state:
        outcome = _controller(
            tmp_path=tmp_path,
            state=state,
            config=_config(GuardianMode.PROPOSE_PREVENTION, policies=(policy,)),
            checkout=checkout,
            provider=provider,
            driver=RecurrenceCodexDriver(),
            broker=broker,
            prevention_runner=prevention,
        ).poll_once()

        assert outcome.runs_failed == 1
        assert outcome.prevention_items_deferred == 1
        assert outcome.prevention_failures == ("PreventionPolicyError",)
        assert outcome.failures == ("PreventionRuntimeError",)
        assert sequence == ["prevention"]
        assert state.pending_event_revisions(mode=GuardianMode.PROPOSE_PREVENTION)


def test_propose_prevention_recovers_without_new_feedback(
    tmp_path: Path, runtime
) -> None:
    _base, _head, checkout, _provider, broker, _sequence = runtime
    provider = FakeSnapshotProvider(())
    recovered = PreventionDraftResult(
        number=92,
        html_url="https://github.com/guardian/pipeline/pull/92",
        candidate_sha="f" * 40,
        created=True,
    )
    prevention = FakePreventionRunner()
    prevention.recover = lambda **_kwargs: PreventionBatchOutcome(  # type: ignore[method-assign]
        drafts=(recovered,)
    )
    policy = replace(_policy(), prevention=_prevention_policy())
    with GuardianState(tmp_path / "state.sqlite3") as state:
        outcome = _controller(
            tmp_path=tmp_path,
            state=state,
            config=_config(GuardianMode.PROPOSE_PREVENTION, policies=(policy,)),
            checkout=checkout,
            provider=provider,
            driver=RecurrenceCodexDriver(),
            broker=broker,
            prevention_runner=prevention,
        ).poll_once()

    assert outcome.prevention_drafts_created == 1
    assert outcome.runs_started == 0
    assert prevention.begin_calls == 1
    assert len(prevention.recover_orphan_calls) == 1


def test_propose_prevention_recovers_orphans_once_before_repository_work(
    tmp_path: Path, runtime
) -> None:
    _base, _head, checkout, _provider, broker, _sequence = runtime
    policies = (
        replace(_policy(), prevention=_prevention_policy()),
        replace(
            _policy(),
            base_repo="acme/other-widgets",
            base_repo_id=43,
            prevention=_prevention_policy(),
        ),
    )
    orphan = PreventionDraftResult(
        number=93,
        html_url="https://github.com/guardian/pipeline/pull/93",
        candidate_sha="a" * 40,
        created=False,
    )
    prevention = FakePreventionRunner(
        orphan_result=PreventionBatchOutcome(
            drafts=(orphan,),
            failures=("PreventionPolicyChanged",),
        )
    )
    provider = FakeSnapshotProvider(())
    with GuardianState(tmp_path / "state.sqlite3") as state:
        outcome = _controller(
            tmp_path=tmp_path,
            state=state,
            config=_config(GuardianMode.PROPOSE_PREVENTION, policies=policies),
            checkout=checkout,
            provider=provider,
            driver=RecurrenceCodexDriver(),
            broker=broker,
            prevention_runner=prevention,
        ).poll_once()

    assert prevention.begin_calls == 1
    assert len(prevention.recover_orphan_calls) == 1
    assert prevention.recover_orphan_calls[0]["configured_policies"] == policies
    assert len(prevention.recover_calls) == 2
    assert outcome.prevention_drafts_created == 0
    assert outcome.prevention_failures == ("PreventionPolicyChanged",)


def test_orphan_prevention_lease_loss_stops_all_repository_work(
    tmp_path: Path, runtime
) -> None:
    _base, _head, checkout, _provider, broker, _sequence = runtime
    policy = replace(_policy(), prevention=_prevention_policy())
    prevention = FakePreventionRunner(
        orphan_error=PreventionLeaseLostError("stale worker")
    )
    provider = FakeSnapshotProvider(())
    with GuardianState(tmp_path / "state.sqlite3") as state:
        outcome = _controller(
            tmp_path=tmp_path,
            state=state,
            config=_config(GuardianMode.PROPOSE_PREVENTION, policies=(policy,)),
            checkout=checkout,
            provider=provider,
            driver=RecurrenceCodexDriver(),
            broker=broker,
            prevention_runner=prevention,
        ).poll_once()

    assert outcome.failures == ("LeaseLost",)
    assert provider.calls == []
    assert prevention.recover_calls == []


def test_observe_uses_exact_base_config_and_is_revision_idempotent(
    tmp_path: Path, runtime
) -> None:
    _base, _head, checkout, provider, broker, sequence = runtime
    driver = FakeCodexDriver()
    with GuardianState(tmp_path / "state.sqlite3") as state:
        controller = _controller(
            tmp_path=tmp_path,
            state=state,
            config=_config(GuardianMode.OBSERVE),
            checkout=checkout,
            provider=provider,
            driver=driver,
            broker=broker,
        )

        first = controller.poll_once()
        second = controller.poll_once()

        assert first.runs_completed == 1
        assert second.runs_started == 0
        assert len(driver.calls) == 1
        assert driver.api_keys == ["scoped-model-key"]
        assert broker.verify_calls == []
        assert sequence == []
        assert state.budget_committed_for_day(NOW.date()) == pytest.approx(0.25)
        assert provider.calls[1][1][0].body == "Use the idiomatic wording."


def test_chatgpt_subscription_ignores_api_helper_and_records_call_not_cost(
    tmp_path: Path,
    runtime,
) -> None:
    _base, _head, checkout, provider, broker, _sequence = runtime
    driver = FakeCodexDriver()
    config = GuardianConfig(
        repositories=(_policy(),),
        mode=GuardianMode.OBSERVE,
        limits=GuardianLimits(max_model_calls_per_day=2),
        runtime=GuardianRuntime(codex_auth_mode=CodexAuthMode.CHATGPT),
    )
    with GuardianState(tmp_path / "state.sqlite3") as state:
        controller = _controller(
            tmp_path=tmp_path,
            state=state,
            config=config,
            checkout=checkout,
            provider=provider,
            driver=driver,
            broker=broker,
        )

        def forbidden_helper() -> str:
            raise AssertionError("subscription mode must not read an API key")

        controller.model_credential_provider = forbidden_helper
        outcome = controller.poll_once()

        assert outcome.runs_completed == 1
        assert driver.api_keys == [None]
        assert state.model_calls_committed_for_day(NOW.date()) == 1
        assert state.cost_for_day(NOW.date()) == 0


def test_subscription_daily_call_limit_stops_before_model_invocation(
    tmp_path: Path,
    runtime,
) -> None:
    _base, _head, checkout, provider, broker, _sequence = runtime
    driver = FakeCodexDriver()
    config = GuardianConfig(
        repositories=(_policy(),),
        mode=GuardianMode.OBSERVE,
        limits=GuardianLimits(max_model_calls_per_day=1),
        runtime=GuardianRuntime(codex_auth_mode=CodexAuthMode.CHATGPT),
    )
    with GuardianState(tmp_path / "state.sqlite3") as state:
        prior_run = state.start_run(
            repository="acme/widgets",
            locale="ru",
            mode=GuardianMode.OBSERVE,
            started_at=NOW,
        )
        assert (
            state.try_reserve_model_call(
                run_id=prior_run,
                daily_limit=1,
                model="test-model",
                purpose="assessment",
                reserved_at=NOW,
            )
            is not None
        )

        outcome = _controller(
            tmp_path=tmp_path,
            state=state,
            config=config,
            checkout=checkout,
            provider=provider,
            driver=driver,
            broker=broker,
        ).poll_once()

        assert outcome.runs_failed == 1
        assert driver.calls == []
        assert state.pending_event_revisions()


def test_each_codex_retry_has_an_independent_budget_reservation_and_cost(
    tmp_path: Path, runtime
) -> None:
    _base, _head, checkout, provider, broker, _sequence = runtime
    with GuardianState(tmp_path / "state.sqlite3") as state:
        outcome = _controller(
            tmp_path=tmp_path,
            state=state,
            config=_config(GuardianMode.OBSERVE),
            checkout=checkout,
            provider=provider,
            driver=RetryingCodexDriver(),
            broker=broker,
        ).poll_once()

        assert outcome.runs_completed == 1
        assert outcome.failures == ()
        assert state.budget_committed_for_day(NOW.date()) == Decimal("0.35")
        with state._connection:  # Exact audit contract, not a public query surface.
            reservations = state._connection.execute(
                "SELECT status FROM budget_reservations ORDER BY reservation_id"
            ).fetchall()
        assert [row["status"] for row in reservations] == ["settled", "settled"]


def test_poll_lease_outlives_one_configured_operation_timeout(
    tmp_path: Path, runtime
) -> None:
    _base, _head, checkout, _provider, broker, _sequence = runtime
    state_path = tmp_path / "state.sqlite3"
    timeout_seconds = 10
    provider = LeaseProbeSnapshotProvider(
        (_snapshot(),),
        state_path=state_path,
        probe_at=NOW + timedelta(seconds=timeout_seconds + 1),
    )
    limits = GuardianLimits(
        run_timeout_seconds=timeout_seconds,
        daily_cost_limit_usd=2,
        model_call_reservation_usd=1,
    )
    with GuardianState(state_path) as state:
        outcome = _controller(
            tmp_path=tmp_path,
            state=state,
            config=_config(GuardianMode.OBSERVE, limits=limits),
            checkout=checkout,
            provider=provider,
            driver=FakeCodexDriver(),
            broker=broker,
        ).poll_once()

        assert provider.rival_acquired is False
        assert outcome.runs_completed == 1
        assert outcome.failures == ()


def test_poll_deadline_stops_later_repositories_and_releases_lease(
    tmp_path: Path,
    runtime,
) -> None:
    _base, _head, checkout, _provider, broker, _sequence = runtime
    now = [10.0]
    calls: list[str] = []

    class ExpiringProvider(FakeSnapshotProvider):
        def __call__(self, policy, previous_feedback):
            del previous_feedback
            calls.append(policy.base_repo)
            now[0] = 13.0
            return ()

    second_policy = replace(
        _policy(repository="acme/gadgets"),
        base_repo_id=43,
    )
    state_path = tmp_path / "state.sqlite3"
    with GuardianState(state_path) as state:
        outcome = _controller(
            tmp_path=tmp_path,
            state=state,
            config=_config(
                GuardianMode.OBSERVE,
                policies=(_policy(), second_policy),
            ),
            checkout=checkout,
            provider=ExpiringProvider(()),
            driver=FakeCodexDriver(),
            broker=broker,
            deadline=PollDeadline(3, clock=lambda: now[0]),
        ).poll_once()

        assert calls == ["acme/widgets"]
        assert outcome.failures == ("PollDeadlineExceeded",)
        assert state.latest_health("guardian").status == "failed"
        assert state.acquire_lease(
            name="guardian:poll",
            owner="rival",
            ttl_seconds=30,
            now=NOW,
        )


def test_poll_deadline_in_preflight_is_a_bounded_failure_and_releases_lease(
    tmp_path: Path,
    runtime,
) -> None:
    _base, _head, checkout, provider, broker, _sequence = runtime
    now = [10.0]
    deadline = PollDeadline(3, clock=lambda: now[0])

    def expire_during_preflight() -> None:
        now[0] = 13.0
        deadline.require_remaining()

    state_path = tmp_path / "state.sqlite3"
    with GuardianState(state_path) as state:
        outcome = _controller(
            tmp_path=tmp_path,
            state=state,
            config=_config(GuardianMode.OBSERVE),
            checkout=checkout,
            provider=provider,
            driver=FakeCodexDriver(),
            broker=broker,
            publication_actor_preflight=expire_during_preflight,
            deadline=deadline,
        ).poll_once()

        assert outcome.repositories_polled == 0
        assert outcome.failures == ("PollDeadlineExceeded",)
        assert state.latest_health("guardian").status == "failed"
        assert state.acquire_lease(
            name="guardian:poll",
            owner="rival",
            ttl_seconds=30,
            now=NOW,
        )


def test_last_repository_deadline_skips_the_historical_phase(
    tmp_path: Path,
    runtime,
) -> None:
    base, head, checkout, _provider, broker, _sequence = runtime
    now = [10.0]
    calls: list[str] = []

    class ExpiringSecondProvider(FakeSnapshotProvider):
        def __call__(self, policy, previous_feedback):
            del previous_feedback
            calls.append(policy.base_repo)
            if policy.base_repo == "acme/gadgets":
                now[0] = 13.0
            return ()

    second_policy = replace(
        _policy(repository="acme/gadgets"),
        base_repo_id=43,
    )
    historical_provider = FakeHistoricalSnapshotProvider(())
    current_provider = FakeCurrentBaseProvider()
    with GuardianState(tmp_path / "state.sqlite3") as state:
        outcome = _controller(
            tmp_path=tmp_path,
            state=state,
            config=_config(
                GuardianMode.OBSERVE,
                policies=(_historical_policy(), second_policy),
            ),
            checkout=checkout,
            provider=ExpiringSecondProvider(()),
            driver=FakeCodexDriver(),
            broker=broker,
            historical_snapshot_provider=historical_provider,
            historical_checkout_factory=FakeHistoricalCheckoutFactory(
                base,
                head,
                tmp_path,
            ),
            current_base_provider=current_provider,
            deadline=PollDeadline(3, clock=lambda: now[0]),
        ).poll_once()

    assert calls == ["acme/widgets", "acme/gadgets"]
    assert outcome.failures == ("PollDeadlineExceeded",)
    assert historical_provider.calls == []
    assert current_provider.calls == []


def test_edited_feedback_is_a_new_revision_and_reassessed(
    tmp_path: Path, runtime
) -> None:
    _base, _head, checkout, provider, broker, _sequence = runtime
    driver = FakeCodexDriver()
    with GuardianState(tmp_path / "state.sqlite3") as state:
        controller = _controller(
            tmp_path=tmp_path,
            state=state,
            config=_config(GuardianMode.OBSERVE),
            checkout=checkout,
            provider=provider,
            driver=driver,
            broker=broker,
        )
        controller.poll_once()
        provider.snapshots = (
            _snapshot(
                feedback=(
                    _feedback(
                        body="Use the revised idiomatic wording.",
                        updated_at="2026-08-30T11:00:00Z",
                    ),
                ),
            ),
        )

        outcome = controller.poll_once()

        assert outcome.runs_completed == 1
        assert len(driver.calls) == 2
        assert len(state.latest_event_revisions(repository="acme/widgets")) == 1


def test_mode_escalation_reuses_the_exact_cached_assessment(
    tmp_path: Path, runtime
) -> None:
    _base, _head, checkout, provider, broker, _sequence = runtime
    driver = FakeCodexDriver()
    with GuardianState(tmp_path / "state.sqlite3") as state:
        outcome = _controller(
            tmp_path=tmp_path,
            state=state,
            config=_config(GuardianMode.OBSERVE),
            checkout=checkout,
            provider=provider,
            driver=driver,
            broker=broker,
        ).poll_once()

        outcome = _controller(
            tmp_path=tmp_path,
            state=state,
            config=_config(GuardianMode.PREPARE),
            checkout=checkout,
            provider=provider,
            driver=driver,
            broker=broker,
        ).poll_once()

        assert outcome.prepared_value_edits == 1
        assert len(driver.calls) == 1
        assert state.pending_event_revisions(mode=GuardianMode.PREPARE) == ()


def test_changed_edit_limit_retries_policy_rejection_without_rebilling(
    tmp_path: Path, runtime
) -> None:
    """Reuse a paid assessment when changed policy permits a previously rejected patch."""
    _base, _head, checkout, provider, broker, _sequence = runtime
    driver = FakeCodexDriver()
    config = _config(GuardianMode.APPLY_OWNED_TRANSLATIONS)
    limited = replace(config, limits=replace(config.limits, max_value_edits_per_run=0))
    with GuardianState(tmp_path / "state.sqlite3") as state:

        def poll(settings):
            """Run the same retained evidence under a supplied policy configuration."""
            return _controller(
                tmp_path=tmp_path,
                state=state,
                config=settings,
                checkout=checkout,
                provider=provider,
                driver=driver,
                broker=broker,
            ).poll_once()

        assert poll(limited).applied_commits == ()
        assert poll(limited).runs_started == 0
        assert poll(config).applied_commits == (COMMIT_SHA,)
        assert len(driver.calls) == 1


@pytest.mark.parametrize("changed_file", ["config.yaml", "glossary.json"])
def test_base_bundle_change_reconsiders_deterministic_patch_rejection(
    tmp_path: Path, runtime, changed_file: str,
) -> None:
    """Bind rejected work to the actual trusted base config and glossary bytes."""
    base, _head, checkout, provider, broker, _sequence = runtime
    driver = FakeCodexDriver()
    calls = []

    def reject_first(**kwargs):
        """Simulate a deterministic constraint that a config change corrects."""
        calls.append(kwargs)
        if len(calls) == 1:
            raise guardian_controller.PatchPolicyError("test policy rejection")
        return apply_replacements(**kwargs)

    with GuardianState(tmp_path / "state.sqlite3") as state:
        def poll():
            """Reuse the durable rejection ledger across policy snapshots."""
            controller = _controller(
                tmp_path=tmp_path, state=state,
                config=_config(GuardianMode.APPLY_OWNED_TRANSLATIONS),
                checkout=checkout, provider=provider, driver=driver, broker=broker,
                replacement_applier=reject_first,
            )
            return controller.poll_once()

        assert poll().applied_commits == ()
        assert poll().applied_commits == ()
        assert len(calls) == 1
        target = base / ".localize" / changed_file
        target.write_text(target.read_text(encoding="utf-8") + "\n", encoding="utf-8")
        assert poll().applied_commits == (COMMIT_SHA,)
        assert len(calls) == 2


def test_crash_after_model_success_reuses_durable_result_without_rebilling(
    tmp_path: Path,
    runtime,
) -> None:
    _base, _head, checkout, provider, broker, _sequence = runtime
    driver = FakeCodexDriver()
    with GuardianState(tmp_path / "state.sqlite3") as state:
        first = _controller(
            tmp_path=tmp_path,
            state=state,
            config=_config(GuardianMode.OBSERVE),
            checkout=checkout,
            provider=provider,
            driver=driver,
            broker=broker,
        )

        def crash_after_persistence(*_args, **_kwargs):
            raise RuntimeError("simulated post-model crash")

        first.assessment_converter = crash_after_persistence
        failed = first.poll_once()

        assert failed.runs_failed == 1
        assert len(driver.calls) == 1
        assert state.cost_for_day(NOW.date()) == Decimal("0.25")
        assert state.pending_event_revisions(mode=GuardianMode.OBSERVE)

        recovered = _controller(
            tmp_path=tmp_path,
            state=state,
            config=_config(GuardianMode.OBSERVE),
            checkout=checkout,
            provider=provider,
            driver=driver,
            broker=broker,
        ).poll_once()

        assert recovered.runs_completed == 1
        assert len(driver.calls) == 1
        assert driver.api_keys == ["scoped-model-key"]
        assert state.cost_for_day(NOW.date()) == Decimal("0.25")
        assert state.pending_event_revisions(mode=GuardianMode.OBSERVE) == ()


def test_new_edit_supersedes_retryable_old_revision_before_assessment(
    tmp_path: Path, runtime
) -> None:
    _base, _head, checkout, provider, broker, _sequence = runtime
    driver = FakeCodexDriver()
    no_budget = GuardianLimits(
        daily_cost_limit_usd=1,
        model_call_reservation_usd=1,
    )
    with GuardianState(tmp_path / "state.sqlite3") as state:
        _consume_test_budget(state)
        _controller(
            tmp_path=tmp_path,
            state=state,
            config=_config(GuardianMode.OBSERVE, limits=no_budget),
            checkout=checkout,
            provider=provider,
            driver=driver,
            broker=broker,
        ).poll_once()
        provider.snapshots = (
            _snapshot(
                feedback=(
                    _feedback(
                        body="Use the newly edited wording.",
                        updated_at="2026-08-30T11:30:00Z",
                    ),
                )
            ),
        )

        outcome = _controller(
            tmp_path=tmp_path,
            state=state,
            config=_config(GuardianMode.OBSERVE),
            checkout=checkout,
            provider=provider,
            driver=driver,
            broker=broker,
        ).poll_once()

        assert outcome.runs_completed == 1
        assert len(driver.calls) == 1
        assert state.pending_event_revisions(mode=GuardianMode.OBSERVE) == ()


def test_trusted_deletion_tombstone_resolves_retryable_old_revision_without_model(
    tmp_path: Path, runtime
) -> None:
    _base, _head, checkout, provider, broker, _sequence = runtime
    driver = FakeCodexDriver()
    no_budget = GuardianLimits(
        daily_cost_limit_usd=1,
        model_call_reservation_usd=1,
    )
    with GuardianState(tmp_path / "state.sqlite3") as state:
        _consume_test_budget(state)
        _controller(
            tmp_path=tmp_path,
            state=state,
            config=_config(GuardianMode.OBSERVE, limits=no_budget),
            checkout=checkout,
            provider=provider,
            driver=driver,
            broker=broker,
        ).poll_once()
        provider.snapshots = (
            _snapshot(
                feedback=(
                    replace(
                        _feedback(),
                        body="",
                        deleted=True,
                        updated_at="2026-08-30T11:45:00Z",
                    ),
                )
            ),
        )

        outcome = _controller(
            tmp_path=tmp_path,
            state=state,
            config=_config(GuardianMode.OBSERVE),
            checkout=checkout,
            provider=provider,
            driver=driver,
            broker=broker,
        ).poll_once()

        assert outcome.runs_completed == 1
        assert driver.calls == []
        latest = state.latest_event_revisions(repository="acme/widgets")
        assert latest[0].deleted is True
        assert state.pending_event_revisions(mode=GuardianMode.OBSERVE) == ()


def test_prepare_validates_in_ephemeral_checkout_without_remote_writes(
    tmp_path: Path, runtime
) -> None:
    _base, _head, checkout, provider, broker, sequence = runtime
    driver = FakeCodexDriver()
    with GuardianState(tmp_path / "state.sqlite3") as state:
        outcome = _controller(
            tmp_path=tmp_path,
            state=state,
            config=_config(GuardianMode.PREPARE),
            checkout=checkout,
            provider=provider,
            driver=driver,
            broker=broker,
        ).poll_once()

        assert outcome.runs_completed == 1
        assert outcome.prepared_value_edits == 1
        assert outcome.applied_commits == ()
        assert sequence == []
        assert broker.verify_calls == []
        assert all(workspace.commits == 0 for workspace in checkout.workspaces)


def test_apply_signs_then_reverifies_immediately_before_normal_publish_and_reply(
    tmp_path: Path, runtime
) -> None:
    """Bind signing, publication, and reply to their independent authority checks."""
    _base, _head, checkout, provider, broker, sequence = runtime
    driver = FakeCodexDriver()
    with GuardianState(tmp_path / "state.sqlite3") as state:
        outcome = _controller(
            tmp_path=tmp_path,
            state=state,
            config=_config(GuardianMode.APPLY_OWNED_TRANSLATIONS),
            checkout=checkout,
            provider=provider,
            driver=driver,
            broker=broker,
        ).poll_once()

        assert outcome.applied_commits == (COMMIT_SHA,)
        assert sequence == ["commit", "verify", "verify", "publish", "reply"]
        assert [item.author_email for item in checkout.workspaces if item.commits] == [
            "8+translation-service@users.noreply.github.com"
        ]
        assert broker.verify_calls == [
            {
                "pull_number": 12,
                "expected_head_sha": HEAD_SHA,
                "expected_base_sha": BASE_SHA,
                "expected_actor": TrustedActor("translation-service", 8, "User"),
            },
            {
                "pull_number": 12,
                "expected_head_sha": HEAD_SHA,
                "expected_base_sha": BASE_SHA,
                "expected_actor": TrustedActor("translation-service", 8, "User"),
            },
        ]
        assert broker.reply_calls[0]["event_revision_id"].isdigit()
        assert broker.reply_calls[0]["expected_actor"] == _policy().publication_actor
        assert state.pending_publications() == ()
        publication_actor = _policy().publication_actor
        assert publication_actor is not None
        publication = state.replied_publication_for_head(
            repository="acme/widgets",
            pr_number=12,
            head_sha=COMMIT_SHA,
            publication_actor_id=publication_actor.id,
            publication_actor_type=publication_actor.type,
        )
        assert publication is not None
        assert broker.reply_calls[0]["action_id"] == publication.publication_key


def test_lost_lease_immediately_before_push_prevents_all_remote_mutations(
    tmp_path: Path, runtime
) -> None:
    _base, _head, checkout, provider, broker, sequence = runtime
    driver = FakeCodexDriver()
    with GuardianState(tmp_path / "state.sqlite3") as state:
        original_refresh = state.refresh_lease

        def lose_after_remote_verification(**kwargs):
            if sequence and sequence[-1] == "verify":
                return False
            return original_refresh(**kwargs)

        state.refresh_lease = lose_after_remote_verification  # type: ignore[method-assign]
        outcome = _controller(
            tmp_path=tmp_path,
            state=state,
            config=_config(GuardianMode.APPLY_OWNED_TRANSLATIONS),
            checkout=checkout,
            provider=provider,
            driver=driver,
            broker=broker,
        ).poll_once()

        assert outcome.runs_failed == 0
        assert outcome.failures == ("LeaseLost",)
        assert outcome.raw_bodies_purged == 0
        assert outcome.applied_commits == ()
        assert sequence == ["commit", "verify"]
        assert broker.reply_calls == []
        assert state.pending_publications()[0].phase == "prepared"


def test_base_movement_after_initial_verification_prevents_push_and_reply(
    tmp_path: Path, runtime
) -> None:
    _base, _head, checkout, provider, broker, sequence = runtime
    broker.verify_error_on_call = 2
    with GuardianState(tmp_path / "state.sqlite3") as state:
        outcome = _controller(
            tmp_path=tmp_path,
            state=state,
            config=_config(GuardianMode.APPLY_OWNED_TRANSLATIONS),
            checkout=checkout,
            provider=provider,
            driver=FakeCodexDriver(),
            broker=broker,
        ).poll_once()

        assert outcome.runs_failed == 1
        assert outcome.applied_commits == ()
        assert sequence == ["commit", "verify", "verify"]
        assert broker.reply_calls == []
        assert state.pending_publications()[0].phase == "prepared"


def test_published_commit_reply_recovers_idempotently_without_a_second_model_call(
    tmp_path: Path, runtime
) -> None:
    _base, _head, checkout, provider, broker, _sequence = runtime
    driver = FakeCodexDriver()
    broker.reply_error = RuntimeError("connection dropped after publication")
    with GuardianState(tmp_path / "state.sqlite3") as state:
        first = _controller(
            tmp_path=tmp_path,
            state=state,
            config=_config(GuardianMode.APPLY_OWNED_TRANSLATIONS),
            checkout=checkout,
            provider=provider,
            driver=driver,
            broker=broker,
        ).poll_once()

        assert first.runs_failed == 1
        pending = state.pending_publications()[0]
        assert pending.phase == "published"
        assert pending.publication_actor_id == 8
        assert pending.publication_actor_type == "User"
        broker.reply_error = None
        provider.snapshots = (_snapshot(pull=_pull(head_sha=COMMIT_SHA)),)

        second = _controller(
            tmp_path=tmp_path,
            state=state,
            config=_config(GuardianMode.APPLY_OWNED_TRANSLATIONS),
            checkout=checkout,
            provider=provider,
            driver=driver,
            broker=broker,
        ).poll_once()

        assert second.failures == ()
        assert len(driver.calls) == 1
        assert state.pending_publications() == ()
        assert [call["expected_actor"] for call in broker.reply_calls] == [
            _policy().publication_actor,
            _policy().publication_actor,
        ]
        assert (
            state.pending_event_revisions(mode=GuardianMode.APPLY_OWNED_TRANSLATIONS)
            == ()
        )


def test_publication_recovery_overflow_defers_new_model_work(
    tmp_path: Path,
    runtime,
) -> None:
    _base, _head, checkout, provider, broker, _sequence = runtime
    driver = FakeCodexDriver()
    provider.snapshots = (_snapshot(pull=_pull(head_sha=COMMIT_SHA)),)
    with GuardianState(tmp_path / "state.sqlite3") as state:
        event = authorize_feedback(
            policy=_policy(),
            snapshot=_snapshot(),
            path_locales={TARGET_PATH: "ru"},
            changed_locales=("ru",),
        ).events[0]
        revision = state.record_feedback_event(event, observed_at=NOW)
        run_id = state.start_run(
            repository="acme/widgets",
            locale="ru",
            mode=GuardianMode.APPLY_OWNED_TRANSLATIONS,
            started_at=NOW,
        )
        for index in range(101):
            commit_sha = COMMIT_SHA if index == 100 else f"{index + 100:040x}"
            state.record_publication_event(
                run_id=run_id,
                repository="acme/widgets",
                pr_number=12,
                original_head_sha=HEAD_SHA,
                base_sha=BASE_SHA,
                commit_sha=commit_sha,
                publication_actor_id=8,
                publication_actor_type="User",
                event_revision_ids=(revision.revision_id,),
                open_source=OpenPullAuthorityReference(
                    repository="acme/widgets",
                    repository_id=42,
                    pull_id=500,
                    pr_number=12,
                    authority_digest=f"{index + 1:064x}",
                    head_sha=HEAD_SHA,
                    base_sha=BASE_SHA,
                    feedback_digest=f"{index + 200:064x}",
                ),
                phase="prepared",
                completion_actions=(
                    (revision.revision_id, "completed", {"outcome": "applied"}),
                ),
                occurred_at=NOW,
            )

        outcome = _controller(
            tmp_path=tmp_path,
            state=state,
            config=_config(GuardianMode.APPLY_OWNED_TRANSLATIONS),
            checkout=checkout,
            provider=provider,
            driver=driver,
            broker=broker,
        ).poll_once()

        assert outcome.failures == ("_PublicationRecoveryBacklog",)
        assert driver.calls == []
        remaining = state.pending_publications(repository_id=42)
        assert len(remaining) == 1
        assert remaining[0].commit_sha == COMMIT_SHA
        assert broker.reply_calls == []


def test_recovery_rejects_changed_publication_actor_before_broker_use(
    tmp_path: Path,
    runtime,
) -> None:
    _base, _head, checkout, provider, broker, _sequence = runtime
    broker.reply_error = RuntimeError("connection dropped after publication")
    with GuardianState(tmp_path / "state.sqlite3") as state:
        first = _controller(
            tmp_path=tmp_path,
            state=state,
            config=_config(GuardianMode.APPLY_OWNED_TRANSLATIONS),
            checkout=checkout,
            provider=provider,
            driver=FakeCodexDriver(),
            broker=broker,
        ).poll_once()

        assert first.runs_failed == 1
        pending = state.pending_publications()[0]
        assert pending.publication_actor_id == 8
        assert pending.publication_actor_type == "User"
        provider.snapshots = (_snapshot(pull=_pull(head_sha=COMMIT_SHA)),)
        broker.reply_error = None
        broker_uses: list[RepositoryPolicy] = []
        changed_policy = replace(
            _policy(),
            publication_actor=TrustedActor("replacement-service", 99, "User"),
        )
        controller = _controller(
            tmp_path=tmp_path,
            state=state,
            config=_config(
                GuardianMode.APPLY_OWNED_TRANSLATIONS,
                policies=(changed_policy,),
            ),
            checkout=checkout,
            provider=provider,
            driver=FakeCodexDriver(),
            broker=broker,
        )
        controller.write_broker_factory = lambda policy: (
            broker_uses.append(policy) or broker
        )
        verify_calls = tuple(broker.verify_calls)
        reply_calls = tuple(broker.reply_calls)
        assert state.acquire_lease(
            name="guardian:poll",
            owner="test-owner",
            ttl_seconds=60,
            now=NOW,
        )

        with pytest.raises(
            guardian_controller._PublicationRecoveryManualRequired,
            match="actor no longer matches",
        ):
            controller._recover_publications(
                policy=changed_policy,
                snapshots=provider.snapshots,
                observed_at=NOW,
                lease_owner="test-owner",
            )

        assert broker_uses == []
        assert tuple(broker.verify_calls) == verify_calls
        assert tuple(broker.reply_calls) == reply_calls
        assert state.pending_publications() == (pending,)


def test_recovery_accepts_renamed_publication_actor_login(
    tmp_path: Path,
    runtime,
) -> None:
    _base, _head, checkout, provider, broker, _sequence = runtime
    driver = FakeCodexDriver()
    broker.reply_error = RuntimeError("connection dropped after publication")
    with GuardianState(tmp_path / "state.sqlite3") as state:
        first = _controller(
            tmp_path=tmp_path,
            state=state,
            config=_config(GuardianMode.APPLY_OWNED_TRANSLATIONS),
            checkout=checkout,
            provider=provider,
            driver=driver,
            broker=broker,
        ).poll_once()

        assert first.runs_failed == 1
        assert state.pending_publications()[0].publication_actor_id == 8
        renamed_actor = TrustedActor("renamed-translation-service", 8, "User")
        renamed_policy = replace(_policy(), publication_actor=renamed_actor)
        broker.reply_error = None
        provider.snapshots = (_snapshot(pull=_pull(head_sha=COMMIT_SHA)),)

        second = _controller(
            tmp_path=tmp_path,
            state=state,
            config=_config(
                GuardianMode.APPLY_OWNED_TRANSLATIONS,
                policies=(renamed_policy,),
            ),
            checkout=checkout,
            provider=provider,
            driver=driver,
            broker=broker,
        ).poll_once()

        assert second.failures == ()
        assert state.pending_publications() == ()
        assert len(driver.calls) == 1
        assert broker.reply_calls[-1]["expected_actor"] == renamed_actor


def test_published_reply_recovery_survives_base_repository_rename(
    tmp_path: Path,
    runtime,
) -> None:
    _base, _head, checkout, provider, broker, _sequence = runtime
    driver = FakeCodexDriver()
    broker.reply_error = RuntimeError("connection dropped after publication")
    with GuardianState(tmp_path / "state.sqlite3") as state:
        first = _controller(
            tmp_path=tmp_path,
            state=state,
            config=_config(GuardianMode.APPLY_OWNED_TRANSLATIONS),
            checkout=checkout,
            provider=provider,
            driver=driver,
            broker=broker,
        ).poll_once()

        assert first.runs_failed == 1
        original = state.pending_publications()[0]
        assert original.phase == "published"
        renamed_policy = _policy(repository="acme/renamed-widgets")
        renamed_snapshot = guardian_controller._repository_route_alias(
            _snapshot(pull=_pull(head_sha=COMMIT_SHA)),
            repository=renamed_policy.base_repo,
        )
        provider.snapshots = (renamed_snapshot,)
        broker.reply_error = None

        second = _controller(
            tmp_path=tmp_path,
            state=state,
            config=_config(
                GuardianMode.APPLY_OWNED_TRANSLATIONS,
                policies=(renamed_policy,),
            ),
            checkout=checkout,
            provider=provider,
            driver=driver,
            broker=broker,
        ).poll_once()

        assert second.failures == ()
        assert state.pending_publications(repository_id=42) == ()
        assert len(driver.calls) == 1
        replied = state.replied_publication_for_head(
            repository="acme/renamed-widgets",
            repository_id=42,
            pr_number=12,
            head_sha=COMMIT_SHA,
            publication_actor_id=8,
            publication_actor_type="User",
        )
        assert replied is not None
        assert replied.repository == "acme/widgets"


def test_repository_route_alias_preserves_open_authority_hashes() -> None:
    original_policy = _policy()
    original_snapshot = _snapshot()
    original_authorized = authorize_feedback(
        policy=original_policy,
        snapshot=original_snapshot,
        path_locales={TARGET_PATH: "ru"},
        changed_locales=("ru",),
    )
    original = GuardianController._open_pull_authority_reference(
        policy=original_policy,
        snapshot=original_snapshot,
        authorized=original_authorized,
    )
    renamed_policy = _policy(repository="acme/renamed-widgets")
    renamed_snapshot = guardian_controller._repository_route_alias(
        original_snapshot,
        repository=renamed_policy.base_repo,
    )
    renamed_authorized = authorize_feedback(
        policy=renamed_policy,
        snapshot=renamed_snapshot,
        path_locales={TARGET_PATH: "ru"},
        changed_locales=("ru",),
    )

    routed = GuardianController._open_pull_authority_reference(
        policy=renamed_policy,
        snapshot=renamed_snapshot,
        authorized=renamed_authorized,
        authority_repository=original_policy.base_repo,
    )

    assert routed == original


@pytest.mark.parametrize("race", ("edited", "deleted", "added"))
def test_recovery_never_replies_after_trusted_feedback_authority_changes(
    race: str,
    tmp_path: Path,
    runtime,
) -> None:
    """Preserve the published result while suppressing a now-unauthorized reply."""
    _base, _head, checkout, provider, broker, _sequence = runtime
    broker.reply_error = RuntimeError("connection dropped after publication")
    with GuardianState(tmp_path / "state.sqlite3") as state:
        first = _controller(
            tmp_path=tmp_path,
            state=state,
            config=_config(GuardianMode.APPLY_OWNED_TRANSLATIONS),
            checkout=checkout,
            provider=provider,
            driver=FakeCodexDriver(),
            broker=broker,
        ).poll_once()
        assert first.runs_failed == 1
        pending = state.pending_publications()[0]
        assert pending.open_source is not None
        assert pending.open_source.feedback_digest is not None

        feedback = list(provider.snapshots[0].feedback)
        if race == "edited":
            feedback[0] = replace(
                feedback[0],
                body="Use different reviewed wording.",
                updated_at="2026-08-30T10:01:00Z",
            )
        elif race == "deleted":
            feedback[0] = replace(
                feedback[0],
                body="",
                deleted=True,
                updated_at="2026-08-30T10:01:00Z",
            )
        else:
            feedback.append(
                _feedback(
                    body="Also fix this independently reviewed defect.",
                    source_id="45",
                    updated_at="2026-08-30T10:01:00Z",
                )
            )
        raced = replace(
            provider.snapshots[0],
            pull_request=replace(
                provider.snapshots[0].pull_request,
                head_sha=COMMIT_SHA,
            ),
            feedback=tuple(feedback),
        )
        provider.snapshots = (raced,)
        replies_before_recovery = len(broker.reply_calls)
        broker.reply_error = None
        assert state.acquire_lease(
            name="guardian:poll",
            owner="test-owner",
            ttl_seconds=60,
            now=NOW,
        )

        _controller(
            tmp_path=tmp_path,
            state=state,
            config=_config(GuardianMode.APPLY_OWNED_TRANSLATIONS),
            checkout=checkout,
            provider=provider,
            driver=FakeCodexDriver(),
            broker=broker,
        )._recover_publications(
            policy=_policy(),
            snapshots=(raced,),
            observed_at=NOW,
            lease_owner="test-owner",
        )

        assert len(broker.reply_calls) == replies_before_recovery
        assert state.pending_publications() == ()
        assert state.get_run(pending.run_id).status == "completed"
        assert state.publication_reply_terminal_reason(pending.publication_key) == (
            "trusted_feedback_changed"
        )


def test_feedback_edit_after_push_completes_commit_without_claiming_reply(
    tmp_path: Path, runtime,
) -> None:
    """A bot acknowledgement race must not turn an applied commit into failed work."""
    _base, _head, checkout, provider, broker, _sequence = runtime
    original_reply = broker.post_commit_reply

    def change_feedback_before_reply(**kwargs):
        """Simulate a reviewer acknowledgement arriving after the signed push."""
        snapshot = provider.snapshots[0]
        provider.snapshots = (replace(
            snapshot,
            feedback=(replace(snapshot.feedback[0], body="Fixed, thank you."),),
        ),)
        return original_reply(**kwargs)

    broker.post_commit_reply = change_feedback_before_reply
    with GuardianState(tmp_path / "state.sqlite3") as state:
        outcome = _controller(
            tmp_path=tmp_path, state=state,
            config=_config(GuardianMode.APPLY_OWNED_TRANSLATIONS),
            checkout=checkout, provider=provider,
            driver=FakeCodexDriver(), broker=broker,
        ).poll_once()
        assert outcome.runs_failed == 0
        assert outcome.applied_commits == (COMMIT_SHA,)
        assert state.pending_publications() == ()
        assert state._connection.execute(
            "SELECT COUNT(*) FROM publication_events WHERE phase='replied'"
        ).fetchone()[0] == 0
        assert state._connection.execute(
            "SELECT reason FROM publication_reply_terminal_events"
        ).fetchone()[0] == "trusted_feedback_changed"


def test_recovery_abandons_publication_when_the_base_revision_moved(
    tmp_path: Path, runtime
) -> None:
    _base, _head, checkout, provider, broker, _sequence = runtime
    driver = FakeCodexDriver()
    broker.reply_error = RuntimeError("connection dropped after publication")
    with GuardianState(tmp_path / "state.sqlite3") as state:
        first = _controller(
            tmp_path=tmp_path,
            state=state,
            config=_config(GuardianMode.APPLY_OWNED_TRANSLATIONS),
            checkout=checkout,
            provider=provider,
            driver=driver,
            broker=broker,
        ).poll_once()

        assert first.runs_failed == 1
        assert state.pending_publications()[0].phase == "published"
        broker.reply_error = None
        replies_before_recovery = len(broker.reply_calls)
        provider.snapshots = (
            _snapshot(
                pull=_pull(
                    head_sha=COMMIT_SHA,
                    base_sha="e" * 40,
                )
            ),
        )

        second = _controller(
            tmp_path=tmp_path,
            state=state,
            config=_config(GuardianMode.APPLY_OWNED_TRANSLATIONS),
            checkout=checkout,
            provider=provider,
            driver=driver,
            broker=broker,
        ).poll_once()

        assert second.failures == ()
        assert len(broker.reply_calls) == replies_before_recovery + 1
        assert len(driver.calls) == 2
        stale_reply, fresh_reply = broker.reply_calls
        assert stale_reply["expected_base_sha"] == BASE_SHA
        assert fresh_reply["expected_base_sha"] == "e" * 40
        assert fresh_reply["action_id"] != stale_reply["action_id"]
        assert state.pending_publications() == ()
        assert (
            state.pending_event_revisions(mode=GuardianMode.APPLY_OWNED_TRANSLATIONS)
            == ()
        )


def test_recovery_abandons_publication_when_pull_is_no_longer_open_or_authorized(
    tmp_path: Path, runtime
) -> None:
    _base, _head, checkout, provider, broker, _sequence = runtime
    driver = FakeCodexDriver()
    broker.reply_error = RuntimeError("connection dropped after publication")
    with GuardianState(tmp_path / "state.sqlite3") as state:
        first = _controller(
            tmp_path=tmp_path,
            state=state,
            config=_config(GuardianMode.APPLY_OWNED_TRANSLATIONS),
            checkout=checkout,
            provider=provider,
            driver=driver,
            broker=broker,
        ).poll_once()
        assert first.runs_failed == 1
        assert state.pending_publications()[0].phase == "published"

        broker.reply_error = None
        provider.snapshots = ()
        second = _controller(
            tmp_path=tmp_path,
            state=state,
            config=_config(GuardianMode.APPLY_OWNED_TRANSLATIONS),
            checkout=checkout,
            provider=provider,
            driver=driver,
            broker=broker,
        ).poll_once()

        assert second.failures == ()
        assert len(driver.calls) == 1
        assert state.pending_publications() == ()


def test_lost_lease_prevents_a_recovered_status_reply(tmp_path: Path, runtime) -> None:
    _base, _head, checkout, provider, broker, _sequence = runtime
    driver = FakeCodexDriver()
    broker.reply_error = RuntimeError("connection dropped after publication")
    with GuardianState(tmp_path / "state.sqlite3") as state:
        first = _controller(
            tmp_path=tmp_path,
            state=state,
            config=_config(GuardianMode.APPLY_OWNED_TRANSLATIONS),
            checkout=checkout,
            provider=provider,
            driver=driver,
            broker=broker,
        ).poll_once()
        assert first.runs_failed == 1
        assert state.pending_publications()[0].phase == "published"

        broker.reply_error = None
        replies_before_recovery = len(broker.reply_calls)
        provider.snapshots = (_snapshot(pull=_pull(head_sha=COMMIT_SHA)),)
        original_refresh = state.refresh_lease
        refresh_calls = 0

        def lose_during_recovery(**kwargs):
            nonlocal refresh_calls
            refresh_calls += 1
            if refresh_calls == 2:
                return False
            return original_refresh(**kwargs)

        state.refresh_lease = lose_during_recovery  # type: ignore[method-assign]
        second = _controller(
            tmp_path=tmp_path,
            state=state,
            config=_config(GuardianMode.APPLY_OWNED_TRANSLATIONS),
            checkout=checkout,
            provider=provider,
            driver=driver,
            broker=broker,
        ).poll_once()

        assert second.failures == ("LeaseLost",)
        assert second.raw_bodies_purged == 0
        assert len(broker.reply_calls) == replies_before_recovery
        assert state.pending_publications()[0].phase == "published"


def test_lost_lease_after_recovered_reply_stops_all_completion_writes(
    tmp_path: Path, runtime
) -> None:
    _base, _head, checkout, provider, broker, _sequence = runtime
    driver = FakeCodexDriver()
    broker.reply_error = RuntimeError("connection dropped after publication")
    with GuardianState(tmp_path / "state.sqlite3") as state:
        first = _controller(
            tmp_path=tmp_path,
            state=state,
            config=_config(GuardianMode.APPLY_OWNED_TRANSLATIONS),
            checkout=checkout,
            provider=provider,
            driver=driver,
            broker=broker,
        ).poll_once()
        assert first.runs_failed == 1
        pending = state.pending_publications()[0]

        broker.reply_error = None
        provider.snapshots = (_snapshot(pull=_pull(head_sha=COMMIT_SHA)),)
        original_reply = broker.post_commit_reply
        original_refresh = state.refresh_lease
        reply_completed = False

        def complete_reply_then_lose_lease(**kwargs):
            nonlocal reply_completed
            result = original_reply(**kwargs)
            reply_completed = True
            return result

        def lose_after_reply(**kwargs):
            if reply_completed:
                return False
            return original_refresh(**kwargs)

        broker.post_commit_reply = complete_reply_then_lose_lease  # type: ignore[method-assign]
        state.refresh_lease = lose_after_reply  # type: ignore[method-assign]

        second = _controller(
            tmp_path=tmp_path,
            state=state,
            config=_config(GuardianMode.APPLY_OWNED_TRANSLATIONS),
            checkout=checkout,
            provider=provider,
            driver=driver,
            broker=broker,
        ).poll_once()

        assert second.failures == ("LeaseLost",)
        assert state.pending_publications() == (pending,)
        assert state.get_run(pending.run_id).status == "running"
        assert (
            state._connection.execute(  # noqa: SLF001
                "SELECT COUNT(*) FROM actions WHERE run_id = ?",
                (pending.run_id,),
            ).fetchone()[0]
            == 0
        )

        state.refresh_lease = original_refresh  # type: ignore[method-assign]
        third = _controller(
            tmp_path=tmp_path,
            state=state,
            config=_config(GuardianMode.APPLY_OWNED_TRANSLATIONS),
            checkout=checkout,
            provider=provider,
            driver=driver,
            broker=broker,
        ).poll_once()

        assert third.failures == ()
        assert state.pending_publications() == ()
        assert state.get_run(pending.run_id).status == "completed"
        assert (
            state._connection.execute(  # noqa: SLF001
                "SELECT COUNT(*) FROM actions WHERE run_id = ?",
                (pending.run_id,),
            ).fetchone()[0]
            == 1
        )


@pytest.mark.parametrize("non_write_mode", [GuardianMode.OBSERVE, GuardianMode.PREPARE])
def test_non_write_modes_never_recover_a_pending_write(
    tmp_path: Path, runtime, non_write_mode: GuardianMode
) -> None:
    _base, _head, checkout, provider, broker, _sequence = runtime
    driver = FakeCodexDriver()
    broker.reply_error = RuntimeError("connection dropped after publication")
    with GuardianState(tmp_path / "state.sqlite3") as state:
        first = _controller(
            tmp_path=tmp_path,
            state=state,
            config=_config(GuardianMode.APPLY_OWNED_TRANSLATIONS),
            checkout=checkout,
            provider=provider,
            driver=driver,
            broker=broker,
        ).poll_once()
        assert first.runs_failed == 1
        assert state.pending_publications()[0].phase == "published"

        broker.reply_error = None
        replies_before_observe = len(broker.reply_calls)
        provider.snapshots = (_snapshot(pull=_pull(head_sha=COMMIT_SHA)),)
        _controller(
            tmp_path=tmp_path,
            state=state,
            config=_config(non_write_mode),
            checkout=checkout,
            provider=provider,
            driver=driver,
            broker=broker,
        ).poll_once()

        assert len(broker.reply_calls) == replies_before_observe
        assert state.pending_publications()[0].phase == "published"


def test_guardian_owned_head_does_not_reassess_unchanged_feedback(
    tmp_path: Path, runtime
) -> None:
    _base, _head, checkout, provider, broker, _sequence = runtime
    driver = FakeCodexDriver()
    with GuardianState(tmp_path / "state.sqlite3") as state:
        controller = _controller(
            tmp_path=tmp_path,
            state=state,
            config=_config(GuardianMode.APPLY_OWNED_TRANSLATIONS),
            checkout=checkout,
            provider=provider,
            driver=driver,
            broker=broker,
        )
        controller.poll_once()
        provider.snapshots = (_snapshot(pull=_pull(head_sha=COMMIT_SHA)),)

        outcome = controller.poll_once()

        assert outcome.runs_completed == 1
        assert len(driver.calls) == 1
        assert (
            state.pending_event_revisions(mode=GuardianMode.APPLY_OWNED_TRANSLATIONS)
            == ()
        )


def test_migrated_actorless_reply_does_not_suppress_current_feedback(
    tmp_path: Path, runtime
) -> None:
    _base, _head, checkout, provider, broker, sequence = runtime
    database = tmp_path / "state.sqlite3"
    with GuardianState(database) as state:
        revision = state.record_feedback_event(
            FeedbackEvent(
                repository="acme/widgets",
                pr_number=12,
                kind="review_comment",
                event_id="44",
                author="native-reviewer",
                author_id=101,
                author_type="User",
                body="Use the idiomatic wording.",
                head_sha=HEAD_SHA,
                base_sha=BASE_SHA,
                locale="ru",
                updated_at="2026-08-30T10:00:00Z",
                path=TARGET_PATH,
                line=1,
                html_url=("https://github.com/acme/widgets/pull/12#discussion_r44"),
            ),
            observed_at=NOW,
        )
        run_id = state.start_run(
            repository="acme/widgets",
            locale="ru",
            mode=GuardianMode.APPLY_OWNED_TRANSLATIONS,
            started_at=NOW,
        )

    publication_key = _insert_legacy_publication(
        database,
        run_id=run_id,
        repository="acme/widgets",
        pr_number=12,
        original_head_sha=HEAD_SHA,
        base_sha=BASE_SHA,
        commit_sha=COMMIT_SHA,
        event_revision_ids=(revision.revision_id,),
        occurred_at=NOW,
        phase="replied",
    )

    driver = FakeCodexDriver()
    provider.snapshots = (_snapshot(pull=_pull(head_sha=COMMIT_SHA)),)
    with GuardianState(database) as state:
        row = state._connection.execute(  # noqa: SLF001
            "SELECT * FROM publication_events WHERE publication_key = ?",
            (publication_key,),
        ).fetchone()
        publication = state._publication_from_row(row)  # noqa: SLF001
        assert publication.phase == "replied"
        assert publication.publication_actor_id is None
        assert publication.publication_actor_type is None

        outcome = _controller(
            tmp_path=tmp_path,
            state=state,
            config=_config(GuardianMode.OBSERVE),
            checkout=checkout,
            provider=provider,
            driver=driver,
            broker=broker,
        ).poll_once()

        assert outcome.runs_completed == 1
        assert len(driver.calls) == 1

    assert broker.reply_calls == []
    assert sequence == []


def test_apply_below_confidence_threshold_never_mutates_or_contacts_write_broker(
    tmp_path: Path, runtime
) -> None:
    _base, _head, checkout, provider, broker, sequence = runtime
    driver = FakeCodexDriver(confidence=0.89)
    with GuardianState(tmp_path / "state.sqlite3") as state:
        outcome = _controller(
            tmp_path=tmp_path,
            state=state,
            config=_config(GuardianMode.APPLY_OWNED_TRANSLATIONS),
            checkout=checkout,
            provider=provider,
            driver=driver,
            broker=broker,
        ).poll_once()

        assert outcome.prepared_value_edits == 0
        assert outcome.applied_commits == ()
        assert sequence == []
        assert broker.verify_calls == []


def test_daily_budget_is_reserved_before_model_and_denial_remains_retryable(
    tmp_path: Path, runtime
) -> None:
    _base, _head, checkout, provider, broker, _sequence = runtime
    driver = FakeCodexDriver()
    limits = GuardianLimits(
        daily_cost_limit_usd=1,
        model_call_reservation_usd=1,
    )
    with GuardianState(tmp_path / "state.sqlite3") as state:
        _consume_test_budget(state)
        outcome = _controller(
            tmp_path=tmp_path,
            state=state,
            config=_config(GuardianMode.OBSERVE, limits=limits),
            checkout=checkout,
            provider=provider,
            driver=driver,
            broker=broker,
        ).poll_once()

        assert outcome.runs_failed == 1
        assert driver.calls == []
        assert len(state.pending_event_revisions(mode=GuardianMode.OBSERVE)) == 1
        assert state.latest_health("guardian").status == "failed"


def test_final_guardian_health_is_recorded_before_lease_release(
    tmp_path: Path, runtime
) -> None:
    _base, _head, checkout, provider, broker, _sequence = runtime
    with GuardianState(tmp_path / "state.sqlite3") as state:
        original_record_health = state.record_health
        original_release_lease = state.release_lease
        lease_released = False
        guardian_health_while_live = False

        def record_health(**kwargs):
            nonlocal guardian_health_while_live
            if kwargs["component"] == "guardian":
                guardian_health_while_live = not lease_released
                assert guardian_health_while_live
            return original_record_health(**kwargs)

        def release_lease(**kwargs):
            nonlocal lease_released
            lease_released = True
            return original_release_lease(**kwargs)

        state.record_health = record_health  # type: ignore[method-assign]
        state.release_lease = release_lease  # type: ignore[method-assign]

        outcome = _controller(
            tmp_path=tmp_path,
            state=state,
            config=_config(GuardianMode.OBSERVE),
            checkout=checkout,
            provider=provider,
            driver=FakeCodexDriver(),
            broker=broker,
        ).poll_once()

        assert outcome.failures == ()
        assert guardian_health_while_live is True
        assert lease_released is True


def test_unknown_model_cost_keeps_conservative_reservation(
    tmp_path: Path, runtime
) -> None:
    _base, _head, checkout, provider, broker, _sequence = runtime
    driver = FakeCodexDriver()
    original_run = driver.run

    def no_cost(
        task,
        *,
        api_key=None,
        attempt_observer=None,
        success_observer=None,
    ):
        def without_reported_cost(attempt, phase, usage):
            if phase == "succeeded":
                usage = CodexUsage(input_tokens=100, output_tokens=20)
            if attempt_observer is not None:
                attempt_observer(attempt, phase, usage)

        result = original_run(
            task,
            api_key=api_key,
            attempt_observer=without_reported_cost,
            success_observer=(
                None
                if success_observer is None
                else lambda attempt, _usage, successful: success_observer(
                    attempt,
                    CodexUsage(input_tokens=100, output_tokens=20),
                    replace(
                        successful,
                        usage=CodexUsage(input_tokens=100, output_tokens=20),
                    ),
                )
            ),
        )
        return replace(result, usage=CodexUsage(input_tokens=100, output_tokens=20))

    driver.run = no_cost  # type: ignore[method-assign]
    with GuardianState(tmp_path / "state.sqlite3") as state:
        _controller(
            tmp_path=tmp_path,
            state=state,
            config=_config(GuardianMode.OBSERVE),
            checkout=checkout,
            provider=provider,
            driver=driver,
            broker=broker,
        ).poll_once()

        assert state.cost_for_day(NOW.date()) == 0
        assert state.budget_committed_for_day(NOW.date()) == 1


def test_codex_authentication_failure_opens_circuit_and_stops_later_repositories(
    tmp_path: Path, runtime
) -> None:
    base, head, checkout, _provider, broker, _sequence = runtime
    second_policy = _policy(repository="other/widgets")
    second_snapshot = replace(
        _snapshot(),
        repository_identity=GitHubRepositoryIdentity("other/widgets", 42, False),
        pull_request=replace(_pull(), repository="other/widgets"),
        feedback=(replace(_feedback(), repository="other/widgets"),),
    )
    provider = FakeSnapshotProvider((_snapshot(), second_snapshot))
    driver = FakeCodexDriver(error=CodexAuthenticationError("credential rejected"))
    with GuardianState(tmp_path / "state.sqlite3") as state:
        outcome = _controller(
            tmp_path=tmp_path,
            state=state,
            config=_config(
                GuardianMode.OBSERVE,
                policies=(_policy(), second_policy),
            ),
            checkout=checkout,
            provider=provider,
            driver=driver,
            broker=broker,
        ).poll_once()

        assert outcome.authentication_circuit_open is True
        assert [repository for repository, _previous in provider.calls] == [
            "acme/widgets"
        ]
        assert state.latest_health("codex").status == "failed"
        assert state.budget_committed_for_day(NOW.date()) == 1


def test_codex_capacity_failure_opens_model_circuit_and_stops_later_repositories(
    tmp_path: Path, runtime
) -> None:
    _base, _head, checkout, _provider, broker, _sequence = runtime
    second_policy = _policy(repository="other/widgets")
    second_snapshot = replace(
        _snapshot(),
        repository_identity=GitHubRepositoryIdentity("other/widgets", 42, False),
        pull_request=replace(_pull(), repository="other/widgets"),
        feedback=(replace(_feedback(), repository="other/widgets"),),
    )
    provider = FakeSnapshotProvider((_snapshot(), second_snapshot))
    driver = FakeCodexDriver(error=CodexCapacityError("allowance exhausted"))
    with GuardianState(tmp_path / "state.sqlite3") as state:
        outcome = _controller(
            tmp_path=tmp_path,
            state=state,
            config=_config(
                GuardianMode.OBSERVE,
                policies=(_policy(), second_policy),
            ),
            checkout=checkout,
            provider=provider,
            driver=driver,
            broker=broker,
        ).poll_once()

        assert outcome.model_circuit_open is True
        assert outcome.authentication_circuit_open is False
        assert [repository for repository, _previous in provider.calls] == [
            "acme/widgets"
        ]
        assert state.latest_health("codex").status == "failed"


def test_model_credential_helper_failure_opens_circuit_without_reserving_cost(
    tmp_path: Path, runtime
) -> None:
    _base, _head, checkout, _provider, broker, _sequence = runtime
    second_policy = _policy(repository="other/widgets")
    second_snapshot = replace(
        _snapshot(),
        repository_identity=GitHubRepositoryIdentity("other/widgets", 42, False),
        pull_request=replace(_pull(), repository="other/widgets"),
        feedback=(replace(_feedback(), repository="other/widgets"),),
    )
    provider = FakeSnapshotProvider((_snapshot(), second_snapshot))
    driver = FakeCodexDriver()
    with GuardianState(tmp_path / "state.sqlite3") as state:
        controller = _controller(
            tmp_path=tmp_path,
            state=state,
            config=_config(
                GuardianMode.OBSERVE,
                policies=(_policy(), second_policy),
            ),
            checkout=checkout,
            provider=provider,
            driver=driver,
            broker=broker,
        )

        def unavailable_credential() -> str:
            raise RuntimeError("keychain locked")

        controller.model_credential_provider = unavailable_credential
        outcome = controller.poll_once()

        assert outcome.authentication_circuit_open is True
        assert [repository for repository, _previous in provider.calls] == [
            "acme/widgets"
        ]
        assert driver.calls == []
        assert state.budget_committed_for_day(NOW.date()) == 0


def test_raw_feedback_body_is_purged_after_retention_window(
    tmp_path: Path, runtime
) -> None:
    _base, _head, checkout, provider, broker, _sequence = runtime
    driver = FakeCodexDriver()
    with GuardianState(tmp_path / "state.sqlite3") as state:
        old_event = state.record_feedback_event(
            # Build through the same authorization path once, then make its
            # raw observation old while retaining the immutable revision.
            FeedbackEvent(
                repository="acme/widgets",
                pr_number=12,
                kind="review_comment",
                event_id="99",
                author="native-reviewer",
                author_id=101,
                author_type="User",
                body="Use the idiomatic wording.",
                head_sha=HEAD_SHA,
                base_sha=BASE_SHA,
                locale="ru",
                updated_at="2026-08-30T10:00:00Z",
                path=TARGET_PATH,
                line=1,
                html_url="https://github.com/acme/widgets/pull/12#discussion_r99",
            ),
            observed_at=NOW - timedelta(days=91),
        )
        outcome = _controller(
            tmp_path=tmp_path,
            state=state,
            config=_config(GuardianMode.OBSERVE),
            checkout=checkout,
            provider=provider,
            driver=driver,
            broker=broker,
        ).poll_once()

        assert outcome.failures == ()
        assert outcome.raw_bodies_purged == 1
        assert state.get_event_revision(old_event.revision_id).body is None


def test_head_checkout_failure_finishes_run_and_keeps_feedback_retryable(
    tmp_path: Path, runtime
) -> None:
    _base, _head, checkout, provider, broker, sequence = runtime

    class FailingHeadCheckout(FakeCheckoutFactory):
        @contextmanager
        def __call__(self, revision):
            if revision.sha == HEAD_SHA:
                raise RuntimeError("head fetch failed")
            with super().__call__(revision) as workspace:
                yield workspace

    failing = FailingHeadCheckout(
        checkout.base_tree,
        checkout.head_tree,
        tmp_path,
        sequence,
    )
    driver = FakeCodexDriver()
    with GuardianState(tmp_path / "state.sqlite3") as state:
        outcome = _controller(
            tmp_path=tmp_path,
            state=state,
            config=_config(GuardianMode.OBSERVE),
            checkout=failing,
            provider=provider,
            driver=driver,
            broker=broker,
        ).poll_once()

        assert outcome.runs_failed == 1
        assert outcome.failures == ("RuntimeError",)
        assert driver.calls == []
        assert state.pending_event_revisions(mode=GuardianMode.OBSERVE)
        assert state.reconcile_incomplete_runs(before=NOW + timedelta(days=1)) == ()


def test_non_target_or_wrong_source_locale_pr_is_rejected_before_model(
    tmp_path: Path, runtime
) -> None:
    base, _head, checkout, provider, broker, _sequence = runtime
    driver = FakeCodexDriver()
    base_config = yaml.safe_load((base / ".localize/config.yaml").read_text())
    base_config["source_locale"] = "de"
    base_config["localization_layout"]["source_locale"] = "de"
    (base / ".localize/config.yaml").write_text(yaml.safe_dump(base_config))
    provider.snapshots = (
        _snapshot(
            changed_files=(
                ChangedFile(path="src/App.java", status="modified", sha="d" * 40),
            )
        ),
    )
    with GuardianState(tmp_path / "state.sqlite3") as state:
        outcome = _controller(
            tmp_path=tmp_path,
            state=state,
            config=_config(GuardianMode.OBSERVE),
            checkout=checkout,
            provider=provider,
            driver=driver,
            broker=broker,
        ).poll_once()

        assert outcome.runs_started == 0
        assert outcome.failures
        assert driver.calls == []


@pytest.mark.parametrize(
    "missing_dependency",
    [
        "historical_snapshot_provider",
        "historical_checkout_factory",
        "current_base_provider",
    ],
)
def test_closed_backfill_requires_every_read_only_dependency(
    tmp_path: Path,
    runtime,
    missing_dependency: str,
) -> None:
    base, head, checkout, provider, broker, sequence = runtime
    dependencies: dict[str, object | None] = {
        "historical_snapshot_provider": FakeHistoricalSnapshotProvider(()),
        "historical_checkout_factory": FakeHistoricalCheckoutFactory(
            base,
            head,
            tmp_path,
        ),
        "current_base_provider": FakeCurrentBaseProvider(),
    }
    dependencies[missing_dependency] = None
    with GuardianState(tmp_path / "state.sqlite3") as state:
        with pytest.raises(ValueError, match="Closed-PR backfill requires"):
            GuardianController(
                config=_config(
                    GuardianMode.OBSERVE,
                    policies=(_historical_policy(),),
                ),
                state=state,
                snapshot_provider=provider,
                checkout_factory=checkout,
                codex_driver=FakeCodexDriver(),
                write_broker_factory=lambda _policy: broker,
                evidence_root=tmp_path / "evidence",
                now=lambda: NOW,
                **dependencies,
            )


def test_apply_capable_closed_remediation_requires_dedicated_runner(
    tmp_path: Path,
    runtime,
) -> None:
    base, head, checkout, provider, broker, _sequence = runtime
    with GuardianState(tmp_path / "state.sqlite3") as state:
        with pytest.raises(ValueError, match="requires a remediation runner"):
            _controller(
                tmp_path=tmp_path,
                state=state,
                config=_config(
                    GuardianMode.APPLY_OWNED_TRANSLATIONS,
                    policies=(_historical_policy(remediation=True),),
                ),
                checkout=checkout,
                provider=provider,
                driver=FakeCodexDriver(),
                broker=broker,
                historical_snapshot_provider=FakeHistoricalSnapshotProvider(()),
                historical_checkout_factory=FakeHistoricalCheckoutFactory(
                    base,
                    head,
                    tmp_path,
                ),
                current_base_provider=FakeCurrentBaseProvider(),
            )


def test_historical_prevention_requires_exact_source_revalidation(
    tmp_path: Path,
    runtime,
) -> None:
    base, head, checkout, provider, broker, _sequence = runtime
    policy = replace(_historical_policy(), prevention=_prevention_policy())
    with GuardianState(tmp_path / "state.sqlite3") as state:
        with pytest.raises(
            ValueError,
            match="Closed-PR mutations require an exact source",
        ):
            GuardianController(
                config=_config(
                    GuardianMode.PROPOSE_PREVENTION,
                    policies=(policy,),
                ),
                state=state,
                snapshot_provider=provider,
                checkout_factory=checkout,
                codex_driver=FakeCodexDriver(),
                write_broker_factory=lambda _policy: broker,
                prevention_runner=FakePreventionRunner(),
                historical_snapshot_provider=FakeHistoricalSnapshotProvider(()),
                historical_checkout_factory=FakeHistoricalCheckoutFactory(
                    base,
                    head,
                    tmp_path,
                ),
                current_base_provider=FakeCurrentBaseProvider(),
                publication_actor_preflight=lambda: None,
            )


@pytest.mark.parametrize(
    ("mode", "remediation", "remediation_cap", "expected"),
    [
        (GuardianMode.OBSERVE, True, 1, (HistoricalCheckScope.ASSESSMENT,)),
        (GuardianMode.PREPARE, True, 1, (HistoricalCheckScope.ASSESSMENT,)),
        (
            GuardianMode.APPLY_OWNED_TRANSLATIONS,
            False,
            1,
            (HistoricalCheckScope.ASSESSMENT,),
        ),
        (
            GuardianMode.APPLY_OWNED_TRANSLATIONS,
            True,
            0,
            (HistoricalCheckScope.ASSESSMENT,),
        ),
        (
            GuardianMode.APPLY_OWNED_TRANSLATIONS,
            True,
            1,
            (
                HistoricalCheckScope.ASSESSMENT,
                HistoricalCheckScope.REMEDIATION,
            ),
        ),
        (
            GuardianMode.PROPOSE_PREVENTION,
            True,
            1,
            (
                HistoricalCheckScope.ASSESSMENT,
                HistoricalCheckScope.PREVENTION,
                HistoricalCheckScope.REMEDIATION,
            ),
        ),
    ],
)
def test_required_historical_scopes_are_mode_and_authority_specific(
    mode: GuardianMode,
    remediation: bool,
    remediation_cap: int,
    expected: tuple[HistoricalCheckScope, ...],
) -> None:
    limits = GuardianLimits(
        max_remediation_drafts_per_run=remediation_cap,
        daily_cost_limit_usd=2,
        model_call_reservation_usd=1,
    )
    policy = _historical_policy(remediation=remediation)
    if mode is GuardianMode.PROPOSE_PREVENTION:
        policy = replace(policy, prevention=_prevention_policy())
    config = _config(
        mode,
        policies=(policy,),
        limits=limits,
    )

    assert (
        guardian_controller._required_historical_scopes(
            config,
            config.repositories[0],
        )
        == expected
    )


def test_historical_digests_bind_snapshot_policy_assessment_and_config_bundle(
    tmp_path: Path,
) -> None:
    policy = _historical_policy()
    config = _config(GuardianMode.OBSERVE, policies=(policy,))
    operator = PipelineConfigSnapshot(
        config_root=tmp_path,
        config_path=tmp_path / "config.yaml",
        bundle_digest="a" * 64,
    )

    def digest(
        *,
        selected_config: GuardianConfig = config,
        selected_policy: RepositoryPolicy = policy,
        model: str = "test-model",
        config_bundle_digest: str = operator.bundle_digest,
    ) -> str:
        return guardian_controller._historical_policy_digest(
            config=selected_config,
            policy=selected_policy,
            model=model,
            pipeline_config_bundle_digest=config_bundle_digest,
        )

    baseline = digest()
    variants = {
        digest(model="different-model"),
        digest(
            selected_config=replace(
                config,
                mode=GuardianMode.PREPARE,
            )
        ),
        digest(
            selected_config=replace(
                config,
                limits=replace(config.limits, min_apply_confidence=0.95),
            )
        ),
        digest(
            selected_config=replace(
                config,
                runtime=replace(config.runtime, codex_reasoning_effort="medium"),
            )
        ),
        digest(
            selected_policy=replace(
                policy,
                allowed_path_globs=("translations/*.properties",),
            )
        ),
        digest(
            config_bundle_digest="b" * 64,
        ),
    }
    pull_digest = _authorized_historical_digest(
        policy, _snapshot(pull=_pull(state="closed"))
    )
    changed_pull_digest = _authorized_historical_digest(
        policy,
        _snapshot(
            pull=_pull(state="closed"),
            feedback=(_feedback(body="Edited without touching the pull."),),
        ),
    )

    assert len(baseline) == 64
    assert baseline not in variants
    assert len(variants) == 6
    assert pull_digest != changed_pull_digest


def test_historical_digest_contains_only_exact_authorized_feedback() -> None:
    policy = _historical_policy()
    trusted = _feedback()
    baseline = _snapshot(
        pull=_pull(state="closed"),
        feedback=(trusted,),
    )
    untrusted = replace(
        trusted,
        source_id="45",
        node_id="node-45",
        author_login="drive-by-user",
        author_id=999,
        body="attacker-controlled edit",
    )
    noisy = _snapshot(
        pull=_pull(state="closed", updated_at="2026-09-01T12:00:00Z"),
        feedback=(trusted, untrusted),
    )

    baseline_digest = _authorized_historical_digest(policy, baseline)
    assert _authorized_historical_digest(policy, noisy) == baseline_digest
    assert (
        _authorized_historical_digest(
            policy,
            replace(baseline, feedback=(replace(trusted, body="trusted edit"),)),
        )
        != baseline_digest
    )

    wrong_locale = replace(
        trusted,
        source_id="46",
        node_id="node-46",
        author_id=202,
        author_login="german-reviewer",
    )
    locale_policy = replace(
        policy,
        trusted_reviewers={
            **policy.trusted_reviewers,
            "de": (TrustedActor("german-reviewer", 202, "User"),),
        },
    )
    wrong_locale_snapshot = replace(baseline, feedback=(wrong_locale,))
    empty_digest = _authorized_historical_digest(locale_policy, wrong_locale_snapshot)
    assert (
        _authorized_historical_digest(
            locale_policy,
            replace(
                wrong_locale_snapshot,
                feedback=(replace(wrong_locale, body="unrelated edit"),),
            ),
        )
        == empty_digest
    )

    for ignored in (
        replace(trusted, body="   "),
        replace(trusted, body="<!-- localize-guardian:v1 generated -->"),
    ):
        ignored_snapshot = replace(baseline, feedback=(ignored,))
        assert _authorized_historical_digest(policy, ignored_snapshot) == (
            guardian_controller._historical_pull_revision_digest(policy, baseline)
        )

    authorized = authorize_historical_feedback(
        policy=policy,
        snapshot=baseline,
        path_locales={TARGET_PATH: "ru"},
        changed_locales=("ru",),
    ).events[0]
    assert (
        guardian_controller._historical_pull_revision_digest(
            policy,
            baseline,
            feedback_events=(replace(authorized, body="", deleted=True),),
        )
        != baseline_digest
    )


def test_current_localization_digest_is_canonical_and_inline_path_scoped(
    tmp_path: Path,
) -> None:
    root = tmp_path / "current"
    _write_tree(root)
    config_path = root / ".localize/config.yaml"
    config = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    config["localization_formats"] = [
        {
            "id": "java_properties",
            "layout": {"id": "suffix", "base_name": "messages"},
        },
        {
            "id": "java_properties",
            "layout": {"id": "suffix", "base_name": "errors"},
        },
    ]
    config_path.write_text(yaml.safe_dump(config), encoding="utf-8")
    other_target = "l10n/errors_ru.properties"
    (root / "l10n/errors_en.properties").write_text(
        "failure=Failed\n",
        encoding="utf-8",
    )
    (root / other_target).write_text("failure=Ошибка\n", encoding="utf-8")
    scope = guardian_controller._TargetScope(
        config_path=config_path,
        config_root=root,
        source_root=root,
        config_bundle_digest=None,
        path_locales={TARGET_PATH: "ru", other_target: "ru"},
        changed_files={},
    )
    event = FeedbackEvent(
        repository="acme/widgets",
        pr_number=12,
        kind="review_comment",
        event_id="44",
        author="native-reviewer",
        author_id=101,
        author_type="User",
        body="Use the idiomatic wording.",
        head_sha=HEAD_SHA,
        base_sha=BASE_SHA,
        locale="ru",
        path=TARGET_PATH,
        line=1,
    )

    def identity() -> guardian_controller._CurrentLocalizationIdentity:
        return guardian_controller._current_localization_content_digest(
            root=root,
            scope=scope,
            policy=_historical_policy(),
            events=(event,),
        )

    baseline = identity()
    (root / TARGET_PATH).write_text(
        "# formatting-only comment\ngreeting=Старый %0 был отклонён (%1). %2 %3\n",
        encoding="utf-8",
    )
    assert identity() == baseline
    (root / other_target).write_text("failure=Другая ошибка\n", encoding="utf-8")
    (root / "l10n/errors_en.properties").write_text(
        "failure=Different failure\n",
        encoding="utf-8",
    )
    assert identity() == baseline

    (root / TARGET_PATH).write_text("greeting=Изменено\n", encoding="utf-8")
    changed_target = identity()
    assert changed_target.applicable is True
    assert changed_target.digest != baseline.digest
    (root / "l10n/messages_en.properties").write_text(
        "greeting=Push to %0 was rejected (%1). %2 %3\n"
        "source_only=First source value\n",
        encoding="utf-8",
    )
    source_only = identity()
    assert source_only.digest != changed_target.digest
    (root / "l10n/messages_en.properties").write_text(
        "greeting=Push to %0 was rejected (%1). %2 %3\n"
        "source_only=Changed source value\n",
        encoding="utf-8",
    )
    assert identity().digest != source_only.digest
    (root / TARGET_PATH).write_text(
        "greeting=Изменено\ntarget_only=Только цель\n",
        encoding="utf-8",
    )
    target_only = identity()
    assert target_only.digest != source_only.digest
    (root / "l10n/messages_en.properties").write_text(
        "greeting=Changed source\n",
        encoding="utf-8",
    )
    assert identity().digest != target_only.digest

    (root / TARGET_PATH).unlink()
    missing = identity()
    assert missing.applicable is False
    assert missing.digest != changed_target.digest
    (root / TARGET_PATH).write_text("greeting=Восстановлено\n", encoding="utf-8")
    (root / "l10n/messages_en.properties").unlink()
    missing_source = identity()
    assert missing_source.applicable is False
    assert missing_source.digest != missing.digest


def test_base_pipeline_bundle_digest_tracks_only_config_and_glossary_bytes(
    tmp_path: Path,
) -> None:
    _write_tree(tmp_path)
    baseline = guardian_controller._base_pipeline_config_bundle_digest(
        config_root=tmp_path,
        config_relative_path=".localize/config.yaml",
    )

    (tmp_path / "unrelated.txt").write_text("new base commit", encoding="utf-8")
    assert (
        guardian_controller._base_pipeline_config_bundle_digest(
            config_root=tmp_path,
            config_relative_path=".localize/config.yaml",
        )
        == baseline
    )

    (tmp_path / ".localize/glossary.json").write_text(
        json.dumps({"ru": {"term": "термин"}}),
        encoding="utf-8",
    )
    glossary_changed = guardian_controller._base_pipeline_config_bundle_digest(
        config_root=tmp_path,
        config_relative_path=".localize/config.yaml",
    )
    assert glossary_changed != baseline

    config = yaml.safe_load((tmp_path / ".localize/config.yaml").read_text())
    config["placeholder_profile"] = "standard"
    (tmp_path / ".localize/config.yaml").write_text(
        yaml.safe_dump(config),
        encoding="utf-8",
    )
    assert guardian_controller._base_pipeline_config_bundle_digest(
        config_root=tmp_path,
        config_relative_path=".localize/config.yaml",
    ) not in {baseline, glossary_changed}


def test_every_open_repository_finishes_before_closed_backfill_discovery(
    tmp_path: Path,
    runtime,
) -> None:
    base, head, checkout, _provider, broker, sequence = runtime
    first = _historical_policy()
    second = replace(
        _historical_policy(),
        base_repo="acme/second",
        base_repo_id=43,
    )

    class SequencedOpenProvider(FakeSnapshotProvider):
        def __call__(self, policy, previous_feedback):
            sequence.append(f"open:{policy.base_repo}")
            return super().__call__(policy, previous_feedback)

    open_provider = SequencedOpenProvider(())
    historical_provider = FakeHistoricalSnapshotProvider((), sequence=sequence)
    with GuardianState(tmp_path / "state.sqlite3") as state:
        outcome = _controller(
            tmp_path=tmp_path,
            state=state,
            config=_config(GuardianMode.OBSERVE, policies=(first, second)),
            checkout=checkout,
            provider=open_provider,
            driver=FakeCodexDriver(),
            broker=broker,
            historical_snapshot_provider=historical_provider,
            historical_checkout_factory=FakeHistoricalCheckoutFactory(
                base,
                head,
                tmp_path,
            ),
            current_base_provider=FakeCurrentBaseProvider(),
        ).poll_once()

    assert outcome.repositories_polled == 2
    assert outcome.historical_repositories_polled == 2
    assert sequence == [
        "open:acme/widgets",
        "open:acme/second",
        "history:acme/widgets",
        "history:acme/second",
    ]


def test_observe_backfill_uses_historical_diff_and_current_base_values_once(
    tmp_path: Path,
    runtime,
) -> None:
    base, head, checkout, _provider, broker, sequence = runtime
    old_base = tmp_path / "old-base"
    shutil.copytree(base, old_base)
    (old_base / TARGET_PATH).write_text(
        "greeting=Историческое значение %0 (%1). %2 %3\n",
        encoding="utf-8",
    )
    pull = _pull(state="closed")
    snapshot = _snapshot(pull=pull)
    historical_provider = FakeHistoricalSnapshotProvider((snapshot,))
    historical_checkout = FakeHistoricalCheckoutFactory(
        old_base,
        head,
        tmp_path,
    )
    current_provider = FakeCurrentBaseProvider()
    driver = FakeCodexDriver()
    observed_values: list[tuple[str, str]] = []
    observed_diffs: list[str] = []
    cache_keys: list[tuple[str, str]] = []

    def evidence_spy(**kwargs):
        observed_diffs.append(kwargs["diff_text"])
        bundle = build_evidence_bundle(**kwargs)
        payload = json.loads(
            (bundle.root / "localization.json").read_text(encoding="utf-8")
        )
        values = payload[0]["entries"]["greeting"]
        observed_values.append((values["source"], values["target"]))
        common = {
            "model": driver.model,
            "reasoning_effort": "high",
        }
        cache_keys.append(
            (
                guardian_controller._assessment_cache_key(
                    bundle,
                    prompt=guardian_controller._ASSESSMENT_PROMPT,
                    **common,
                ),
                guardian_controller._assessment_cache_key(
                    bundle,
                    prompt=guardian_controller._HISTORICAL_ASSESSMENT_PROMPT,
                    **common,
                ),
            )
        )
        return bundle

    with GuardianState(tmp_path / "state.sqlite3") as state:
        controller = _controller(
            tmp_path=tmp_path,
            state=state,
            config=_config(
                GuardianMode.OBSERVE,
                policies=(_historical_policy(),),
            ),
            checkout=checkout,
            provider=FakeSnapshotProvider(()),
            driver=driver,
            broker=broker,
            historical_snapshot_provider=historical_provider,
            historical_checkout_factory=historical_checkout,
            current_base_provider=current_provider,
            evidence_builder=evidence_spy,
        )
        first = controller.poll_once()
        second = controller.poll_once()

    assert first.historical_pull_requests_seen == 1
    assert first.historical_pull_requests_completed == 1
    assert first.runs_completed == 1
    assert second.historical_pull_requests_seen == 0
    assert len(driver.calls) == 1
    assert driver.calls[0].prompt == (guardian_controller._HISTORICAL_ASSESSMENT_PROMPT)
    assert cache_keys[0][0] != cache_keys[0][1]
    assert observed_values == [
        (
            "Push to %0 was rejected (%1). %2 %3",
            "Старый %0 был отклонён (%1). %2 %3",
        )
    ]
    assert observed_diffs == [
        "diff --git a/l10n/messages_ru.properties "
        "b/l10n/messages_ru.properties\n"
        "@@ -1 +1 @@\n-old\n+new\n"
    ]
    assert [revision.fetch_target for revision in historical_checkout.revisions] == [
        BASE_SHA,
        "refs/pull/12/head",
        BASE_SHA,
    ]
    assert all(
        revision.owner == "acme" and revision.repository == "widgets"
        for revision in historical_checkout.revisions
    )
    # Each poll captures current base once; each terminal decision revalidates
    # that exact identity and SHA before persisting completion.
    assert len(current_provider.calls) == 4
    assert broker.verify_calls == []
    assert broker.reply_calls == []
    assert "publish" not in sequence


@pytest.mark.parametrize(
    "invalid_target",
    ("missing", "historical_missing", "unparseable", "unmapped"),
)
def test_historical_mixed_targets_process_only_applicable_feedback(
    tmp_path: Path,
    runtime,
    invalid_target: str,
) -> None:
    base, head, checkout, _provider, broker, _sequence = runtime
    for tree in (base, head):
        _add_second_localization_target(tree)
    old_base = tmp_path / "old-base"
    shutil.copytree(base, old_base)

    if invalid_target == "missing":
        (base / SECOND_TARGET_PATH).unlink()
    elif invalid_target == "historical_missing":
        (head / SECOND_TARGET_PATH).unlink()
    elif invalid_target == "unparseable":
        (base / SECOND_TARGET_PATH).write_bytes(b"\xff")
    else:
        config_path = base / ".localize/config.yaml"
        config = yaml.safe_load(config_path.read_text(encoding="utf-8"))
        config["localization_formats"] = config["localization_formats"][:1]
        config_path.write_text(yaml.safe_dump(config), encoding="utf-8")

    second_feedback = replace(
        _feedback(source_id="45"),
        path=SECOND_TARGET_PATH,
    )
    snapshot = _snapshot(
        pull=_pull(state="closed"),
        feedback=(_feedback(), second_feedback),
        changed_files=(
            ChangedFile(
                path=TARGET_PATH,
                status="modified",
                sha="d" * 40,
                patch="@@ -1 +1 @@\n-old greeting\n+new greeting",
            ),
            ChangedFile(
                path=SECOND_TARGET_PATH,
                status="modified",
                sha="e" * 40,
                patch="@@ -1 +1 @@\n-old error\n+new error",
            ),
        ),
    )

    class CapturingDriver(FakeCodexDriver):
        def __init__(self) -> None:
            super().__init__()
            self.feedback_ids: list[tuple[str, ...]] = []
            self.localization_paths: list[tuple[str, ...]] = []

        def run(self, task, **kwargs):
            manifest = json.loads(
                (task.evidence_dir / "manifest.json").read_text(encoding="utf-8")
            )
            localization = json.loads(
                (task.evidence_dir / "localization.json").read_text(encoding="utf-8")
            )
            self.feedback_ids.append(tuple(manifest["feedback_ids"]))
            self.localization_paths.append(tuple(item["path"] for item in localization))
            return super().run(task, **kwargs)

    driver = CapturingDriver()
    remediation = FakeRemediationRunner()
    with GuardianState(tmp_path / "state.sqlite3") as state:
        controller = _controller(
            tmp_path=tmp_path,
            state=state,
            config=_config(
                GuardianMode.APPLY_OWNED_TRANSLATIONS,
                policies=(_historical_policy(remediation=True),),
            ),
            checkout=checkout,
            provider=FakeSnapshotProvider(()),
            driver=driver,
            broker=broker,
            historical_snapshot_provider=FakeHistoricalSnapshotProvider((snapshot,)),
            historical_checkout_factory=FakeHistoricalCheckoutFactory(
                old_base,
                head,
                tmp_path,
            ),
            current_base_provider=FakeCurrentBaseProvider(),
            remediation_runner=remediation,
        )
        first = controller.poll_once()
        second = controller.poll_once()
        actions = state._connection.execute(  # noqa: SLF001
            """
            SELECT e.event_id, a.status, a.details_json
            FROM actions AS a
            JOIN event_revisions AS e ON e.revision_id = a.event_revision_id
            ORDER BY e.event_id
            """
        ).fetchall()
        assessment = state._connection.execute(  # noqa: SLF001
            """
            SELECT event_revision_ids_json, ignored_event_revision_ids_json
            FROM historical_pull_completions
            WHERE authority_scope = 'assessment'
            """
        ).fetchone()
        assert assessment is not None
        assessed_ids = tuple(json.loads(assessment["event_revision_ids_json"]))
        assessed_events = state._connection.execute(  # noqa: SLF001
            """
            SELECT event_id FROM event_revisions
            WHERE revision_id IN ({})
            """.format(", ".join("?" for _ in assessed_ids)),
            assessed_ids,
        ).fetchall()
        ignored_ids = tuple(json.loads(assessment["ignored_event_revision_ids_json"]))
        ignored_events = state._connection.execute(  # noqa: SLF001
            """
            SELECT event_id FROM event_revisions
            WHERE revision_id IN ({})
            """.format(", ".join("?" for _ in ignored_ids)),
            ignored_ids,
        ).fetchall()

    assert first.failures == ()
    assert first.historical_pull_requests_completed == 1
    assert second.historical_pull_requests_seen == 0
    assert driver.feedback_ids == [("review_comment:44",)]
    assert driver.localization_paths == [(TARGET_PATH,)]
    assert len(remediation.publish_calls) == 1
    assert [
        (replacement.feedback_id, replacement.path)
        for replacement in remediation.publish_calls[0]["replacements"]
    ] == [("review_comment:44", TARGET_PATH)]
    assert [
        (row["event_id"], row["status"], json.loads(row["details_json"])["outcome"])
        for row in actions
    ] == [
        ("44", "completed", "historical_assessed"),
        ("45", "skipped", "historical_target_inapplicable"),
    ]
    assert [row["event_id"] for row in assessed_events] == ["44"]
    assert [row["event_id"] for row in ignored_events] == ["45"]


def test_historical_completion_rechecks_exact_current_values_but_not_noise(
    tmp_path: Path,
    runtime,
) -> None:
    base, head, checkout, _provider, broker, _sequence = runtime
    policy = _historical_policy()
    trusted = _feedback()
    snapshot = _snapshot(pull=_pull(state="closed"), feedback=(trusted,))
    provider = FakeHistoricalSnapshotProvider((snapshot,))
    driver = FakeCodexDriver()
    limits = GuardianLimits(
        max_model_calls_per_day=5,
        daily_cost_limit_usd=5,
        model_call_reservation_usd=1,
        raw_retention_days=90,
    )
    with GuardianState(tmp_path / "state.sqlite3") as state:
        controller = _controller(
            tmp_path=tmp_path,
            state=state,
            config=_config(
                GuardianMode.OBSERVE,
                policies=(policy,),
                limits=limits,
            ),
            checkout=checkout,
            provider=FakeSnapshotProvider(()),
            driver=driver,
            broker=broker,
            historical_snapshot_provider=provider,
            historical_checkout_factory=FakeHistoricalCheckoutFactory(
                base,
                head,
                tmp_path,
            ),
            # Deliberately returns the same SHA: the key is content, not base SHA.
            current_base_provider=FakeCurrentBaseProvider(),
        )
        first = controller.poll_once()

        untrusted = replace(
            trusted,
            source_id="45",
            node_id="node-45",
            author_login="drive-by-user",
            author_id=999,
            body="attacker-controlled noise",
        )
        provider.snapshots = (
            _snapshot(
                pull=_pull(
                    state="closed",
                    updated_at="2026-09-01T12:00:00Z",
                ),
                feedback=(trusted, untrusted),
            ),
        )
        (base / TARGET_PATH).write_text(
            "# formatting-only comment\ngreeting=Старый %0 был отклонён (%1). %2 %3\n",
            encoding="utf-8",
        )
        noise = controller.poll_once()

        (base / TARGET_PATH).write_text(
            "greeting=Текущее другое значение %0 (%1). %2 %3\n",
            encoding="utf-8",
        )
        target_changed = controller.poll_once()
        (base / "l10n/messages_en.properties").write_text(
            "greeting=Current source changed %0 (%1). %2 %3\n",
            encoding="utf-8",
        )
        source_changed = controller.poll_once()

    assert first.historical_pull_requests_seen == 1
    assert noise.historical_pull_requests_seen == 0
    assert target_changed.historical_pull_requests_seen == 1
    assert source_changed.historical_pull_requests_seen == 1
    assert len(driver.calls) == 3


def test_historical_target_restoration_revisits_exact_no_action_state(
    tmp_path: Path,
    runtime,
) -> None:
    base, head, checkout, _provider, broker, _sequence = runtime
    old_base = tmp_path / "old-base"
    shutil.copytree(base, old_base)
    current_target = (base / TARGET_PATH).read_text(encoding="utf-8")
    (base / TARGET_PATH).unlink()
    driver = FakeCodexDriver()
    with GuardianState(tmp_path / "state.sqlite3") as state:
        controller = _controller(
            tmp_path=tmp_path,
            state=state,
            config=_config(
                GuardianMode.OBSERVE,
                policies=(_historical_policy(),),
            ),
            checkout=checkout,
            provider=FakeSnapshotProvider(()),
            driver=driver,
            broker=broker,
            historical_snapshot_provider=FakeHistoricalSnapshotProvider(
                (_snapshot(pull=_pull(state="closed")),)
            ),
            historical_checkout_factory=FakeHistoricalCheckoutFactory(
                old_base,
                head,
                tmp_path,
            ),
            current_base_provider=FakeCurrentBaseProvider(),
        )
        absent = controller.poll_once()
        calls_while_absent = len(driver.calls)
        (base / TARGET_PATH).write_text(current_target, encoding="utf-8")
        restored = controller.poll_once()
        unchanged = controller.poll_once()

    assert absent.failures == ()
    assert absent.historical_pull_requests_seen == 1
    assert absent.historical_pull_requests_completed == 1
    assert calls_while_absent == 0
    assert len(driver.calls) == 1
    assert restored.historical_pull_requests_seen == 1
    assert restored.historical_pull_requests_completed == 1
    assert unchanged.historical_pull_requests_seen == 0


def test_historical_scan_skips_cycle_seen_pulls_then_restarts_with_new_window(
    tmp_path: Path,
    runtime,
) -> None:
    base, head, checkout, _provider, broker, _sequence = runtime
    snapshots = (
        _snapshot(pull=_pull(state="closed")),
        _snapshot(
            pull=_pull(
                state="closed",
                pull_id=501,
                number=13,
                html_url="https://github.com/acme/widgets/pull/13",
            ),
            feedback=(_feedback(pull_number=13, source_id="45"),),
        ),
    )
    provider = FakeHistoricalSnapshotProvider(snapshots)
    policy = replace(
        _historical_policy(),
        closed_pr_backfill=ClosedPrBackfillPolicy(
            lookback_days=90,
            max_prs_per_poll=1,
        ),
    )
    clock = [NOW]
    with GuardianState(tmp_path / "state.sqlite3") as state:
        controller = _controller(
            tmp_path=tmp_path,
            state=state,
            config=_config(GuardianMode.OBSERVE, policies=(policy,)),
            checkout=checkout,
            provider=FakeSnapshotProvider(()),
            driver=FakeCodexDriver(),
            broker=broker,
            historical_snapshot_provider=provider,
            historical_checkout_factory=FakeHistoricalCheckoutFactory(
                base,
                head,
                tmp_path,
            ),
            current_base_provider=FakeCurrentBaseProvider(),
            now=lambda: clock[0],
        )

        first = controller.poll_once()
        clock[0] = NOW + timedelta(days=1)
        second = controller.poll_once()
        clock[0] = NOW + timedelta(days=2)
        third = controller.poll_once()

    assert [call["seen_pulls"] for call in provider.calls] == [
        (),
        ((500, 12),),
        (),
    ]
    assert [call["cutoff"] for call in provider.calls] == [
        NOW - timedelta(days=90),
        NOW - timedelta(days=90),
        NOW + timedelta(days=2) - timedelta(days=90),
    ]
    assert [call["upper_bound"] for call in provider.calls] == [
        NOW,
        NOW,
        NOW + timedelta(days=2),
    ]
    assert first.historical_pull_requests_seen == 1
    assert second.historical_pull_requests_seen == 1
    # A new cycle rehydrates its first item, but the exact trusted digest is
    # already complete and therefore consumes no model work.
    assert third.historical_pull_requests_seen == 0


def test_historical_cursor_advances_poison_but_retries_auth_failed_item(
    tmp_path: Path,
    runtime,
) -> None:
    base, head, checkout, _provider, broker, _sequence = runtime
    snapshot = _snapshot(pull=_pull(state="closed"))

    class PoisonThenSnapshotProvider:
        def __init__(self) -> None:
            self.calls: list[dict[str, object]] = []

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
        ) -> ClosedPullScanResult:
            del excluded_pulls
            self.calls.append(
                {
                    "policy": policy,
                    "previous_feedback": previous_feedback,
                    "cutoff": cutoff,
                    "upper_bound": upper_bound,
                    "max_prs_per_poll": max_prs_per_poll,
                    "seen_pulls": seen_pulls,
                    "priority_pull_groups": priority_pull_groups,
                }
            )
            hydrated = ClosedPullScanItem(
                position=ClosedPullScanPosition(1, 1),
                snapshot=snapshot,
                pull_id=snapshot.pull_request.pull_id,
                pull_number=snapshot.pull_request.number,
                hydration_attempted=True,
            )
            if not seen_pulls:
                return ClosedPullScanResult(
                    items=(
                        ClosedPullScanItem(
                            position=ClosedPullScanPosition(1, 0),
                            pull_id=499,
                            pull_number=11,
                            failure_type="GitHubAPIError",
                            hydration_attempted=True,
                        ),
                        hydrated,
                    ),
                    hydration_attempts=2,
                    cycle_complete=True,
                )
            assert seen_pulls == ((499, 11),)
            return ClosedPullScanResult(
                items=(hydrated,),
                hydration_attempts=1,
                cycle_complete=True,
            )

    historical_provider = PoisonThenSnapshotProvider()
    driver = FakeCodexDriver(error=CodexAuthenticationError("expired"))
    clock = [NOW]
    with GuardianState(tmp_path / "state.sqlite3") as state:
        controller = _controller(
            tmp_path=tmp_path,
            state=state,
            config=_config(
                GuardianMode.OBSERVE,
                policies=(_historical_policy(),),
            ),
            checkout=checkout,
            provider=FakeSnapshotProvider(()),
            driver=driver,
            broker=broker,
            historical_snapshot_provider=historical_provider,
            historical_checkout_factory=FakeHistoricalCheckoutFactory(
                base,
                head,
                tmp_path,
            ),
            current_base_provider=FakeCurrentBaseProvider(),
            now=lambda: clock[0],
        )

        first = controller.poll_once()
        driver.error = None
        clock[0] = NOW + timedelta(days=1)
        second = controller.poll_once()

    assert first.authentication_circuit_open is True
    assert first.failures == ("GitHubAPIError",)
    # The poison item reached a defined skip outcome and advanced. The item
    # that opened the global auth circuit did not, so the next poll resumes it.
    assert [call["seen_pulls"] for call in historical_provider.calls] == [
        (),
        ((499, 11),),
    ]
    assert [call["cutoff"] for call in historical_provider.calls] == [
        NOW - timedelta(days=90),
        NOW - timedelta(days=90),
    ]
    assert second.authentication_circuit_open is False
    assert second.historical_pull_requests_completed == 1


def test_deterministic_closed_pr_policy_rejection_completes_all_scopes(
    tmp_path: Path,
    runtime,
) -> None:
    base, head, checkout, _provider, broker, _sequence = runtime
    pull = _pull(state="closed")
    snapshot = _snapshot(
        pull=pull,
        changed_files=(
            ChangedFile(path=TARGET_PATH, status="modified", sha="d" * 40),
            ChangedFile(path="README.md", status="modified", sha="f" * 40),
        ),
    )
    order: list[str] = []
    historical_provider = FakeHistoricalSnapshotProvider(
        (snapshot,),
        sequence=order,
    )
    remediation = FakeRemediationRunner(sequence=order)
    current_provider = FakeCurrentBaseProvider()
    historical_checkout = FakeHistoricalCheckoutFactory(base, head, tmp_path)
    driver = FakeCodexDriver()
    with GuardianState(tmp_path / "state.sqlite3") as state:
        outcome = _controller(
            tmp_path=tmp_path,
            state=state,
            config=_config(
                GuardianMode.APPLY_OWNED_TRANSLATIONS,
                policies=(_historical_policy(remediation=True),),
            ),
            checkout=checkout,
            provider=FakeSnapshotProvider(()),
            driver=driver,
            broker=broker,
            historical_snapshot_provider=historical_provider,
            historical_checkout_factory=historical_checkout,
            current_base_provider=current_provider,
            remediation_runner=remediation,
        ).poll_once()
        terminal_status = state.latest_health("guardian_history")

    assert outcome.historical_policy_rejections == 1
    assert outcome.historical_pull_requests_completed == 1
    assert remediation.begin_calls == 1
    assert len(remediation.recover_calls) == 1
    assert remediation.publish_calls == []
    assert order[:2] == [
        "remediation-recover:acme/widgets",
        "history:acme/widgets",
    ]
    assert len(current_provider.calls) == 3
    assert all(
        policy == _historical_policy(remediation=True)
        for policy in current_provider.calls
    )
    assert len(checkout.workspaces) == 1
    assert len(historical_checkout.revisions) == 1
    assert historical_checkout.revisions[0].sha == BASE_SHA
    assert historical_checkout.revisions[0].pull_number is None
    assert driver.calls == []
    assert terminal_status is not None
    assert terminal_status.details["outcome"] == "policy_rejected"


def test_historical_prevention_aggregates_candidates_and_completes_its_scope(
    tmp_path: Path,
    runtime,
) -> None:
    base, head, checkout, _provider, broker, _sequence = runtime
    first_pull = _pull(state="closed")
    second_pull = _pull(
        state="closed",
        pull_id=501,
        number=13,
        html_url="https://github.com/acme/widgets/pull/13",
    )
    snapshots = (
        _snapshot(pull=first_pull),
        _snapshot(
            pull=second_pull,
            feedback=(_feedback(pull_number=13, source_id="45"),),
        ),
    )
    provider = FakeHistoricalSnapshotProvider(snapshots)
    prevention = FakePreventionRunner()
    policy = replace(
        _historical_policy(),
        prevention=_prevention_policy(),
    )
    with GuardianState(tmp_path / "state.sqlite3") as state:
        outcome = _controller(
            tmp_path=tmp_path,
            state=state,
            config=_config(GuardianMode.PROPOSE_PREVENTION, policies=(policy,)),
            checkout=checkout,
            provider=FakeSnapshotProvider(()),
            driver=RecurrenceCodexDriver(),
            broker=broker,
            prevention_runner=prevention,
            historical_snapshot_provider=provider,
            historical_checkout_factory=FakeHistoricalCheckoutFactory(
                base,
                head,
                tmp_path,
            ),
            current_base_provider=FakeCurrentBaseProvider(),
        ).poll_once()

    assert outcome.historical_pull_requests_completed == 2
    assert len(prevention.propose_calls) == 1
    proposal = prevention.propose_calls[0]
    proposed = proposal["recurrence_candidates"]
    assert len(proposed) == 2
    assert tuple(source.pr_number for source in proposal["source_pulls"]) == (
        12,
        13,
    )
    assert len(proposal["source_event_revision_ids"]) == 2
    assert callable(proposal["require_exact_sources_still_closed"])
    assert [
        tuple(source.pr_number for source in call["sources"])
        for call in provider.exact_calls
    ] == [(12,), (12,), (13,), (13,)]


def test_transient_historical_checkout_failure_remains_retryable(
    tmp_path: Path,
    runtime,
) -> None:
    base, head, checkout, _provider, broker, _sequence = runtime
    pull = _pull(state="closed")
    historical_provider = FakeHistoricalSnapshotProvider((_snapshot(pull=pull),))
    historical_checkout = FakeHistoricalCheckoutFactory(
        base,
        head,
        tmp_path,
        fail_once=OSError("temporary checkout failure"),
    )
    driver = FakeCodexDriver()
    with GuardianState(tmp_path / "state.sqlite3") as state:
        controller = _controller(
            tmp_path=tmp_path,
            state=state,
            config=_config(
                GuardianMode.OBSERVE,
                policies=(_historical_policy(),),
            ),
            checkout=checkout,
            provider=FakeSnapshotProvider(()),
            driver=driver,
            broker=broker,
            historical_snapshot_provider=historical_provider,
            historical_checkout_factory=historical_checkout,
            current_base_provider=FakeCurrentBaseProvider(),
        )
        first = controller.poll_once()
        second = controller.poll_once()

    assert first.failures == ("OSError",)
    assert first.historical_pull_requests_completed == 0
    assert second.historical_pull_requests_completed == 1
    assert len(historical_provider.calls) == 2
    assert len(driver.calls) == 1


def test_historical_assessment_deadline_stops_remaining_candidates(
    tmp_path: Path,
    runtime,
) -> None:
    base, head, checkout, _provider, broker, _sequence = runtime
    snapshots = (
        _snapshot(pull=_pull(state="closed")),
        _snapshot(
            pull=_pull(
                state="closed",
                pull_id=501,
                number=13,
                html_url="https://github.com/acme/widgets/pull/13",
            ),
            feedback=(_feedback(pull_number=13, source_id="45"),),
        ),
    )
    driver = FakeCodexDriver(
        error=PollDeadlineExceeded("Guardian poll deadline was exceeded.")
    )
    with GuardianState(tmp_path / "state.sqlite3") as state:
        outcome = _controller(
            tmp_path=tmp_path,
            state=state,
            config=_config(
                GuardianMode.OBSERVE,
                policies=(_historical_policy(),),
            ),
            checkout=checkout,
            provider=FakeSnapshotProvider(()),
            driver=driver,
            broker=broker,
            historical_snapshot_provider=FakeHistoricalSnapshotProvider(snapshots),
            historical_checkout_factory=FakeHistoricalCheckoutFactory(
                base,
                head,
                tmp_path,
            ),
            current_base_provider=FakeCurrentBaseProvider(),
        ).poll_once()

    assert outcome.failures == ("PollDeadlineExceeded",)
    assert outcome.historical_pull_requests_completed == 0
    assert len(driver.calls) == 1


def test_failed_edge_hydration_is_prioritized_after_lookback_moves(
    tmp_path: Path,
    runtime,
) -> None:
    base, head, checkout, _provider, broker, _sequence = runtime
    policy = replace(
        _historical_policy(),
        closed_pr_backfill=ClosedPrBackfillPolicy(
            lookback_days=1,
            max_prs_per_poll=1,
        ),
    )
    snapshot = _snapshot(
        pull=_pull(
            state="closed",
            updated_at=(NOW - timedelta(days=1)).isoformat(),
        )
    )
    historical_provider = LookbackEdgeHistoricalSnapshotProvider(
        snapshot,
        fail_first_hydration=True,
    )
    clock = [NOW]
    with GuardianState(tmp_path / "state.sqlite3") as state:
        controller = _controller(
            tmp_path=tmp_path,
            state=state,
            config=_config(GuardianMode.OBSERVE, policies=(policy,)),
            checkout=checkout,
            provider=FakeSnapshotProvider(()),
            driver=FakeCodexDriver(),
            broker=broker,
            historical_snapshot_provider=historical_provider,
            historical_checkout_factory=FakeHistoricalCheckoutFactory(
                base,
                head,
                tmp_path,
            ),
            current_base_provider=FakeCurrentBaseProvider(),
            now=lambda: clock[0],
        )
        first = controller.poll_once()
        clock[0] = NOW + timedelta(days=1)
        second = controller.poll_once()

    assert first.failures == ("GitHubAPIError",)
    assert first.historical_pull_requests_completed == 0
    assert second.historical_pull_requests_completed == 1
    assert [call["cutoff"] for call in historical_provider.calls] == [
        NOW - timedelta(days=1),
        NOW,
    ]
    assert [call["priority_pull_groups"] for call in historical_provider.calls] == [
        (),
        (((500, 12),),),
    ]


def test_persistent_retry_does_not_starve_ordinary_history_at_batch_one(
    tmp_path: Path,
    runtime,
) -> None:
    base, head, checkout, _provider, broker, _sequence = runtime
    failed_pull = _pull(state="closed")
    ordinary = _snapshot(
        pull=_pull(
            state="closed",
            pull_id=501,
            number=13,
            html_url="https://github.com/acme/widgets/pull/13",
        ),
        feedback=(_feedback(pull_number=13, source_id="45"),),
    )
    calls: list[dict[str, object]] = []

    def historical_provider(
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
        del policy, previous_feedback, cutoff, upper_bound, excluded_pulls
        calls.append(
            {
                "seen_pulls": seen_pulls,
                "priority_pull_groups": priority_pull_groups,
            }
        )
        if len(calls) == 1:
            return ClosedPullScanResult(
                items=(
                    ClosedPullScanItem(
                        position=ClosedPullScanPosition(1, 0),
                        pull_id=failed_pull.pull_id,
                        pull_number=failed_pull.number,
                        failure_type="GitHubAPIError",
                        hydration_attempted=True,
                    ),
                ),
                hydration_attempts=max_prs_per_poll,
                cycle_complete=False,
            )
        assert max_prs_per_poll == 1
        return ClosedPullScanResult(
            items=(
                ClosedPullScanItem(
                    position=ClosedPullScanPosition(1, 1),
                    snapshot=ordinary,
                    pull_id=ordinary.pull_request.pull_id,
                    pull_number=ordinary.pull_request.number,
                    hydration_attempted=True,
                ),
            ),
            hydration_attempts=1,
            cycle_complete=True,
        )

    policy = replace(
        _historical_policy(),
        closed_pr_backfill=ClosedPrBackfillPolicy(
            lookback_days=90,
            max_prs_per_poll=1,
        ),
    )
    with GuardianState(tmp_path / "state.sqlite3") as state:
        controller = _controller(
            tmp_path=tmp_path,
            state=state,
            config=_config(GuardianMode.OBSERVE, policies=(policy,)),
            checkout=checkout,
            provider=FakeSnapshotProvider(()),
            driver=FakeCodexDriver(),
            broker=broker,
            historical_snapshot_provider=historical_provider,
            historical_checkout_factory=FakeHistoricalCheckoutFactory(
                base,
                head,
                tmp_path,
            ),
            current_base_provider=FakeCurrentBaseProvider(),
        )
        first = controller.poll_once()
        second = controller.poll_once()

    assert first.failures == ("GitHubAPIError",)
    assert second.historical_pull_requests_completed == 1
    assert calls == [
        {"seen_pulls": (), "priority_pull_groups": ()},
        {"seen_pulls": ((500, 12),), "priority_pull_groups": ()},
    ]


def test_persistent_retries_each_run_once_per_fresh_cycle_at_batch_one(
    tmp_path: Path,
    runtime,
) -> None:
    base, head, checkout, _provider, broker, _sequence = runtime
    identities = ((500, 12), (501, 13))
    calls: list[dict[str, object]] = []

    def historical_provider(
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
        del policy, previous_feedback, cutoff, upper_bound, excluded_pulls
        calls.append(
            {
                "seen_pulls": seen_pulls,
                "priority_pull_groups": priority_pull_groups,
            }
        )
        if len(calls) <= 2:
            identity = identities[len(calls) - 1]
        else:
            assert len(priority_pull_groups) == 1
            (identity,) = priority_pull_groups[0]
        return ClosedPullScanResult(
            items=(
                ClosedPullScanItem(
                    position=ClosedPullScanPosition(1, len(calls) - 1),
                    pull_id=identity[0],
                    pull_number=identity[1],
                    failure_type="GitHubAPIError",
                    hydration_attempted=True,
                ),
            ),
            hydration_attempts=max_prs_per_poll,
            cycle_complete=len(calls) != 1,
        )

    policy = replace(
        _historical_policy(),
        closed_pr_backfill=ClosedPrBackfillPolicy(
            lookback_days=90,
            max_prs_per_poll=1,
        ),
    )
    with GuardianState(tmp_path / "state.sqlite3") as state:
        controller = _controller(
            tmp_path=tmp_path,
            state=state,
            config=_config(GuardianMode.OBSERVE, policies=(policy,)),
            checkout=checkout,
            provider=FakeSnapshotProvider(()),
            driver=FakeCodexDriver(),
            broker=broker,
            historical_snapshot_provider=historical_provider,
            historical_checkout_factory=FakeHistoricalCheckoutFactory(
                base,
                head,
                tmp_path,
            ),
            current_base_provider=FakeCurrentBaseProvider(),
        )

        outcomes = tuple(controller.poll_once() for _ in range(4))

    assert [outcome.failures for outcome in outcomes] == [
        ("GitHubAPIError",),
        ("GitHubAPIError",),
        ("GitHubAPIError",),
        ("GitHubAPIError",),
    ]
    assert calls == [
        {"seen_pulls": (), "priority_pull_groups": ()},
        {"seen_pulls": ((500, 12),), "priority_pull_groups": ()},
        {"seen_pulls": (), "priority_pull_groups": (((500, 12),),)},
        {
            "seen_pulls": ((500, 12),),
            "priority_pull_groups": (((501, 13),),),
        },
    ]


def test_operator_quarantined_retry_is_excluded_from_priority_and_discovery(
    tmp_path: Path,
    runtime,
) -> None:
    base, head, checkout, _provider, broker, _sequence = runtime
    policy = replace(
        _historical_policy(),
        closed_pr_backfill=ClosedPrBackfillPolicy(
            lookback_days=90,
            max_prs_per_poll=1,
        ),
    )
    config = _config(GuardianMode.OBSERVE, policies=(policy,))
    driver = FakeCodexDriver()
    policy_digest = guardian_controller._historical_policy_digest(
        config=config,
        policy=policy,
        model=driver.model,
        pipeline_config_bundle_digest=(
            guardian_controller._base_pipeline_config_bundle_digest(
                config_root=base,
                config_relative_path=policy.pipeline_config_path,
            )
        ),
    )
    quarantined_identity = (500, 12)
    calls: list[dict[str, object]] = []

    def historical_provider(
        selected_policy: RepositoryPolicy,
        previous_feedback: tuple[FeedbackRevision, ...],
        *,
        cutoff: datetime,
        upper_bound: datetime,
        max_prs_per_poll: int,
        seen_pulls: tuple[tuple[int, int], ...],
        excluded_pulls: tuple[tuple[int, int], ...],
        priority_pull_groups: tuple[tuple[tuple[int, int], ...], ...],
    ) -> ClosedPullScanResult:
        del selected_policy, previous_feedback, cutoff, upper_bound
        calls.append(
            {
                "max_prs_per_poll": max_prs_per_poll,
                "seen_pulls": seen_pulls,
                "excluded_pulls": excluded_pulls,
                "priority_pull_groups": priority_pull_groups,
            }
        )
        return ClosedPullScanResult(
            items=(),
            hydration_attempts=0,
            cycle_complete=True,
        )

    with GuardianState(tmp_path / "state.sqlite3") as state:
        retry_identity = {
            "repository": policy.base_repo,
            "repository_id": policy.base_repo_id,
            "policy_digest": policy_digest,
            "pull_id": quarantined_identity[0],
            "pr_number": quarantined_identity[1],
        }
        state.record_historical_pull_retry(
            **retry_identity,
            failure_type="GitHubAPIError",
            failed_at=NOW - timedelta(minutes=1),
        )
        state.record_historical_pull_retry_resolution(
            **retry_identity,
            resolution="operator_quarantined",
            terminal_local_skip_acknowledged=True,
            occurred_at=NOW,
        )
        controller = _controller(
            tmp_path=tmp_path,
            state=state,
            config=config,
            checkout=checkout,
            provider=FakeSnapshotProvider(()),
            driver=driver,
            broker=broker,
            historical_snapshot_provider=historical_provider,
            historical_checkout_factory=FakeHistoricalCheckoutFactory(
                base,
                head,
                tmp_path,
            ),
            current_base_provider=FakeCurrentBaseProvider(),
        )

        outcome = controller.poll_once()

    assert outcome.failures == ()
    assert calls == [
        {
            "max_prs_per_poll": 1,
            "seen_pulls": (),
            "excluded_pulls": (quarantined_identity,),
            "priority_pull_groups": (),
        }
    ]


def test_operator_quarantine_vetoes_exact_source_reauthorization(
    tmp_path: Path,
    runtime,
) -> None:
    base, head, checkout, _provider, broker, _sequence = runtime
    policy = _historical_policy(remediation=True)
    source = _retry_source()
    historical = FakeHistoricalSnapshotProvider(
        (_snapshot(pull=_pull(state="closed")),)
    )

    with GuardianState(tmp_path / "state.sqlite3") as state:
        retry_identity = {
            "repository": source.repository,
            "repository_id": source.repository_id,
            "policy_digest": source.policy_digest,
            "pull_id": source.pull_id,
            "pr_number": source.pr_number,
        }
        state.record_historical_pull_retry(
            **retry_identity,
            failure_type="HistoricalScopeIncomplete",
            failed_at=NOW - timedelta(minutes=1),
        )
        state.record_historical_pull_retry_resolution(
            **retry_identity,
            resolution="operator_quarantined",
            terminal_local_skip_acknowledged=True,
            occurred_at=NOW,
        )
        controller = _controller(
            tmp_path=tmp_path,
            state=state,
            config=_config(
                GuardianMode.APPLY_OWNED_TRANSLATIONS,
                policies=(policy,),
            ),
            checkout=checkout,
            provider=FakeSnapshotProvider(()),
            driver=FakeCodexDriver(),
            broker=broker,
            historical_snapshot_provider=historical,
            historical_checkout_factory=FakeHistoricalCheckoutFactory(
                base,
                head,
                tmp_path,
            ),
            current_base_provider=FakeCurrentBaseProvider(),
            remediation_runner=FakeRemediationRunner(),
        )

        with pytest.raises(
            RemediationSourceAuthorityError,
            match="operator quarantine",
        ):
            controller._require_exact_historical_sources_still_closed(
                policy=policy,
                sources=(source,),
                event_revision_ids=(),
                operator_config=None,
                require_live_lease=lambda: None,
            )

    assert historical.exact_calls == []


@pytest.mark.parametrize("mutation", ("lifecycle", "feedback", "base", "head"))
def test_historical_source_race_after_local_checkout_stops_publication_guard(
    mutation: str,
    tmp_path: Path,
    runtime,
) -> None:
    base, head, checkout, _provider, broker, _sequence = runtime
    policy = _historical_policy(remediation=True)
    original = _snapshot(pull=_pull(state="closed"))
    mutated = original
    if mutation == "lifecycle":
        mutated = replace(
            original,
            pull_request=replace(original.pull_request, state="open"),
        )
    elif mutation == "feedback":
        mutated = replace(
            original,
            feedback=(
                replace(
                    original.feedback[0],
                    body="Trusted feedback changed during local checkout.",
                    updated_at="2026-08-30T11:00:00Z",
                ),
            ),
        )
    elif mutation == "base":
        mutated = replace(
            original,
            pull_request=replace(original.pull_request, base_sha="8" * 40),
        )
    else:
        mutated = replace(
            original,
            pull_request=replace(original.pull_request, head_sha="9" * 40),
        )

    calls = 0

    def exact_source_provider(
        _policy: RepositoryPolicy,
        _sources: tuple[HistoricalPullReference, ...],
    ) -> tuple[PullRequestFeedbackSnapshot, ...]:
        nonlocal calls
        calls += 1
        return (original if calls == 1 else mutated,)

    pull = original.pull_request
    source = HistoricalPullReference(
        repository=policy.base_repo,
        repository_id=policy.base_repo_id,
        pull_id=pull.pull_id,
        pr_number=pull.number,
        pull_revision_digest="a" * 64,
        authority_digest=_authorized_historical_digest(policy, original),
        policy_digest="b" * 64,
        head_sha=pull.head_sha,
        base_sha=pull.base_sha,
    )
    with GuardianState(tmp_path / "state.sqlite3") as state:
        controller = _controller(
            tmp_path=tmp_path,
            state=state,
            config=_config(
                GuardianMode.APPLY_OWNED_TRANSLATIONS,
                policies=(policy,),
            ),
            checkout=checkout,
            provider=FakeSnapshotProvider(()),
            driver=FakeCodexDriver(),
            broker=broker,
            historical_snapshot_provider=FakeHistoricalSnapshotProvider((original,)),
            historical_source_snapshot_provider=exact_source_provider,
            historical_checkout_factory=FakeHistoricalCheckoutFactory(
                base,
                head,
                tmp_path,
            ),
            current_base_provider=FakeCurrentBaseProvider(),
            remediation_runner=FakeRemediationRunner(),
        )

        with pytest.raises(
            RemediationSourceAuthorityError,
            match="changed during authority validation",
        ):
            controller._require_exact_historical_sources_still_closed(
                policy=policy,
                sources=(source,),
                event_revision_ids=(),
                operator_config=None,
                require_live_lease=lambda: None,
            )

    assert calls == 2


def test_historical_source_revalidation_survives_base_repository_rename(
    tmp_path: Path,
    runtime,
) -> None:
    base, head, checkout, _provider, broker, _sequence = runtime
    original_policy = _historical_policy(remediation=True)
    original = _snapshot(pull=_pull(state="closed"))
    source = HistoricalPullReference(
        repository=original_policy.base_repo,
        repository_id=original_policy.base_repo_id,
        pull_id=original.pull_request.pull_id,
        pr_number=original.pull_request.number,
        pull_revision_digest="a" * 64,
        authority_digest=_authorized_historical_digest(original_policy, original),
        policy_digest="b" * 64,
        head_sha=original.pull_request.head_sha,
        base_sha=original.pull_request.base_sha,
    )
    renamed_policy = replace(
        original_policy,
        base_repo="acme/renamed-widgets",
    )
    renamed = guardian_controller._repository_route_alias(
        original,
        repository=renamed_policy.base_repo,
    )
    calls = 0

    def exact_source_provider(
        policy: RepositoryPolicy,
        sources: tuple[HistoricalPullReference, ...],
    ) -> tuple[PullRequestFeedbackSnapshot, ...]:
        nonlocal calls
        calls += 1
        assert policy == renamed_policy
        assert sources == (source,)
        return (renamed,)

    with GuardianState(tmp_path / "state.sqlite3") as state:
        controller = _controller(
            tmp_path=tmp_path,
            state=state,
            config=_config(
                GuardianMode.APPLY_OWNED_TRANSLATIONS,
                policies=(renamed_policy,),
            ),
            checkout=checkout,
            provider=FakeSnapshotProvider(()),
            driver=FakeCodexDriver(),
            broker=broker,
            historical_snapshot_provider=FakeHistoricalSnapshotProvider((renamed,)),
            historical_source_snapshot_provider=exact_source_provider,
            historical_checkout_factory=FakeHistoricalCheckoutFactory(
                base,
                head,
                tmp_path,
            ),
            current_base_provider=FakeCurrentBaseProvider(),
            remediation_runner=FakeRemediationRunner(),
        )

        controller._require_exact_historical_sources_still_closed(
            policy=renamed_policy,
            sources=(source,),
            event_revision_ids=(),
            operator_config=None,
            require_live_lease=lambda: None,
        )

    assert calls == 2


def test_historical_publication_guard_leaves_source_as_last_remote_read(
    tmp_path: Path,
    runtime,
) -> None:
    base, head, checkout, _provider, broker, _sequence = runtime
    policy = _historical_policy(remediation=True)
    snapshot = _snapshot(pull=_pull(state="closed"))
    sequence: list[str] = []

    class SequencedHistoricalProvider(FakeHistoricalSnapshotProvider):
        def revalidate(self, policy, sources):
            sequence.append("remote:source")
            return super().revalidate(policy, sources)

    class PublicationBoundaryRunner(FakeRemediationRunner):
        def publish(self, **kwargs: object) -> RemediationBatchOutcome:
            self.publish_calls.append(dict(kwargs))
            guard = kwargs["require_exact_sources_still_closed"]
            assert callable(guard)
            guard(
                tuple(kwargs["source_pulls"]),
                tuple(kwargs["event_revision_ids"]),
            )
            sequence.append("remote:draft-post")
            return self.publish_result

    remediation = PublicationBoundaryRunner()
    with GuardianState(tmp_path / "state.sqlite3") as state:
        outcome = _controller(
            tmp_path=tmp_path,
            state=state,
            config=_config(
                GuardianMode.APPLY_OWNED_TRANSLATIONS,
                policies=(policy,),
            ),
            checkout=checkout,
            provider=FakeSnapshotProvider(()),
            driver=FakeCodexDriver(),
            broker=broker,
            historical_snapshot_provider=FakeHistoricalSnapshotProvider((snapshot,)),
            historical_source_snapshot_provider=SequencedHistoricalProvider(
                (snapshot,)
            ).revalidate,
            historical_checkout_factory=FakeHistoricalCheckoutFactory(
                base,
                head,
                tmp_path,
            ),
            current_base_provider=FakeCurrentBaseProvider(sequence=sequence),
            remediation_runner=remediation,
        ).poll_once()

    assert outcome.failures == ()
    assert remediation.publish_calls
    post_index = sequence.index("remote:draft-post")
    assert sequence[post_index - 1] == "remote:source"


def test_failed_open_scan_blocks_historical_remote_writes_for_repository(
    tmp_path: Path,
    runtime,
) -> None:
    base, head, checkout, _provider, broker, _sequence = runtime
    policy = _historical_policy(remediation=True)
    historical = FakeHistoricalSnapshotProvider(
        (_snapshot(pull=_pull(state="closed")),)
    )
    remediation = FakeRemediationRunner()

    def failed_open_scan(
        _policy: RepositoryPolicy,
        _previous: tuple[FeedbackRevision, ...],
    ) -> tuple[PullRequestFeedbackSnapshot, ...]:
        raise RuntimeError("open listing failed")

    with GuardianState(tmp_path / "state.sqlite3") as state:
        outcome = _controller(
            tmp_path=tmp_path,
            state=state,
            config=_config(
                GuardianMode.APPLY_OWNED_TRANSLATIONS,
                policies=(policy,),
            ),
            checkout=checkout,
            provider=failed_open_scan,  # type: ignore[arg-type]
            driver=FakeCodexDriver(),
            broker=broker,
            historical_snapshot_provider=historical,
            historical_checkout_factory=FakeHistoricalCheckoutFactory(
                base,
                head,
                tmp_path,
            ),
            current_base_provider=FakeCurrentBaseProvider(),
            remediation_runner=remediation,
        ).poll_once()

    assert outcome.failures == ("RuntimeError",)
    assert historical.calls == []
    assert remediation.publish_calls == []


def test_lazy_snapshot_provider_never_loads_repository_wide_feedback_history(
    tmp_path: Path,
    runtime,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    base, head, checkout, _provider, broker, _sequence = runtime
    policy = _historical_policy()

    class LazyProvider(FakeSnapshotProvider):
        loads_previous_feedback_per_pull = True

    original = GuardianState.latest_event_revisions
    calls: list[int | None] = []

    def bounded_latest(
        state: GuardianState,
        *,
        repository: str | None = None,
        pr_number: int | None = None,
    ):
        calls.append(pr_number)
        if repository is not None and pr_number is None:
            raise AssertionError("repository-wide feedback history was loaded")
        return original(state, repository=repository, pr_number=pr_number)

    monkeypatch.setattr(GuardianState, "latest_event_revisions", bounded_latest)
    with GuardianState(tmp_path / "state.sqlite3") as state:
        outcome = _controller(
            tmp_path=tmp_path,
            state=state,
            config=_config(GuardianMode.OBSERVE, policies=(policy,)),
            checkout=checkout,
            provider=LazyProvider(()),
            driver=FakeCodexDriver(),
            broker=broker,
            historical_snapshot_provider=FakeHistoricalSnapshotProvider(()),
            historical_checkout_factory=FakeHistoricalCheckoutFactory(
                base,
                head,
                tmp_path,
            ),
            current_base_provider=FakeCurrentBaseProvider(),
        ).poll_once()

    assert outcome.failures == ()
    assert calls == []


def test_open_pull_processing_queries_only_its_pending_feedback_workset(
    tmp_path: Path,
    runtime,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Avoid cross-PR pending-work scans while processing an exact pull."""
    _base, _head, checkout, provider, broker, _sequence = runtime
    original = GuardianState.pending_event_revisions
    calls: list[int | None] = []

    def bounded_pending(
        state: GuardianState,
        *,
        repository: str | None = None,
        pr_number: int | None = None,
        locale: str | None = None,
        mode: GuardianMode | str | None = None,
        policy_digest: str | None = None,
        limit: int = 500,
    ):
        """Record the exact PR boundary used for pending-feedback selection."""
        calls.append(pr_number)
        if repository is not None and pr_number is None:
            raise AssertionError("repository-wide pending feedback was loaded")
        return original(
            state,
            repository=repository,
            pr_number=pr_number,
            locale=locale,
            mode=mode,
            policy_digest=policy_digest,
            limit=limit,
        )

    monkeypatch.setattr(GuardianState, "pending_event_revisions", bounded_pending)
    with GuardianState(tmp_path / "state.sqlite3") as state:
        outcome = _controller(
            tmp_path=tmp_path,
            state=state,
            config=_config(GuardianMode.OBSERVE),
            checkout=checkout,
            provider=provider,
            driver=FakeCodexDriver(),
            broker=broker,
        ).poll_once()

    assert outcome.failures == ()
    assert calls == [12]


def test_open_translation_scope_defers_overlapping_historical_remediation(
    tmp_path: Path,
    runtime,
) -> None:
    base, head, checkout, _provider, broker, _sequence = runtime
    policy = _historical_policy(remediation=True)
    open_snapshot = _snapshot(pull=_pull(state="open"))
    closed_snapshot = _snapshot(
        pull=_pull(
            state="closed",
            pull_id=501,
            number=13,
            html_url="https://github.com/acme/widgets/pull/13",
        ),
        feedback=(_feedback(pull_number=13, source_id="45"),),
    )
    remediation = FakeRemediationRunner()
    driver = FakeCodexDriver()

    with GuardianState(tmp_path / "state.sqlite3") as state:
        outcome = _controller(
            tmp_path=tmp_path,
            state=state,
            config=_config(
                GuardianMode.APPLY_OWNED_TRANSLATIONS,
                policies=(policy,),
            ),
            checkout=checkout,
            provider=FakeSnapshotProvider((open_snapshot,), sequence=_sequence),
            driver=driver,
            broker=broker,
            historical_snapshot_provider=FakeHistoricalSnapshotProvider(
                (closed_snapshot,)
            ),
            historical_checkout_factory=FakeHistoricalCheckoutFactory(
                base,
                head,
                tmp_path,
            ),
            current_base_provider=FakeCurrentBaseProvider(),
            remediation_runner=remediation,
        ).poll_once()

    assert outcome.applied_commits == (COMMIT_SHA,)
    assert outcome.remediation_items_deferred == 1
    assert remediation.publish_calls == []
    assert len(driver.calls) == 2


@pytest.mark.parametrize("failure_stage", ["checkout", "assessment"])
def test_failed_edge_processing_is_prioritized_after_lookback_moves(
    tmp_path: Path,
    runtime,
    failure_stage: str,
) -> None:
    base, head, checkout, _provider, broker, _sequence = runtime
    policy = replace(
        _historical_policy(),
        closed_pr_backfill=ClosedPrBackfillPolicy(
            lookback_days=1,
            max_prs_per_poll=1,
        ),
    )
    snapshot = _snapshot(
        pull=_pull(
            state="closed",
            updated_at=(NOW - timedelta(days=1)).isoformat(),
        )
    )
    historical_provider = LookbackEdgeHistoricalSnapshotProvider(snapshot)
    historical_checkout = FakeHistoricalCheckoutFactory(
        base,
        head,
        tmp_path,
        fail_once=(
            OSError("temporary checkout failure")
            if failure_stage == "checkout"
            else None
        ),
    )
    driver = FakeCodexDriver(
        error=(
            OSError("temporary assessment failure")
            if failure_stage == "assessment"
            else None
        )
    )
    clock = [NOW]
    with GuardianState(tmp_path / "state.sqlite3") as state:
        controller = _controller(
            tmp_path=tmp_path,
            state=state,
            config=_config(GuardianMode.OBSERVE, policies=(policy,)),
            checkout=checkout,
            provider=FakeSnapshotProvider(()),
            driver=driver,
            broker=broker,
            historical_snapshot_provider=historical_provider,
            historical_checkout_factory=historical_checkout,
            current_base_provider=FakeCurrentBaseProvider(),
            now=lambda: clock[0],
        )
        first = controller.poll_once()
        driver.error = None
        clock[0] = NOW + timedelta(days=1)
        second = controller.poll_once()

    assert first.failures == ("OSError",)
    assert first.historical_pull_requests_completed == 0
    assert second.historical_pull_requests_completed == 1
    assert [call["cutoff"] for call in historical_provider.calls] == [
        NOW - timedelta(days=1),
        NOW,
    ]
    assert [call["priority_pull_groups"] for call in historical_provider.calls] == [
        (),
        (((500, 12),),),
    ]


def test_changed_current_base_defers_completion_and_retries_outside_lookback(
    tmp_path: Path,
    runtime,
) -> None:
    base, head, checkout, _provider, broker, _sequence = runtime
    policy = replace(
        _historical_policy(),
        closed_pr_backfill=ClosedPrBackfillPolicy(
            lookback_days=1,
            max_prs_per_poll=1,
        ),
    )
    snapshot = _snapshot(
        pull=_pull(
            state="closed",
            updated_at=(NOW - timedelta(days=1)).isoformat(),
        )
    )
    historical_provider = LookbackEdgeHistoricalSnapshotProvider(snapshot)
    current_provider = FakeCurrentBaseProvider()

    class MovingBaseDriver(FakeCodexDriver):
        def run(self, *args: object, **kwargs: object) -> CodexResult:
            result = super().run(*args, **kwargs)
            current_provider.sha = "f" * 40
            return result

    driver = MovingBaseDriver()
    clock = [NOW]
    with GuardianState(tmp_path / "state.sqlite3") as state:
        controller = _controller(
            tmp_path=tmp_path,
            state=state,
            config=_config(GuardianMode.OBSERVE, policies=(policy,)),
            checkout=checkout,
            provider=FakeSnapshotProvider(()),
            driver=driver,
            broker=broker,
            historical_snapshot_provider=historical_provider,
            historical_checkout_factory=FakeHistoricalCheckoutFactory(
                base,
                head,
                tmp_path,
            ),
            current_base_provider=current_provider,
            now=lambda: clock[0],
        )
        first = controller.poll_once()
        clock[0] = NOW + timedelta(days=1)
        second = controller.poll_once()

    assert first.failures == ("_HistoricalCurrentBaseChanged",)
    assert first.historical_pull_requests_completed == 0
    assert second.historical_pull_requests_completed == 1
    assert [call["priority_pull_groups"] for call in historical_provider.calls] == [
        (),
        (((500, 12),),),
    ]
    assert len(driver.calls) == 1


def test_failed_edge_prevention_scope_is_prioritized_after_lookback_moves(
    tmp_path: Path,
    runtime,
) -> None:
    base, head, checkout, _provider, broker, _sequence = runtime
    policy = replace(
        _historical_policy(),
        prevention=_prevention_policy(),
        closed_pr_backfill=ClosedPrBackfillPolicy(
            lookback_days=1,
            max_prs_per_poll=1,
        ),
    )
    snapshot = _snapshot(
        pull=_pull(
            state="closed",
            updated_at=(NOW - timedelta(days=1)).isoformat(),
        )
    )
    historical_provider = LookbackEdgeHistoricalSnapshotProvider(snapshot)
    prevention = FakePreventionRunner(error=RuntimeError("temporary failure"))
    driver = RecurrenceCodexDriver()
    clock = [NOW]
    with GuardianState(tmp_path / "state.sqlite3") as state:
        controller = _controller(
            tmp_path=tmp_path,
            state=state,
            config=_config(GuardianMode.PROPOSE_PREVENTION, policies=(policy,)),
            checkout=checkout,
            provider=FakeSnapshotProvider(()),
            driver=driver,
            broker=broker,
            prevention_runner=prevention,
            historical_snapshot_provider=historical_provider,
            historical_checkout_factory=FakeHistoricalCheckoutFactory(
                base,
                head,
                tmp_path,
            ),
            current_base_provider=FakeCurrentBaseProvider(),
            now=lambda: clock[0],
        )
        first = controller.poll_once()
        prevention.error = None
        clock[0] = NOW + timedelta(days=1)
        second = controller.poll_once()

    assert first.prevention_failures == ("RuntimeError",)
    assert first.historical_pull_requests_completed == 0
    assert second.historical_pull_requests_completed == 1
    assert [call["priority_pull_groups"] for call in historical_provider.calls] == [
        (),
        (((500, 12),),),
    ]
    assert len(prevention.propose_calls) == 2
    assert len(driver.calls) == 1


def test_deferred_edge_remediation_scope_is_prioritized_after_lookback_moves(
    tmp_path: Path,
    runtime,
) -> None:
    base, head, checkout, _provider, broker, _sequence = runtime
    base_policy = _historical_policy(remediation=True)
    policy = replace(
        base_policy,
        closed_pr_backfill=replace(
            base_policy.closed_pr_backfill,
            lookback_days=1,
            max_prs_per_poll=1,
        ),
    )
    snapshot = _snapshot(
        pull=_pull(
            state="closed",
            updated_at=(NOW - timedelta(days=1)).isoformat(),
        )
    )
    historical_provider = LookbackEdgeHistoricalSnapshotProvider(snapshot)
    remediation = FakeRemediationRunner(
        publish_result=RemediationBatchOutcome(deferred=1)
    )
    driver = FakeCodexDriver()
    clock = [NOW]
    with GuardianState(tmp_path / "state.sqlite3") as state:
        controller = _controller(
            tmp_path=tmp_path,
            state=state,
            config=_config(
                GuardianMode.APPLY_OWNED_TRANSLATIONS,
                policies=(policy,),
            ),
            checkout=checkout,
            provider=FakeSnapshotProvider(()),
            driver=driver,
            broker=broker,
            historical_snapshot_provider=historical_provider,
            historical_checkout_factory=FakeHistoricalCheckoutFactory(
                base,
                head,
                tmp_path,
            ),
            current_base_provider=FakeCurrentBaseProvider(),
            remediation_runner=remediation,
            now=lambda: clock[0],
        )
        first = controller.poll_once()
        remediation.publish_result = RemediationBatchOutcome(
            drafts=(
                RemediationDraftResult(
                    number=77,
                    html_url="https://github.com/acme/widgets/pull/77",
                    candidate_sha="9" * 40,
                    created=True,
                ),
            )
        )
        clock[0] = NOW + timedelta(days=1)
        second = controller.poll_once()

    assert first.remediation_items_deferred == 1
    assert first.historical_pull_requests_completed == 0
    assert second.historical_pull_requests_completed == 1
    assert [call["priority_pull_groups"] for call in historical_provider.calls] == [
        (),
        (((500, 12),),),
    ]
    assert len(remediation.publish_calls) == 2
    assert len(driver.calls) == 1


def test_historical_feedback_deletion_records_tombstone_without_second_model(
    tmp_path: Path,
    runtime,
) -> None:
    base, head, checkout, _provider, broker, _sequence = runtime
    original_pull = _pull(state="closed")
    original = _snapshot(pull=original_pull)
    provider = FakeHistoricalSnapshotProvider((original,))
    remediation = FakeRemediationRunner()
    driver = FakeCodexDriver()
    with GuardianState(tmp_path / "state.sqlite3") as state:
        controller = _controller(
            tmp_path=tmp_path,
            state=state,
            config=_config(
                GuardianMode.APPLY_OWNED_TRANSLATIONS,
                policies=(_historical_policy(remediation=True),),
            ),
            checkout=checkout,
            provider=FakeSnapshotProvider(()),
            driver=driver,
            broker=broker,
            historical_snapshot_provider=provider,
            historical_checkout_factory=FakeHistoricalCheckoutFactory(
                base,
                head,
                tmp_path,
            ),
            current_base_provider=FakeCurrentBaseProvider(),
            remediation_runner=remediation,
        )
        first = controller.poll_once()
        deleted_pull = replace(
            original_pull,
            updated_at="2026-08-30T11:00:00Z",
        )
        deleted_feedback = replace(
            _feedback(updated_at="2026-08-30T11:00:00Z"),
            body="",
            deleted=True,
        )
        provider.snapshots = (
            _snapshot(
                pull=deleted_pull,
                feedback=(deleted_feedback,),
            ),
        )
        second = controller.poll_once()
        latest = state.latest_event_revisions(
            repository="acme/widgets",
            pr_number=12,
        )

    assert first.historical_pull_requests_completed == 1
    assert second.historical_pull_requests_completed == 1
    assert second.feedback_revisions_recorded == 1
    assert second.runs_completed == 1
    assert len(driver.calls) == 1
    assert len(remediation.publish_calls) == 1
    assert len(latest) == 1
    assert latest[0].deleted is True
    assert latest[0].body == ""


@pytest.mark.parametrize(
    ("mutation", "accepted"),
    [
        ("unchanged", True),
        ("reviewer_login_rename", True),
        ("untrusted_comment_added", True),
        ("reopened", False),
        ("trusted_comment_added", False),
        ("trusted_comment_edited", False),
        ("trusted_comment_deleted", False),
    ],
)
def test_historical_remediation_revalidates_exact_source_authority_before_write(
    tmp_path: Path,
    runtime,
    capsys: pytest.CaptureFixture[str],
    mutation: str,
    accepted: bool,
) -> None:
    base, head, checkout, _provider, broker, _sequence = runtime
    secret_body = "SENSITIVE-REVIEW-BODY-MUST-NOT-BE-LOGGED"
    original_feedback = _feedback(body=secret_body)
    original = _snapshot(
        pull=_pull(state="closed"),
        feedback=(original_feedback,),
    )
    historical_provider = FakeHistoricalSnapshotProvider((original,))
    remediation = FakeRemediationRunner()

    def exact_source_provider(
        _policy: RepositoryPolicy,
        _sources: tuple[HistoricalPullReference, ...],
    ) -> tuple[PullRequestFeedbackSnapshot, ...]:
        pull = original.pull_request
        feedback = original.feedback
        if mutation == "reviewer_login_rename":
            feedback = (replace(original_feedback, author_login="renamed-reviewer"),)
        elif mutation == "untrusted_comment_added":
            feedback = (
                original_feedback,
                replace(
                    _feedback(source_id="45", body="untrusted noise"),
                    author_login="stranger",
                    author_id=999,
                ),
            )
        elif mutation == "reopened":
            pull = replace(pull, state="open")
        elif mutation == "trusted_comment_added":
            feedback = (
                original_feedback,
                _feedback(source_id="45", body="another trusted instruction"),
            )
        elif mutation == "trusted_comment_edited":
            feedback = (
                replace(
                    original_feedback,
                    body="changed trusted instruction",
                    updated_at="2026-08-30T11:00:00Z",
                ),
            )
        elif mutation == "trusted_comment_deleted":
            feedback = (
                replace(
                    original_feedback,
                    body="",
                    deleted=True,
                    updated_at="2026-08-30T11:00:00Z",
                ),
            )
        return (replace(original, pull_request=pull, feedback=feedback),)

    with GuardianState(tmp_path / "state.sqlite3") as state:
        outcome = _controller(
            tmp_path=tmp_path,
            state=state,
            config=_config(
                GuardianMode.APPLY_OWNED_TRANSLATIONS,
                policies=(_historical_policy(remediation=True),),
            ),
            checkout=checkout,
            provider=FakeSnapshotProvider(()),
            driver=FakeCodexDriver(),
            broker=broker,
            historical_snapshot_provider=historical_provider,
            historical_source_snapshot_provider=exact_source_provider,
            historical_checkout_factory=FakeHistoricalCheckoutFactory(
                base,
                head,
                tmp_path,
            ),
            current_base_provider=FakeCurrentBaseProvider(),
            remediation_runner=remediation,
        ).poll_once()
        assert len(remediation.publish_calls) == 1
        source = tuple(remediation.publish_calls[0]["source_pulls"])[0]
        assert isinstance(source, HistoricalPullReference)
        completed = state.historical_pull_is_complete(
            repository=source.repository,
            repository_id=source.repository_id,
            pull_id=source.pull_id,
            pull_revision_digest=source.pull_revision_digest,
            policy_digest=source.policy_digest,
            authority_scope=HistoricalCheckScope.REMEDIATION,
        )

    captured = capsys.readouterr()
    assert secret_body not in captured.out
    assert secret_body not in captured.err
    if accepted:
        assert outcome.historical_pull_requests_completed == 1
        assert outcome.remediation_failures == ()
        assert completed is True
    else:
        assert outcome.historical_pull_requests_completed == 0
        assert outcome.remediation_failures == ("RemediationSourceAuthorityError",)
        assert completed is False


def test_missing_target_on_current_base_is_terminal_no_action(
    tmp_path: Path,
    runtime,
) -> None:
    base, head, checkout, _provider, broker, _sequence = runtime
    old_base = tmp_path / "old-base"
    shutil.copytree(base, old_base)
    (base / TARGET_PATH).unlink()
    pull = _pull(state="closed")
    historical_provider = FakeHistoricalSnapshotProvider((_snapshot(pull=pull),))
    remediation = FakeRemediationRunner()
    driver = FakeCodexDriver()
    with GuardianState(tmp_path / "state.sqlite3") as state:
        outcome = _controller(
            tmp_path=tmp_path,
            state=state,
            config=_config(
                GuardianMode.APPLY_OWNED_TRANSLATIONS,
                policies=(_historical_policy(remediation=True),),
            ),
            checkout=checkout,
            provider=FakeSnapshotProvider(()),
            driver=driver,
            broker=broker,
            historical_snapshot_provider=historical_provider,
            historical_checkout_factory=FakeHistoricalCheckoutFactory(
                old_base,
                head,
                tmp_path,
            ),
            current_base_provider=FakeCurrentBaseProvider(),
            remediation_runner=remediation,
        ).poll_once()

    assert outcome.historical_pull_requests_completed == 1
    assert outcome.historical_policy_rejections == 0
    assert driver.calls == []
    assert remediation.publish_calls == []


def test_stale_historical_expected_value_is_deferred_against_current_base(
    tmp_path: Path,
    runtime,
) -> None:
    base, head, checkout, _provider, broker, _sequence = runtime
    old_base = tmp_path / "old-base"
    shutil.copytree(base, old_base)
    historical_value = "Историческое значение %0 (%1). %2 %3"
    (old_base / TARGET_PATH).write_text(
        f"greeting={historical_value}\n",
        encoding="utf-8",
    )

    class StaleExpectedDriver(FakeCodexDriver):
        def run(self, task, **kwargs):
            result = super().run(task, **kwargs)
            replacement = replace(
                result.feedback[0].replacements[0],
                expected_value=historical_value,
            )
            return replace(
                result,
                feedback=(replace(result.feedback[0], replacements=(replacement,)),),
            )

    remediation = FakeRemediationRunner()
    with GuardianState(tmp_path / "state.sqlite3") as state:
        outcome = _controller(
            tmp_path=tmp_path,
            state=state,
            config=_config(
                GuardianMode.APPLY_OWNED_TRANSLATIONS,
                policies=(_historical_policy(remediation=True),),
            ),
            checkout=checkout,
            provider=FakeSnapshotProvider(()),
            driver=StaleExpectedDriver(),
            broker=broker,
            historical_snapshot_provider=FakeHistoricalSnapshotProvider(
                (_snapshot(pull=_pull(state="closed")),)
            ),
            historical_checkout_factory=FakeHistoricalCheckoutFactory(
                old_base,
                head,
                tmp_path,
            ),
            current_base_provider=FakeCurrentBaseProvider(),
            remediation_runner=remediation,
        ).poll_once()

    assert outcome.historical_items_deferred == 1
    assert outcome.remediation_items_deferred == 1
    assert outcome.historical_pull_requests_completed == 0
    assert remediation.publish_calls == []


def test_closed_remediation_batches_agreement_once_and_never_writes_old_pull(
    tmp_path: Path,
    runtime,
) -> None:
    base, head, checkout, _provider, broker, _sequence = runtime
    first_pull = _pull(state="closed")
    second_pull = _pull(
        state="closed",
        pull_id=501,
        number=13,
        html_url="https://github.com/acme/widgets/pull/13",
        updated_at="2026-08-30T11:00:00Z",
    )
    snapshots = (
        _snapshot(pull=first_pull),
        _snapshot(
            pull=second_pull,
            feedback=(_feedback(pull_number=13, source_id="45"),),
        ),
    )
    historical_provider = FakeHistoricalSnapshotProvider(snapshots)
    remediation = FakeRemediationRunner(
        publish_result=RemediationBatchOutcome(
            drafts=(
                RemediationDraftResult(
                    number=77,
                    html_url="https://github.com/acme/widgets/pull/77",
                    candidate_sha="9" * 40,
                    created=True,
                ),
            ),
        )
    )
    driver = FakeCodexDriver()
    with GuardianState(tmp_path / "state.sqlite3") as state:
        controller = _controller(
            tmp_path=tmp_path,
            state=state,
            config=_config(
                GuardianMode.APPLY_OWNED_TRANSLATIONS,
                policies=(_historical_policy(remediation=True),),
                limits=GuardianLimits(
                    daily_cost_limit_usd=2,
                    model_call_reservation_usd=1,
                    raw_retention_days=90,
                    max_remediation_drafts_per_run=1,
                ),
            ),
            checkout=checkout,
            provider=FakeSnapshotProvider(()),
            driver=driver,
            broker=broker,
            historical_snapshot_provider=historical_provider,
            historical_checkout_factory=FakeHistoricalCheckoutFactory(
                base,
                head,
                tmp_path,
            ),
            current_base_provider=FakeCurrentBaseProvider(),
            remediation_runner=remediation,
        )
        first = controller.poll_once()
        second = controller.poll_once()

    assert first.historical_pull_requests_seen == 2
    assert first.historical_pull_requests_completed == 2
    assert first.remediation_drafts_created == 1
    assert second.historical_pull_requests_seen == 0
    assert len(remediation.publish_calls) == 1
    published = remediation.publish_calls[0]
    assert len(published["replacements"]) == 1
    assert {source.pr_number for source in published["source_pulls"]} == {12, 13}
    assert len(published["event_revision_ids"]) == 2
    assert broker.verify_calls == []
    assert broker.reply_calls == []
    assert all(
        workspace.commits == 0 and workspace.publications == 0
        for workspace in checkout.workspaces
    )


def test_closed_remediation_binds_every_assessed_feedback_url_for_its_source(
    tmp_path: Path,
    runtime,
) -> None:
    base, head, checkout, _provider, broker, _sequence = runtime
    snapshot = _snapshot(
        pull=_pull(state="closed"),
        feedback=(_feedback(), _feedback(source_id="45")),
    )

    class OneEditTwoDecisionDriver(FakeCodexDriver):
        def run(
            self,
            task,
            *,
            api_key=None,
            attempt_observer=None,
            success_observer=None,
        ) -> CodexResult:
            transformed: CodexResult | None = None

            def persist(attempt, usage, result):
                nonlocal transformed
                manifest = json.loads((task.evidence_dir / "manifest.json").read_text())
                assert manifest["feedback_ids"] == [
                    "review_comment:44",
                    "review_comment:45",
                ]
                transformed = replace(
                    result,
                    feedback=(
                        result.feedback[0],
                        GuardianFeedbackDecision(
                            feedback_id="review_comment:45",
                            verdict="reject",
                            confidence=0.99,
                            rationale="No separate current-base edit is needed.",
                            replacements=(),
                        ),
                    ),
                )
                if success_observer is not None:
                    success_observer(attempt, usage, transformed)

            super().run(
                task,
                api_key=api_key,
                attempt_observer=attempt_observer,
                success_observer=persist,
            )
            assert transformed is not None
            return transformed

    remediation = FakeRemediationRunner(
        publish_result=RemediationBatchOutcome(
            drafts=(
                RemediationDraftResult(
                    number=77,
                    html_url="https://github.com/acme/widgets/pull/77",
                    candidate_sha="9" * 40,
                    created=True,
                ),
            ),
        )
    )
    with GuardianState(tmp_path / "state.sqlite3") as state:
        outcome = _controller(
            tmp_path=tmp_path,
            state=state,
            config=_config(
                GuardianMode.APPLY_OWNED_TRANSLATIONS,
                policies=(_historical_policy(remediation=True),),
                limits=GuardianLimits(
                    daily_cost_limit_usd=2,
                    model_call_reservation_usd=1,
                    raw_retention_days=90,
                    max_remediation_drafts_per_run=1,
                ),
            ),
            checkout=checkout,
            provider=FakeSnapshotProvider(()),
            driver=OneEditTwoDecisionDriver(),
            broker=broker,
            historical_snapshot_provider=FakeHistoricalSnapshotProvider((snapshot,)),
            historical_checkout_factory=FakeHistoricalCheckoutFactory(
                base,
                head,
                tmp_path,
            ),
            current_base_provider=FakeCurrentBaseProvider(),
            remediation_runner=remediation,
        ).poll_once()

    assert outcome.remediation_drafts_created == 1
    assert len(remediation.publish_calls) == 1
    published = remediation.publish_calls[0]
    assert len(published["event_revision_ids"]) == 2
    assert published["feedback_urls"] == (
        "https://github.com/acme/widgets/pull/12#discussion_r44",
        "https://github.com/acme/widgets/pull/12#discussion_r45",
    )


def test_remediation_cap_publishes_a_bounded_partial_source_batch(
    tmp_path: Path,
    runtime,
) -> None:
    base, head, checkout, _provider, broker, _sequence = runtime
    for tree in (base, head):
        source = tree / "l10n/messages_en.properties"
        target = tree / TARGET_PATH
        source.write_text(
            source.read_text(encoding="utf-8")
            + "alpha=English alpha\nbeta=English beta\n",
            encoding="utf-8",
        )
        target.write_text(
            target.read_text(encoding="utf-8")
            + "alpha=Старый альфа\nbeta=Старый бета\n",
            encoding="utf-8",
        )
    retained_pull = _pull(
        state="closed",
        pull_id=501,
        number=13,
        html_url="https://github.com/acme/widgets/pull/13",
    )
    omitted_pull = _pull(state="closed")
    snapshots = (
        _snapshot(
            pull=retained_pull,
            feedback=(_feedback(pull_number=13, source_id="45"),),
        ),
        _snapshot(pull=omitted_pull),
    )

    class MultiReplacementDriver(FakeCodexDriver):
        @staticmethod
        def _transform(result: CodexResult) -> CodexResult:
            decision = result.feedback[0]
            if decision.feedback_id == "review_comment:45":
                replacements = (
                    GuardianReplacement(
                        path=TARGET_PATH,
                        key="greeting",
                        expected_value=("Старый %0 был отклонён (%1). %2 %3"),
                        proposed_value="Сохранённое исправление %0 (%1). %2 %3",
                    ),
                )
            else:
                replacements = (
                    GuardianReplacement(
                        path=TARGET_PATH,
                        key="alpha",
                        expected_value="Старый альфа",
                        proposed_value="Исправленный альфа",
                    ),
                    GuardianReplacement(
                        path=TARGET_PATH,
                        key="beta",
                        expected_value="Старый бета",
                        proposed_value="Исправленный бета",
                    ),
                )
            return replace(
                result,
                feedback=(replace(decision, replacements=replacements),),
            )

        def run(
            self,
            task,
            *,
            api_key=None,
            attempt_observer=None,
            success_observer=None,
        ) -> CodexResult:
            transformed: CodexResult | None = None

            def persist(attempt, usage, result):
                nonlocal transformed
                transformed = self._transform(result)
                if success_observer is not None:
                    success_observer(attempt, usage, transformed)

            result = super().run(
                task,
                api_key=api_key,
                attempt_observer=attempt_observer,
                success_observer=persist,
            )
            return transformed or self._transform(result)

    remediation = FakeRemediationRunner(
        publish_result=RemediationBatchOutcome(
            drafts=(
                RemediationDraftResult(
                    number=77,
                    html_url="https://github.com/acme/widgets/pull/77",
                    candidate_sha="9" * 40,
                    created=True,
                ),
            ),
        )
    )
    with GuardianState(tmp_path / "state.sqlite3") as state:
        outcome = _controller(
            tmp_path=tmp_path,
            state=state,
            config=_config(
                GuardianMode.APPLY_OWNED_TRANSLATIONS,
                policies=(_historical_policy(remediation=True),),
                limits=GuardianLimits(
                    max_value_edits_per_run=2,
                    daily_cost_limit_usd=2,
                    model_call_reservation_usd=1,
                    raw_retention_days=90,
                    max_remediation_drafts_per_run=1,
                ),
            ),
            checkout=checkout,
            provider=FakeSnapshotProvider(()),
            driver=MultiReplacementDriver(),
            broker=broker,
            historical_snapshot_provider=FakeHistoricalSnapshotProvider(snapshots),
            historical_checkout_factory=FakeHistoricalCheckoutFactory(
                base,
                head,
                tmp_path,
            ),
            current_base_provider=FakeCurrentBaseProvider(),
            remediation_runner=remediation,
        ).poll_once()

    assert outcome.remediation_items_deferred == 1
    assert len(remediation.publish_calls) == 1
    published = remediation.publish_calls[0]
    assert [(item.path, item.key) for item in published["replacements"]] == [
        (TARGET_PATH, "greeting"),
        (TARGET_PATH, "alpha"),
    ]
    assert [item.pr_number for item in published["source_pulls"]] == [13, 12]
    assert len(published["event_revision_ids"]) == 2
    assert set(published["feedback_urls"]) == {
        "https://github.com/acme/widgets/pull/12#discussion_r44",
        "https://github.com/acme/widgets/pull/13#discussion_r45",
    }


def test_noop_capped_remediation_completes_only_fully_selected_sources(
    tmp_path: Path,
    runtime,
) -> None:
    base, head, checkout, _provider, broker, _sequence = runtime
    for tree in (base, head):
        source = tree / "l10n/messages_en.properties"
        target = tree / TARGET_PATH
        source.write_text(
            source.read_text(encoding="utf-8")
            + "alpha=English alpha\nbeta=English beta\n",
            encoding="utf-8",
        )
        target.write_text(
            target.read_text(encoding="utf-8")
            + "alpha=Старый альфа\nbeta=Старый бета\n",
            encoding="utf-8",
        )
    first = _snapshot(
        pull=_pull(
            state="closed",
            pull_id=501,
            number=13,
            html_url="https://github.com/acme/widgets/pull/13",
        ),
        feedback=(_feedback(pull_number=13, source_id="45"),),
    )
    second = _snapshot(pull=_pull(state="closed"))

    class SplitReplacementDriver(FakeCodexDriver):
        @staticmethod
        def _transform(result: CodexResult) -> CodexResult:
            decision = result.feedback[0]
            if decision.feedback_id == "review_comment:45":
                replacements = decision.replacements
            else:
                replacements = (
                    GuardianReplacement(
                        path=TARGET_PATH,
                        key="alpha",
                        expected_value="Старый альфа",
                        proposed_value="Исправленный альфа",
                    ),
                    GuardianReplacement(
                        path=TARGET_PATH,
                        key="beta",
                        expected_value="Старый бета",
                        proposed_value="Исправленный бета",
                    ),
                )
            return replace(
                result,
                feedback=(replace(decision, replacements=replacements),),
            )

        def run(
            self,
            task,
            *,
            api_key=None,
            attempt_observer=None,
            success_observer=None,
        ) -> CodexResult:
            transformed: CodexResult | None = None

            def persist(attempt, usage, result):
                nonlocal transformed
                transformed = self._transform(result)
                if success_observer is not None:
                    success_observer(attempt, usage, transformed)

            result = super().run(
                task,
                api_key=api_key,
                attempt_observer=attempt_observer,
                success_observer=persist,
            )
            return transformed or self._transform(result)

    selected_batches: list[tuple[ProposedReplacement, ...]] = []

    def already_current(**kwargs: object) -> PatchResult:
        selected = tuple(kwargs["replacements"])
        assert all(isinstance(item, ProposedReplacement) for item in selected)
        selected_batches.append(selected)  # type: ignore[arg-type]
        return PatchResult(changed_files=(), changed_keys=())

    remediation = FakeRemediationRunner()
    with GuardianState(tmp_path / "state.sqlite3") as state:
        outcome = _controller(
            tmp_path=tmp_path,
            state=state,
            config=_config(
                GuardianMode.APPLY_OWNED_TRANSLATIONS,
                policies=(_historical_policy(remediation=True),),
                limits=GuardianLimits(
                    max_value_edits_per_run=2,
                    daily_cost_limit_usd=2,
                    model_call_reservation_usd=1,
                    raw_retention_days=90,
                    max_remediation_drafts_per_run=1,
                ),
            ),
            checkout=checkout,
            provider=FakeSnapshotProvider(()),
            driver=SplitReplacementDriver(),
            broker=broker,
            historical_snapshot_provider=FakeHistoricalSnapshotProvider(
                (first, second)
            ),
            historical_checkout_factory=FakeHistoricalCheckoutFactory(
                base,
                head,
                tmp_path,
            ),
            current_base_provider=FakeCurrentBaseProvider(),
            remediation_runner=remediation,
            replacement_applier=already_current,
        ).poll_once()

        completed_prs = tuple(
            int(row["pr_number"])
            for row in state._connection.execute(  # noqa: SLF001 - checkpoint assertion
                """
                SELECT pr_number FROM historical_pull_completions
                WHERE authority_scope = 'remediation'
                ORDER BY pr_number
                """
            ).fetchall()
        )

    assert [[item.key for item in batch] for batch in selected_batches] == [
        ["greeting", "alpha"]
    ]
    assert completed_prs == (13,)
    assert remediation.publish_calls == []
    assert outcome.historical_pull_requests_completed == 1
    assert outcome.remediation_items_deferred == 1


def test_closed_remediation_subtracts_opened_edit_from_mixed_batch(
    tmp_path: Path,
    runtime,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    base, head, checkout, _provider, broker, _sequence = runtime
    for tree in (base, head):
        source = tree / "l10n/messages_en.properties"
        target = tree / TARGET_PATH
        source.write_text(
            source.read_text(encoding="utf-8") + "alpha=English alpha\n",
            encoding="utf-8",
        )
        target.write_text(
            target.read_text(encoding="utf-8") + "alpha=Старый альфа\n",
            encoding="utf-8",
        )
    remediation = FakeRemediationRunner(
        publish_result=RemediationBatchOutcome(
            drafts=(
                RemediationDraftResult(
                    number=77,
                    html_url="https://github.com/acme/widgets/pull/77",
                    candidate_sha="9" * 40,
                    created=True,
                ),
            ),
        )
    )
    greeting_target = remediation_target_hash(
        ProposedReplacement(
            feedback_id="review_comment:44",
            path=TARGET_PATH,
            key="greeting",
            locale="ru",
            expected_value="unused",
            proposed_value="unused",
            confidence=1.0,
            evidence=(),
        )
    )
    observed_mappings: list[tuple[tuple[str, str], ...]] = []
    with GuardianState(tmp_path / "state.sqlite3") as state:

        def coverage(**kwargs: object) -> RemediationEditCoverage:
            mappings = tuple(kwargs["edit_target_hashes"])
            observed_mappings.append(mappings)
            return RemediationEditCoverage(
                opened_edit_hashes=frozenset(
                    edit_hash
                    for edit_hash, target_hash in mappings
                    if target_hash == greeting_target
                ),
                pending_edit_hashes=frozenset(),
                incompatible_edit_hashes=frozenset(),
                opened_draft_keys_by_edit_hash={
                    edit_hash: ("7" * 64,)
                    for edit_hash, target_hash in mappings
                    if target_hash == greeting_target
                },
            )

        monkeypatch.setattr(state, "remediation_edit_coverage", coverage)
        outcome = _controller(
            tmp_path=tmp_path,
            state=state,
            config=_config(
                GuardianMode.APPLY_OWNED_TRANSLATIONS,
                policies=(_historical_policy(remediation=True),),
            ),
            checkout=checkout,
            provider=FakeSnapshotProvider(()),
            driver=TwoReplacementCodexDriver(),
            broker=broker,
            historical_snapshot_provider=FakeHistoricalSnapshotProvider(
                (_snapshot(pull=_pull(state="closed")),)
            ),
            historical_checkout_factory=FakeHistoricalCheckoutFactory(
                base,
                head,
                tmp_path,
            ),
            current_base_provider=FakeCurrentBaseProvider(),
            remediation_runner=remediation,
        ).poll_once()

    assert len(observed_mappings) == 1
    assert len(observed_mappings[0]) == 2
    assert len(remediation.publish_calls) == 1
    assert [
        (item.path, item.key) for item in remediation.publish_calls[0]["replacements"]
    ] == [(TARGET_PATH, "alpha")]
    assert outcome.prepared_value_edits == 1
    assert outcome.historical_pull_requests_completed == 1


def test_closed_remediation_defers_same_target_active_conflict(
    tmp_path: Path,
    runtime,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    base, head, checkout, _provider, broker, _sequence = runtime
    remediation = FakeRemediationRunner()
    with GuardianState(tmp_path / "state.sqlite3") as state:

        def coverage(**kwargs: object) -> RemediationEditCoverage:
            mappings = tuple(kwargs["edit_target_hashes"])
            return RemediationEditCoverage(
                opened_edit_hashes=frozenset(),
                pending_edit_hashes=frozenset(),
                incompatible_edit_hashes=frozenset(),
                conflicting_edit_hashes=frozenset(
                    edit_hash for edit_hash, _target_hash in mappings
                ),
            )

        monkeypatch.setattr(state, "remediation_edit_coverage", coverage)
        outcome = _controller(
            tmp_path=tmp_path,
            state=state,
            config=_config(
                GuardianMode.APPLY_OWNED_TRANSLATIONS,
                policies=(_historical_policy(remediation=True),),
            ),
            checkout=checkout,
            provider=FakeSnapshotProvider(()),
            driver=FakeCodexDriver(),
            broker=broker,
            historical_snapshot_provider=FakeHistoricalSnapshotProvider(
                (_snapshot(pull=_pull(state="closed")),)
            ),
            historical_checkout_factory=FakeHistoricalCheckoutFactory(
                base,
                head,
                tmp_path,
            ),
            current_base_provider=FakeCurrentBaseProvider(),
            remediation_runner=remediation,
        ).poll_once()

    assert remediation.publish_calls == []
    assert outcome.remediation_items_deferred == 1
    assert outcome.historical_pull_requests_completed == 0


def test_closed_remediation_conflict_is_deferred_without_publication(
    tmp_path: Path,
    runtime,
) -> None:
    base, head, checkout, _provider, broker, _sequence = runtime
    pulls = (
        _pull(state="closed"),
        _pull(
            state="closed",
            pull_id=501,
            number=13,
            html_url="https://github.com/acme/widgets/pull/13",
        ),
    )
    snapshots = (
        _snapshot(pull=pulls[0]),
        _snapshot(
            pull=pulls[1],
            feedback=(_feedback(pull_number=13, source_id="45"),),
        ),
    )

    class ConflictingDriver(FakeCodexDriver):
        def run(self, task, **kwargs):
            result = super().run(task, **kwargs)
            if len(self.calls) == 2:
                replacement = replace(
                    result.feedback[0].replacements[0],
                    proposed_value="Конфликтующее предложение %0 (%1). %2 %3",
                )
                return replace(
                    result,
                    feedback=(
                        replace(
                            result.feedback[0],
                            replacements=(replacement,),
                        ),
                    ),
                )
            return result

    historical_provider = FakeHistoricalSnapshotProvider(snapshots)
    remediation = FakeRemediationRunner()
    with GuardianState(tmp_path / "state.sqlite3") as state:
        outcome = _controller(
            tmp_path=tmp_path,
            state=state,
            config=_config(
                GuardianMode.APPLY_OWNED_TRANSLATIONS,
                policies=(_historical_policy(remediation=True),),
            ),
            checkout=checkout,
            provider=FakeSnapshotProvider(()),
            driver=ConflictingDriver(),
            broker=broker,
            historical_snapshot_provider=historical_provider,
            historical_checkout_factory=FakeHistoricalCheckoutFactory(
                base,
                head,
                tmp_path,
            ),
            current_base_provider=FakeCurrentBaseProvider(),
            remediation_runner=remediation,
        ).poll_once()

    assert outcome.historical_items_deferred == 2
    assert outcome.remediation_items_deferred == 2
    assert outcome.historical_pull_requests_completed == 0
    assert remediation.publish_calls == []


def test_completed_remediation_is_not_republished_while_prevention_retries(
    tmp_path: Path,
    runtime,
) -> None:
    base, head, checkout, _provider, broker, _sequence = runtime
    policy = replace(
        _historical_policy(remediation=True),
        prevention=_prevention_policy(),
    )
    historical_provider = FakeHistoricalSnapshotProvider(
        (_snapshot(pull=_pull(state="closed")),)
    )
    prevention = FakePreventionRunner(result=PreventionBatchOutcome(deferred=1))
    remediation = FakeRemediationRunner(
        publish_result=RemediationBatchOutcome(
            drafts=(
                RemediationDraftResult(
                    number=77,
                    html_url="https://github.com/acme/widgets/pull/77",
                    candidate_sha="9" * 40,
                    created=True,
                ),
            ),
        )
    )
    driver = RecurrenceCodexDriver()
    with GuardianState(tmp_path / "state.sqlite3") as state:
        controller = _controller(
            tmp_path=tmp_path,
            state=state,
            config=_config(GuardianMode.PROPOSE_PREVENTION, policies=(policy,)),
            checkout=checkout,
            provider=FakeSnapshotProvider(()),
            driver=driver,
            broker=broker,
            prevention_runner=prevention,
            historical_snapshot_provider=historical_provider,
            historical_checkout_factory=FakeHistoricalCheckoutFactory(
                base,
                head,
                tmp_path,
            ),
            current_base_provider=FakeCurrentBaseProvider(),
            remediation_runner=remediation,
        )

        first = controller.poll_once()
        prevention.result = PreventionBatchOutcome()
        second = controller.poll_once()

    assert first.historical_pull_requests_completed == 0
    assert first.remediation_drafts_created == 1
    assert second.historical_pull_requests_completed == 1
    assert len(prevention.propose_calls) == 2
    assert len(remediation.publish_calls) == 1
    assert len(driver.calls) == 1


def test_completed_prevention_is_not_reproposed_while_remediation_retries(
    tmp_path: Path,
    runtime,
) -> None:
    base, head, checkout, _provider, broker, _sequence = runtime
    policy = replace(
        _historical_policy(remediation=True),
        prevention=_prevention_policy(),
    )
    historical_provider = FakeHistoricalSnapshotProvider(
        (_snapshot(pull=_pull(state="closed")),)
    )
    prevention = FakePreventionRunner()
    remediation = FakeRemediationRunner(
        publish_result=RemediationBatchOutcome(deferred=1)
    )
    driver = RecurrenceCodexDriver()
    with GuardianState(tmp_path / "state.sqlite3") as state:
        controller = _controller(
            tmp_path=tmp_path,
            state=state,
            config=_config(GuardianMode.PROPOSE_PREVENTION, policies=(policy,)),
            checkout=checkout,
            provider=FakeSnapshotProvider(()),
            driver=driver,
            broker=broker,
            prevention_runner=prevention,
            historical_snapshot_provider=historical_provider,
            historical_checkout_factory=FakeHistoricalCheckoutFactory(
                base,
                head,
                tmp_path,
            ),
            current_base_provider=FakeCurrentBaseProvider(),
            remediation_runner=remediation,
        )

        first = controller.poll_once()
        remediation.publish_result = RemediationBatchOutcome(
            drafts=(
                RemediationDraftResult(
                    number=77,
                    html_url="https://github.com/acme/widgets/pull/77",
                    candidate_sha="9" * 40,
                    created=True,
                ),
            ),
        )
        second = controller.poll_once()

    assert first.historical_pull_requests_completed == 0
    assert first.remediation_items_deferred == 1
    assert second.historical_pull_requests_completed == 1
    assert len(prevention.propose_calls) == 1
    assert len(remediation.publish_calls) == 2
    assert len(driver.calls) == 1


def test_transient_remediation_publication_failure_retries_without_new_model_call(
    tmp_path: Path,
    runtime,
) -> None:
    base, head, checkout, _provider, broker, _sequence = runtime
    pull = _pull(state="closed")
    provider = FakeHistoricalSnapshotProvider((_snapshot(pull=pull),))
    remediation = FakeRemediationRunner(
        publish_error=RuntimeError("temporary draft failure")
    )
    driver = FakeCodexDriver()
    with GuardianState(tmp_path / "state.sqlite3") as state:
        controller = _controller(
            tmp_path=tmp_path,
            state=state,
            config=_config(
                GuardianMode.APPLY_OWNED_TRANSLATIONS,
                policies=(_historical_policy(remediation=True),),
            ),
            checkout=checkout,
            provider=FakeSnapshotProvider(()),
            driver=driver,
            broker=broker,
            historical_snapshot_provider=provider,
            historical_checkout_factory=FakeHistoricalCheckoutFactory(
                base,
                head,
                tmp_path,
            ),
            current_base_provider=FakeCurrentBaseProvider(),
            remediation_runner=remediation,
        )
        first = controller.poll_once()
        remediation.publish_error = None
        second = controller.poll_once()

    assert first.remediation_failures == ("RuntimeError",)
    assert first.historical_pull_requests_completed == 0
    assert second.remediation_failures == ()
    assert second.historical_pull_requests_completed == 1
    assert len(remediation.publish_calls) == 2
    assert len(driver.calls) == 1


def test_pending_two_source_batch_rehydrates_and_republishes_atomically(
    tmp_path: Path,
    runtime,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    base, head, checkout, _provider, broker, _sequence = runtime
    snapshots = (
        _snapshot(pull=_pull(state="closed")),
        _snapshot(
            pull=_pull(
                state="closed",
                pull_id=501,
                number=13,
                html_url="https://github.com/acme/widgets/pull/13",
                updated_at="2026-08-30T11:00:00Z",
            ),
            feedback=(_feedback(pull_number=13, source_id="45"),),
        ),
    )
    policy = _historical_policy(remediation=True)
    assert policy.closed_pr_backfill is not None
    policy = replace(
        policy,
        closed_pr_backfill=replace(
            policy.closed_pr_backfill,
            max_prs_per_poll=2,
        ),
    )
    provider = FakeHistoricalSnapshotProvider(snapshots)
    remediation = FakeRemediationRunner(
        publish_error=RuntimeError("lost two-source draft response")
    )
    driver = FakeCodexDriver()
    with GuardianState(tmp_path / "state.sqlite3") as state:
        monkeypatch.setattr(
            state,
            "active_remediation_drafts_for_identity",
            lambda **_kwargs: (object(),),
        )
        controller = _controller(
            tmp_path=tmp_path,
            state=state,
            config=_config(
                GuardianMode.APPLY_OWNED_TRANSLATIONS,
                policies=(policy,),
            ),
            checkout=checkout,
            provider=FakeSnapshotProvider(()),
            driver=driver,
            broker=broker,
            historical_snapshot_provider=provider,
            historical_checkout_factory=FakeHistoricalCheckoutFactory(
                base,
                head,
                tmp_path,
            ),
            current_base_provider=FakeCurrentBaseProvider(),
            remediation_runner=remediation,
        )

        first = controller.poll_once()
        original_batch = tuple(remediation.publish_calls[0]["source_pulls"])
        assert len(original_batch) == 2
        remediation.recover_result = RemediationBatchOutcome(
            deferred=1,
            retry_source_batches=(original_batch,),
        )
        remediation.publish_error = None
        second = controller.poll_once()

    expected_group = tuple(
        (source.pull_id, source.pr_number) for source in original_batch
    )
    assert first.remediation_failures == ("RuntimeError",)
    assert first.historical_pull_requests_completed == 0
    assert [call["max_prs_per_poll"] for call in provider.calls] == [2, 2]
    assert [call["priority_pull_groups"] for call in provider.calls] == [
        (),
        (expected_group,),
    ]
    assert tuple(remediation.publish_calls[1]["source_pulls"]) == original_batch
    assert second.historical_pull_requests_completed == 2
    assert len(driver.calls) == 2


def test_pending_recovery_survives_base_repository_rename(
    tmp_path: Path,
    runtime,
) -> None:
    base, head, checkout, _provider, broker, _sequence = runtime
    renamed_repository = "acme/renamed-widgets"
    policy = replace(
        _historical_policy(remediation=True),
        base_repo=renamed_repository,
    )
    current_snapshot = guardian_controller._repository_route_alias(
        _snapshot(pull=_pull(state="closed")),
        repository=renamed_repository,
    )
    old_route_source = _retry_source(repository="acme/widgets")
    provider = FakeHistoricalSnapshotProvider((current_snapshot,))
    remediation = FakeRemediationRunner(
        recover_result=RemediationBatchOutcome(
            deferred=1,
            retry_source_batches=((old_route_source,),),
        )
    )

    with GuardianState(tmp_path / "state.sqlite3") as state:
        outcome = _controller(
            tmp_path=tmp_path,
            state=state,
            config=_config(
                GuardianMode.APPLY_OWNED_TRANSLATIONS,
                policies=(policy,),
            ),
            checkout=checkout,
            provider=FakeSnapshotProvider(()),
            driver=FakeCodexDriver(),
            broker=broker,
            historical_snapshot_provider=provider,
            historical_checkout_factory=FakeHistoricalCheckoutFactory(
                base,
                head,
                tmp_path,
            ),
            current_base_provider=FakeCurrentBaseProvider(),
            remediation_runner=remediation,
        ).poll_once()

    assert outcome.remediation_failures == ()
    assert provider.calls[0]["priority_pull_groups"] == (((500, 12),),)
    assert remediation.publish_calls[0]["source_pulls"][0].repository == (
        renamed_repository
    )
    assert outcome.historical_pull_requests_completed == 1


def test_pending_recovery_retries_once_then_allows_older_history(
    tmp_path: Path,
    runtime,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    base, head, checkout, _provider, broker, _sequence = runtime
    snapshots = (
        _snapshot(pull=_pull(state="closed")),
        _snapshot(
            pull=_pull(
                state="closed",
                pull_id=501,
                number=13,
                html_url="https://github.com/acme/widgets/pull/13",
            ),
            feedback=(_feedback(pull_number=13, source_id="45"),),
        ),
    )
    policy = _historical_policy(remediation=True)
    assert policy.closed_pr_backfill is not None
    policy = replace(
        policy,
        closed_pr_backfill=replace(
            policy.closed_pr_backfill,
            max_prs_per_poll=1,
        ),
    )
    provider = FakeHistoricalSnapshotProvider(snapshots)
    remediation = FakeRemediationRunner(
        publish_error=RuntimeError("lost draft response")
    )
    driver = FakeCodexDriver()
    with GuardianState(tmp_path / "state.sqlite3") as state:
        monkeypatch.setattr(
            state,
            "active_remediation_drafts_for_identity",
            lambda **_kwargs: (object(),),
        )
        controller = _controller(
            tmp_path=tmp_path,
            state=state,
            config=_config(
                GuardianMode.APPLY_OWNED_TRANSLATIONS,
                policies=(policy,),
            ),
            checkout=checkout,
            provider=FakeSnapshotProvider(()),
            driver=driver,
            broker=broker,
            historical_snapshot_provider=provider,
            historical_checkout_factory=FakeHistoricalCheckoutFactory(
                base,
                head,
                tmp_path,
            ),
            current_base_provider=FakeCurrentBaseProvider(),
            remediation_runner=remediation,
        )
        first = controller.poll_once()
        retry_source = remediation.publish_calls[0]["source_pulls"][0]
        remediation.recover_result = RemediationBatchOutcome(
            deferred=1,
            retry_source_batches=((retry_source,),),
        )
        second = controller.poll_once()
        remediation.publish_error = None
        third = controller.poll_once()

    assert first.remediation_failures == ("RuntimeError",)
    assert second.remediation_failures == ("RuntimeError",)
    assert [call["seen_pulls"] for call in provider.calls] == [
        (),
        (),
        ((500, 12),),
    ]
    assert [call["priority_pull_groups"] for call in provider.calls] == [
        (),
        (((500, 12),),),
        (),
    ]
    assert [
        call["source_pulls"][0].pr_number for call in remediation.publish_calls
    ] == [12, 12, 13]
    assert third.historical_pull_requests_completed == 1
    assert len(driver.calls) == 2


def test_remediation_failure_without_durable_candidate_does_not_starve_history(
    tmp_path: Path,
    runtime,
) -> None:
    base, head, checkout, _provider, broker, _sequence = runtime
    snapshots = (
        _snapshot(pull=_pull(state="closed")),
        _snapshot(
            pull=_pull(
                state="closed",
                pull_id=501,
                number=13,
                html_url="https://github.com/acme/widgets/pull/13",
            ),
            feedback=(_feedback(pull_number=13, source_id="45"),),
        ),
    )
    policy = _historical_policy(remediation=True)
    assert policy.closed_pr_backfill is not None
    policy = replace(
        policy,
        closed_pr_backfill=replace(
            policy.closed_pr_backfill,
            max_prs_per_poll=1,
        ),
    )
    provider = FakeHistoricalSnapshotProvider(snapshots)
    remediation = FakeRemediationRunner(
        publish_error=RuntimeError("failed before durable validation")
    )
    with GuardianState(tmp_path / "state.sqlite3") as state:
        controller = _controller(
            tmp_path=tmp_path,
            state=state,
            config=_config(
                GuardianMode.APPLY_OWNED_TRANSLATIONS,
                policies=(policy,),
            ),
            checkout=checkout,
            provider=FakeSnapshotProvider(()),
            driver=FakeCodexDriver(),
            broker=broker,
            historical_snapshot_provider=provider,
            historical_checkout_factory=FakeHistoricalCheckoutFactory(
                base,
                head,
                tmp_path,
            ),
            current_base_provider=FakeCurrentBaseProvider(),
            remediation_runner=remediation,
        )
        first = controller.poll_once()
        remediation.publish_error = None
        second = controller.poll_once()

    assert first.remediation_failures == ("RuntimeError",)
    assert [call["seen_pulls"] for call in provider.calls] == [
        (),
        ((500, 12),),
    ]
    assert [
        call["source_pulls"][0].pr_number for call in remediation.publish_calls
    ] == [12, 13]
    assert second.historical_pull_requests_completed == 1


def test_transient_remediation_recovery_failure_prevents_discovery_and_retries(
    tmp_path: Path,
    runtime,
) -> None:
    base, head, checkout, _provider, broker, _sequence = runtime
    provider = FakeHistoricalSnapshotProvider((_snapshot(pull=_pull(state="closed")),))
    remediation = FakeRemediationRunner(
        recover_error=RuntimeError("temporary recovery failure")
    )
    driver = FakeCodexDriver()
    with GuardianState(tmp_path / "state.sqlite3") as state:
        controller = _controller(
            tmp_path=tmp_path,
            state=state,
            config=_config(
                GuardianMode.APPLY_OWNED_TRANSLATIONS,
                policies=(_historical_policy(remediation=True),),
            ),
            checkout=checkout,
            provider=FakeSnapshotProvider(()),
            driver=driver,
            broker=broker,
            historical_snapshot_provider=provider,
            historical_checkout_factory=FakeHistoricalCheckoutFactory(
                base,
                head,
                tmp_path,
            ),
            current_base_provider=FakeCurrentBaseProvider(),
            remediation_runner=remediation,
        )
        first = controller.poll_once()
        remediation.recover_error = None
        second = controller.poll_once()

    assert first.failures == ("RuntimeError",)
    assert first.remediation_failures == ("RuntimeError",)
    assert first.historical_repositories_polled == 0
    assert second.historical_pull_requests_completed == 1
    assert len(provider.calls) == 1
    assert len(driver.calls) == 1


@pytest.mark.parametrize(
    "terminal_change", ["current_no_action", "historical_rejection"]
)
def test_terminal_recheck_fills_only_the_missing_remediation_scope(
    tmp_path: Path,
    runtime,
    terminal_change: str,
) -> None:
    base, head, checkout, _provider, broker, sequence = runtime
    old_base = tmp_path / "old-base"
    shutil.copytree(base, old_base)
    policy = _historical_policy(remediation=True)
    provider = FakeHistoricalSnapshotProvider((_snapshot(pull=_pull(state="closed")),))
    remediation = FakeRemediationRunner(
        publish_result=RemediationBatchOutcome(deferred=1)
    )
    driver = FakeCodexDriver()
    with GuardianState(tmp_path / "state.sqlite3") as state:
        controller = _controller(
            tmp_path=tmp_path,
            state=state,
            config=_config(
                GuardianMode.APPLY_OWNED_TRANSLATIONS,
                policies=(policy,),
            ),
            checkout=checkout,
            provider=FakeSnapshotProvider(()),
            driver=driver,
            broker=broker,
            historical_snapshot_provider=provider,
            historical_checkout_factory=FakeHistoricalCheckoutFactory(
                old_base,
                head,
                tmp_path,
            ),
            current_base_provider=FakeCurrentBaseProvider(),
            remediation_runner=remediation,
        )
        first = controller.poll_once()
        changed_root = base if terminal_change == "current_no_action" else head
        (changed_root / TARGET_PATH).unlink()
        second = controller.poll_once()
        completions = state._connection.execute(  # noqa: SLF001
            """
            SELECT authority_scope, event_revision_ids_json
            FROM historical_pull_completions
            ORDER BY authority_scope
            """
        ).fetchall()

    assert first.historical_pull_requests_completed == 0
    assert first.remediation_items_deferred == 1
    assert second.failures == ()
    assert second.historical_pull_requests_completed == 1
    assert second.historical_policy_rejections == (
        1 if terminal_change == "historical_rejection" else 0
    )
    expected = [("assessment", "[1]"), ("remediation", "[]")]
    if terminal_change == "current_no_action":
        expected.insert(1, ("assessment", "[]"))
    assert [tuple(row) for row in completions] == expected
    assert len(driver.calls) == 1
    assert len(remediation.publish_calls) == 1


def test_historical_prevention_github_authentication_opens_global_circuit(
    tmp_path: Path,
    runtime,
) -> None:
    base, head, checkout, _provider, broker, _sequence = runtime
    policy = replace(
        _historical_policy(),
        prevention=_prevention_policy(),
    )
    prevention = FakePreventionRunner(error=GitHubAuthenticationError("expired"))
    with GuardianState(tmp_path / "state.sqlite3") as state:
        outcome = _controller(
            tmp_path=tmp_path,
            state=state,
            config=_config(GuardianMode.PROPOSE_PREVENTION, policies=(policy,)),
            checkout=checkout,
            provider=FakeSnapshotProvider(()),
            driver=RecurrenceCodexDriver(),
            broker=broker,
            prevention_runner=prevention,
            historical_snapshot_provider=FakeHistoricalSnapshotProvider(
                (_snapshot(pull=_pull(state="closed")),)
            ),
            historical_checkout_factory=FakeHistoricalCheckoutFactory(
                base,
                head,
                tmp_path,
            ),
            current_base_provider=FakeCurrentBaseProvider(),
        ).poll_once()

    assert outcome.authentication_circuit_open is True
    assert outcome.prevention_failures == ()
    assert outcome.failures == ()


@pytest.mark.parametrize("exhaustion", ["model_calls", "budget"])
def test_historical_limit_exhaustion_defers_at_cursor_until_next_day(
    tmp_path: Path,
    runtime,
    exhaustion: str,
) -> None:
    base, head, checkout, _provider, broker, _sequence = runtime
    second_pull = _pull(
        state="closed",
        pull_id=501,
        number=13,
        html_url="https://github.com/acme/widgets/pull/13",
    )
    snapshots = (
        _snapshot(pull=_pull(state="closed")),
        _snapshot(
            pull=second_pull,
            feedback=(_feedback(pull_number=13, source_id="45"),),
        ),
    )
    provider = FakeHistoricalSnapshotProvider(snapshots)
    limits = GuardianLimits(
        max_attempts=1,
        max_model_calls_per_day=1 if exhaustion == "model_calls" else 10,
        daily_cost_limit_usd=10 if exhaustion == "model_calls" else 1,
        model_call_reservation_usd=1,
        raw_retention_days=90,
    )
    clock = [NOW]
    driver = FakeCodexDriver()
    with GuardianState(tmp_path / "state.sqlite3") as state:
        controller = _controller(
            tmp_path=tmp_path,
            state=state,
            config=_config(
                GuardianMode.OBSERVE,
                policies=(_historical_policy(),),
                limits=limits,
            ),
            checkout=checkout,
            provider=FakeSnapshotProvider(()),
            driver=driver,
            broker=broker,
            historical_snapshot_provider=provider,
            historical_checkout_factory=FakeHistoricalCheckoutFactory(
                base,
                head,
                tmp_path,
            ),
            current_base_provider=FakeCurrentBaseProvider(),
            now=lambda: clock[0],
        )
        first = controller.poll_once()
        run_statuses = tuple(
            row[0]
            for row in state._connection.execute(  # noqa: SLF001
                "SELECT status FROM runs ORDER BY started_at, rowid"
            )
        )
        action_statuses = tuple(
            row[0]
            for row in state._connection.execute(  # noqa: SLF001
                "SELECT status FROM actions ORDER BY action_id"
            )
        )
        clock[0] += timedelta(days=1)
        second = controller.poll_once()

    assert first.failures == ()
    assert first.runs_failed == 0
    assert first.historical_items_deferred == 1
    assert first.historical_pull_requests_completed == 1
    assert run_statuses == ("completed", "cancelled")
    assert action_statuses == ("completed", "skipped")
    assert [call["seen_pulls"] for call in provider.calls] == [
        (),
        ((500, 12),),
    ]
    assert second.historical_items_deferred == 0
    assert second.historical_pull_requests_completed == 1
    assert len(driver.calls) == 2


def test_enabling_prevention_cap_revisits_prior_historical_recurrence(
    tmp_path: Path,
    runtime,
) -> None:
    base, head, checkout, _provider, broker, _sequence = runtime
    policy = replace(
        _historical_policy(),
        prevention=_prevention_policy(),
    )
    provider = FakeHistoricalSnapshotProvider((_snapshot(pull=_pull(state="closed")),))
    prevention = FakePreventionRunner()
    driver = RecurrenceCodexDriver()

    def config(prevention_cap: int) -> GuardianConfig:
        return _config(
            GuardianMode.PROPOSE_PREVENTION,
            policies=(policy,),
            limits=GuardianLimits(
                max_prevention_drafts_per_run=prevention_cap,
                max_model_calls_per_day=4,
                daily_cost_limit_usd=4,
                model_call_reservation_usd=1,
                raw_retention_days=90,
            ),
        )

    with GuardianState(tmp_path / "state.sqlite3") as state:
        common = {
            "tmp_path": tmp_path,
            "state": state,
            "checkout": checkout,
            "provider": FakeSnapshotProvider(()),
            "driver": driver,
            "broker": broker,
            "prevention_runner": prevention,
            "historical_snapshot_provider": provider,
            "historical_checkout_factory": FakeHistoricalCheckoutFactory(
                base,
                head,
                tmp_path,
            ),
            "current_base_provider": FakeCurrentBaseProvider(),
        }
        first = _controller(config=config(0), **common).poll_once()
        second = _controller(config=config(1), **common).poll_once()

    assert first.historical_pull_requests_completed == 1
    assert first.prevention_items_skipped == 0
    assert second.historical_pull_requests_seen == 1
    assert second.historical_pull_requests_completed == 1
    assert len(prevention.propose_calls) == 1
    assert len(driver.calls) == 1
