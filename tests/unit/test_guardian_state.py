"""Tests for durable, revision-aware PR guardian state."""

from __future__ import annotations

from dataclasses import replace
from datetime import date, datetime, timedelta, timezone
from decimal import Decimal
import hashlib
import json
import os
from pathlib import Path
import sqlite3
from uuid import uuid4

import pytest

from localize.guardian import FeedbackEvent, GuardianMode
from localize.guardian import state as guardian_state
from localize.guardian.models import HistoricalCheckScope, ProposedReplacement
from localize.guardian.state import (
    GuardianState,
    HistoricalPullReference,
    OpenPullAuthorityReference,
    PreventionRecoveryAttemptDisposition,
    RemediationCoverageReason,
)


UTC = timezone.utc


def _overdeep_json_value() -> object:
    value: object = 0
    for _ in range(65):
        value = [value]
    return value


# Frozen schema shipped by Guardian state version 1. Migration tests must start
# from this fixture, not from a newer database with selected objects dropped.
_V1_SCHEMA_SQL = """
CREATE TABLE runs (
    run_id TEXT PRIMARY KEY,
    repository TEXT NOT NULL,
    locale TEXT NOT NULL,
    mode TEXT NOT NULL,
    status TEXT NOT NULL,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    summary TEXT
);
CREATE TABLE event_revisions (
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
        repository, pr_number, kind, event_id, revision_hash, head_sha, base_sha
    )
);
CREATE TABLE event_raw_bodies (
    event_revision_id INTEGER PRIMARY KEY,
    body TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    FOREIGN KEY (event_revision_id) REFERENCES event_revisions(revision_id)
);
CREATE TABLE actions (
    action_id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL,
    event_revision_id INTEGER NOT NULL,
    action TEXT NOT NULL,
    status TEXT NOT NULL,
    details_json TEXT NOT NULL,
    occurred_at TEXT NOT NULL,
    FOREIGN KEY (run_id) REFERENCES runs(run_id),
    FOREIGN KEY (event_revision_id) REFERENCES event_revisions(revision_id)
);
CREATE TABLE costs (
    cost_id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL,
    amount_microusd INTEGER NOT NULL CHECK (amount_microusd >= 0),
    model TEXT NOT NULL,
    input_tokens INTEGER NOT NULL CHECK (input_tokens >= 0),
    output_tokens INTEGER NOT NULL CHECK (output_tokens >= 0),
    incurred_at TEXT NOT NULL,
    FOREIGN KEY (run_id) REFERENCES runs(run_id)
);
CREATE TABLE budget_reservations (
    reservation_id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL,
    amount_microusd INTEGER NOT NULL CHECK (amount_microusd >= 0),
    model TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('reserved', 'unknown', 'settled')),
    reserved_at TEXT NOT NULL,
    settled_at TEXT,
    FOREIGN KEY (run_id) REFERENCES runs(run_id)
);
CREATE TABLE model_call_reservations (
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
CREATE TABLE assessment_results (
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
CREATE TABLE health (
    health_id INTEGER PRIMARY KEY AUTOINCREMENT,
    component TEXT NOT NULL,
    status TEXT NOT NULL,
    message TEXT NOT NULL,
    details_json TEXT NOT NULL,
    checked_at TEXT NOT NULL
);
CREATE TABLE publication_events (
    publication_event_id INTEGER PRIMARY KEY AUTOINCREMENT,
    publication_key TEXT NOT NULL,
    run_id TEXT NOT NULL,
    repository TEXT NOT NULL,
    pr_number INTEGER NOT NULL CHECK (pr_number > 0),
    original_head_sha TEXT NOT NULL,
    base_sha TEXT NOT NULL,
    commit_sha TEXT NOT NULL,
    event_revision_ids_json TEXT NOT NULL,
    phase TEXT NOT NULL CHECK (
        phase IN ('prepared', 'published', 'replied', 'abandoned')
    ),
    occurred_at TEXT NOT NULL,
    UNIQUE (publication_key, phase),
    FOREIGN KEY (run_id) REFERENCES runs(run_id)
);
CREATE TABLE prevention_draft_events (
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
    draft_url TEXT,
    occurred_at TEXT NOT NULL,
    UNIQUE (draft_key, phase),
    FOREIGN KEY (run_id) REFERENCES runs(run_id)
);
CREATE TABLE leases (
    name TEXT PRIMARY KEY,
    owner TEXT NOT NULL,
    acquired_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
);
CREATE INDEX event_revisions_repo_pr
    ON event_revisions(repository, pr_number, revision_id);
CREATE INDEX actions_event_status ON actions(event_revision_id, status);
CREATE INDEX costs_incurred_at ON costs(incurred_at);
CREATE INDEX budget_reservations_reserved_at
    ON budget_reservations(reserved_at, status);
CREATE INDEX model_call_reservations_reserved_at
    ON model_call_reservations(reserved_at, status);
CREATE INDEX assessment_results_created_at ON assessment_results(created_at);
CREATE INDEX health_component_checked
    ON health(component, checked_at DESC, health_id DESC);
CREATE INDEX publication_events_pending
    ON publication_events(repository, pr_number, publication_key,
                          publication_event_id DESC);
CREATE INDEX prevention_draft_events_pending
    ON prevention_draft_events(source_repository, target_repository,
                               draft_key, prevention_event_id DESC);
CREATE TRIGGER event_revisions_no_update BEFORE UPDATE ON event_revisions
BEGIN SELECT RAISE(ABORT, 'event revisions are immutable'); END;
CREATE TRIGGER event_revisions_no_delete BEFORE DELETE ON event_revisions
BEGIN SELECT RAISE(ABORT, 'event revisions are immutable'); END;
CREATE TRIGGER publication_events_no_update BEFORE UPDATE ON publication_events
BEGIN SELECT RAISE(ABORT, 'publication events are immutable'); END;
CREATE TRIGGER publication_events_no_delete BEFORE DELETE ON publication_events
BEGIN SELECT RAISE(ABORT, 'publication events are immutable'); END;
CREATE TRIGGER prevention_draft_events_no_update
BEFORE UPDATE ON prevention_draft_events
BEGIN SELECT RAISE(ABORT, 'prevention draft events are immutable'); END;
CREATE TRIGGER prevention_draft_events_no_delete
BEFORE DELETE ON prevention_draft_events
BEGIN SELECT RAISE(ABORT, 'prevention draft events are immutable'); END;
PRAGMA user_version = 1;
"""


def _create_exact_v1_database(database: Path, *, populated: bool = False) -> None:
    with sqlite3.connect(database) as connection:
        connection.executescript(_V1_SCHEMA_SQL)
        if populated:
            event = _event()
            observed = "2026-08-30T08:00:00.000000Z"
            revision_hash = guardian_state._legacy_revision_hash(event)  # noqa: SLF001
            body_hash = hashlib.sha256(event.body.encode("utf-8")).hexdigest()
            connection.execute(
                """
                INSERT INTO event_revisions (
                    repository, pr_number, kind, event_id, body_hash,
                    revision_hash, head_sha, base_sha, author, author_id,
                    author_type, locale, event_updated_at, path, line, html_url,
                    deleted, observed_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event.repository,
                    event.pr_number,
                    event.kind,
                    event.event_id,
                    body_hash,
                    revision_hash,
                    event.head_sha,
                    event.base_sha,
                    event.author,
                    event.author_id,
                    event.author_type,
                    event.locale,
                    event.updated_at,
                    event.path,
                    event.line,
                    event.html_url,
                    int(event.deleted),
                    observed,
                ),
            )
            revision_id = int(
                connection.execute("SELECT last_insert_rowid()").fetchone()[0]
            )
            connection.execute(
                "INSERT INTO event_raw_bodies VALUES (?, ?, ?)",
                (revision_id, event.body, observed),
            )
            connection.execute(
                "INSERT INTO runs VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    "00000000-0000-4000-8000-000000000001",
                    event.repository,
                    event.locale,
                    GuardianMode.OBSERVE.value,
                    "completed",
                    observed,
                    observed,
                    "legacy summary",
                ),
            )
            connection.execute(
                """
                INSERT INTO actions (
                    run_id, event_revision_id, action, status, details_json,
                    occurred_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    "00000000-0000-4000-8000-000000000001",
                    revision_id,
                    "observe",
                    "completed",
                    "{}",
                    observed,
                ),
            )
    database.chmod(0o600)


def _create_v2_migration_fixture(database: Path) -> None:
    """Create the frozen migration-relevant v2 table shapes."""

    _create_exact_v1_database(database)
    with sqlite3.connect(database) as connection:
        connection.executescript(
            """
            CREATE TABLE historical_pull_completions (
                completion_id INTEGER PRIMARY KEY AUTOINCREMENT,
                repository TEXT NOT NULL,
                repository_id INTEGER NOT NULL CHECK (repository_id > 0),
                pull_id INTEGER NOT NULL CHECK (pull_id > 0),
                pr_number INTEGER NOT NULL CHECK (pr_number > 0),
                pull_revision_digest TEXT NOT NULL,
                policy_digest TEXT NOT NULL,
                authority_scope TEXT NOT NULL CHECK (
                    authority_scope IN ('assessment', 'prevention', 'remediation')
                ),
                completed_at TEXT NOT NULL,
                head_sha TEXT NOT NULL,
                base_sha TEXT NOT NULL,
                event_revision_ids_json TEXT NOT NULL,
                UNIQUE (
                    repository, repository_id, pull_id, pull_revision_digest,
                    policy_digest, authority_scope
                )
            );
            CREATE TABLE remediation_draft_events (
                remediation_event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                draft_key TEXT NOT NULL,
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
            CREATE TABLE remediation_draft_edit_events (
                edit_event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                draft_key TEXT NOT NULL,
                edit_hash TEXT NOT NULL,
                UNIQUE (draft_key, edit_hash)
            );
            CREATE INDEX remediation_draft_events_pending
                ON remediation_draft_events(
                    target_repository, draft_key, remediation_event_id DESC
                );
            CREATE INDEX remediation_draft_edits_by_hash
                ON remediation_draft_edit_events(edit_hash, draft_key);
            PRAGMA user_version = 2;
            """
        )


def _create_v3_migration_fixture(database: Path) -> None:
    """Create the frozen migration-relevant v3 shapes and pending retry."""

    _create_v2_migration_fixture(database)
    with sqlite3.connect(database) as connection:
        connection.executescript(
            """
            ALTER TABLE historical_pull_completions
                ADD COLUMN event_revision_watermark INTEGER NOT NULL DEFAULT 0
                CHECK (event_revision_watermark >= 0);
            ALTER TABLE remediation_draft_edit_events ADD COLUMN target_hash TEXT;
            CREATE INDEX remediation_draft_edits_by_target
                ON remediation_draft_edit_events(target_hash, draft_key);
            CREATE TABLE historical_pull_retry_events (
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
            CREATE INDEX historical_pull_retry_latest
                ON historical_pull_retry_events(
                    repository, repository_id, policy_digest, pull_id,
                    retry_event_id DESC
                );
            CREATE TRIGGER historical_pull_retries_no_update
            BEFORE UPDATE ON historical_pull_retry_events
            BEGIN SELECT RAISE(ABORT, 'historical pull retries are immutable'); END;
            CREATE TRIGGER historical_pull_retries_no_delete
            BEFORE DELETE ON historical_pull_retry_events
            BEGIN SELECT RAISE(ABORT, 'historical pull retries are immutable'); END;
            INSERT INTO historical_pull_retry_events (
                repository, repository_id, policy_digest, pull_id, pr_number,
                phase, failure_type, occurred_at
            ) VALUES (
                'acme/widgets', 42,
                'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
                500, 12, 'pending', 'GitHubAPIError',
                '2026-09-01T08:00:00.000000Z'
            );
            PRAGMA user_version = 3;
            """
        )


def _create_v4_migration_fixture(database: Path) -> None:
    """Create the frozen migration-relevant v4 state shape."""

    _create_v3_migration_fixture(database)
    with sqlite3.connect(database) as connection:
        connection.executescript(
            """
            CREATE TABLE historical_pull_retry_resolution_events (
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
            CREATE TABLE historical_pull_identities (
                identity_id INTEGER PRIMARY KEY AUTOINCREMENT,
                repository TEXT NOT NULL,
                repository_id INTEGER NOT NULL CHECK (repository_id > 0),
                pull_id INTEGER NOT NULL CHECK (pull_id > 0),
                pr_number INTEGER NOT NULL CHECK (pr_number > 0),
                first_seen_at TEXT NOT NULL,
                UNIQUE (repository, repository_id, pull_id),
                UNIQUE (repository, repository_id, pr_number)
            );
            CREATE TABLE remediation_checkpoint_events (
                checkpoint_event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                draft_key TEXT NOT NULL UNIQUE,
                occurred_at TEXT NOT NULL
            );
            CREATE TABLE remediation_recovery_attempt_events (
                recovery_attempt_id INTEGER PRIMARY KEY AUTOINCREMENT,
                draft_key TEXT NOT NULL,
                occurred_at TEXT NOT NULL
            );
            CREATE TABLE remediation_resolution_events (
                resolution_id INTEGER PRIMARY KEY AUTOINCREMENT,
                draft_key TEXT NOT NULL UNIQUE,
                resolution TEXT NOT NULL CHECK (
                    resolution IN ('merged', 'operator_quarantined')
                ),
                occurred_at TEXT NOT NULL
            );
            CREATE TRIGGER remediation_checkpoint_events_no_update
            BEFORE UPDATE ON remediation_checkpoint_events
            BEGIN SELECT RAISE(ABORT, 'remediation checkpoints are immutable'); END;
            CREATE TRIGGER remediation_checkpoint_events_no_delete
            BEFORE DELETE ON remediation_checkpoint_events
            BEGIN SELECT RAISE(ABORT, 'remediation checkpoints are immutable'); END;
            CREATE TRIGGER remediation_recovery_attempts_no_update
            BEFORE UPDATE ON remediation_recovery_attempt_events
            BEGIN SELECT RAISE(ABORT, 'remediation recovery attempts are immutable'); END;
            CREATE TRIGGER remediation_recovery_attempts_no_delete
            BEFORE DELETE ON remediation_recovery_attempt_events
            BEGIN SELECT RAISE(ABORT, 'remediation recovery attempts are immutable'); END;
            CREATE TRIGGER remediation_resolutions_no_update
            BEFORE UPDATE ON remediation_resolution_events
            BEGIN SELECT RAISE(ABORT, 'remediation resolutions are immutable'); END;
            CREATE TRIGGER remediation_resolutions_no_delete
            BEFORE DELETE ON remediation_resolution_events
            BEGIN SELECT RAISE(ABORT, 'remediation resolutions are immutable'); END;
            PRAGMA user_version = 4;
            """
        )


def _populate_v4_remediation_fixture(
    database: Path,
) -> tuple[
    str,
    HistoricalPullReference,
    str,
    HistoricalPullReference,
    HistoricalPullReference,
]:
    """Add recoverable and unattested v4 remediation rows."""

    run_id = "00000000-0000-4000-8000-000000000004"
    quarantined_key = "d" * 64
    checkpointed_key = "c" * 64
    quarantined_source = HistoricalPullReference(
        repository="acme/widgets",
        repository_id=42,
        pull_id=600,
        pr_number=60,
        pull_revision_digest="1" * 64,
        authority_digest=guardian_state._LEGACY_UNATTESTED_AUTHORITY_DIGEST,
        policy_digest="2" * 64,
        head_sha="a" * 40,
        base_sha="b" * 40,
    )
    checkpointed_source = HistoricalPullReference(
        repository="acme/widgets",
        repository_id=42,
        pull_id=601,
        pr_number=61,
        pull_revision_digest="3" * 64,
        authority_digest=guardian_state._LEGACY_UNATTESTED_AUTHORITY_DIGEST,
        policy_digest="2" * 64,
        head_sha="a" * 40,
        base_sha="b" * 40,
    )
    unattested_source = HistoricalPullReference(
        repository="acme/widgets",
        repository_id=42,
        pull_id=602,
        pr_number=62,
        pull_revision_digest="4" * 64,
        authority_digest=guardian_state._LEGACY_UNATTESTED_AUTHORITY_DIGEST,
        policy_digest="2" * 64,
        head_sha="c" * 40,
        base_sha="d" * 40,
    )

    def source_json(source: HistoricalPullReference) -> str:
        return json.dumps(
            [
                {
                    "base_sha": source.base_sha,
                    "head_sha": source.head_sha,
                    "policy_digest": source.policy_digest,
                    "pr_number": source.pr_number,
                    "pull_id": source.pull_id,
                    "pull_revision_digest": source.pull_revision_digest,
                    "repository": source.repository,
                    "repository_id": source.repository_id,
                }
            ],
            separators=(",", ":"),
            sort_keys=True,
        )

    with sqlite3.connect(database) as connection:
        connection.execute(
            "INSERT INTO runs VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                run_id,
                "acme/widgets",
                "ru",
                GuardianMode.PROPOSE_PREVENTION.value,
                "completed",
                "2026-08-30T12:00:00.000000Z",
                "2026-08-30T12:02:00.000000Z",
                "legacy remediation run",
            ),
        )
        connection.executemany(
            """
            INSERT INTO historical_pull_identities (
                repository, repository_id, pull_id, pr_number, first_seen_at
            ) VALUES (?, ?, ?, ?, ?)
            """,
            (
                (
                    "acme/widgets",
                    42,
                    pull_id,
                    pr_number,
                    "2026-08-30T12:00:00.000000Z",
                )
                for pull_id, pr_number in ((500, 12), (600, 60), (601, 61), (602, 62))
            ),
        )
        revision_ids: list[int] = []
        for index, source in enumerate(
            (quarantined_source, checkpointed_source),
            start=1,
        ):
            event = _event(
                repository=source.repository,
                pr_number=source.pr_number,
                event_id=str(99000 + index),
                body=f"Legacy finding {index}",
            )
            cursor = connection.execute(
                """
                INSERT INTO event_revisions (
                    repository, pr_number, kind, event_id, body_hash,
                    revision_hash, head_sha, base_sha, author, author_id,
                    author_type, locale, event_updated_at, path, line,
                    html_url, deleted, observed_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event.repository,
                    event.pr_number,
                    event.kind,
                    event.event_id,
                    hashlib.sha256(event.body.encode()).hexdigest(),
                    guardian_state._revision_hash(event),  # noqa: SLF001
                    event.head_sha,
                    event.base_sha,
                    event.author,
                    event.author_id,
                    event.author_type,
                    event.locale,
                    event.updated_at,
                    event.path,
                    event.line,
                    event.html_url,
                    0,
                    "2026-08-30T12:00:00.000000Z",
                ),
            )
            revision_ids.append(int(cursor.lastrowid))

        def insert_draft(
            *,
            draft_key: str,
            source: HistoricalPullReference,
            revision_id: int,
            edit_hash: str,
            phases: tuple[str, ...],
            draft_number: int,
        ) -> None:
            batch_hash = guardian_state.remediation_batch_hash((edit_hash,))
            for phase in phases:
                opened = phase == "draft_opened"
                connection.execute(
                    """
                    INSERT INTO remediation_draft_events (
                        draft_key, run_id, target_repository,
                        target_repository_id, target_base_branch,
                        target_base_sha, push_repository, push_repository_id,
                        branch, candidate_sha, evidence_hash, batch_hash,
                        source_pulls_json, event_revision_ids_json, title, body,
                        phase, draft_number, draft_url, occurred_at
                    ) VALUES (
                        ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
                    )
                    """,
                    (
                        draft_key,
                        run_id,
                        source.repository,
                        source.repository_id,
                        "main",
                        "a" * 40,
                        "localize-bot/widgets",
                        84,
                        f"guardian/remediation-{draft_key}",
                        "e" * 40,
                        "f" * 64,
                        batch_hash,
                        source_json(source),
                        json.dumps([revision_id], separators=(",", ":")),
                        "Review legacy historical corrections",
                        "Legacy signed remediation candidate.\n",
                        phase,
                        draft_number if opened else None,
                        (
                            f"https://github.test/acme/widgets/pull/{draft_number}"
                            if opened
                            else None
                        ),
                        "2026-08-30T12:00:00.000000Z",
                    ),
                )
            connection.execute(
                """
                INSERT INTO remediation_draft_edit_events (
                    draft_key, edit_hash, target_hash
                ) VALUES (?, ?, ?)
                """,
                (
                    draft_key,
                    edit_hash,
                    hashlib.sha256(f"target:{edit_hash}".encode()).hexdigest(),
                ),
            )

        insert_draft(
            draft_key=quarantined_key,
            source=quarantined_source,
            revision_id=revision_ids[0],
            edit_hash="5" * 64,
            phases=("validated",),
            draft_number=90,
        )
        insert_draft(
            draft_key=checkpointed_key,
            source=checkpointed_source,
            revision_id=revision_ids[1],
            edit_hash="6" * 64,
            phases=("validated", "pushed", "draft_opened"),
            draft_number=91,
        )
        connection.execute(
            """
            INSERT INTO remediation_resolution_events (
                draft_key, resolution, occurred_at
            ) VALUES (?, 'operator_quarantined', ?)
            """,
            (quarantined_key, "2026-08-30T12:01:00.000000Z"),
        )
        connection.execute(
            """
            INSERT INTO remediation_checkpoint_events (draft_key, occurred_at)
            VALUES (?, ?)
            """,
            (checkpointed_key, "2026-08-30T12:01:00.000000Z"),
        )
        for source, event_ids, watermark in (
            (checkpointed_source, (revision_ids[1],), revision_ids[1]),
            (unattested_source, (), revision_ids[1]),
        ):
            connection.execute(
                """
                INSERT INTO historical_pull_completions (
                    repository, repository_id, pull_id, pr_number,
                    pull_revision_digest, policy_digest, authority_scope,
                    completed_at, head_sha, base_sha,
                    event_revision_ids_json, event_revision_watermark
                ) VALUES (?, ?, ?, ?, ?, ?, 'remediation', ?, ?, ?, ?, ?)
                """,
                (
                    source.repository,
                    source.repository_id,
                    source.pull_id,
                    source.pr_number,
                    source.pull_revision_digest,
                    source.policy_digest,
                    "2026-08-30T12:00:00.000000Z",
                    source.head_sha,
                    source.base_sha,
                    json.dumps(event_ids, separators=(",", ":")),
                    watermark,
                ),
            )
    return (
        quarantined_key,
        quarantined_source,
        checkpointed_key,
        checkpointed_source,
        unattested_source,
    )


def _event(
    *,
    body: str = "Please use the glossary term.",
    head_sha: str = "a" * 40,
    base_sha: str = "b" * 40,
    repository: str = "acme/widgets",
    pr_number: int = 123,
    kind: str = "review_comment",
    event_id: str = "98765",
    author: str = "coderabbitai[bot]",
    author_id: int = 202,
    author_type: str = "Bot",
    locale: str = "ru",
    html_url: str | None = None,
) -> FeedbackEvent:
    return FeedbackEvent(
        repository=repository,
        pr_number=pr_number,
        kind=kind,
        event_id=event_id,
        author=author,
        author_id=author_id,
        author_type=author_type,
        body=body,
        head_sha=head_sha,
        base_sha=base_sha,
        locale=locale,
        updated_at="2026-08-30T08:00:00Z",
        path="l10n/messages_ru.properties",
        line=17,
        html_url=html_url
        or (
            f"https://github.test/{repository}/pull/{pr_number}#discussion_r{event_id}"
        ),
    )


def test_policy_rejections_only_resolve_the_same_effective_policy(
    tmp_path: Path,
) -> None:
    """A deterministic rejection is terminal only under its matching policy digest."""
    with GuardianState(tmp_path / "guardian.sqlite3") as state:
        revision = state.record_feedback_event(_event())
        run_id = state.start_run(
            repository="acme/widgets",
            locale="ru",
            mode=GuardianMode.APPLY_OWNED_TRANSLATIONS,
        )
        state.record_action(
            run_id=run_id,
            event_revision_id=revision.revision_id,
            action="apply-owned-translations",
            status="skipped",
            details={"outcome": "deterministic_policy_rejection"},
        )
        assert state.pending_event_revisions() == ()
        assert state.pending_event_revisions(policy_digest="a" * 64)
        state.record_action(
            run_id=run_id,
            event_revision_id=revision.revision_id,
            action="apply-owned-translations",
            status="skipped",
            details={
                "outcome": "deterministic_policy_rejection",
                "policy_digest": "a" * 64,
            },
        )
        assert state.pending_event_revisions(policy_digest="a" * 64) == ()
        assert state.pending_event_revisions(policy_digest="b" * 64)
        state.record_action(
            run_id=run_id,
            event_revision_id=revision.revision_id,
            action="apply-owned-translations",
            status="completed",
            details={"outcome": "applied"},
        )
        assert state.pending_event_revisions(policy_digest="b" * 64) == ()


def test_exact_duplicate_is_not_pending_but_edits_and_sha_changes_are(
    tmp_path: Path,
) -> None:
    with GuardianState(tmp_path / "guardian.sqlite3") as state:
        first = state.record_feedback_event(_event())
        assert first.is_new is True
        assert [item.revision_id for item in state.pending_event_revisions()] == [
            first.revision_id
        ]
        run_id = state.start_run(
            repository="acme/widgets",
            locale="ru",
            mode=GuardianMode.OBSERVE,
        )
        state.record_action(
            run_id=run_id,
            event_revision_id=first.revision_id,
            action="report",
            status="completed",
            details={"result": "reported"},
        )

        duplicate = state.record_feedback_event(_event())
        assert duplicate.revision_id == first.revision_id
        assert duplicate.is_new is False
        assert state.pending_event_revisions() == ()

        edited = state.record_feedback_event(_event(body="Use a different term."))
        moved_head = state.record_feedback_event(_event(head_sha="c" * 40))
        moved_base = state.record_feedback_event(_event(base_sha="d" * 40))

        assert edited.is_new is True
        assert moved_head.is_new is True
        assert moved_base.is_new is True
        assert [item.revision_id for item in state.pending_event_revisions()] == [
            edited.revision_id,
            moved_head.revision_id,
            moved_base.revision_id,
        ]


def test_display_login_rename_keeps_the_same_event_revision(tmp_path: Path) -> None:
    with GuardianState(tmp_path / "guardian.sqlite3") as state:
        first = state.record_feedback_event(_event(author="old-login"))
        renamed = state.record_feedback_event(_event(author="new-login"))

    assert renamed.revision_id == first.revision_id
    assert renamed.is_new is False


def test_pending_query_derives_terminal_status_bindings_from_policy(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with GuardianState(tmp_path / "guardian.sqlite3") as state:
        revision = state.record_feedback_event(_event())
        run_id = state.start_run(
            repository="acme/widgets",
            locale="ru",
            mode=GuardianMode.OBSERVE,
        )
        state.record_action(
            run_id=run_id,
            event_revision_id=revision.revision_id,
            action="observe",
            status="failed",
        )
        assert tuple(item.revision_id for item in state.pending_event_revisions()) == (
            revision.revision_id,
        )

        monkeypatch.setattr(
            guardian_state,
            "_TERMINAL_ACTION_STATUSES",
            frozenset({"completed", "failed", "skipped"}),
        )

        assert state.pending_event_revisions() == ()


def test_state_database_is_private_even_when_created_under_a_permissive_umask(
    tmp_path: Path,
) -> None:
    path = tmp_path / "guardian.sqlite3"
    previous_umask = os.umask(0)
    try:
        with GuardianState(path):
            pass
    finally:
        os.umask(previous_umask)

    assert path.stat().st_mode & 0o777 == 0o600


def test_live_sqlite_artifacts_are_private_under_a_restrictive_umask(
    tmp_path: Path,
) -> None:
    path = tmp_path / "guardian.sqlite3"
    previous_umask = os.umask(0o777)
    try:
        with GuardianState(path) as state:
            state.record_health(
                component="test",
                status="ok",
                message="force a WAL write",
            )
            artifacts = (
                path,
                Path(f"{path}-wal"),
                Path(f"{path}-shm"),
            )
            assert all(artifact.is_file() for artifact in artifacts)
            assert all(
                artifact.stat().st_mode & 0o777 == 0o600
                and artifact.stat().st_nlink == 1
                for artifact in artifacts
            )
    finally:
        os.umask(previous_umask)


def test_state_refuses_a_symlink_without_touching_its_target(tmp_path: Path) -> None:
    target = tmp_path / "foreign.sqlite3"
    target.write_text("do not modify", encoding="utf-8")
    target.chmod(0o644)
    state_path = tmp_path / "guardian.sqlite3"
    state_path.symlink_to(target)

    with pytest.raises(ValueError, match="symlink"):
        GuardianState(state_path)

    assert target.read_text(encoding="utf-8") == "do not modify"
    assert target.stat().st_mode & 0o777 == 0o644


def test_state_refuses_a_hardlinked_database_without_opening_it(
    tmp_path: Path,
) -> None:
    state_path = tmp_path / "guardian.sqlite3"
    state_path.write_bytes(b"not a database")
    state_path.chmod(0o600)
    alias = tmp_path / "state-alias"
    alias.hardlink_to(state_path)

    with pytest.raises(ValueError, match="hard-linked"):
        GuardianState(state_path)

    assert state_path.read_bytes() == b"not a database"
    assert state_path.stat().st_nlink == 2


@pytest.mark.parametrize("suffix", ["-wal", "-shm", "-journal"])
@pytest.mark.parametrize("unsafe_kind", ["hardlink", "symlink", "mode", "directory"])
def test_state_refuses_unsafe_sqlite_sidecars_before_they_can_be_mutated(
    tmp_path: Path,
    suffix: str,
    unsafe_kind: str,
) -> None:
    state_path = tmp_path / "guardian.sqlite3"
    with GuardianState(state_path):
        pass
    sidecar = Path(f"{state_path}{suffix}")
    if sidecar.exists() or sidecar.is_symlink():
        sidecar.unlink()
    sentinel = tmp_path / f"sentinel-{suffix.removeprefix('-')}"
    if unsafe_kind == "directory":
        sidecar.mkdir(mode=0o700)
    else:
        sentinel.write_bytes(b"do not mutate")
        sentinel.chmod(0o600)
        if unsafe_kind == "hardlink":
            sidecar.hardlink_to(sentinel)
        elif unsafe_kind == "symlink":
            sidecar.symlink_to(sentinel)
        else:
            sidecar.write_bytes(b"do not mutate")
            sidecar.chmod(0o644)

    with pytest.raises(ValueError, match="state artifact"):
        GuardianState(state_path)

    if unsafe_kind in {"hardlink", "symlink"}:
        assert sentinel.read_bytes() == b"do not mutate"
    elif unsafe_kind == "mode":
        assert sidecar.read_bytes() == b"do not mutate"
        assert sidecar.stat().st_mode & 0o777 == 0o644


def test_state_refuses_insecure_existing_files_and_directories(tmp_path: Path) -> None:
    insecure_file = tmp_path / "guardian.sqlite3"
    insecure_file.write_bytes(b"")
    insecure_file.chmod(0o644)

    with pytest.raises(ValueError, match="mode 0600"):
        GuardianState(insecure_file)
    assert insecure_file.stat().st_mode & 0o777 == 0o644

    private_root = tmp_path / "private"
    private_root.mkdir(mode=0o755)
    with pytest.raises(ValueError, match="mode 0700"):
        GuardianState(private_root / "guardian.sqlite3")
    assert not (private_root / "guardian.sqlite3").exists()


def test_future_schema_is_rejected_before_any_database_mutation(
    tmp_path: Path,
) -> None:
    state_path = tmp_path / "guardian.sqlite3"
    with sqlite3.connect(state_path) as connection:
        connection.execute("CREATE TABLE future_only (value TEXT NOT NULL)")
        connection.execute("INSERT INTO future_only VALUES ('sentinel')")
        connection.execute("PRAGMA user_version = 999")
    state_path.chmod(0o600)
    before = state_path.read_bytes()
    before_names = {item.name for item in tmp_path.iterdir()}

    with pytest.raises(RuntimeError, match="schema version 999"):
        GuardianState(state_path)

    assert state_path.read_bytes() == before
    assert {item.name for item in tmp_path.iterdir()} == before_names
    with sqlite3.connect(
        f"{state_path.resolve().as_uri()}?mode=ro", uri=True
    ) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 999
        assert connection.execute("SELECT value FROM future_only").fetchone()[0] == (
            "sentinel"
        )


def test_mode_escalation_reconsiders_feedback_but_never_repeats_same_authority(
    tmp_path: Path,
) -> None:
    with GuardianState(tmp_path / "guardian.sqlite3") as state:
        revision = state.record_feedback_event(
            _event(pr_number=123, head_sha="a" * 40, base_sha="b" * 40)
        )
        run_id = state.start_run(
            repository="acme/widgets",
            locale="ru",
            mode=GuardianMode.OBSERVE,
        )
        state.record_action(
            run_id=run_id,
            event_revision_id=revision.revision_id,
            action="observe",
            status="completed",
        )

        assert state.pending_event_revisions(mode=GuardianMode.OBSERVE) == ()
        assert [
            item.revision_id
            for item in state.pending_event_revisions(mode=GuardianMode.PREPARE)
        ] == [revision.revision_id]
        assert [
            item.revision_id
            for item in state.pending_event_revisions(
                mode=GuardianMode.APPLY_OWNED_TRANSLATIONS
            )
        ] == [revision.revision_id]


def test_revision_identity_is_scoped_to_repository_and_pr(tmp_path: Path) -> None:
    with GuardianState(tmp_path / "guardian.sqlite3") as state:
        first = state.record_feedback_event(_event())
        other_pr = state.record_feedback_event(_event(pr_number=124))
        other_repo = state.record_feedback_event(
            _event(repository="example/translations")
        )

        assert (
            len({first.revision_id, other_pr.revision_id, other_repo.revision_id}) == 3
        )
        assert len(state.pending_event_revisions()) == 3


@pytest.mark.parametrize(
    "changed",
    [
        {"author_id": 203},
        {"author_type": "User"},
        {"locale": "de"},
    ],
)
def test_revision_identity_binds_actor_identity_and_locale(
    tmp_path: Path,
    changed: dict[str, object],
) -> None:
    with GuardianState(tmp_path / "guardian.sqlite3") as state:
        original = state.record_feedback_event(_event())
        changed_revision = state.record_feedback_event(_event(**changed))

        assert changed_revision.is_new is True
        assert changed_revision.revision_id != original.revision_id


def test_runs_actions_costs_and_health_are_persisted(tmp_path: Path) -> None:
    now = datetime(2026, 8, 30, 8, 0, tzinfo=UTC)
    database_path = tmp_path / "guardian.sqlite3"

    with GuardianState(database_path) as state:
        revision = state.record_feedback_event(_event(), observed_at=now)
        run_id = state.start_run(
            repository="acme/widgets",
            locale="ru",
            mode=GuardianMode.PREPARE,
            started_at=now,
        )
        state.record_action(
            run_id=run_id,
            event_revision_id=revision.revision_id,
            action="prepare-replacement",
            status="completed",
            details={"edits": 1},
            occurred_at=now,
        )
        state.record_cost(
            run_id=run_id,
            amount_usd=Decimal("1.234567"),
            model="gpt-test",
            input_tokens=100,
            output_tokens=25,
            incurred_at=now,
        )
        state.finish_run(
            run_id,
            status="completed",
            summary="Prepared one replacement.",
            finished_at=now,
        )
        state.record_health(
            component="github-intake",
            status="healthy",
            message="Intake completed.",
            details={"events": 1},
            checked_at=now,
        )

    with GuardianState(database_path) as state:
        run = state.get_run(run_id)
        assert run.status == "completed"
        assert run.summary == "Prepared one replacement."
        assert state.cost_for_day(date(2026, 8, 30)) == Decimal("1.234567")
        health = state.latest_health("github-intake")
        assert health is not None
        assert health.status == "healthy"
        assert health.details == {"events": 1}
        assert state.pending_event_revisions() == ()


@pytest.mark.parametrize(
    "details_json",
    (
        pytest.param("{malformed", id="malformed-syntax"),
        pytest.param(
            json.dumps({"nested": _overdeep_json_value()}, separators=(",", ":")),
            id="over-depth",
        ),
        pytest.param("[]", id="wrong-shape"),
        pytest.param('{"events": 1}', id="non-canonical"),
    ),
)
def test_latest_health_rejects_malformed_details_json(
    tmp_path: Path,
    details_json: str,
) -> None:
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
    with GuardianState(tmp_path / "guardian.sqlite3") as state:
        health_id = state.record_health(
            component="github-intake",
            status="healthy",
            message="Intake completed.",
            details={"events": 1},
            checked_at=now,
        )
        state._connection.execute(  # noqa: SLF001 - frozen corruption fixture
            "UPDATE health SET details_json = ? WHERE health_id = ?",
            (details_json, health_id),
        )

        with pytest.raises(RuntimeError, match="Health ledger contains malformed data"):
            state.latest_health("github-intake")


def test_raw_event_body_can_expire_without_deleting_immutable_revision(
    tmp_path: Path,
) -> None:
    observed_at = datetime(2026, 1, 1, tzinfo=UTC)

    with GuardianState(tmp_path / "guardian.sqlite3") as state:
        revision = state.record_feedback_event(_event(), observed_at=observed_at)

        deleted = state.purge_raw_event_bodies(before=datetime(2026, 4, 1, tzinfo=UTC))

        assert deleted == 1
        retained = state.get_event_revision(revision.revision_id)
        assert retained is not None
        assert retained.body is None
        assert retained.body_hash == revision.body_hash
        assert retained.author_id == 202
        assert retained.author_type == "Bot"
        assert retained.path == "l10n/messages_ru.properties"
        assert retained.line == 17
        assert retained.html_url.endswith("#discussion_r98765")
        assert retained.updated_at == "2026-08-30T08:00:00Z"


def test_historical_completion_is_idempotent_and_scope_aware(tmp_path: Path) -> None:
    database = tmp_path / "guardian.sqlite3"
    metadata = {
        "repository": "acme/widgets",
        "repository_id": 42,
        "pull_id": 500,
        "pr_number": 12,
        "pull_revision_digest": "a" * 64,
        "policy_digest": "b" * 64,
    }
    with GuardianState(database) as state:
        assert (
            state.historical_pull_is_complete(
                **{key: value for key, value in metadata.items() if key != "pr_number"},
                authority_scope=HistoricalCheckScope.ASSESSMENT,
            )
            is False
        )
        assert (
            state.record_historical_pull_completion(
                **metadata,
                head_sha="c" * 40,
                base_sha="d" * 40,
                authority_scope=HistoricalCheckScope.ASSESSMENT,
            )
            is True
        )
        assert (
            state.record_historical_pull_completion(
                **metadata,
                head_sha="c" * 40,
                base_sha="d" * 40,
                authority_scope=HistoricalCheckScope.ASSESSMENT,
            )
            is False
        )
        assert (
            state.historical_pull_is_complete(
                **{key: value for key, value in metadata.items() if key != "pr_number"},
                authority_scope=HistoricalCheckScope.ASSESSMENT,
            )
            is True
        )
        assert (
            state.historical_pull_is_complete(
                **{key: value for key, value in metadata.items() if key != "pr_number"},
                authority_scope=HistoricalCheckScope.PREVENTION,
            )
            is False
        )

        assert (
            state.record_historical_pull_completion(
                **metadata,
                head_sha="c" * 40,
                base_sha="d" * 40,
                authority_scope=HistoricalCheckScope.PREVENTION,
            )
            is True
        )
        assert (
            state.historical_pull_is_complete(
                **{key: value for key, value in metadata.items() if key != "pr_number"},
                authority_scope=HistoricalCheckScope.PREVENTION,
            )
            is True
        )

    with GuardianState(database) as state:
        assert (
            state.historical_pull_is_complete(
                **{key: value for key, value in metadata.items() if key != "pr_number"},
                authority_scope=HistoricalCheckScope.PREVENTION,
            )
            is True
        )


def test_historical_completion_replay_keeps_its_original_watermark(
    tmp_path: Path,
) -> None:
    metadata = {
        "repository": "acme/widgets",
        "repository_id": 42,
        "pull_id": 500,
        "pr_number": 12,
        "pull_revision_digest": "a" * 64,
        "policy_digest": "b" * 64,
        "head_sha": "c" * 40,
        "base_sha": "d" * 40,
        "authority_scope": HistoricalCheckScope.REMEDIATION,
    }
    with GuardianState(tmp_path / "guardian.sqlite3") as state:
        state.record_feedback_event(
            _event(pr_number=12, head_sha="c" * 40, base_sha="d" * 40)
        )
        assert state.record_historical_pull_completion(**metadata) is True
        state.record_feedback_event(
            _event(
                pr_number=12,
                head_sha="c" * 40,
                base_sha="d" * 40,
                body="newer feedback",
            )
        )

        assert state.record_historical_pull_completion(**metadata) is False


def test_prevention_completion_also_satisfies_assessment_scope(tmp_path: Path) -> None:
    lookup = {
        "repository": "acme/widgets",
        "repository_id": 42,
        "pull_id": 500,
        "pull_revision_digest": "a" * 64,
        "policy_digest": "b" * 64,
    }
    with GuardianState(tmp_path / "guardian.sqlite3") as state:
        state.record_historical_pull_completion(
            **lookup,
            pr_number=12,
            head_sha="c" * 40,
            base_sha="d" * 40,
            authority_scope=HistoricalCheckScope.PREVENTION,
        )

        assert (
            state.historical_pull_is_complete(
                **lookup,
                authority_scope=HistoricalCheckScope.ASSESSMENT,
            )
            is True
        )


@pytest.mark.parametrize(
    ("recorded_scope", "requested_scope", "expected"),
    [
        (HistoricalCheckScope.REMEDIATION, HistoricalCheckScope.ASSESSMENT, False),
        (HistoricalCheckScope.REMEDIATION, HistoricalCheckScope.REMEDIATION, False),
        (HistoricalCheckScope.REMEDIATION, HistoricalCheckScope.PREVENTION, False),
        (HistoricalCheckScope.PREVENTION, HistoricalCheckScope.REMEDIATION, False),
        (HistoricalCheckScope.ASSESSMENT, HistoricalCheckScope.REMEDIATION, False),
    ],
)
def test_historical_remediation_scope_is_distinct_from_prevention(
    tmp_path: Path,
    recorded_scope: HistoricalCheckScope,
    requested_scope: HistoricalCheckScope,
    expected: bool,
) -> None:
    lookup = {
        "repository": "acme/widgets",
        "repository_id": 42,
        "pull_id": 500,
        "pull_revision_digest": "a" * 64,
        "policy_digest": "b" * 64,
    }
    with GuardianState(tmp_path / "guardian.sqlite3") as state:
        state.record_historical_pull_completion(
            **lookup,
            pr_number=12,
            head_sha="c" * 40,
            base_sha="d" * 40,
            authority_scope=recorded_scope,
        )

        assert (
            state.historical_pull_is_complete(
                **lookup,
                authority_scope=requested_scope,
            )
            is expected
        )


@pytest.mark.parametrize(
    ("changed_field", "changed_value"),
    [
        ("repository_id", 43),
        ("pull_id", 501),
        ("pull_revision_digest", "c" * 64),
        ("policy_digest", "d" * 64),
    ],
)
def test_historical_completion_is_bound_to_exact_pull_and_policy_revision(
    tmp_path: Path,
    changed_field: str,
    changed_value: int | str,
) -> None:
    lookup: dict[str, int | str] = {
        "repository": "acme/widgets",
        "repository_id": 42,
        "pull_id": 500,
        "pull_revision_digest": "a" * 64,
        "policy_digest": "b" * 64,
    }
    with GuardianState(tmp_path / "guardian.sqlite3") as state:
        state.record_historical_pull_completion(
            **lookup,
            pr_number=12,
            head_sha="c" * 40,
            base_sha="d" * 40,
            authority_scope=HistoricalCheckScope.ASSESSMENT,
        )
        changed = {**lookup, changed_field: changed_value}

        assert (
            state.historical_pull_is_complete(
                **changed,
                authority_scope=HistoricalCheckScope.ASSESSMENT,
            )
            is False
        )


def test_historical_completion_rejects_collision_and_is_append_only(
    tmp_path: Path,
) -> None:
    metadata = {
        "repository": "acme/widgets",
        "repository_id": 42,
        "pull_id": 500,
        "pr_number": 12,
        "pull_revision_digest": "a" * 64,
        "policy_digest": "b" * 64,
        "head_sha": "c" * 40,
        "base_sha": "d" * 40,
        "authority_scope": HistoricalCheckScope.ASSESSMENT,
    }
    with GuardianState(tmp_path / "guardian.sqlite3") as state:
        state.record_historical_pull_completion(**metadata)
        with pytest.raises(RuntimeError, match="identity collision"):
            state.record_historical_pull_completion(**{**metadata, "pr_number": 13})
        with pytest.raises(sqlite3.IntegrityError, match="historical pull completions"):
            state._connection.execute(  # noqa: SLF001 - DB immutability assertion
                "UPDATE historical_pull_completions SET pr_number = 13"
            )
        with pytest.raises(sqlite3.IntegrityError, match="historical pull completions"):
            state._connection.execute(  # noqa: SLF001 - DB immutability assertion
                "DELETE FROM historical_pull_completions"
            )
        with pytest.raises(
            sqlite3.IntegrityError,
            match="historical completion observation identity mismatch",
        ):
            state._connection.execute(  # noqa: SLF001 - DB invariant assertion
                """
                INSERT INTO historical_pull_completion_observations (
                    repository, repository_id, pull_id, pr_number,
                    policy_digest, authority_scope, completion_id, observed_at
                )
                SELECT repository, repository_id, pull_id, pr_number + 1,
                       policy_digest, authority_scope, completion_id, completed_at
                FROM historical_pull_completions
                """
            )
        with pytest.raises(
            sqlite3.IntegrityError,
            match="historical completion observations are immutable",
        ):
            state._connection.execute(  # noqa: SLF001 - DB immutability assertion
                "UPDATE historical_pull_completion_observations SET pr_number = 13"
            )
        with pytest.raises(
            sqlite3.IntegrityError,
            match="historical completion observations are immutable",
        ):
            state._connection.execute(  # noqa: SLF001 - DB immutability assertion
                "DELETE FROM historical_pull_completion_observations"
            )


@pytest.mark.parametrize(
    "changed_identity",
    [
        {"pr_number": 13},
        {"pull_id": 501},
    ],
)
def test_historical_completion_pins_pull_id_to_pr_number_across_revisions(
    tmp_path: Path,
    changed_identity: dict[str, int],
) -> None:
    metadata = {
        "repository": "acme/widgets",
        "repository_id": 42,
        "pull_id": 500,
        "pr_number": 12,
        "pull_revision_digest": "a" * 64,
        "policy_digest": "b" * 64,
        "head_sha": "c" * 40,
        "base_sha": "d" * 40,
        "authority_scope": HistoricalCheckScope.ASSESSMENT,
    }
    with GuardianState(tmp_path / "guardian.sqlite3") as state:
        state.record_historical_pull_completion(**metadata)
        assert (
            state.record_historical_pull_completion(
                **{
                    **metadata,
                    "pull_revision_digest": "c" * 64,
                    "policy_digest": "d" * 64,
                }
            )
            is True
        )

        with pytest.raises(RuntimeError, match="identity collision"):
            state.record_historical_pull_completion(
                **{
                    **metadata,
                    **changed_identity,
                    "pull_revision_digest": "e" * 64,
                    "policy_digest": "f" * 64,
                }
            )


def test_historical_discovery_cursor_round_trips_beyond_one_poll_page_bound(
    tmp_path: Path,
) -> None:
    started = datetime(2026, 9, 1, 8, 0, tzinfo=UTC)
    cycle_id = str(uuid4())
    with GuardianState(tmp_path / "guardian.sqlite3") as state:
        first = state.record_historical_discovery_progress(
            repository="acme/widgets",
            repository_id=42,
            policy_digest="b" * 64,
            cycle_id=cycle_id,
            cycle_started_at=started,
            next_page=101,
            next_offset=37,
            cycle_complete=False,
            expected_cursor_id=None,
            recorded_at=started,
        )

        assert (
            state.get_historical_discovery_cursor(
                repository="acme/widgets",
                repository_id=42,
                policy_digest="b" * 64,
            )
            == first
        )
        assert (first.next_page, first.next_offset) == (101, 37)

        completed = state.record_historical_discovery_progress(
            repository="acme/widgets",
            repository_id=42,
            policy_digest="b" * 64,
            cycle_id=cycle_id,
            cycle_started_at=started,
            next_page=1,
            next_offset=0,
            cycle_complete=True,
            expected_cursor_id=first.cursor_id,
            recorded_at=started + timedelta(minutes=1),
        )
        restarted = state.record_historical_discovery_progress(
            repository="acme/widgets",
            repository_id=42,
            policy_digest="b" * 64,
            cycle_id=str(uuid4()),
            cycle_started_at=started + timedelta(days=1),
            next_page=1,
            next_offset=0,
            cycle_complete=False,
            expected_cursor_id=completed.cursor_id,
            recorded_at=started + timedelta(days=1),
        )

        assert restarted.cursor_id > completed.cursor_id
        assert restarted.cycle_id != completed.cycle_id


def test_historical_discovery_cursor_rejects_stale_cas_and_numeric_overflow(
    tmp_path: Path,
) -> None:
    started = datetime(2026, 9, 1, 8, 0, tzinfo=UTC)
    common = {
        "repository": "acme/widgets",
        "repository_id": 42,
        "policy_digest": "b" * 64,
        "cycle_id": str(uuid4()),
        "cycle_started_at": started,
        "next_offset": 0,
        "cycle_complete": False,
        "recorded_at": started,
    }
    with GuardianState(tmp_path / "guardian.sqlite3") as state:
        first = state.record_historical_discovery_progress(
            **{**common, "next_offset": 5},
            next_page=2,
            expected_cursor_id=None,
        )
        with pytest.raises(RuntimeError, match="CAS collision"):
            state.record_historical_discovery_progress(
                **common,
                next_page=2,
                expected_cursor_id=None,
            )
        with pytest.raises(ValueError, match="next_page"):
            state.record_historical_discovery_progress(
                **common,
                next_page=2_147_483_648,
                expected_cursor_id=first.cursor_id,
            )
        for page, offset in ((2, 5), (2, 4), (1, 99)):
            with pytest.raises(ValueError, match="strictly forward"):
                state.record_historical_discovery_progress(
                    **{
                        **common,
                        "next_offset": offset,
                        "recorded_at": started + timedelta(minutes=1),
                    },
                    next_page=page,
                    expected_cursor_id=first.cursor_id,
                )


def test_historical_cycle_seen_pulls_are_active_append_only_and_idempotent(
    tmp_path: Path,
) -> None:
    started = datetime(2026, 9, 1, 8, 0, tzinfo=UTC)
    cycle_id = str(uuid4())
    identity = {
        "repository": "acme/widgets",
        "repository_id": 42,
        "policy_digest": "b" * 64,
        "cycle_id": cycle_id,
    }
    with GuardianState(tmp_path / "guardian.sqlite3") as state:
        cursor = state.record_historical_discovery_progress(
            **identity,
            cycle_started_at=started,
            next_page=1,
            next_offset=1,
            cycle_complete=False,
            expected_cursor_id=None,
            recorded_at=started,
        )

        state.record_historical_cycle_seen_pull(
            **identity,
            pull_id=500,
            pr_number=12,
            seen_at=started,
        )
        state.record_historical_cycle_seen_pull(
            **identity,
            pull_id=500,
            pr_number=12,
            seen_at=started + timedelta(minutes=1),
        )
        assert state.historical_cycle_seen_pulls(**identity) == ((500, 12),)

        for pull_id, pr_number in ((500, 13), (501, 12)):
            with pytest.raises(RuntimeError, match="identity collision"):
                state.record_historical_cycle_seen_pull(
                    **identity,
                    pull_id=pull_id,
                    pr_number=pr_number,
                    seen_at=started,
                )
        with pytest.raises(sqlite3.IntegrityError, match="cycle seen pulls"):
            state._connection.execute(  # noqa: SLF001 - DB immutability assertion
                "UPDATE historical_cycle_seen_pull_events SET pr_number = 13"
            )
        with pytest.raises(sqlite3.IntegrityError, match="cycle seen pulls"):
            state._connection.execute(  # noqa: SLF001 - DB immutability assertion
                "DELETE FROM historical_cycle_seen_pull_events"
            )

        completed = state.record_historical_discovery_progress(
            **identity,
            cycle_started_at=started,
            next_page=1,
            next_offset=0,
            cycle_complete=True,
            expected_cursor_id=cursor.cursor_id,
            recorded_at=started + timedelta(minutes=2),
        )
        assert completed.cycle_complete is True
        with pytest.raises(RuntimeError, match="not active"):
            state.historical_cycle_seen_pulls(**identity)
        with pytest.raises(RuntimeError, match="not active"):
            state.record_historical_cycle_seen_pull(
                **identity,
                pull_id=501,
                pr_number=13,
                seen_at=started + timedelta(minutes=2),
            )


def test_historical_cycle_seen_pull_rejects_wrong_cycle_and_values(
    tmp_path: Path,
) -> None:
    started = datetime(2026, 9, 1, 8, 0, tzinfo=UTC)
    identity = {
        "repository": "acme/widgets",
        "repository_id": 42,
        "policy_digest": "b" * 64,
    }
    cycle_id = str(uuid4())
    with GuardianState(tmp_path / "guardian.sqlite3") as state:
        state.record_historical_discovery_progress(
            **identity,
            cycle_id=cycle_id,
            cycle_started_at=started,
            next_page=1,
            next_offset=1,
            cycle_complete=False,
            expected_cursor_id=None,
            recorded_at=started,
        )
        with pytest.raises(RuntimeError, match="not active"):
            state.historical_cycle_seen_pulls(
                **identity,
                cycle_id=str(uuid4()),
            )
        with pytest.raises(ValueError, match="seen_at"):
            state.record_historical_cycle_seen_pull(
                **identity,
                cycle_id=cycle_id,
                pull_id=499,
                pr_number=11,
                seen_at=started - timedelta(microseconds=1),
            )
        for field, value in (("pull_id", 0), ("pr_number", True)):
            with pytest.raises(ValueError, match=field):
                state.record_historical_cycle_seen_pull(
                    **identity,
                    cycle_id=cycle_id,
                    seen_at=started,
                    **{
                        "pull_id": 500,
                        "pr_number": 12,
                        field: value,
                    },
                )


def test_historical_cycle_seen_pull_rejects_storage_bound_overflow(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """State cannot persist a cycle the bounded reader cannot load again."""

    started = datetime(2026, 9, 1, 8, 0, tzinfo=UTC)
    identity = {
        "repository": "acme/widgets",
        "repository_id": 42,
        "policy_digest": "b" * 64,
        "cycle_id": str(uuid4()),
    }
    monkeypatch.setattr(guardian_state, "_MAX_HISTORICAL_CYCLE_SEEN_PULLS", 1)
    with GuardianState(tmp_path / "guardian.sqlite3") as state:
        state.record_historical_discovery_progress(
            **identity,
            cycle_started_at=started,
            next_page=1,
            next_offset=0,
            cycle_complete=False,
            expected_cursor_id=None,
            recorded_at=started,
        )
        state.record_historical_cycle_seen_pull(
            **identity,
            pull_id=500,
            pr_number=12,
            seen_at=started,
        )

        # Idempotent replay at the bound is still safe.
        state.record_historical_cycle_seen_pull(
            **identity,
            pull_id=500,
            pr_number=12,
            seen_at=started,
        )
        with pytest.raises(RuntimeError, match="safety bound"):
            state.record_historical_cycle_seen_pull(
                **identity,
                pull_id=501,
                pr_number=13,
                seen_at=started,
            )

        assert state.historical_cycle_seen_pulls(**identity) == ((500, 12),)


def test_historical_pull_retry_ledger_is_append_only_and_resolvable(
    tmp_path: Path,
) -> None:
    started = datetime(2026, 9, 1, 8, 0, tzinfo=UTC)
    identity = {
        "repository": "acme/widgets",
        "repository_id": 42,
        "policy_digest": "b" * 64,
        "pull_id": 500,
        "pr_number": 12,
    }
    with GuardianState(tmp_path / "guardian.sqlite3") as state:
        assert (
            state.record_historical_pull_retry(
                **identity,
                failure_type="OSError",
                failed_at=started,
            )
            is True
        )
        assert (
            state.record_historical_pull_retry(
                **identity,
                failure_type="RuntimeError",
                failed_at=started + timedelta(minutes=1),
            )
            is False
        )
        assert state.pending_historical_pull_retries(
            repository="acme/widgets",
            repository_id=42,
            policy_digest="b" * 64,
        ) == ((500, 12),)

        assert (
            state.resolve_historical_pull_retry(
                **identity,
                resolved_at=started + timedelta(minutes=2),
            )
            is True
        )
        assert (
            state.resolve_historical_pull_retry(
                **identity,
                resolved_at=started + timedelta(minutes=3),
            )
            is False
        )
        assert (
            state.pending_historical_pull_retries(
                repository="acme/widgets",
                repository_id=42,
                policy_digest="b" * 64,
            )
            == ()
        )

        assert (
            state.record_historical_pull_retry(
                **identity,
                failure_type="GitHubAPIError",
                failed_at=started + timedelta(minutes=4),
            )
            is True
        )
        with pytest.raises(RuntimeError, match="identity collision"):
            state.record_historical_pull_retry(
                **{**identity, "pr_number": 13},
                failure_type="OSError",
                failed_at=started + timedelta(minutes=5),
            )
        with pytest.raises(sqlite3.IntegrityError, match="pull retries"):
            state._connection.execute(  # noqa: SLF001 - DB immutability assertion
                "UPDATE historical_pull_retry_events SET phase = 'resolved'"
            )
        with pytest.raises(sqlite3.IntegrityError, match="pull retries"):
            state._connection.execute(  # noqa: SLF001 - DB immutability assertion
                "DELETE FROM historical_pull_retry_events"
            )


def test_historical_pull_retry_operator_quarantine_requires_exact_acknowledgement(
    tmp_path: Path,
) -> None:
    started = datetime(2026, 9, 1, 8, 0, tzinfo=UTC)
    identity = {
        "repository": "acme/widgets",
        "repository_id": 42,
        "policy_digest": "b" * 64,
        "pull_id": 500,
        "pr_number": 12,
    }
    query = {
        "repository": "acme/widgets",
        "repository_id": 42,
        "policy_digest": "b" * 64,
    }
    with GuardianState(tmp_path / "guardian.sqlite3") as state:
        with pytest.raises(ValueError, match="exact pending"):
            state.record_historical_pull_retry_resolution(
                **identity,
                resolution="operator_quarantined",
                terminal_local_skip_acknowledged=True,
                occurred_at=started,
            )
        state.record_historical_pull_retry(
            **identity,
            failure_type="GitHubAPIError",
            failed_at=started,
        )
        with pytest.raises(ValueError, match="explicitly true"):
            state.record_historical_pull_retry_resolution(
                **identity,
                resolution="operator_quarantined",
                terminal_local_skip_acknowledged=False,
                occurred_at=started + timedelta(minutes=1),
            )
        with pytest.raises(ValueError, match="must not precede"):
            state.record_historical_pull_retry_resolution(
                **identity,
                resolution="operator_quarantined",
                terminal_local_skip_acknowledged=True,
                occurred_at=started - timedelta(seconds=1),
            )

        assert (
            state.record_historical_pull_retry_resolution(
                **identity,
                resolution="operator_quarantined",
                terminal_local_skip_acknowledged=True,
                occurred_at=started + timedelta(minutes=1),
            )
            is True
        )
        assert (
            state.record_historical_pull_retry_resolution(
                **identity,
                resolution="operator_quarantined",
                terminal_local_skip_acknowledged=True,
                occurred_at=started + timedelta(minutes=2),
            )
            is False
        )
        assert state.pending_historical_pull_retries(**query) == ()
        assert state.operator_quarantined_historical_pull_retries(**query) == (
            (500, 12),
        )
        assert state.historical_pull_retry_resolution(**identity) == (
            "operator_quarantined"
        )
        with pytest.raises(sqlite3.IntegrityError, match="retry resolutions"):
            state._connection.execute(  # noqa: SLF001 - DB immutability assertion
                "UPDATE historical_pull_retry_resolution_events "
                "SET resolution = 'operator_quarantined'"
            )
        with pytest.raises(sqlite3.IntegrityError, match="retry resolutions"):
            state._connection.execute(  # noqa: SLF001 - DB immutability assertion
                "DELETE FROM historical_pull_retry_resolution_events"
            )


def test_historical_pull_retry_operator_quarantine_enforces_write_bound(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        guardian_state,
        "_MAX_HISTORICAL_PULL_RETRY_RESOLUTIONS",
        1,
    )
    common = {
        "repository": "acme/widgets",
        "repository_id": 42,
        "policy_digest": "b" * 64,
    }
    started = datetime(2026, 9, 1, 8, 0, tzinfo=UTC)
    with GuardianState(tmp_path / "guardian.sqlite3") as state:
        for pull_id, pr_number in ((500, 12), (501, 13)):
            state.record_historical_pull_retry(
                **common,
                pull_id=pull_id,
                pr_number=pr_number,
                failure_type="GitHubAPIError",
                failed_at=started,
            )
        assert (
            state.record_historical_pull_retry_resolution(
                **common,
                pull_id=500,
                pr_number=12,
                resolution="operator_quarantined",
                terminal_local_skip_acknowledged=True,
                occurred_at=started + timedelta(minutes=1),
            )
            is True
        )
        with pytest.raises(RuntimeError, match="safety bound"):
            state.record_historical_pull_retry_resolution(
                **common,
                pull_id=501,
                pr_number=13,
                resolution="operator_quarantined",
                terminal_local_skip_acknowledged=True,
                occurred_at=started + timedelta(minutes=1),
            )

        assert state.operator_quarantined_historical_pull_retries(**common) == (
            (500, 12),
        )
        assert state.pending_historical_pull_retries(**common) == ((501, 13),)
        monkeypatch.setattr(guardian_state, "_MAX_HISTORICAL_PULL_RETRIES", 0)
        with pytest.raises(RuntimeError, match="retry count"):
            state.pending_historical_pull_retries(**common)
        monkeypatch.setattr(
            guardian_state,
            "_MAX_HISTORICAL_PULL_RETRY_RESOLUTIONS",
            0,
        )
        with pytest.raises(RuntimeError, match="resolution count"):
            state.operator_quarantined_historical_pull_retries(**common)


def test_operator_retry_worklist_is_bounded_and_advances_after_resolution(
    tmp_path: Path,
) -> None:
    common = {
        "repository": "acme/widgets",
        "repository_id": 42,
        "policy_digest": "b" * 64,
    }
    started = datetime(2026, 9, 1, 8, 0, tzinfo=UTC)
    with GuardianState(tmp_path / "guardian.sqlite3") as state:
        for offset in range(101):
            state.record_historical_pull_retry(
                **common,
                pull_id=500 + offset,
                pr_number=12 + offset,
                failure_type="GitHubAPIError",
                failed_at=started + timedelta(seconds=offset),
            )

        first_page = state.pending_historical_pull_retry_records()
        assert len(first_page) == 100
        assert state.pending_historical_pull_retry_count() == 101
        assert first_page[0].pull_id == 500
        assert first_page[-1].pull_id == 599

        first = first_page[0]
        state.record_historical_pull_retry_resolution(
            repository=first.repository,
            repository_id=first.repository_id,
            policy_digest=first.policy_digest,
            pull_id=first.pull_id,
            pr_number=first.pr_number,
            resolution="operator_quarantined",
            terminal_local_skip_acknowledged=True,
            occurred_at=started + timedelta(minutes=5),
        )
        second_page = state.pending_historical_pull_retry_records()
        assert len(second_page) == 100
        assert second_page[0].pull_id == 501
        assert second_page[-1].pull_id == 600

        with pytest.raises(ValueError, match="1 through 100"):
            state.pending_historical_pull_retry_records(limit=101)


def test_historical_pull_retry_ledger_enforces_pending_bound(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(guardian_state, "_MAX_HISTORICAL_PULL_RETRIES", 1)
    common = {
        "repository": "acme/widgets",
        "repository_id": 42,
        "policy_digest": "b" * 64,
        "failure_type": "OSError",
    }
    with GuardianState(tmp_path / "guardian.sqlite3") as state:
        state.record_historical_pull_retry(
            **common,
            pull_id=500,
            pr_number=12,
        )
        with pytest.raises(RuntimeError, match="safety bound"):
            state.record_historical_pull_retry(
                **common,
                pull_id=501,
                pr_number=13,
            )
        assert state.pending_historical_pull_retries(
            repository="acme/widgets",
            repository_id=42,
            policy_digest="b" * 64,
        ) == ((500, 12),)


@pytest.mark.parametrize(
    "overrides",
    [
        {"repository": ""},
        {"repository_id": 0},
        {"pull_id": 0},
        {"pr_number": 0},
        {"pull_revision_digest": "a" * 63},
        {"policy_digest": "not-a-digest"},
        {"authority_scope": "write"},
    ],
)
def test_historical_completion_rejects_invalid_metadata(
    tmp_path: Path,
    overrides: dict[str, object],
) -> None:
    metadata: dict[str, object] = {
        "repository": "acme/widgets",
        "repository_id": 42,
        "pull_id": 500,
        "pr_number": 12,
        "pull_revision_digest": "a" * 64,
        "policy_digest": "b" * 64,
        "head_sha": "c" * 40,
        "base_sha": "d" * 40,
        "authority_scope": HistoricalCheckScope.ASSESSMENT,
    }
    with GuardianState(tmp_path / "guardian.sqlite3") as state:
        with pytest.raises((TypeError, ValueError)):
            state.record_historical_pull_completion(**{**metadata, **overrides})


def test_state_migrates_v1_database_to_historical_completion_schema(
    tmp_path: Path,
) -> None:
    """Preserve released v1 state while introducing historical completion tracking."""
    database = tmp_path / "guardian.sqlite3"
    _create_exact_v1_database(database, populated=True)

    with GuardianState(database) as state:
        assert state.get_event_revision(1) is not None
        assert (
            state.record_historical_pull_completion(
                repository="acme/widgets",
                repository_id=42,
                pull_id=500,
                pr_number=12,
                pull_revision_digest="a" * 64,
                policy_digest="b" * 64,
                head_sha="c" * 40,
                base_sha="d" * 40,
                authority_scope=HistoricalCheckScope.ASSESSMENT,
            )
            is True
        )

    with sqlite3.connect(database) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 11


def test_populated_v1_event_remains_idempotent_after_migration(
    tmp_path: Path,
) -> None:
    database = tmp_path / "guardian.sqlite3"
    _create_exact_v1_database(database, populated=True)
    with GuardianState(database) as state:
        duplicate = state.record_feedback_event(_event(author="renamed-bot"))
        assert duplicate.revision_id == 1
        assert duplicate.is_new is False
        assert state.pending_event_revisions() == ()


def test_v1_migration_seals_candidate_against_already_open_writer(
    tmp_path: Path,
) -> None:
    database = tmp_path / "guardian.sqlite3"
    _create_exact_v1_database(database)
    observed = "2026-08-30T08:00:00.000000Z"
    draft_key = "a" * 64
    old_writer = sqlite3.connect(database)
    try:
        old_writer.execute(
            "INSERT INTO runs VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                "00000000-0000-4000-8000-000000000002",
                "acme/widgets",
                "ru",
                GuardianMode.PROPOSE_PREVENTION.value,
                "completed",
                observed,
                observed,
                "released prevention",
            ),
        )
        old_writer.execute(
            """
            INSERT INTO prevention_draft_events (
                draft_key, run_id, source_repository, target_repository,
                target_base_branch, target_base_sha, push_repository,
                branch, candidate_sha, evidence_hash, title, body, phase,
                occurred_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'validated', ?)
            """,
            (
                draft_key,
                "00000000-0000-4000-8000-000000000002",
                "acme/widgets",
                "guardian/pipeline",
                "main",
                "b" * 40,
                "guardian/pipeline",
                "guardian/prevention-existing",
                "c" * 40,
                "d" * 64,
                "Prevent recurrence",
                "Validated body\n",
                observed,
            ),
        )
        old_writer.commit()

        with GuardianState(database) as state:
            assert (
                state._connection.execute(  # noqa: SLF001
                    "SELECT COUNT(*) FROM prevention_legacy_candidate_events"
                ).fetchone()[0]
                == 1
            )

        with pytest.raises(
            sqlite3.IntegrityError,
            match="released-v1 prevention candidate is sealed",
        ):
            old_writer.execute(
                """
                INSERT INTO prevention_draft_events (
                    draft_key, run_id, source_repository, target_repository,
                    target_base_branch, target_base_sha, push_repository,
                    branch, candidate_sha, evidence_hash, title, body, phase,
                    occurred_at
                )
                SELECT draft_key, run_id, source_repository, target_repository,
                       target_base_branch, target_base_sha, push_repository,
                       branch, candidate_sha, evidence_hash, title, body,
                       'pushed', ?
                FROM prevention_draft_events
                WHERE draft_key = ? AND phase = 'validated'
                """,
                ("2026-08-30T08:01:00.000000Z", draft_key),
            )
        old_writer.rollback()
    finally:
        old_writer.close()

    with GuardianState(database) as state:
        phases = state._connection.execute(  # noqa: SLF001
            "SELECT phase FROM prevention_draft_events WHERE draft_key = ?",
            (draft_key,),
        ).fetchall()
        assert [str(row["phase"]) for row in phases] == ["validated"]


def test_v2_remediation_edit_table_gains_target_mapping_column(
    tmp_path: Path,
) -> None:
    """Upgrade legacy remediation edits with explicit target identity storage."""
    database = tmp_path / "guardian.sqlite3"
    _create_v2_migration_fixture(database)

    with GuardianState(database) as state:
        columns = {
            row["name"]
            for row in state._connection.execute(  # noqa: SLF001
                "PRAGMA table_info(remediation_draft_edit_events)"
            )
        }
        assert "target_hash" in columns

    with sqlite3.connect(database) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 11


def test_v3_pending_retry_survives_upgrade_and_gains_resolution_ledger(
    tmp_path: Path,
) -> None:
    """Keep pending historical retries across the resolution-ledger migration."""
    database = tmp_path / "guardian.sqlite3"
    _create_v3_migration_fixture(database)

    with GuardianState(database) as state:
        records = state.pending_historical_pull_retry_records()
        assert [(item.pull_id, item.pr_number) for item in records] == [(500, 12)]
        assert state.record_historical_pull_retry_resolution(
            repository="acme/widgets",
            repository_id=42,
            policy_digest="b" * 64,
            pull_id=500,
            pr_number=12,
            resolution="operator_quarantined",
            terminal_local_skip_acknowledged=True,
            occurred_at=datetime(2026, 9, 1, 8, 1, tzinfo=UTC),
        )

    with sqlite3.connect(database) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 11
        assert (
            connection.execute(
                "SELECT COUNT(*) FROM historical_pull_retry_events"
            ).fetchone()[0]
            == 1
        )
        assert (
            connection.execute(
                "SELECT COUNT(*) FROM historical_pull_retry_resolution_events"
            ).fetchone()[0]
            == 1
        )


def test_empty_v0_database_upgrades_to_v11(tmp_path: Path) -> None:
    """Initialize an empty database at the current supported schema version."""
    database = tmp_path / "guardian.sqlite3"
    with sqlite3.connect(database):
        pass
    database.chmod(0o600)

    with GuardianState(database) as state:
        assert state.status_snapshot(mode=GuardianMode.OBSERVE).pending_revisions == 0

    with sqlite3.connect(database) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 11


def test_v10_upgrade_preserves_audit_and_refuses_old_resolution_semantics(
    tmp_path: Path, monkeypatch,
) -> None:
    """Semantic schema migration preserves history and blocks old readers."""
    database = tmp_path / "guardian.sqlite3"
    with GuardianState(database) as state:
        revision = state.record_feedback_event(_event())
    with sqlite3.connect(database) as connection:
        connection.execute("PRAGMA user_version = 10")
    with GuardianState(database) as state:
        assert state.get_event_revision(revision.revision_id) is not None
        assert state.status_snapshot(mode=GuardianMode.PROPOSE_PREVENTION).pending_revisions == 1
    monkeypatch.setattr(guardian_state, "_SUPPORTED_SCHEMA_VERSIONS", frozenset(range(11)))
    with pytest.raises(RuntimeError, match="Unsupported guardian state schema version 11"):
        GuardianState(database)
    with sqlite3.connect(database) as connection:
        assert connection.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 11


def test_assessment_cache_and_cost_settlement_are_one_transaction(
    tmp_path: Path,
) -> None:
    created_at = datetime(2026, 1, 1, tzinfo=UTC)
    cache_key = "c" * 64
    result_json = '{"schema_version":1}'

    with GuardianState(tmp_path / "guardian.sqlite3") as state:
        run_id = state.start_run(
            repository="acme/widgets",
            locale="ru",
            mode=GuardianMode.OBSERVE,
            started_at=created_at,
        )
        reservation = state.try_reserve_budget(
            run_id=run_id,
            amount_usd=1,
            daily_limit_usd=2,
            model="gpt-test",
            reserved_at=created_at,
        )
        assert reservation is not None

        state.cache_assessment_and_settle_budget(
            cache_key=cache_key,
            repository="acme/widgets",
            pr_number=12,
            head_sha="a" * 40,
            base_sha="b" * 40,
            model="gpt-test",
            reasoning_effort="max",
            result_json=result_json,
            reservation_id=reservation,
            actual_cost_usd=0.25,
            input_tokens=100,
            output_tokens=20,
            created_at=created_at,
        )

        assert (
            state.cached_assessment_result(
                cache_key=cache_key,
                repository="acme/widgets",
                pr_number=12,
                head_sha="a" * 40,
                base_sha="b" * 40,
                model="gpt-test",
                reasoning_effort="max",
            )
            == result_json
        )
        assert state.cost_for_day(created_at.date()) == Decimal("0.25")

        second_reservation = state.try_reserve_budget(
            run_id=run_id,
            amount_usd=1,
            daily_limit_usd=2,
            model="gpt-test",
            reserved_at=created_at,
        )
        assert second_reservation is not None
        with pytest.raises(RuntimeError, match="collision"):
            state.cache_assessment_and_settle_budget(
                cache_key=cache_key,
                repository="acme/widgets",
                pr_number=12,
                head_sha="a" * 40,
                base_sha="b" * 40,
                model="gpt-test",
                reasoning_effort="max",
                result_json='{"different":true}',
                reservation_id=second_reservation,
                actual_cost_usd=0.75,
                input_tokens=1,
                output_tokens=1,
                created_at=created_at,
            )
        assert state.cost_for_day(created_at.date()) == Decimal("0.25")

        assert (
            state.purge_assessment_results(before=datetime(2026, 2, 1, tzinfo=UTC)) == 1
        )


def test_latest_revisions_support_deleted_comment_reconciliation(
    tmp_path: Path,
) -> None:
    with GuardianState(tmp_path / "guardian.sqlite3") as state:
        original = state.record_feedback_event(_event())
        metadata_edit = state.record_feedback_event(
            FeedbackEvent(
                **{
                    **_event().__dict__,
                    "line": 19,
                    "updated_at": "2026-08-30T08:30:00Z",
                }
            )
        )
        deleted = state.record_feedback_event(
            FeedbackEvent(
                **{
                    **_event().__dict__,
                    "body": "",
                    "deleted": True,
                    "updated_at": "2026-08-30T09:00:00Z",
                }
            )
        )

        latest = state.latest_event_revisions(repository="acme/widgets")

        assert len(latest) == 1
        assert latest[0].revision_id == deleted.revision_id
        assert latest[0].deleted is True
        assert latest[0].revision_id != original.revision_id
        assert metadata_edit.is_new is True
        assert metadata_edit.revision_id not in {
            original.revision_id,
            deleted.revision_id,
        }


def test_process_lease_is_exclusive_refreshable_and_recovers_after_expiry(
    tmp_path: Path,
) -> None:
    path = tmp_path / "guardian.sqlite3"
    now = datetime(2026, 8, 30, 8, 0, tzinfo=UTC)
    with GuardianState(path) as first, GuardianState(path) as second:
        assert first.acquire_lease(
            name="guardian-run",
            owner="one",
            ttl_seconds=60,
            now=now,
        )
        assert not second.acquire_lease(
            name="guardian-run",
            owner="two",
            ttl_seconds=60,
            now=now + timedelta(seconds=30),
        )
        assert first.refresh_lease(
            name="guardian-run",
            owner="one",
            ttl_seconds=60,
            now=now + timedelta(seconds=30),
        )
        assert not second.release_lease(name="guardian-run", owner="two")
        assert first.release_lease(name="guardian-run", owner="one")
        assert second.acquire_lease(
            name="guardian-run",
            owner="two",
            ttl_seconds=60,
            now=now + timedelta(seconds=31),
        )
        assert first.acquire_lease(
            name="guardian-run",
            owner="three",
            ttl_seconds=60,
            now=now + timedelta(seconds=92),
        )


def test_reconciles_crashed_runs_without_resolving_their_events(tmp_path: Path) -> None:
    now = datetime(2026, 8, 30, 10, 0, tzinfo=UTC)
    with GuardianState(tmp_path / "guardian.sqlite3") as state:
        revision = state.record_feedback_event(_event(), observed_at=now)
        stale_run = state.start_run(
            repository="acme/widgets",
            locale="ru",
            mode=GuardianMode.PREPARE,
            started_at=now,
        )
        state.record_action(
            run_id=stale_run,
            event_revision_id=revision.revision_id,
            action="prepare",
            status="pending",
            occurred_at=now,
        )
        fresh_run = state.start_run(
            repository="acme/widgets",
            locale="ru",
            mode=GuardianMode.OBSERVE,
            started_at=now + timedelta(hours=2),
        )

        recovered = state.reconcile_incomplete_runs(
            before=now + timedelta(hours=1),
            reconciled_at=now + timedelta(hours=3),
        )

        assert recovered == (stale_run,)
        assert state.get_run(stale_run).status == "failed"
        assert state.get_run(fresh_run).status == "running"
        assert tuple(item.revision_id for item in state.pending_event_revisions()) == (
            revision.revision_id,
        )


def test_budget_reservation_is_atomic_and_settles_to_actual_cost(
    tmp_path: Path,
) -> None:
    path = tmp_path / "guardian.sqlite3"
    now = datetime(2026, 8, 30, 10, 0, tzinfo=UTC)
    with GuardianState(path) as first, GuardianState(path) as second:
        run_one = first.start_run(
            repository="acme/widgets",
            locale="ru",
            mode=GuardianMode.OBSERVE,
            started_at=now,
        )
        run_two = second.start_run(
            repository="acme/widgets",
            locale="ru",
            mode=GuardianMode.OBSERVE,
            started_at=now,
        )
        reservation = first.try_reserve_budget(
            run_id=run_one,
            amount_usd="4.00",
            daily_limit_usd="5.00",
            model="gpt-test",
            reserved_at=now,
        )
        assert reservation is not None
        assert (
            second.try_reserve_budget(
                run_id=run_two,
                amount_usd="2.00",
                daily_limit_usd="5.00",
                model="gpt-test",
                reserved_at=now,
            )
            is None
        )
        assert first.budget_committed_for_day(now.date()) == Decimal("4")

        statements: list[str] = []
        first._connection.set_trace_callback(statements.append)
        first.settle_budget_reservation(
            reservation,
            actual_cost_usd="0.75",
            input_tokens=100,
            output_tokens=20,
            settled_at=now,
        )
        first._connection.set_trace_callback(None)

        assert "BEGIN IMMEDIATE" in statements
        assert first.cost_for_day(now.date()) == Decimal("0.75")
        assert first.budget_committed_for_day(now.date()) == Decimal("0.75")
        assert (
            second.try_reserve_budget(
                run_id=run_two,
                amount_usd="4.00",
                daily_limit_usd="5.00",
                model="gpt-test",
                reserved_at=now,
            )
            is not None
        )


def test_budget_reservation_rejects_naive_timestamp(tmp_path: Path) -> None:
    with GuardianState(tmp_path / "state.sqlite3") as state:
        run_id = state.start_run(
            repository="acme/widgets",
            locale="ru",
            mode=GuardianMode.OBSERVE,
            started_at=datetime(2026, 8, 30, tzinfo=UTC),
        )

        with pytest.raises(ValueError, match="timezone-aware"):
            state.try_reserve_budget(
                run_id=run_id,
                amount_usd=1,
                daily_limit_usd=2,
                model="test-model",
                reserved_at=datetime(2026, 8, 30, 12, 0),
            )


def test_unknown_model_cost_keeps_conservative_reservation(tmp_path: Path) -> None:
    now = datetime(2026, 8, 30, 10, 0, tzinfo=UTC)
    with GuardianState(tmp_path / "guardian.sqlite3") as state:
        run_id = state.start_run(
            repository="acme/widgets",
            locale="ru",
            mode=GuardianMode.OBSERVE,
            started_at=now,
        )
        reservation = state.try_reserve_budget(
            run_id=run_id,
            amount_usd="5.00",
            daily_limit_usd="5.00",
            model="gpt-test",
            reserved_at=now,
        )
        assert reservation is not None

        state.mark_budget_reservation_unknown(reservation, marked_at=now)

        assert state.cost_for_day(now.date()) == Decimal("0")
        assert state.budget_committed_for_day(now.date()) == Decimal("5")


def test_daily_model_call_reservations_are_atomic_and_fail_closed(
    tmp_path: Path,
) -> None:
    path = tmp_path / "guardian.sqlite3"
    now = datetime(2026, 8, 30, 10, 0, tzinfo=UTC)
    with GuardianState(path) as first, GuardianState(path) as second:
        run_one = first.start_run(
            repository="acme/widgets",
            locale="ru",
            mode=GuardianMode.OBSERVE,
            started_at=now,
        )
        run_two = second.start_run(
            repository="acme/widgets",
            locale="ru",
            mode=GuardianMode.OBSERVE,
            started_at=now,
        )

        first_call = first.try_reserve_model_call(
            run_id=run_one,
            daily_limit=1,
            model="gpt-test",
            purpose="assessment",
            reserved_at=now,
        )
        assert first_call is not None
        assert (
            second.try_reserve_model_call(
                run_id=run_two,
                daily_limit=1,
                model="gpt-test",
                purpose="assessment",
                reserved_at=now,
            )
            is None
        )
        assert first.model_calls_committed_for_day(now.date()) == 1

        first.finalize_model_call(first_call, status="cancelled", finalized_at=now)
        second_call = second.try_reserve_model_call(
            run_id=run_two,
            daily_limit=1,
            model="gpt-test",
            purpose="prevention",
            reserved_at=now,
        )
        assert second_call is not None
        second.finalize_model_call(second_call, status="unknown", finalized_at=now)
        assert first.model_calls_committed_for_day(now.date()) == 1


def test_subscription_assessment_cache_does_not_require_a_dollar_reservation(
    tmp_path: Path,
) -> None:
    created_at = datetime(2026, 8, 30, 10, 0, tzinfo=UTC)
    with GuardianState(tmp_path / "guardian.sqlite3") as state:
        state.cache_assessment_result(
            cache_key="d" * 64,
            repository="acme/widgets",
            pr_number=12,
            head_sha="a" * 40,
            base_sha="b" * 40,
            model="gpt-test",
            reasoning_effort="max",
            result_json='{"schema_version":1}',
            created_at=created_at,
        )

        assert (
            state.cached_assessment_result(
                cache_key="d" * 64,
                repository="acme/widgets",
                pr_number=12,
                head_sha="a" * 40,
                base_sha="b" * 40,
                model="gpt-test",
                reasoning_effort="max",
            )
            == '{"schema_version":1}'
        )


def test_publication_ledger_is_append_only_recoverable_and_idempotent(
    tmp_path: Path,
) -> None:
    with GuardianState(tmp_path / "guardian.sqlite3") as state:
        revision = state.record_feedback_event(
            _event(pr_number=123, head_sha="a" * 40, base_sha="b" * 40)
        )
        run_id = state.start_run(
            repository="acme/widgets",
            locale="ru",
            mode=GuardianMode.APPLY_OWNED_TRANSLATIONS,
        )
        metadata = {
            "run_id": run_id,
            "repository": "acme/widgets",
            "pr_number": 123,
            "original_head_sha": "a" * 40,
            "base_sha": "b" * 40,
            "commit_sha": "c" * 40,
            "publication_actor_id": 303,
            "publication_actor_type": "Bot",
            "event_revision_ids": (revision.revision_id,),
            "open_source": OpenPullAuthorityReference(
                repository="acme/widgets",
                repository_id=42,
                pull_id=456,
                pr_number=123,
                authority_digest="d" * 64,
                head_sha="a" * 40,
                base_sha="b" * 40,
                feedback_digest="f" * 64,
            ),
        }
        publication_key = state.record_publication_event(
            **metadata,
            phase="prepared",
            completion_actions=(
                (revision.revision_id, "completed", {"outcome": "applied"}),
            ),
        )

        pending = state.pending_publications(repository="acme/widgets")
        assert len(pending) == 1
        assert pending[0].publication_key == publication_key
        assert pending[0].phase == "prepared"
        assert pending[0].publication_actor_id == 303
        assert pending[0].publication_actor_type == "Bot"
        assert pending[0].repository_id == 42
        assert pending[0].event_revision_ids == (revision.revision_id,)
        assert pending[0].open_source == metadata["open_source"]
        plan_actor = state._connection.execute(  # noqa: SLF001
            "SELECT publication_actor_id, publication_actor_type "
            "FROM publication_completion_plan_items "
            "WHERE publication_key = ?",
            (publication_key,),
        ).fetchone()
        assert tuple(plan_actor) == (303, "Bot")
        assert (
            state.record_publication_event(
                **metadata,
                phase="prepared",
                completion_actions=(
                    (revision.revision_id, "completed", {"outcome": "applied"}),
                ),
            )
            == publication_key
        )

        state.record_publication_event(**metadata, phase="published")
        assert state.pending_publications()[0].phase == "published"
        with pytest.raises(ValueError, match="atomic publication finalization"):
            state.record_publication_event(**metadata, phase="replied")
        state.finalize_replied_publication(
            publication_key=publication_key,
            summary="Completed one exact publication.",
        )
        assert state.pending_publications() == ()

        replied = state.replied_publication_for_head(
            repository="acme/widgets",
            pr_number=123,
            head_sha="c" * 40,
            publication_actor_id=303,
            publication_actor_type="Bot",
        )
        assert replied is not None
        assert replied.phase == "replied"
        assert replied.open_source == metadata["open_source"]
        assert (
            state.replied_publication_for_head(
                repository="acme/renamed-widgets",
                repository_id=42,
                pr_number=123,
                head_sha="c" * 40,
                publication_actor_id=303,
                publication_actor_type="Bot",
            )
            == replied
        )
        assert (
            state.replied_publication_for_head(
                repository="acme/widgets",
                repository_id=43,
                pr_number=123,
                head_sha="c" * 40,
                publication_actor_id=303,
                publication_actor_type="Bot",
            )
            is None
        )
        assert (
            state.replied_publication_for_head(
                repository="acme/widgets",
                pr_number=123,
                head_sha="c" * 40,
                publication_actor_id=304,
                publication_actor_type="Bot",
            )
            is None
        )
        assert (
            state.replied_publication_for_head(
                repository="acme/widgets",
                pr_number=123,
                head_sha="c" * 40,
                publication_actor_id=303,
                publication_actor_type="User",
            )
            is None
        )

        with pytest.raises(
            ValueError,
            match="metadata does not match",
        ):
            state.record_publication_event(
                **{
                    **metadata,
                    "open_source": replace(
                        metadata["open_source"],  # type: ignore[arg-type]
                        authority_digest="e" * 64,
                    ),
                },
                phase="published",
            )

        with pytest.raises(sqlite3.IntegrityError, match="publication events"):
            state._connection.execute(  # noqa: SLF001 - DB immutability assertion
                "UPDATE publication_events SET phase = 'abandoned'"
            )


def test_publication_id_filter_survives_rename_without_foreign_starvation(
    tmp_path: Path,
) -> None:
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
    with GuardianState(tmp_path / "guardian.sqlite3") as state:
        foreign_run = state.start_run(
            repository="acme/current-name",
            locale="ru",
            mode=GuardianMode.APPLY_OWNED_TRANSLATIONS,
            started_at=now,
        )
        for index in range(101):
            revision = state.record_feedback_event(
                _event(
                    repository="acme/current-name",
                    pr_number=123,
                    event_id=str(20_000 + index),
                ),
                observed_at=now,
            )
            state.record_publication_event(
                run_id=foreign_run,
                repository="acme/current-name",
                pr_number=123,
                original_head_sha="a" * 40,
                base_sha="b" * 40,
                commit_sha=f"{index + 1:040x}",
                publication_actor_id=303,
                publication_actor_type="Bot",
                event_revision_ids=(revision.revision_id,),
                open_source=OpenPullAuthorityReference(
                    repository="acme/current-name",
                    repository_id=99,
                    pull_id=900,
                    pr_number=123,
                    authority_digest=f"{index + 1:064x}",
                    head_sha="a" * 40,
                    base_sha="b" * 40,
                    feedback_digest=f"{index + 102:064x}",
                ),
                phase="prepared",
                completion_actions=(
                    (revision.revision_id, "completed", {"outcome": "applied"}),
                ),
                occurred_at=now,
            )

        renamed_revision = state.record_feedback_event(
            _event(
                repository="acme/old-name",
                pr_number=123,
                event_id="30000",
            ),
            observed_at=now,
        )
        renamed_run = state.start_run(
            repository="acme/old-name",
            locale="ru",
            mode=GuardianMode.APPLY_OWNED_TRANSLATIONS,
            started_at=now,
        )
        renamed_key = state.record_publication_event(
            run_id=renamed_run,
            repository="acme/old-name",
            pr_number=123,
            original_head_sha="a" * 40,
            base_sha="b" * 40,
            commit_sha="f" * 40,
            publication_actor_id=303,
            publication_actor_type="Bot",
            event_revision_ids=(renamed_revision.revision_id,),
            open_source=OpenPullAuthorityReference(
                repository="acme/old-name",
                repository_id=42,
                pull_id=901,
                pr_number=123,
                authority_digest="d" * 64,
                head_sha="a" * 40,
                base_sha="b" * 40,
                feedback_digest="e" * 64,
            ),
            phase="prepared",
            completion_actions=(
                (
                    renamed_revision.revision_id,
                    "completed",
                    {"outcome": "applied"},
                ),
            ),
            occurred_at=now,
        )

        selected = state.pending_publications(
            repository="acme/current-name",
            repository_id=42,
            limit=1,
        )
        assert tuple(item.publication_key for item in selected) == (renamed_key,)


def test_publication_id_filter_detects_legacy_ambiguity_beyond_workset(
    tmp_path: Path,
) -> None:
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
    with GuardianState(tmp_path / "guardian.sqlite3") as state:
        revision = state.record_feedback_event(_event(), observed_at=now)
        run_id = state.start_run(
            repository="acme/widgets",
            locale="ru",
            mode=GuardianMode.APPLY_OWNED_TRANSLATIONS,
            started_at=now,
        )
        publication_keys: list[str] = []
        for index in range(102):
            publication_keys.append(
                state.record_publication_event(
                    run_id=run_id,
                    repository="acme/widgets",
                    pr_number=123,
                    original_head_sha="a" * 40,
                    base_sha="b" * 40,
                    commit_sha=f"{index + 1:040x}",
                    publication_actor_id=303,
                    publication_actor_type="Bot",
                    event_revision_ids=(revision.revision_id,),
                    open_source=OpenPullAuthorityReference(
                        repository="acme/widgets",
                        repository_id=42,
                        pull_id=456,
                        pr_number=123,
                        authority_digest=f"{index + 1:064x}",
                        head_sha="a" * 40,
                        base_sha="b" * 40,
                        feedback_digest=f"{index + 200:064x}",
                    ),
                    phase="prepared",
                    completion_actions=(
                        (revision.revision_id, "completed", {"outcome": "applied"}),
                    ),
                    occurred_at=now,
                )
            )

        state._connection.execute(  # noqa: SLF001
            "DROP TRIGGER publication_events_no_update"
        )
        state._connection.execute(  # noqa: SLF001
            "UPDATE publication_events "
            "SET repository = 'acme/old-widgets', repository_id = NULL "
            "WHERE publication_key = ?",
            (publication_keys[-1],),
        )

        with pytest.raises(RuntimeError, match="durable repository authority"):
            state.pending_publications(
                repository="acme/widgets",
                repository_id=42,
                limit=100,
            )


@pytest.mark.parametrize("repository_id", (True, 0, 9_223_372_036_854_775_808))
def test_repository_id_recovery_filters_reject_non_normalized_values(
    tmp_path: Path,
    repository_id: object,
) -> None:
    with GuardianState(tmp_path / "guardian.sqlite3") as state:
        with pytest.raises(ValueError, match="repository_id must be a positive"):
            state.pending_publications(repository_id=repository_id)  # type: ignore[arg-type]
        with pytest.raises(ValueError, match="repository_id must be a positive"):
            state.replied_publication_for_head(
                repository="acme/widgets",
                repository_id=repository_id,  # type: ignore[arg-type]
                pr_number=123,
                head_sha="a" * 40,
                publication_actor_id=303,
                publication_actor_type="Bot",
            )
        with pytest.raises(ValueError, match="repository_id must be a positive"):
            state.pending_remediation_drafts_for_recovery(
                repository_id=repository_id,  # type: ignore[arg-type]
            )
        with pytest.raises(ValueError, match="repository_id must be a positive"):
            state.opened_remediation_drafts_for_reconciliation(
                repository_id=repository_id,  # type: ignore[arg-type]
            )
        with pytest.raises(ValueError, match="repository_id must be a positive"):
            state.pending_merged_remediation_revalidations(
                repository_id=repository_id,  # type: ignore[arg-type]
            )


def test_publication_recovery_rejects_overdeep_completion_details(
    tmp_path: Path,
) -> None:
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
    with GuardianState(tmp_path / "guardian.sqlite3") as state:
        revision = state.record_feedback_event(
            _event(pr_number=123, head_sha="a" * 40, base_sha="b" * 40),
            observed_at=now,
        )
        run_id = state.start_run(
            repository="acme/widgets",
            locale="ru",
            mode=GuardianMode.APPLY_OWNED_TRANSLATIONS,
            started_at=now,
        )
        metadata = {
            "run_id": run_id,
            "repository": "acme/widgets",
            "pr_number": 123,
            "original_head_sha": "a" * 40,
            "base_sha": "b" * 40,
            "commit_sha": "c" * 40,
            "publication_actor_id": 303,
            "publication_actor_type": "Bot",
            "event_revision_ids": (revision.revision_id,),
            "open_source": OpenPullAuthorityReference(
                repository="acme/widgets",
                repository_id=42,
                pull_id=456,
                pr_number=123,
                authority_digest="d" * 64,
                head_sha="a" * 40,
                base_sha="b" * 40,
                feedback_digest="f" * 64,
            ),
        }
        publication_key = state.record_publication_event(
            **metadata,
            phase="prepared",
            completion_actions=(
                (revision.revision_id, "completed", {"outcome": "applied"}),
            ),
            occurred_at=now,
        )
        state.record_publication_event(
            **metadata,
            phase="published",
            occurred_at=now + timedelta(seconds=1),
        )

        corrupted_details = json.dumps(
            {"nested": _overdeep_json_value(), "outcome": "applied"},
            sort_keys=True,
            separators=(",", ":"),
        )
        state._connection.execute(  # noqa: SLF001 - frozen corruption fixture
            "DROP TRIGGER publication_completion_plans_no_update"
        )
        state._connection.execute(  # noqa: SLF001 - frozen corruption fixture
            "UPDATE publication_completion_plan_items SET details_json = ? "
            "WHERE publication_key = ?",
            (corrupted_details, publication_key),
        )
        state._connection.commit()  # noqa: SLF001 - frozen corruption fixture

        with pytest.raises(RuntimeError, match="completion plan.*malformed"):
            state.finalize_replied_publication(
                publication_key=publication_key,
                summary="Recovered exact publication.",
                occurred_at=now + timedelta(minutes=1),
            )
        assert state.get_run(run_id).status == "running"
        assert state.pending_publications()[0].phase == "published"


@pytest.mark.parametrize(
    ("actor_id", "actor_type"),
    (
        (None, "Bot"),
        (0, "Bot"),
        (True, "Bot"),
        (9_223_372_036_854_775_808, "Bot"),
        (303, None),
        (303, "Organization"),
    ),
)
def test_new_publication_rejects_unsafe_actor_authority(
    tmp_path: Path,
    actor_id: object,
    actor_type: object,
) -> None:
    with GuardianState(tmp_path / "guardian.sqlite3") as state:
        revision = state.record_feedback_event(_event())
        run_id = state.start_run(
            repository="acme/widgets",
            locale="ru",
            mode=GuardianMode.APPLY_OWNED_TRANSLATIONS,
        )
        with pytest.raises(ValueError, match="publication_actor"):
            state.record_publication_event(
                run_id=run_id,
                repository="acme/widgets",
                pr_number=123,
                original_head_sha="a" * 40,
                base_sha="b" * 40,
                commit_sha="c" * 40,
                publication_actor_id=actor_id,  # type: ignore[arg-type]
                publication_actor_type=actor_type,  # type: ignore[arg-type]
                event_revision_ids=(revision.revision_id,),
                open_source=OpenPullAuthorityReference(
                    repository="acme/widgets",
                    repository_id=42,
                    pull_id=456,
                    pr_number=123,
                    authority_digest="d" * 64,
                    head_sha="a" * 40,
                    base_sha="b" * 40,
                    feedback_digest="f" * 64,
                ),
                phase="prepared",
                completion_actions=(
                    (revision.revision_id, "completed", {"outcome": "applied"}),
                ),
            )
        assert state.pending_publications() == ()


def test_publication_actor_is_immutable_across_phases_and_plan_rows(
    tmp_path: Path,
) -> None:
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
    with GuardianState(tmp_path / "guardian.sqlite3") as state:
        revision = state.record_feedback_event(_event(), observed_at=now)
        second = state.record_feedback_event(
            _event(event_id="actor-plan-second"), observed_at=now
        )
        run_id = state.start_run(
            repository="acme/widgets",
            locale="ru",
            mode=GuardianMode.APPLY_OWNED_TRANSLATIONS,
            started_at=now,
        )
        metadata = {
            "run_id": run_id,
            "repository": "acme/widgets",
            "pr_number": 123,
            "original_head_sha": "a" * 40,
            "base_sha": "b" * 40,
            "commit_sha": "c" * 40,
            "event_revision_ids": (revision.revision_id,),
            "open_source": OpenPullAuthorityReference(
                repository="acme/widgets",
                repository_id=42,
                pull_id=456,
                pr_number=123,
                authority_digest="d" * 64,
                head_sha="a" * 40,
                base_sha="b" * 40,
                feedback_digest="f" * 64,
            ),
        }
        publication_key = state.record_publication_event(
            **metadata,
            publication_actor_id=303,
            publication_actor_type="Bot",
            phase="prepared",
            completion_actions=(
                (revision.revision_id, "completed", {"outcome": "applied"}),
            ),
            occurred_at=now,
        )

        with pytest.raises(ValueError, match="phase metadata"):
            state.record_publication_event(
                **metadata,
                publication_actor_id=304,
                publication_actor_type="Bot",
                phase="published",
                occurred_at=now,
            )
        with pytest.raises(sqlite3.IntegrityError, match="identity mismatch"):
            state._connection.execute(  # noqa: SLF001
                """
                INSERT INTO publication_events (
                    publication_key, run_id, repository, repository_id, pr_number,
                    original_head_sha, base_sha, commit_sha,
                    publication_actor_id, publication_actor_type,
                    event_revision_ids_json, open_source_json, phase, occurred_at
                )
                SELECT publication_key, run_id, repository, repository_id, pr_number,
                       original_head_sha, base_sha, commit_sha, 304, 'Bot',
                       event_revision_ids_json, open_source_json, 'published',
                       occurred_at
                FROM publication_events
                WHERE publication_key = ? AND phase = 'prepared'
                """,
                (publication_key,),
            )
        with pytest.raises(sqlite3.IntegrityError, match="prepared authority"):
            state._connection.execute(  # noqa: SLF001
                """
                INSERT INTO publication_completion_plan_items (
                    publication_key, plan_index, run_id,
                    publication_actor_id, publication_actor_type,
                    event_revision_id, action, status, details_json, occurred_at
                ) VALUES (?, 1, ?, 304, 'Bot', ?, ?, 'completed', '{}', ?)
                """,
                (
                    publication_key,
                    run_id,
                    second.revision_id,
                    GuardianMode.APPLY_OWNED_TRANSLATIONS.value,
                    now.isoformat(timespec="microseconds").replace("+00:00", "Z"),
                ),
            )


def test_publication_finalizer_rolls_back_all_local_completion_before_terminal(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
    with GuardianState(tmp_path / "guardian.sqlite3") as state:
        selected = state.record_feedback_event(
            _event(event_id="selected"),
            observed_at=now,
        )
        assessed = state.record_feedback_event(
            _event(event_id="assessed", body="No change is needed."),
            observed_at=now,
        )
        run_id = state.start_run(
            repository="acme/widgets",
            locale="ru",
            mode=GuardianMode.APPLY_OWNED_TRANSLATIONS,
            started_at=now,
        )
        metadata = {
            "run_id": run_id,
            "repository": "acme/widgets",
            "pr_number": 123,
            "original_head_sha": "a" * 40,
            "base_sha": "b" * 40,
            "commit_sha": "c" * 40,
            "publication_actor_id": 303,
            "publication_actor_type": "Bot",
            "event_revision_ids": (selected.revision_id,),
            "open_source": OpenPullAuthorityReference(
                repository="acme/widgets",
                repository_id=42,
                pull_id=456,
                pr_number=123,
                authority_digest="d" * 64,
                head_sha="a" * 40,
                base_sha="b" * 40,
                feedback_digest="f" * 64,
            ),
        }
        publication_key = state.record_publication_event(
            **metadata,
            phase="prepared",
            completion_actions=(
                (selected.revision_id, "completed", {"outcome": "applied"}),
                (
                    assessed.revision_id,
                    "completed",
                    {"outcome": "no_eligible_change"},
                ),
            ),
            occurred_at=now + timedelta(minutes=1),
        )
        state.record_publication_event(
            **metadata,
            phase="published",
            occurred_at=now + timedelta(minutes=1),
        )
        assert state.has_pending_publication_for_run(run_id)
        assert (
            state.reconcile_incomplete_runs(
                before=now + timedelta(days=1),
                reconciled_at=now + timedelta(days=1),
            )
            == ()
        )
        original_terminal = state._record_publication_event_in_transaction  # noqa: SLF001

        def insert_terminal_then_fail(**kwargs):
            original_terminal(**kwargs)
            if kwargs["phase"] == "replied":
                raise RuntimeError("crash before transaction commit")

        monkeypatch.setattr(
            state,
            "_record_publication_event_in_transaction",
            insert_terminal_then_fail,
        )
        with pytest.raises(RuntimeError, match="before transaction commit"):
            state.finalize_replied_publication(
                publication_key=publication_key,
                summary="Completed exact publication.",
                occurred_at=now + timedelta(minutes=2),
            )

        assert state.get_run(run_id).status == "running"
        assert state.has_pending_publication_for_run(run_id)
        assert (
            state.replied_publication_for_head(
                repository="acme/widgets",
                pr_number=123,
                head_sha="c" * 40,
                publication_actor_id=303,
                publication_actor_type="Bot",
            )
            is None
        )
        assert (
            state._connection.execute(  # noqa: SLF001
                "SELECT COUNT(*) FROM actions WHERE run_id = ?",
                (run_id,),
            ).fetchone()[0]
            == 0
        )

        monkeypatch.setattr(
            state,
            "_record_publication_event_in_transaction",
            original_terminal,
        )
        replied = state.finalize_replied_publication(
            publication_key=publication_key,
            summary="Completed exact publication.",
            occurred_at=now + timedelta(minutes=2),
        )

        assert replied.phase == "replied"
        assert state.get_run(run_id).status == "completed"
        assert not state.has_pending_publication_for_run(run_id)
        actions = state._connection.execute(  # noqa: SLF001
            "SELECT event_revision_id, status, details_json FROM actions "
            "WHERE run_id = ? ORDER BY event_revision_id",
            (run_id,),
        ).fetchall()
        assert [tuple(row) for row in actions] == [
            (
                selected.revision_id,
                "completed",
                '{"outcome":"applied"}',
            ),
            (
                assessed.revision_id,
                "completed",
                '{"outcome":"no_eligible_change"}',
            ),
        ]


def test_prepared_publication_and_full_completion_plan_are_one_transaction(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
    with GuardianState(tmp_path / "guardian.sqlite3") as state:
        revision = state.record_feedback_event(_event(), observed_at=now)
        run_id = state.start_run(
            repository="acme/widgets",
            locale="ru",
            mode=GuardianMode.APPLY_OWNED_TRANSLATIONS,
            started_at=now,
        )
        metadata = {
            "run_id": run_id,
            "repository": "acme/widgets",
            "pr_number": 123,
            "original_head_sha": "a" * 40,
            "base_sha": "b" * 40,
            "commit_sha": "c" * 40,
            "publication_actor_id": 303,
            "publication_actor_type": "Bot",
            "event_revision_ids": (revision.revision_id,),
            "open_source": OpenPullAuthorityReference(
                repository="acme/widgets",
                repository_id=42,
                pull_id=456,
                pr_number=123,
                authority_digest="d" * 64,
                head_sha="a" * 40,
                base_sha="b" * 40,
                feedback_digest="f" * 64,
            ),
            "phase": "prepared",
            "completion_actions": (
                (revision.revision_id, "completed", {"outcome": "applied"}),
            ),
            "occurred_at": now,
        }
        original = state._record_publication_completion_plan_in_transaction  # noqa: SLF001

        def record_plan_then_fail(**kwargs):
            original(**kwargs)
            raise RuntimeError("crash before prepared transaction commit")

        monkeypatch.setattr(
            state,
            "_record_publication_completion_plan_in_transaction",
            record_plan_then_fail,
        )
        with pytest.raises(RuntimeError, match="before prepared transaction commit"):
            state.record_publication_event(**metadata)

        assert state.pending_publications() == ()
        assert (
            state._connection.execute(  # noqa: SLF001
                "SELECT COUNT(*) FROM publication_events"
            ).fetchone()[0]
            == 0
        )
        assert (
            state._connection.execute(  # noqa: SLF001
                "SELECT COUNT(*) FROM publication_completion_plan_items"
            ).fetchone()[0]
            == 0
        )

        monkeypatch.setattr(
            state,
            "_record_publication_completion_plan_in_transaction",
            original,
        )
        state.record_publication_event(**metadata)
        assert len(state.pending_publications()) == 1


def test_abandoned_publication_rolls_back_actions_and_run_before_terminal(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
    with GuardianState(tmp_path / "guardian.sqlite3") as state:
        revisions = tuple(
            state.record_feedback_event(
                _event(event_id=f"abandon-{index}"),
                observed_at=now,
            )
            for index in range(2)
        )
        run_id = state.start_run(
            repository="acme/widgets",
            locale="ru",
            mode=GuardianMode.APPLY_OWNED_TRANSLATIONS,
            started_at=now,
        )
        metadata = {
            "run_id": run_id,
            "repository": "acme/widgets",
            "pr_number": 123,
            "original_head_sha": "a" * 40,
            "base_sha": "b" * 40,
            "commit_sha": "c" * 40,
            "publication_actor_id": 303,
            "publication_actor_type": "Bot",
            "event_revision_ids": (revisions[0].revision_id,),
            "open_source": OpenPullAuthorityReference(
                repository="acme/widgets",
                repository_id=42,
                pull_id=456,
                pr_number=123,
                authority_digest="d" * 64,
                head_sha="a" * 40,
                base_sha="b" * 40,
                feedback_digest="f" * 64,
            ),
        }
        publication_key = state.record_publication_event(
            **metadata,
            phase="prepared",
            completion_actions=tuple(
                (
                    revision.revision_id,
                    "completed",
                    {"outcome": "applied" if index == 0 else "no_eligible_change"},
                )
                for index, revision in enumerate(revisions)
            ),
            occurred_at=now,
        )
        state.record_publication_event(
            **metadata,
            phase="published",
            occurred_at=now,
        )
        original = state._record_publication_event_in_transaction  # noqa: SLF001

        def insert_terminal_then_fail(**kwargs):
            original(**kwargs)
            if kwargs["phase"] == "abandoned":
                raise RuntimeError("crash before abandoned transaction commit")

        monkeypatch.setattr(
            state,
            "_record_publication_event_in_transaction",
            insert_terminal_then_fail,
        )
        with pytest.raises(RuntimeError, match="before abandoned transaction commit"):
            state.finalize_abandoned_publication(
                publication_key=publication_key,
                reason="pull_request_head_moved",
                summary="Abandoned a stale publication.",
                occurred_at=now + timedelta(minutes=1),
            )

        assert state.get_run(run_id).status == "running"
        assert state.pending_publications()[0].phase == "published"
        assert (
            state._connection.execute(  # noqa: SLF001
                "SELECT COUNT(*) FROM actions WHERE run_id = ?",
                (run_id,),
            ).fetchone()[0]
            == 0
        )

        monkeypatch.setattr(
            state,
            "_record_publication_event_in_transaction",
            original,
        )
        abandoned = state.finalize_abandoned_publication(
            publication_key=publication_key,
            reason="pull_request_head_moved",
            summary="Abandoned a stale publication.",
            occurred_at=now + timedelta(minutes=1),
        )
        assert abandoned.phase == "abandoned"
        assert state.get_run(run_id).status == "failed"
        assert state.pending_publications() == ()
        actions = state._connection.execute(  # noqa: SLF001
            "SELECT status, details_json FROM actions WHERE run_id = ? "
            "ORDER BY event_revision_id",
            (run_id,),
        ).fetchall()
        assert [tuple(row) for row in actions] == [
            (
                "failed",
                '{"outcome":"publication_abandoned",'
                '"reason":"pull_request_head_moved"}',
            ),
            (
                "failed",
                '{"outcome":"publication_abandoned",'
                '"reason":"pull_request_head_moved"}',
            ),
        ]


def test_publication_phase_machine_is_enforced_by_api_and_sql(
    tmp_path: Path,
) -> None:
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)

    def serialized(value: datetime) -> str:
        return value.isoformat(timespec="microseconds").replace("+00:00", "Z")

    with GuardianState(tmp_path / "guardian.sqlite3") as state:
        revision = state.record_feedback_event(_event(), observed_at=now)
        run_id = state.start_run(
            repository="acme/widgets",
            locale="ru",
            mode=GuardianMode.APPLY_OWNED_TRANSLATIONS,
            started_at=now,
        )
        open_source = OpenPullAuthorityReference(
            repository="acme/widgets",
            repository_id=42,
            pull_id=456,
            pr_number=123,
            authority_digest="d" * 64,
            head_sha="a" * 40,
            base_sha="b" * 40,
            feedback_digest="f" * 64,
        )
        metadata = {
            "run_id": run_id,
            "repository": "acme/widgets",
            "pr_number": 123,
            "original_head_sha": "a" * 40,
            "base_sha": "b" * 40,
            "commit_sha": "c" * 40,
            "publication_actor_id": 303,
            "publication_actor_type": "Bot",
            "event_revision_ids": (revision.revision_id,),
            "open_source": open_source,
        }
        plan = ((revision.revision_id, "completed", {"outcome": "applied"}),)

        with pytest.raises(ValueError, match="begin in the prepared phase"):
            state.record_publication_event(
                **metadata,
                phase="published",
                occurred_at=now,
            )

        observe_run = state.start_run(
            repository="acme/widgets",
            locale="ru",
            mode=GuardianMode.OBSERVE,
            started_at=now,
        )
        with pytest.raises(ValueError, match="run authority"):
            state.record_publication_event(
                **{**metadata, "run_id": observe_run, "commit_sha": "e" * 40},
                phase="prepared",
                completion_actions=plan,
                occurred_at=now,
            )
        for key, unauthorized_run, repository in (
            ("7" * 64, observe_run, "acme/widgets"),
            ("8" * 64, run_id, "other/widgets"),
        ):
            with pytest.raises(sqlite3.IntegrityError, match="run authority"):
                state._connection.execute(  # noqa: SLF001
                    """
                    INSERT INTO publication_events (
                        publication_key, run_id, repository, repository_id, pr_number,
                        original_head_sha, base_sha, commit_sha,
                        publication_actor_id, publication_actor_type,
                        event_revision_ids_json, open_source_json,
                        phase, occurred_at
                    ) VALUES (?, ?, ?, 42, ?, ?, ?, ?, 303, 'Bot', ?, NULL, 'prepared', ?)
                    """,
                    (
                        key,
                        unauthorized_run,
                        repository,
                        123,
                        "a" * 40,
                        "b" * 40,
                        key[:40],
                        json.dumps([revision.revision_id], separators=(",", ":")),
                        serialized(now),
                    ),
                )

        publication_key = state.record_publication_event(
            **metadata,
            phase="prepared",
            completion_actions=plan,
            occurred_at=now + timedelta(minutes=1),
        )
        assert (
            state.record_publication_event(
                **metadata,
                phase="prepared",
                completion_actions=plan,
                occurred_at=now + timedelta(minutes=1),
            )
            == publication_key
        )
        assert (
            state._connection.execute(  # noqa: SLF001
                "SELECT COUNT(*) FROM publication_events WHERE publication_key = ?",
                (publication_key,),
            ).fetchone()[0]
            == 1
        )

        with pytest.raises(ValueError, match="timestamps must be monotonic"):
            state.record_publication_event(
                **metadata,
                phase="published",
                occurred_at=now,
            )
        state.record_publication_event(
            **metadata,
            phase="published",
            occurred_at=now + timedelta(minutes=2),
        )
        state.record_publication_event(
            **metadata,
            phase="published",
            occurred_at=now + timedelta(minutes=3),
        )
        assert (
            state._connection.execute(  # noqa: SLF001
                "SELECT COUNT(*) FROM publication_events WHERE publication_key = ?",
                (publication_key,),
            ).fetchone()[0]
            == 2
        )
        with pytest.raises(ValueError, match="transition is invalid"):
            state.record_publication_event(
                **metadata,
                phase="prepared",
                completion_actions=plan,
                occurred_at=now + timedelta(minutes=3),
            )
        with pytest.raises(ValueError, match="atomic publication finalization"):
            state.record_publication_event(
                **metadata,
                phase="replied",
                occurred_at=now + timedelta(minutes=3),
            )

        first = state._connection.execute(  # noqa: SLF001
            "SELECT event_revision_ids_json, open_source_json "
            "FROM publication_events WHERE publication_key = ? "
            "ORDER BY publication_event_id LIMIT 1",
            (publication_key,),
        ).fetchone()
        with pytest.raises(sqlite3.IntegrityError, match="completed plan"):
            state._connection.execute(  # noqa: SLF001
                """
                INSERT INTO publication_events (
                    publication_key, run_id, repository, repository_id, pr_number,
                    original_head_sha, base_sha, commit_sha,
                    publication_actor_id, publication_actor_type,
                    event_revision_ids_json, open_source_json, phase, occurred_at
                ) VALUES (?, ?, ?, 42, ?, ?, ?, ?, 303, 'Bot', ?, ?, 'replied', ?)
                """,
                (
                    publication_key,
                    run_id,
                    "acme/widgets",
                    123,
                    "a" * 40,
                    "b" * 40,
                    "c" * 40,
                    first["event_revision_ids_json"],
                    first["open_source_json"],
                    serialized(now + timedelta(minutes=3)),
                ),
            )
        with pytest.raises(sqlite3.IntegrityError, match="identity mismatch"):
            state._connection.execute(  # noqa: SLF001
                """
                INSERT INTO publication_events (
                    publication_key, run_id, repository, repository_id, pr_number,
                    original_head_sha, base_sha, commit_sha,
                    publication_actor_id, publication_actor_type,
                    event_revision_ids_json, open_source_json, phase, occurred_at
                ) VALUES (?, ?, 'other/widgets', 42, ?, ?, ?, ?, 303, 'Bot', ?, ?, 'published', ?)
                """,
                (
                    publication_key,
                    run_id,
                    123,
                    "a" * 40,
                    "b" * 40,
                    "c" * 40,
                    first["event_revision_ids_json"],
                    first["open_source_json"],
                    serialized(now + timedelta(minutes=3)),
                ),
            )

        completed_run = state.start_run(
            repository="acme/widgets",
            locale="ru",
            mode=GuardianMode.APPLY_OWNED_TRANSLATIONS,
            started_at=now,
        )
        state.finish_run(
            completed_run,
            status="completed",
            summary="No publication.",
            finished_at=now,
        )
        with pytest.raises(sqlite3.IntegrityError, match="begin prepared"):
            state._connection.execute(  # noqa: SLF001
                """
                INSERT INTO publication_events (
                    publication_key, run_id, repository, repository_id, pr_number,
                    original_head_sha, base_sha, commit_sha,
                    publication_actor_id, publication_actor_type,
                    event_revision_ids_json, open_source_json, phase, occurred_at
                ) VALUES (?, ?, ?, 42, ?, ?, ?, ?, 303, 'Bot', ?, ?, 'replied', ?)
                """,
                (
                    "9" * 64,
                    completed_run,
                    "acme/widgets",
                    123,
                    "a" * 40,
                    "b" * 40,
                    "9" * 40,
                    first["event_revision_ids_json"],
                    first["open_source_json"],
                    serialized(now + timedelta(minutes=3)),
                ),
            )

        state.finalize_replied_publication(
            publication_key=publication_key,
            summary="Completed exact publication.",
            occurred_at=now + timedelta(minutes=3),
        )
        with pytest.raises(sqlite3.IntegrityError):
            state._connection.execute(  # noqa: SLF001
                """
                INSERT INTO publication_events (
                    publication_key, run_id, repository, repository_id, pr_number,
                    original_head_sha, base_sha, commit_sha,
                    publication_actor_id, publication_actor_type,
                    event_revision_ids_json, open_source_json, phase, occurred_at
                ) VALUES (?, ?, ?, 42, ?, ?, ?, ?, 303, 'Bot', ?, ?, 'abandoned', ?)
                """,
                (
                    publication_key,
                    run_id,
                    "acme/widgets",
                    123,
                    "a" * 40,
                    "b" * 40,
                    "c" * 40,
                    first["event_revision_ids_json"],
                    first["open_source_json"],
                    serialized(now + timedelta(minutes=4)),
                ),
            )


@pytest.mark.parametrize(
    "open_source",
    [
        None,
        OpenPullAuthorityReference(
            repository="acme/widgets",
            repository_id=42,
            pull_id=456,
            pr_number=123,
            authority_digest="d" * 64,
            head_sha="a" * 40,
            base_sha="b" * 40,
        ),
        OpenPullAuthorityReference(
            repository="other/widgets",
            repository_id=42,
            pull_id=456,
            pr_number=123,
            authority_digest="d" * 64,
            head_sha="a" * 40,
            base_sha="b" * 40,
            feedback_digest="f" * 64,
        ),
        OpenPullAuthorityReference(
            repository="acme/widgets",
            repository_id=42,
            pull_id=456,
            pr_number=124,
            authority_digest="d" * 64,
            head_sha="a" * 40,
            base_sha="b" * 40,
            feedback_digest="f" * 64,
        ),
        OpenPullAuthorityReference(
            repository="acme/widgets",
            repository_id=42,
            pull_id=456,
            pr_number=123,
            authority_digest="d" * 64,
            head_sha="e" * 40,
            base_sha="b" * 40,
            feedback_digest="f" * 64,
        ),
        OpenPullAuthorityReference(
            repository="acme/widgets",
            repository_id=42,
            pull_id=456,
            pr_number=123,
            authority_digest="d" * 64,
            head_sha="a" * 40,
            base_sha="e" * 40,
            feedback_digest="f" * 64,
        ),
    ],
    ids=(
        "missing",
        "missing-feedback-digest",
        "repository",
        "pull-number",
        "head",
        "base",
    ),
)
def test_new_prepared_publication_requires_exact_open_authority(
    open_source: OpenPullAuthorityReference | None,
    tmp_path: Path,
) -> None:
    with GuardianState(tmp_path / "guardian.sqlite3") as state:
        revision = state.record_feedback_event(
            _event(pr_number=123, head_sha="a" * 40, base_sha="b" * 40)
        )
        run_id = state.start_run(
            repository="acme/widgets",
            locale="ru",
            mode=GuardianMode.APPLY_OWNED_TRANSLATIONS,
        )

        with pytest.raises(ValueError, match="exact open-pull authority"):
            state.record_publication_event(
                run_id=run_id,
                repository="acme/widgets",
                pr_number=123,
                original_head_sha="a" * 40,
                base_sha="b" * 40,
                commit_sha="c" * 40,
                publication_actor_id=303,
                publication_actor_type="Bot",
                event_revision_ids=(revision.revision_id,),
                open_source=open_source,
                phase="prepared",
                completion_actions=(
                    (revision.revision_id, "completed", {"outcome": "applied"}),
                ),
            )


def test_published_remediation_reply_can_be_terminalized_separately(
    tmp_path: Path,
) -> None:
    """Complete published remediation without inventing a reply on a closed PR."""
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
    with GuardianState(tmp_path / "guardian.sqlite3") as state:
        metadata = _remediation_metadata(state, now=now)
        draft_key = _open_remediation_draft(state, metadata, draft_number=91)
        feedback = state.record_feedback_event(
            _event(
                repository="acme/widgets",
                pr_number=91,
                event_id="reply-terminal",
                head_sha=metadata["candidate_sha"],
                base_sha=metadata["target_base_sha"],
            ),
            observed_at=now + timedelta(minutes=1),
        )
        publication = {
            "run_id": metadata["run_id"],
            "repository": "acme/widgets",
            "pr_number": 91,
            "original_head_sha": metadata["candidate_sha"],
            "base_sha": metadata["target_base_sha"],
            "commit_sha": "d" * 40,
            "event_revision_ids": (feedback.revision_id,),
            "open_source": OpenPullAuthorityReference(
                repository="acme/widgets",
                repository_id=42,
                pull_id=901,
                pr_number=91,
                authority_digest="f" * 64,
                head_sha=metadata["candidate_sha"],
                base_sha=metadata["target_base_sha"],
                feedback_digest="6" * 64,
            ),
            "draft_key": draft_key,
            "source_pulls": tuple(metadata["source_pulls"]),
            "edit_hashes": tuple(metadata["edit_hashes"]),
            "changed_paths": ("l10n/messages_ru.properties",),
            "actor_id": 202,
            "actor_type": "Bot",
            "publication_actor_id": 303,
            "publication_actor_type": "Bot",
        }
        intent = state.record_remediation_successor_publication_event(
            **publication,
            phase="prepared",
            completion_actions=(
                (feedback.revision_id, "completed", {"outcome": "applied"}),
            ),
            occurred_at=now + timedelta(minutes=2),
        )

        with pytest.raises(ValueError, match="atomic publication finalization"):
            state.record_publication_reply_terminal(
                publication_key=intent.publication_key,
                reason="remediation_closed_unmerged",
                occurred_at=now + timedelta(minutes=3),
            )

        state.record_remediation_successor_publication_event(
            **publication,
            phase="published",
            occurred_at=now + timedelta(minutes=3),
        )
        assert (
            state.finalize_publication_reply_terminal(
                publication_key=intent.publication_key,
                reason="remediation_closed_unmerged",
                summary="Recovered a closed remediation publication.",
                occurred_at=now + timedelta(minutes=4),
            )
            == "remediation_closed_unmerged"
        )
        assert state.pending_publications(repository="acme/widgets") == ()
        assert (
            state.publication_reply_terminal_reason(intent.publication_key)
            == "remediation_closed_unmerged"
        )
        phases = state._connection.execute(  # noqa: SLF001
            "SELECT phase FROM publication_events WHERE publication_key = ? "
            "ORDER BY publication_event_id",
            (intent.publication_key,),
        ).fetchall()
        assert [row["phase"] for row in phases] == ["prepared", "published"]
        assert (
            state.finalize_publication_reply_terminal(
                publication_key=intent.publication_key,
                reason="remediation_closed_unmerged",
                summary="Recovered a closed remediation publication.",
                occurred_at=now + timedelta(minutes=5),
            )
            == "remediation_closed_unmerged"
        )
        with pytest.raises(ValueError, match="already terminal"):
            state.finalize_publication_reply_terminal(
                publication_key=intent.publication_key,
                reason="remediation_merged",
                summary="Recovered a closed remediation publication.",
                occurred_at=now + timedelta(minutes=5),
            )
        with pytest.raises(sqlite3.IntegrityError, match="reply terminals"):
            state._connection.execute(  # noqa: SLF001
                "UPDATE publication_reply_terminal_events SET reason = "
                "'remediation_merged'"
            )

    # Recreate the released v9 enum with a genuine completed terminal row.
    database = tmp_path / "guardian.sqlite3"
    _restore_v9_reply_terminal_table(database)
    with GuardianState(database) as migrated:
        assert migrated.publication_reply_terminal_reason(intent.publication_key) == (
            "remediation_closed_unmerged"
        )
        assert migrated.pending_publications() == ()
        with pytest.raises(sqlite3.IntegrityError, match="reply terminals"):
            migrated._connection.execute("DELETE FROM publication_reply_terminal_events")


def _restore_v9_reply_terminal_table(database: Path) -> None:
    """Build the previous enum while retaining exact terminal evidence rows."""
    with sqlite3.connect(database) as connection:
        connection.execute("ALTER TABLE publication_reply_terminal_events RENAME TO terminals_new")
        connection.execute("""
            CREATE TABLE publication_reply_terminal_events (
                publication_key TEXT PRIMARY KEY,
                reason TEXT NOT NULL CHECK (reason IN (
                    'remediation_closed_unmerged', 'remediation_merged'
                )),
                occurred_at TEXT NOT NULL
            )
        """)
        connection.execute("INSERT INTO publication_reply_terminal_events SELECT * FROM terminals_new")
        connection.execute("DROP TABLE terminals_new")
        connection.execute("PRAGMA user_version = 9")


def test_v9_reply_enum_migration_rolls_back_on_later_failure(tmp_path, monkeypatch):
    """A failed upgrade must retain the old schema without a partial table swap."""
    database = tmp_path / "guardian.sqlite3"
    with GuardianState(database):
        pass
    _restore_v9_reply_terminal_table(database)

    def fail_after_migration(_self):
        """Inject a later failure to verify the entire schema upgrade rolls back."""
        raise RuntimeError("injected migration failure")

    monkeypatch.setattr(GuardianState, "_install_publication_reply_triggers", fail_after_migration)
    with pytest.raises(RuntimeError, match="injected migration failure"):
        GuardianState(database)
    with sqlite3.connect(database) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 9
        sql = connection.execute(
            "SELECT sql FROM sqlite_master WHERE name='publication_reply_terminal_events'"
        ).fetchone()[0]
        assert "trusted_feedback_changed" not in sql
        assert connection.execute(
            "SELECT COUNT(*) FROM sqlite_master WHERE name='publication_reply_terminal_events_v10'"
        ).fetchone()[0] == 0


def test_publication_completion_action_is_exact_and_idempotent(
    tmp_path: Path,
) -> None:
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
    with GuardianState(tmp_path / "guardian.sqlite3") as state:
        metadata = _remediation_metadata(state, now=now)
        draft_key = _open_remediation_draft(state, metadata, draft_number=91)
        feedback = state.record_feedback_event(
            _event(
                repository="acme/widgets",
                pr_number=91,
                event_id="completion-action",
                head_sha=metadata["candidate_sha"],
                base_sha=metadata["target_base_sha"],
            ),
            observed_at=now + timedelta(minutes=1),
        )
        publication = {
            "run_id": metadata["run_id"],
            "repository": "acme/widgets",
            "pr_number": 91,
            "original_head_sha": metadata["candidate_sha"],
            "base_sha": metadata["target_base_sha"],
            "commit_sha": "d" * 40,
            "event_revision_ids": (feedback.revision_id,),
            "open_source": OpenPullAuthorityReference(
                repository="acme/widgets",
                repository_id=42,
                pull_id=901,
                pr_number=91,
                authority_digest="f" * 64,
                head_sha=metadata["candidate_sha"],
                base_sha=metadata["target_base_sha"],
                feedback_digest="6" * 64,
            ),
            "draft_key": draft_key,
            "source_pulls": tuple(metadata["source_pulls"]),
            "edit_hashes": tuple(metadata["edit_hashes"]),
            "changed_paths": ("l10n/messages_ru.properties",),
            "actor_id": 202,
            "actor_type": "Bot",
            "publication_actor_id": 303,
            "publication_actor_type": "Bot",
        }
        details = {
            "outcome": "applied",
            "commit_sha": "d" * 40,
            "recovered_reply": False,
            "reply_not_applicable": "closed",
            "remediation_merged": False,
        }
        prepared = state.record_remediation_successor_publication_event(
            **publication,
            phase="prepared",
            completion_actions=((feedback.revision_id, "completed", details),),
            occurred_at=now + timedelta(minutes=2),
        )
        state.record_remediation_successor_publication_event(
            **publication,
            phase="published",
            occurred_at=now + timedelta(minutes=3),
        )
        first = state.record_publication_completion_action(
            publication_key=prepared.publication_key,
            event_revision_id=feedback.revision_id,
            details=details,
            occurred_at=now + timedelta(minutes=4),
        )
        second = state.record_publication_completion_action(
            publication_key=prepared.publication_key,
            event_revision_id=feedback.revision_id,
            details=details,
            occurred_at=now + timedelta(minutes=5),
        )

        assert second == first
        assert (
            state._connection.execute(  # noqa: SLF001
                "SELECT COUNT(*) FROM actions WHERE run_id = ?",
                (metadata["run_id"],),
            ).fetchone()[0]
            == 1
        )
        with pytest.raises(ValueError, match="completion action"):
            state.record_publication_completion_action(
                publication_key=prepared.publication_key,
                event_revision_id=feedback.revision_id,
                details={**details, "remediation_merged": True},
                occurred_at=now + timedelta(minutes=5),
            )


def test_v1_publication_migrates_without_inferred_open_authority(
    tmp_path: Path,
) -> None:
    database = tmp_path / "guardian.sqlite3"
    _create_exact_v1_database(database, populated=True)
    with sqlite3.connect(database) as connection:
        connection.execute(
            """
            INSERT INTO publication_events (
                publication_key, run_id, repository, pr_number,
                original_head_sha, base_sha, commit_sha,
                event_revision_ids_json, phase, occurred_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                hashlib.sha256(
                    (f"acme/widgets\n12\n{'a' * 40}\n{'b' * 40}\n{'c' * 40}").encode(
                        "utf-8"
                    )
                ).hexdigest(),
                "00000000-0000-4000-8000-000000000001",
                "acme/widgets",
                12,
                "a" * 40,
                "b" * 40,
                "c" * 40,
                "[1]",
                "published",
                "2026-08-30T08:01:00.000000Z",
            ),
        )

    with GuardianState(database) as state:
        row = state._connection.execute(  # noqa: SLF001
            "SELECT * FROM publication_events"
        ).fetchone()
        audit_record = state._publication_from_row(row)  # noqa: SLF001
        assert audit_record.open_source is None
        assert audit_record.publication_actor_id is None
        assert audit_record.publication_actor_type is None
        with pytest.raises(RuntimeError, match="durable publication-actor"):
            state.pending_publications()
        with pytest.raises(RuntimeError, match="durable actor authority"):
            state.record_publication_completion_action(
                publication_key=audit_record.publication_key,
                event_revision_id=1,
                details={"outcome": "legacy"},
            )


def test_v1_replied_publication_never_matches_a_current_actor(tmp_path: Path) -> None:
    database = tmp_path / "guardian.sqlite3"
    _create_exact_v1_database(database, populated=True)
    with sqlite3.connect(database) as connection:
        connection.execute(
            """
            INSERT INTO publication_events (
                publication_key, run_id, repository, pr_number,
                original_head_sha, base_sha, commit_sha,
                event_revision_ids_json, phase, occurred_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'replied', ?)
            """,
            (
                hashlib.sha256(
                    (f"acme/widgets\n12\n{'a' * 40}\n{'b' * 40}\n{'c' * 40}").encode(
                        "utf-8"
                    )
                ).hexdigest(),
                "00000000-0000-4000-8000-000000000001",
                "acme/widgets",
                12,
                "a" * 40,
                "b" * 40,
                "c" * 40,
                "[1]",
                "2026-08-30T08:01:00.000000Z",
            ),
        )

    with GuardianState(database) as state:
        row = state._connection.execute(  # noqa: SLF001
            "SELECT * FROM publication_events"
        ).fetchone()
        audit_record = state._publication_from_row(row)  # noqa: SLF001
        assert audit_record.phase == "replied"
        assert audit_record.publication_actor_id is None
        assert audit_record.publication_actor_type is None
        assert (
            state.replied_publication_for_head(
                repository="acme/widgets",
                pr_number=12,
                head_sha="c" * 40,
                publication_actor_id=303,
                publication_actor_type="User",
            )
            is None
        )


def test_v7_publication_actor_migration_is_explicit_and_fails_closed(
    tmp_path: Path,
) -> None:
    """Do not synthesize publication actor authority during legacy migration."""
    database = tmp_path / "guardian.sqlite3"
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
    with GuardianState(database) as state:
        revision = state.record_feedback_event(_event(), observed_at=now)
        run_id = state.start_run(
            repository="acme/widgets",
            locale="ru",
            mode=GuardianMode.APPLY_OWNED_TRANSLATIONS,
            started_at=now,
        )
        publication_key = state.record_publication_event(
            run_id=run_id,
            repository="acme/widgets",
            pr_number=123,
            original_head_sha="a" * 40,
            base_sha="b" * 40,
            commit_sha="c" * 40,
            publication_actor_id=303,
            publication_actor_type="Bot",
            event_revision_ids=(revision.revision_id,),
            open_source=OpenPullAuthorityReference(
                repository="acme/widgets",
                repository_id=42,
                pull_id=456,
                pr_number=123,
                authority_digest="d" * 64,
                head_sha="a" * 40,
                base_sha="b" * 40,
                feedback_digest="f" * 64,
            ),
            phase="prepared",
            completion_actions=(
                (revision.revision_id, "completed", {"outcome": "applied"}),
            ),
            occurred_at=now,
        )

    with sqlite3.connect(database) as connection:
        for trigger in (
            "publication_events_identity",
            "publication_events_actor_safe",
            "publication_events_repository_id_safe",
            "publication_completion_plans_prepared",
            "remediation_successor_intents_prepared",
            "prevention_draft_events_run_authority",
            "prevention_draft_events_identity",
            "prevention_draft_events_transition",
            "remediation_draft_events_run_authority",
            "remediation_draft_events_require_validated",
            "remediation_draft_events_identity",
            "remediation_draft_events_transition",
            "remediation_draft_events_resolved_terminal",
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

    with GuardianState(database) as state:
        assert (
            state._connection.execute(  # noqa: SLF001
                "PRAGMA user_version"
            ).fetchone()[0]
            == 11
        )
        for table in (
            "publication_events",
            "publication_completion_plan_items",
        ):
            actor_columns = {
                row["name"]: row
                for row in state._connection.execute(  # noqa: SLF001, S608
                    f"PRAGMA table_info({table})"
                )
                if row["name"] in {"publication_actor_id", "publication_actor_type"}
            }
            assert set(actor_columns) == {
                "publication_actor_id",
                "publication_actor_type",
            }
            assert all(row["notnull"] == 0 for row in actor_columns.values())

        installed_triggers = {
            row["name"]
            for row in state._connection.execute(  # noqa: SLF001
                "SELECT name FROM sqlite_master WHERE type = 'trigger'"
            )
        }
        assert {
            "publication_events_actor_safe",
            "publication_events_repository_id_safe",
            "publication_completion_plans_prepared",
            "prevention_draft_events_run_authority",
            "prevention_draft_events_identity",
            "prevention_draft_events_transition",
            "remediation_draft_events_run_authority",
            "remediation_draft_events_require_validated",
            "remediation_draft_events_identity",
            "remediation_draft_events_transition",
            "remediation_draft_events_resolved_terminal",
        } <= installed_triggers

        row = state._connection.execute(  # noqa: SLF001
            "SELECT * FROM publication_events WHERE publication_key = ?",
            (publication_key,),
        ).fetchone()
        publication = state._publication_from_row(row)  # noqa: SLF001
        assert publication.repository_id == 42
        assert publication.publication_actor_id is None
        assert publication.publication_actor_type is None
        with pytest.raises(RuntimeError, match="durable publication-actor"):
            state.pending_publications()

        with pytest.raises(sqlite3.IntegrityError, match="actor is unsafe"):
            state._connection.execute(  # noqa: SLF001
                """
                INSERT INTO publication_events (
                    publication_key, run_id, repository, repository_id, pr_number,
                    original_head_sha, base_sha, commit_sha,
                    event_revision_ids_json, open_source_json, phase, occurred_at
                )
                SELECT publication_key, run_id, repository, repository_id, pr_number,
                       original_head_sha, base_sha, commit_sha,
                       event_revision_ids_json, open_source_json, 'published', ?
                FROM publication_events
                WHERE publication_key = ? AND phase = 'prepared'
                """,
                (
                    "2026-08-30T12:01:00.000000Z",
                    publication_key,
                ),
            )

        state._connection.execute(  # noqa: SLF001
            "DROP TRIGGER publication_events_no_update"
        )
        state._connection.execute(  # noqa: SLF001
            "UPDATE publication_events SET publication_actor_id = 303 "
            "WHERE publication_key = ?",
            (publication_key,),
        )
        malformed_row = state._connection.execute(  # noqa: SLF001
            "SELECT * FROM publication_events WHERE publication_key = ?",
            (publication_key,),
        ).fetchone()
        with pytest.raises(RuntimeError, match="malformed data"):
            state._publication_from_row(malformed_row)  # noqa: SLF001


def test_v8_publication_repository_id_migration_backfills_only_exact_authority(
    tmp_path: Path,
) -> None:
    database = tmp_path / "guardian.sqlite3"
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
    with GuardianState(database) as state:
        revision = state.record_feedback_event(_event(), observed_at=now)
        run_id = state.start_run(
            repository="acme/widgets",
            locale="ru",
            mode=GuardianMode.APPLY_OWNED_TRANSLATIONS,
            started_at=now,
        )

        def record_publication(commit_sha: str, authority_digest: str) -> str:
            return state.record_publication_event(
                run_id=run_id,
                repository="acme/widgets",
                pr_number=123,
                original_head_sha="a" * 40,
                base_sha="b" * 40,
                commit_sha=commit_sha,
                publication_actor_id=303,
                publication_actor_type="Bot",
                event_revision_ids=(revision.revision_id,),
                open_source=OpenPullAuthorityReference(
                    repository="acme/widgets",
                    repository_id=42,
                    pull_id=456,
                    pr_number=123,
                    authority_digest=authority_digest,
                    head_sha="a" * 40,
                    base_sha="b" * 40,
                    feedback_digest="f" * 64,
                ),
                phase="prepared",
                completion_actions=(
                    (revision.revision_id, "completed", {"outcome": "applied"}),
                ),
                occurred_at=now,
            )

        exact_key = record_publication("c" * 40, "d" * 64)
        malformed_key = record_publication("e" * 40, "9" * 64)
        state.record_feedback_event(
            _event(body="Feedback edited after the publication was prepared."),
            observed_at=now + timedelta(minutes=1),
        )

    with sqlite3.connect(database) as connection:
        connection.execute("DROP TRIGGER publication_events_no_update")
        connection.execute(
            "UPDATE publication_events SET open_source_json = '{malformed' "
            "WHERE publication_key = ?",
            (malformed_key,),
        )
        connection.execute("DROP TRIGGER publication_events_identity")
        connection.execute("DROP TRIGGER publication_events_repository_id_safe")
        connection.execute("DROP INDEX publication_events_pending_by_repository_id")
        connection.execute("DROP INDEX publication_events_replied_by_repository_id")
        connection.execute("ALTER TABLE publication_events DROP COLUMN repository_id")
        connection.execute("PRAGMA user_version = 8")

    with GuardianState(database) as state:
        repository_id_column = next(
            row
            for row in state._connection.execute(  # noqa: SLF001
                "PRAGMA table_info(publication_events)"
            )
            if row["name"] == "repository_id"
        )
        assert repository_id_column["notnull"] == 0
        migrated_ids = {
            row["publication_key"]: row["repository_id"]
            for row in state._connection.execute(  # noqa: SLF001
                "SELECT publication_key, repository_id FROM publication_events"
            )
        }
        assert migrated_ids == {exact_key: 42, malformed_key: None}
        assert tuple(
            publication.publication_key
            for publication in state.pending_publications(repository_id=42)
        ) == (exact_key,)
        with pytest.raises(
            RuntimeError,
            match="Pending publication lacks durable repository authority",
        ):
            state.pending_publications(
                repository="acme/widgets",
                repository_id=42,
            )
        with pytest.raises(RuntimeError, match="Publication ledger contains malformed"):
            state.pending_publications(repository="acme/widgets")

        with pytest.raises(
            sqlite3.IntegrityError,
            match="publication repository id is unsafe",
        ):
            state._connection.execute(  # noqa: SLF001
                """
                INSERT INTO publication_events (
                    publication_key, run_id, repository, pr_number,
                    original_head_sha, base_sha, commit_sha,
                    publication_actor_id, publication_actor_type,
                    event_revision_ids_json, open_source_json, phase, occurred_at
                )
                SELECT ?, run_id, repository, pr_number,
                       original_head_sha, base_sha, commit_sha,
                       publication_actor_id, publication_actor_type,
                       event_revision_ids_json, open_source_json, phase, occurred_at
                FROM publication_events
                WHERE publication_key = ? AND phase = 'prepared'
                """,
                ("8" * 64, exact_key),
            )

    with GuardianState(database) as state:
        assert (
            state._connection.execute(  # noqa: SLF001
                "SELECT repository_id FROM publication_events "
                "WHERE publication_key = ?",
                (exact_key,),
            ).fetchone()["repository_id"]
            == 42
        )


def test_prevention_draft_ledger_recovers_pushes_and_deduplicates_opened_evidence(
    tmp_path: Path,
) -> None:
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
    with GuardianState(tmp_path / "guardian.sqlite3") as state:
        run_id = state.start_run(
            repository="acme/widgets",
            locale="ru",
            mode=GuardianMode.PROPOSE_PREVENTION,
            started_at=now,
        )
        metadata = {
            "run_id": run_id,
            "source_repository": "acme/widgets",
            "target_repository": "guardian/pipeline",
            "target_base_branch": "main",
            "target_base_sha": "a" * 40,
            "push_repository": "guardian/pipeline",
            "branch": "guardian/prevention-" + "a" * 12 + "-" + "b" * 64,
            "candidate_sha": "c" * 40,
            "evidence_hash": "b" * 64,
            **_prevention_attestation_metadata(state),
            "title": "Prevent recurrence: placeholder parity",
            "body": "Validated prevention body\n",
            "occurred_at": now,
        }
        with pytest.raises(ValueError, match="title must be a bounded"):
            state.record_prevention_draft_event(
                **{**metadata, "title": "界" * 86},
                phase="validated",
            )
        with pytest.raises(ValueError, match="body must be a bounded"):
            state.record_prevention_draft_event(
                **{**metadata, "body": "x" * (60 * 1024 + 1)},
                phase="validated",
            )
        with pytest.raises(ValueError, match="patch_paths must contain bounded"):
            state.record_prevention_draft_event(
                **{**metadata, "patch_paths": ("x" * 4097,)},
                phase="validated",
            )
        with pytest.raises(ValueError, match="canonical byte bound"):
            state.record_prevention_draft_event(
                **{
                    **metadata,
                    "patch_paths": tuple(
                        f"{index}-{'界' * 1300}" for index in range(100)
                    ),
                },
                phase="validated",
            )
        with pytest.raises(ValueError, match="exact policy identities"):
            state.record_prevention_draft_event(
                **{
                    **metadata,
                    "branch": "guardian/prevention-" + "b" * 64,
                },
                phase="validated",
            )
        draft_key = state.record_prevention_draft_event(
            **metadata,
            phase="validated",
        )
        assert (
            state.record_prevention_draft_event(
                **metadata,
                phase="validated",
            )
            == draft_key
        )
        assert state.pending_prevention_drafts()[0].phase == "validated"

        state.record_prevention_draft_event(**metadata, phase="pushed")
        pending = state.pending_prevention_drafts(source_repository="acme/widgets")
        assert len(pending) == 1
        assert pending[0].phase == "pushed"
        assert pending[0].candidate_sha == "c" * 40
        assert pending[0].patch_paths == (
            "localize/rules.py",
            "tests/unit/test_rules.py",
        )
        assert pending[0].patch_hash == "d" * 64
        assert pending[0].open_source == metadata["open_source"]
        assert pending[0].source_pulls == ()
        assert pending[0].event_revision_ids == (1,)

        state.record_prevention_draft_event(
            **metadata,
            phase="draft_opened",
            draft_number=17,
            draft_url="https://github.test/guardian/pipeline/pull/17",
        )
        with pytest.raises(ValueError, match="metadata does not match"):
            state.record_prevention_draft_event(
                **metadata,
                phase="draft_opened",
                draft_number=18,
                draft_url="https://github.test/guardian/pipeline/pull/18",
            )
        with pytest.raises(ValueError, match="phase transition"):
            state.record_prevention_draft_event(
                **metadata,
                phase="abandoned",
            )
        assert state.pending_prevention_drafts() == ()
        assert state.opened_prevention_evidence_hashes(
            source_repository_id=42,
            target_repository_id=84,
        ) == frozenset({"b" * 64})
        with pytest.raises(ValueError, match="pending prevention draft"):
            state.record_prevention_resolution(
                draft_key=draft_key,
                resolution="remote_conflict",
                occurred_at=now,
            )
        for non_pending_key in (draft_key, "f" * 64):
            with pytest.raises(
                sqlite3.IntegrityError,
                match="prevention resolution requires latest pending event",
            ):
                state._connection.execute(  # noqa: SLF001 - DB invariant assertion
                    """
                    INSERT INTO prevention_resolution_events (
                        draft_key, resolution, occurred_at
                    ) VALUES (?, 'remote_conflict', ?)
                    """,
                    (non_pending_key, "2026-08-30T12:01:00.000000Z"),
                )

        with pytest.raises(sqlite3.IntegrityError, match="prevention draft events"):
            state._connection.execute(  # noqa: SLF001 - immutability assertion
                "UPDATE prevention_draft_events SET phase = 'abandoned'"
            )
        with pytest.raises(sqlite3.IntegrityError, match="prevention attestations"):
            state._connection.execute(  # noqa: SLF001 - DB immutability assertion
                "UPDATE prevention_candidate_attestations SET patch_hash = ?",
                ("e" * 64,),
            )


def test_prevention_draft_read_reapplies_source_cardinality_bound(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
    with GuardianState(tmp_path / "guardian.sqlite3") as state:
        run_id = state.start_run(
            repository="acme/widgets",
            locale="ru",
            mode=GuardianMode.PROPOSE_PREVENTION,
            started_at=now,
        )
        metadata = {
            "run_id": run_id,
            "source_repository": "acme/widgets",
            "target_repository": "guardian/pipeline",
            "target_base_branch": "main",
            "target_base_sha": "a" * 40,
            "push_repository": "guardian/pipeline",
            "branch": "guardian/prevention-" + "a" * 12 + "-" + "b" * 64,
            "candidate_sha": "c" * 40,
            "evidence_hash": "b" * 64,
            **_prevention_attestation_metadata(state),
            "title": "Prevent recurrence: placeholder parity",
            "body": "Validated prevention body\n",
        }
        draft_key = state.record_prevention_draft_event(
            **metadata,
            phase="validated",
            occurred_at=now,
        )
        monkeypatch.setattr(guardian_state, "_MAX_PREVENTION_SOURCE_REVISIONS", 0)

        with pytest.raises(RuntimeError, match="malformed data"):
            state.prevention_draft_by_key(draft_key)


def test_prevention_attestation_rejects_recursively_nested_json_as_value_error(
    tmp_path: Path,
) -> None:
    nested = '{"nested":' + "[" * 1200 + "0" + "]" * 1200 + "}"
    with GuardianState(tmp_path / "guardian.sqlite3") as state:
        metadata = _prevention_attestation_metadata(state)
        with pytest.raises(ValueError, match="canonical JSON"):
            state.record_prevention_draft_event(
                run_id=state.start_run(
                    repository="acme/widgets",
                    locale="ru",
                    mode=GuardianMode.PROPOSE_PREVENTION,
                ),
                source_repository="acme/widgets",
                target_repository="guardian/pipeline",
                target_base_branch="main",
                target_base_sha="a" * 40,
                push_repository="guardian/pipeline",
                branch="guardian/prevention-" + "a" * 12 + "-" + "b" * 64,
                candidate_sha="c" * 40,
                evidence_hash="b" * 64,
                **{**metadata, "source_policy_json": nested},
                title="Prevent recurrence: nested attestation",
                body="Validated prevention body\n",
                phase="validated",
            )


def _prevention_attestation_metadata(
    state: GuardianState,
    *,
    source_repository: str = "acme/widgets",
    source_repository_id: int = 42,
    target_repository: str = "guardian/pipeline",
    target_repository_id: int = 84,
    push_repository: str = "guardian/pipeline",
    push_repository_id: int = 84,
    target_base_sha: str = "a" * 40,
    candidate_sha: str = "c" * 40,
) -> dict[str, object]:
    source_revision = state.record_feedback_event(
        _event(
            repository=source_repository,
            pr_number=12,
            event_id="42",
            head_sha="a" * 40,
            base_sha="b" * 40,
        )
    )
    policy = json.dumps(
        {
            "attestation_version": 1,
            "repository_policy": {
                "base_repo": source_repository,
                "base_repo_id": source_repository_id,
                "prevention": {
                    "target_base_branch": "main",
                    "push_branch_prefix": "guardian/prevention-",
                    "focused_test_argv": [["pytest", "-q"]],
                    "target_repository": {
                        "full_name": target_repository,
                        "id": target_repository_id,
                    },
                    "push_repository": {
                        "full_name": push_repository,
                        "id": push_repository_id,
                    },
                },
            },
        },
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    )
    tests = json.dumps(
        {
            "attestation_version": 1,
            "configured_focused_test_argv": [["pytest", "-q"]],
            "results": [
                {
                    "phase": "base",
                    "outcome": "failed",
                    "argv": ["pytest", "-q"],
                    "commit_sha": target_base_sha,
                    "parent_sha": None,
                    "returncode": 1,
                    "test_overlay_hash": "f" * 64,
                    "focused": True,
                },
                {
                    "phase": "patched",
                    "outcome": "passed",
                    "argv": ["pytest", "-q"],
                    "commit_sha": candidate_sha,
                    "parent_sha": target_base_sha,
                    "returncode": 0,
                    "test_overlay_hash": "f" * 64,
                    "focused": True,
                },
            ],
        },
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    )
    return {
        "source_policy_json": policy,
        "source_policy_digest": hashlib.sha256(policy.encode("ascii")).hexdigest(),
        "patch_paths": ("localize/rules.py", "tests/unit/test_rules.py"),
        "patch_hash": "d" * 64,
        "test_attestation_json": tests,
        "test_attestation_digest": hashlib.sha256(tests.encode("ascii")).hexdigest(),
        "open_source": OpenPullAuthorityReference(
            repository=source_repository,
            repository_id=source_repository_id,
            pull_id=500,
            pr_number=12,
            authority_digest="e" * 64,
            head_sha="a" * 40,
            base_sha="b" * 40,
        ),
        "source_pulls": (),
        "event_revision_ids": (source_revision.revision_id,),
    }


def test_prevention_open_source_revisions_must_match_live_exact_pull(
    tmp_path: Path,
) -> None:
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
    with GuardianState(tmp_path / "guardian.sqlite3") as state:
        run_id = state.start_run(
            repository="acme/widgets",
            locale="ru",
            mode=GuardianMode.PROPOSE_PREVENTION,
            started_at=now,
        )
        metadata = {
            "run_id": run_id,
            "source_repository": "acme/widgets",
            "target_repository": "guardian/pipeline",
            "target_base_branch": "main",
            "target_base_sha": "a" * 40,
            "push_repository": "guardian/pipeline",
            "branch": "guardian/prevention-" + "a" * 12 + "-" + "b" * 64,
            "candidate_sha": "c" * 40,
            "evidence_hash": "b" * 64,
            **_prevention_attestation_metadata(state),
            "title": "Prevent recurrence: placeholder parity",
            "body": "Validated prevention body\n",
            "phase": "validated",
            "occurred_at": now,
        }

        with pytest.raises(ValueError, match="exact open pull snapshot"):
            state.record_prevention_draft_event(
                **{**metadata, "event_revision_ids": (999,)}
            )

        source = metadata["open_source"]
        assert isinstance(source, OpenPullAuthorityReference)
        with pytest.raises(ValueError, match="exact open pull snapshot"):
            state.record_prevention_draft_event(
                **{**metadata, "open_source": replace(source, head_sha="d" * 40)}
            )

        deleted = state.record_feedback_event(
            replace(
                _event(
                    repository="acme/widgets",
                    pr_number=12,
                    event_id="43",
                    head_sha="a" * 40,
                    base_sha="b" * 40,
                ),
                deleted=True,
            ),
            observed_at=now,
        )
        with pytest.raises(ValueError, match="exact open pull snapshot"):
            state.record_prevention_draft_event(
                **{**metadata, "event_revision_ids": (deleted.revision_id,)}
            )


@pytest.mark.parametrize("deleted", [False, True], ids=("edited", "tombstoned"))
def test_prevention_open_source_rejects_superseded_event_before_authoring(
    deleted: bool,
    tmp_path: Path,
) -> None:
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
    with GuardianState(tmp_path / "guardian.sqlite3") as state:
        metadata = _prevention_attestation_metadata(state)
        source = metadata["open_source"]
        revision_ids = metadata["event_revision_ids"]
        assert isinstance(source, OpenPullAuthorityReference)
        assert isinstance(revision_ids, tuple)
        state.record_feedback_event(
            replace(
                _event(
                    repository="acme/widgets",
                    pr_number=12,
                    event_id="42",
                    head_sha="a" * 40,
                    base_sha="b" * 40,
                    body="Edited authority after candidate selection.",
                ),
                deleted=deleted,
                updated_at="2026-08-30T09:00:00Z",
            ),
            observed_at=now,
        )

        with pytest.raises(ValueError, match="exact open pull snapshot"):
            state.validate_prevention_source_attestation(
                source_repository="acme/widgets",
                open_source=source,
                source_pulls=(),
                event_revision_ids=revision_ids,
            )


def test_restored_identical_feedback_becomes_current_after_tombstone(
    tmp_path: Path,
) -> None:
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
    visible = _event(
        repository="acme/widgets",
        pr_number=12,
        event_id="42",
        head_sha="a" * 40,
        base_sha="b" * 40,
    )
    with GuardianState(tmp_path / "guardian.sqlite3") as state:
        first = state.record_feedback_event(visible, observed_at=now)
        refreshed = state.record_feedback_event(
            visible,
            observed_at=now + timedelta(seconds=30),
        )
        assert refreshed.revision_id == first.revision_id
        assert state.purge_raw_event_bodies(before=now + timedelta(seconds=1)) == 0
        assert state.get_event_revision(first.revision_id).body == visible.body
        tombstone = state.record_feedback_event(
            replace(visible, body="", deleted=True),
            observed_at=now + timedelta(minutes=1),
        )
        assert (
            state.purge_raw_event_bodies(before=now + timedelta(minutes=1, seconds=30))
            == 2
        )
        assert state.get_event_revision(first.revision_id).body is None
        restored = state.record_feedback_event(
            visible,
            observed_at=now + timedelta(minutes=2),
        )

        assert restored.revision_id == first.revision_id
        assert tombstone.revision_id != first.revision_id
        assert restored.is_new is False
        assert restored.body == visible.body
        latest = state.latest_event_revisions(
            repository="acme/widgets",
            pr_number=12,
        )
        assert len(latest) == 1
        assert latest[0].revision_id == first.revision_id
        assert latest[0].deleted is False
        assert latest[0].body == visible.body

        state.validate_prevention_source_attestation(
            source_repository="acme/widgets",
            open_source=OpenPullAuthorityReference(
                repository="acme/widgets",
                repository_id=42,
                pull_id=500,
                pr_number=12,
                authority_digest="f" * 64,
                head_sha="a" * 40,
                base_sha="b" * 40,
            ),
            source_pulls=(),
            event_revision_ids=(first.revision_id,),
        )


def test_current_observation_rejects_a_mismatched_event_identity(
    tmp_path: Path,
) -> None:
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
    with GuardianState(tmp_path / "guardian.sqlite3") as state:
        first = state.record_feedback_event(_event(event_id="42"), observed_at=now)
        second = state.record_feedback_event(_event(event_id="43"), observed_at=now)

        with pytest.raises(
            sqlite3.IntegrityError,
            match="event current observation identity mismatch",
        ):
            state._connection.execute(  # noqa: SLF001 - DB invariant assertion
                """
                INSERT INTO event_current_observations (
                    repository, pr_number, kind, event_id,
                    event_revision_id, observed_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    first.repository,
                    first.pr_number,
                    first.kind,
                    first.event_id,
                    second.revision_id,
                    "2026-08-30T12:01:00.000000Z",
                ),
            )


def test_prevention_open_source_validation_chunks_revision_queries(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
    with GuardianState(tmp_path / "guardian.sqlite3") as state:
        revisions = tuple(
            state.record_feedback_event(
                _event(
                    repository="acme/widgets",
                    pr_number=12,
                    event_id=str(event_id),
                    head_sha="a" * 40,
                    base_sha="b" * 40,
                ),
                observed_at=now,
            ).revision_id
            for event_id in range(1, 4)
        )
        source = OpenPullAuthorityReference(
            repository="acme/widgets",
            repository_id=42,
            pull_id=500,
            pr_number=12,
            authority_digest="f" * 64,
            head_sha="a" * 40,
            base_sha="b" * 40,
        )
        monkeypatch.setattr(guardian_state, "_SQLITE_IN_QUERY_CHUNK", 1)

        state.validate_prevention_source_attestation(
            source_repository="acme/widgets",
            open_source=source,
            source_pulls=(),
            event_revision_ids=revisions,
        )


def test_claimed_prevention_evidence_lookup_is_bounded_to_current_candidates(
    tmp_path: Path,
) -> None:
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
    with GuardianState(tmp_path / "guardian.sqlite3") as state:
        run_id = state.start_run(
            repository="acme/widgets",
            locale="ru",
            mode=GuardianMode.PROPOSE_PREVENTION,
            started_at=now,
        )
        evidence_hashes = tuple(
            hashlib.sha256(f"evidence-{index}".encode()).hexdigest()
            for index in range(500)
        )
        attestation = _prevention_attestation_metadata(state)
        for index, evidence_hash in enumerate(evidence_hashes):
            state.record_prevention_draft_event(
                run_id=run_id,
                source_repository="acme/widgets",
                target_repository="guardian/pipeline",
                target_base_branch="main",
                target_base_sha="a" * 40,
                push_repository="guardian/pipeline",
                branch=("guardian/prevention-" + "a" * 12 + "-" + evidence_hash),
                candidate_sha="c" * 40,
                evidence_hash=evidence_hash,
                **attestation,
                title=f"Prevention {index}",
                body="Body\n",
                phase="validated",
                occurred_at=now,
            )
        unknown = "f" * 64

        assert state.claimed_prevention_evidence_hashes(
            source_repository_id=42,
            target_repository_id=84,
            evidence_hashes=(evidence_hashes[-1], unknown),
        ) == frozenset({evidence_hashes[-1]})
        plan = state._connection.execute(  # noqa: SLF001 - index assertion
            """
            EXPLAIN QUERY PLAN
            SELECT DISTINCT event.evidence_hash
            FROM prevention_draft_events AS event
            JOIN prevention_candidate_attestations AS attestation
              ON attestation.draft_key = event.draft_key
            WHERE attestation.source_repository_id = ?
              AND attestation.target_repository_id = ?
              AND event.evidence_hash IN (?, ?)
            """,
            (
                42,
                84,
                evidence_hashes[-1],
                unknown,
            ),
        ).fetchall()
        assert any(
            "prevention_attestation_repository_ids" in str(row["detail"])
            or "prevention_draft_evidence_key" in str(row["detail"])
            for row in plan
        )
        with pytest.raises(ValueError, match="at most 100"):
            state.claimed_prevention_evidence_hashes(
                source_repository_id=42,
                target_repository_id=84,
                evidence_hashes=evidence_hashes[:101],
            )


def test_prevention_sequence_bounds_are_checked_before_materialization(
    tmp_path: Path,
) -> None:
    class OversizedSequence:
        def __len__(self) -> int:
            return 101

        def __iter__(self):
            raise AssertionError("oversized input must not be materialized")

    oversized = OversizedSequence()
    with GuardianState(tmp_path / "guardian.sqlite3") as state:
        with pytest.raises(ValueError, match="bindings are malformed"):
            state.validate_prevention_evidence_bindings(
                source_repository="acme/widgets",
                feedback_revision_ids=oversized,  # type: ignore[arg-type]
            )
        with pytest.raises(ValueError, match="at most 100"):
            state.claimed_prevention_evidence_hashes(
                source_repository_id=42,
                target_repository_id=84,
                evidence_hashes=oversized,  # type: ignore[arg-type]
            )


def test_prevention_recovery_rotation_and_operator_quarantine_are_bounded(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
    monkeypatch.setattr(guardian_state, "_MAX_PREVENTION_RECOVERY_ATTEMPTS", 1)
    with GuardianState(tmp_path / "guardian.sqlite3") as state:
        run_id = state.start_run(
            repository="acme/widgets",
            locale="ru",
            mode=GuardianMode.PROPOSE_PREVENTION,
            started_at=now,
        )
        keys: list[str] = []
        for offset in range(2):
            metadata = {
                "run_id": run_id,
                "source_repository": "acme/widgets",
                "target_repository": "guardian/pipeline",
                "target_base_branch": "main",
                "target_base_sha": "a" * 40,
                "push_repository": "guardian/pipeline",
                "branch": (
                    "guardian/prevention-" + "a" * 12 + "-" + f"{offset + 1:x}" * 64
                ),
                "candidate_sha": f"{offset + 2:x}" * 40,
                "evidence_hash": f"{offset + 1:x}" * 64,
                **_prevention_attestation_metadata(
                    state,
                    candidate_sha=f"{offset + 2:x}" * 40,
                ),
                "title": f"Prevent recurrence {offset}",
                "body": "Validated prevention body\n",
                "occurred_at": now + timedelta(seconds=offset),
            }
            keys.append(
                state.record_prevention_draft_event(
                    **metadata,
                    phase="validated",
                )
            )

        assert state.pending_prevention_draft_keys_for_recovery(limit=1) == (keys[0],)
        assert (
            state.record_prevention_recovery_attempt(
                draft_key=keys[0],
                occurred_at=now + timedelta(minutes=1),
            )
            is PreventionRecoveryAttemptDisposition.RETRYABLE
        )
        assert (
            state.record_prevention_recovery_attempt(
                draft_key=keys[0],
                occurred_at=now + timedelta(minutes=2),
            )
            is PreventionRecoveryAttemptDisposition.FINAL
        )
        assert (
            state.record_prevention_recovery_attempt(
                draft_key=keys[0],
                occurred_at=now + timedelta(minutes=3),
            )
            is PreventionRecoveryAttemptDisposition.FINAL
        )
        assert state.pending_prevention_draft_keys_for_recovery(limit=1) == (keys[1],)
        with pytest.raises(ValueError, match="acknowledgement"):
            state.record_prevention_resolution(
                draft_key=keys[1],
                resolution="operator_quarantined",
                occurred_at=now + timedelta(minutes=1),
            )
        state.record_prevention_resolution(
            draft_key=keys[1],
            resolution="operator_quarantined",
            terminal_local_skip_acknowledged=True,
            occurred_at=now + timedelta(minutes=1),
        )
        with pytest.raises(ValueError, match="pending prevention draft"):
            state.record_prevention_recovery_attempt(
                draft_key=keys[1],
                occurred_at=now + timedelta(minutes=2),
            )
        with pytest.raises(sqlite3.IntegrityError, match="pending event"):
            state._connection.execute(  # noqa: SLF001 - DB invariant assertion
                """
                INSERT INTO prevention_recovery_attempt_events (
                    draft_key, occurred_at
                ) VALUES (?, ?)
                """,
                (keys[1], "2026-08-30T12:02:00.000000Z"),
            )
        with pytest.raises(ValueError, match="resolution is terminal"):
            state.record_prevention_draft_event(
                **{
                    "run_id": run_id,
                    "source_repository": "acme/widgets",
                    "target_repository": "guardian/pipeline",
                    "target_base_branch": "main",
                    "target_base_sha": "a" * 40,
                    "push_repository": "guardian/pipeline",
                    "branch": ("guardian/prevention-" + "a" * 12 + "-" + "2" * 64),
                    "candidate_sha": "3" * 40,
                    "evidence_hash": "2" * 64,
                    **_prevention_attestation_metadata(
                        state,
                        candidate_sha="3" * 40,
                    ),
                    "title": "Prevent recurrence 1",
                    "body": "Validated prevention body\n",
                },
                phase="pushed",
                occurred_at=now + timedelta(minutes=1),
            )
        with pytest.raises(
            sqlite3.IntegrityError,
            match="prevention draft resolution is terminal",
        ):
            state._connection.execute(  # noqa: SLF001 - DB invariant assertion
                """
                INSERT INTO prevention_draft_events (
                    draft_key, run_id, source_repository, target_repository,
                    target_base_branch, target_base_sha, push_repository,
                    branch, candidate_sha, evidence_hash, title, body, phase,
                    draft_number, draft_url, occurred_at
                )
                SELECT draft_key, run_id, source_repository, target_repository,
                       target_base_branch, target_base_sha, push_repository,
                       branch, candidate_sha, evidence_hash, title, body,
                       'pushed', NULL, NULL, ?
                FROM prevention_draft_events
                WHERE draft_key = ? AND phase = 'validated'
                """,
                (
                    "2026-08-30T12:01:00.000000Z",
                    keys[1],
                ),
            )

        snapshot = state.status_snapshot(
            mode=GuardianMode.PROPOSE_PREVENTION,
            as_of=now + timedelta(minutes=2),
        )
        assert snapshot.pending_preventions == 1
        assert snapshot.opened_preventions == 0
        assert snapshot.conflicted_preventions == 0
        assert snapshot.quarantined_preventions == 1
        with pytest.raises(ValueError, match="1 through 100"):
            state.pending_prevention_draft_keys_for_recovery(limit=101)


def _remediation_target_mappings(
    edit_hashes: tuple[str, ...],
) -> tuple[tuple[str, str], ...]:
    return tuple(
        (
            edit_hash,
            hashlib.sha256(f"target:{edit_hash}".encode()).hexdigest(),
        )
        for edit_hash in edit_hashes
    )


def _remediation_metadata(
    state: GuardianState,
    *,
    now: datetime,
    repository: str = "acme/widgets",
    repository_id: int = 42,
    edit_hashes: tuple[str, ...] = ("e" * 64,),
) -> dict[str, object]:
    first = state.record_feedback_event(
        _event(repository=repository, pr_number=12),
        observed_at=now,
    )
    second = state.record_feedback_event(
        _event(
            repository=repository,
            pr_number=13,
            body="Second finding",
            event_id="98766",
        ),
        observed_at=now,
    )
    run_id = state.start_run(
        repository=repository,
        locale="ru",
        mode=GuardianMode.PROPOSE_PREVENTION,
        started_at=now,
    )
    source_pulls = (
        HistoricalPullReference(
            repository=repository,
            repository_id=repository_id,
            pull_id=500,
            pr_number=12,
            pull_revision_digest="1" * 64,
            authority_digest="4" * 64,
            policy_digest="2" * 64,
            head_sha="a" * 40,
            base_sha="b" * 40,
        ),
        HistoricalPullReference(
            repository=repository,
            repository_id=repository_id,
            pull_id=501,
            pr_number=13,
            pull_revision_digest="3" * 64,
            authority_digest="5" * 64,
            policy_digest="2" * 64,
            head_sha="a" * 40,
            base_sha="b" * 40,
        ),
    )
    event_revision_ids = (first.revision_id, second.revision_id)
    for source in source_pulls:
        source_revision_ids = tuple(
            revision_id
            for revision_id in event_revision_ids
            if state.get_event_revision(revision_id).pr_number == source.pr_number
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
            event_revision_ids=source_revision_ids,
            authority_scope=HistoricalCheckScope.ASSESSMENT,
            completed_at=now,
        )
    evidence_hash = state.validate_historical_remediation_evidence(
        source_pulls=source_pulls,
        event_revision_ids=event_revision_ids,
    )
    return {
        "run_id": run_id,
        "target_repository": repository,
        "target_repository_id": repository_id,
        "target_base_branch": "main",
        "target_base_sha": "a" * 40,
        "push_repository": "localize-bot/widgets",
        "push_repository_id": 84,
        "branch": "guardian/remediation-" + "b" * 64,
        "candidate_sha": "c" * 40,
        "evidence_hash": evidence_hash,
        "batch_hash": guardian_state.remediation_batch_hash(edit_hashes),
        "edit_hashes": edit_hashes,
        "edit_target_hashes": _remediation_target_mappings(edit_hashes),
        "source_pulls": source_pulls,
        "event_revision_ids": event_revision_ids,
        "changed_paths": ("l10n/messages_ru.properties",),
        "title": "Review historical localization corrections",
        "body": "Signed remediation candidate for human review.\n",
        "occurred_at": now,
    }


def _open_remediation_draft(
    state: GuardianState,
    metadata: dict[str, object],
    *,
    draft_number: int = 91,
) -> str:
    draft_key = state.record_remediation_draft_event(
        **metadata,
        phase="validated",
    )
    state.record_remediation_draft_event(**metadata, phase="pushed")
    state.record_remediation_draft_event(
        **metadata,
        phase="draft_opened",
        draft_number=draft_number,
        draft_pull_id=901,
        draft_url=f"https://github.test/acme/widgets/pull/{draft_number}",
    )
    return draft_key


@pytest.mark.parametrize(
    "mode",
    (
        GuardianMode.APPLY_OWNED_TRANSLATIONS,
        GuardianMode.PROPOSE_PREVENTION,
    ),
)
def test_remediation_draft_accepts_each_write_run_mode(
    tmp_path: Path,
    mode: GuardianMode,
) -> None:
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
    with GuardianState(tmp_path / "guardian.sqlite3") as state:
        metadata = _remediation_metadata(state, now=now)
        run_id = state.start_run(
            repository="acme/widgets",
            locale="ru",
            mode=mode,
            started_at=now,
        )
        draft_key = state.record_remediation_draft_event(
            **{**metadata, "run_id": run_id},
            phase="validated",
        )

        draft = state.remediation_draft_by_key(draft_key=draft_key)
        assert draft is not None
        assert draft.run_id == run_id


@pytest.mark.parametrize(
    ("ledger", "invalid_run"),
    (
        ("prevention", "missing"),
        ("prevention", "wrong-repository"),
        ("prevention", "wrong-mode"),
        ("prevention", "apply-mode"),
        ("remediation", "missing"),
        ("remediation", "wrong-repository"),
        ("remediation", "wrong-mode"),
        ("remediation", "prepare-mode"),
    ),
)
def test_draft_ledgers_require_mode_specific_run_authority(
    tmp_path: Path,
    ledger: str,
    invalid_run: str,
) -> None:
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
    with GuardianState(tmp_path / "guardian.sqlite3") as state:
        if invalid_run == "missing":
            run_id = "missing-run"
        else:
            run_id = state.start_run(
                repository=(
                    "other/widgets"
                    if invalid_run == "wrong-repository"
                    else "acme/widgets"
                ),
                locale="ru",
                mode={
                    "wrong-repository": GuardianMode.PROPOSE_PREVENTION,
                    "wrong-mode": GuardianMode.OBSERVE,
                    "apply-mode": GuardianMode.APPLY_OWNED_TRANSLATIONS,
                    "prepare-mode": GuardianMode.PREPARE,
                }[invalid_run],
                started_at=now,
            )
        if ledger == "prevention":
            metadata = {
                "run_id": run_id,
                "source_repository": "acme/widgets",
                "target_repository": "guardian/pipeline",
                "target_base_branch": "main",
                "target_base_sha": "a" * 40,
                "push_repository": "guardian/pipeline",
                "branch": "guardian/prevention-" + "a" * 12 + "-" + "b" * 64,
                "candidate_sha": "c" * 40,
                "evidence_hash": "b" * 64,
                **_prevention_attestation_metadata(state),
                "title": "Prevent recurrence: run authority",
                "body": "Validated prevention body\n",
                "occurred_at": now,
            }
            with pytest.raises(ValueError, match="run authority"):
                state.record_prevention_draft_event(**metadata, phase="validated")
        else:
            metadata = _remediation_metadata(state, now=now)
            with pytest.raises(ValueError, match="run authority"):
                state.record_remediation_draft_event(
                    **{**metadata, "run_id": run_id},
                    phase="validated",
                )


@pytest.mark.parametrize(
    ("ledger", "invalid_run"),
    (
        ("prevention", "missing"),
        ("prevention", "wrong-repository"),
        ("prevention", "wrong-mode"),
        ("prevention", "apply-mode"),
        ("remediation", "missing"),
        ("remediation", "wrong-repository"),
        ("remediation", "wrong-mode"),
        ("remediation", "prepare-mode"),
    ),
)
def test_draft_run_authority_is_enforced_for_raw_sql(
    tmp_path: Path,
    ledger: str,
    invalid_run: str,
) -> None:
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
    with GuardianState(tmp_path / "guardian.sqlite3") as state:
        if invalid_run == "missing":
            invalid_run_id = "missing-run"
        else:
            invalid_run_id = state.start_run(
                repository=(
                    "other/widgets"
                    if invalid_run == "wrong-repository"
                    else "acme/widgets"
                ),
                locale="ru",
                mode={
                    "wrong-repository": GuardianMode.PROPOSE_PREVENTION,
                    "wrong-mode": GuardianMode.OBSERVE,
                    "apply-mode": GuardianMode.APPLY_OWNED_TRANSLATIONS,
                    "prepare-mode": GuardianMode.PREPARE,
                }[invalid_run],
                started_at=now,
            )
        if ledger == "prevention":
            metadata = {
                "run_id": state.start_run(
                    repository="acme/widgets",
                    locale="ru",
                    mode=GuardianMode.PROPOSE_PREVENTION,
                    started_at=now,
                ),
                "source_repository": "acme/widgets",
                "target_repository": "guardian/pipeline",
                "target_base_branch": "main",
                "target_base_sha": "a" * 40,
                "push_repository": "guardian/pipeline",
                "branch": "guardian/prevention-" + "a" * 12 + "-" + "b" * 64,
                "candidate_sha": "c" * 40,
                "evidence_hash": "b" * 64,
                **_prevention_attestation_metadata(state),
                "title": "Prevent recurrence: raw run authority",
                "body": "Validated prevention body\n",
                "occurred_at": now,
            }
            draft_key = state.record_prevention_draft_event(
                **metadata, phase="validated"
            )
            with pytest.raises(sqlite3.IntegrityError, match="run authority"):
                state._connection.execute(  # noqa: SLF001
                    """
                    INSERT INTO prevention_draft_events (
                        draft_key, run_id, source_repository, target_repository,
                        target_base_branch, target_base_sha, push_repository,
                        branch, candidate_sha, evidence_hash, title, body, phase,
                        draft_number, draft_pull_id, draft_url, occurred_at
                    )
                    SELECT ?, ?, source_repository, target_repository,
                           target_base_branch, target_base_sha, push_repository,
                           branch, candidate_sha, evidence_hash, title, body,
                           phase, draft_number, draft_pull_id, draft_url, occurred_at
                    FROM prevention_draft_events
                    WHERE draft_key = ? LIMIT 1
                    """,
                    ("1" * 64, invalid_run_id, draft_key),
                )
        else:
            metadata = _remediation_metadata(state, now=now)
            draft_key = state.record_remediation_draft_event(
                **metadata, phase="validated"
            )
            with pytest.raises(sqlite3.IntegrityError, match="run authority"):
                state._connection.execute(  # noqa: SLF001
                    """
                    INSERT INTO remediation_draft_events (
                        draft_key, branch_identity_version, run_id,
                        target_repository, target_repository_id,
                        target_base_branch, target_base_sha, push_repository,
                        push_repository_id, branch, candidate_sha, evidence_hash,
                        batch_hash, source_pulls_json, event_revision_ids_json,
                        title, body, phase, draft_number, draft_pull_id, draft_url,
                        occurred_at
                    )
                    SELECT ?, branch_identity_version, ?, target_repository,
                           target_repository_id, target_base_branch,
                           target_base_sha, push_repository, push_repository_id,
                           branch, candidate_sha, evidence_hash, batch_hash,
                           source_pulls_json, event_revision_ids_json, title, body,
                           phase, draft_number, draft_pull_id, draft_url, occurred_at
                    FROM remediation_draft_events
                    WHERE draft_key = ? LIMIT 1
                    """,
                    ("1" * 64, invalid_run_id, draft_key),
                )


@pytest.mark.parametrize(
    ("ledger", "parent_corruption"),
    (
        ("prevention", "missing"),
        ("prevention", "wrong-repository"),
        ("prevention", "wrong-mode"),
        ("remediation", "missing"),
        ("remediation", "wrong-repository"),
        ("remediation", "wrong-mode"),
    ),
)
def test_pending_draft_recovery_revalidates_parent_run(
    tmp_path: Path,
    ledger: str,
    parent_corruption: str,
) -> None:
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
    with GuardianState(tmp_path / "guardian.sqlite3") as state:
        if ledger == "prevention":
            run_id = state.start_run(
                repository="acme/widgets",
                locale="ru",
                mode=GuardianMode.PROPOSE_PREVENTION,
                started_at=now,
            )
            state.record_prevention_draft_event(
                run_id=run_id,
                source_repository="acme/widgets",
                target_repository="guardian/pipeline",
                target_base_branch="main",
                target_base_sha="a" * 40,
                push_repository="guardian/pipeline",
                branch="guardian/prevention-" + "a" * 12 + "-" + "b" * 64,
                candidate_sha="c" * 40,
                evidence_hash="b" * 64,
                **_prevention_attestation_metadata(state),
                title="Prevent recurrence: recover parent",
                body="Validated prevention body\n",
                phase="validated",
                occurred_at=now,
            )
        else:
            metadata = _remediation_metadata(state, now=now)
            run_id = str(metadata["run_id"])
            state.record_remediation_draft_event(**metadata, phase="validated")

        if parent_corruption == "missing":
            state._connection.execute("PRAGMA foreign_keys = OFF")  # noqa: SLF001
            state._connection.execute(  # noqa: SLF001
                "DELETE FROM runs WHERE run_id = ?", (run_id,)
            )
        elif parent_corruption == "wrong-repository":
            state._connection.execute(  # noqa: SLF001
                "UPDATE runs SET repository = 'other/widgets' WHERE run_id = ?",
                (run_id,),
            )
        else:
            state._connection.execute(  # noqa: SLF001
                "UPDATE runs SET mode = ? WHERE run_id = ?",
                (GuardianMode.OBSERVE.value, run_id),
            )
        with pytest.raises(RuntimeError, match="malformed data"):
            if ledger == "prevention":
                state.pending_prevention_drafts()
            else:
                state.pending_remediation_drafts()


def _insert_raw_remediation_phase(
    state: GuardianState,
    *,
    source_draft_key: str,
    draft_key: str,
    phase: str,
    occurred_at: datetime,
    body: str | None = None,
) -> None:
    opened = phase == "draft_opened"
    state._connection.execute(  # noqa: SLF001
        """
        INSERT INTO remediation_draft_events (
            draft_key, branch_identity_version, run_id,
            target_repository, target_repository_id,
            target_base_branch, target_base_sha, push_repository,
            push_repository_id, branch, candidate_sha, evidence_hash,
            batch_hash, source_pulls_json, event_revision_ids_json,
            title, body, phase, draft_number, draft_pull_id, draft_url,
            occurred_at
        )
        SELECT ?, branch_identity_version, run_id, target_repository,
               target_repository_id, target_base_branch, target_base_sha,
               push_repository, push_repository_id, branch, candidate_sha,
               evidence_hash, batch_hash, source_pulls_json,
               event_revision_ids_json, title, COALESCE(?, body), ?, ?, ?, ?, ?
        FROM remediation_draft_events
        WHERE draft_key = ? AND phase = 'validated'
        """,
        (
            draft_key,
            body,
            phase,
            91 if opened else None,
            901 if opened else None,
            "https://github.test/acme/widgets/pull/91" if opened else None,
            occurred_at.isoformat(timespec="microseconds").replace("+00:00", "Z"),
            source_draft_key,
        ),
    )


@pytest.mark.parametrize(
    "mode",
    (
        GuardianMode.APPLY_OWNED_TRANSLATIONS,
        GuardianMode.PROPOSE_PREVENTION,
    ),
)
def test_migration_accepts_each_remediation_write_run_mode(
    tmp_path: Path,
    mode: GuardianMode,
) -> None:
    """Retain valid historical publications from either authorized write mode."""
    database = tmp_path / "guardian.sqlite3"
    _create_v4_migration_fixture(database)
    run_id = "00000000-0000-4000-8000-000000000099"
    with sqlite3.connect(database) as connection:
        connection.execute(
            "INSERT INTO runs VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                run_id,
                "acme/widgets",
                "ru",
                mode.value,
                "completed",
                "2026-08-30T12:00:00.000000Z",
                "2026-08-30T12:01:00.000000Z",
                "legacy audit fixture",
            ),
        )
        connection.execute(
            """
            INSERT INTO remediation_draft_events (
                draft_key, run_id, target_repository, target_repository_id,
                target_base_branch, target_base_sha, push_repository,
                push_repository_id, branch, candidate_sha, evidence_hash,
                batch_hash, source_pulls_json, event_revision_ids_json,
                title, body, phase, draft_number, draft_url, occurred_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "a" * 64,
                run_id,
                "acme/widgets",
                42,
                "main",
                "a" * 40,
                "localize-bot/widgets",
                84,
                "guardian/remediation-audit",
                "c" * 40,
                "d" * 64,
                "e" * 64,
                "[]",
                "[]",
                "Legacy remediation audit",
                "Legacy body\n",
                "validated",
                None,
                None,
                "2026-08-30T12:00:00.000000Z",
            ),
        )

    with GuardianState(database) as state:
        assert (
            state._connection.execute(  # noqa: SLF001
                "PRAGMA user_version"
            ).fetchone()[0]
            == 11
        )


@pytest.mark.parametrize(
    "malformation",
    (
        "missing-validated",
        "skipped-pushed",
        "identity-change",
        "after-abandoned",
        "after-opened",
        "after-resolution",
    ),
)
def test_remediation_phase_machine_is_enforced_for_raw_sql(
    tmp_path: Path,
    malformation: str,
) -> None:
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
    with GuardianState(tmp_path / "guardian.sqlite3") as state:
        metadata = _remediation_metadata(state, now=now)
        draft_key = state.record_remediation_draft_event(**metadata, phase="validated")

        if malformation == "missing-validated":
            with pytest.raises(sqlite3.IntegrityError, match="begin with validated"):
                _insert_raw_remediation_phase(
                    state,
                    source_draft_key=draft_key,
                    draft_key="1" * 64,
                    phase="pushed",
                    occurred_at=now + timedelta(minutes=1),
                )
        elif malformation == "skipped-pushed":
            with pytest.raises(sqlite3.IntegrityError, match="transition"):
                _insert_raw_remediation_phase(
                    state,
                    source_draft_key=draft_key,
                    draft_key=draft_key,
                    phase="draft_opened",
                    occurred_at=now + timedelta(minutes=1),
                )
        elif malformation == "identity-change":
            with pytest.raises(sqlite3.IntegrityError, match="identity"):
                _insert_raw_remediation_phase(
                    state,
                    source_draft_key=draft_key,
                    draft_key=draft_key,
                    phase="pushed",
                    body="Changed body\n",
                    occurred_at=now + timedelta(minutes=1),
                )
        elif malformation == "after-abandoned":
            state.record_remediation_draft_event(
                **{**metadata, "occurred_at": now + timedelta(minutes=1)},
                phase="abandoned",
            )
            with pytest.raises(sqlite3.IntegrityError, match="transition"):
                _insert_raw_remediation_phase(
                    state,
                    source_draft_key=draft_key,
                    draft_key=draft_key,
                    phase="pushed",
                    occurred_at=now + timedelta(minutes=2),
                )
        elif malformation == "after-opened":
            state.record_remediation_draft_event(
                **{**metadata, "occurred_at": now + timedelta(minutes=1)},
                phase="pushed",
            )
            state.record_remediation_draft_event(
                **{**metadata, "occurred_at": now + timedelta(minutes=2)},
                phase="draft_opened",
                draft_number=91,
                draft_pull_id=901,
                draft_url="https://github.test/acme/widgets/pull/91",
            )
            with pytest.raises(sqlite3.IntegrityError, match="transition"):
                _insert_raw_remediation_phase(
                    state,
                    source_draft_key=draft_key,
                    draft_key=draft_key,
                    phase="abandoned",
                    occurred_at=now + timedelta(minutes=3),
                )
        else:
            state.record_remediation_resolution(
                draft_key=draft_key,
                resolution="operator_quarantined",
                terminal_local_skip_acknowledged=True,
                occurred_at=now + timedelta(minutes=1),
            )
            with pytest.raises(sqlite3.IntegrityError, match="resolution is terminal"):
                _insert_raw_remediation_phase(
                    state,
                    source_draft_key=draft_key,
                    draft_key=draft_key,
                    phase="pushed",
                    occurred_at=now + timedelta(minutes=2),
                )


def _source_lookup(source: HistoricalPullReference) -> dict[str, object]:
    return {
        "repository": source.repository,
        "repository_id": source.repository_id,
        "pull_id": source.pull_id,
        "pull_revision_digest": source.pull_revision_digest,
        "policy_digest": source.policy_digest,
    }


def _source_revision_ids(
    state: GuardianState,
    metadata: dict[str, object],
    source: HistoricalPullReference,
) -> tuple[int, ...]:
    return tuple(
        revision_id
        for revision_id in metadata["event_revision_ids"]
        if state.get_event_revision(revision_id).pr_number == source.pr_number
    )


def _record_merged_observation(
    state: GuardianState,
    *,
    draft_key: str,
    observed_at: datetime,
    observed_base_sha: str = "f" * 40,
) -> None:
    draft = state.remediation_draft_by_key(draft_key=draft_key)
    assert draft is not None
    state.record_remediation_remote_observation(
        draft_key=draft_key,
        observation="exact",
        state="closed",
        is_draft=False,
        is_merged=True,
        pr_number=draft.draft_number,
        pr_url=draft.draft_url,
        observed_base_sha=observed_base_sha,
        observed_head_sha=state.remediation_candidate_tip(draft_key),
        closed_at=observed_at.isoformat().replace("+00:00", "Z"),
        merged_at=observed_at.isoformat().replace("+00:00", "Z"),
        observed_at=observed_at,
    )


def _record_draft_backed_remediation_completions(
    state: GuardianState,
    coverage_by_source: dict[HistoricalPullReference, tuple[str, ...]],
    reason: RemediationCoverageReason,
    **kwargs: object,
) -> tuple[guardian_state.RemediationSourceCoverageGroup, ...]:
    required: dict[HistoricalPullReference, tuple[str, ...]] = {}
    for source, draft_keys in coverage_by_source.items():
        hashes: set[str] = set()
        for draft_key in draft_keys:
            draft = state.remediation_draft_by_key(draft_key=draft_key)
            if draft is not None:
                hashes.update(draft.edit_hashes)
        required[source] = tuple(sorted(hashes or {"e" * 64}))
    return state.record_draft_backed_remediation_completions(
        coverage_by_source,
        reason,
        required_edit_hashes_by_source=required,
        **kwargs,
    )


def test_operator_remediation_worklist_is_bounded_and_advances(
    tmp_path: Path,
) -> None:
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
    with GuardianState(tmp_path / "guardian.sqlite3") as state:
        first_metadata = _remediation_metadata(
            state,
            now=now,
            edit_hashes=("e" * 64,),
        )
        first_key = state.record_remediation_draft_event(
            **first_metadata,
            phase="validated",
        )
        second_metadata = _remediation_metadata(
            state,
            now=now + timedelta(seconds=1),
            edit_hashes=("f" * 64,),
        )
        second_key = state.record_remediation_draft_event(
            **second_metadata,
            phase="validated",
        )
        third_metadata = _remediation_metadata(
            state,
            now=now + timedelta(seconds=2),
            edit_hashes=("1" * 64,),
        )
        third_key = state.record_remediation_draft_event(
            **third_metadata,
            phase="validated",
        )
        state.record_remediation_draft_event(
            **{
                **third_metadata,
                "occurred_at": now + timedelta(seconds=3),
            },
            phase="abandoned",
        )

        assert [
            item.draft_key
            for item in state.active_remediation_drafts_for_operator(limit=1)
        ] == [first_key]
        assert state.active_remediation_draft_count() == 2
        state.record_remediation_resolution(
            draft_key=first_key,
            resolution="operator_quarantined",
            terminal_local_skip_acknowledged=True,
            occurred_at=now + timedelta(minutes=1),
        )
        assert [
            item.draft_key
            for item in state.active_remediation_drafts_for_operator(limit=1)
        ] == [second_key]
        assert [
            item.draft_key for item in state.remediation_drafts_for_operator(limit=3)
        ] == [second_key, first_key, third_key]
        assert state.remediation_draft_count_for_operator() == 3

        with pytest.raises(ValueError, match="1 through 100"):
            state.active_remediation_drafts_for_operator(limit=101)
        with pytest.raises(ValueError, match="1 through 100"):
            state.remediation_drafts_for_operator(limit=101)


def test_remediation_draft_phase_timestamps_are_monotonic_and_db_enforced(
    tmp_path: Path,
) -> None:
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
    with GuardianState(tmp_path / "guardian.sqlite3") as state:
        metadata = _remediation_metadata(state, now=now)
        draft_key = state.record_remediation_draft_event(
            **metadata,
            phase="validated",
        )
        state.record_remediation_draft_event(
            **{**metadata, "occurred_at": now + timedelta(minutes=2)},
            phase="pushed",
        )

        with pytest.raises(ValueError, match="monotonic"):
            state.record_remediation_draft_event(
                **{**metadata, "occurred_at": now + timedelta(minutes=1)},
                phase="draft_opened",
                draft_number=91,
                draft_pull_id=9_091,
                draft_url="https://github.test/acme/widgets/pull/91",
            )
        with pytest.raises(sqlite3.IntegrityError, match="monotonic"):
            state._connection.execute(  # noqa: SLF001 - DB invariant assertion
                """
                INSERT INTO remediation_draft_events (
                    draft_key, branch_identity_version, run_id,
                    target_repository, target_repository_id,
                    target_base_branch, target_base_sha, push_repository,
                    push_repository_id, branch, candidate_sha, evidence_hash,
                    batch_hash, source_pulls_json, event_revision_ids_json,
                    title, body, phase, draft_number, draft_pull_id,
                    draft_url, occurred_at
                )
                SELECT draft_key, branch_identity_version, run_id,
                       target_repository, target_repository_id,
                       target_base_branch, target_base_sha, push_repository,
                       push_repository_id, branch, candidate_sha, evidence_hash,
                       batch_hash, source_pulls_json, event_revision_ids_json,
                       title, body, 'draft_opened', 91, 9091,
                       'https://github.test/acme/widgets/pull/91', ?
                FROM remediation_draft_events
                WHERE draft_key = ? AND phase = 'pushed'
                """,
                ("2026-08-30T12:01:00.000000Z", draft_key),
            )

        assert state.remediation_draft_by_key(draft_key=draft_key).phase == "pushed"


def test_status_snapshot_counts_retry_and_every_remediation_state(
    tmp_path: Path,
) -> None:
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
    with GuardianState(tmp_path / "guardian.sqlite3") as state:
        retry_common = {
            "repository": "acme/widgets",
            "repository_id": 42,
            "policy_digest": "9" * 64,
        }
        for pull_id, pr_number in ((700, 70), (701, 71)):
            state.record_historical_pull_retry(
                **retry_common,
                pull_id=pull_id,
                pr_number=pr_number,
                failure_type="GitHubAPIError",
                failed_at=now,
            )
        state.record_historical_pull_retry_resolution(
            **retry_common,
            pull_id=700,
            pr_number=70,
            resolution="operator_quarantined",
            terminal_local_skip_acknowledged=True,
            occurred_at=now,
        )

        keys: dict[str, str] = {}
        for offset, phase in enumerate(
            ("validated", "draft_opened", "abandoned", "quarantined", "merged")
        ):
            metadata = _remediation_metadata(
                state,
                now=now + timedelta(seconds=offset),
                edit_hashes=(f"{offset + 1:x}" * 64,),
            )
            key = state.record_remediation_draft_event(
                **metadata,
                phase="validated",
            )
            keys[phase] = key
            if phase in {"draft_opened", "merged"}:
                state.record_remediation_draft_event(**metadata, phase="pushed")
                state.record_remediation_draft_event(
                    **metadata,
                    phase="draft_opened",
                    draft_number=90 + offset,
                    draft_pull_id=9_000 + offset,
                    draft_url=f"https://github.test/acme/widgets/pull/{90 + offset}",
                )
            elif phase == "abandoned":
                state.record_remediation_draft_event(**metadata, phase="abandoned")
            elif phase == "quarantined":
                state.record_remediation_resolution(
                    draft_key=key,
                    resolution="operator_quarantined",
                    terminal_local_skip_acknowledged=True,
                    occurred_at=now + timedelta(minutes=1),
                )
        merged_draft = state.remediation_draft_by_key(draft_key=keys["merged"])
        assert merged_draft is not None
        state.record_remediation_remote_observation(
            draft_key=keys["merged"],
            observation="exact",
            state="closed",
            is_draft=False,
            is_merged=True,
            pr_number=merged_draft.draft_number,
            pr_url=merged_draft.draft_url,
            observed_base_sha="f" * 40,
            observed_head_sha=state.remediation_candidate_tip(keys["merged"]),
            closed_at="2026-08-30T12:01:00Z",
            merged_at="2026-08-30T12:01:00Z",
            observed_at=now + timedelta(minutes=1),
        )

        snapshot = state.status_snapshot(mode=GuardianMode.OBSERVE, as_of=now)

    assert snapshot.pending_historical_retries == 1
    assert snapshot.quarantined_historical_retries == 1
    assert snapshot.pending_remediations == 1
    assert snapshot.opened_remediations == 1
    assert snapshot.abandoned_remediations == 1
    assert snapshot.quarantined_remediations == 1
    assert snapshot.merged_remediations == 1
    assert snapshot.remote_exact_open_remediations == 0
    assert snapshot.remote_closed_unmerged_remediations == 0
    assert snapshot.remote_not_found_remediations == 0
    assert snapshot.remote_conflict_remediations == 0


def test_remediation_evidence_requires_exact_assessed_revision_set(
    tmp_path: Path,
) -> None:
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
    with GuardianState(tmp_path / "guardian.sqlite3") as state:
        first = state.record_feedback_event(_event(pr_number=12), observed_at=now)
        second = state.record_feedback_event(
            _event(pr_number=12, event_id="98766", body="Second finding"),
            observed_at=now,
        )
        source = HistoricalPullReference(
            repository="acme/widgets",
            repository_id=42,
            pull_id=500,
            pr_number=12,
            pull_revision_digest="1" * 64,
            authority_digest="4" * 64,
            policy_digest="2" * 64,
            head_sha="a" * 40,
            base_sha="b" * 40,
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
            event_revision_ids=(first.revision_id, second.revision_id),
            authority_scope=HistoricalCheckScope.ASSESSMENT,
            completed_at=now,
        )

        with pytest.raises(ValueError, match="exactly match"):
            state.validate_historical_remediation_evidence(
                source_pulls=(source,),
                event_revision_ids=(first.revision_id,),
            )


def test_current_evidence_allows_only_assessment_classified_extra_events(
    tmp_path: Path,
) -> None:
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
    with GuardianState(tmp_path / "guardian.sqlite3") as state:
        selected = state.record_feedback_event(
            _event(pr_number=12),
            observed_at=now,
        )
        inapplicable = state.record_feedback_event(
            _event(
                pr_number=12,
                event_id="98766",
                body="Finding for a target absent from the current base.",
            ),
            observed_at=now,
        )
        tombstone = state.record_feedback_event(
            replace(
                _event(
                    pr_number=12,
                    event_id="98767",
                    body="",
                ),
                deleted=True,
            ),
            observed_at=now,
        )
        source = HistoricalPullReference(
            repository="acme/widgets",
            repository_id=42,
            pull_id=500,
            pr_number=12,
            pull_revision_digest="1" * 64,
            authority_digest="4" * 64,
            policy_digest="2" * 64,
            head_sha="a" * 40,
            base_sha="b" * 40,
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
            event_revision_ids=(selected.revision_id,),
            ignored_event_revision_ids=(
                inapplicable.revision_id,
                tombstone.revision_id,
            ),
            authority_scope=HistoricalCheckScope.ASSESSMENT,
            completed_at=now,
        )

        state.validate_current_historical_remediation_evidence(
            source_pulls=(source,),
            event_revision_ids=(selected.revision_id,),
        )
        completion = state._connection.execute(  # noqa: SLF001
            "SELECT ignored_event_revision_ids_json "
            "FROM historical_pull_completions "
            "WHERE authority_scope = 'assessment'"
        ).fetchone()
        assert completion is not None
        assert json.loads(completion["ignored_event_revision_ids_json"]) == [
            inapplicable.revision_id,
            tombstone.revision_id,
        ]

        state.record_feedback_event(
            _event(
                pr_number=12,
                event_id="98768",
                body="Trusted feedback added after assessment.",
            ),
            observed_at=now + timedelta(minutes=1),
        )
        with pytest.raises(ValueError, match="no longer current"):
            state.validate_current_historical_remediation_evidence(
                source_pulls=(source,),
                event_revision_ids=(selected.revision_id,),
            )


def test_historical_completion_rejects_overlapping_authority_classifications(
    tmp_path: Path,
) -> None:
    with GuardianState(tmp_path / "guardian.sqlite3") as state:
        revision = state.record_feedback_event(_event(pr_number=12))

        with pytest.raises(ValueError, match="disjoint"):
            state.record_historical_pull_completion(
                repository="acme/widgets",
                repository_id=42,
                pull_id=500,
                pr_number=12,
                pull_revision_digest="1" * 64,
                policy_digest="2" * 64,
                head_sha="a" * 40,
                base_sha="b" * 40,
                event_revision_ids=(revision.revision_id,),
                ignored_event_revision_ids=(revision.revision_id,),
                authority_scope=HistoricalCheckScope.ASSESSMENT,
            )


@pytest.mark.parametrize(
    "raw_revision_ids",
    (
        "1",
        "[[1]]",
        "[1,1]",
        "[2,1]",
        "[" * 1200 + "1" + "]" * 1200,
    ),
    ids=("scalar", "nested", "duplicate", "unsorted", "recursive"),
)
def test_historical_revision_id_json_is_bounded_canonical_and_typed(
    raw_revision_ids: str,
) -> None:
    with pytest.raises(RuntimeError, match="malformed evidence"):
        guardian_state._validated_revision_ids_json(  # noqa: SLF001
            raw_revision_ids,
            label="Historical assessment completion",
        )


def test_historical_revision_id_json_is_rejected_before_oversized_materialization(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
    with GuardianState(tmp_path / "guardian.sqlite3") as state:
        metadata = _remediation_metadata(state, now=now)
        source = metadata["source_pulls"][0]
        state._connection.execute(  # noqa: SLF001 - corruption fixture
            "DROP TRIGGER historical_pull_completions_no_update"
        )
        state._connection.execute(  # noqa: SLF001 - corruption fixture
            "UPDATE historical_pull_completions "
            "SET event_revision_ids_json = ? "
            "WHERE repository = ? AND pull_id = ?",
            ("[1]" * 1024, source.repository, source.pull_id),
        )
        state._connection.commit()  # noqa: SLF001 - corruption fixture
        monkeypatch.setattr(
            guardian_state,
            "_MAX_PREVENTION_SOURCE_JSON_BYTES",
            8,
        )

        with pytest.raises(RuntimeError, match="malformed evidence"):
            state.validate_historical_remediation_evidence(
                source_pulls=metadata["source_pulls"],
                event_revision_ids=metadata["event_revision_ids"],
            )


def test_merged_revalidation_revision_ids_accept_500_and_reject_501() -> None:
    at_bound = tuple(range(1, 501))

    assert json.loads(
        guardian_state._merged_revalidation_revision_ids_json(at_bound)  # noqa: SLF001
    ) == list(at_bound)
    with pytest.raises(ValueError, match="bounded workset"):
        guardian_state._merged_revalidation_revision_ids_json(  # noqa: SLF001
            (*at_bound, 501)
        )


def test_remediation_evidence_rejects_an_older_edit_on_the_same_pull_snapshot(
    tmp_path: Path,
) -> None:
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
    with GuardianState(tmp_path / "guardian.sqlite3") as state:
        old = state.record_feedback_event(_event(pr_number=12), observed_at=now)
        edited = state.record_feedback_event(
            _event(pr_number=12, body="Edited finding"),
            observed_at=now,
        )
        source = HistoricalPullReference(
            repository="acme/widgets",
            repository_id=42,
            pull_id=500,
            pr_number=12,
            pull_revision_digest="1" * 64,
            authority_digest="4" * 64,
            policy_digest="2" * 64,
            head_sha="a" * 40,
            base_sha="b" * 40,
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
            event_revision_ids=(edited.revision_id,),
            authority_scope=HistoricalCheckScope.ASSESSMENT,
            completed_at=now,
        )

        with pytest.raises(ValueError, match="exact assessed pull snapshot"):
            state.validate_historical_remediation_evidence(
                source_pulls=(source,),
                event_revision_ids=(old.revision_id,),
            )


def test_current_evidence_rejects_a_new_revision_after_assessment(
    tmp_path: Path,
) -> None:
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
    with GuardianState(tmp_path / "guardian.sqlite3") as state:
        metadata = _remediation_metadata(state, now=now)
        exact_hash = state.validate_historical_remediation_evidence(
            source_pulls=metadata["source_pulls"],
            event_revision_ids=metadata["event_revision_ids"],
        )
        state.record_feedback_event(
            _event(pr_number=12, body="later edit"),
            observed_at=now + timedelta(minutes=1),
        )

        assert (
            state.validate_historical_remediation_evidence(
                source_pulls=metadata["source_pulls"],
                event_revision_ids=metadata["event_revision_ids"],
            )
            == exact_hash
        )
        with pytest.raises(ValueError, match="superseded|current"):
            state.validate_current_historical_remediation_evidence(
                source_pulls=metadata["source_pulls"],
                event_revision_ids=metadata["event_revision_ids"],
            )


def test_historical_evidence_recovers_after_identical_feedback_is_restored(
    tmp_path: Path,
) -> None:
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
    visible = _event(pr_number=12)
    source = HistoricalPullReference(
        repository="acme/widgets",
        repository_id=42,
        pull_id=500,
        pr_number=12,
        pull_revision_digest="1" * 64,
        authority_digest="4" * 64,
        policy_digest="2" * 64,
        head_sha="a" * 40,
        base_sha="b" * 40,
    )
    with GuardianState(tmp_path / "guardian.sqlite3") as state:
        first = state.record_feedback_event(visible, observed_at=now)
        assert state.record_historical_pull_completion(
            repository=source.repository,
            repository_id=source.repository_id,
            pull_id=source.pull_id,
            pr_number=source.pr_number,
            pull_revision_digest=source.pull_revision_digest,
            policy_digest=source.policy_digest,
            head_sha=source.head_sha,
            base_sha=source.base_sha,
            event_revision_ids=(first.revision_id,),
            authority_scope=HistoricalCheckScope.ASSESSMENT,
            completed_at=now,
        )
        tombstone = state.record_feedback_event(
            replace(visible, body="", deleted=True),
            observed_at=now + timedelta(minutes=1),
        )
        tombstoned_source = replace(source, pull_revision_digest="3" * 64)
        assert state.record_historical_pull_completion(
            repository=tombstoned_source.repository,
            repository_id=tombstoned_source.repository_id,
            pull_id=tombstoned_source.pull_id,
            pr_number=tombstoned_source.pr_number,
            pull_revision_digest=tombstoned_source.pull_revision_digest,
            policy_digest=tombstoned_source.policy_digest,
            head_sha=tombstoned_source.head_sha,
            base_sha=tombstoned_source.base_sha,
            event_revision_ids=(tombstone.revision_id,),
            authority_scope=HistoricalCheckScope.ASSESSMENT,
            completed_at=now + timedelta(minutes=1),
        )
        with pytest.raises(ValueError, match="superseded|current"):
            state.validate_current_historical_remediation_evidence(
                source_pulls=(source,),
                event_revision_ids=(first.revision_id,),
            )

        restored = state.record_feedback_event(
            visible,
            observed_at=now + timedelta(minutes=2),
        )
        assert restored.revision_id == first.revision_id
        assert not state.record_historical_pull_completion(
            repository=source.repository,
            repository_id=source.repository_id,
            pull_id=source.pull_id,
            pr_number=source.pr_number,
            pull_revision_digest=source.pull_revision_digest,
            policy_digest=source.policy_digest,
            head_sha=source.head_sha,
            base_sha=source.base_sha,
            event_revision_ids=(restored.revision_id,),
            authority_scope=HistoricalCheckScope.ASSESSMENT,
            completed_at=now + timedelta(minutes=2),
        )
        state.validate_current_historical_remediation_evidence(
            source_pulls=(source,),
            event_revision_ids=(first.revision_id,),
        )
        observations = state._connection.execute(  # noqa: SLF001 - ABA invariant
            """
            SELECT completion.pull_revision_digest
            FROM historical_pull_completion_observations AS observation
            JOIN historical_pull_completions AS completion
              ON completion.completion_id = observation.completion_id
            ORDER BY observation.observation_id
            """
        ).fetchall()
        assert [row["pull_revision_digest"] for row in observations] == [
            source.pull_revision_digest,
            tombstoned_source.pull_revision_digest,
            source.pull_revision_digest,
        ]


def test_remediation_evidence_hash_is_independent_of_local_revision_ids(
    tmp_path: Path,
) -> None:
    from localize.guardian.remediation import _branch_name

    hashes: list[str] = []
    branches: list[str] = []
    revision_ids: list[int] = []
    edit_hash = guardian_state.remediation_edit_hash(
        ProposedReplacement(
            feedback_id="review_comment:98765",
            path="l10n/messages_ru.properties",
            key="hello",
            locale="ru",
            expected_value="old",
            proposed_value="new",
            confidence=0.99,
            evidence=("feedback",),
            source_value="Hello",
        )
    )
    batch_hash = guardian_state.remediation_batch_hash((edit_hash,))
    source = HistoricalPullReference(
        repository="acme/widgets",
        repository_id=42,
        pull_id=500,
        pr_number=12,
        pull_revision_digest="1" * 64,
        authority_digest="4" * 64,
        policy_digest="2" * 64,
        head_sha="a" * 40,
        base_sha="b" * 40,
    )
    for index in range(2):
        with GuardianState(tmp_path / f"guardian-{index}.sqlite3") as state:
            if index:
                state.record_feedback_event(
                    _event(repository="other/widgets", pr_number=99)
                )
            revision = state.record_feedback_event(_event(pr_number=12))
            state.record_historical_pull_completion(
                repository=source.repository,
                repository_id=source.repository_id,
                pull_id=source.pull_id,
                pr_number=source.pr_number,
                pull_revision_digest=source.pull_revision_digest,
                policy_digest=source.policy_digest,
                head_sha=source.head_sha,
                base_sha=source.base_sha,
                event_revision_ids=(revision.revision_id,),
                authority_scope=HistoricalCheckScope.ASSESSMENT,
            )
            hashes.append(
                state.validate_historical_remediation_evidence(
                    source_pulls=(source,),
                    event_revision_ids=(revision.revision_id,),
                )
            )
            branches.append(
                _branch_name(
                    prefix="guardian/remediation-",
                    batch_hash=batch_hash,
                    target_base_sha="c" * 40,
                    evidence_hash=hashes[-1],
                )
            )
            revision_ids.append(revision.revision_id)

    assert revision_ids == [1, 2]
    assert hashes[0] == hashes[1]
    assert branches[0] == branches[1]


def test_current_evidence_requires_the_latest_assessment_for_the_policy(
    tmp_path: Path,
) -> None:
    with GuardianState(tmp_path / "guardian.sqlite3") as state:
        revision = state.record_feedback_event(_event(pr_number=12))
        old_source = HistoricalPullReference(
            repository="acme/widgets",
            repository_id=42,
            pull_id=500,
            pr_number=12,
            pull_revision_digest="1" * 64,
            authority_digest="4" * 64,
            policy_digest="2" * 64,
            head_sha="a" * 40,
            base_sha="b" * 40,
        )
        newer_source = replace(old_source, pull_revision_digest="3" * 64)
        for source in (old_source, newer_source):
            state.record_historical_pull_completion(
                repository=source.repository,
                repository_id=source.repository_id,
                pull_id=source.pull_id,
                pr_number=source.pr_number,
                pull_revision_digest=source.pull_revision_digest,
                policy_digest=source.policy_digest,
                head_sha=source.head_sha,
                base_sha=source.base_sha,
                event_revision_ids=(revision.revision_id,),
                authority_scope=HistoricalCheckScope.ASSESSMENT,
            )

        with pytest.raises(ValueError, match="latest assessment"):
            state.validate_current_historical_remediation_evidence(
                source_pulls=(old_source,),
                event_revision_ids=(revision.revision_id,),
            )
        state.validate_current_historical_remediation_evidence(
            source_pulls=(newer_source,),
            event_revision_ids=(revision.revision_id,),
        )


def test_remediation_evidence_binds_stored_urls_and_replacement_feedback_ids(
    tmp_path: Path,
) -> None:
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
    with GuardianState(tmp_path / "guardian.sqlite3") as state:
        metadata = _remediation_metadata(state, now=now)
        with pytest.raises(ValueError, match="stored event URLs"):
            state.validate_historical_remediation_evidence(
                source_pulls=metadata["source_pulls"],
                event_revision_ids=metadata["event_revision_ids"],
                feedback_urls=(
                    "https://github.test/acme/widgets/pull/12#discussion_r1",
                ),
            )
        with pytest.raises(ValueError, match="feedback_id"):
            state.validate_historical_remediation_evidence(
                source_pulls=metadata["source_pulls"],
                event_revision_ids=metadata["event_revision_ids"],
                replacements=(
                    ProposedReplacement(
                        feedback_id="review_comment:missing",
                        path="l10n/messages_ru.properties",
                        key="hello",
                        locale="ru",
                        expected_value="old",
                        proposed_value="new",
                        confidence=0.99,
                        evidence=("feedback",),
                    ),
                ),
            )


def test_remediation_draft_ledger_is_append_only_recoverable_and_typed(
    tmp_path: Path,
) -> None:
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
    with GuardianState(tmp_path / "guardian.sqlite3") as state:
        metadata = _remediation_metadata(state, now=now)
        draft_key = state.record_remediation_draft_event(
            **metadata,
            phase="validated",
        )
        assert (
            state.record_remediation_draft_event(
                **metadata,
                phase="validated",
            )
            == draft_key
        )

        pending = state.pending_remediation_drafts(repository="acme/widgets")
        assert len(pending) == 1
        assert pending[0].draft_key == draft_key
        assert pending[0].phase == "validated"
        assert pending[0].target_repository_id == 42
        assert pending[0].push_repository_id == 84
        assert pending[0].edit_hashes == metadata["edit_hashes"]
        assert pending[0].source_pulls == metadata["source_pulls"]
        assert pending[0].event_revision_ids == metadata["event_revision_ids"]

        state.record_remediation_draft_event(**metadata, phase="pushed")
        assert state.pending_remediation_drafts()[0].phase == "pushed"

        state.record_remediation_draft_event(
            **metadata,
            phase="draft_opened",
            draft_number=91,
            draft_pull_id=9_091,
            draft_url="https://github.test/acme/widgets/pull/91",
        )
        assert state.pending_remediation_drafts() == ()
        opened = state.opened_remediation_drafts(repository="acme/widgets")
        assert len(opened) == 1
        assert opened[0].phase == "draft_opened"
        assert opened[0].draft_number == 91
        assert state.opened_remediation_evidence_hashes(
            repository="acme/widgets"
        ) == frozenset({metadata["evidence_hash"]})

        with pytest.raises(sqlite3.IntegrityError, match="remediation draft events"):
            state._connection.execute(  # noqa: SLF001 - immutability assertion
                "UPDATE remediation_draft_events SET phase = 'abandoned'"
            )
        with pytest.raises(sqlite3.IntegrityError, match="remediation draft events"):
            state._connection.execute(  # noqa: SLF001 - immutability assertion
                "DELETE FROM remediation_draft_events"
            )
        with pytest.raises(sqlite3.IntegrityError, match="remediation draft edits"):
            state._connection.execute(  # noqa: SLF001 - immutability assertion
                "UPDATE remediation_draft_edit_events SET edit_hash = 'bad'"
            )
        with pytest.raises(sqlite3.IntegrityError, match="remediation draft edits"):
            state._connection.execute(  # noqa: SLF001 - immutability assertion
                "DELETE FROM remediation_draft_edit_events"
            )


def test_remediation_recovery_selectors_use_immutable_repository_id(
    tmp_path: Path,
) -> None:
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
    with GuardianState(tmp_path / "guardian.sqlite3") as state:
        current_name_wrong_id = _remediation_metadata(
            state,
            now=now,
            repository="acme/current-name",
            repository_id=99,
        )
        old_name_same_id = _remediation_metadata(
            state,
            now=now,
            repository="acme/old-name",
            repository_id=42,
        )

        def attempt(metadata: dict[str, object], index: int) -> dict[str, object]:
            edit_hashes = (f"{index:064x}",)
            return {
                **metadata,
                "branch": f"guardian/remediation-{index:064x}",
                "candidate_sha": f"{index:040x}",
                "batch_hash": guardian_state.remediation_batch_hash(edit_hashes),
                "edit_hashes": edit_hashes,
                "edit_target_hashes": _remediation_target_mappings(edit_hashes),
            }

        for index in range(1, 102):
            state.record_remediation_draft_event(
                **attempt(current_name_wrong_id, index),
                phase="validated",
            )
        renamed_pending = state.record_remediation_draft_event(
            **attempt(old_name_same_id, 200),
            phase="validated",
        )

        wrong_opened = _open_remediation_draft(
            state,
            attempt(current_name_wrong_id, 300),
            draft_number=91,
        )
        renamed_opened = _open_remediation_draft(
            state,
            attempt(old_name_same_id, 301),
            draft_number=91,
        )

        wrong_merged = _open_remediation_draft(
            state,
            attempt(current_name_wrong_id, 400),
            draft_number=92,
        )
        _record_merged_observation(
            state,
            draft_key=wrong_merged,
            observed_at=now + timedelta(minutes=1),
        )
        renamed_merged = _open_remediation_draft(
            state,
            attempt(old_name_same_id, 401),
            draft_number=92,
        )
        _record_merged_observation(
            state,
            draft_key=renamed_merged,
            observed_at=now + timedelta(minutes=1),
        )

        assert tuple(
            item.draft_key
            for item in state.pending_remediation_drafts_for_recovery(
                repository="acme/current-name",
                repository_id=42,
                limit=1,
            )
        ) == (renamed_pending,)
        assert tuple(
            item.draft_key
            for item in state.opened_remediation_drafts_for_reconciliation(
                repository="acme/current-name",
                repository_id=42,
            )
        ) == (renamed_opened,)
        assert {
            item.draft_key
            for item in state.pending_merged_remediation_revalidations(
                repository="acme/current-name",
                repository_id=42,
            )
        } == {renamed_merged}
        recovered = state.remediation_draft_for_pull(
            repository="acme/current-name",
            repository_id=42,
            pr_number=91,
        )
        assert recovered is not None
        assert recovered.draft_key == renamed_opened
        assert recovered.draft_key != wrong_opened


def test_remediation_recovery_rejects_overdeep_source_metadata(
    tmp_path: Path,
) -> None:
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
    with GuardianState(tmp_path / "guardian.sqlite3") as state:
        metadata = _remediation_metadata(state, now=now)
        draft_key = state.record_remediation_draft_event(
            **metadata,
            phase="validated",
        )
        row = state._connection.execute(  # noqa: SLF001 - corruption fixture
            "SELECT source_pulls_json FROM remediation_draft_events "
            "WHERE draft_key = ?",
            (draft_key,),
        ).fetchone()
        assert row is not None
        source_pulls = json.loads(row["source_pulls_json"])
        source_pulls[0]["unexpected"] = _overdeep_json_value()
        corrupted_source_pulls = json.dumps(
            source_pulls,
            sort_keys=True,
            separators=(",", ":"),
        )
        state._connection.execute(  # noqa: SLF001 - frozen corruption fixture
            "DROP TRIGGER remediation_draft_events_no_update"
        )
        state._connection.execute(  # noqa: SLF001 - frozen corruption fixture
            "UPDATE remediation_draft_events SET source_pulls_json = ? "
            "WHERE draft_key = ?",
            (corrupted_source_pulls, draft_key),
        )
        state._connection.commit()  # noqa: SLF001 - frozen corruption fixture

        with pytest.raises(RuntimeError, match="ledger contains malformed data"):
            state.pending_remediation_drafts(repository="acme/widgets")


@pytest.mark.parametrize(
    ("initial_phase", "resolution"),
    [
        ("validated", "operator_quarantined"),
        ("pushed", "operator_quarantined"),
        ("draft_opened", "operator_quarantined"),
        ("draft_opened", "merged"),
    ],
)
def test_remediation_resolution_is_append_only_and_removes_active_coverage(
    tmp_path: Path,
    initial_phase: str,
    resolution: str,
) -> None:
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
    with GuardianState(tmp_path / "guardian.sqlite3") as state:
        metadata = _remediation_metadata(state, now=now)
        draft_key = state.record_remediation_draft_event(
            **metadata,
            phase="validated",
        )
        if initial_phase in {"pushed", "draft_opened"}:
            state.record_remediation_draft_event(**metadata, phase="pushed")
        if initial_phase == "draft_opened":
            state.record_remediation_draft_event(
                **metadata,
                phase="draft_opened",
                draft_number=91,
                draft_pull_id=9_091,
                draft_url="https://github.test/acme/widgets/pull/91",
            )
            assert [
                item.draft_key
                for item in state.opened_remediation_drafts_for_reconciliation()
            ] == [draft_key]

        if resolution == "merged":
            observation = state.record_remediation_remote_observation(
                draft_key=draft_key,
                observation="exact",
                state="closed",
                is_draft=False,
                is_merged=True,
                pr_number=91,
                pr_url="https://github.test/acme/widgets/pull/91",
                observed_base_sha="f" * 40,
                observed_head_sha=state.remediation_candidate_tip(draft_key),
                closed_at="2026-08-30T12:01:00Z",
                merged_at="2026-08-30T12:01:00Z",
                observed_at=now + timedelta(minutes=1),
            )
            assert observation.is_merged is True
            with pytest.raises(ValueError, match="exact atomic remote observation"):
                state.record_remediation_resolution(
                    draft_key=draft_key,
                    resolution=resolution,
                )
        else:
            assert state.record_remediation_resolution(
                draft_key=draft_key,
                resolution=resolution,
                terminal_local_skip_acknowledged=True,
                occurred_at=now + timedelta(minutes=1),
            )
            assert not state.record_remediation_resolution(
                draft_key=draft_key,
                resolution=resolution,
                terminal_local_skip_acknowledged=True,
                occurred_at=now + timedelta(minutes=2),
            )
        assert state.remediation_resolution(draft_key=draft_key) == resolution
        assert state.remediation_draft_by_key(draft_key=draft_key) is not None
        assert state.pending_remediation_drafts() == ()
        assert state.opened_remediation_drafts() == ()
        assert state.opened_remediation_drafts_for_reconciliation() == ()
        assert (
            state.active_remediation_drafts_for_identity(
                repository="acme/widgets",
                repository_id=42,
                batch_hash=metadata["batch_hash"],
            )
            == ()
        )
        coverage = state.remediation_edit_coverage(
            target_repository="acme/widgets",
            target_repository_id=42,
            edit_target_hashes=metadata["edit_target_hashes"],
        )
        assert not coverage.opened_edit_hashes
        assert not coverage.pending_edit_hashes
        assert not coverage.conflicting_edit_hashes

        with pytest.raises(sqlite3.IntegrityError, match="remediation resolutions"):
            state._connection.execute(  # noqa: SLF001 - immutability assertion
                "DELETE FROM remediation_resolution_events"
            )


def test_only_opened_remediation_can_be_resolved_as_merged(tmp_path: Path) -> None:
    with GuardianState(tmp_path / "guardian.sqlite3") as state:
        metadata = _remediation_metadata(
            state,
            now=datetime(2026, 8, 30, 12, 0, tzinfo=UTC),
        )
        draft_key = state.record_remediation_draft_event(
            **metadata,
            phase="validated",
        )

        with pytest.raises(ValueError, match="opened remediation"):
            state.record_remediation_remote_observation(
                draft_key=draft_key,
                observation="exact",
                state="closed",
                is_draft=False,
                is_merged=True,
                pr_number=91,
                pr_url="https://github.test/acme/widgets/pull/91",
                observed_base_sha="f" * 40,
                observed_head_sha=metadata["candidate_sha"],
                closed_at="2026-08-30T12:01:00Z",
                merged_at="2026-08-30T12:01:00Z",
            )


def test_remediation_operator_quarantine_requires_ack_and_monotonic_timestamp(
    tmp_path: Path,
) -> None:
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
    with GuardianState(tmp_path / "guardian.sqlite3") as state:
        metadata = _remediation_metadata(state, now=now)
        draft_key = state.record_remediation_draft_event(
            **metadata,
            phase="validated",
        )

        with pytest.raises(ValueError, match="explicitly true"):
            state.record_remediation_resolution(
                draft_key=draft_key,
                resolution="operator_quarantined",
            )
        with pytest.raises(ValueError, match="must not precede"):
            state.record_remediation_resolution(
                draft_key=draft_key,
                resolution="operator_quarantined",
                terminal_local_skip_acknowledged=True,
                occurred_at=now - timedelta(microseconds=1),
            )

        state.record_remediation_remote_observation(
            draft_key=draft_key,
            observation="not_found",
            observed_at=now + timedelta(minutes=1),
        )
        with pytest.raises(ValueError, match="latest remote observation"):
            state.record_remediation_resolution(
                draft_key=draft_key,
                resolution="operator_quarantined",
                terminal_local_skip_acknowledged=True,
                occurred_at=now,
            )
        with pytest.raises(sqlite3.IntegrityError, match="monotonic"):
            state._connection.execute(  # noqa: SLF001 - DB invariant assertion
                """
                INSERT INTO remediation_resolution_events (
                    draft_key, resolution, occurred_at
                ) VALUES (?, 'operator_quarantined', ?)
                """,
                (draft_key, "2026-08-30T12:00:00.000000Z"),
            )

        assert state.record_remediation_resolution(
            draft_key=draft_key,
            resolution="operator_quarantined",
            terminal_local_skip_acknowledged=True,
            occurred_at=now + timedelta(minutes=1),
        )


def test_remediation_edit_coverage_separates_phase_and_repository_identity(
    tmp_path: Path,
) -> None:
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
    opened_hash = "1" * 64
    pending_hash = "2" * 64
    name_collision_hash = "3" * 64
    id_collision_hash = "4" * 64
    with GuardianState(tmp_path / "guardian.sqlite3") as state:
        opened = _remediation_metadata(
            state,
            now=now,
            edit_hashes=(opened_hash,),
        )
        state.record_remediation_draft_event(**opened, phase="validated")
        state.record_remediation_draft_event(**opened, phase="pushed")
        state.record_remediation_draft_event(
            **opened,
            phase="draft_opened",
            draft_number=91,
            draft_pull_id=9_091,
            draft_url="https://github.test/acme/widgets/pull/91",
        )
        pending = _remediation_metadata(
            state,
            now=now + timedelta(minutes=1),
            edit_hashes=(pending_hash,),
        )
        state.record_remediation_draft_event(**pending, phase="validated")
        same_name_wrong_id = _remediation_metadata(
            state,
            now=now + timedelta(minutes=2),
            repository_id=43,
            edit_hashes=(name_collision_hash,),
        )
        state.record_remediation_draft_event(
            **same_name_wrong_id,
            phase="validated",
        )
        same_id_wrong_name = _remediation_metadata(
            state,
            now=now + timedelta(minutes=3),
            repository="renamed/widgets",
            edit_hashes=(id_collision_hash,),
        )
        state.record_remediation_draft_event(
            **same_id_wrong_name,
            phase="validated",
        )

        coverage = state.remediation_edit_coverage(
            target_repository="acme/widgets",
            target_repository_id=42,
            edit_target_hashes=(
                *opened["edit_target_hashes"],
                *pending["edit_target_hashes"],
                *same_name_wrong_id["edit_target_hashes"],
                *same_id_wrong_name["edit_target_hashes"],
                ("5" * 64, "6" * 64),
            ),
        )

        assert coverage.opened_edit_hashes == frozenset({opened_hash})
        assert coverage.pending_edit_hashes == frozenset({pending_hash})
        assert coverage.incompatible_edit_hashes == frozenset(
            {name_collision_hash, id_collision_hash}
        )
        assert coverage.conflicting_edit_hashes == frozenset()
        assert coverage.repository_identity_conflict is True
        assert (
            state.active_remediation_drafts_for_identity(
                repository="acme/widgets",
                repository_id=42,
                batch_hash=opened["batch_hash"],
            )[0].phase
            == "draft_opened"
        )

        conflicting_hash = "7" * 64
        conflict = state.remediation_edit_coverage(
            target_repository="acme/widgets",
            target_repository_id=42,
            edit_target_hashes=(
                (conflicting_hash, opened["edit_target_hashes"][0][1]),
            ),
        )
        assert conflict.opened_edit_hashes == frozenset()
        assert conflict.pending_edit_hashes == frozenset()
        assert conflict.conflicting_edit_hashes == frozenset({conflicting_hash})


def test_uncheckpointed_opened_remediation_query_does_not_starve_new_work(
    tmp_path: Path,
) -> None:
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
    with GuardianState(tmp_path / "guardian.sqlite3") as state:
        metadata = _remediation_metadata(state, now=now)
        draft_keys: list[str] = []
        for index in range(101):
            edit_hashes = (f"{index + 1:064x}",)
            attempt = {
                **metadata,
                "branch": f"guardian/remediation-{index:064x}",
                "candidate_sha": f"{index + 1:040x}",
                "batch_hash": guardian_state.remediation_batch_hash(edit_hashes),
                "edit_hashes": edit_hashes,
                "edit_target_hashes": _remediation_target_mappings(edit_hashes),
            }
            draft_key = state.record_remediation_draft_event(
                **attempt,
                phase="validated",
            )
            state.record_remediation_draft_event(**attempt, phase="pushed")
            state.record_remediation_draft_event(
                **attempt,
                phase="draft_opened",
                draft_number=index + 1,
                draft_pull_id=10_000 + index,
                draft_url=f"https://github.test/acme/widgets/pull/{index + 1}",
            )
            draft_keys.append(draft_key)
        for draft_key in draft_keys[:100]:
            assert (
                state.record_remediation_checkpoint(
                    draft_key=draft_key,
                    occurred_at=now,
                )
                is True
            )

        uncheckpointed = state.uncheckpointed_opened_remediation_drafts(
            repository="acme/widgets",
            limit=100,
        )
        assert tuple(record.draft_key for record in uncheckpointed) == (draft_keys[-1],)
        assert (
            state.record_remediation_checkpoint(
                draft_key=draft_keys[0],
                occurred_at=now,
            )
            is False
        )

        pending_keys: list[str] = []
        for index in range(101):
            edit_hashes = (f"{index + 201:064x}",)
            attempt = {
                **metadata,
                "branch": f"guardian/pending-{index:064x}",
                "candidate_sha": f"{index + 201:040x}",
                "batch_hash": guardian_state.remediation_batch_hash(edit_hashes),
                "edit_hashes": edit_hashes,
                "edit_target_hashes": _remediation_target_mappings(edit_hashes),
            }
            pending_keys.append(
                state.record_remediation_draft_event(
                    **attempt,
                    phase="validated",
                )
            )
        first_workset = state.pending_remediation_drafts_for_recovery(limit=100)
        for record in first_workset:
            state.record_remediation_recovery_attempt(
                draft_key=record.draft_key,
                occurred_at=now,
            )

        rotated = state.pending_remediation_drafts_for_recovery(limit=100)
        assert rotated[0].draft_key == pending_keys[-1]


def test_remediation_draft_abandonment_is_terminal_but_not_opened(
    tmp_path: Path,
) -> None:
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
    with GuardianState(tmp_path / "guardian.sqlite3") as state:
        metadata = _remediation_metadata(state, now=now)
        state.record_remediation_draft_event(**metadata, phase="validated")
        state.record_remediation_draft_event(**metadata, phase="abandoned")

        assert state.pending_remediation_drafts() == ()
        assert state.opened_remediation_drafts() == ()
        terminal = state.terminal_remediation_drafts(repository="acme/widgets")
        assert len(terminal) == 1
        assert terminal[0].phase == "abandoned"


def test_abandoned_orphan_can_be_retried_in_a_new_run_with_same_evidence(
    tmp_path: Path,
) -> None:
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
    with GuardianState(tmp_path / "guardian.sqlite3") as state:
        metadata = _remediation_metadata(state, now=now)
        first_key = state.record_remediation_draft_event(
            **metadata,
            phase="validated",
        )
        state.record_remediation_draft_event(
            **metadata,
            phase="abandoned",
        )
        retry_run_id = state.start_run(
            repository="acme/widgets",
            locale="ru",
            mode=GuardianMode.PROPOSE_PREVENTION,
            started_at=now + timedelta(minutes=1),
        )

        retry_key = state.record_remediation_draft_event(
            **{
                **metadata,
                "run_id": retry_run_id,
                "occurred_at": now + timedelta(minutes=1),
            },
            phase="validated",
        )

        assert retry_key != first_key
        assert [record.draft_key for record in state.pending_remediation_drafts()] == [
            retry_key
        ]


def test_remediation_draft_rejects_invalid_transitions_and_collisions(
    tmp_path: Path,
) -> None:
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
    with GuardianState(tmp_path / "guardian.sqlite3") as state:
        metadata = _remediation_metadata(state, now=now)
        with pytest.raises(ValueError, match="transition"):
            state.record_remediation_draft_event(**metadata, phase="pushed")

        state.record_remediation_draft_event(**metadata, phase="validated")
        with pytest.raises(ValueError, match="opened remediation draft"):
            state.record_remediation_draft_event(
                **metadata,
                phase="draft_opened",
            )
        with pytest.raises(ValueError, match="transition"):
            state.record_remediation_draft_event(
                **metadata,
                phase="draft_opened",
                draft_number=91,
                draft_pull_id=9_091,
                draft_url="https://github.test/acme/widgets/pull/91",
            )
        with pytest.raises(ValueError, match="metadata"):
            state.record_remediation_draft_event(
                **{**metadata, "title": "Different title"},
                phase="validated",
            )


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"target_repository_id": 0}, "target_repository_id"),
        ({"push_repository_id": 0}, "push_repository_id"),
        ({"target_base_sha": "a" * 39}, "SHAs"),
        ({"evidence_hash": "D" * 64}, "evidence_hash"),
        ({"batch_hash": "e" * 63}, "batch_hash"),
        ({"event_revision_ids": ()}, "event_revision_ids"),
        ({"source_pulls": ()}, "source_pulls"),
        (
            {"push_repository": "acme/widgets", "push_repository_id": 84},
            "ambiguous repository identity",
        ),
    ],
)
def test_remediation_draft_rejects_invalid_authority_metadata(
    tmp_path: Path,
    overrides: dict[str, object],
    message: str,
) -> None:
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
    with GuardianState(tmp_path / "guardian.sqlite3") as state:
        metadata = _remediation_metadata(state, now=now)
        with pytest.raises(ValueError, match=message):
            state.record_remediation_draft_event(
                **{**metadata, **overrides},
                phase="validated",
            )


def test_remediation_draft_paths_are_bounded_and_canonicalized(
    tmp_path: Path,
) -> None:
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
    with GuardianState(tmp_path / "guardian.sqlite3") as state:
        metadata = _remediation_metadata(state, now=now)
        paths = tuple(
            reversed(tuple(f"l10n/messages_{index}.properties" for index in range(100)))
        )
        draft_key = state.record_remediation_draft_event(
            **{**metadata, "changed_paths": paths},
            phase="validated",
        )

        stored = state.remediation_draft_by_key(draft_key=draft_key)
        assert stored is not None
        assert stored.changed_paths == tuple(sorted(paths))

        for invalid in (
            (*paths, "l10n/too-many.properties"),
            ("x" * 4097,),
            ("../outside.properties",),
            ([],),
        ):
            with pytest.raises(ValueError, match="changed_paths"):
                state.record_remediation_draft_event(
                    **{**metadata, "changed_paths": invalid},
                    phase="validated",
                )


@pytest.mark.parametrize(
    "changed_paths_json",
    (
        "{not-json",
        json.dumps(
            [f"l10n/messages_{index}.properties" for index in range(101)],
            separators=(",", ":"),
        ),
        '["../outside.properties"]',
        '["l10n/messages_ru.properties","l10n/messages_ru.properties"]',
    ),
    ids=("invalid-json", "too-many", "unsafe", "duplicate"),
)
def test_remediation_draft_path_database_bounds_fail_closed(
    tmp_path: Path,
    changed_paths_json: str,
) -> None:
    with GuardianState(tmp_path / "guardian.sqlite3") as state:
        with pytest.raises(sqlite3.DatabaseError):
            state._connection.execute(  # noqa: SLF001 - DB invariant assertion
                "INSERT INTO remediation_draft_path_attestations "
                "(draft_key, changed_paths_json) VALUES (?, ?)",
                ("d" * 64, changed_paths_json),
            )


def test_remediation_draft_parser_rejects_corrupted_path_attestation(
    tmp_path: Path,
) -> None:
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
    with GuardianState(tmp_path / "guardian.sqlite3") as state:
        metadata = _remediation_metadata(state, now=now)
        draft_key = state.record_remediation_draft_event(
            **metadata,
            phase="validated",
        )
        state._connection.execute(  # noqa: SLF001 - frozen corruption fixture
            "DROP TRIGGER remediation_draft_paths_no_update"
        )
        state._connection.execute(  # noqa: SLF001 - frozen corruption fixture
            "UPDATE remediation_draft_path_attestations "
            "SET changed_paths_json = ? WHERE draft_key = ?",
            ('["../outside.properties"]', draft_key),
        )

        with pytest.raises(RuntimeError, match="malformed data"):
            state.remediation_draft_by_key(draft_key=draft_key)


def test_remediation_draft_binds_event_revisions_to_source_pulls(
    tmp_path: Path,
) -> None:
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
    with GuardianState(tmp_path / "guardian.sqlite3") as state:
        metadata = _remediation_metadata(state, now=now)
        wrong_source = HistoricalPullReference(
            repository="acme/widgets",
            repository_id=42,
            pull_id=999,
            pr_number=99,
            pull_revision_digest="4" * 64,
            authority_digest="5" * 64,
            policy_digest="2" * 64,
            head_sha="a" * 40,
            base_sha="b" * 40,
        )
        with pytest.raises(ValueError, match="source pull"):
            state.record_remediation_draft_event(
                **{**metadata, "source_pulls": (wrong_source,)},
                phase="validated",
            )


@pytest.mark.parametrize("collision", ["pull_id", "pr_number", "policy_digest"])
def test_remediation_draft_rejects_ambiguous_historical_pull_identities(
    tmp_path: Path,
    collision: str,
) -> None:
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
    with GuardianState(tmp_path / "guardian.sqlite3") as state:
        metadata = _remediation_metadata(state, now=now)
        first, second = metadata["source_pulls"]
        if collision == "pull_id":
            second = replace(second, pull_id=first.pull_id)
            revision_ids = metadata["event_revision_ids"]
        elif collision == "pr_number":
            second = replace(second, pr_number=first.pr_number)
            revision_ids = (metadata["event_revision_ids"][0],)
        else:
            second = replace(second, policy_digest="9" * 64)
            revision_ids = metadata["event_revision_ids"]

        with pytest.raises(ValueError, match="source_pulls"):
            state.record_remediation_draft_event(
                **{
                    **metadata,
                    "source_pulls": (first, second),
                    "event_revision_ids": revision_ids,
                },
                phase="validated",
            )


def test_state_migrates_v1_database_to_remediation_ledger(tmp_path: Path) -> None:
    """Upgrade released v1 history without granting unattested remediation authority."""
    database = tmp_path / "guardian.sqlite3"
    _create_exact_v1_database(database)

    with GuardianState(database) as state:
        metadata = _remediation_metadata(
            state,
            now=datetime(2026, 8, 30, 12, 0, tzinfo=UTC),
        )
        state.record_remediation_draft_event(**metadata, phase="validated")
        assert len(state.pending_remediation_drafts()) == 1

    with sqlite3.connect(database) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 11


def test_state_migrates_successor_publication_actor_columns_fail_closed(
    tmp_path: Path,
) -> None:
    database = tmp_path / "guardian.sqlite3"
    with GuardianState(database):
        pass

    with sqlite3.connect(database) as connection:
        for trigger in (
            "remediation_successors_require_intent",
            "remediation_successor_intents_prepared",
            "remediation_successor_intent_actor_safe",
            "remediation_successor_actor_safe",
        ):
            connection.execute(f"DROP TRIGGER {trigger}")  # noqa: S608
        for table in (
            "remediation_successor_intents",
            "remediation_successor_publications",
        ):
            connection.execute(  # noqa: S608
                f"ALTER TABLE {table} DROP COLUMN publication_actor_type"
            )
            connection.execute(  # noqa: S608
                f"ALTER TABLE {table} DROP COLUMN publication_actor_id"
            )

    with GuardianState(database) as state:
        for table in (
            "remediation_successor_intents",
            "remediation_successor_publications",
        ):
            columns = {
                row["name"]
                for row in state._connection.execute(  # noqa: SLF001, S608
                    f"PRAGMA table_info({table})"
                )
            }
            assert {"publication_actor_id", "publication_actor_type"} <= columns
        with pytest.raises(
            sqlite3.IntegrityError,
            match="successor intent publication actor is unsafe",
        ):
            state._connection.execute(  # noqa: SLF001
                """
                INSERT INTO remediation_successor_intents (
                    intent_key, draft_key, publication_key, run_id,
                    parent_candidate_sha, successor_candidate_sha,
                    source_pulls_json, edit_hashes_json, changed_paths_json,
                    actor_id, actor_type, occurred_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    "1" * 64,
                    "2" * 64,
                    "3" * 64,
                    "run",
                    "4" * 40,
                    "5" * 40,
                    "[]",
                    "[]",
                    '["l10n/messages_ru.properties"]',
                    1,
                    "Bot",
                    "2026-08-30T12:03:00.000000Z",
                ),
            )


def test_draft_backed_remediation_coverage_survives_successive_aba_attempts(
    tmp_path: Path,
) -> None:
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
    with GuardianState(tmp_path / "guardian.sqlite3") as state:
        first_metadata = _remediation_metadata(state, now=now)
        sources = tuple(first_metadata["source_pulls"])
        first_key = _open_remediation_draft(state, first_metadata, draft_number=91)
        first_groups = _record_draft_backed_remediation_completions(
            state,
            {source: (first_key,) for source in sources},
            RemediationCoverageReason.DRAFT_PUBLISHED,
            checkpoint_draft_key=first_key,
            occurred_at=now,
        )
        assert {group.source for group in first_groups} == set(sources)
        assert all(group.effective for group in first_groups)
        assert all(group.member_count == 1 for group in first_groups)
        assert all(len(group.canonical_hash) == 64 for group in first_groups)

        _record_merged_observation(
            state,
            draft_key=first_key,
            observed_at=now + timedelta(minutes=1),
        )
        assert all(
            not state.historical_pull_is_complete(
                **_source_lookup(source),
                authority_scope=HistoricalCheckScope.REMEDIATION,
            )
            for source in sources
        )

        second_metadata = _remediation_metadata(
            state,
            now=now + timedelta(minutes=2),
            edit_hashes=("f" * 64,),
        )
        second_metadata["branch"] = "guardian/remediation-" + "c" * 64
        second_key = _open_remediation_draft(
            state,
            second_metadata,
            draft_number=92,
        )
        state.record_remediation_remote_observation(
            draft_key=second_key,
            observation="exact",
            state="open",
            is_draft=True,
            is_merged=False,
            pr_number=92,
            pr_url="https://github.test/acme/widgets/pull/92",
            observed_base_sha="e" * 40,
            observed_head_sha=state.remediation_candidate_tip(second_key),
            observed_at=now + timedelta(minutes=2),
        )
        _record_draft_backed_remediation_completions(
            state,
            {source: (second_key,) for source in sources},
            RemediationCoverageReason.DRAFT_RECOVERED,
            occurred_at=now + timedelta(minutes=2),
        )
        assert all(
            state.historical_pull_is_complete(
                **_source_lookup(source),
                authority_scope=HistoricalCheckScope.REMEDIATION,
            )
            for source in sources
        )

        _record_merged_observation(
            state,
            draft_key=second_key,
            observed_at=now + timedelta(minutes=3),
        )
        assert all(
            not state.historical_pull_is_complete(
                **_source_lookup(source),
                authority_scope=HistoricalCheckScope.REMEDIATION,
            )
            for source in sources
        )

        third_metadata = _remediation_metadata(
            state,
            now=now + timedelta(minutes=4),
            edit_hashes=("1" * 64,),
        )
        third_metadata["branch"] = "guardian/remediation-" + "d" * 64
        third_key = _open_remediation_draft(
            state,
            third_metadata,
            draft_number=93,
        )
        _record_draft_backed_remediation_completions(
            state,
            {source: (third_key,) for source in sources},
            RemediationCoverageReason.DRAFT_PUBLISHED,
            occurred_at=now + timedelta(minutes=4),
        )

        assert all(
            state.historical_pull_is_complete(
                **_source_lookup(source),
                authority_scope=HistoricalCheckScope.REMEDIATION,
            )
            for source in sources
        )
        first_coverage = state.remediation_source_coverage_for_draft(first_key)
        assert first_coverage and all(not group.effective for group in first_coverage)
        third_coverage = state.remediation_source_coverage_for_draft(third_key)
        assert third_coverage and all(group.effective for group in third_coverage)


def test_independent_coverage_remains_effective_after_covered_draft_merges(
    tmp_path: Path,
) -> None:
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
    with GuardianState(tmp_path / "guardian.sqlite3") as state:
        metadata = _remediation_metadata(state, now=now)
        source = tuple(metadata["source_pulls"])[0]
        draft_key = _open_remediation_draft(state, metadata)
        _record_draft_backed_remediation_completions(
            state,
            {source: (draft_key,)},
            RemediationCoverageReason.DRAFT_PUBLISHED,
            occurred_at=now,
        )
        _record_merged_observation(
            state,
            draft_key=draft_key,
            observed_at=now + timedelta(minutes=1),
        )
        assert not state.historical_pull_is_complete(
            **_source_lookup(source),
            authority_scope=HistoricalCheckScope.REMEDIATION,
        )

        group = state.record_independent_remediation_completion(
            source,
            RemediationCoverageReason.INDEPENDENT_ALREADY_CURRENT,
            event_revision_ids=_source_revision_ids(state, metadata, source),
            occurred_at=now + timedelta(minutes=2),
        )

        assert group.kind == "independent"
        assert group.draft_keys == ()
        assert group.effective is True
        assert state.historical_pull_is_complete(
            **_source_lookup(source),
            authority_scope=HistoricalCheckScope.REMEDIATION,
        )


def test_signed_successor_lineage_is_linear_and_authorizes_only_its_tip(
    tmp_path: Path,
) -> None:
    database = tmp_path / "guardian.sqlite3"
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
    with GuardianState(database) as state:
        metadata = _remediation_metadata(state, now=now)
        metadata["changed_paths"] = (
            "l10n/messages_ru.properties",
            "l10n/other_ru.properties",
        )
        sources = tuple(metadata["source_pulls"])
        draft_key = _open_remediation_draft(state, metadata, draft_number=91)
        first_feedback = state.record_feedback_event(
            _event(
                repository="acme/widgets",
                pr_number=91,
                event_id="70001",
                head_sha=metadata["candidate_sha"],
                base_sha=metadata["target_base_sha"],
            ),
            observed_at=now + timedelta(minutes=1),
        )
        first_publication_metadata = {
            "run_id": metadata["run_id"],
            "repository": "acme/widgets",
            "pr_number": 91,
            "original_head_sha": metadata["candidate_sha"],
            "base_sha": metadata["target_base_sha"],
            "commit_sha": "d" * 40,
            "event_revision_ids": (first_feedback.revision_id,),
            "open_source": OpenPullAuthorityReference(
                repository="acme/widgets",
                repository_id=42,
                pull_id=901,
                pr_number=91,
                authority_digest="f" * 64,
                head_sha=metadata["candidate_sha"],
                base_sha=metadata["target_base_sha"],
                feedback_digest="6" * 64,
            ),
            "draft_key": draft_key,
            "source_pulls": sources,
            "edit_hashes": ("8" * 64,),
            "changed_paths": ("l10n/messages_ru.properties",),
            "actor_id": 202,
            "actor_type": "Bot",
            "publication_actor_id": 303,
            "publication_actor_type": "Bot",
        }
        first_intent = state.record_remediation_successor_publication_event(
            **first_publication_metadata,
            phase="prepared",
            completion_actions=(
                (first_feedback.revision_id, "completed", {"outcome": "applied"}),
            ),
            occurred_at=now + timedelta(minutes=2),
        )
        assert (
            first_intent.publication_key
            == state.pending_publications()[0].publication_key
        )

        fork_feedback = state.record_feedback_event(
            _event(
                repository="acme/widgets",
                pr_number=91,
                event_id="70002",
                head_sha=metadata["candidate_sha"],
                base_sha=metadata["target_base_sha"],
            ),
            observed_at=now + timedelta(minutes=3),
        )
        fork_publication_metadata = {
            **first_publication_metadata,
            "commit_sha": "e" * 40,
            "event_revision_ids": (fork_feedback.revision_id,),
            "edit_hashes": ("9" * 64,),
        }
        fork_intent = state.record_remediation_successor_publication_event(
            **fork_publication_metadata,
            phase="prepared",
            completion_actions=(
                (fork_feedback.revision_id, "completed", {"outcome": "applied"}),
            ),
            occurred_at=now + timedelta(minutes=4),
        )
        first_successor = state.record_remediation_successor_publication_event(
            **first_publication_metadata,
            phase="published",
            occurred_at=now + timedelta(minutes=5),
        )
        assert first_successor.lineage_key == first_intent.intent_key
        assert first_successor.parent_candidate_sha == metadata["candidate_sha"]
        assert first_successor.changed_paths == ("l10n/messages_ru.properties",)
        assert state.remediation_candidate_tip(draft_key) == "d" * 40

        with pytest.raises(ValueError, match="prepared intent"):
            state.record_remediation_successor_publication_event(
                **{
                    **first_publication_metadata,
                    "changed_paths": ("l10n/other_ru.properties",),
                },
                phase="published",
                occurred_at=now + timedelta(minutes=5),
            )

        with pytest.raises(ValueError, match="phase metadata"):
            state.record_remediation_successor_publication_event(
                **{
                    **first_publication_metadata,
                    "publication_actor_id": 304,
                },
                phase="published",
                occurred_at=now + timedelta(minutes=5),
            )

        with pytest.raises(ValueError, match="exact next remediation head"):
            state.record_remediation_successor_publication_event(
                **fork_publication_metadata,
                phase="published",
                occurred_at=now + timedelta(minutes=6),
            )
        pending_by_key = {
            publication.publication_key: publication
            for publication in state.pending_publications()
        }
        assert pending_by_key[fork_intent.publication_key].phase == "prepared"
        assert (
            state.record_remediation_successor_publication_event(
                **first_publication_metadata,
                phase="published",
                occurred_at=now + timedelta(minutes=7),
            )
            == first_successor
        )

        with pytest.raises(ValueError, match="opened remediation draft"):
            state.record_remediation_remote_observation(
                draft_key=draft_key,
                observation="exact",
                state="open",
                is_draft=True,
                is_merged=False,
                pr_number=91,
                pr_url="https://github.test/acme/widgets/pull/91",
                observed_base_sha=metadata["target_base_sha"],
                observed_head_sha=metadata["candidate_sha"],
                observed_at=now + timedelta(minutes=8),
            )

    with GuardianState(database) as state:
        assert state.remediation_candidate_tip(draft_key) == "d" * 40
        assert (
            state.remediation_successor_intent(
                publication_key=first_intent.publication_key
            )
            == first_intent
        )
        observation = state.record_remediation_remote_observation(
            draft_key=draft_key,
            observation="exact",
            state="open",
            is_draft=True,
            is_merged=False,
            pr_number=91,
            pr_url="https://github.test/acme/widgets/pull/91",
            observed_base_sha=metadata["target_base_sha"],
            observed_head_sha="d" * 40,
            observed_at=now + timedelta(minutes=9),
        )
        assert observation.observed_head_sha == "d" * 40


def test_successor_publish_without_durable_intent_rolls_back_phase(
    tmp_path: Path,
) -> None:
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
    with GuardianState(tmp_path / "guardian.sqlite3") as state:
        metadata = _remediation_metadata(state, now=now)
        sources = tuple(metadata["source_pulls"])
        draft_key = _open_remediation_draft(state, metadata, draft_number=91)
        feedback = state.record_feedback_event(
            _event(
                repository="acme/widgets",
                pr_number=91,
                event_id="70001",
                head_sha=metadata["candidate_sha"],
                base_sha=metadata["target_base_sha"],
            ),
            observed_at=now + timedelta(minutes=1),
        )
        publication_metadata = {
            "run_id": metadata["run_id"],
            "repository": "acme/widgets",
            "pr_number": 91,
            "original_head_sha": metadata["candidate_sha"],
            "base_sha": metadata["target_base_sha"],
            "commit_sha": "d" * 40,
            "event_revision_ids": (feedback.revision_id,),
            "open_source": OpenPullAuthorityReference(
                repository="acme/widgets",
                repository_id=42,
                pull_id=901,
                pr_number=91,
                authority_digest="f" * 64,
                head_sha=metadata["candidate_sha"],
                base_sha=metadata["target_base_sha"],
                feedback_digest="6" * 64,
            ),
        }
        publication_key = state.record_publication_event(
            **publication_metadata,
            publication_actor_id=303,
            publication_actor_type="Bot",
            phase="prepared",
            completion_actions=(
                (feedback.revision_id, "completed", {"outcome": "applied"}),
            ),
            occurred_at=now + timedelta(minutes=2),
        )

        with pytest.raises(ValueError, match="durable prepared intent"):
            state.record_remediation_successor_publication_event(
                **publication_metadata,
                phase="published",
                draft_key=draft_key,
                source_pulls=sources,
                edit_hashes=("8" * 64,),
                changed_paths=("l10n/messages_ru.properties",),
                actor_id=202,
                actor_type="Bot",
                publication_actor_id=303,
                publication_actor_type="Bot",
                occurred_at=now + timedelta(minutes=3),
            )

        pending = state.pending_publications(repository="acme/widgets")
        assert len(pending) == 1
        assert pending[0].publication_key == publication_key
        assert pending[0].phase == "prepared"
        assert (
            state.remediation_successor_intent(publication_key=publication_key) is None
        )
        assert state.remediation_successor_publications(draft_key=draft_key) == ()


@pytest.mark.parametrize(
    "missing_authority",
    ("changed_paths", "publication_actor"),
)
def test_legacy_successor_intent_never_infers_missing_authority(
    tmp_path: Path,
    missing_authority: str,
) -> None:
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
    with GuardianState(tmp_path / "guardian.sqlite3") as state:
        metadata = _remediation_metadata(state, now=now)
        draft_key = _open_remediation_draft(state, metadata, draft_number=91)
        feedback = state.record_feedback_event(
            _event(
                repository="acme/widgets",
                pr_number=91,
                event_id="legacy-successor-paths",
                head_sha=metadata["candidate_sha"],
                base_sha=metadata["target_base_sha"],
            ),
            observed_at=now + timedelta(minutes=1),
        )
        publication_key = state.record_publication_event(
            run_id=str(metadata["run_id"]),
            repository="acme/widgets",
            pr_number=91,
            original_head_sha=str(metadata["candidate_sha"]),
            base_sha=str(metadata["target_base_sha"]),
            commit_sha="d" * 40,
            publication_actor_id=303,
            publication_actor_type="Bot",
            event_revision_ids=(feedback.revision_id,),
            open_source=OpenPullAuthorityReference(
                repository="acme/widgets",
                repository_id=42,
                pull_id=901,
                pr_number=91,
                authority_digest="f" * 64,
                head_sha=str(metadata["candidate_sha"]),
                base_sha=str(metadata["target_base_sha"]),
                feedback_digest="6" * 64,
            ),
            phase="prepared",
            completion_actions=(
                (feedback.revision_id, "completed", {"outcome": "applied"}),
            ),
            occurred_at=now + timedelta(minutes=2),
        )
        source_pulls_json = state._connection.execute(  # noqa: SLF001
            "SELECT source_pulls_json FROM remediation_draft_events "
            "WHERE draft_key = ? LIMIT 1",
            (draft_key,),
        ).fetchone()[0]

        # Simulate rows created before each authority field was persisted and
        # then migrated with NULL. Current insert triggers reject those legacy
        # shapes, so bypass them only to construct frozen migration fixtures.
        # Recovery must not infer paths from the draft or an actor from policy.
        state._connection.execute(  # noqa: SLF001
            "DROP TRIGGER remediation_successor_intent_paths_safe"
        )
        state._connection.execute(  # noqa: SLF001
            "DROP TRIGGER remediation_successor_intent_actor_safe"
        )
        state._connection.execute(  # noqa: SLF001
            "DROP TRIGGER remediation_successor_intents_prepared"
        )
        state._connection.execute(  # noqa: SLF001
            """
            INSERT INTO remediation_successor_intents (
                intent_key, draft_key, publication_key, run_id,
                parent_candidate_sha, successor_candidate_sha,
                source_pulls_json, edit_hashes_json, changed_paths_json,
                actor_id, actor_type, publication_actor_id,
                publication_actor_type, occurred_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "7" * 64,
                draft_key,
                publication_key,
                metadata["run_id"],
                metadata["candidate_sha"],
                "d" * 40,
                source_pulls_json,
                json.dumps(["8" * 64], separators=(",", ":")),
                (
                    None
                    if missing_authority == "changed_paths"
                    else json.dumps(
                        ["l10n/messages_ru.properties"], separators=(",", ":")
                    )
                ),
                202,
                "Bot",
                None if missing_authority == "publication_actor" else 303,
                None if missing_authority == "publication_actor" else "Bot",
                "2026-08-30T12:03:00.000000Z",
            ),
        )

        with pytest.raises(RuntimeError, match="intent ledger is malformed"):
            state.remediation_successor_intent(publication_key=publication_key)


@pytest.mark.parametrize("ledger", ("intent", "publication"))
def test_successor_publication_actor_tampering_fails_closed(
    tmp_path: Path,
    ledger: str,
) -> None:
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
    with GuardianState(tmp_path / "guardian.sqlite3") as state:
        metadata = _remediation_metadata(state, now=now)
        draft_key = _open_remediation_draft(state, metadata, draft_number=91)
        feedback = state.record_feedback_event(
            _event(
                repository="acme/widgets",
                pr_number=91,
                event_id=f"tampered-publication-actor-{ledger}",
                head_sha=metadata["candidate_sha"],
                base_sha=metadata["target_base_sha"],
            ),
            observed_at=now + timedelta(minutes=1),
        )
        publication = {
            "run_id": metadata["run_id"],
            "repository": "acme/widgets",
            "pr_number": 91,
            "original_head_sha": metadata["candidate_sha"],
            "base_sha": metadata["target_base_sha"],
            "commit_sha": "d" * 40,
            "event_revision_ids": (feedback.revision_id,),
            "open_source": OpenPullAuthorityReference(
                repository="acme/widgets",
                repository_id=42,
                pull_id=901,
                pr_number=91,
                authority_digest="f" * 64,
                head_sha=metadata["candidate_sha"],
                base_sha=metadata["target_base_sha"],
                feedback_digest="6" * 64,
            ),
            "draft_key": draft_key,
            "source_pulls": tuple(metadata["source_pulls"]),
            "edit_hashes": tuple(metadata["edit_hashes"]),
            "changed_paths": ("l10n/messages_ru.properties",),
            "actor_id": 202,
            "actor_type": "Bot",
            "publication_actor_id": 303,
            "publication_actor_type": "Bot",
        }
        intent = state.record_remediation_successor_publication_event(
            **publication,
            phase="prepared",
            completion_actions=(
                (feedback.revision_id, "completed", {"outcome": "applied"}),
            ),
            occurred_at=now + timedelta(minutes=2),
        )
        if ledger == "publication":
            state.record_remediation_successor_publication_event(
                **publication,
                phase="published",
                occurred_at=now + timedelta(minutes=3),
            )
            table = "remediation_successor_publications"
            trigger = "remediation_successors_no_update"
        else:
            table = "remediation_successor_intents"
            trigger = "remediation_successor_intents_no_update"
        state._connection.execute(f"DROP TRIGGER {trigger}")  # noqa: S608, SLF001
        state._connection.execute(  # noqa: S608, SLF001
            f"UPDATE {table} SET publication_actor_id = 304"
        )

        if ledger == "publication":
            with pytest.raises(RuntimeError, match="publication ledger is malformed"):
                state.remediation_successor_publications(draft_key=draft_key)
        else:
            with pytest.raises(RuntimeError, match="intent ledger is malformed"):
                state.remediation_successor_intent(
                    publication_key=intent.publication_key
                )


def test_merged_source_queue_survives_restart_and_multiple_merges(
    tmp_path: Path,
) -> None:
    database = tmp_path / "guardian.sqlite3"
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
    with GuardianState(database) as state:
        first_metadata = _remediation_metadata(state, now=now)
        first_key = _open_remediation_draft(state, first_metadata, draft_number=91)
        _record_merged_observation(
            state,
            draft_key=first_key,
            observed_at=now + timedelta(minutes=1),
        )
        second_metadata = _remediation_metadata(
            state,
            now=now + timedelta(minutes=2),
            edit_hashes=("f" * 64,),
        )
        second_metadata["branch"] = "guardian/remediation-" + "4" * 64
        second_key = _open_remediation_draft(
            state,
            second_metadata,
            draft_number=92,
        )
        _record_merged_observation(
            state,
            draft_key=second_key,
            observed_at=now + timedelta(minutes=3),
        )

        queued = state.pending_merged_remediation_revalidations(
            repository="acme/widgets"
        )
        assert len(queued) == 4
        assert {item.draft_key for item in queued} == {first_key, second_key}
        first = queued[0]
        attempted = state.record_merged_remediation_revalidation_attempt(
            revalidation_key=first.revalidation_key,
            occurred_at=now + timedelta(minutes=4),
        )
        assert attempted.phase == "attempted"

    with GuardianState(database) as state:
        restarted = state.pending_merged_remediation_revalidations(
            repository="acme/widgets"
        )
        assert len(restarted) == 4
        assert restarted[-1].revalidation_key == first.revalidation_key
        terminal = state.resolve_merged_remediation_revalidation(
            revalidation_key=first.revalidation_key,
            outcome="resolved",
            occurred_at=now + timedelta(minutes=5),
        )
        assert terminal.phase == "resolved"
        remaining = state.pending_merged_remediation_revalidations(
            repository="acme/widgets"
        )
        assert len(remaining) == 3
        assert first.revalidation_key not in {
            item.revalidation_key for item in remaining
        }


def test_recovered_merged_draft_can_be_attested_but_is_immediately_ineffective(
    tmp_path: Path,
) -> None:
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
    with GuardianState(tmp_path / "guardian.sqlite3") as state:
        metadata = _remediation_metadata(state, now=now)
        source = tuple(metadata["source_pulls"])[0]
        draft_key = _open_remediation_draft(state, metadata)
        _record_merged_observation(
            state,
            draft_key=draft_key,
            observed_at=now + timedelta(minutes=1),
        )

        group = _record_draft_backed_remediation_completions(
            state,
            {source: (draft_key,)},
            RemediationCoverageReason.DRAFT_RECOVERED,
            occurred_at=now + timedelta(minutes=1),
        )[0]

        assert group.effective is False
        assert not state.historical_pull_is_complete(
            **_source_lookup(source),
            authority_scope=HistoricalCheckScope.REMEDIATION,
        )
        with pytest.raises(ValueError, match="eligible opened"):
            _record_draft_backed_remediation_completions(
                state,
                {source: (draft_key,)},
                RemediationCoverageReason.DRAFT_PUBLISHED,
                occurred_at=now + timedelta(minutes=2),
            )


def test_recovered_coverage_requires_latest_exact_remote_observation(
    tmp_path: Path,
) -> None:
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
    with GuardianState(tmp_path / "guardian.sqlite3") as state:
        metadata = _remediation_metadata(state, now=now)
        source = tuple(metadata["source_pulls"])[0]
        draft_key = _open_remediation_draft(state, metadata)
        with pytest.raises(ValueError, match="exact remote observation"):
            _record_draft_backed_remediation_completions(
                state,
                {source: (draft_key,)},
                RemediationCoverageReason.DRAFT_RECOVERED,
                occurred_at=now + timedelta(minutes=1),
            )
        state.record_remediation_remote_observation(
            draft_key=draft_key,
            observation="conflict",
            observed_at=now + timedelta(minutes=1),
        )
        with pytest.raises(ValueError, match="exact remote observation"):
            _record_draft_backed_remediation_completions(
                state,
                {source: (draft_key,)},
                RemediationCoverageReason.DRAFT_RECOVERED,
                occurred_at=now + timedelta(minutes=1),
            )


def test_recovered_coverage_chronology_failure_rolls_back_every_write(
    tmp_path: Path,
) -> None:
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
    with GuardianState(tmp_path / "guardian.sqlite3") as state:
        metadata = _remediation_metadata(state, now=now)
        source = tuple(metadata["source_pulls"])[0]
        draft_key = _open_remediation_draft(state, metadata)
        state.record_remediation_remote_observation(
            draft_key=draft_key,
            observation="exact",
            state="open",
            is_draft=True,
            is_merged=False,
            pr_number=91,
            pr_url="https://github.test/acme/widgets/pull/91",
            observed_base_sha="d" * 40,
            observed_head_sha=state.remediation_candidate_tip(draft_key),
            observed_at=now + timedelta(minutes=2),
        )

        with pytest.raises(
            (ValueError, RuntimeError),
            match="exact remote observation|coverage ledger is malformed",
        ):
            _record_draft_backed_remediation_completions(
                state,
                {source: (draft_key,)},
                RemediationCoverageReason.DRAFT_RECOVERED,
                occurred_at=now + timedelta(minutes=1),
            )

        assert (
            state._connection.execute(  # noqa: SLF001
                "SELECT COUNT(*) FROM historical_pull_completions "
                "WHERE authority_scope = 'remediation'"
            ).fetchone()[0]
            == 0
        )
        assert (
            state._connection.execute(  # noqa: SLF001
                "SELECT COUNT(*) FROM remediation_source_coverage_groups"
            ).fetchone()[0]
            == 0
        )
        assert not state.historical_pull_is_complete(
            **_source_lookup(source),
            authority_scope=HistoricalCheckScope.REMEDIATION,
        )


def test_multi_draft_group_requires_every_member_and_later_group_can_recover(
    tmp_path: Path,
) -> None:
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
    with GuardianState(tmp_path / "guardian.sqlite3") as state:
        first_metadata = _remediation_metadata(state, now=now)
        source = tuple(first_metadata["source_pulls"])[0]
        first_key = _open_remediation_draft(state, first_metadata, draft_number=91)
        second_metadata = _remediation_metadata(
            state,
            now=now + timedelta(minutes=1),
            edit_hashes=("f" * 64,),
        )
        second_metadata["branch"] = "guardian/remediation-" + "c" * 64
        second_key = _open_remediation_draft(
            state,
            second_metadata,
            draft_number=92,
        )
        members = tuple(sorted((first_key, second_key)))

        group = _record_draft_backed_remediation_completions(
            state,
            {source: members},
            RemediationCoverageReason.DRAFT_PUBLISHED,
            checkpoint_draft_key=second_key,
            occurred_at=now + timedelta(minutes=2),
        )[0]
        assert group.draft_keys == members
        assert group.effective is True

        _record_merged_observation(
            state,
            draft_key=first_key,
            observed_at=now + timedelta(minutes=3),
        )
        assert not state.historical_pull_is_complete(
            **_source_lookup(source),
            authority_scope=HistoricalCheckScope.REMEDIATION,
        )

        state.record_remediation_remote_observation(
            draft_key=second_key,
            observation="exact",
            state="open",
            is_draft=True,
            is_merged=False,
            pr_number=92,
            pr_url="https://github.test/acme/widgets/pull/92",
            observed_base_sha="e" * 40,
            observed_head_sha=state.remediation_candidate_tip(second_key),
            observed_at=now + timedelta(minutes=3, seconds=30),
        )
        recovered = _record_draft_backed_remediation_completions(
            state,
            {source: (second_key,)},
            RemediationCoverageReason.DRAFT_RECOVERED,
            occurred_at=now + timedelta(minutes=4),
        )[0]
        assert recovered.effective is True
        assert state.historical_pull_is_complete(
            **_source_lookup(source),
            authority_scope=HistoricalCheckScope.REMEDIATION,
        )


def test_semantic_dedupe_links_new_source_to_existing_open_draft(
    tmp_path: Path,
) -> None:
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
    with GuardianState(tmp_path / "guardian.sqlite3") as state:
        metadata = _remediation_metadata(state, now=now)
        draft_key = _open_remediation_draft(state, metadata)
        revision = state.record_feedback_event(
            _event(
                pr_number=14,
                event_id="98767",
                body="The same exact correction is needed.",
            ),
            observed_at=now + timedelta(minutes=1),
        )
        source = HistoricalPullReference(
            repository="acme/widgets",
            repository_id=42,
            pull_id=502,
            pr_number=14,
            pull_revision_digest="4" * 64,
            authority_digest="6" * 64,
            policy_digest="2" * 64,
            head_sha="a" * 40,
            base_sha="b" * 40,
        )
        state.record_historical_pull_completion(
            **_source_lookup(source),
            pr_number=source.pr_number,
            head_sha=source.head_sha,
            base_sha=source.base_sha,
            event_revision_ids=(revision.revision_id,),
            authority_scope=HistoricalCheckScope.ASSESSMENT,
            completed_at=now + timedelta(minutes=1),
        )

        with pytest.raises(ValueError, match="exact event revisions"):
            _record_draft_backed_remediation_completions(
                state,
                {source: (draft_key,)},
                RemediationCoverageReason.DRAFT_SEMANTIC_DEDUPE,
            )
        with pytest.raises(ValueError, match="assessed pull snapshot"):
            _record_draft_backed_remediation_completions(
                state,
                {source: (draft_key,)},
                RemediationCoverageReason.DRAFT_SEMANTIC_DEDUPE,
                event_revision_ids_by_source={
                    source: (tuple(metadata["event_revision_ids"])[0],)
                },
            )

        group = _record_draft_backed_remediation_completions(
            state,
            {source: (draft_key,)},
            RemediationCoverageReason.DRAFT_SEMANTIC_DEDUPE,
            event_revision_ids_by_source={source: (revision.revision_id,)},
            occurred_at=now + timedelta(minutes=1),
        )[0]

        assert (
            source
            not in state.remediation_draft_by_key(draft_key=draft_key).source_pulls
        )
        assert group.source == source
        assert group.draft_keys == (draft_key,)
        assert group.reason is RemediationCoverageReason.DRAFT_SEMANTIC_DEDUPE
        assert group.effective is True
        assert state.remediation_source_coverage_count_for_draft(draft_key) == 1


def test_merge_revalidates_semantic_dedupe_source_outside_immutable_draft(
    tmp_path: Path,
) -> None:
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
    database = tmp_path / "guardian.sqlite3"
    with GuardianState(database) as state:
        metadata = _remediation_metadata(state, now=now)
        original_sources = tuple(metadata["source_pulls"])
        draft_key = _open_remediation_draft(state, metadata)
        revision = state.record_feedback_event(
            _event(
                pr_number=14,
                event_id="98767",
                body="The same exact correction is needed.",
            ),
            observed_at=now + timedelta(minutes=1),
        )
        semantic_source = HistoricalPullReference(
            repository="acme/widgets",
            repository_id=42,
            pull_id=502,
            pr_number=14,
            pull_revision_digest="4" * 64,
            authority_digest="6" * 64,
            policy_digest="2" * 64,
            head_sha="a" * 40,
            base_sha="b" * 40,
        )
        state.record_historical_pull_completion(
            **_source_lookup(semantic_source),
            pr_number=semantic_source.pr_number,
            head_sha=semantic_source.head_sha,
            base_sha=semantic_source.base_sha,
            event_revision_ids=(revision.revision_id,),
            authority_scope=HistoricalCheckScope.ASSESSMENT,
            completed_at=now + timedelta(minutes=1),
        )
        _record_draft_backed_remediation_completions(
            state,
            {semantic_source: (draft_key,)},
            RemediationCoverageReason.DRAFT_SEMANTIC_DEDUPE,
            event_revision_ids_by_source={semantic_source: (revision.revision_id,)},
            occurred_at=now + timedelta(minutes=1),
        )

        _record_merged_observation(
            state,
            draft_key=draft_key,
            observed_at=now + timedelta(minutes=2),
        )

        pending = state.pending_merged_remediation_revalidations()
        assert {item.source for item in pending} == {
            *original_sources,
            semantic_source,
        }
        semantic_item = next(item for item in pending if item.source == semantic_source)
        assert semantic_item.event_revision_ids == (revision.revision_id,)
        assert not state.historical_pull_is_complete(
            **_source_lookup(semantic_source),
            authority_scope=HistoricalCheckScope.REMEDIATION,
        )

    # Reopening exercises durable row validation for a source that is linked
    # through semantic coverage instead of immutable draft.source_pulls.
    with GuardianState(database) as state:
        pending = state.pending_merged_remediation_revalidations()
        semantic_item = next(item for item in pending if item.source == semantic_source)
        state.record_independent_remediation_completion(
            semantic_source,
            RemediationCoverageReason.INDEPENDENT_ALREADY_CURRENT,
            event_revision_ids=semantic_item.event_revision_ids,
            occurred_at=now + timedelta(minutes=3),
        )
        resolved = state.resolve_merged_remediation_revalidation(
            revalidation_key=semantic_item.revalidation_key,
            outcome="resolved",
            occurred_at=now + timedelta(minutes=3),
        )

        assert resolved.phase == "resolved"
        assert semantic_item.revalidation_key not in {
            item.revalidation_key
            for item in state.pending_merged_remediation_revalidations()
        }
        assert state.historical_pull_is_complete(
            **_source_lookup(semantic_source),
            authority_scope=HistoricalCheckScope.REMEDIATION,
        )


def test_merge_revalidation_writer_rejects_source_revision_count_over_bound(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
    with GuardianState(tmp_path / "guardian.sqlite3") as state:
        metadata = _remediation_metadata(state, now=now)
        draft_key = _open_remediation_draft(state, metadata)
        monkeypatch.setattr(
            guardian_state,
            "_MAX_REMEDIATION_SOURCE_EVENT_REVISIONS",
            0,
        )

        with pytest.raises(RuntimeError, match="evidence reached its safety bound"):
            _record_merged_observation(
                state,
                draft_key=draft_key,
                observed_at=now + timedelta(minutes=1),
            )

        assert state.remediation_resolution(draft_key=draft_key) is None
        assert state.latest_remediation_remote_observation(draft_key) is None
        assert state.pending_merged_remediation_revalidations() == ()


@pytest.mark.parametrize(
    ("limit_name", "limit_value", "corrupt_revision_ids"),
    (
        ("_MAX_REMEDIATION_SOURCE_EVENT_REVISIONS", 0, None),
        (
            "_MAX_REMEDIATION_SOURCE_EVENT_REVISIONS_JSON_BYTES",
            2,
            "[1]",
        ),
    ),
    ids=("count", "bytes"),
)
def test_merge_revalidation_reader_rejects_source_evidence_over_bound(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    limit_name: str,
    limit_value: int,
    corrupt_revision_ids: str | None,
) -> None:
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
    with GuardianState(tmp_path / "guardian.sqlite3") as state:
        metadata = _remediation_metadata(state, now=now)
        draft_key = _open_remediation_draft(state, metadata)
        _record_merged_observation(
            state,
            draft_key=draft_key,
            observed_at=now + timedelta(minutes=1),
        )
        if corrupt_revision_ids is not None:
            state._connection.execute(  # noqa: SLF001 - corruption fixture
                "DROP TRIGGER remediation_merge_revalidations_no_update"
            )
            state._connection.execute(  # noqa: SLF001 - corruption fixture
                "UPDATE remediation_merge_revalidation_events "
                "SET event_revision_ids_json = ?",
                (corrupt_revision_ids,),
            )
            state._connection.commit()  # noqa: SLF001 - corruption fixture
        monkeypatch.setattr(guardian_state, limit_name, limit_value)

        with pytest.raises(
            RuntimeError,
            match="Merged remediation revalidation ledger is malformed",
        ):
            state.pending_merged_remediation_revalidations()


def test_semantic_dedupe_cannot_bind_a_draft_from_another_repository(
    tmp_path: Path,
) -> None:
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
    with GuardianState(tmp_path / "guardian.sqlite3") as state:
        metadata = _remediation_metadata(state, now=now)
        draft_key = _open_remediation_draft(state, metadata)
        revision = state.record_feedback_event(
            _event(
                repository="other/widgets",
                pr_number=14,
                event_id="98767",
                body="The same exact correction is needed elsewhere.",
            ),
            observed_at=now + timedelta(minutes=1),
        )
        source = HistoricalPullReference(
            repository="other/widgets",
            repository_id=77,
            pull_id=502,
            pr_number=14,
            pull_revision_digest="4" * 64,
            authority_digest="6" * 64,
            policy_digest="2" * 64,
            head_sha="a" * 40,
            base_sha="b" * 40,
        )
        state.record_historical_pull_completion(
            **_source_lookup(source),
            pr_number=source.pr_number,
            head_sha=source.head_sha,
            base_sha=source.base_sha,
            event_revision_ids=(revision.revision_id,),
            authority_scope=HistoricalCheckScope.ASSESSMENT,
            completed_at=now + timedelta(minutes=1),
        )

        with pytest.raises(ValueError, match="source repository identity"):
            _record_draft_backed_remediation_completions(
                state,
                {source: (draft_key,)},
                RemediationCoverageReason.DRAFT_SEMANTIC_DEDUPE,
                event_revision_ids_by_source={source: (revision.revision_id,)},
                occurred_at=now + timedelta(minutes=1),
            )

        assert (
            state._connection.execute(  # noqa: SLF001
                "SELECT COUNT(*) FROM historical_pull_completions "
                "WHERE authority_scope = 'remediation'"
            ).fetchone()[0]
            == 0
        )
        assert (
            state._connection.execute(  # noqa: SLF001
                "SELECT COUNT(*) FROM remediation_source_coverage_groups"
            ).fetchone()[0]
            == 0
        )
        assert not state.historical_pull_is_complete(
            **_source_lookup(source),
            authority_scope=HistoricalCheckScope.REMEDIATION,
        )


def test_operator_quarantine_atomically_attests_every_exact_source(
    tmp_path: Path,
) -> None:
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
    with GuardianState(tmp_path / "guardian.sqlite3") as state:
        metadata = _remediation_metadata(state, now=now)
        sources = tuple(metadata["source_pulls"])
        draft_key = state.record_remediation_draft_event(
            **metadata,
            phase="validated",
        )

        assert state.record_remediation_quarantine(
            draft_key=draft_key,
            terminal_local_skip_acknowledged=True,
            occurred_at=now + timedelta(minutes=1),
        )

        groups = state.remediation_source_coverage_for_draft(draft_key)
        assert {group.source for group in groups} == set(sources)
        assert all(
            group.reason is RemediationCoverageReason.OPERATOR_QUARANTINED
            and group.effective
            for group in groups
        )
        for source in sources:
            assert state.historical_pull_is_complete(
                **_source_lookup(source),
                authority_scope=HistoricalCheckScope.REMEDIATION,
            )
        changed_policy = replace(sources[0], policy_digest="9" * 64)
        changed_revision = replace(sources[0], pull_revision_digest="8" * 64)
        for changed in (changed_policy, changed_revision):
            assert not state.historical_pull_is_complete(
                **_source_lookup(changed),
                authority_scope=HistoricalCheckScope.REMEDIATION,
            )


def test_quarantine_injection_failure_rolls_back_completion_group_and_resolution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
    with GuardianState(tmp_path / "guardian.sqlite3") as state:
        metadata = _remediation_metadata(state, now=now)
        draft_key = state.record_remediation_draft_event(
            **metadata,
            phase="validated",
        )

        def fail_member_insert(**_kwargs: object) -> None:
            raise RuntimeError("injected coverage failure")

        monkeypatch.setattr(
            state,
            "_insert_remediation_coverage_members_in_transaction",
            fail_member_insert,
        )
        with pytest.raises(RuntimeError, match="injected coverage failure"):
            state.record_remediation_quarantine(
                draft_key=draft_key,
                terminal_local_skip_acknowledged=True,
                occurred_at=now + timedelta(minutes=1),
            )

        assert state.remediation_resolution(draft_key=draft_key) is None
        assert (
            state._connection.execute(  # noqa: SLF001
                "SELECT COUNT(*) FROM historical_pull_completions "
                "WHERE authority_scope = 'remediation'"
            ).fetchone()[0]
            == 0
        )
        assert (
            state._connection.execute(  # noqa: SLF001
                "SELECT COUNT(*) FROM remediation_source_coverage_groups"
            ).fetchone()[0]
            == 0
        )


def test_checkpoint_injection_failure_rolls_back_draft_backed_completions(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
    with GuardianState(tmp_path / "guardian.sqlite3") as state:
        metadata = _remediation_metadata(state, now=now)
        sources = tuple(metadata["source_pulls"])
        draft_key = _open_remediation_draft(state, metadata)

        def fail_checkpoint(**_kwargs: object) -> bool:
            raise RuntimeError("injected checkpoint failure")

        monkeypatch.setattr(
            state,
            "_record_remediation_checkpoint_in_transaction",
            fail_checkpoint,
        )
        with pytest.raises(RuntimeError, match="injected checkpoint failure"):
            _record_draft_backed_remediation_completions(
                state,
                {source: (draft_key,) for source in sources},
                RemediationCoverageReason.DRAFT_PUBLISHED,
                checkpoint_draft_key=draft_key,
                occurred_at=now + timedelta(minutes=1),
            )

        assert (
            state._connection.execute(  # noqa: SLF001
                "SELECT COUNT(*) FROM historical_pull_completions "
                "WHERE authority_scope = 'remediation'"
            ).fetchone()[0]
            == 0
        )
        assert (
            state._connection.execute(  # noqa: SLF001
                "SELECT COUNT(*) FROM remediation_source_coverage_groups"
            ).fetchone()[0]
            == 0
        )
        assert (
            state._connection.execute(  # noqa: SLF001
                "SELECT COUNT(*) FROM remediation_checkpoint_events"
            ).fetchone()[0]
            == 0
        )


def test_independent_completion_validation_failure_rolls_back_every_write(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
    with GuardianState(tmp_path / "guardian.sqlite3") as state:
        metadata = _remediation_metadata(state, now=now)
        source = tuple(metadata["source_pulls"])[0]

        def fail_validation(**_kwargs: object) -> None:
            raise RuntimeError("injected coverage validation failure")

        monkeypatch.setattr(state, "_coverage_record_by_id", fail_validation)
        with pytest.raises(RuntimeError, match="injected coverage validation failure"):
            state.record_independent_remediation_completion(
                source,
                RemediationCoverageReason.INDEPENDENT_ALREADY_CURRENT,
                event_revision_ids=_source_revision_ids(state, metadata, source),
                occurred_at=now,
            )

        assert (
            state._connection.execute(  # noqa: SLF001
                "SELECT COUNT(*) FROM historical_pull_completions "
                "WHERE authority_scope = 'remediation'"
            ).fetchone()[0]
            == 0
        )
        assert (
            state._connection.execute(  # noqa: SLF001
                "SELECT COUNT(*) FROM remediation_source_coverage_groups"
            ).fetchone()[0]
            == 0
        )


def test_malformed_later_coverage_group_fails_closed_without_short_circuit(
    tmp_path: Path,
) -> None:
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
    with GuardianState(tmp_path / "guardian.sqlite3") as state:
        metadata = _remediation_metadata(state, now=now)
        source = tuple(metadata["source_pulls"])[0]
        valid = state.record_independent_remediation_completion(
            source,
            RemediationCoverageReason.INDEPENDENT_ALREADY_CURRENT,
            event_revision_ids=_source_revision_ids(state, metadata, source),
            occurred_at=now,
        )
        state._connection.execute(  # noqa: SLF001 - malformed-ledger fixture
            """
            INSERT INTO remediation_source_coverage_groups (
                completion_id, authority_digest, kind, reason, canonical_hash,
                member_count, occurred_at
            ) VALUES (?, ?, 'draft_backed', 'draft_published', ?, 1, ?)
            """,
            (
                valid.completion_id,
                source.authority_digest,
                "9" * 64,
                "2026-08-30T12:01:00.000000Z",
            ),
        )

        with pytest.raises(RuntimeError, match="coverage ledger is malformed"):
            state.historical_pull_is_complete(
                **_source_lookup(source),
                authority_scope=HistoricalCheckScope.REMEDIATION,
            )


def test_coverage_member_bound_rejects_oversized_group(tmp_path: Path) -> None:
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
    with GuardianState(tmp_path / "guardian.sqlite3") as state:
        metadata = _remediation_metadata(state, now=now)
        source = tuple(metadata["source_pulls"])[0]
        oversized = tuple(f"{index + 1:064x}" for index in range(101))

        with pytest.raises(ValueError, match="at most 100 members"):
            _record_draft_backed_remediation_completions(
                state,
                {source: oversized},
                RemediationCoverageReason.DRAFT_PUBLISHED,
            )


def test_coverage_group_application_bound_keeps_existing_group_readable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
    with GuardianState(tmp_path / "guardian.sqlite3") as state:
        metadata = _remediation_metadata(state, now=now)
        source = tuple(metadata["source_pulls"])[0]
        revision_ids = _source_revision_ids(state, metadata, source)
        first = state.record_independent_remediation_completion(
            source,
            RemediationCoverageReason.INDEPENDENT_ALREADY_CURRENT,
            event_revision_ids=revision_ids,
            occurred_at=now,
        )
        monkeypatch.setattr(
            guardian_state,
            "_MAX_REMEDIATION_SOURCE_COVERAGE_GROUPS",
            1,
        )

        with pytest.raises(RuntimeError, match="group count"):
            state.record_independent_remediation_completion(
                source,
                RemediationCoverageReason.INDEPENDENT_NO_ACTION,
                event_revision_ids=revision_ids,
                occurred_at=now + timedelta(minutes=1),
            )

        assert (
            state._coverage_record_by_id(  # noqa: SLF001
                coverage_group_id=first.coverage_group_id
            )
            == first
        )
        assert state.historical_pull_is_complete(
            **_source_lookup(source),
            authority_scope=HistoricalCheckScope.REMEDIATION,
        )


def test_remote_observations_preserve_exact_lifecycle_and_advanced_base(
    tmp_path: Path,
) -> None:
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
    with GuardianState(tmp_path / "guardian.sqlite3") as state:
        metadata = _remediation_metadata(state, now=now)
        draft_key = _open_remediation_draft(state, metadata)

        missing = state.record_remediation_remote_observation(
            draft_key=draft_key,
            observation="not_found",
            observed_at=now + timedelta(minutes=1),
        )
        assert missing.state is None
        conflict = state.record_remediation_remote_observation(
            draft_key=draft_key,
            observation="conflict",
            state="open",
            is_draft=True,
            is_merged=False,
            pr_number=999,
            pr_url="https://github.test/acme/widgets/pull/999",
            observed_base_sha="d" * 40,
            observed_head_sha="0" * 40,
            observed_at=now + timedelta(minutes=2),
        )
        assert conflict.pr_number == 999
        opened = state.record_remediation_remote_observation(
            draft_key=draft_key,
            observation="exact",
            state="open",
            is_draft=True,
            is_merged=False,
            pr_number=91,
            pr_url="https://github.test/acme/widgets/pull/91",
            observed_base_sha="d" * 40,
            observed_head_sha=state.remediation_candidate_tip(draft_key),
            observed_at=now + timedelta(minutes=3),
        )
        assert opened.observed_base_sha == "d" * 40
        assert opened.observed_base_sha != metadata["target_base_sha"]
        ready = state.record_remediation_remote_observation(
            draft_key=draft_key,
            observation="exact",
            state="open",
            is_draft=False,
            is_merged=False,
            pr_number=91,
            pr_url="https://github.test/acme/widgets/pull/91",
            observed_base_sha="e" * 40,
            observed_head_sha=state.remediation_candidate_tip(draft_key),
            observed_at=now + timedelta(minutes=4),
        )
        assert ready.is_draft is False
        _record_merged_observation(
            state,
            draft_key=draft_key,
            observed_at=now + timedelta(minutes=5),
            observed_base_sha="f" * 40,
        )

        latest = state.latest_remediation_remote_observation(draft_key)
        assert latest is not None
        assert latest.observation == "exact"
        assert latest.state == "closed"
        assert latest.is_draft is False
        assert latest.is_merged is True
        assert latest.observed_base_sha == "f" * 40
        assert state.remediation_resolution(draft_key=draft_key) == "merged"


def test_resolved_remote_lifecycle_is_terminal_and_db_enforced(
    tmp_path: Path,
) -> None:
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
    with GuardianState(tmp_path / "guardian.sqlite3") as state:
        metadata = _remediation_metadata(state, now=now)
        draft_key = _open_remediation_draft(state, metadata)
        _record_merged_observation(
            state,
            draft_key=draft_key,
            observed_at=now + timedelta(minutes=1),
        )
        merged = state.latest_remediation_remote_observation(draft_key)
        assert merged is not None

        duplicate = state.record_remediation_remote_observation(
            draft_key=draft_key,
            observation="exact",
            state="closed",
            is_draft=False,
            is_merged=True,
            pr_number=91,
            pr_url="https://github.test/acme/widgets/pull/91",
            observed_base_sha="f" * 40,
            observed_head_sha=state.remediation_candidate_tip(draft_key),
            closed_at="2026-08-30T12:01:00Z",
            merged_at="2026-08-30T12:01:00Z",
            observed_at=now + timedelta(minutes=2),
        )
        assert duplicate == merged
        with pytest.raises(ValueError, match="lifecycle is terminal"):
            state.record_remediation_remote_observation(
                draft_key=draft_key,
                observation="not_found",
                observed_at=now + timedelta(minutes=2),
            )
        with pytest.raises(sqlite3.IntegrityError, match="lifecycle is terminal"):
            state._connection.execute(  # noqa: SLF001 - DB invariant assertion
                """
                INSERT INTO remediation_remote_observation_events (
                    draft_key, observation, occurred_at
                ) VALUES (?, 'not_found', ?)
                """,
                (draft_key, "2026-08-30T12:02:00.000000Z"),
            )

        assert state.latest_remediation_remote_observation(draft_key) == merged


@pytest.mark.parametrize("is_draft", [True, False])
def test_exact_closed_unmerged_observation_preserves_draft_state(
    tmp_path: Path,
    is_draft: bool,
) -> None:
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
    with GuardianState(tmp_path / "guardian.sqlite3") as state:
        metadata = _remediation_metadata(state, now=now)
        draft_key = _open_remediation_draft(state, metadata)

        observed = state.record_remediation_remote_observation(
            draft_key=draft_key,
            observation="exact",
            state="closed",
            is_draft=is_draft,
            is_merged=False,
            pr_number=91,
            pr_url="https://github.test/acme/widgets/pull/91",
            observed_base_sha="d" * 40,
            observed_head_sha=state.remediation_candidate_tip(draft_key),
            closed_at="2026-08-30T12:01:00Z",
            observed_at=now + timedelta(minutes=1),
        )

        assert observed.state == "closed"
        assert observed.is_draft is is_draft
        assert observed.is_merged is False
        assert state.remediation_resolution(draft_key=draft_key) is None


def test_remote_lifecycle_accepts_close_reopen_then_exact_merge(
    tmp_path: Path,
) -> None:
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
    with GuardianState(tmp_path / "guardian.sqlite3") as state:
        metadata = _remediation_metadata(state, now=now)
        draft_key = _open_remediation_draft(state, metadata)
        common = {
            "draft_key": draft_key,
            "observation": "exact",
            "is_draft": False,
            "pr_number": 91,
            "pr_url": "https://github.test/acme/widgets/pull/91",
            "observed_base_sha": "d" * 40,
            "observed_head_sha": state.remediation_candidate_tip(draft_key),
        }
        state.record_remediation_remote_observation(
            **common,
            state="closed",
            is_merged=False,
            closed_at="2026-08-30T12:01:00Z",
            observed_at=now + timedelta(minutes=1),
        )
        reopened = state.record_remediation_remote_observation(
            **common,
            state="open",
            is_merged=False,
            observed_at=now + timedelta(minutes=2),
        )
        merged = state.record_remediation_remote_observation(
            **common,
            state="closed",
            is_merged=True,
            closed_at="2026-08-30T12:03:01Z",
            merged_at="2026-08-30T12:03:00Z",
            observed_at=now + timedelta(minutes=4),
        )

        assert reopened.closed_at is None
        assert merged.closed_at == "2026-08-30T12:03:01Z"
        assert merged.merged_at == "2026-08-30T12:03:00Z"
        assert state.remediation_resolution(draft_key=draft_key) == "merged"
        assert len(state.pending_merged_remediation_revalidations()) == len(
            tuple(metadata["source_pulls"])
        )


@pytest.mark.parametrize(
    "metadata",
    [
        {
            "observation": "not_found",
            "state": "open",
        },
        {
            "observation": "exact",
            "state": "closed",
            "is_draft": True,
            "is_merged": True,
            "pr_number": 91,
            "pr_url": "https://github.test/acme/widgets/pull/91",
            "observed_base_sha": "d" * 40,
        },
        {
            "observation": "exact",
            "state": "open",
            "is_draft": False,
            "is_merged": True,
            "pr_number": 91,
            "pr_url": "https://github.test/acme/widgets/pull/91",
            "observed_base_sha": "d" * 40,
        },
        {
            "observation": "conflict",
            "state": "open",
            "is_draft": False,
        },
    ],
)
def test_remote_observation_rejects_partial_or_impossible_lifecycle(
    tmp_path: Path,
    metadata: dict[str, object],
) -> None:
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
    with GuardianState(tmp_path / "guardian.sqlite3") as state:
        remediation = _remediation_metadata(state, now=now)
        draft_key = _open_remediation_draft(state, remediation)

        with pytest.raises(ValueError):
            state.record_remediation_remote_observation(
                draft_key=draft_key,
                observed_at=now + timedelta(minutes=1),
                **metadata,
            )


def test_remote_observation_db_rejects_partial_conflict_metadata(
    tmp_path: Path,
) -> None:
    with GuardianState(tmp_path / "guardian.sqlite3") as state:
        with pytest.raises(sqlite3.IntegrityError, match="CHECK constraint"):
            state._connection.execute(  # noqa: SLF001 - DB invariant assertion
                """
                INSERT INTO remediation_remote_observation_events (
                    draft_key, observation, state, occurred_at
                ) VALUES (?, 'conflict', 'open', ?)
                """,
                ("d" * 64, "2026-08-30T12:00:00.000000Z"),
            )


def test_remote_observation_timestamp_is_monotonic_and_db_enforced(
    tmp_path: Path,
) -> None:
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
    with GuardianState(tmp_path / "guardian.sqlite3") as state:
        metadata = _remediation_metadata(state, now=now)
        draft_key = _open_remediation_draft(state, metadata)
        state.record_remediation_remote_observation(
            draft_key=draft_key,
            observation="not_found",
            observed_at=now + timedelta(minutes=2),
        )

        with pytest.raises(ValueError, match="monotonic"):
            state.record_remediation_remote_observation(
                draft_key=draft_key,
                observation="not_found",
                observed_at=now + timedelta(minutes=1),
            )
        with pytest.raises(sqlite3.IntegrityError, match="monotonic"):
            state._connection.execute(  # noqa: SLF001 - DB trigger assertion
                """
                INSERT INTO remediation_remote_observation_events (
                    draft_key, observation, occurred_at
                ) VALUES (?, 'not_found', ?)
                """,
                (draft_key, "2026-08-30T12:01:00.000000Z"),
            )
        latest = state.latest_remediation_remote_observation(draft_key)
        assert latest is not None
        assert latest.occurred_at == now + timedelta(minutes=2)


def test_remote_observation_application_bound_leaves_latest_readable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
    with GuardianState(tmp_path / "guardian.sqlite3") as state:
        metadata = _remediation_metadata(state, now=now)
        draft_key = _open_remediation_draft(state, metadata)
        first = state.record_remediation_remote_observation(
            draft_key=draft_key,
            observation="not_found",
            observed_at=now + timedelta(minutes=1),
        )
        monkeypatch.setattr(
            guardian_state,
            "_MAX_REMEDIATION_REMOTE_OBSERVATIONS",
            1,
        )

        duplicate = state.record_remediation_remote_observation(
            draft_key=draft_key,
            observation="not_found",
            observed_at=now + timedelta(minutes=2),
        )
        assert duplicate == first
        assert (
            state._connection.execute(  # noqa: SLF001
                "SELECT COUNT(*) FROM remediation_remote_observation_events"
            ).fetchone()[0]
            == 1
        )

        with pytest.raises(RuntimeError, match="observation count"):
            state.record_remediation_remote_observation(
                draft_key=draft_key,
                observation="conflict",
                observed_at=now + timedelta(minutes=3),
            )

        assert state.latest_remediation_remote_observation(draft_key) == first


def test_early_remote_observation_remains_readable_after_later_draft_phases(
    tmp_path: Path,
) -> None:
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
    with GuardianState(tmp_path / "guardian.sqlite3") as state:
        metadata = _remediation_metadata(state, now=now)
        draft_key = state.record_remediation_draft_event(
            **metadata,
            phase="validated",
        )
        state.record_remediation_remote_observation(
            draft_key=draft_key,
            observation="not_found",
            observed_at=now + timedelta(minutes=1),
        )
        state.record_remediation_draft_event(
            **{**metadata, "occurred_at": now + timedelta(minutes=2)},
            phase="pushed",
        )
        state.record_remediation_draft_event(
            **{**metadata, "occurred_at": now + timedelta(minutes=3)},
            phase="draft_opened",
            draft_number=91,
            draft_pull_id=9_091,
            draft_url="https://github.test/acme/widgets/pull/91",
        )

        latest = state.latest_remediation_remote_observation(draft_key)
        assert latest is not None
        assert latest.observation == "not_found"
        assert latest.occurred_at == now + timedelta(minutes=1)


def test_latest_remote_observation_controls_coverage_and_edit_blocking(
    tmp_path: Path,
) -> None:
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
    with GuardianState(tmp_path / "guardian.sqlite3") as state:
        metadata = _remediation_metadata(state, now=now)
        source = tuple(metadata["source_pulls"])[0]
        draft_key = _open_remediation_draft(state, metadata)
        _record_draft_backed_remediation_completions(
            state,
            {source: (draft_key,)},
            RemediationCoverageReason.DRAFT_PUBLISHED,
            occurred_at=now,
        )

        def assert_effective(expected: bool) -> None:
            group = state.remediation_source_coverage_for_draft(draft_key)[0]
            assert group.effective is expected
            assert (
                state.historical_pull_is_complete(
                    **_source_lookup(source),
                    authority_scope=HistoricalCheckScope.REMEDIATION,
                )
                is expected
            )

        assert_effective(True)
        for offset, observation in enumerate(("not_found", "conflict"), start=1):
            state.record_remediation_remote_observation(
                draft_key=draft_key,
                observation=observation,
                observed_at=now + timedelta(minutes=offset),
            )
            assert_effective(False)
            edit_coverage = state.remediation_edit_coverage(
                target_repository="acme/widgets",
                target_repository_id=42,
                edit_target_hashes=metadata["edit_target_hashes"],
            )
            assert edit_coverage.opened_edit_hashes == frozenset()
            assert edit_coverage.incompatible_edit_hashes == frozenset(
                metadata["edit_hashes"]
            )
            with pytest.raises(ValueError, match="remote lifecycle evidence"):
                _record_draft_backed_remediation_completions(
                    state,
                    {source: (draft_key,)},
                    RemediationCoverageReason.DRAFT_SEMANTIC_DEDUPE,
                    event_revision_ids_by_source={
                        source: _source_revision_ids(state, metadata, source)
                    },
                    occurred_at=now + timedelta(minutes=offset),
                )

        state.record_remediation_remote_observation(
            draft_key=draft_key,
            observation="exact",
            state="closed",
            is_draft=False,
            is_merged=False,
            pr_number=91,
            pr_url="https://github.test/acme/widgets/pull/91",
            observed_base_sha="f" * 40,
            observed_head_sha=state.remediation_candidate_tip(draft_key),
            closed_at="2026-08-30T12:03:00Z",
            observed_at=now + timedelta(minutes=3),
        )
        assert_effective(True)

        state.record_remediation_remote_observation(
            draft_key=draft_key,
            observation="conflict",
            observed_at=now + timedelta(minutes=4),
        )
        assert_effective(False)
        state.record_remediation_resolution(
            draft_key=draft_key,
            resolution="operator_quarantined",
            terminal_local_skip_acknowledged=True,
            occurred_at=now + timedelta(minutes=5),
        )
        assert_effective(True)


def test_status_snapshot_counts_latest_remote_lifecycle_categories(
    tmp_path: Path,
) -> None:
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
    observations = (
        ("exact", "open", True, False),
        ("exact", "closed", False, False),
        ("not_found", None, None, None),
        ("conflict", None, None, None),
    )
    with GuardianState(tmp_path / "guardian.sqlite3") as state:
        for index, (observation, remote_state, is_draft, is_merged) in enumerate(
            observations,
            start=1,
        ):
            metadata = _remediation_metadata(
                state,
                now=now + timedelta(seconds=index),
                edit_hashes=(f"{index:064x}",),
            )
            draft_number = 90 + index
            draft_key = _open_remediation_draft(
                state,
                metadata,
                draft_number=draft_number,
            )
            exact = observation == "exact"
            state.record_remediation_remote_observation(
                draft_key=draft_key,
                observation=observation,
                state=remote_state,
                is_draft=is_draft,
                is_merged=is_merged,
                pr_number=draft_number if exact else None,
                pr_url=(
                    f"https://github.test/acme/widgets/pull/{draft_number}"
                    if exact
                    else None
                ),
                observed_base_sha="f" * 40 if exact else None,
                observed_head_sha=(
                    state.remediation_candidate_tip(draft_key) if exact else None
                ),
                closed_at=(
                    f"2026-08-30T12:0{index}:00Z" if remote_state == "closed" else None
                ),
                observed_at=now + timedelta(minutes=index),
            )

        snapshot = state.status_snapshot(mode=GuardianMode.OBSERVE, as_of=now)

        assert snapshot.remote_exact_open_remediations == 1
        assert snapshot.remote_closed_unmerged_remediations == 1
        assert snapshot.remote_not_found_remediations == 1
        assert snapshot.remote_conflict_remediations == 1


def test_merged_observation_and_resolution_roll_back_together(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
    with GuardianState(tmp_path / "guardian.sqlite3") as state:
        metadata = _remediation_metadata(state, now=now)
        draft_key = _open_remediation_draft(state, metadata)

        def fail_resolution(**_kwargs: object) -> bool:
            raise RuntimeError("injected resolution failure")

        monkeypatch.setattr(
            state,
            "_record_remediation_resolution_in_transaction",
            fail_resolution,
        )
        with pytest.raises(RuntimeError, match="injected resolution failure"):
            _record_merged_observation(
                state,
                draft_key=draft_key,
                observed_at=now + timedelta(minutes=1),
            )

        assert state.remediation_resolution(draft_key=draft_key) is None
        assert state.latest_remediation_remote_observation(draft_key) is None
        assert state.pending_merged_remediation_revalidations() == ()


def test_new_schema_ledgers_are_immutable_and_structurally_bounded(
    tmp_path: Path,
) -> None:
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
    with GuardianState(tmp_path / "guardian.sqlite3") as state:
        metadata = _remediation_metadata(state, now=now)
        source = tuple(metadata["source_pulls"])[0]
        draft_key = _open_remediation_draft(state, metadata)
        _record_draft_backed_remediation_completions(
            state,
            {source: (draft_key,)},
            RemediationCoverageReason.DRAFT_PUBLISHED,
            occurred_at=now,
        )
        state.record_remediation_remote_observation(
            draft_key=draft_key,
            observation="not_found",
            observed_at=now + timedelta(minutes=1),
        )

        for table in (
            "remediation_source_coverage_groups",
            "remediation_source_coverage_members",
            "remediation_remote_observation_events",
        ):
            with pytest.raises(sqlite3.IntegrityError, match="immutable"):
                state._connection.execute(  # noqa: SLF001
                    f"UPDATE {table} SET rowid = rowid"
                )
            with pytest.raises(sqlite3.IntegrityError, match="immutable"):
                state._connection.execute(  # noqa: SLF001
                    f"DELETE FROM {table}"
                )
        triggers = {
            row[0]: row[1]
            for row in state._connection.execute(  # noqa: SLF001
                "SELECT name, sql FROM sqlite_master WHERE type = 'trigger'"
            )
        }
        assert ">= 100" in triggers["remediation_source_members_bounded"]
        assert ">= 10000" in triggers["remediation_source_groups_bounded"]
        assert ">= 10000" in triggers["remediation_remote_observations_bounded"]
        assert "remediation_draft_events_monotonic" in triggers
        assert "remediation_remote_observations_terminal" in triggers
        indexes = {
            row[0]
            for row in state._connection.execute(  # noqa: SLF001
                "SELECT name FROM sqlite_master WHERE type = 'index'"
            )
        }
        assert "remediation_source_coverage_by_completion" in indexes
        assert "remediation_source_coverage_by_draft" in indexes
        assert "remediation_remote_observation_latest" in indexes


def test_v2_draft_identity_binds_policy_digest_and_v1_collision_fails_closed(
    tmp_path: Path,
) -> None:
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
    with GuardianState(tmp_path / "guardian.sqlite3") as state:
        metadata = _remediation_metadata(state, now=now)
        old_sources = tuple(metadata["source_pulls"])
        new_sources = tuple(
            replace(source, policy_digest="9" * 64) for source in old_sources
        )
        for source in new_sources:
            state.record_historical_pull_completion(
                **_source_lookup(source),
                pr_number=source.pr_number,
                head_sha=source.head_sha,
                base_sha=source.base_sha,
                event_revision_ids=_source_revision_ids(state, metadata, source),
                authority_scope=HistoricalCheckScope.ASSESSMENT,
                completed_at=now,
            )
        new_policy_metadata = {**metadata, "source_pulls": new_sources}
        old_v2_key = state.record_remediation_draft_event(
            **metadata,
            phase="validated",
        )
        new_v2_key = state.record_remediation_draft_event(
            **new_policy_metadata,
            phase="validated",
        )
        assert old_v2_key != new_v2_key
        assert (
            state.remediation_draft_by_key(draft_key=old_v2_key).branch_identity_version
            == 2
        )
        assert (
            state.remediation_draft_by_key(draft_key=new_v2_key).branch_identity_version
            == 2
        )

    with GuardianState(tmp_path / "legacy.sqlite3") as state:
        metadata = _remediation_metadata(state, now=now)
        old_sources = tuple(metadata["source_pulls"])
        new_sources = tuple(
            replace(source, policy_digest="9" * 64) for source in old_sources
        )
        for source in new_sources:
            state.record_historical_pull_completion(
                **_source_lookup(source),
                pr_number=source.pr_number,
                head_sha=source.head_sha,
                base_sha=source.base_sha,
                event_revision_ids=_source_revision_ids(state, metadata, source),
                authority_scope=HistoricalCheckScope.ASSESSMENT,
                completed_at=now,
            )
        state.record_remediation_draft_event(
            **metadata,
            branch_identity_version=1,
            phase="validated",
        )
        with pytest.raises(ValueError, match="metadata"):
            state.record_remediation_draft_event(
                **{**metadata, "source_pulls": new_sources},
                branch_identity_version=1,
                phase="validated",
            )


def test_v2_draft_identity_and_evidence_bind_source_authority_digest(
    tmp_path: Path,
) -> None:
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
    with GuardianState(tmp_path / "guardian.sqlite3") as state:
        metadata = _remediation_metadata(state, now=now)
        original_sources = tuple(metadata["source_pulls"])
        changed_sources = (
            replace(original_sources[0], authority_digest="9" * 64),
            original_sources[1],
        )
        changed_evidence_hash = state.validate_historical_remediation_evidence(
            source_pulls=changed_sources,
            event_revision_ids=metadata["event_revision_ids"],
        )
        assert changed_evidence_hash != metadata["evidence_hash"]

        original_key = state.record_remediation_draft_event(
            **metadata,
            phase="validated",
        )
        changed_key = state.record_remediation_draft_event(
            **{
                **metadata,
                "source_pulls": changed_sources,
                "evidence_hash": changed_evidence_hash,
            },
            phase="validated",
        )

        assert changed_key != original_key
        changed = state.remediation_draft_by_key(draft_key=changed_key)
        assert changed is not None
        assert changed.source_pulls == changed_sources
        source_json = state._connection.execute(  # noqa: SLF001
            "SELECT source_pulls_json FROM remediation_draft_events "
            "WHERE draft_key = ? ORDER BY remediation_event_id LIMIT 1",
            (changed_key,),
        ).fetchone()[0]
        assert json.loads(source_json)[0]["authority_digest"] == "9" * 64

        legacy_sources = tuple(
            replace(
                source,
                authority_digest=guardian_state._LEGACY_UNATTESTED_AUTHORITY_DIGEST,
            )
            for source in original_sources
        )
        with pytest.raises(ValueError, match="source_pulls"):
            state.record_remediation_draft_event(
                **{**metadata, "source_pulls": legacy_sources},
                phase="validated",
            )


def test_source_authority_digest_validation_and_coverage_collision(
    tmp_path: Path,
) -> None:
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
    with GuardianState(tmp_path / "guardian.sqlite3") as state:
        metadata = _remediation_metadata(state, now=now)
        source = tuple(metadata["source_pulls"])[0]
        with pytest.raises(ValueError, match="authority_digest"):
            replace(source, authority_digest="not-a-digest")

        state.record_independent_remediation_completion(
            source,
            RemediationCoverageReason.INDEPENDENT_ALREADY_CURRENT,
            event_revision_ids=_source_revision_ids(state, metadata, source),
            occurred_at=now,
        )
        with pytest.raises(RuntimeError, match="authority digest identity collision"):
            state.record_independent_remediation_completion(
                replace(source, authority_digest="9" * 64),
                RemediationCoverageReason.INDEPENDENT_NO_ACTION,
                event_revision_ids=_source_revision_ids(state, metadata, source),
                occurred_at=now + timedelta(minutes=1),
            )


def test_v1_legacy_authority_sentinel_preserves_evidence_and_draft_identity(
    tmp_path: Path,
) -> None:
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
    with GuardianState(tmp_path / "guardian.sqlite3") as state:
        metadata = _remediation_metadata(state, now=now)
        legacy_sources = tuple(
            replace(
                source,
                authority_digest=guardian_state._LEGACY_UNATTESTED_AUTHORITY_DIGEST,
            )
            for source in metadata["source_pulls"]
        )
        urls = tuple(
            sorted(
                state.get_event_revision(revision_id).html_url
                for revision_id in metadata["event_revision_ids"]
            )
        )
        legacy_payload = {
            "feedback_urls": list(urls),
            "source_pulls": [
                {
                    "base_sha": source.base_sha,
                    "head_sha": source.head_sha,
                    "pr_number": source.pr_number,
                    "pull_id": source.pull_id,
                    "pull_revision_digest": source.pull_revision_digest,
                    "repository": source.repository,
                    "repository_id": source.repository_id,
                }
                for source in legacy_sources
            ],
        }
        expected_evidence_hash = hashlib.sha256(
            json.dumps(
                legacy_payload,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
        ).hexdigest()
        evidence_hash = state.validate_historical_remediation_evidence(
            source_pulls=legacy_sources,
            event_revision_ids=metadata["event_revision_ids"],
        )
        assert evidence_hash == expected_evidence_hash
        legacy_metadata = {
            **metadata,
            "source_pulls": legacy_sources,
            "evidence_hash": evidence_hash,
        }
        expected_key_payload = (
            f"{metadata['run_id']}\n{metadata['target_repository']}\n"
            f"{metadata['target_repository_id']}\n{metadata['target_base_branch']}\n"
            f"{metadata['target_base_sha']}\n{metadata['push_repository']}\n"
            f"{metadata['push_repository_id']}\n{metadata['candidate_sha']}\n"
            f"{evidence_hash}\n{metadata['batch_hash']}"
        )

        draft_key = state.record_remediation_draft_event(
            **legacy_metadata,
            branch_identity_version=1,
            phase="validated",
        )

        assert draft_key == hashlib.sha256(expected_key_payload.encode()).hexdigest()
        stored_json = state._connection.execute(  # noqa: SLF001
            "SELECT source_pulls_json FROM remediation_draft_events "
            "WHERE draft_key = ?",
            (draft_key,),
        ).fetchone()[0]
        assert all(
            "authority_digest" not in source for source in json.loads(stored_json)
        )


def test_v4_migration_keeps_unattested_completion_upgradeable_and_is_idempotent(
    tmp_path: Path,
) -> None:
    """Preserve upgradeable legacy completion evidence across repeated migrations."""
    database = tmp_path / "guardian.sqlite3"
    _create_v4_migration_fixture(database)
    (
        quarantined_key,
        quarantined_source,
        checkpointed_key,
        checkpointed_source,
        unattested_source,
    ) = _populate_v4_remediation_fixture(database)

    with GuardianState(database) as state:
        quarantined = state.remediation_draft_by_key(draft_key=quarantined_key)
        checkpointed = state.remediation_draft_by_key(draft_key=checkpointed_key)
        assert quarantined is not None
        assert checkpointed is not None
        assert quarantined.branch_identity_version == 1
        assert checkpointed.branch_identity_version == 1
        assert (
            state.remediation_resolution(draft_key=quarantined_key)
            == "operator_quarantined"
        )
        assert state.latest_remediation_remote_observation(quarantined_key) is None
        assert state.latest_remediation_remote_observation(checkpointed_key) is None

        assert state.historical_pull_is_complete(
            **_source_lookup(quarantined_source),
            authority_scope=HistoricalCheckScope.REMEDIATION,
        )
        assert state.historical_pull_is_complete(
            **_source_lookup(quarantined_source),
            authority_scope=HistoricalCheckScope.ASSESSMENT,
        )
        for source in (quarantined_source, checkpointed_source):
            assert not state.historical_pull_is_complete(
                **_source_lookup(source),
                authority_scope=HistoricalCheckScope.PREVENTION,
            )
        for scope in (
            HistoricalCheckScope.REMEDIATION,
            HistoricalCheckScope.ASSESSMENT,
        ):
            assert not state.historical_pull_is_complete(
                **_source_lookup(checkpointed_source),
                authority_scope=scope,
            )
        for scope in (
            HistoricalCheckScope.REMEDIATION,
            HistoricalCheckScope.ASSESSMENT,
        ):
            assert not state.historical_pull_is_complete(
                **_source_lookup(unattested_source),
                authority_scope=scope,
            )

        quarantined_coverage = state.remediation_source_coverage_for_draft(
            quarantined_key
        )
        checkpointed_coverage = state.remediation_source_coverage_for_draft(
            checkpointed_key
        )
        assert len(quarantined_coverage) == 1
        assert checkpointed_coverage == ()
        assert quarantined_coverage[0].reason is (
            RemediationCoverageReason.MIGRATED_LEGACY
        )
        assert quarantined_coverage[0].effective is True
        migration_counts = (
            state._connection.execute(  # noqa: SLF001
                "SELECT COUNT(*) FROM historical_pull_completions "
                "WHERE authority_scope = 'remediation'"
            ).fetchone()[0],
            state._connection.execute(  # noqa: SLF001
                "SELECT COUNT(*) FROM remediation_source_coverage_groups"
            ).fetchone()[0],
            state._connection.execute(  # noqa: SLF001
                "SELECT COUNT(*) FROM remediation_source_coverage_members"
            ).fetchone()[0],
        )
        assert migration_counts == (3, 1, 1)

        attested_source = replace(
            checkpointed_source,
            authority_digest="7" * 64,
        )
        upgraded = state.record_independent_remediation_completion(
            attested_source,
            RemediationCoverageReason.INDEPENDENT_ALREADY_CURRENT,
            event_revision_ids=checkpointed.event_revision_ids,
            occurred_at=datetime(2026, 9, 1, 12, 0, tzinfo=UTC),
        )
        assert upgraded.source == attested_source
        assert upgraded.effective is True
        assert state.historical_pull_is_complete(
            **_source_lookup(attested_source),
            authority_scope=HistoricalCheckScope.REMEDIATION,
        )
        counts = (
            state._connection.execute(  # noqa: SLF001
                "SELECT COUNT(*) FROM historical_pull_completions "
                "WHERE authority_scope = 'remediation'"
            ).fetchone()[0],
            state._connection.execute(  # noqa: SLF001
                "SELECT COUNT(*) FROM remediation_source_coverage_groups"
            ).fetchone()[0],
            state._connection.execute(  # noqa: SLF001
                "SELECT COUNT(*) FROM remediation_source_coverage_members"
            ).fetchone()[0],
        )
        assert counts == (3, 2, 1)

    with GuardianState(database) as state:
        assert (
            state._connection.execute(  # noqa: SLF001
                "PRAGMA user_version"
            ).fetchone()[0]
            == 11
        )
        assert "branch_identity_version" in {
            row["name"]
            for row in state._connection.execute(  # noqa: SLF001
                "PRAGMA table_info(remediation_draft_events)"
            )
        }
        reopened_counts = (
            state._connection.execute(  # noqa: SLF001
                "SELECT COUNT(*) FROM historical_pull_completions "
                "WHERE authority_scope = 'remediation'"
            ).fetchone()[0],
            state._connection.execute(  # noqa: SLF001
                "SELECT COUNT(*) FROM remediation_source_coverage_groups"
            ).fetchone()[0],
            state._connection.execute(  # noqa: SLF001
                "SELECT COUNT(*) FROM remediation_source_coverage_members"
            ).fetchone()[0],
        )
        assert reopened_counts == counts


@pytest.mark.parametrize(
    "malformation",
    (
        "phase-sequence",
        "skipped-pushed",
        "time-regression",
        "identity",
        "run-authority",
        "post-resolution",
    ),
)
def test_migration_rejects_malformed_legacy_remediation_history(
    tmp_path: Path,
    malformation: str,
) -> None:
    database = tmp_path / "guardian.sqlite3"
    _create_v4_migration_fixture(database)
    run_id = "00000000-0000-4000-8000-000000000099"
    with sqlite3.connect(database) as connection:
        connection.execute(
            "INSERT INTO runs VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                run_id,
                "other/widgets" if malformation == "run-authority" else "acme/widgets",
                "ru",
                GuardianMode.PROPOSE_PREVENTION.value,
                "completed",
                "2026-08-30T12:00:00.000000Z",
                "2026-08-30T12:01:00.000000Z",
                "legacy audit fixture",
            ),
        )

        def insert(
            phase: str,
            *,
            body: str = "Legacy body\n",
            occurred_at: str = "2026-08-30T12:00:00.000000Z",
        ) -> None:
            connection.execute(
                """
                INSERT INTO remediation_draft_events (
                    draft_key, run_id, target_repository, target_repository_id,
                    target_base_branch, target_base_sha, push_repository,
                    push_repository_id, branch, candidate_sha, evidence_hash,
                    batch_hash, source_pulls_json, event_revision_ids_json,
                    title, body, phase, draft_number, draft_url, occurred_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    "a" * 64,
                    run_id,
                    "acme/widgets",
                    42,
                    "main",
                    "a" * 40,
                    "localize-bot/widgets",
                    84,
                    "guardian/remediation-audit",
                    "c" * 40,
                    "d" * 64,
                    "e" * 64,
                    "[]",
                    "[]",
                    "Legacy remediation audit",
                    body,
                    phase,
                    None,
                    None,
                    occurred_at,
                ),
            )

        if malformation == "phase-sequence":
            insert("pushed")
        elif malformation == "time-regression":
            insert("validated", occurred_at="2026-08-30T12:02:00.000000Z")
            insert("pushed", occurred_at="2026-08-30T12:01:00.000000Z")
        else:
            insert("validated")
            if malformation == "skipped-pushed":
                insert("draft_opened")
            elif malformation == "identity":
                insert("pushed", body="Changed legacy body\n")
            elif malformation == "post-resolution":
                connection.execute(
                    "INSERT INTO remediation_resolution_events "
                    "(draft_key, resolution, occurred_at) VALUES (?, ?, ?)",
                    (
                        "a" * 64,
                        "operator_quarantined",
                        "2026-08-30T12:01:00.000000Z",
                    ),
                )
                insert("pushed", occurred_at="2026-08-30T12:02:00.000000Z")

    expected = {
        "phase-sequence": "invalid legacy phase sequence",
        "skipped-pushed": "invalid legacy phase sequence",
        "time-regression": "invalid legacy phase sequence",
        "identity": "conflicting legacy identity",
        "run-authority": "invalid legacy run authority",
        "post-resolution": "appended after a legacy resolution",
    }[malformation]
    with pytest.raises(RuntimeError, match=expected):
        GuardianState(database)
    with sqlite3.connect(database) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 4
        columns = {
            row[1]
            for row in connection.execute("PRAGMA table_info(remediation_draft_events)")
        }
        assert "branch_identity_version" not in columns


def test_migration_rejects_malformed_non_v1_prevention_sequence(
    tmp_path: Path,
) -> None:
    database = tmp_path / "guardian.sqlite3"
    with GuardianState(database) as state:
        run_id = state.start_run(
            repository="acme/widgets",
            locale="ru",
            mode=GuardianMode.PROPOSE_PREVENTION,
            started_at=datetime(2026, 8, 30, 12, 0, tzinfo=UTC),
        )
        state._connection.execute(  # noqa: SLF001 - pre-v8 fixture downgrade
            "DROP TRIGGER prevention_draft_events_require_validated"
        )
        state._connection.execute(  # noqa: SLF001 - pre-v8 corruption fixture
            """
            INSERT INTO prevention_draft_events (
                draft_key, run_id, source_repository, target_repository,
                target_base_branch, target_base_sha, push_repository, branch,
                candidate_sha, evidence_hash, title, body, phase, draft_number,
                draft_url, occurred_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "a" * 64,
                run_id,
                "acme/widgets",
                "guardian/pipeline",
                "main",
                "a" * 40,
                "guardian/pipeline",
                "guardian/prevention-audit",
                "c" * 40,
                "d" * 64,
                "Legacy prevention audit",
                "Legacy body\n",
                "pushed",
                None,
                None,
                "2026-08-30T12:00:00.000000Z",
            ),
        )
        state._connection.execute("PRAGMA user_version = 7")  # noqa: SLF001
        state._connection.commit()  # noqa: SLF001

    with pytest.raises(RuntimeError, match="invalid legacy phase sequence"):
        GuardianState(database)
    with sqlite3.connect(database) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 7


def test_state_startup_rejects_foreign_key_violations(tmp_path: Path) -> None:
    database = tmp_path / "guardian.sqlite3"
    with GuardianState(database):
        pass
    with sqlite3.connect(database) as connection:
        connection.execute("PRAGMA foreign_keys = OFF")
        connection.execute(
            """
            INSERT INTO actions (
                run_id, event_revision_id, action, status,
                details_json, occurred_at
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                "missing-run",
                999,
                GuardianMode.OBSERVE.value,
                "completed",
                "{}",
                "2026-08-30T12:00:00.000000Z",
            ),
        )

    with pytest.raises(RuntimeError, match="foreign-key violation"):
        GuardianState(database)


def test_bounded_quick_check_failure_is_rejected() -> None:
    class Cursor:
        def __init__(self, row: tuple[str] | None) -> None:
            self._row = row

        def fetchone(self) -> tuple[str] | None:
            return self._row

    class Connection:
        def execute(self, query: str) -> Cursor:
            return Cursor(None if query == "PRAGMA foreign_key_check" else ("bad",))

    state = object.__new__(GuardianState)
    state._connection = Connection()  # type: ignore[assignment]  # noqa: SLF001
    with pytest.raises(RuntimeError, match="quick_check"):
        state._verify_database_integrity()  # noqa: SLF001


def test_v4_migration_failure_rolls_back_every_schema_change(tmp_path: Path) -> None:
    database = tmp_path / "guardian.sqlite3"
    _create_v4_migration_fixture(database)
    run_id = "00000000-0000-4000-8000-000000000005"
    with sqlite3.connect(database) as connection:
        connection.execute(
            "INSERT INTO runs VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                run_id,
                "acme/widgets",
                "ru",
                GuardianMode.PROPOSE_PREVENTION.value,
                "completed",
                "2026-08-30T12:00:00.000000Z",
                "2026-08-30T12:01:00.000000Z",
                "malformed migration fixture",
            ),
        )
        connection.execute(
            """
            INSERT INTO remediation_draft_events (
                draft_key, run_id, target_repository, target_repository_id,
                target_base_branch, target_base_sha, push_repository,
                push_repository_id, branch, candidate_sha, evidence_hash,
                batch_hash, source_pulls_json, event_revision_ids_json,
                title, body, phase, draft_number, draft_url, occurred_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "a" * 64,
                run_id,
                "acme/widgets",
                42,
                "main",
                "a" * 40,
                "localize-bot/widgets",
                84,
                "guardian/remediation-malformed",
                "c" * 40,
                "d" * 64,
                "e" * 64,
                "{malformed",
                "[]",
                "Malformed legacy remediation",
                "Malformed body\n",
                "validated",
                None,
                None,
                "2026-08-30T12:00:00.000000Z",
            ),
        )
        connection.execute(
            """
            INSERT INTO remediation_checkpoint_events (draft_key, occurred_at)
            VALUES (?, ?)
            """,
            ("a" * 64, "2026-08-30T12:01:00.000000Z"),
        )

    with pytest.raises(RuntimeError, match="malformed data"):
        GuardianState(database)

    with sqlite3.connect(database) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 4
        columns = {
            row[1]
            for row in connection.execute("PRAGMA table_info(remediation_draft_events)")
        }
        assert "branch_identity_version" not in columns
        assert (
            connection.execute(
                """
            SELECT 1 FROM sqlite_master
            WHERE type = 'table' AND name = 'remediation_source_coverage_groups'
            """
            ).fetchone()
            is None
        )


def test_required_edit_provenance_keeps_partial_source_eligible(
    tmp_path: Path,
) -> None:
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
    first_edit = "1" * 64
    second_edit = "2" * 64
    required = (first_edit, second_edit)
    with GuardianState(tmp_path / "guardian.sqlite3") as state:
        first_metadata = _remediation_metadata(
            state,
            now=now,
            edit_hashes=(first_edit,),
        )
        source = tuple(first_metadata["source_pulls"])[0]
        first_key = _open_remediation_draft(state, first_metadata, draft_number=91)

        first_group = state.record_draft_backed_remediation_completions(
            {source: (first_key,)},
            RemediationCoverageReason.DRAFT_PUBLISHED,
            required_edit_hashes_by_source={source: required},
            checkpoint_draft_key=first_key,
            occurred_at=now,
        )[0]

        assert first_group.required_edit_hashes == required
        assert first_group.effective is False
        assert not state.historical_pull_is_complete(
            **_source_lookup(source),
            authority_scope=HistoricalCheckScope.REMEDIATION,
        )

        second_metadata = _remediation_metadata(
            state,
            now=now + timedelta(minutes=1),
            edit_hashes=(second_edit,),
        )
        second_metadata["branch"] = "guardian/remediation-" + "3" * 64
        second_key = _open_remediation_draft(
            state,
            second_metadata,
            draft_number=92,
        )
        completed = state.record_draft_backed_remediation_completions(
            {source: tuple(sorted((first_key, second_key)))},
            RemediationCoverageReason.DRAFT_PUBLISHED,
            required_edit_hashes_by_source={source: required},
            checkpoint_draft_key=second_key,
            occurred_at=now + timedelta(minutes=1),
        )[0]

        assert completed.required_edit_hashes == required
        assert completed.effective is True
        assert state.historical_pull_is_complete(
            **_source_lookup(source),
            authority_scope=HistoricalCheckScope.REMEDIATION,
        )


def test_feedback_and_publication_recovery_reads_are_bounded_worksets(
    tmp_path: Path,
) -> None:
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
    with GuardianState(tmp_path / "guardian.sqlite3") as state:
        run_id = state.start_run(
            repository="acme/widgets",
            locale="ru",
            mode=GuardianMode.APPLY_OWNED_TRANSLATIONS,
            started_at=now,
        )
        revisions = tuple(
            state.record_feedback_event(
                _event(pr_number=12, event_id=str(10_000 + index)),
                observed_at=now,
            )
            for index in range(501)
        )
        for index, revision in enumerate(revisions[:101]):
            state.record_publication_event(
                run_id=run_id,
                repository="acme/widgets",
                pr_number=12,
                original_head_sha="a" * 40,
                base_sha="b" * 40,
                commit_sha=f"{index + 1:040x}",
                publication_actor_id=303,
                publication_actor_type="Bot",
                event_revision_ids=(revision.revision_id,),
                open_source=OpenPullAuthorityReference(
                    repository="acme/widgets",
                    repository_id=42,
                    pull_id=500,
                    pr_number=12,
                    authority_digest=f"{index + 1:064x}",
                    head_sha="a" * 40,
                    base_sha="b" * 40,
                    feedback_digest=f"{index + 102:064x}",
                ),
                phase="prepared",
                completion_actions=(
                    (revision.revision_id, "completed", {"outcome": "applied"}),
                ),
                occurred_at=now,
            )

        pending = state.pending_event_revisions(
            repository="acme/widgets",
            pr_number=12,
        )
        publications = state.pending_publications(repository="acme/widgets")

        assert len(pending) == 500
        assert pending[0].revision_id == revisions[0].revision_id
        assert pending[-1].revision_id == revisions[499].revision_id
        assert len(publications) == 100


def test_latest_feedback_authority_fails_closed_above_github_pull_bound(
    tmp_path: Path,
) -> None:
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
    with GuardianState(tmp_path / "guardian.sqlite3") as state:
        for index in range(501):
            state.record_feedback_event(
                _event(pr_number=12, event_id=str(20_000 + index)),
                observed_at=now,
            )


def test_historical_current_authority_uses_a_501_row_overflow_sentinel(
    tmp_path: Path,
) -> None:
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
    with GuardianState(tmp_path / "guardian.sqlite3") as state:
        revisions = tuple(
            state.record_feedback_event(
                _event(pr_number=12, event_id=str(30_000 + index)),
                observed_at=now,
            )
            for index in range(500)
        )
        source = HistoricalPullReference(
            repository="acme/widgets",
            repository_id=42,
            pull_id=500,
            pr_number=12,
            pull_revision_digest="1" * 64,
            authority_digest="4" * 64,
            policy_digest="2" * 64,
            head_sha="a" * 40,
            base_sha="b" * 40,
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
            event_revision_ids=(revisions[0].revision_id,),
            ignored_event_revision_ids=tuple(
                revision.revision_id for revision in revisions[1:]
            ),
            authority_scope=HistoricalCheckScope.ASSESSMENT,
            completed_at=now,
        )
        state.record_feedback_event(
            _event(pr_number=12, event_id="30500"),
            observed_at=now,
        )

        with pytest.raises(RuntimeError, match="Historical current feedback.*bound"):
            state.validate_current_historical_remediation_evidence(
                source_pulls=(source,),
                event_revision_ids=(revisions[0].revision_id,),
            )

        with pytest.raises(RuntimeError, match="current feedback.*bound"):
            state.latest_event_revisions(
                repository="acme/widgets",
                pr_number=12,
            )


def test_remediation_recovery_rotation_uses_one_mutable_cursor_per_draft(
    tmp_path: Path,
) -> None:
    database = tmp_path / "guardian.sqlite3"
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
    with GuardianState(database) as state:
        metadata = _remediation_metadata(state, now=now)
        draft_key = state.record_remediation_draft_event(
            **metadata,
            phase="validated",
        )
        state._connection.execute(
            "INSERT INTO remediation_recovery_attempt_events "
            "(draft_key, occurred_at) VALUES (?, ?), (?, ?)",
            (
                draft_key,
                "2026-08-30T12:01:00.000000Z",
                draft_key,
                "2026-08-30T12:02:00.000000Z",
            ),
        )
        state._connection.commit()

    with GuardianState(database) as state:
        cursor = state._connection.execute(
            "SELECT recovery_rank, occurred_at "
            "FROM remediation_recovery_cursors WHERE draft_key = ?",
            (draft_key,),
        ).fetchone()
        assert cursor is not None
        assert tuple(cursor) == (2, "2026-08-30T12:02:00.000000Z")

        state.record_remediation_recovery_attempt(
            draft_key=draft_key,
            occurred_at=now + timedelta(minutes=3),
        )
        assert (
            state._connection.execute(
                "SELECT COUNT(*) FROM remediation_recovery_attempt_events"
            ).fetchone()[0]
            == 2
        )
        assert (
            state._connection.execute(
                "SELECT COUNT(*) FROM remediation_recovery_cursors"
            ).fetchone()[0]
            == 1
        )


def test_remediation_source_authority_rejects_more_than_one_hundred_pulls(
    tmp_path: Path,
) -> None:
    now = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
    with GuardianState(tmp_path / "guardian.sqlite3") as state:
        metadata = _remediation_metadata(state, now=now)
        source = tuple(metadata["source_pulls"])[0]

        with pytest.raises(ValueError, match="source_pulls.*bounded"):
            state.record_remediation_draft_event(
                **{
                    **metadata,
                    "source_pulls": tuple(source for _ in range(101)),
                },
                phase="validated",
            )
