"""Bounded orchestration coverage for opt-in closed-PR assessment."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
import json

from localize.guardian.evidence import build_evidence_bundle
from localize.guardian.github import ChangedFile
from localize.guardian.models import GuardianMode
from localize.guardian.state import GuardianState
from tests.unit.test_guardian_controller import (
    FakeBroker,
    FakeCheckoutFactory,
    FakeCodexDriver,
    FakeCurrentBaseProvider,
    FakeHistoricalCheckoutFactory,
    FakeHistoricalSnapshotProvider,
    FakeSnapshotProvider,
    SECOND_TARGET_PATH,
    TARGET_PATH,
    _add_second_localization_target,
    _config,
    _controller,
    _feedback,
    _historical_policy,
    _pull,
    _snapshot,
    _write_tree,
)


def test_open_phase_precedes_observe_history_using_current_values_without_writes(
    tmp_path: Path,
) -> None:
    """Exercise real state/evidence/controller logic around mocked I/O edges."""

    current = tmp_path / "current"
    old_base = tmp_path / "old-base"
    old_head = tmp_path / "old-head"
    for tree in (current, old_base, old_head):
        tree.mkdir()
        _write_tree(tree)
    (old_base / TARGET_PATH).write_text(
        "greeting=Историческая база %0 (%1). %2 %3\n",
        encoding="utf-8",
    )
    (old_head / TARGET_PATH).write_text(
        "greeting=Историческая ветка %0 (%1). %2 %3\n",
        encoding="utf-8",
    )

    sequence: list[str] = []

    class OrderedOpenProvider(FakeSnapshotProvider):
        def __call__(self, policy, previous_feedback):
            sequence.append("open-discovery")
            return super().__call__(policy, previous_feedback)

    open_provider = OrderedOpenProvider((_snapshot(),))
    closed_pull = _pull(state="closed", pull_id=501, number=13)
    closed = _snapshot(
        pull=closed_pull,
        feedback=(_feedback(pull_number=13, source_id="45"),),
        changed_files=(
            ChangedFile(
                path=TARGET_PATH,
                status="modified",
                sha="d" * 40,
                patch="@@ -1 +1 @@\n-historical-old\n+historical-new",
            ),
        ),
    )
    history_provider = FakeHistoricalSnapshotProvider(
        (closed,),
        sequence=sequence,
    )
    checkout = FakeCheckoutFactory(current, old_head, tmp_path, sequence)
    historical_checkout = FakeHistoricalCheckoutFactory(
        old_base,
        old_head,
        tmp_path,
        sequence=sequence,
    )
    current_provider = FakeCurrentBaseProvider(sequence=sequence)
    broker = FakeBroker(sequence)
    driver = FakeCodexDriver()
    evidence: list[tuple[str, str, str]] = []

    def evidence_spy(**kwargs):
        bundle = build_evidence_bundle(**kwargs)
        localization = json.loads(
            (bundle.root / "localization.json").read_text(encoding="utf-8")
        )
        values = localization[0]["entries"]["greeting"]
        evidence.append(
            (kwargs["diff_text"], values["source"], values["target"])
        )
        return bundle

    policy = _historical_policy()
    with GuardianState(tmp_path / "state.sqlite3") as state:
        controller = _controller(
            tmp_path=tmp_path,
            state=state,
            config=_config(GuardianMode.OBSERVE, policies=(policy,)),
            checkout=checkout,
            provider=open_provider,
            driver=driver,
            broker=broker,
            historical_snapshot_provider=history_provider,
            historical_checkout_factory=historical_checkout,
            current_base_provider=current_provider,
            evidence_builder=evidence_spy,
        )
        convert = controller.assessment_converter
        conversion_scopes = []

        def authorized_conversion(*args, **kwargs):
            """Require explicit locale authority on both open and historical paths."""
            conversion_scopes.append(kwargs.get("target_locales_by_feedback"))
            assert kwargs["target_locales_by_feedback"]
            return convert(*args, **kwargs)

        controller.assessment_converter = authorized_conversion
        outcome = controller.poll_once()
        assert len(conversion_scopes) == 2
        assert conversion_scopes[1]["review_comment:45"][TARGET_PATH] == "ru"

    assert sequence.index("open-discovery") < sequence.index(
        "history:acme/widgets"
    )
    assert outcome.pull_requests_seen == 1
    assert outcome.historical_pull_requests_seen == 1
    assert outcome.historical_pull_requests_completed == 1
    assert "historical-old" in evidence[1][0]
    assert evidence[1][1:] == (
        "Push to %0 was rejected (%1). %2 %3",
        "Старый %0 был отклонён (%1). %2 %3",
    )
    assert historical_checkout.revisions[1].fetch_target == "refs/pull/13/head"
    assert broker.verify_calls == []
    assert broker.reply_calls == []
    assert all(
        workspace.commits == 0 and workspace.publications == 0
        for workspace in checkout.workspaces
    )


def test_mixed_current_targets_assess_valid_feedback_and_checkpoint_invalid(
    tmp_path: Path,
) -> None:
    current = tmp_path / "current"
    old_base = tmp_path / "old-base"
    old_head = tmp_path / "old-head"
    for tree in (current, old_base, old_head):
        tree.mkdir()
        _write_tree(tree)
        _add_second_localization_target(tree)
    (current / SECOND_TARGET_PATH).unlink()

    closed = _snapshot(
        pull=_pull(state="closed"),
        feedback=(
            _feedback(),
            replace(_feedback(source_id="45"), path=SECOND_TARGET_PATH),
        ),
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
    history_provider = FakeHistoricalSnapshotProvider((closed,))
    checkout = FakeCheckoutFactory(current, old_head, tmp_path, [])
    historical_checkout = FakeHistoricalCheckoutFactory(
        old_base,
        old_head,
        tmp_path,
    )
    driver = FakeCodexDriver()
    captured: list[tuple[tuple[str, ...], tuple[str, ...]]] = []

    def evidence_spy(**kwargs):
        bundle = build_evidence_bundle(**kwargs)
        manifest = json.loads(
            (bundle.root / "manifest.json").read_text(encoding="utf-8")
        )
        localization = json.loads(
            (bundle.root / "localization.json").read_text(encoding="utf-8")
        )
        captured.append(
            (
                tuple(manifest["feedback_ids"]),
                tuple(item["path"] for item in localization),
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
            broker=FakeBroker([]),
            historical_snapshot_provider=history_provider,
            historical_checkout_factory=historical_checkout,
            current_base_provider=FakeCurrentBaseProvider(),
            evidence_builder=evidence_spy,
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

    assert first.historical_pull_requests_completed == 1
    assert second.historical_pull_requests_seen == 0
    assert captured == [(("review_comment:44",), (TARGET_PATH,))]
    assert [
        (row["event_id"], row["status"], json.loads(row["details_json"])["outcome"])
        for row in actions
    ] == [
        ("44", "completed", "historical_assessed"),
        ("45", "skipped", "historical_target_inapplicable"),
    ]
