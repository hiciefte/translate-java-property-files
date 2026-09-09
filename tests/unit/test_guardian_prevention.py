from __future__ import annotations

import os
from pathlib import Path
import shutil

import pytest

from localize.guardian.deadline import PollDeadline, PollDeadlineExceeded
from localize.guardian.prevention import (
    DraftPreventionPlan,
    DuplicatePreventionCandidateError,
    PreventionPolicyError,
    TestCommandResult,
    TestOutcome,
    plan_prevention_draft,
)


BASE_SHA = "a" * 40
PATCHED_SHA = "b" * 40
TEST_OVERLAY_HASH = "63fc72e23d93e0e514d89ef953479860fb4af3253abfa00294dbcf6764303440"


class _TickingClock:
    def __init__(self, step: float) -> None:
        self.value = 0.0
        self.step = step

    def __call__(self) -> float:
        current = self.value
        self.value += self.step
        return current


def _workspaces(tmp_path: Path) -> tuple[Path, Path]:
    base = tmp_path / "base"
    candidate = tmp_path / "candidate"
    (base / "localize").mkdir(parents=True)
    (base / "tests/unit").mkdir(parents=True)
    (base / "localize/rules.py").write_text(
        "def preserve(value):\n    return value\n",
        encoding="utf-8",
    )
    (base / "tests/unit/test_rules.py").write_text(
        "def test_preserve():\n    assert True\n",
        encoding="utf-8",
    )
    (base / "README.md").write_text("example\n", encoding="utf-8")
    shutil.copytree(base, candidate)
    (candidate / "localize/rules.py").write_text(
        "def preserve(value):\n    return value.strip()\n",
        encoding="utf-8",
    )
    (candidate / "tests/unit/test_rules.py").write_text(
        "def test_preserve():\n    assert preserve(' value ') == 'value'\n",
        encoding="utf-8",
    )
    return base, candidate


def _result(
    phase: str,
    outcome: TestOutcome,
    *,
    argv: tuple[str, ...] = ("venv/bin/pytest", "tests/unit/test_rules.py", "-q"),
    commit_sha: str | None = None,
    parent_sha: str | None = None,
    returncode: int | None = None,
    focused: bool = True,
) -> TestCommandResult:
    if commit_sha is None:
        commit_sha = BASE_SHA if phase == "base" else PATCHED_SHA
    if parent_sha is None and phase == "patched":
        parent_sha = BASE_SHA
    if returncode is None:
        returncode = 0 if outcome is TestOutcome.PASSED else 1
    return TestCommandResult(
        phase=phase,
        outcome=outcome,
        argv=argv,
        commit_sha=commit_sha,
        parent_sha=parent_sha,
        returncode=returncode,
        test_overlay_hash=TEST_OVERLAY_HASH,
        focused=focused,
    )


def _plan(tmp_path: Path, **overrides: object) -> DraftPreventionPlan:
    base, candidate = _workspaces(tmp_path)
    values: dict[str, object] = {
        "base_workspace": base,
        "candidate_workspace": candidate,
        "allowed_code_path_globs": ("localize/*.py",),
        "allowed_test_path_globs": ("tests/**/*.py",),
        "exact_base_sha": BASE_SHA,
        "root_cause": "Placeholder validation omitted one token family",
        "evidence_feedback_ids": (
            "review_comment:42:revision-a",
            "issue_comment:84:revision-b",
        ),
        "max_changed_files": 4,
        "test_results": (
            _result("base", TestOutcome.FAILED),
            _result("patched", TestOutcome.PASSED),
        ),
    }
    values.update(overrides)
    return plan_prevention_draft(**values)


def test_builds_deterministic_side_effect_free_draft_plan(tmp_path):
    plan = _plan(tmp_path)

    assert isinstance(plan, DraftPreventionPlan)
    assert plan.paths == (
        "localize/rules.py",
        "tests/unit/test_rules.py",
    )
    assert plan.base_sha == BASE_SHA
    assert plan.candidate_sha == PATCHED_SHA
    assert len(plan.evidence_hash) == 64
    assert plan.title == (
        "Prevent recurrence: Placeholder validation omitted one token family"
    )
    assert "failed on the exact base" in plan.body
    assert "passed on its direct child" in plan.body
    assert "review_comment:42:revision-a" in plan.body
    assert "publish only this signed candidate" in plan.body
    assert "cannot merge or deploy" in plan.body


def test_draft_plan_checks_deadline_during_recursive_inventory(tmp_path: Path) -> None:
    deadline = PollDeadline(0.2, clock=_TickingClock(0.05))

    with pytest.raises(PollDeadlineExceeded):
        _plan(tmp_path, deadline=deadline)


def test_hash_is_stable_across_whitespace_and_evidence_order(tmp_path):
    first = _plan(tmp_path / "first")
    second = _plan(
        tmp_path / "second",
        root_cause="  PLACEHOLDER\n validation omitted   one token family  ",
        evidence_feedback_ids=(
            "issue_comment:84:revision-b",
            "review_comment:42:revision-a",
        ),
    )

    assert first.evidence_hash == second.evidence_hash


def test_untrusted_root_cause_cannot_inject_markdown_or_mentions(tmp_path):
    plan = _plan(
        tmp_path,
        root_cause="@maintainers [click](https://attacker.invalid)",
    )

    assert "@maintainers" not in plan.title
    assert "@maintainers" not in plan.body
    assert "[click](https://attacker.invalid)" not in plan.body


@pytest.mark.parametrize("executable", [
    "/Users/private-operator/runtime/bin/pytest",
    "/home/private-operator/bin/custom-private-runner",
    "C:\\Users\\private-operator\\Scripts\\pytest.exe",
])
def test_public_regression_proof_never_contains_operator_argv(tmp_path, executable):
    """Keep host paths and arbitrary command arguments in the private audit only."""
    argv = (executable, "--cache-dir=/private/operator-cache", "private-argument")
    results = (
        _result("base", TestOutcome.FAILED, argv=argv),
        _result("patched", TestOutcome.PASSED, argv=argv),
    )
    plan = _plan(tmp_path, test_results=results)
    for private_text in ("private-operator", "/private/", "private-argument", "custom-private-runner"):
        assert private_text not in plan.body
    assert "command fingerprint" in plan.body
    assert "private audit" in plan.body
    assert results[0].argv == argv


def test_generated_draft_text_has_deterministic_utf8_byte_bounds(tmp_path):
    large_argument = "界" * 1365
    commands = tuple(
        (f"/opt/localize-guardian/bin/check-{index}", large_argument)
        for index in range(64)
    )
    results = tuple(
        result
        for argv in commands
        for result in (
            _result("base", TestOutcome.FAILED, argv=argv),
            _result("patched", TestOutcome.PASSED, argv=argv),
        )
    )
    feedback_ids = tuple(f"review_comment:{index}:" + "a" * 220 for index in range(100))

    first = _plan(
        tmp_path / "first",
        root_cause="界" * 500,
        evidence_feedback_ids=feedback_ids,
        test_results=results,
    )
    second = _plan(
        tmp_path / "second",
        root_cause="界" * 500,
        evidence_feedback_ids=feedback_ids,
        test_results=results,
    )

    assert first.title == second.title
    assert first.body == second.body
    assert len(first.title) <= 120
    assert len(first.title.encode("utf-8")) <= 256
    assert len(first.body.encode("utf-8")) <= 60 * 1024
    assert "full-list fingerprint" in first.body
    assert "additional item" in first.body


def test_rejects_a_previously_seen_root_cause_and_evidence_hash(tmp_path):
    original = _plan(tmp_path / "original")

    with pytest.raises(DuplicatePreventionCandidateError, match="already planned"):
        _plan(
            tmp_path / "duplicate",
            known_evidence_hashes=(original.evidence_hash,),
        )


@pytest.mark.parametrize(
    "changed_path",
    [
        "README.md",
        ".github/workflows/publish.yml",
        "localize/unexpected.txt",
    ],
)
def test_rejects_every_changed_path_outside_code_and_test_allowlists(
    tmp_path,
    changed_path,
):
    base, candidate = _workspaces(tmp_path)
    path = candidate / changed_path
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("changed\n", encoding="utf-8")

    with pytest.raises(PreventionPolicyError, match="outside the allowed"):
        _plan(tmp_path / "unused", base_workspace=base, candidate_workspace=candidate)


def test_single_segment_glob_does_not_authorize_nested_paths(tmp_path):
    base, candidate = _workspaces(tmp_path)
    nested = candidate / "localize/nested/extra.py"
    nested.parent.mkdir()
    nested.write_text("unexpected = True\n", encoding="utf-8")

    with pytest.raises(PreventionPolicyError, match="outside the allowed"):
        _plan(
            tmp_path / "unused",
            base_workspace=base,
            candidate_workspace=candidate,
            allowed_code_path_globs=("localize/*.py",),
        )


@pytest.mark.parametrize(
    "globs",
    [
        ("../localize/*.py",),
        ("/tmp/*.py",),
        ("localize\\*.py",),
        (".git/**",),
    ],
)
def test_rejects_unsafe_allowlist_globs(tmp_path, globs):
    with pytest.raises(PreventionPolicyError, match="glob"):
        _plan(tmp_path, allowed_code_path_globs=globs)


def test_rejects_changed_file_and_directory_symlinks(tmp_path):
    base, candidate = _workspaces(tmp_path / "file")
    target = candidate / "localize/rules.py"
    target.unlink()
    target.symlink_to(candidate / "README.md")

    with pytest.raises(PreventionPolicyError, match="symbolic link"):
        _plan(
            tmp_path / "file-unused",
            base_workspace=base,
            candidate_workspace=candidate,
        )

    base, candidate = _workspaces(tmp_path / "directory")
    shutil.rmtree(candidate / "tests")
    (candidate / "tests").symlink_to(candidate / "localize", target_is_directory=True)

    with pytest.raises(PreventionPolicyError, match="symbolic link"):
        _plan(
            tmp_path / "directory-unused",
            base_workspace=base,
            candidate_workspace=candidate,
        )


def test_rejects_hard_linked_files_that_bypass_workspace_containment(tmp_path):
    base, candidate = _workspaces(tmp_path)
    outside = tmp_path / "outside.py"
    outside.write_text("sensitive = True\n", encoding="utf-8")
    target = candidate / "localize/rules.py"
    target.unlink()
    os.link(outside, target)

    with pytest.raises(PreventionPolicyError, match="hard-linked"):
        _plan(
            tmp_path / "unused",
            base_workspace=base,
            candidate_workspace=candidate,
        )


def test_rejects_symlinked_or_overlapping_workspace_roots(tmp_path):
    base, candidate = _workspaces(tmp_path / "roots")
    linked = tmp_path / "linked"
    linked.symlink_to(candidate, target_is_directory=True)

    with pytest.raises(PreventionPolicyError, match="workspace"):
        _plan(
            tmp_path / "linked-unused",
            base_workspace=base,
            candidate_workspace=linked,
        )

    nested = base / "candidate"
    shutil.copytree(candidate, nested)
    with pytest.raises(PreventionPolicyError, match="overlap"):
        _plan(
            tmp_path / "nested-unused",
            base_workspace=base,
            candidate_workspace=nested,
        )


@pytest.mark.parametrize("payload", [b"text\x00binary\n", b"\xff\xfe\x00"])
def test_rejects_binary_changed_files(tmp_path, payload):
    base, candidate = _workspaces(tmp_path)
    (candidate / "localize/rules.py").write_bytes(payload)

    with pytest.raises(PreventionPolicyError, match="binary|UTF-8"):
        _plan(
            tmp_path / "unused",
            base_workspace=base,
            candidate_workspace=candidate,
        )


def test_rejects_oversized_or_too_many_changed_files(tmp_path):
    base, candidate = _workspaces(tmp_path / "bytes")
    with pytest.raises(PreventionPolicyError, match="byte limit"):
        _plan(
            tmp_path / "bytes-unused",
            base_workspace=base,
            candidate_workspace=candidate,
            max_changed_bytes=10,
        )

    base, candidate = _workspaces(tmp_path / "files")
    with pytest.raises(PreventionPolicyError, match="file limit"):
        _plan(
            tmp_path / "files-unused",
            base_workspace=base,
            candidate_workspace=candidate,
            max_changed_files=1,
        )


def test_requires_a_real_test_content_change(tmp_path):
    base, candidate = _workspaces(tmp_path / "unchanged")
    shutil.copy2(
        base / "tests/unit/test_rules.py",
        candidate / "tests/unit/test_rules.py",
    )
    with pytest.raises(PreventionPolicyError, match="test file content"):
        _plan(
            tmp_path / "unchanged-unused",
            base_workspace=base,
            candidate_workspace=candidate,
        )

    base, candidate = _workspaces(tmp_path / "mode")
    test_path = candidate / "tests/unit/test_rules.py"
    test_path.chmod(test_path.stat().st_mode | 0o111)
    test_path.write_bytes((base / "tests/unit/test_rules.py").read_bytes())
    with pytest.raises(PreventionPolicyError, match="test file content"):
        _plan(
            tmp_path / "mode-unused",
            base_workspace=base,
            candidate_workspace=candidate,
        )


def test_requires_a_distinct_real_pipeline_code_change(tmp_path):
    base, candidate = _workspaces(tmp_path / "unchanged")
    shutil.copy2(
        base / "localize/rules.py",
        candidate / "localize/rules.py",
    )

    with pytest.raises(PreventionPolicyError, match="code file content"):
        _plan(
            tmp_path / "unchanged-unused",
            base_workspace=base,
            candidate_workspace=candidate,
        )


def test_rejects_a_changed_path_matching_both_code_and_test_scopes(tmp_path):
    with pytest.raises(PreventionPolicyError, match="both code and test"):
        _plan(
            tmp_path,
            allowed_code_path_globs=("**/*.py",),
            allowed_test_path_globs=("**/*.py",),
        )


def test_rejects_deletions_in_a_prevention_draft(tmp_path):
    base, candidate = _workspaces(tmp_path)
    (candidate / "localize/rules.py").unlink()

    with pytest.raises(PreventionPolicyError, match="delete"):
        _plan(
            tmp_path / "unused",
            base_workspace=base,
            candidate_workspace=candidate,
        )


@pytest.mark.parametrize(
    "results, message",
    [
        ((_result("patched", TestOutcome.PASSED),), "failed on the exact base"),
        ((_result("base", TestOutcome.FAILED),), "passed on its direct child"),
        (
            (
                _result("base", TestOutcome.ERROR),
                _result("patched", TestOutcome.PASSED),
            ),
            "failed on the exact base",
        ),
        (
            (
                _result("base", TestOutcome.FAILED),
                _result("patched", TestOutcome.TIMED_OUT, returncode=124),
            ),
            "passed on its direct child",
        ),
        (
            (
                _result("base", TestOutcome.FAILED),
                _result(
                    "patched",
                    TestOutcome.PASSED,
                    argv=("venv/bin/pytest", "tests/unit/test_other.py", "-q"),
                ),
            ),
            "same focused argv",
        ),
    ],
)
def test_requires_a_completed_matching_focused_regression_pair(
    tmp_path,
    results,
    message,
):
    with pytest.raises(PreventionPolicyError, match=message):
        _plan(tmp_path, test_results=results)


def test_rejects_stale_base_or_non_child_patched_test_records(tmp_path):
    stale_base = (
        _result("base", TestOutcome.FAILED, commit_sha="c" * 40),
        _result("patched", TestOutcome.PASSED),
    )
    with pytest.raises(PreventionPolicyError, match="exact base SHA"):
        _plan(tmp_path / "base", test_results=stale_base)

    non_child = (
        _result("base", TestOutcome.FAILED),
        _result("patched", TestOutcome.PASSED, parent_sha="c" * 40),
    )
    with pytest.raises(PreventionPolicyError, match="direct child"):
        _plan(tmp_path / "child", test_results=non_child)

    mixed_object_formats = (
        _result("base", TestOutcome.FAILED),
        _result("patched", TestOutcome.PASSED, commit_sha="c" * 64),
    )
    with pytest.raises(PreventionPolicyError, match="object format"):
        _plan(tmp_path / "object-format", test_results=mixed_object_formats)


def test_rejects_mixed_candidate_commits_and_duplicate_result_records(tmp_path):
    mixed = (
        _result("base", TestOutcome.FAILED),
        _result("patched", TestOutcome.PASSED),
        _result(
            "patched",
            TestOutcome.PASSED,
            commit_sha="c" * 40,
            focused=False,
            argv=("venv/bin/pytest", "-q"),
        ),
    )
    with pytest.raises(PreventionPolicyError, match="one candidate commit"):
        _plan(tmp_path / "mixed", test_results=mixed)

    duplicate = (
        _result("base", TestOutcome.FAILED),
        _result("base", TestOutcome.FAILED),
        _result("patched", TestOutcome.PASSED),
    )
    with pytest.raises(PreventionPolicyError, match="duplicate test result"):
        _plan(tmp_path / "duplicate", test_results=duplicate)


@pytest.mark.parametrize(
    "argv",
    [
        "pytest tests/unit/test_rules.py",
        ("bash", "-c", "pytest tests/unit/test_rules.py"),
        ("/usr/bin/env", "bash", "-c", "pytest"),
        ("python", "-c", "print('not a test')"),
        ("venv/bin/pytest", "tests/unit/test_rules.py\n--collect-only"),
        ("venv/bin/pytest", "tests/unit/test_rules.py\N{RIGHT-TO-LEFT OVERRIDE}"),
    ],
)
def test_test_result_requires_non_shell_argv_only_commands(argv):
    with pytest.raises(ValueError, match="argv|shell|interpreter"):
        TestCommandResult(
            phase="base",
            outcome=TestOutcome.FAILED,
            argv=argv,
            commit_sha=BASE_SHA,
            parent_sha=None,
            returncode=1,
            test_overlay_hash=TEST_OVERLAY_HASH,
        )


@pytest.mark.parametrize(
    "phase, outcome, returncode",
    [
        ("unknown", TestOutcome.FAILED, 1),
        ("base", TestOutcome.PASSED, 1),
        ("base", TestOutcome.FAILED, 0),
        ("patched", TestOutcome.ERROR, 0),
    ],
)
def test_test_result_rejects_invalid_phase_or_outcome_exit_code(
    phase,
    outcome,
    returncode,
):
    with pytest.raises(ValueError):
        _result(phase, outcome, returncode=returncode)


def test_rejects_invalid_root_cause_feedback_ids_and_limits(tmp_path):
    with pytest.raises(PreventionPolicyError, match="root cause"):
        _plan(tmp_path / "cause", root_cause="\x00hostile")
    with pytest.raises(PreventionPolicyError, match="root cause"):
        _plan(tmp_path / "bidi-cause", root_cause="hostile\N{RIGHT-TO-LEFT OVERRIDE}")
    with pytest.raises(PreventionPolicyError, match="feedback ID"):
        _plan(tmp_path / "feedback", evidence_feedback_ids=("../comment",))
    with pytest.raises(PreventionPolicyError, match="duplicate feedback ID"):
        _plan(
            tmp_path / "duplicate",
            evidence_feedback_ids=("review:42", "review:42"),
        )
    with pytest.raises(PreventionPolicyError, match="file limit"):
        _plan(tmp_path / "files", max_changed_files=0)
    with pytest.raises(PreventionPolicyError, match="byte limit"):
        _plan(tmp_path / "bytes", max_changed_bytes=0)


def test_ignores_checkout_metadata_but_not_nested_git_content(tmp_path):
    base, candidate = _workspaces(tmp_path)
    (base / ".git").mkdir()
    (candidate / ".git").mkdir()
    (base / ".git/HEAD").write_text("base\n", encoding="utf-8")
    (candidate / ".git/HEAD").write_text("candidate\n", encoding="utf-8")
    plan = _plan(
        tmp_path / "unused",
        base_workspace=base,
        candidate_workspace=candidate,
    )
    assert ".git/HEAD" not in plan.paths

    (candidate / "localize/.git").mkdir()
    (candidate / "localize/.git/config").write_text("hostile\n", encoding="utf-8")
    with pytest.raises(PreventionPolicyError, match="outside the allowed"):
        _plan(
            tmp_path / "nested-unused",
            base_workspace=base,
            candidate_workspace=candidate,
        )


def test_regular_unchanged_repository_symlinks_do_not_expand_patch_scope(tmp_path):
    if not hasattr(os, "symlink"):
        pytest.skip("symbolic links are not supported")
    base, candidate = _workspaces(tmp_path)
    (base / "docs-link").symlink_to("README.md")
    (candidate / "docs-link").symlink_to("README.md")

    plan = _plan(
        tmp_path / "unused",
        base_workspace=base,
        candidate_workspace=candidate,
    )

    assert "docs-link" not in plan.paths
