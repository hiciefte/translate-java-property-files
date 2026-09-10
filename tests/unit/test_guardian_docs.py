"""Static safety and portability checks for the public Guardian guide."""

from __future__ import annotations

from pathlib import Path

import yaml

import localize.guardian as guardian
from localize.guardian.config import load_guardian_config
from localize.guardian.models import (
    CodexAuthMode,
    GuardianMode,
    PipelineConfigSource,
    TrustedActor,
)


PROJECT_ROOT = Path(__file__).resolve().parents[2]
GUIDE = PROJECT_ROOT / "docs" / "guardian.md"
EXAMPLE = PROJECT_ROOT / "examples" / "guardian.config.yaml"
README = PROJECT_ROOT / "README.md"
LLMS = PROJECT_ROOT / "llms.txt"
CHANGELOG = PROJECT_ROOT / "CHANGELOG.md"


def _guide_text() -> str:
    return GUIDE.read_text(encoding="utf-8")


def _example_text() -> str:
    return EXAMPLE.read_text(encoding="utf-8")


def _normalized_guide() -> str:
    return " ".join(_guide_text().casefold().split())


def test_guardian_example_is_valid_report_only_policy_with_numeric_identities():
    config = load_guardian_config(EXAMPLE)

    assert config.mode is GuardianMode.OBSERVE
    assert len(config.repositories) == 1
    policy = config.repositories[0]
    assert policy.base_repo == "acme/widgets"
    assert policy.base_repo_id > 0
    assert policy.base_branch == "main"
    assert policy.private_repo_model_opt_in is False
    assert policy.publication_actor == TrustedActor(
        "localization-machine-user", 100000002, "User"
    )
    assert policy.allowed_pr_authors == (
        TrustedActor("translation-contributor", 100000008, "User"),
    )
    assert policy.publication_actor not in policy.allowed_pr_authors
    assert config.enabled_publication_actors == ()
    assert config.runtime.codex_model == "gpt-5.6-terra"
    assert config.runtime.codex_reasoning_effort == "high"
    assert config.runtime.codex_auth_mode is CodexAuthMode.CHATGPT
    assert config.runtime.codex_home == "~/.local/share/localize-guardian/codex"
    assert config.runtime.codex_api_key_command == ()
    assert config.limits.max_model_calls_per_day == 2
    assert config.limits.max_remediation_drafts_per_run == 0
    assert config.limits.daily_cost_limit_usd is None
    assert config.limits.model_call_reservation_usd is None
    assert config.schedule.hour == 0
    assert config.schedule.minute == 0
    assert policy.pipeline_config_source is PipelineConfigSource.BASE
    assert policy.closed_pr_backfill is None

    assert policy.allowed_pr_authors
    assert policy.allowed_head_owners
    assert policy.allowed_head_repositories
    assert all(actor.id > 0 for actor in policy.allowed_pr_authors)
    assert all(actor.id > 0 for actor in policy.allowed_head_owners)
    assert all(repository.id > 0 for repository in policy.allowed_head_repositories)

    reviewers = policy.trusted_reviewers_for("de")
    bots = policy.trusted_bots_for("de")
    assert reviewers and bots
    assert all(actor.id > 0 and actor.type == "User" for actor in reviewers)
    assert all(actor.id > 0 and actor.type == "Bot" for actor in bots)
    assert {actor.id for actor in reviewers}.isdisjoint(actor.id for actor in bots)


def test_closed_pr_backfill_models_are_part_of_the_public_guardian_api():
    for name in (
        "ClosedPrBackfillPolicy",
        "HistoricalCheckScope",
        "HistoricalRemediationPolicy",
    ):
        assert name in guardian.__all__
        assert getattr(guardian, name) is not None


def test_guardian_example_includes_only_commented_closed_pr_backfill_authority():
    example = _example_text()
    normalized = " ".join(example.replace("#", "").casefold().split())

    assert "max_remediation_drafts_per_run: 0" in example
    assert "# closed_pr_backfill:" in example
    assert "#   lookback_days:" in example
    assert "#   max_prs_per_poll:" in example
    assert "#   remediation:" in example
    assert "#     push_repository:" in example
    assert "#     push_branch_prefix:" in example
    assert "#     publication_actor:" in example
    assert "64-character" in example
    assert "allowed_head_repositories" in example
    assert "allowed_branch_globs" in example
    assert '# - "localization/guardian-remediation-*"' in example
    assert "remediation publication_actor" in normalized
    assert "created or recovered pr author" in normalized
    assert "does not grant ownership authority in allowed_pr_authors" in normalized
    assert "observe/prepare keep it dormant" in normalized
    assert "restarts at page 1" in normalized
    assert "second identity-only traversal" in normalized
    assert "not an atomic snapshot" in normalized
    assert "100 pages/10,000 entries" in normalized
    assert "three immediate hydration attempts" in normalized
    assert "current-cycle skip" in normalized
    assert "durable priority retry" in normalized
    assert "outside the discovery window" in normalized
    assert "#   publication_actor:" in example
    assert "numeric id + github user type grant" in normalized
    assert "github app installation-token bot identities are not supported" in normalized
    assert "all-or-nothing local-state group" in normalized
    assert "final remote checks are sequential" in normalized
    assert "time window admits new evidence only" in normalized
    assert "durable pending group cannot age out" in normalized
    assert "new human-review correction draft" in normalized
    assert "signed commit" in normalized


def test_closed_pr_backfill_is_recorded_in_the_v020_release_notes():
    changelog = CHANGELOG.read_text(encoding="utf-8")
    unreleased, released = changelog.split("## [0.1.20]", 1)
    release = " ".join(released.split("## [0.1.19]", 1)[0].casefold().split())

    assert "closed pull-request backfill" not in unreleased.casefold()
    assert "closed pull-request backfill" in release
    assert "append-only per-cycle seen identities" in release
    assert "bounded identity-only confirmation traversals" in release
    assert "quiescent pass, not an atomic github snapshot" in release
    assert "100 pages or 10,000 entries fails visibly" in release
    assert "three immediate attempts before a current-cycle skip" in release
    assert "durable priority retry on later polls" in release
    assert "outside the discovery window" in release
    assert "window admits new evidence only" in release
    assert "durable pending recovery groups cannot age out" in release
    assert "current-base remediation" in release
    assert "multi-source recovery batches remain grouped and all-or-nothing" in release
    assert "destination and source observations remain sequential" in release
    assert "same-target conflicts" in release
    assert "operator cleanup" in release
    assert "automatic liveness" in release
    assert "read-only evidence" in release
    assert "uncovered finding is published only through a new draft" in release
    assert "correction pr with a signed commit" in release
    assert "read-only source pr and feedback" in release


def test_guardian_example_contains_policy_not_credentials():
    raw = yaml.safe_load(_example_text())
    assert isinstance(raw, dict)

    forbidden_key_fragments = ("password", "secret", "token", "api_key", "credential")

    def visit(value: object) -> None:
        if isinstance(value, dict):
            for key, item in value.items():
                normalized = str(key).casefold()
                assert not any(part in normalized for part in forbidden_key_fragments)
                visit(item)
        elif isinstance(value, list):
            for item in value:
                visit(item)

    visit(raw)
    text = _example_text()
    assert "inert placeholder" in text.casefold()
    assert "OPENAI_API_KEY" not in text
    assert "GITHUB_TOKEN" not in text
    assert "ghp_" not in text


def test_guardian_guide_covers_operator_ownership_and_authority_modes():
    guide = _guide_text()
    normalized = _normalized_guide()

    assert "operator runs" in normalized
    assert "supplies their own codex/chatgpt plan" in normalized
    assert "explicitly opts into api billing" in normalized
    assert "not a hosted service" in normalized
    for mode in (
        "observe",
        "prepare",
        "apply-owned-translations",
        "propose-prevention",
    ):
        assert f"`{mode}`" in guide
    assert "report-only" in normalized
    assert "cannot raise" in normalized
    assert "creates no commits, pushes, comments, or other github writes" in normalized
    assert (
        "stores the outcome and a changed-key count in private action state"
        in normalized
    )
    assert "retains no patch or reviewable plan" in normalized
    assert "not the prepared key count or a diff" in normalized
    assert "do not treat `prepare` as a reviewable diff preview" in normalized


def test_guardian_guide_documents_identity_privacy_and_write_boundaries():
    guide = _guide_text()
    lowered = _normalized_guide()

    assert "numeric github id" in lowered
    assert "base_repo_id" in guide
    assert "exact configured target base branch (`base_branch`)" in lowered
    assert "allowed_head_repositories[].id" in guide
    assert "are authoritative" in lowered
    assert "per repository and locale" in lowered
    assert "trusted_reviewers" in guide
    assert "trusted_bots" in guide
    assert "may authorize auto-application" in lowered
    assert "never inherits trust" in lowered
    assert "allowed_head_repositories" in _example_text()
    assert "private_repo_model_opt_in" in guide
    assert "explicit opt-in" in lowered
    assert "value-only" in lowered
    assert "expected value" in lowered
    assert "source value" in lowered
    assert "exact trusted base sha" in lowered
    assert "never from the pr head" in lowered
    assert "head sha" in lowered
    assert "base sha" in lowered
    assert "does not merge" in lowered
    assert "resolve review threads" in lowered
    assert "`pipeline_config_source: operator`" in lowered
    assert "snapshot" in lowered
    assert "mode `0700`" in lowered
    assert "mode `0600`" in lowered
    assert "exact base sha" in lowered


def test_guardian_guide_documents_hardened_codex_boundary():
    guide = _guide_text()
    normalized = _normalized_guide()

    assert "Codex CLI" in guide
    assert "codex exec" in guide
    assert "`guardian_evidence` permission profile" in guide
    assert "minimal filesystem reads plus read access" in normalized
    for option in (
        "--ephemeral",
        "--output-schema",
        "--json",
        "--skip-git-repo-check",
        "--ignore-user-config",
        "--ignore-rules",
        "--strict-config",
        "--ask-for-approval never",
    ):
        assert f"`{option}`" in guide
    assert "https://learn.chatgpt.com/docs/non-interactive-mode" in guide

    forbidden = (
        "bypassPermissions",
        "danger-full-access",
        "dangerously-bypass",
        "--full-auto",
        "--sandbox read-only",
    )
    assert not any(value in guide for value in forbidden)


def test_guardian_docs_publish_exact_prevention_collection_and_text_bounds():
    guide = _normalized_guide()
    example = " ".join(_example_text().casefold().split())
    readme = " ".join(README.read_text(encoding="utf-8").casefold().split())

    for text in (guide, example):
        assert "100 code globs" in text
        assert "100 test globs" in text
        assert "64 focused commands" in text
        assert "256" in text and "focused" in text
        assert "exactly one" in text and "sandbox" in text
        assert "4096 utf-8 bytes" in text
        assert "max_changed_files" in text and "100" in text
        assert "77" in text and "branch" in text
        assert "512 kib" in text and "attestation" in text
        assert "100 recurrence candidates" in text
        assert "100 evidence" in text
        assert "120" in text and "256 utf-8 bytes" in text
        assert "60 kib" in text
        assert "fingerprint" in text

    assert "100 code globs" in readme
    assert "4096 utf-8 bytes" in readme
    assert "60 kib" in readme
    assert "`gpt-5.6-terra` with reasoning effort `high`" in guide


def test_guardian_guide_documents_deliberate_plugin_isolation():
    guide = _guide_text()

    assert "An explicit `--plugin` argument is rejected" in guide
    assert "`LOCALIZE_PLUGIN_MODULES`" in guide
    assert "entry points" in guide
    assert "fails closed" in guide


def test_guardian_guide_documents_untrusted_inputs_and_secret_brokerage():
    guide = _guide_text()
    lowered = _normalized_guide()

    for untrusted_input in (
        "review comments",
        "repository content",
        "model output",
    ):
        assert untrusted_input in lowered
    assert "prompt injection" in lowered
    assert "os secret store" in lowered
    assert "token helper" in lowered
    assert "never stored in guardian yaml" in lowered
    assert "shell=false" in lowered
    assert "`codex_auth_mode: chatgpt`" in lowered
    assert "localize guardian login --config" in guide
    assert "dedicated `codex_home`" in lowered
    assert "chatgpt plan allowance" in lowered
    assert "not metered api billing" in lowered
    assert 'forced_login_method="chatgpt"' in guide
    assert 'cli_auth_credentials_store="file"' in guide
    assert "`codex_api_key` and `openai_api_key` are removed" in lowered
    assert "api-key mode is an explicit opt-in" in lowered
    assert "does not accept an ambient api key" in lowered
    assert "opens the poll's authentication circuit" in lowered
    assert "model-capacity circuit" in lowered
    assert "does not immediately retry" in lowered
    assert "github credential-helper or api authentication failure" in lowered
    assert "non-authentication github transport" in lowered


def test_guardian_guide_documents_audit_cost_retention_and_safe_prevention():
    """Document audit retention, session accounting, and prevention authority."""
    guide = _guide_text()
    lowered = _normalized_guide()

    assert "immutable revision" in lowered
    assert "body hash" in lowered
    assert "daily model-call" in lowered
    assert "raw_retention_days" in guide
    assert "logically deleted from the active sqlite tables" in lowered
    assert "not a secure-erasure guarantee" in lowered
    assert "pull request ready for review" in lowered
    assert "never reopens or converts an existing pr" in lowered
    assert "at most 8 kib" in lowered
    assert "not proof of its author's identity or authority" in lowered
    assert "regression test" in lowered
    assert "failing on the base" in lowered
    assert "passing with the draft" in lowered
    assert "operator-supplied `sandbox_argv_prefix`" in lowered
    assert "one-item argv" in lowered
    assert "unchecked prefix argument is rejected" in lowered
    assert "before every focused command, a runtime probe" in lowered
    assert "an af_inet loopback bind and a connection" in lowered
    assert "filesystem af_unix canary connection" in lowered
    assert "does not prove the policy's behavior for every host path" in lowered
    assert "parent guardian process must be allowed" in lowered
    assert "operator-controlled absolute interpreter" in lowered
    assert "every block must state `private_target_model_opt_in`" in lowered
    assert "both opt-ins are required" in lowered
    assert "non-refundable per-poll publication slot" in lowered
    assert "across the entire poll, shared by all repositories" in lowered
    assert "counter is not reset per feedback run" in lowered
    assert "a zero cap is a prevention-publication kill switch" in lowered
    assert "still retains the translation-write authority" in lowered
    assert "not whole-run exactly-once execution" in lowered
    assert "can repeat an ambiguous model attempt" in lowered
    assert "consume another call slot" in lowered
    assert "max_model_calls_per_day >= max_attempts" in guide
    assert "max_attempts *" in guide
    assert "(1 + max_prevention_drafts_per_run)" in guide
    assert "daily_cost_limit_usd >= model_call_reservation_usd" in guide
    assert "report-only example pins the cap to zero" in lowered
    assert "cap provides two full" in _example_text()
    assert "[/absolute/path/to/python, -m, pytest" in _example_text()
    assert "private_target_model_opt_in: false" in _example_text()
    assert "🤖" in guide
    assert "commit-linked" in lowered


def test_guardian_guide_documents_bounded_closed_pr_history_without_legacy_writes():
    """Distinguish bounded historical intake from new ready correction PRs."""
    guide = _guide_text()
    normalized = _normalized_guide()

    assert "`closed_pr_backfill`" in guide
    assert "open-pr phase" in normalized
    assert "`lookback_days`" in guide
    assert "`max_prs_per_poll`" in guide
    assert "durable scan cycles" in normalized
    assert "every later poll restarts at github page 1" in normalized
    assert "append-only per-cycle seen set" in normalized
    assert "does not persist a mutable pagination position" in normalized
    assert "second identity-only traversal" in normalized
    assert "github's rest listing is not an atomic snapshot" in normalized
    assert "quiescent, bounded discovery-and-confirmation pass" in normalized
    assert "100 numeric pages" in normalized
    assert "10,000 list entries" in normalized
    assert "poll fails visibly and keeps the cycle incomplete" in normalized
    assert "narrow `lookback_days`" in normalized
    assert "quiescent long enough for confirmation" in normalized
    assert "retried up to three times immediately" in normalized
    assert "skipped for the rest of the current cycle" in normalized
    assert "durable pending retry is prioritized on later polls" in normalized
    assert "independently of the discovery window" in normalized
    assert "authentication failures abort the poll" in normalized
    assert "at most one durable pending branch-only remediation batch" in normalized
    assert "frozen upper bound and lookback cutoff govern discovery" in normalized
    assert "direct recovery ignores the discovery window" in normalized
    assert "already-published branch cannot age out" in normalized
    assert "remain closed" in normalized
    assert "current policy and trust eligibility" in normalized
    assert "immutable stored evidence" in normalized
    assert "exact remote branch/pr identity" in normalized
    assert "whole source group enters the durable priority" in normalized
    assert "no partial candidate is published" in normalized
    assert "terminal-local-skip `remediation quarantine`" in normalized
    assert (
        "publication safety and backlog fairness over automatic liveness" in normalized
    )
    assert "next poll starts a fresh cycle at the newest page" in normalized
    assert "top-level `updated_at` did not change" in normalized
    assert "untrusted comment churn" in normalized
    assert "merged and unmerged" in normalized
    assert (
        "historical pull request and its review feedback are evidence only"
        in normalized
    )
    assert "exact current base" in normalized
    assert "independently exists on that current base" in normalized
    assert "already fixed or otherwise obsolete" in normalized
    assert "configured current base branch" in normalized
    assert "current default branch" not in normalized
    assert "terminal no-action checkpoint" in normalized
    assert "compatible current-base fixes may share one batch" in normalized
    assert "conflicting proposals for the same target" in normalized
    assert "unsafe cases remain deferred" in normalized
    assert "uncovered and selected for remediation" in normalized
    assert "published only through a new bot-marked, ready-for-review correction pr" in normalized
    assert "closed source pr and validated feedback" in normalized
    assert "leaves the historical pr and its branch untouched" in normalized
    assert "separate from any optional pipeline-prevention proposal" in normalized
    assert "observe` and `prepare` perform no github writes" in normalized
    assert "nested remediation policy may remain configured" in normalized
    assert "changing mode is the authority ceiling" in normalized
    assert "`max_remediation_drafts_per_run: 0`" in guide
    assert "zero is also the schema default" in normalized
    assert "one remediation batch per repository per poll" in normalized
    assert "global per-poll cap" in normalized
    assert "new bot-marked pull request ready for human and automated review" in normalized
    assert "bounded current-base correction prs ready for review" in normalized
    assert "bounded current-base correction drafts" not in normalized
    assert "`[localize guardian bot]`" in normalized
    assert "title prefix and body text identify it as bot-generated" in normalized
    assert "signed commit" in normalized
    assert "human review" in normalized
    assert "never reopens, edits, or comments on a closed pull request" in normalized
    assert "never merges the remediation draft" in normalized
    assert "64-character lowercase hexadecimal" in normalized
    assert "`allowed_head_repositories`" in guide
    assert "`allowed_branch_globs`" in guide
    assert "typed numeric-id `publication_actor`" in normalized
    assert "match the configured `publication_actor`" in normalized
    assert "same actor as its author" in normalized
    assert "exact generated title and body" in normalized
    assert "different allowlisted author fails closed" in normalized
    assert "same read-only probe resolves `/user` once" in normalized
    assert "neither the token nor mutable login is printed" in normalized
    assert "crash recovery" in normalized
    assert "duplicate branch or draft" in normalized
    assert "already-created exact pr remains recoverable" in normalized
    assert "ordinary target-base advancement" in normalized
    assert "marks that local attempt abandoned" in normalized
    assert "fresh validation can then create a distinct attempt" in normalized
    assert "exact merged observation" in normalized
    assert "human veto" in normalized
    assert "does not recreate the same correction unchanged" in normalized
    assert "draft-backed source coverage becomes ineffective" in normalized
    assert "branch identities use version 2" in normalized
    assert "rows migrated from version 1" in normalized
    assert "leaves any remote branch untouched" in normalized
    assert "favors publication safety" in normalized
    assert "continues to cover its exact edits" in normalized
    assert "semantic rather than tied to a comment revision" in normalized
    assert "target identity is the path-and-key pair" in normalized
    assert "exact edit covered by an open or human-closed-unmerged" in normalized
    assert "removed from a mixed batch" in normalized
    assert "different edit aimed at the same target identity conflicts" in normalized
    assert "grouped, bounded recovery path" in normalized
    assert "compare-and-swap protected" in normalized
    assert "stale concurrent progress writer fails closed" in normalized
    assert "editing or deleting an authorized reviewer/bot item" in normalized
    assert "trusted pipeline config-and-glossary bundle" in normalized
    assert "exact current base or the private operator snapshot" in normalized


def test_guardian_guide_has_consistent_cli_and_launchd_catch_up_instructions():
    guide = _guide_text()

    for command in ("init", "login", "doctor", "run", "status", "install"):
        assert f"localize guardian {command} --config" in guide
    assert "localize guardian remediation list --config" in guide
    assert "localize guardian history-retry list --config" in guide
    normalized = _normalized_guide()
    assert "--acknowledge-terminal-local-skip" in guide
    assert "permanent source-pr veto under that policy digest" in normalized
    assert "later comments on that pr are ignored" in normalized
    assert "changing the policy makes the pr eligible again" in normalized
    assert "neither command" in normalized
    assert "changes github state" in normalized
    assert "launchd" in guide
    assert "RunAtLoad" in guide
    assert "StartInterval" in guide
    assert "wake" in guide.casefold()
    assert "catch-up" in guide.casefold()
    assert "failed scheduled attempt is not retried" in guide.casefold()
    assert "schedule.hour" in guide
    assert "schedule.minute" in guide
    assert "local wall-clock" in guide.casefold()
    assert "explicit manual `guardian run`" in guide
    assert "stages the files but does not load" in guide
    assert "runtime.codex_executable" in guide
    assert "runtime.github_token_command[0]" in guide
    assert "runtime.codex_api_key_command[0]" in guide
    assert "interpreter or dispatcher programs are not accepted" in _normalized_guide()
    assert "executable absolute paths" in guide
    assert "removes only regular files created by that attempt" in guide
    assert "preserves pre-existing" in guide
    assert "not a file to commit" in _normalized_guide()

    example = _example_text()
    assert "codex_executable: /absolute/path/to/codex" in example
    assert "github_token_command: [/absolute/path/to/github-token-helper]" in example
    assert "codex_api_key_command: [/absolute/path/to/model-key-helper]" in example
    assert "git_executable: /absolute/path/to/git" in example
    assert "- /absolute/path/to/guardian-sandbox-wrapper" in example
    assert "codex_auth_mode: chatgpt" in example
    assert "max_model_calls_per_day: 2" in example


def test_guardian_is_discoverable_without_implying_a_hosted_service():
    readme = README.read_text(encoding="utf-8")
    llms = LLMS.read_text(encoding="utf-8")

    for text in (readme, llms):
        normalized = " ".join(text.split())
        assert "docs/guardian.md" in text
        assert "examples/guardian.config.yaml" in text
        assert "self-hosted" in text.casefold()
        assert "operator" in text.casefold()
        assert "gpt-5.6-terra" in text
        assert "LOCALIZE_PLUGIN_MODULES" in text
        assert "manual `guardian run`" in normalized
    assert "not a service run" in readme.casefold()
    assert "does not operate the guardian" in llms.casefold()
    normalized_readme = " ".join(readme.casefold().split())
    assert "new draft correction pr" in normalized_readme
    assert "draft links the still-valid closed feedback" in normalized_readme
    assert "never writes to the closed pr" in normalized_readme
    assert "not an atomic snapshot" in normalized_readme
    assert "completion requires a quiescent pass" in normalized_readme
    assert "100 pages or 10,000 entries fails visibly" in normalized_readme
    assert "three immediate hydration attempts" in normalized_readme
    assert "multi-source recovery batch remains bounded and all-or-nothing" in normalized_readme
    assert "destination and source observations are necessarily sequential" in normalized_readme
    assert "discovery window admits new evidence only" in normalized_readme
    assert "published branch cannot age out before reconciliation" in normalized_readme


def test_guardian_public_files_stay_generic_and_have_no_project_runner():
    combined = f"{_guide_text()}\n{_example_text()}".casefold()

    assert "bisq" not in combined
    assert "jabref" not in combined
    assert "run-pilot" not in combined
    assert "outreach/" not in combined
    assert "profiles/" not in combined

    readme = README.read_text(encoding="utf-8")
    guardian_start = readme.index("## Optional Self-Hosted PR Guardian")
    guardian_end = readme.index("\n## ", guardian_start + 1)
    all_discovery_text = "\n".join(
        (
            combined,
            readme[guardian_start:guardian_end].casefold(),
            LLMS.read_text(encoding="utf-8").casefold(),
        )
    )
    assert "jabref" not in all_discovery_text
    assert "ultra" not in combined
    assert "ultra" not in readme[guardian_start:guardian_end].casefold()
    llms = LLMS.read_text(encoding="utf-8").casefold()
    llms_guardian_start = llms.index("guardian authority")
    llms_guardian = llms[llms_guardian_start : llms.index("\n## ", llms_guardian_start)]
    assert "ultra" not in llms_guardian
