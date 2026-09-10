from pathlib import Path
import json
import re
from unittest.mock import MagicMock, patch

import pytest
import yaml

from localize.localization_formats import JSON_FORMAT, JAVA_PROPERTIES_FORMAT
from localize.localization_layouts import LocalizationLayout, SUFFIX_LAYOUT
from localize.localization_profiles import LocalizationProfile
from localize.semantic_quality import SemanticQAStats, SemanticRule
from localize.translation_quality_gate import (
    QualityGateConfig,
    analyze_all_translation_entries_for_profiles,
    analyze_semantic_qa_changes,
    analyze_semantic_qa_changes_for_profiles,
    analyze_source_identical_changes_for_profiles,
    analyze_source_identical_changes,
    build_quality_gate_report,
    load_quality_gate_config,
    load_quality_gate_localization_metadata,
    load_quality_gate_localization_profiles,
    load_validation_summary,
    render_quality_gate_markdown,
)

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def _write_properties(path: Path, entries: dict[str, str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "\n".join(f"{key}={value}" for key, value in entries.items()) + "\n",
        encoding="utf-8",
    )


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def test_source_identical_gate_ignores_glossary_tokens_and_enum_keys(tmp_path):
    repo_root = tmp_path
    input_folder = repo_root / "resources"
    _write_properties(
        input_folder / "mobile.properties",
        {
            "mobile.open": "Open trades",
            "mobile.sort": "Sort",
            "BTC": "BTC",
            "PAYMENT_METHOD": "MoneyGram",
            "mobile.done": "Done",
        },
    )

    diff_text = """diff --git a/resources/mobile_es.properties b/resources/mobile_es.properties
+++ b/resources/mobile_es.properties
+mobile.open=Open trades
+mobile.sort=Sort
+BTC=BTC
+PAYMENT_METHOD=MoneyGram
+mobile.done=Listo
"""

    stats = analyze_source_identical_changes(
        diff_text=diff_text,
        repo_root=str(repo_root),
        input_folder=str(input_folder),
        locale_codes=["es"],
        brand_glossary=["BTC", "MoneyGram"],
    )

    assert stats.changed_entries_count == 5
    assert stats.source_identical_count == 4
    assert stats.expected_source_identical_count == 2
    assert stats.unexpected_source_identical_count == 2
    assert stats.unexpected_source_identical_ratio == 2 / 3


def test_source_identical_gate_blocks_new_non_brand_values_and_honors_locale_allowlist(tmp_path):
    repo_root = tmp_path
    input_folder = repo_root / "resources"
    _write_properties(
        input_folder / "mobile.properties",
        {
            "mobile.trade": "Trade",
            "mobile.network": "Internet",
        },
    )
    diff_text = """diff --git a/resources/mobile_cs.properties b/resources/mobile_cs.properties
+++ b/resources/mobile_cs.properties
+mobile.trade=Trade
+mobile.network=Internet
"""

    stats = analyze_source_identical_changes(
        diff_text=diff_text,
        repo_root=str(repo_root),
        input_folder=str(input_folder),
        locale_codes=["cs"],
        brand_glossary=[],
        source_identical_allowlist={"cs": ["Internet"]},
    )
    report = build_quality_gate_report(
        source_stats=stats,
        semantic_stats=None,
        validation_summary={"files": {}, "pipeline_warnings": []},
        changed_files=["resources/mobile_cs.properties"],
        input_folder=str(input_folder),
        config=QualityGateConfig(source_identical_min_block_count=1),
    )

    assert stats.expected_source_identical_count == 1
    assert stats.unexpected_source_identical_count == 1
    assert report["blocking"] is True


def test_source_identical_gate_supports_json_locale_directory_layout(tmp_path):
    repo_root = tmp_path
    input_folder = repo_root / "locales"
    layout = LocalizationLayout(id="locale_directory", source_locale="en")
    _write_json(
        input_folder / "en" / "common.json",
        {
            "title": "Open trades",
            "nested": {"cta": "Continue"},
            "steps": [{"label": "Review details"}],
        },
    )
    _write_json(
        input_folder / "de" / "common.json",
        {
            "title": "Open trades",
            "nested": {"cta": "Weiter"},
            "steps": [{"label": "Review details"}],
        },
    )
    diff_text = """diff --git a/locales/de/common.json b/locales/de/common.json
+++ b/locales/de/common.json
+  "title": "Open trades",
"""

    stats = analyze_source_identical_changes(
        diff_text=diff_text,
        repo_root=str(repo_root),
        input_folder=str(input_folder),
        locale_codes=["de"],
        brand_glossary=[],
        localization_format=JSON_FORMAT,
        localization_layout=layout,
    )

    assert stats.changed_entries_count == 1
    assert stats.source_identical_count == 1
    assert stats.unexpected_source_identical_count == 1
    assert stats.examples == [
        {"file": "de/common.json", "key": "/title", "value": "Open trades"},
    ]


def test_source_identical_gate_excludes_ignored_json_pointer_keys(tmp_path):
    repo_root = tmp_path
    input_folder = repo_root / "locales"
    _write_json(
        input_folder / "en.json",
        {
            "#1": "Phrases in app/Main.tsx",
            "title": "Open trades",
        },
    )
    _write_json(
        input_folder / "de.json",
        {
            "#1": "Phrases in app/Main.tsx",
            "title": "Open trades",
        },
    )
    diff_text = """diff --git a/locales/de.json b/locales/de.json
+++ b/locales/de.json
+  "#1": "Phrases in app/Main.tsx",
+  "title": "Open trades",
"""

    stats = analyze_source_identical_changes(
        diff_text=diff_text,
        repo_root=str(repo_root),
        input_folder=str(input_folder),
        locale_codes=["de"],
        brand_glossary=[],
        localization_format=JSON_FORMAT,
        localization_layout=LocalizationLayout(id="locale_filename", source_locale="en"),
        ignore_key_patterns=[re.compile(r"^/#\d+$"), r"^/metadata$"],
    )

    assert stats.changed_entries_count == 1
    assert stats.source_identical_count == 1
    assert stats.unexpected_source_identical_count == 1
    assert stats.examples == [
        {"file": "de.json", "key": "/title", "value": "Open trades"},
    ]


def test_quality_gate_config_loads_ignore_key_patterns(tmp_path):
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        yaml.safe_dump(
            {
                "ignore_key_patterns": [r"^/#\d+$"],
                "supported_locales": [{"code": "de", "name": "German"}],
            }
        ),
        encoding="utf-8",
    )

    config, _locale_codes, _brand_glossary, _rules = load_quality_gate_config(str(config_path))

    assert [pattern.pattern for pattern in config.ignore_key_patterns] == [r"^/#\d+$"]
    report = build_quality_gate_report(
        source_stats=analyze_source_identical_changes(
            diff_text="",
            repo_root=str(tmp_path),
            input_folder=str(tmp_path),
            locale_codes=["de"],
            brand_glossary=[],
            ignore_key_patterns=config.ignore_key_patterns,
        ),
        semantic_stats=None,
        validation_summary={"files": {}, "pipeline_warnings": []},
        changed_files=[],
        input_folder=str(tmp_path),
        config=config,
    )
    assert report["thresholds"]["ignore_key_patterns"] == [r"^/#\d+$"]
    json.dumps(report["thresholds"])


def test_quality_gate_localization_metadata_rejects_invalid_format(tmp_path):
    config_path = tmp_path / "config.yaml"
    config_path.write_text("localization_format: unknown\n", encoding="utf-8")

    with pytest.raises(ValueError, match="Unsupported localization_format"):
        load_quality_gate_localization_metadata(str(config_path))


def test_quality_gate_localization_metadata_rejects_invalid_layout(tmp_path):
    config_path = tmp_path / "config.yaml"
    config_path.write_text("localization_layout: unknown\n", encoding="utf-8")

    with pytest.raises(ValueError, match="Unsupported localization_layout"):
        load_quality_gate_localization_metadata(str(config_path))


def test_quality_gate_loads_mixed_localization_profiles(tmp_path):
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        yaml.safe_dump({
            "localization_formats": [
                {"id": "java_properties", "layout": "suffix"},
                {"id": "json", "layout": {"id": "locale_directory", "source_locale": "en"}},
            ]
        }),
        encoding="utf-8",
    )

    profiles = load_quality_gate_localization_profiles(str(config_path))

    assert [profile.localization_format.id for profile in profiles] == ["java_properties", "json"]
    assert profiles[1].localization_layout.id == "locale_directory"


def test_quality_gate_analyzes_changed_entries_across_profiles(tmp_path):
    repo_root = tmp_path
    input_folder = repo_root / "resources"
    layout = LocalizationLayout(id="locale_directory", source_locale="en")
    _write_properties(input_folder / "messages.properties", {"title": "Open trades"})
    _write_json(input_folder / "en" / "common.json", {"cta": "Continue"})
    _write_json(input_folder / "de" / "common.json", {"cta": "Continue"})
    diff_text = """diff --git a/resources/messages_de.properties b/resources/messages_de.properties
+++ b/resources/messages_de.properties
+title=Open trades
diff --git a/resources/de/common.json b/resources/de/common.json
+++ b/resources/de/common.json
+  "cta": "Continue",
"""

    stats = analyze_source_identical_changes_for_profiles(
        diff_text=diff_text,
        repo_root=str(repo_root),
        input_folder=str(input_folder),
        locale_codes=["de"],
        brand_glossary=[],
        localization_profiles=(
            LocalizationProfile(JAVA_PROPERTIES_FORMAT, SUFFIX_LAYOUT),
            LocalizationProfile(JSON_FORMAT, layout),
        ),
    )

    assert stats.changed_entries_count == 2
    assert stats.unexpected_source_identical_count == 2
    assert {example["file"] for example in stats.examples} == {
        "messages_de.properties",
        "de/common.json",
    }


def test_quality_gate_deduplicates_overlapping_profile_source_checks(tmp_path):
    repo_root = tmp_path
    input_folder = repo_root / "resources"
    _write_properties(input_folder / "messages.properties", {"title": "Open trades"})
    diff_text = """diff --git a/resources/messages_de.properties b/resources/messages_de.properties
+++ b/resources/messages_de.properties
+title=Open trades
"""

    stats = analyze_source_identical_changes_for_profiles(
        diff_text=diff_text,
        repo_root=str(repo_root),
        input_folder=str(input_folder),
        locale_codes=["de"],
        brand_glossary=[],
        localization_profiles=(
            LocalizationProfile(JAVA_PROPERTIES_FORMAT, SUFFIX_LAYOUT),
            LocalizationProfile(JAVA_PROPERTIES_FORMAT, SUFFIX_LAYOUT),
        ),
    )

    assert stats.changed_entries_count == 1
    assert stats.unexpected_source_identical_count == 1


def test_semantic_qa_analyzes_changed_entries_across_profiles(tmp_path):
    repo_root = tmp_path
    input_folder = repo_root / "resources"
    layout = LocalizationLayout(id="locale_directory", source_locale="en")
    _write_properties(input_folder / "messages.properties", {"title": "Open trades"})
    _write_json(input_folder / "en" / "common.json", {"cta": "Continue"})
    _write_json(input_folder / "de" / "common.json", {"cta": "Continue"})
    diff_text = """diff --git a/resources/messages_de.properties b/resources/messages_de.properties
+++ b/resources/messages_de.properties
+title=Open trades
diff --git a/resources/de/common.json b/resources/de/common.json
+++ b/resources/de/common.json
+  "cta": "Continue",
"""

    stats = analyze_semantic_qa_changes_for_profiles(
        diff_text=diff_text,
        repo_root=str(repo_root),
        input_folder=str(input_folder),
        locale_codes=["de"],
        brand_glossary=[],
        semantic_rules=[
            SemanticRule(
                id="no-english",
                message="German translation still contains source text.",
                locales=("de",),
                severity="warning",
                forbidden_target_regex=r"Open trades|Continue",
            )
        ],
        localization_profiles=(
            LocalizationProfile(JAVA_PROPERTIES_FORMAT, SUFFIX_LAYOUT),
            LocalizationProfile(JSON_FORMAT, layout),
        ),
    )

    assert stats.warnings_count == 2
    assert {example["file"] for example in stats.examples} == {
        "messages_de.properties",
        "de/common.json",
    }


def test_semantic_qa_deduplicates_overlapping_profile_changed_entries(tmp_path):
    repo_root = tmp_path
    input_folder = repo_root / "resources"
    _write_properties(input_folder / "messages.properties", {"title": "Open trades"})
    diff_text = """diff --git a/resources/messages_de.properties b/resources/messages_de.properties
+++ b/resources/messages_de.properties
+title=Open trades
"""

    stats = analyze_semantic_qa_changes_for_profiles(
        diff_text=diff_text,
        repo_root=str(repo_root),
        input_folder=str(input_folder),
        locale_codes=["de"],
        brand_glossary=[],
        semantic_rules=[
            SemanticRule(
                id="no-english",
                message="German translation still contains source text.",
                locales=("de",),
                severity="warning",
                forbidden_target_regex=r"Open trades",
            )
        ],
        localization_profiles=(
            LocalizationProfile(JAVA_PROPERTIES_FORMAT, SUFFIX_LAYOUT),
            LocalizationProfile(JAVA_PROPERTIES_FORMAT, SUFFIX_LAYOUT),
        ),
    )

    assert stats.warnings_count == 1
    assert len(stats.examples) == 1


def test_semantic_qa_deduplicates_overlapping_profile_full_audit_entries(tmp_path):
    repo_root = tmp_path
    input_folder = repo_root / "resources"
    _write_properties(input_folder / "messages.properties", {"title": "Open trades"})
    _write_properties(input_folder / "messages_de.properties", {"title": "Open trades"})

    stats = analyze_all_translation_entries_for_profiles(
        repo_root=str(repo_root),
        input_folder=str(input_folder),
        locale_codes=["de"],
        brand_glossary=[],
        semantic_rules=[
            SemanticRule(
                id="no-english",
                message="German translation still contains source text.",
                locales=("de",),
                severity="warning",
                forbidden_target_regex=r"Open trades",
            )
        ],
        localization_profiles=(
            LocalizationProfile(JAVA_PROPERTIES_FORMAT, SUFFIX_LAYOUT),
            LocalizationProfile(JAVA_PROPERTIES_FORMAT, SUFFIX_LAYOUT),
        ),
    )

    assert stats.warnings_count == 1
    assert len(stats.examples) == 1


def test_quality_gate_blocks_many_unexpected_source_identical_changes(tmp_path):
    repo_root = tmp_path
    input_folder = repo_root / "resources"
    _write_properties(
        input_folder / "mobile.properties",
        {
            "k1": "Open trades",
            "k2": "Sort",
            "k3": "Completed",
            "k4": "Cancelled",
            "k5": "Search",
        },
    )

    diff_text = """diff --git a/resources/mobile_es.properties b/resources/mobile_es.properties
+++ b/resources/mobile_es.properties
+k1=Open trades
+k2=Sort
+k3=Completed
+k4=Cancelled
+k5=Search
"""

    stats = analyze_source_identical_changes(
        diff_text=diff_text,
        repo_root=str(repo_root),
        input_folder=str(input_folder),
        locale_codes=["es"],
        brand_glossary=[],
    )
    report = build_quality_gate_report(
        source_stats=stats,
        semantic_stats=None,
        validation_summary={"files": {}, "pipeline_warnings": []},
        changed_files=["resources/mobile_es.properties"],
        input_folder=str(input_folder),
        config=QualityGateConfig(
            source_identical_min_block_count=5,
            source_identical_max_count=20,
            source_identical_max_ratio=0.30,
            block_on_pipeline_warnings=True,
        ),
    )

    assert report["blocking"] is True
    assert "source-identical" in report["blocking_reasons"][0]
    assert report["status_state"] == "failure"


def test_pipeline_warnings_are_blocking_when_configured():
    report = build_quality_gate_report(
        source_stats=analyze_source_identical_changes(
            diff_text="",
            repo_root=".",
            input_folder=".",
            locale_codes=["es"],
            brand_glossary=[],
        ),
        semantic_stats=None,
        validation_summary={
            "files": {},
            "pipeline_warnings": [
                {"file": "mobile_es.properties", "errors": ["Invalid escape sequence"]}
            ],
        },
        changed_files=["resources/mobile_es.properties"],
        input_folder="resources",
        config=QualityGateConfig(block_on_pipeline_warnings=True),
    )

    assert report["blocking"] is True
    assert report["pipeline_warnings_count"] == 1
    assert report["status_state"] == "failure"


def test_validation_control_and_placeholder_failures_are_blocking():
    source_stats = analyze_source_identical_changes(
        diff_text="",
        repo_root=".",
        input_folder="resources",
        locale_codes=["es"],
        brand_glossary=[],
    )
    source_stats.control_character_findings_count = 1

    report = build_quality_gate_report(
        source_stats=source_stats,
        semantic_stats=None,
        validation_summary={
            "files": {
                "mobile_es.properties": {
                    "reverted_keys_count": 2,
                    "control_character_findings_count": 1,
                    "placeholder_failures_count": 1,
                }
            },
            "pipeline_warnings": [],
        },
        changed_files=["resources/mobile_es.properties"],
        input_folder="resources",
        config=QualityGateConfig(block_on_pipeline_warnings=False),
    )

    assert report["blocking"] is True
    assert any("Control-character" in reason for reason in report["blocking_reasons"])
    assert any("Placeholder parity" in reason for reason in report["blocking_reasons"])


def test_model_translation_failures_are_blocking():
    report = build_quality_gate_report(
        source_stats=analyze_source_identical_changes(
            diff_text="",
            repo_root=".",
            input_folder="resources",
            locale_codes=["es"],
            brand_glossary=[],
        ),
        semantic_stats=None,
        validation_summary={
            "files": {
                "mobile_es.properties": {
                    "model_translation_failed_count": 1,
                    "model_translation_failed_keys": ["mobile.example"],
                }
            },
            "pipeline_warnings": [],
        },
        changed_files=["resources/mobile_es.properties"],
        input_folder="resources",
        config=QualityGateConfig(block_on_pipeline_warnings=False),
    )

    assert report["blocking"] is True
    assert report["validation"]["model_translation_failed_count"] == 1
    assert report["validation"]["model_translation_failed_keys"] == {
        "mobile_es.properties": ["mobile.example"]
    }
    assert any("Model translation" in reason for reason in report["blocking_reasons"])

    markdown = render_quality_gate_markdown(report)
    assert "### Model Translation Failures" in markdown
    assert "`mobile_es.properties` `mobile.example`" in markdown


def test_pipeline_warnings_are_filtered_to_current_batch():
    report = build_quality_gate_report(
        source_stats=analyze_source_identical_changes(
            diff_text="",
            repo_root=".",
            input_folder="resources",
            locale_codes=["es"],
            brand_glossary=[],
        ),
        semantic_stats=None,
        validation_summary={
            "files": {},
            "pipeline_warnings": [
                {"file": "mobile_es.properties", "errors": ["Current batch warning"]},
                {"file": "mobile_de.properties", "errors": ["Other batch warning"]},
            ],
        },
        changed_files=["resources/mobile_es.properties"],
        input_folder="resources",
        config=QualityGateConfig(block_on_pipeline_warnings=True),
    )

    assert report["blocking"] is True
    assert report["pipeline_warnings_count"] == 1
    assert report["pipeline_warnings"][0]["file"] == "mobile_es.properties"


def test_pipeline_warnings_from_other_batches_do_not_block():
    report = build_quality_gate_report(
        source_stats=analyze_source_identical_changes(
            diff_text="",
            repo_root=".",
            input_folder="resources",
            locale_codes=["es"],
            brand_glossary=[],
        ),
        semantic_stats=None,
        validation_summary={
            "files": {},
            "pipeline_warnings": [
                {"file": "mobile_de.properties", "errors": ["Other batch warning"]},
            ],
        },
        changed_files=["resources/mobile_es.properties"],
        input_folder="resources",
        config=QualityGateConfig(block_on_pipeline_warnings=True),
    )

    assert report["blocking"] is False
    assert report["pipeline_warnings_count"] == 0


def test_missing_validation_summary_loads_empty_summary(tmp_path):
    summary = load_validation_summary(str(tmp_path / "missing.json"))

    assert summary == {"files": {}, "pipeline_warnings": []}


def test_get_staged_diff_uses_pinned_no_color_diff_options():
    from localize.translation_quality_gate import get_staged_diff

    completed = MagicMock(returncode=0, stdout="diff", stderr="")
    with patch("localize.translation_quality_gate.subprocess.run", return_value=completed) as run:
        diff_text = get_staged_diff("/repo", ["resources/mobile_de.properties"])

    assert diff_text == "diff"
    command = run.call_args.args[0]
    assert command[:7] == [
        "git",
        "-c",
        "diff.noprefix=false",
        "-c",
        "core.quotePath=false",
        "diff",
        "--cached",
    ]
    assert "--no-color" in command
    assert "--no-ext-diff" in command


def test_semantic_qa_blocks_recent_coderabbit_translation_nits(tmp_path):
    repo_root = tmp_path
    input_folder = repo_root / "resources"
    input_folder.mkdir()
    _, _, _, semantic_rules = load_quality_gate_config(str(PROJECT_ROOT / "profiles" / "bisq" / "config.yaml"))
    diff_text = """diff --git a/resources/mobile_af_ZA.properties b/resources/mobile_af_ZA.properties
+++ b/resources/mobile_af_ZA.properties
+mobile.tradeHistory.count.many={0} handelaars
+mobile.tradeHistory.count.filtered={0} van {1} handelaars
diff --git a/resources/mobile_es.properties b/resources/mobile_es.properties
+++ b/resources/mobile_es.properties
+mobile.tradeHistory.details.tradersAndRole=Traders / Rol
diff --git a/resources/mobile_fr.properties b/resources/mobile_fr.properties
+++ b/resources/mobile_fr.properties
+mobile.tradeHistory.details.tradersAndRole=Traders / Rôle
diff --git a/resources/mobile_vi.properties b/resources/mobile_vi.properties
+++ b/resources/mobile_vi.properties
+mobile.tradeHistory.details.networkAddress.clear=Xóa địa chỉ mạng: {0}
"""

    semantic_stats = analyze_semantic_qa_changes(
        diff_text=diff_text,
        repo_root=str(repo_root),
        input_folder=str(input_folder),
        locale_codes=["af_ZA", "es", "fr", "vi"],
        semantic_rules=semantic_rules,
    )
    report = build_quality_gate_report(
        source_stats=analyze_source_identical_changes(
            diff_text="",
            repo_root=str(repo_root),
            input_folder=str(input_folder),
            locale_codes=["af_ZA", "es", "fr", "vi"],
            brand_glossary=[],
        ),
        semantic_stats=semantic_stats,
        validation_summary={"files": {}, "pipeline_warnings": []},
        changed_files=[
            "resources/mobile_af_ZA.properties",
            "resources/mobile_es.properties",
            "resources/mobile_fr.properties",
            "resources/mobile_vi.properties",
        ],
        input_folder=str(input_folder),
        config=QualityGateConfig(block_on_semantic_qa_findings=True),
    )

    assert semantic_stats.findings_count == 5
    assert semantic_stats.errors_count == 5
    assert report["blocking"] is True
    assert "Semantic translation QA" in report["blocking_reasons"][0]


def test_semantic_qa_reports_retained_source_words_but_ignores_glossary(tmp_path):
    repo_root = tmp_path
    input_folder = repo_root / "resources"
    _write_properties(
        input_folder / "mobile.properties",
        {
            "mobile.some.label": "Settlement Details",
            "mobile.invoice": "Lightning invoice",
        },
    )
    diff_text = """diff --git a/resources/mobile_es.properties b/resources/mobile_es.properties
+++ b/resources/mobile_es.properties
+mobile.some.label=Detalles Settlement
+mobile.invoice=Factura Lightning
"""

    semantic_stats = analyze_semantic_qa_changes(
        diff_text=diff_text,
        repo_root=str(repo_root),
        input_folder=str(input_folder),
        locale_codes=["es"],
        brand_glossary=["Lightning"],
    )

    assert semantic_stats.findings_count == 1
    assert "Settlement" in semantic_stats.examples[0]["reason"]


def test_quality_gate_excludes_remediated_semantic_review_findings():
    report = build_quality_gate_report(
        source_stats=analyze_source_identical_changes(
            diff_text="",
            repo_root=".",
            input_folder="resources",
            locale_codes=["es"],
            brand_glossary=[],
        ),
        semantic_stats=None,
        validation_summary={
            "files": {},
            "pipeline_warnings": [],
            "semantic_review_findings": [
                {
                    "file": "mobile_es.properties",
                    "key": "mobile.peer.count",
                    "severity": "error",
                    "reason": "Connected peers was mistranslated.",
                    "value": "Conexiones de pares: {0}",
                    "suggested_value": "Pares conectados: {0}",
                    "finding_signature": "peer-count-finding",
                    "rule_id": "ai-review",
                    "source": "ai-review",
                },
                {
                    "file": "mobile_es.properties",
                    "key": "mobile.slow.body",
                    "severity": "warning",
                    "reason": "Encrypted should use stronger security terminology.",
                    "value": "Tu conexión está encriptada.",
                    "suggested_value": "Tu conexión está cifrada.",
                    "finding_signature": "encrypted-warning",
                    "rule_id": "ai-review",
                    "source": "ai-review",
                },
            ],
            "semantic_review_remediations": [
                {
                    "file": "mobile_es.properties",
                    "key": "mobile.peer.count",
                    "finding_signature": "peer-count-finding",
                },
            ],
        },
        changed_files=["resources/mobile_es.properties"],
        input_folder="resources",
        config=QualityGateConfig(block_on_semantic_qa_findings=True),
    )

    assert report["semantic_qa"]["findings_count"] == 1
    assert report["semantic_qa"]["errors_count"] == 0
    assert report["semantic_qa"]["warnings_count"] == 1
    assert report["semantic_qa"]["source_breakdown"]["ai_review"]["findings_count"] == 1
    assert report["semantic_qa"]["source_breakdown"]["remediated_ai_findings_count"] == 1
    assert report["blocking"] is False


def test_quality_gate_markdown_separates_semantic_sources():
    report = build_quality_gate_report(
        source_stats=analyze_source_identical_changes(
            diff_text="",
            repo_root=".",
            input_folder="resources",
            locale_codes=["es"],
            brand_glossary=[],
        ),
        semantic_stats=SemanticQAStats(
            findings_count=1,
            warnings_count=1,
            examples=[
                {
                    "file": "mobile_es.properties",
                    "key": "mobile.internet",
                    "value": "conexión a internet",
                    "reason": "Target may retain untranslated source term(s): internet.",
                    "severity": "warning",
                    "rule_id": "retained-source-word",
                    "source": "heuristic",
                }
            ],
        ),
        validation_summary={
            "files": {},
            "pipeline_warnings": [],
            "semantic_review_findings": [
                {
                    "file": "mobile_es.properties",
                    "key": "mobile.slow.body",
                    "severity": "warning",
                    "reason": "Encrypted should use stronger security terminology.",
                    "value": "Tu conexión está encriptada.",
                    "suggested_value": "Tu conexión está cifrada.",
                    "finding_signature": "encrypted-warning",
                    "rule_id": "ai-review",
                    "source": "ai-review",
                },
            ],
        },
        changed_files=["resources/mobile_es.properties"],
        input_folder="resources",
        config=QualityGateConfig(),
    )

    markdown = render_quality_gate_markdown(report)

    assert "AI review: 1" in markdown
    assert "rules/heuristics: 1" in markdown
    assert "### Semantic QA Examples" in markdown
    assert "#### AI Review" in markdown
    assert "#### Rules And Heuristics" in markdown
    assert "Suggested: `Tu conexión está cifrada.`" in markdown
    assert "Target may retain untranslated source term(s): internet." in markdown


def test_quality_gate_markdown_contains_validation_summary():
    report = {
        "blocking": False,
        "source_identical": {
            "changed_entries_count": 10,
            "checked_entries_count": 8,
            "source_identical_count": 3,
            "expected_source_identical_count": 2,
            "unexpected_source_identical_count": 1,
            "unexpected_source_identical_ratio": 0.125,
            "examples": [],
        },
        "semantic_qa": {
            "findings_count": 1,
            "examples": [
                {
                    "file": "mobile_es.properties",
                    "key": "mobile.tradeHistory.details.tradersAndRole",
                    "value": "Traders / Rol",
                    "reason": "Trade Details traders/role label contains untranslated English term 'Traders'.",
                }
            ],
        },
        "validation": {
            "reverted_keys_count": 2,
            "control_character_findings_count": 1,
            "placeholder_failures_count": 1,
        },
        "pipeline_warnings_count": 0,
        "pipeline_warnings": [],
        "blocking_reasons": [],
    }

    markdown = render_quality_gate_markdown(report)

    assert "Translation Validation Summary" in markdown
    assert "Unexpected source-identical changed values" in markdown
    assert "Semantic QA findings" in markdown
    assert "Semantic QA Examples" in markdown
    assert "Reverted keys" in markdown
    assert "Control-character findings" in markdown
    assert "| Model translation failures | 0 |" in markdown


def test_quality_gate_markdown_escapes_semantic_review_text():
    report = {
        "blocking": True,
        "source_identical": {
            "changed_entries_count": 0,
            "checked_entries_count": 0,
            "source_identical_count": 0,
            "expected_source_identical_count": 0,
            "unexpected_source_identical_count": 0,
            "unexpected_source_identical_ratio": 0.0,
            "examples": [],
        },
        "semantic_qa": {
            "findings_count": 1,
            "errors_count": 1,
            "warnings_count": 0,
            "source_breakdown": {
                "ai_review": {
                    "findings_count": 1,
                    "errors_count": 1,
                    "warnings_count": 0,
                    "examples": [
                        {
                            "file": "mobile_de.properties",
                            "key": "bad`key",
                            "value": "value`\r\n**Status:** Passed",
                            "reason": "reason`\r\n### Spoofed",
                            "suggested_value": "fix`",
                        }
                    ],
                },
                "rules_and_heuristics": {"findings_count": 0, "examples": []},
            },
            "examples": [],
        },
        "validation": {
            "reverted_keys_count": 0,
            "control_character_findings_count": 0,
            "placeholder_failures_count": 0,
        },
        "pipeline_warnings_count": 0,
        "pipeline_warnings": [],
        "blocking_reasons": ["Semantic translation QA found blocking issues."],
    }

    markdown = render_quality_gate_markdown(report)

    assert "reason\\`\\r\\n### Spoofed" in markdown
    assert "value\\`\\r\\n**Status:** Passed" in markdown
    assert "`bad\\`key`" in markdown
