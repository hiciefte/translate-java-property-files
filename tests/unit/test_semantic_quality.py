from pathlib import Path
import json

from localize.localization_formats import JSON_FORMAT
from localize.localization_layouts import LocalizationLayout
from localize.semantic_quality import (
    SemanticRule,
    TranslationChange,
    analyze_all_translation_entries,
    evaluate_retained_source_words,
    evaluate_semantic_rules,
    iter_translation_changes_from_diff,
    load_semantic_rules,
)
from localize.translation_quality_gate import (
    QualityGateConfig,
    analyze_semantic_qa_changes,
    analyze_source_identical_changes,
    build_quality_gate_report,
    load_quality_gate_config,
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


def test_declarative_semantic_rule_blocks_forbidden_target_text(tmp_path):
    repo_root = tmp_path
    input_folder = repo_root / "resources"
    input_folder.mkdir()
    rules = [
        SemanticRule(
            id="trade-history-traders-label",
            message="Fully localize the traders label.",
            locales=("es", "fr"),
            keys=("mobile.tradeHistory.details.tradersAndRole",),
            forbidden_target_regex=r"\bTraders\b",
            severity="error",
        )
    ]
    diff_text = """diff --git a/resources/mobile_es.properties b/resources/mobile_es.properties
+++ b/resources/mobile_es.properties
+mobile.tradeHistory.details.tradersAndRole=Traders / Rol
"""

    semantic_stats = analyze_semantic_qa_changes(
        diff_text=diff_text,
        repo_root=str(repo_root),
        input_folder=str(input_folder),
        locale_codes=["es"],
        semantic_rules=rules,
    )
    report = build_quality_gate_report(
        source_stats=analyze_source_identical_changes(
            diff_text="",
            repo_root=str(repo_root),
            input_folder=str(input_folder),
            locale_codes=["es"],
            brand_glossary=[],
        ),
        semantic_stats=semantic_stats,
        validation_summary={"files": {}, "pipeline_warnings": []},
        changed_files=["resources/mobile_es.properties"],
        input_folder=str(input_folder),
        config=QualityGateConfig(block_on_semantic_qa_findings=True),
    )

    assert semantic_stats.errors_count == 1
    assert semantic_stats.warnings_count == 0
    assert semantic_stats.examples[0]["rule_id"] == "trade-history-traders-label"
    assert report["blocking"] is True


def test_retained_source_word_findings_are_warning_only_by_default():
    change = TranslationChange(
        file="resources/mobile_es.properties",
        locale_code="es",
        key="mobile.some.label",
        source_value="Settlement Details",
        old_value=None,
        new_value="Detalles Settlement",
    )

    findings = evaluate_retained_source_words(
        changes=[change],
        brand_glossary=["Lightning"],
    )

    assert len(findings) == 1
    assert findings[0].severity == "warning"
    assert findings[0].rule_id == "retained-source-word"


def test_retained_source_word_allowlist_is_locale_scoped():
    changes = [
        TranslationChange(
            file="resources/mobile_es.properties",
            locale_code="es",
            key="mobile.settings.analytics.info.noPii",
            source_value="No personal information, accounts, or device IDs",
            old_value=None,
            new_value="No se recopila información personal, cuentas o IDs de dispositivo",
        ),
        TranslationChange(
            file="resources/mobile_fr.properties",
            locale_code="fr",
            key="mobile.settings.analytics.info.noPii",
            source_value="No personal information, accounts, or device IDs",
            old_value=None,
            new_value="Aucune information personnelle, aucun compte ni identifiant d'appareil",
        ),
        TranslationChange(
            file="resources/mobile_it.properties",
            locale_code="it",
            key="mobile.settings.analytics.title",
            source_value="Crash & usage reporting",
            old_value=None,
            new_value="Reporting di crash e utilizzo",
        ),
        TranslationChange(
            file="resources/mobile_de.properties",
            locale_code="de",
            key="mobile.settings.analytics.info.noPii",
            source_value="No personal information, accounts, or device IDs",
            old_value=None,
            new_value="Keine personal Daten",
        ),
    ]

    findings = evaluate_retained_source_words(
        changes=changes,
        brand_glossary=[],
        retained_source_word_allowlist={
            "es": ["personal"],
            "fr": ["information", "message", "messages"],
            "it": ["reporting"],
        },
    )

    assert len(findings) == 1
    assert findings[0].file == "resources/mobile_de.properties"
    assert "personal" in findings[0].reason


def test_retained_source_words_use_language_allowlists_for_regional_locales():
    changes = [
        TranslationChange(
            file="resources/mobile_ru_RU.properties",
            locale_code="ru_RU",
            key="mobile.offerbook.open",
            source_value="Open Offerbook",
            old_value="Открыть книгу предложений",
            new_value="Открыть Offerbook",
        ),
        TranslationChange(
            file="resources/mobile_vi_VN.properties",
            locale_code="vi_VN",
            key="mobile.offer.take",
            source_value="Select take-offer",
            old_value="Chọn đề nghị",
            new_value="Chọn take-offer",
        ),
        TranslationChange(
            file="resources/mobile_vi_VN.properties",
            locale_code="vi_VN",
            key="mobile.lightning",
            source_value="Use Lightning",
            old_value="Dùng Lightning",
            new_value="Sử dụng Lightning",
        ),
        TranslationChange(
            file="resources/mobile_vi_VN.properties",
            locale_code="vi_VN",
            key="mobile.personal",
            source_value="Personal information",
            old_value="Thông tin cá nhân",
            new_value="Thông tin personal",
        ),
    ]

    findings = evaluate_retained_source_words(
        changes=changes,
        brand_glossary=["Lightning"],
        retained_source_word_allowlist={"vi": ["personal"]},
    )

    assert [finding.key for finding in findings] == [
        "mobile.offerbook.open",
        "mobile.offer.take",
    ]
    assert "Offerbook" in findings[0].reason
    assert "take-offer" in findings[1].reason


def test_semantic_warnings_do_not_block_unless_configured(tmp_path):
    repo_root = tmp_path
    input_folder = repo_root / "resources"
    _write_properties(input_folder / "mobile.properties", {"k": "Settlement Details"})
    diff_text = """diff --git a/resources/mobile_es.properties b/resources/mobile_es.properties
+++ b/resources/mobile_es.properties
+k=Detalles Settlement
"""

    semantic_stats = analyze_semantic_qa_changes(
        diff_text=diff_text,
        repo_root=str(repo_root),
        input_folder=str(input_folder),
        locale_codes=["es"],
        brand_glossary=[],
    )
    report = build_quality_gate_report(
        source_stats=analyze_source_identical_changes(
            diff_text="",
            repo_root=str(repo_root),
            input_folder=str(input_folder),
            locale_codes=["es"],
            brand_glossary=[],
        ),
        semantic_stats=semantic_stats,
        validation_summary={"files": {}, "pipeline_warnings": []},
        changed_files=["resources/mobile_es.properties"],
        input_folder=str(input_folder),
        config=QualityGateConfig(
            block_on_semantic_qa_findings=True,
            block_on_semantic_qa_warnings=False,
        ),
    )

    assert semantic_stats.findings_count == 1
    assert semantic_stats.warnings_count == 1
    assert report["blocking"] is False


def test_properties_diff_continuation_does_not_swallow_next_hunk(tmp_path):
    repo_root = tmp_path
    input_folder = repo_root / "resources"
    input_folder.mkdir()
    diff_text = """diff --git a/resources/messages_de.properties b/resources/messages_de.properties
--- a/resources/messages_de.properties
+++ b/resources/messages_de.properties
@@ -1 +1 @@
+first=Hallo \\
@@ -8 +8 @@
+second=Welt
"""

    changes = list(
        iter_translation_changes_from_diff(
            diff_text=diff_text,
            repo_root=str(repo_root),
            input_folder=str(input_folder),
            locale_codes=["de"],
        )
    )

    assert [change.key for change in changes] == ["first", "second"]


def test_json_diff_ambiguity_reports_all_matching_leaf_values(tmp_path):
    repo_root = tmp_path
    input_folder = repo_root / "resources"
    _write_json(
        input_folder / "messages_de.json",
        {
            "dialog": {"label": "Open"},
            "menu": {"label": "Open"},
        },
    )
    diff_text = """diff --git a/resources/messages_de.json b/resources/messages_de.json
--- a/resources/messages_de.json
+++ b/resources/messages_de.json
@@ -2 +2 @@
+    "label": "Open"
"""

    changes = list(
        iter_translation_changes_from_diff(
            diff_text=diff_text,
            repo_root=str(repo_root),
            input_folder=str(input_folder),
            locale_codes=["de"],
            localization_format=JSON_FORMAT,
        )
    )

    assert {change.key for change in changes} == {"/dialog/label", "/menu/label"}


def test_ai_review_error_findings_are_folded_into_quality_gate(tmp_path):
    report = build_quality_gate_report(
        source_stats=analyze_source_identical_changes(
            diff_text="",
            repo_root=str(tmp_path),
            input_folder=str(tmp_path),
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
                    "key": "mobile.clear",
                    "severity": "error",
                    "reason": "The target uses a delete verb for a clearnet label.",
                    "value": "Borrar red: {0}",
                    "source": "ai-review",
                }
            ],
        },
        changed_files=["resources/mobile_es.properties"],
        input_folder="resources",
        config=QualityGateConfig(block_on_semantic_qa_findings=True),
    )

    assert report["semantic_qa"]["errors_count"] == 1
    assert report["blocking"] is True
    assert "Semantic translation QA" in report["blocking_reasons"][0]


def test_full_semantic_audit_scans_entries_without_diff(tmp_path):
    repo_root = tmp_path
    input_folder = repo_root / "resources"
    _write_properties(input_folder / "mobile.properties", {"mobile.some.label": "Settlement Details"})
    _write_properties(input_folder / "mobile_es.properties", {"mobile.some.label": "Detalles Settlement"})

    stats = analyze_all_translation_entries(
        repo_root=str(repo_root),
        input_folder=str(input_folder),
        locale_codes=["es"],
        brand_glossary=[],
        semantic_rules=[],
    )

    assert stats.findings_count == 1
    assert stats.warnings_count == 1
    assert stats.examples[0]["file"] == "mobile_es.properties"


def test_full_semantic_audit_scans_json_locale_directory_entries(tmp_path):
    repo_root = tmp_path
    input_folder = repo_root / "locales"
    layout = LocalizationLayout(id="locale_directory", source_locale="en")
    _write_json(input_folder / "en" / "common.json", {"label": "Settlement Details"})
    _write_json(input_folder / "es" / "common.json", {"label": "Detalles Settlement"})

    stats = analyze_all_translation_entries(
        repo_root=str(repo_root),
        input_folder=str(input_folder),
        locale_codes=["es"],
        brand_glossary=[],
        semantic_rules=[],
        localization_format=JSON_FORMAT,
        localization_layout=layout,
    )

    assert stats.findings_count == 1
    assert stats.examples[0]["file"] == "es/common.json"
    assert stats.examples[0]["key"] == "/label"


def test_changed_json_diff_yields_only_changed_leaf(tmp_path):
    repo_root = tmp_path
    input_folder = repo_root / "locales"
    layout = LocalizationLayout(id="locale_directory", source_locale="en")
    _write_json(
        input_folder / "en" / "common.json",
        {
            "title": "Open trades",
            "steps": [{"label": "Review details"}],
        },
    )
    _write_json(
        input_folder / "de" / "common.json",
        {
            "title": "Open trades",
            "steps": [{"label": "Review details"}],
        },
    )
    diff_text = """diff --git a/locales/de/common.json b/locales/de/common.json
+++ b/locales/de/common.json
+  "title": "Open trades",
"""

    changes = list(iter_translation_changes_from_diff(
        diff_text=diff_text,
        repo_root=str(repo_root),
        input_folder=str(input_folder),
        locale_codes=["de"],
        localization_format=JSON_FORMAT,
        localization_layout=layout,
    ))

    assert [(change.key, change.new_value) for change in changes] == [
        ("/title", "Open trades"),
    ]


def test_changed_json_diff_disambiguates_nested_leaf_by_value(tmp_path):
    repo_root = tmp_path
    input_folder = repo_root / "locales"
    layout = LocalizationLayout(id="locale_directory", source_locale="en")
    _write_json(
        input_folder / "en" / "common.json",
        {
            "title": "Top title",
            "nested": {"title": "Nested title"},
        },
    )
    _write_json(
        input_folder / "de" / "common.json",
        {
            "title": "Obertitel",
            "nested": {"title": "Verschachtelter Titel"},
        },
    )
    diff_text = """diff --git a/locales/de/common.json b/locales/de/common.json
+++ b/locales/de/common.json
+    "title": "Verschachtelter Titel",
"""

    changes = list(iter_translation_changes_from_diff(
        diff_text=diff_text,
        repo_root=str(repo_root),
        input_folder=str(input_folder),
        locale_codes=["de"],
        localization_format=JSON_FORMAT,
        localization_layout=layout,
    ))

    assert [(change.key, change.new_value) for change in changes] == [
        ("/nested/title", "Verschachtelter Titel"),
    ]


def test_changed_properties_diff_joins_multiline_continuations(tmp_path):
    repo_root = tmp_path
    input_folder = repo_root / "resources"
    _write_properties(input_folder / "mobile.properties", {"long": "Hello world"})
    diff_text = """diff --git a/resources/mobile_de.properties b/resources/mobile_de.properties
+++ b/resources/mobile_de.properties
+long=Hallo \\
+Welt
"""

    changes = list(iter_translation_changes_from_diff(
        diff_text=diff_text,
        repo_root=str(repo_root),
        input_folder=str(input_folder),
        locale_codes=["de"],
    ))

    assert [(change.key, change.new_value) for change in changes] == [
        ("long", "Hallo Welt"),
    ]


def test_feedback_rules_load_review_source_metadata():
    rules = load_semantic_rules(
        [
            {
                "id": "vi-clearnet-clear",
                "message": "Do not translate clear as delete.",
                "locales": ["vi"],
                "keys": ["mobile.tradeHistory.details.networkAddress.clear"],
                "forbidden_target_regex": r"^Xóa\b",
                "severity": "error",
                "source": "bisq-mobile#1478 CodeRabbit",
            }
        ]
    )

    findings = evaluate_semantic_rules(
        changes=[
            TranslationChange(
                file="resources/mobile_vi.properties",
                locale_code="vi",
                key="mobile.tradeHistory.details.networkAddress.clear",
                source_value="Clear network address: {0}",
                old_value=None,
                new_value="Xóa địa chỉ mạng: {0}",
            )
        ],
        rules=rules,
    )

    assert findings[0].rule_id == "vi-clearnet-clear"
    assert findings[0].source == "bisq-mobile#1478 CodeRabbit"


def test_configured_semantic_rules_catch_recent_mobile_review_nits():
    rules = load_semantic_rules(
        [
            {
                "id": "analytics-cta-truncated-reporting",
                "message": "Analytics CTA contains truncated English.",
                "locales": ["*"],
                "keys": ["*"],
                "forbidden_target_regex": r"\breportin\b",
                "severity": "error",
            },
            {
                "id": "analytics-cta-reporting-loanword",
                "message": "Fully localize the analytics CTA.",
                "locales": ["fr", "it"],
                "keys": ["mobile.welcomeCarousel.analytics.action"],
                "forbidden_target_regex": r"\breporting\b",
                "severity": "error",
            },
            {
                "id": "it-analytics-self-hosted",
                "message": "Italian analytics retention copy must localize self-hosted.",
                "locales": ["it"],
                "keys": ["*"],
                "forbidden_target_regex": r"\bself-hosted\b",
                "severity": "error",
            },
            {
                "id": "fr-analytics-no-pii-negation",
                "message": "French no-PII copy must keep parallel negation.",
                "locales": ["fr"],
                "keys": ["mobile.settings.analytics.info.noPii"],
                "forbidden_target_regex": r"^Aucune information personnelle,\s*comptes\b",
                "severity": "error",
            },
        ]
    )

    findings = evaluate_semantic_rules(
        changes=[
            TranslationChange(
                file="mobile_fr.properties",
                locale_code="fr",
                key="mobile.settings.analytics.info.noPii",
                source_value="No personal information, accounts, or device IDs",
                old_value=None,
                new_value="Aucune information personnelle, comptes ou identifiants d'appareil",
            ),
            TranslationChange(
                file="mobile_fr.properties",
                locale_code="fr",
                key="mobile.welcomeCarousel.analytics.action",
                source_value="Enable reporting",
                old_value=None,
                new_value="Activer le reporting",
            ),
            TranslationChange(
                file="mobile_it.properties",
                locale_code="it",
                key="mobile.welcomeCarousel.analytics.action",
                source_value="Enable reporting",
                old_value=None,
                new_value="Abilita il reporting",
            ),
            TranslationChange(
                file="mobile_it.properties",
                locale_code="it",
                key="mobile.settings.analytics.info.retention",
                source_value="Automatically deleted after 90 days on a self-hosted server",
                old_value=None,
                new_value="Eliminato automaticamente dopo 90 giorni su un server self-hosted",
            ),
            TranslationChange(
                file="mobile_pcm.properties",
                locale_code="pcm",
                key="mobile.welcomeCarousel.analytics.action",
                source_value="Enable reporting",
                old_value=None,
                new_value="Enable reportin",
            ),
        ],
        rules=rules,
    )

    assert {finding.rule_id for finding in findings} == {
        "analytics-cta-truncated-reporting",
        "analytics-cta-reporting-loanword",
        "it-analytics-self-hosted",
        "fr-analytics-no-pii-negation",
    }
    assert sum(1 for finding in findings if finding.rule_id == "analytics-cta-reporting-loanword") == 2


def test_configured_semantic_rules_catch_bisq2_review_nits():
    # Bisq project knowledge lives in the Bisq profile (the example is minimal/generic).
    _, _, _, rules = load_quality_gate_config(str(PROJECT_ROOT / "profiles" / "bisq" / "config.yaml"))

    findings = evaluate_semantic_rules(
        changes=[
            TranslationChange(
                file="application_el.properties",
                locale_code="el",
                key="tac.risk.noGuarantees.body",
                source_value="Dispute resolution may help in some situations, but recovery, refund, or compensation cannot be guaranteed.",
                old_value=None,
                new_value="Η αποκατάσταση, η αποζημίωση ή η αποζημίωση δεν μπορούν να εγγυηθούν.",
            ),
            TranslationChange(
                file="application_fi.properties",
                locale_code="fi",
                key="tac.legal.section3.body",
                source_value="Users are responsible for independently verifying all information before relying on it.",
                old_value=None,
                new_value="Käyttäjät ovat vastuussa kaikentietojen itsenäisestä vahvistamisesta.",
            ),
            TranslationChange(
                file="application_fr.properties",
                locale_code="fr",
                key="tac.legal.section4.body",
                source_value="These payment methods may involve account freezes.",
                old_value=None,
                new_value="Ces méthodes peuvent impliquer des gel des comptes.",
            ),
            TranslationChange(
                file="application_ga.properties",
                locale_code="ga",
                key="tac.legal.section6.body",
                source_value="No central entity holds custody of user funds.",
                old_value=None,
                new_value="Ní choinníonn sé custaim de chuid úsáideoirí.",
            ),
            TranslationChange(
                file="application_ha.properties",
                locale_code="ha",
                key="tac.risk.noGuarantees.title",
                source_value="No Guarantee of Recovery or Compensation",
                old_value=None,
                new_value="Babu Tabbatarwa na Dawowa ko Kwamfuta",
            ),
            TranslationChange(
                file="application_mk.properties",
                locale_code="mk",
                key="tac.legal.section6.body",
                source_value="No central entity controls the network.",
                old_value=None,
                new_value="Нема централна ентиетa која ја контролира мрежата.",
            ),
            TranslationChange(
                file="application_sl.properties",
                locale_code="sl",
                key="tac.risk.p2p.body",
                source_value="Bisq developers, contributors, and the Bisq DAO do not control user funds.",
                old_value=None,
                new_value="Razvijalci Bisq, prispevki in Bisq DAO ne nadzorujejo uporabniških sredstev.",
            ),
            TranslationChange(
                file="application_sr.properties",
                locale_code="sr",
                key="tac.risk.financial.body",
                source_value="Software vulnerabilities may lead to unrecoverable losses.",
                old_value=None,
                new_value="Ране у софтверу могу довести до неповратних губитака.",
            ),
            TranslationChange(
                file="application_th.properties",
                locale_code="th",
                key="tac.legal.section1.body",
                source_value="without warranties or representations of any kind",
                old_value=None,
                new_value="โดยไม่มีการรับประกันหรือการแสดงออกใด ๆ",
            ),
            TranslationChange(
                file="application_yo.properties",
                locale_code="yo",
                key="tac.legal.headline",
                source_value="Legal Terms",
                old_value=None,
                new_value="Àwọn Ọ̀rọ̀ Ìṣèlú",
            ),
            TranslationChange(
                file="bisq_easy_af_ZA.properties",
                locale_code="af_ZA",
                key="bisqEasy.tradeGuide.rules.content",
                source_value="Either party can cancel the trade without justification.",
                old_value=None,
                new_value="Enige party kan die handel sonder regverdigheid kanselleer.",
            ),
            TranslationChange(
                file="bisq_easy_ca.properties",
                locale_code="ca",
                key="bisqEasy.tradeGuide.rules.content",
                source_value="Before account details are exchanged",
                old_value=None,
                new_value="Abans que es canviïn els detalls del compte",
            ),
            TranslationChange(
                file="bisq_easy_fi.properties",
                locale_code="fi",
                key="bisqEasy.tradeGuide.rules.content",
                source_value="For unresolved issues, invite a mediator.",
                old_value=None,
                new_value="Ratkaisemattomissa asioissa kutsu välimies.",
            ),
            TranslationChange(
                file="bisq_easy_fr.properties",
                locale_code="fr",
                key="bisqEasy.tradeGuide.rules.content",
                source_value="Traders must check their trades regularly.",
                old_value=None,
                new_value="Les commerçants doivent vérifier régulièrement leurs échanges.",
            ),
            TranslationChange(
                file="bisq_easy_ga.properties",
                locale_code="ga",
                key="bisqEasy.tradeGuide.rules.content",
                source_value="For unresolved issues, invite a mediator.",
                old_value=None,
                new_value="Maidir le fadhbanna nach bhfuil réitithe, cuir i gcuimhne idirghabhálaí.",
            ),
            TranslationChange(
                file="bisq_easy_hr.properties",
                locale_code="hr",
                key="bisqEasy.tradeGuide.rules.content",
                source_value="The mediator cannot guarantee a refund.",
                old_value=None,
                new_value="Posrednik ne može jamčiti povratak.",
            ),
            TranslationChange(
                file="bisq_easy_ta.properties",
                locale_code="ta",
                key="bisqEasy.tradeGuide.rules.content",
                source_value="This does not apply if the trade peer does not respond.",
                old_value=None,
                new_value="இது வர்த்தக சகோதரர் பதிலளிக்காத போது பொருந்தாது.",
            ),
        ],
        rules=rules,
    )

    assert {finding.rule_id for finding in findings} == {
        "el-tac-duplicate-compensation",
        "fi-tac-fused-all-information",
        "fr-tac-account-freeze-plural",
        "ga-tac-custody-customs",
        "ha-tac-compensation-computer",
        "mk-tac-central-entity-typo",
        "sl-tac-contributors-noun",
        "sr-tac-software-vulnerabilities",
        "th-tac-legal-representations",
        "yo-tac-risk-legal-headlines",
        "af-trade-guide-without-justification",
        "ca-trade-guide-exchange-account-details",
        "fi-trade-guide-mediator-term",
        "fr-trade-guide-trader-term",
        "ga-trade-guide-request-mediator",
        "hr-trade-guide-refund-term",
        "ta-trade-guide-counterparty-term",
    }
