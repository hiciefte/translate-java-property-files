"""Unit tests for reusable translation prompt construction."""

from localize.localization_formats import JAVA_PROPERTIES_FORMAT
from localize.translation_prompts import build_translation_system_prompt


def test_translation_system_prompt_is_generic_without_project_context():
    prompt = build_translation_system_prompt(
        target_language="German",
        style_rules_text="",
        project_context="",
        localization_format=JAVA_PROPERTIES_FORMAT,
    )

    assert "software localization" in prompt
    assert "Bisq" not in prompt
    assert "desktop trading app" not in prompt


def test_translation_system_prompt_includes_configured_project_context():
    prompt = build_translation_system_prompt(
        target_language="German",
        style_rules_text="",
        project_context="Translate for Acme Cloud's admin console.",
        localization_format=JAVA_PROPERTIES_FORMAT,
    )

    assert "Project Context" in prompt
    assert "Acme Cloud" in prompt


def test_translation_system_prompt_describes_prompt_only_glossary_as_lemmas():
    prompt = build_translation_system_prompt(
        target_language="Russian",
        style_rules_text="",
        project_context="",
        localization_format=JAVA_PROPERTIES_FORMAT,
        translation_glossary_enforcement="prompt-only",
    )

    assert "preferred terminology guidance" in prompt
    assert "Inflect or adapt" in prompt
    assert "non-negotiable" not in prompt


def test_translation_system_prompt_mentions_format_metadata():
    prompt = build_translation_system_prompt(
        target_language="German",
        style_rules_text="",
        project_context="",
        localization_format=JAVA_PROPERTIES_FORMAT,
    )

    assert JAVA_PROPERTIES_FORMAT.display_name in prompt


def test_translation_system_prompt_requests_grammatical_number_agreement():
    prompt = build_translation_system_prompt(
        target_language="German",
        style_rules_text="",
        project_context="",
        localization_format=JAVA_PROPERTIES_FORMAT,
    )

    assert "grammatical number" in prompt
    # Singular/plural count-template families must be called out explicitly so
    # the model does not reuse the plural wording for the singular case.
    assert ".single" in prompt
    assert ".plural" in prompt
    # The bisq-mobile i18nPlural convention uses `.1`/`.*` count keys, where
    # `.*` is a catch-all for every count other than one (bisq-mobile#1669).
    assert "`.1`" in prompt
    assert "`.*`" in prompt
    assert "catch-all" in prompt
    assert "count-neutral" in prompt
    assert "identical singular and plural target forms are acceptable" in prompt
    # The example must render a real placeholder, not a doubled f-string brace.
    assert "Used {0} time" in prompt
    assert "{{0}}" not in prompt


def test_translation_system_prompt_requests_ui_label_cross_reference_consistency():
    prompt = build_translation_system_prompt(
        target_language="German",
        style_rules_text="",
        project_context="",
        localization_format=JAVA_PROPERTIES_FORMAT,
    )

    # Strings that reference other UI elements by name (navigation paths, quoted
    # menu/button labels) must reuse the existing localized label wording so the
    # instructions match the controls the user actually sees.
    assert "Keep references to other UI labels consistent" in prompt
    assert "context examples and existing translations" in prompt
    # Guidance must stay product-agnostic; no concrete menu names leak in.
    assert "Bisq" not in prompt


def test_translation_system_prompt_warns_against_compound_splitting():
    prompt = build_translation_system_prompt(
        target_language="Norwegian",
        style_rules_text="",
        project_context="",
        localization_format=JAVA_PROPERTIES_FORMAT,
    )

    # Compound-building languages must keep closed compounds joined rather than
    # splitting them (Norwegian saerskriving), which recurred in wallet keys.
    assert "compound noun" in prompt
    assert "Adressenotat" in prompt
    assert "Adresse notat" in prompt
    assert "Do not mechanically join" in prompt


def test_translation_system_prompt_warns_against_dangling_connective_fragments():
    """Keep fragment guidance open-ended without product-specific instructions."""
    prompt = build_translation_system_prompt(
        target_language="Hindi",
        style_rules_text="",
        project_context="",
        localization_format=JAVA_PROPERTIES_FORMAT,
    )

    # Fragment labels that end on a preposition/connective are completed by an
    # element the UI appends after them; the model must not invent a closing
    # referent that orphans that element (bisq-mobile#1822 hi connectedVia
    # regressed "connected via" to "connected through it").
    assert "Keep trailing connective fragments open-ended" in prompt
    assert "connected via the following" in prompt
    assert "do not invent a demonstrative or pronoun referent" in prompt
    # Guidance must stay product-agnostic; no concrete product names leak in.
    assert "Bisq" not in prompt
