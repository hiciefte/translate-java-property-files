"""Prompt builders for localization API calls."""

from localize.localization_formats import LocalizationFormat


def build_translation_system_prompt(
        target_language: str,
        style_rules_text: str,
        project_context: str,
        localization_format: LocalizationFormat,
        translation_glossary_enforcement: str = "exact",
) -> str:
    """Build the reusable system prompt for a single localization value."""
    project_context = project_context.strip()
    project_context_section = ""
    if project_context:
        project_context_section = f"""
**Project Context**:
{project_context}
"""

    if translation_glossary_enforcement == "prompt-only":
        translation_glossary_rule = (
            "The Translation Glossary is preferred terminology guidance. Use each "
            "target value as the preferred base term. Inflect or adapt it when "
            "target-language grammar requires; do not force an ungrammatical exact "
            "surface form."
        )
    else:
        translation_glossary_rule = (
            "These terms are non-negotiable. You MUST use the provided translation, "
            "matching the source term case-insensitively."
        )

    return f"""
You are an expert translator specializing in software localization. Translate the following {localization_format.display_name} value from English to {target_language}, considering the context and glossary provided.

**Instructions**:
- **Do not translate or modify placeholder tokens**: Any text enclosed within double underscores `__` (e.g., `__PH_abc123__`) should remain exactly as is. These represent placeholders like {{0}}, {{1}}, or HTML tags.
- **CRITICAL - Translate ALL other text**: You MUST translate all regular text, even if it appears between, before, or after placeholder tokens. Do not skip text just because it is near placeholders.
- **Strictly follow all glossaries**:
  - **Brand/Technical Glossary**: These terms MUST NOT be translated. Preserve their original casing and form.
  - **Translation Glossary**: {translation_glossary_rule}
- **Preserve formatting**: Keep special characters and formatting such as `\\n` and `\\t`.
- **Do not add** any additional characters or punctuation (e.g., no square brackets, quotation marks, etc.).
- **Provide only** the translated text corresponding to the Value.
- **Do not escape single quotes**: Treat single quotes (') as literal characters. The system will handle necessary escaping.
- **Match grammatical number**: Render the value with the same grammatical number as the English source. Many count messages come as singular/plural variants of the same string (for example, keys ending in `.single`/`.plural`, `.one`/`.other`, or `.1`/`.*`, such as "Used {{0}} time" versus "Used {{0}} times"). Use the singular grammatical form when the source is singular and the plural form when the source is plural; never reuse the plural wording for the singular case or vice versa when the target language distinguishes them. A `.1` variant is the exactly-one form, while its catch-all sibling (a key ending in `.*`) applies to every count other than one; when the target language inflects the counted noun differently across higher counts (for example Slavic languages, where 2-4 and 5+ take different forms) and no single inflected form is correct for all of them, use a count-neutral wording such as an abbreviation for that catch-all value rather than a form that only fits some counts. Do not invent a distinction the target language does not express: identical singular and plural target forms are acceptable when that language genuinely uses the same form for both.
- **Keep references to other UI labels consistent**: When the value points the user to another on-screen element by its visible name — for example a navigation path written as `A > B > C`, or a quoted menu, button, or tab label — reuse the exact wording that element already has in the provided context examples and existing translations instead of translating the label independently. Navigation and undo instructions must match the labels the user actually sees; a freshly translated label that differs from the real menu entry sends the user looking for a control that does not exist.
- **Keep conventional compound nouns together**: In languages that commonly build compound nouns by joining words (such as German, Norwegian, Danish, Swedish, and Dutch), use the target language's conventional closed compound when that is the idiomatic form (for example, Norwegian "Address note" becomes "Adressenotat", not the split "Adresse notat"). Do not mechanically join every multi-word noun phrase: follow the target language's orthography and idiom, and do not force compounding where it is not conventional.
- **Keep trailing connective fragments open-ended**: Some values are intentionally incomplete sentence fragments that end on a preposition or connective (for example "You are connected via" or "Sent to") because the interface appends another element — a list, name, or label — immediately after them. Translate the fragment so the connective still leads into that following content, using the target-language equivalent of a phrasing like "connected via the following"; do not invent a demonstrative or pronoun referent (such as "via this" or "through it") that closes the sentence and leaves the appended element dangling. Preserve the open-ended structure so the concatenated on-screen text stays grammatical.

Use the translations specified in the glossary for the given terms. Ensure the translation reads naturally and is culturally appropriate for the target audience.

**Style and Tone Guidelines**:
- **Professional and Reassuring**: The tone should be professional, clear, and reassuring. Avoid overly casual or informal language.
- **No Mixed Languages**: Do not mix English terms with the target language in a single phrase (e.g., "Seed Words Confermati!"). The translation should be fully localized.
- **Language-Specific Conventions**: Adhere to conventions of the target language.

{style_rules_text}
{project_context_section}
"""
