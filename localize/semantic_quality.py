"""Semantic translation quality policy evaluation."""

from __future__ import annotations

import fnmatch
import json
import os
import re
import unicodedata
from collections.abc import Iterable as IterableABC
from collections.abc import Mapping as MappingABC
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Pattern, Sequence, Tuple

from localize.localization_adapters import get_localization_adapter
from localize.localization_formats import JAVA_PROPERTIES_FORMAT, LocalizationFormat
from localize.localization_layouts import SUFFIX_LAYOUT, LocalizationLayout
from localize.properties_parser import _has_unescaped_trailing_backslash


@dataclass(frozen=True)
class TranslationChange:
    file: str
    locale_code: str
    key: str
    source_value: Optional[str]
    old_value: Optional[str]
    new_value: str


@dataclass(frozen=True)
class SemanticRule:
    id: str
    message: str
    locales: Tuple[str, ...] = ("*",)
    excluded_locales: Tuple[str, ...] = ()
    keys: Tuple[str, ...] = ("*",)
    severity: str = "error"
    forbidden_target_regex: Optional[str | Pattern[str]] = None
    required_target_regex: Optional[str | Pattern[str]] = None
    source_regex: Optional[str | Pattern[str]] = None
    source: str = "semantic-rule"


@dataclass(frozen=True)
class SemanticFinding:
    file: str
    key: str
    value: str
    reason: str
    severity: str
    rule_id: str
    source: str
    suggested_value: Optional[str] = None

    def to_example(self) -> Dict[str, str]:
        result = {
            "file": self.file,
            "key": self.key,
            "value": self.value,
            "reason": self.reason,
            "severity": self.severity,
            "rule_id": self.rule_id,
            "source": self.source,
        }
        if self.suggested_value:
            result["suggested_value"] = self.suggested_value
        return result


@dataclass
class SemanticQAStats:
    findings_count: int = 0
    errors_count: int = 0
    warnings_count: int = 0
    examples: List[Dict[str, str]] = field(default_factory=list)

    @classmethod
    def from_findings(
        cls,
        findings: Sequence[SemanticFinding],
        examples_limit: int = 10,
    ) -> "SemanticQAStats":
        return cls(
            findings_count=len(findings),
            errors_count=sum(1 for finding in findings if finding.severity == "error"),
            warnings_count=sum(1 for finding in findings if finding.severity == "warning"),
            examples=[
                finding.to_example()
                for finding in sorted(findings, key=lambda item: (item.file, item.key, item.rule_id))[:examples_limit]
            ],
        )

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


_SOURCE_WORD_RE = re.compile(r"[A-Za-z][A-Za-z'-]{6,}")
_SOURCE_WORD_ALLOWLIST = {
    "clearnet",
    "routing",
}
_SOURCE_WORD_STOPWORDS = {
    "another",
    "because",
    "between",
    "through",
    "without",
}


def normalize_retained_source_word_allowlist(raw_allowlist: Any) -> Dict[str, Tuple[str, ...]]:
    """Normalize locale-scoped retained-source word allowlists from config-like data."""
    if not isinstance(raw_allowlist, MappingABC):
        return {}

    normalized: Dict[str, Tuple[str, ...]] = {}
    for locale_code, raw_terms in raw_allowlist.items():
        locale = str(locale_code).strip()
        terms = _normalize_allowlist_terms(raw_terms)
        if locale and terms:
            normalized[locale] = terms
    return normalized


def _normalize_allowlist_terms(raw_terms: Any) -> Tuple[str, ...]:
    if isinstance(raw_terms, str):
        terms = (raw_terms,)
    elif isinstance(raw_terms, MappingABC):
        return ()
    elif isinstance(raw_terms, IterableABC):
        terms = raw_terms
    else:
        return ()

    return tuple(
        text
        for text in (str(term).strip() for term in terms)
        if text
    )


def normalize_value(value: Optional[str]) -> str:
    return (value or "").strip()


def _extract_properties_entry(diff_line: str) -> Optional[Tuple[str, str]]:
    stripped = diff_line.strip()
    if not stripped or stripped.startswith(("#", "!")):
        return None

    escaped = False
    for index, character in enumerate(diff_line):
        if character == "\\":
            escaped = not escaped
            continue
        if character in ("=", ":") and not escaped:
            key = re.sub(r'\\([:=\s])', r'\1', diff_line[:index].strip())
            value = diff_line[index + 1 :].strip()
            return (key, value) if key else None
        escaped = False
    return None


def _matching_translation_keys(
    key_hint: str,
    translations: Mapping[str, str],
    expected_value: Optional[str] = None,
) -> List[str]:
    hint_leaf = key_hint.rsplit("/", 1)[-1]
    candidates = sorted(
        key
        for key in translations
        if key == key_hint or key.rsplit("/", 1)[-1] == hint_leaf
    )
    if expected_value is not None:
        candidates = [
            key for key in candidates
            if translations.get(key) == expected_value
        ]
    if len(candidates) == 1:
        return candidates
    if expected_value is None and key_hint in translations:
        return [key_hint]
    return candidates


def _extract_json_added_value_from_diff_line(diff_line: str) -> Optional[str]:
    match = re.match(
        r'\s*"(?:\\.|[^"\\])*"\s*:\s*("(?:\\.|[^"\\])*")\s*,?\s*$',
        diff_line,
    )
    if not match:
        return None
    try:
        value = json.loads(match.group(1))
    except json.JSONDecodeError:
        return None
    return value if isinstance(value, str) else None


def _extract_changed_entries(
    diff_line: str,
    localization_format: LocalizationFormat,
    translations: Optional[Mapping[str, str]],
) -> List[Tuple[str, str]]:
    if localization_format.id == JAVA_PROPERTIES_FORMAT.id:
        entry = _extract_properties_entry(diff_line)
        return [entry] if entry else []

    adapter = get_localization_adapter(localization_format)
    key_hint = adapter.extract_changed_key_from_diff_line(diff_line)
    if not key_hint or translations is None:
        return []
    expected_value = _extract_json_added_value_from_diff_line(diff_line)
    return [
        (key, translations[key])
        for key in _matching_translation_keys(key_hint, translations, expected_value)
    ]


def _relpath(path: str, start: str) -> str:
    try:
        return os.path.relpath(path, start)
    except ValueError:
        return path


def _append_properties_continuation(current: str, next_line: str) -> str:
    return current[:-1] + next_line.lstrip()


def iter_translation_changes_from_diff(
    diff_text: str,
    repo_root: str,
    input_folder: str,
    locale_codes: Sequence[str],
    localization_format: LocalizationFormat = JAVA_PROPERTIES_FORMAT,
    localization_layout: LocalizationLayout = SUFFIX_LAYOUT,
    hydrate_source: bool = True,
) -> Iterable[TranslationChange]:
    repo_root_path = Path(repo_root)
    input_folder_path = Path(input_folder)
    adapter = get_localization_adapter(localization_format)
    source_cache: Dict[Path, Dict[str, str]] = {}
    target_cache: Dict[Path, Dict[str, str]] = {}
    current_file: Optional[str] = None
    removed_values: Dict[str, Optional[str]] = {}
    pending_added_line: Optional[str] = None
    pending_removed_line: Optional[str] = None

    def changes_for_added_line(added_line: str, file_path: str) -> List[TranslationChange]:
        rel_to_input = _relpath(str(repo_root_path / file_path), str(input_folder_path))
        changed_path = repo_root_path / file_path
        target_translations: Optional[Mapping[str, str]] = None
        if localization_format.id != JAVA_PROPERTIES_FORMAT.id:
            if not changed_path.exists():
                return []
            if changed_path not in target_cache:
                try:
                    _, target_cache[changed_path] = adapter.parse_file(str(changed_path))
                except Exception:
                    return []
            target_translations = target_cache[changed_path]

        changed_entries = _extract_changed_entries(
            added_line,
            localization_format,
            target_translations,
        )
        if not changed_entries:
            return []
        locale_code = localization_layout.extract_locale(rel_to_input, locale_codes, localization_format) or ""
        source_translations: Dict[str, str] = {}

        if hydrate_source and locale_code:
            source_rel = localization_layout.source_path_for_target(
                rel_to_input,
                locale_codes,
                localization_format,
            )
            source_path = input_folder_path / source_rel
            if source_path.exists():
                if source_path not in source_cache:
                    try:
                        _, source_cache[source_path] = adapter.parse_file(str(source_path))
                    except Exception:
                        source_cache[source_path] = {}
                source_translations = source_cache[source_path]

        return [
            TranslationChange(
                file=_relpath(str(changed_path), str(input_folder_path)),
                locale_code=locale_code,
                key=key,
                source_value=source_translations.get(key),
                old_value=removed_values.pop(key, None),
                new_value=target_value,
            )
            for key, target_value in changed_entries
        ]

    def flush_pending_added_line() -> List[TranslationChange]:
        nonlocal pending_added_line
        if not current_file or pending_added_line is None:
            pending_added_line = None
            return []
        added_line = pending_added_line
        if _has_unescaped_trailing_backslash(added_line):
            added_line = added_line[:-1].rstrip()
        pending_added_line = None
        return changes_for_added_line(added_line, current_file)

    for line in diff_text.splitlines():
        if line.startswith("diff --git "):
            for change in flush_pending_added_line():
                yield change
            current_file = None
            removed_values = {}
            pending_removed_line = None
            continue
        if line.startswith("+++ /dev/null"):
            for change in flush_pending_added_line():
                yield change
            current_file = None
            removed_values = {}
            pending_removed_line = None
            continue
        if line.startswith("+++ b/"):
            for change in flush_pending_added_line():
                yield change
            current_file = line[len("+++ b/") :]
            removed_values = {}
            pending_removed_line = None
            continue
        if not current_file or not localization_format.is_supported_file(current_file):
            continue
        rel_to_input = _relpath(str(repo_root_path / current_file), str(input_folder_path))
        if locale_codes and not localization_layout.is_target_file(
            rel_to_input,
            locale_codes,
            localization_format,
        ):
            continue
        if line.startswith("---"):
            for change in flush_pending_added_line():
                yield change
            pending_removed_line = None
            continue
        if line.startswith("@@"):
            for change in flush_pending_added_line():
                yield change
            pending_removed_line = None
            continue
        if line.startswith("-"):
            for change in flush_pending_added_line():
                yield change
            removed_line = line[1:]
            if localization_format.id == JAVA_PROPERTIES_FORMAT.id:
                pending_removed_line = (
                    _append_properties_continuation(pending_removed_line, removed_line)
                    if pending_removed_line is not None
                    else removed_line
                )
                if _has_unescaped_trailing_backslash(pending_removed_line):
                    continue
                removed_line = pending_removed_line
                pending_removed_line = None
            for key, value in _extract_changed_entries(removed_line, localization_format, None):
                removed_values[key] = value
            continue
        if not line.startswith("+"):
            for change in flush_pending_added_line():
                yield change
            pending_removed_line = None
            continue
        added_line = line[1:]
        if localization_format.id == JAVA_PROPERTIES_FORMAT.id:
            pending_added_line = (
                _append_properties_continuation(pending_added_line, added_line)
                if pending_added_line is not None
                else added_line
            )
            if _has_unescaped_trailing_backslash(pending_added_line):
                continue
            added_line = pending_added_line
            pending_added_line = None

        for change in changes_for_added_line(added_line, current_file):
            yield change
    for change in flush_pending_added_line():
        yield change


def load_semantic_rules(raw_rules: Iterable[Dict[str, Any]]) -> List[SemanticRule]:
    rules: List[SemanticRule] = []
    for raw_rule in raw_rules or []:
        if not isinstance(raw_rule, dict):
            continue
        rule_id = str(raw_rule.get("id", "")).strip()
        message = str(raw_rule.get("message", "")).strip()
        if not rule_id or not message:
            continue
        severity = str(raw_rule.get("severity", "error")).strip().lower()
        if severity not in {"error", "warning"}:
            severity = "error"
        rules.append(
            SemanticRule(
                id=rule_id,
                message=message,
                locales=_as_tuple(raw_rule.get("locales", ["*"])),
                excluded_locales=_as_tuple(raw_rule.get("excluded_locales", []), default=()),
                keys=_as_tuple(raw_rule.get("keys", ["*"])),
                severity=severity,
                forbidden_target_regex=_compile_optional_regex(
                    raw_rule.get("forbidden_target_regex"),
                    rule_id,
                    "forbidden_target_regex",
                    ignorecase=bool(raw_rule.get("regex_ignorecase", False)),
                ),
                required_target_regex=_compile_optional_regex(
                    raw_rule.get("required_target_regex"),
                    rule_id,
                    "required_target_regex",
                    ignorecase=bool(raw_rule.get("regex_ignorecase", False)),
                ),
                source_regex=_compile_optional_regex(
                    raw_rule.get("source_regex"),
                    rule_id,
                    "source_regex",
                    ignorecase=bool(raw_rule.get("regex_ignorecase", False)),
                ),
                source=str(raw_rule.get("source", "semantic-rule")),
            )
        )
    return rules


def _as_tuple(value: Any, default: Tuple[str, ...] = ("*",)) -> Tuple[str, ...]:
    if isinstance(value, str):
        return (value,)
    if isinstance(value, Iterable):
        result = tuple(str(item) for item in value if str(item).strip())
        return result or default
    return default


def _optional_string(value: Any) -> Optional[str]:
    if value is None:
        return None
    text = str(value)
    return text if text else None


def _compile_optional_regex(
    value: Any,
    rule_id: str,
    field_name: str,
    *,
    ignorecase: bool,
) -> Optional[Pattern[str]]:
    pattern = _optional_string(value)
    if pattern is None:
        return None
    flags = re.IGNORECASE if ignorecase else 0
    try:
        return re.compile(pattern, flags)
    except re.error as exc:
        raise ValueError(f"Invalid {field_name} for semantic rule '{rule_id}': {exc}") from exc


def _matches_any(value: str, patterns: Sequence[str]) -> bool:
    return any(pattern == "*" or fnmatch.fnmatchcase(value, pattern) for pattern in patterns)


def _regex_matches(pattern: str | Pattern[str], value: Optional[str]) -> bool:
    normalized_value = unicodedata.normalize("NFC", value or "")
    if isinstance(pattern, re.Pattern):
        return pattern.search(normalized_value) is not None
    return re.search(pattern, normalized_value) is not None


def evaluate_semantic_rules(
    changes: Iterable[TranslationChange],
    rules: Sequence[SemanticRule],
) -> List[SemanticFinding]:
    findings: List[SemanticFinding] = []
    for change in changes:
        for rule in rules:
            if not _matches_any(change.locale_code, rule.locales):
                continue
            if rule.excluded_locales and _matches_any(change.locale_code, rule.excluded_locales):
                continue
            if not _matches_any(change.key, rule.keys):
                continue
            if rule.source_regex and not _regex_matches(rule.source_regex, change.source_value):
                continue

            violation = False
            if rule.forbidden_target_regex and _regex_matches(
                rule.forbidden_target_regex,
                change.new_value,
            ):
                violation = True
            if rule.required_target_regex and not _regex_matches(
                rule.required_target_regex,
                change.new_value,
            ):
                violation = True
            if not violation:
                continue

            findings.append(
                SemanticFinding(
                    file=change.file,
                    key=change.key,
                    value=change.new_value,
                    reason=rule.message,
                    severity=rule.severity,
                    rule_id=rule.id,
                    source=rule.source,
                )
            )
    return findings


def evaluate_retained_source_words(
    changes: Iterable[TranslationChange],
    brand_glossary: Iterable[str],
    retained_source_word_allowlist: Optional[Mapping[str, Iterable[str]]] = None,
) -> List[SemanticFinding]:
    findings: List[SemanticFinding] = []
    allowlist = normalize_retained_source_word_allowlist(retained_source_word_allowlist or {})
    locale_allowed_words: Dict[str, set[str]] = {}
    glossary_words = _glossary_words(brand_glossary)
    for change in changes:
        if _locale_language_code(change.locale_code) in {"en", "pcm"}:
            continue
        if not change.source_value:
            continue
        if normalize_value(change.source_value) == normalize_value(change.new_value):
            continue
        if change.locale_code not in locale_allowed_words:
            locale_allowed_words[change.locale_code] = _allowed_source_words_for_locale(
                change.locale_code,
                allowlist,
            )
        retained_words = _retained_source_words(
            source_value=change.source_value,
            target_value=change.new_value,
            glossary_words=glossary_words,
            retained_source_word_allowlist=locale_allowed_words[change.locale_code],
        )
        if not retained_words:
            continue
        findings.append(
            SemanticFinding(
                file=change.file,
                key=change.key,
                value=change.new_value,
                reason="Target may retain untranslated source term(s): "
                f"{', '.join(retained_words[:3])}.",
                severity="warning",
                rule_id="retained-source-word",
                source="heuristic",
            )
        )
    return findings


def _contains_word(value: str, word: str) -> bool:
    return re.search(rf"(?<![A-Za-z]){re.escape(word)}(?![A-Za-z])", value, re.IGNORECASE) is not None


def _glossary_words(brand_glossary: Iterable[str]) -> set[str]:
    words: set[str] = set()
    for term in brand_glossary:
        words.update(word.casefold() for word in _SOURCE_WORD_RE.findall(str(term)))
    return words


def _allowlist_words(terms: Iterable[str]) -> set[str]:
    words: set[str] = set()
    for term in terms:
        text = str(term).strip()
        if not text:
            continue
        words.add(text.casefold())
        words.update(word.casefold() for word in _SOURCE_WORD_RE.findall(text))
    return words


def _allowed_source_words_for_locale(
    locale_code: str,
    retained_source_word_allowlist: Mapping[str, Iterable[str]],
) -> set[str]:
    language_code = _locale_language_code(locale_code)
    return _allowlist_words(
        (
            *retained_source_word_allowlist.get("*", ()),
            *retained_source_word_allowlist.get(language_code, ()),
            *retained_source_word_allowlist.get(locale_code, ()),
        )
    )


def _locale_language_code(locale_code: str) -> str:
    """Return the language component of a BCP 47 or underscore locale code."""
    return re.split(r"[-_]", locale_code, maxsplit=1)[0].casefold()


def _retained_source_words(
    source_value: str,
    target_value: str,
    glossary_words: set[str],
    retained_source_word_allowlist: Iterable[str] = (),
) -> List[str]:
    allowed_words = set(_SOURCE_WORD_ALLOWLIST)
    allowed_words.update(_allowlist_words(retained_source_word_allowlist))
    retained: List[str] = []
    seen: set[str] = set()

    for source_word in _SOURCE_WORD_RE.findall(source_value):
        normalized = source_word.casefold()
        if normalized in seen:
            continue
        seen.add(normalized)
        if normalized in glossary_words:
            continue
        if normalized in allowed_words:
            continue
        if normalized in _SOURCE_WORD_STOPWORDS:
            continue
        if _contains_word(target_value, source_word):
            retained.append(source_word)

    return retained


def analyze_translation_changes(
    changes: Sequence[TranslationChange],
    semantic_rules: Sequence[SemanticRule],
    brand_glossary: Iterable[str],
    retained_source_word_allowlist: Optional[Mapping[str, Iterable[str]]] = None,
    examples_limit: int = 10,
) -> SemanticQAStats:
    findings = evaluate_semantic_rules(changes, semantic_rules)
    findings.extend(
        evaluate_retained_source_words(
            changes,
            brand_glossary,
            retained_source_word_allowlist=retained_source_word_allowlist,
        )
    )
    return SemanticQAStats.from_findings(findings, examples_limit=examples_limit)


def analyze_all_translation_entries(
    repo_root: str,
    input_folder: str,
    locale_codes: Sequence[str],
    brand_glossary: Iterable[str],
    semantic_rules: Sequence[SemanticRule],
    retained_source_word_allowlist: Optional[Mapping[str, Iterable[str]]] = None,
    examples_limit: int = 10,
    localization_format: LocalizationFormat = JAVA_PROPERTIES_FORMAT,
    localization_layout: LocalizationLayout = SUFFIX_LAYOUT,
) -> SemanticQAStats:
    return analyze_translation_changes(
        changes=list(
            iter_all_translation_entries(
                repo_root=repo_root,
                input_folder=input_folder,
                locale_codes=locale_codes,
                localization_format=localization_format,
                localization_layout=localization_layout,
            )
        ),
        semantic_rules=semantic_rules,
        brand_glossary=brand_glossary,
        retained_source_word_allowlist=retained_source_word_allowlist,
        examples_limit=examples_limit,
    )


def iter_all_translation_entries(
    repo_root: str,
    input_folder: str,
    locale_codes: Sequence[str],
    localization_format: LocalizationFormat = JAVA_PROPERTIES_FORMAT,
    localization_layout: LocalizationLayout = SUFFIX_LAYOUT,
) -> Iterable[TranslationChange]:
    """Yield every target translation entry for the configured format/layout."""
    input_folder_path = Path(input_folder)
    adapter = get_localization_adapter(localization_format)
    source_cache: Dict[Path, Dict[str, str]] = {}

    for target_path in sorted(input_folder_path.rglob(f"*{localization_format.file_extension}")):
        target_rel_path = _relpath(str(target_path), str(input_folder_path))
        if not localization_layout.is_target_file(target_rel_path, locale_codes, localization_format):
            continue
        locale_code = localization_layout.extract_locale(target_rel_path, locale_codes, localization_format)
        if not locale_code:
            continue
        source_rel_path = localization_layout.source_path_for_target(
            target_rel_path,
            locale_codes,
            localization_format,
        )
        source_path = input_folder_path / source_rel_path
        if not source_path.exists():
            continue
        if source_path not in source_cache:
            try:
                _, source_cache[source_path] = adapter.parse_file(str(source_path))
            except Exception:
                source_cache[source_path] = {}
        source_translations = source_cache[source_path]
        try:
            _, target_translations = adapter.parse_file(str(target_path))
        except Exception:
            continue

        for key, target_value in target_translations.items():
            yield TranslationChange(
                file=target_rel_path,
                locale_code=locale_code,
                key=key,
                source_value=source_translations.get(key),
                old_value=None,
                new_value=target_value,
            )
