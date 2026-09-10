"""Quality gate for generated translation pull requests."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import (
    Any,
    Dict,
    Iterable,
    List,
    Mapping,
    Optional,
    Pattern,
    Sequence,
    Tuple,
)

import yaml

from localize.ignore_keys import compile_ignore_key_patterns, is_ignored_key
from localize.localization_formats import (
    JAVA_PROPERTIES_FORMAT,
    LocalizationFormat,
    load_localization_format,
)
from localize.localization_layouts import (
    SUFFIX_LAYOUT,
    LocalizationLayout,
    load_localization_layout,
)
from localize.localization_profiles import (
    LocalizationProfile,
    load_localization_profiles,
)
from localize.semantic_quality import (
    SemanticFinding,
    SemanticQAStats,
    SemanticRule,
    TranslationChange,
    analyze_translation_changes,
    iter_all_translation_entries,
    iter_translation_changes_from_diff,
    load_semantic_rules,
    normalize_value,
    normalize_retained_source_word_allowlist,
)
from localize.translation_validator import find_disallowed_control_characters


@dataclass
class QualityGateConfig:
    """Thresholds for blocking generated translation pull requests."""

    source_identical_min_block_count: int = 5
    source_identical_max_count: int = 20
    source_identical_max_ratio: float = 0.30
    block_on_pipeline_warnings: bool = True
    block_on_semantic_qa_findings: bool = True
    block_on_semantic_qa_warnings: bool = False
    semantic_qa_audit_scope: str = "changed"
    retained_source_word_allowlist: Dict[str, Tuple[str, ...]] = field(
        default_factory=dict
    )
    source_identical_allowlist: Dict[str, Tuple[str, ...]] = field(
        default_factory=dict
    )
    ignore_key_patterns: List[Pattern[str]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source_identical_min_block_count": self.source_identical_min_block_count,
            "source_identical_max_count": self.source_identical_max_count,
            "source_identical_max_ratio": self.source_identical_max_ratio,
            "block_on_pipeline_warnings": self.block_on_pipeline_warnings,
            "block_on_semantic_qa_findings": self.block_on_semantic_qa_findings,
            "block_on_semantic_qa_warnings": self.block_on_semantic_qa_warnings,
            "semantic_qa_audit_scope": self.semantic_qa_audit_scope,
            "retained_source_word_allowlist": self.retained_source_word_allowlist,
            "source_identical_allowlist": self.source_identical_allowlist,
            "ignore_key_patterns": [
                pattern.pattern for pattern in self.ignore_key_patterns
            ],
        }


@dataclass
class SourceIdenticalStats:
    changed_entries_count: int = 0
    checked_entries_count: int = 0
    source_identical_count: int = 0
    expected_source_identical_count: int = 0
    unexpected_source_identical_count: int = 0
    unexpected_source_identical_ratio: float = 0.0
    control_character_findings_count: int = 0
    examples: List[Dict[str, str]] = field(default_factory=list)
    control_character_examples: List[Dict[str, str]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


_TOKEN_PATTERNS = [
    re.compile(r"^\{[^{}]+\}$"),
    re.compile(r"^(https?://|www\.)\S+$", re.IGNORECASE),
    re.compile(r"^\S+@\S+$"),
    re.compile(r"^[A-Z0-9_.:+/#-]{2,}$"),
]
_ENUM_LIKE_KEY = re.compile(r"^[A-Z0-9_.$-]+$")


def is_expected_source_identical(
    key: str,
    value: str,
    brand_glossary: Iterable[str],
    locale_code: str = "",
    source_identical_allowlist: Optional[Mapping[str, Iterable[str]]] = None,
) -> bool:
    """Return true for values that are commonly and legitimately untranslated."""
    normalized = normalize_value(value)
    if not normalized:
        return True
    if _ENUM_LIKE_KEY.match(key):
        return True
    glossary = {term.strip().casefold() for term in brand_glossary if str(term).strip()}
    if normalized.casefold() in glossary:
        return True
    allowlist = normalize_retained_source_word_allowlist(
        source_identical_allowlist or {}
    )
    allowed_values = {
        normalize_value(term).casefold()
        for term in (*allowlist.get("*", ()), *allowlist.get(locale_code, ()))
    }
    if normalized.casefold() in allowed_values:
        return True
    if not any(character.isalpha() for character in normalized):
        return True
    return any(pattern.match(normalized) for pattern in _TOKEN_PATTERNS)


def analyze_source_identical_changes(
    diff_text: str,
    repo_root: str,
    input_folder: str,
    locale_codes: Sequence[str],
    brand_glossary: Iterable[str],
    examples_limit: int = 10,
    localization_format: LocalizationFormat = JAVA_PROPERTIES_FORMAT,
    localization_layout: LocalizationLayout = SUFFIX_LAYOUT,
    ignore_key_patterns: Sequence[Pattern[str] | str] = (),
    source_identical_allowlist: Optional[Mapping[str, Iterable[str]]] = None,
) -> SourceIdenticalStats:
    """Analyze staged translation changes for suspicious English-source fallbacks."""
    changes = iter_translation_changes_from_diff(
        diff_text=diff_text,
        repo_root=repo_root,
        input_folder=input_folder,
        locale_codes=locale_codes,
        localization_format=localization_format,
        localization_layout=localization_layout,
        hydrate_source=True,
    )
    return _analyze_source_identical_translation_changes(
        changes=changes,
        brand_glossary=brand_glossary,
        examples_limit=examples_limit,
        ignore_key_patterns=_ensure_ignore_key_patterns(ignore_key_patterns),
        source_identical_allowlist=source_identical_allowlist,
    )


def _ensure_ignore_key_patterns(
    patterns: Sequence[Pattern[str] | str],
) -> List[Pattern[str]]:
    return compile_ignore_key_patterns(patterns)


def _filter_ignored_changes(
    changes: Iterable[TranslationChange],
    ignore_key_patterns: Sequence[Pattern[str]],
) -> Iterable[TranslationChange]:
    for change in changes:
        if is_ignored_key(change.key, ignore_key_patterns):
            continue
        yield change


def _analyze_source_identical_translation_changes(
    changes: Iterable[TranslationChange],
    brand_glossary: Iterable[str],
    examples_limit: int,
    ignore_key_patterns: Sequence[Pattern[str]] = (),
    source_identical_allowlist: Optional[Mapping[str, Iterable[str]]] = None,
) -> SourceIdenticalStats:
    stats = SourceIdenticalStats()

    for change in _filter_ignored_changes(changes, ignore_key_patterns):
        if change.source_value is None:
            continue

        stats.changed_entries_count += 1

        control_findings = find_disallowed_control_characters(change.new_value)
        if control_findings:
            stats.control_character_findings_count += len(control_findings)
            if len(stats.control_character_examples) < examples_limit:
                stats.control_character_examples.append(
                    {
                        "file": change.file,
                        "key": change.key,
                        "findings": ", ".join(control_findings[:3]),
                    }
                )

        source_value = change.source_value
        if normalize_value(source_value) != normalize_value(change.new_value):
            stats.checked_entries_count += 1
            continue

        stats.source_identical_count += 1
        if is_expected_source_identical(
            change.key,
            source_value,
            brand_glossary,
            change.locale_code,
            source_identical_allowlist,
        ):
            stats.expected_source_identical_count += 1
            continue

        stats.checked_entries_count += 1
        stats.unexpected_source_identical_count += 1
        if len(stats.examples) < examples_limit:
            stats.examples.append(
                {
                    "file": change.file,
                    "key": change.key,
                    "value": change.new_value,
                }
            )

    if stats.checked_entries_count:
        stats.unexpected_source_identical_ratio = (
            stats.unexpected_source_identical_count / stats.checked_entries_count
        )
    return stats


def _deduplicate_translation_changes(
    changes: Iterable[TranslationChange],
) -> List[TranslationChange]:
    unique_changes: List[TranslationChange] = []
    seen: set[tuple[str, str]] = set()
    for change in changes:
        identity = (change.file, change.key)
        if identity in seen:
            continue
        seen.add(identity)
        unique_changes.append(change)
    return unique_changes


def _iter_profile_translation_changes(
    diff_text: str,
    repo_root: str,
    input_folder: str,
    locale_codes: Sequence[str],
    localization_profiles: Sequence[LocalizationProfile],
) -> Iterable[TranslationChange]:
    for profile in localization_profiles:
        yield from iter_translation_changes_from_diff(
            diff_text=diff_text,
            repo_root=repo_root,
            input_folder=input_folder,
            locale_codes=locale_codes,
            localization_format=profile.localization_format,
            localization_layout=profile.localization_layout,
        )


def _iter_profile_translation_entries(
    repo_root: str,
    input_folder: str,
    locale_codes: Sequence[str],
    localization_profiles: Sequence[LocalizationProfile],
) -> Iterable[TranslationChange]:
    for profile in localization_profiles:
        yield from iter_all_translation_entries(
            repo_root=repo_root,
            input_folder=input_folder,
            locale_codes=locale_codes,
            localization_format=profile.localization_format,
            localization_layout=profile.localization_layout,
        )


def analyze_source_identical_changes_for_profiles(
    diff_text: str,
    repo_root: str,
    input_folder: str,
    locale_codes: Sequence[str],
    brand_glossary: Iterable[str],
    localization_profiles: Sequence[LocalizationProfile],
    examples_limit: int = 10,
    ignore_key_patterns: Sequence[Pattern[str]] = (),
    source_identical_allowlist: Optional[Mapping[str, Iterable[str]]] = None,
) -> SourceIdenticalStats:
    """Analyze suspicious source-identical changes across configured profiles."""
    return _analyze_source_identical_translation_changes(
        changes=_deduplicate_translation_changes(
            _iter_profile_translation_changes(
                diff_text=diff_text,
                repo_root=repo_root,
                input_folder=input_folder,
                locale_codes=locale_codes,
                localization_profiles=localization_profiles,
            )
        ),
        brand_glossary=brand_glossary,
        examples_limit=examples_limit,
        ignore_key_patterns=ignore_key_patterns,
        source_identical_allowlist=source_identical_allowlist,
    )


def analyze_semantic_qa_changes(
    diff_text: str,
    repo_root: str,
    input_folder: str,
    locale_codes: Sequence[str],
    brand_glossary: Iterable[str] = (),
    semantic_rules: Sequence[SemanticRule] = (),
    retained_source_word_allowlist: Optional[Mapping[str, Iterable[str]]] = None,
    examples_limit: int = 10,
    localization_format: LocalizationFormat = JAVA_PROPERTIES_FORMAT,
    localization_layout: LocalizationLayout = SUFFIX_LAYOUT,
    ignore_key_patterns: Sequence[Pattern[str] | str] = (),
) -> SemanticQAStats:
    """Scan changed translations for configured semantic regressions."""
    changes = list(
        iter_translation_changes_from_diff(
            diff_text=diff_text,
            repo_root=repo_root,
            input_folder=input_folder,
            locale_codes=locale_codes,
            localization_format=localization_format,
            localization_layout=localization_layout,
        )
    )
    compiled_ignore_key_patterns = _ensure_ignore_key_patterns(ignore_key_patterns)
    return analyze_translation_changes(
        changes=list(_filter_ignored_changes(changes, compiled_ignore_key_patterns)),
        semantic_rules=semantic_rules,
        brand_glossary=brand_glossary,
        retained_source_word_allowlist=retained_source_word_allowlist,
        examples_limit=examples_limit,
    )


def analyze_semantic_qa_changes_for_profiles(
    diff_text: str,
    repo_root: str,
    input_folder: str,
    locale_codes: Sequence[str],
    brand_glossary: Iterable[str] = (),
    semantic_rules: Sequence[SemanticRule] = (),
    retained_source_word_allowlist: Optional[Mapping[str, Iterable[str]]] = None,
    localization_profiles: Sequence[LocalizationProfile] = (),
    examples_limit: int = 10,
    ignore_key_patterns: Sequence[Pattern[str]] = (),
) -> SemanticQAStats:
    """Scan changed translations across all configured format/layout profiles."""
    changes = _deduplicate_translation_changes(
        _iter_profile_translation_changes(
            diff_text=diff_text,
            repo_root=repo_root,
            input_folder=input_folder,
            locale_codes=locale_codes,
            localization_profiles=localization_profiles,
        )
    )
    return analyze_translation_changes(
        changes=list(_filter_ignored_changes(changes, ignore_key_patterns)),
        semantic_rules=semantic_rules,
        brand_glossary=brand_glossary,
        retained_source_word_allowlist=retained_source_word_allowlist,
        examples_limit=examples_limit,
    )


def analyze_all_translation_entries_for_profiles(
    repo_root: str,
    input_folder: str,
    locale_codes: Sequence[str],
    brand_glossary: Iterable[str],
    semantic_rules: Sequence[SemanticRule],
    retained_source_word_allowlist: Optional[Mapping[str, Iterable[str]]] = None,
    localization_profiles: Sequence[LocalizationProfile] = (),
    examples_limit: int = 10,
    ignore_key_patterns: Sequence[Pattern[str]] = (),
) -> SemanticQAStats:
    """Scan all translations across all configured format/layout profiles."""
    changes = _deduplicate_translation_changes(
        _iter_profile_translation_entries(
            repo_root=repo_root,
            input_folder=input_folder,
            locale_codes=locale_codes,
            localization_profiles=localization_profiles,
        )
    )
    return analyze_translation_changes(
        changes=list(_filter_ignored_changes(changes, ignore_key_patterns)),
        semantic_rules=semantic_rules,
        brand_glossary=brand_glossary,
        retained_source_word_allowlist=retained_source_word_allowlist,
        examples_limit=examples_limit,
    )


def load_quality_gate_config(
    config_path: str,
) -> Tuple[QualityGateConfig, List[str], List[str], List[SemanticRule]]:
    with open(config_path, "r", encoding="utf-8") as file:
        raw_config = yaml.safe_load(file) or {}

    quality_gate = raw_config.get("quality_gate", {}) or {}
    locales = [
        str(locale.get("code") if isinstance(locale, dict) else locale)
        for locale in raw_config.get("supported_locales", [])
        if (isinstance(locale, dict) and locale.get("code")) or isinstance(locale, str)
    ]
    semantic_qa_audit_scope = str(
        quality_gate.get("semantic_qa_audit_scope", "changed")
    )
    if semantic_qa_audit_scope not in {"changed", "all"}:
        raise ValueError(
            "quality_gate.semantic_qa_audit_scope must be 'changed' or 'all'."
        )
    brand_glossary = [
        str(term) for term in raw_config.get("brand_technical_glossary", [])
    ]
    return (
        QualityGateConfig(
            source_identical_min_block_count=int(
                quality_gate.get("source_identical_min_block_count", 5)
            ),
            source_identical_max_count=int(
                quality_gate.get("source_identical_max_count", 20)
            ),
            source_identical_max_ratio=float(
                quality_gate.get("source_identical_max_ratio", 0.30)
            ),
            block_on_pipeline_warnings=bool(
                quality_gate.get("block_on_pipeline_warnings", True)
            ),
            block_on_semantic_qa_findings=bool(
                quality_gate.get("block_on_semantic_qa_findings", True)
            ),
            block_on_semantic_qa_warnings=bool(
                quality_gate.get("block_on_semantic_qa_warnings", False)
            ),
            semantic_qa_audit_scope=semantic_qa_audit_scope,
            retained_source_word_allowlist=normalize_retained_source_word_allowlist(
                quality_gate.get("retained_source_word_allowlist", {})
            ),
            source_identical_allowlist=normalize_retained_source_word_allowlist(
                quality_gate.get("source_identical_allowlist", {})
            ),
            ignore_key_patterns=compile_ignore_key_patterns(
                raw_config.get("ignore_key_patterns", [])
            ),
        ),
        locales,
        brand_glossary,
        load_semantic_rules(raw_config.get("semantic_quality_rules", [])),
    )


def load_quality_gate_localization_metadata(
    config_path: str,
) -> Tuple[LocalizationFormat, LocalizationLayout]:
    """Load localization format/layout metadata used by quality gates."""
    with open(config_path, "r", encoding="utf-8") as file:
        raw_config = yaml.safe_load(file) or {}

    localization_format = load_localization_format(
        raw_config.get("localization_format")
    )
    localization_layout = load_localization_layout(
        raw_config.get("localization_layout"),
        source_locale=str(raw_config.get("source_locale") or "en"),
    )

    return localization_format, localization_layout


def load_quality_gate_localization_profiles(
    config_path: str,
) -> Tuple[LocalizationProfile, ...]:
    """Load localization profiles used by quality gate sidecars."""
    with open(config_path, "r", encoding="utf-8") as file:
        raw_config = yaml.safe_load(file) or {}
    return load_localization_profiles(raw_config)


def load_validation_summary(path: str) -> Dict[str, Any]:
    if not path or not os.path.exists(path):
        return {"files": {}, "pipeline_warnings": []}
    with open(path, "r", encoding="utf-8") as file:
        data = json.load(file)
    if not isinstance(data, dict):
        return {"files": {}, "pipeline_warnings": []}
    data.setdefault("files", {})
    data.setdefault("pipeline_warnings", [])
    return data


def _changed_files_relative_to_input(
    changed_files: Sequence[str], input_folder: str
) -> set[str]:
    input_path = Path(input_folder)
    result = set()
    for changed_file in changed_files:
        changed_path = Path(changed_file)
        result.add(changed_path.as_posix())
        if changed_path.is_absolute():
            try:
                result.add(changed_path.relative_to(input_path).as_posix())
            except ValueError:
                result.add(changed_path.as_posix())
        else:
            input_folder_name = input_path.name
            parts = changed_path.parts
            for index, part in enumerate(parts):
                if part == input_folder_name and index + 1 < len(parts):
                    result.add(Path(*parts[index + 1 :]).as_posix())
    return result


def _file_matches_changed_files(
    filename: str, changed_relative_files: set[str]
) -> bool:
    path = Path(filename)
    return path.as_posix() in changed_relative_files


def _aggregate_validation(
    validation_summary: Dict[str, Any],
    changed_files: Sequence[str],
    input_folder: str,
) -> Dict[str, Any]:
    changed_relative_files = _changed_files_relative_to_input(
        changed_files, input_folder
    )
    totals = {
        "reverted_keys_count": 0,
        "control_character_findings_count": 0,
        "placeholder_failures_count": 0,
        "model_translation_failed_count": 0,
        "model_translation_failed_keys": {},
    }
    for filename, file_summary in validation_summary.get("files", {}).items():
        if changed_relative_files and not _file_matches_changed_files(
            filename, changed_relative_files
        ):
            continue
        totals["reverted_keys_count"] += int(file_summary.get("reverted_keys_count", 0))
        totals["control_character_findings_count"] += int(
            file_summary.get("control_character_findings_count", 0)
        )
        totals["placeholder_failures_count"] += int(
            file_summary.get("placeholder_failures_count", 0)
        )
        totals["model_translation_failed_count"] += int(
            file_summary.get("model_translation_failed_count", 0)
        )
        raw_failed_keys = file_summary.get("model_translation_failed_keys", [])
        if isinstance(raw_failed_keys, Sequence) and not isinstance(
            raw_failed_keys, (str, bytes)
        ):
            failed_keys = sorted({str(key) for key in raw_failed_keys if str(key)})
            if failed_keys:
                totals["model_translation_failed_keys"][str(filename)] = failed_keys
    return totals


def _filter_pipeline_warnings(
    validation_summary: Dict[str, Any],
    changed_files: Sequence[str],
    input_folder: str,
) -> List[Dict[str, Any]]:
    changed_relative_files = _changed_files_relative_to_input(
        changed_files, input_folder
    )
    warnings = validation_summary.get("pipeline_warnings", [])
    if not changed_relative_files:
        return list(warnings)
    return [
        warning
        for warning in warnings
        if warning.get("scope") == "run"
        or _file_matches_changed_files(
            str(warning.get("file", "")), changed_relative_files
        )
    ]


def _semantic_review_remediation_signatures(
    validation_summary: Dict[str, Any],
    changed_files: Sequence[str],
    input_folder: str,
) -> set[str]:
    changed_relative_files = _changed_files_relative_to_input(
        changed_files, input_folder
    )
    signatures: set[str] = set()
    for raw_remediation in validation_summary.get("semantic_review_remediations", []):
        if not isinstance(raw_remediation, dict):
            continue
        filename = str(raw_remediation.get("file", ""))
        if changed_relative_files and not _file_matches_changed_files(
            filename, changed_relative_files
        ):
            continue
        signature = str(raw_remediation.get("finding_signature", ""))
        if signature:
            signatures.add(signature)
    return signatures


def _semantic_review_stats_from_validation(
    validation_summary: Dict[str, Any],
    changed_files: Sequence[str],
    input_folder: str,
) -> Tuple[SemanticQAStats, int]:
    changed_relative_files = _changed_files_relative_to_input(
        changed_files, input_folder
    )
    remediated_signatures = _semantic_review_remediation_signatures(
        validation_summary,
        changed_files,
        input_folder,
    )
    findings: List[SemanticFinding] = []
    for raw_finding in validation_summary.get("semantic_review_findings", []):
        if not isinstance(raw_finding, dict):
            continue
        filename = str(raw_finding.get("file", ""))
        if changed_relative_files and not _file_matches_changed_files(
            filename, changed_relative_files
        ):
            continue
        signature = str(raw_finding.get("finding_signature", ""))
        if signature and signature in remediated_signatures:
            continue
        severity = str(raw_finding.get("severity", "warning")).lower()
        if severity not in {"error", "warning"}:
            severity = "warning"
        findings.append(
            SemanticFinding(
                file=filename,
                key=str(raw_finding.get("key", "")),
                value=str(raw_finding.get("value", raw_finding.get("new_value", ""))),
                reason=str(raw_finding.get("reason", "")),
                severity=severity,
                rule_id=str(raw_finding.get("rule_id", "ai-review")),
                source=str(raw_finding.get("source", "ai-review")),
                suggested_value=(
                    str(raw_finding["suggested_value"])
                    if raw_finding.get("suggested_value")
                    else None
                ),
            )
        )
    return SemanticQAStats.from_findings(findings), len(remediated_signatures)


def _merge_semantic_stats(
    first: Optional[SemanticQAStats],
    second: Optional[SemanticQAStats],
    examples_limit: int = 10,
) -> SemanticQAStats:
    first = first or SemanticQAStats()
    second = second or SemanticQAStats()
    return SemanticQAStats(
        findings_count=first.findings_count + second.findings_count,
        errors_count=first.errors_count + second.errors_count,
        warnings_count=first.warnings_count + second.warnings_count,
        examples=[*first.examples, *second.examples][:examples_limit],
    )


def build_quality_gate_report(
    source_stats: SourceIdenticalStats,
    semantic_stats: Optional[SemanticQAStats],
    validation_summary: Dict[str, Any],
    changed_files: Sequence[str],
    input_folder: str,
    config: QualityGateConfig,
) -> Dict[str, Any]:
    validation_totals = _aggregate_validation(
        validation_summary, changed_files, input_folder
    )
    pipeline_warnings = _filter_pipeline_warnings(
        validation_summary, changed_files, input_folder
    )
    blocking_reasons: List[str] = []
    rule_and_heuristic_stats = semantic_stats or SemanticQAStats()
    semantic_review_stats, remediated_ai_findings_count = (
        _semantic_review_stats_from_validation(
            validation_summary,
            changed_files,
            input_folder,
        )
    )
    semantic_stats = _merge_semantic_stats(
        rule_and_heuristic_stats,
        semantic_review_stats,
    )
    semantic_qa = semantic_stats.to_dict()
    semantic_qa["source_breakdown"] = {
        "rules_and_heuristics": rule_and_heuristic_stats.to_dict(),
        "ai_review": semantic_review_stats.to_dict(),
        "remediated_ai_findings_count": remediated_ai_findings_count,
    }

    source_identical_blocking = (
        source_stats.unexpected_source_identical_count
        >= config.source_identical_min_block_count
        and (
            source_stats.unexpected_source_identical_count
            > config.source_identical_max_count
            or source_stats.unexpected_source_identical_ratio
            > config.source_identical_max_ratio
        )
    )
    if source_identical_blocking:
        blocking_reasons.append(
            "Unexpected source-identical changed values exceed configured quality thresholds."
        )

    if config.block_on_pipeline_warnings and pipeline_warnings:
        blocking_reasons.append(
            "Translation pipeline warnings require manual resolution."
        )

    semantic_review_status = validation_summary.get("semantic_review")
    if semantic_review_status is not None:
        semantic_review_incomplete = not isinstance(
            semantic_review_status, dict
        ) or bool(
            semantic_review_status.get("failed_run")
            or semantic_review_status.get("failed_batches")
            or semantic_review_status.get("failed_locales")
        )
        if semantic_review_incomplete:
            blocking_reasons.append(
                "Semantic AI review did not complete and requires manual resolution."
            )

    if (
        source_stats.control_character_findings_count
        or validation_totals["control_character_findings_count"]
    ):
        blocking_reasons.append(
            "Control-character artifacts require manual resolution."
        )
    if validation_totals["placeholder_failures_count"]:
        blocking_reasons.append(
            "Placeholder parity failures require manual resolution."
        )
    if validation_totals["model_translation_failed_count"]:
        blocking_reasons.append("Model translation failures require manual resolution.")

    if config.block_on_semantic_qa_findings and semantic_stats.errors_count:
        blocking_reasons.append(
            "Semantic translation QA findings require manual resolution."
        )
    elif config.block_on_semantic_qa_warnings and semantic_stats.warnings_count:
        blocking_reasons.append(
            "Semantic translation QA warnings require manual resolution."
        )

    blocking = bool(blocking_reasons)
    description = (
        blocking_reasons[0] if blocking else "Translation quality gate passed."
    )
    description = description[:140]

    return {
        "blocking": blocking,
        "blocking_reasons": blocking_reasons,
        "status_state": "failure" if blocking else "success",
        "status_description": description,
        "source_identical": source_stats.to_dict(),
        "semantic_qa": semantic_qa,
        "validation": validation_totals,
        "pipeline_warnings_count": len(pipeline_warnings),
        "pipeline_warnings": pipeline_warnings,
        "thresholds": config.to_dict(),
    }


def _format_percent(value: float) -> str:
    return f"{value * 100:.1f}%"


def _truncate(value: str, limit: int = 100) -> str:
    value = value.replace("\n", "\\n")
    return value if len(value) <= limit else value[: limit - 3] + "..."


def _escape_markdown_report_text(value: Any, limit: int = 500) -> str:
    text = str(value)
    text = text.replace("\r", "\\r").replace("\n", "\\n")
    text = text.replace("`", "\\`")
    return text if len(text) <= limit else text[: limit - 3] + "..."


def _semantic_breakdown_summary(semantic_qa: Mapping[str, Any]) -> str:
    breakdown = semantic_qa.get("source_breakdown")
    if not isinstance(breakdown, Mapping):
        return ""

    ai_review = breakdown.get("ai_review", {})
    rules_and_heuristics = breakdown.get("rules_and_heuristics", {})
    if not isinstance(ai_review, Mapping):
        ai_review = {}
    if not isinstance(rules_and_heuristics, Mapping):
        rules_and_heuristics = {}

    parts = [
        f"AI review: {int(ai_review.get('findings_count', 0))}",
        f"rules/heuristics: {int(rules_and_heuristics.get('findings_count', 0))}",
    ]
    remediated_count = int(breakdown.get("remediated_ai_findings_count", 0))
    if remediated_count:
        parts.append(f"auto-remediated: {remediated_count}")
    return "; " + "; ".join(parts)


def _semantic_example_line(example: Mapping[str, Any]) -> str:
    line = (
        f"- `{_escape_markdown_report_text(example['file'], 160)}` "
        f"`{_escape_markdown_report_text(example['key'], 160)}`: "
        f"{_escape_markdown_report_text(example['reason'])} "
        f"Value: `{_escape_markdown_report_text(example['value'], 100)}`"
    )
    suggested_value = example.get("suggested_value")
    if suggested_value:
        line += f" Suggested: `{_escape_markdown_report_text(suggested_value, 100)}`"
    return line


def _append_semantic_example_group(
    lines: List[str],
    title: str,
    examples: Sequence[Mapping[str, Any]],
) -> None:
    if not examples:
        return
    lines.append(f"#### {title}")
    lines.append("")
    for example in examples:
        lines.append(_semantic_example_line(example))
    lines.append("")


def render_quality_gate_markdown(report: Dict[str, Any]) -> str:
    source = report["source_identical"]
    semantic_qa = report.get("semantic_qa", {"findings_count": 0, "examples": []})
    validation = report["validation"]
    lines = ["## Translation Validation Summary", ""]

    if report["blocking"]:
        lines.append("**Status:** Blocked by `translation-quality-gate`.")
        lines.append("")
        for reason in report["blocking_reasons"]:
            lines.append(f"- {reason}")
        lines.append("")
    else:
        lines.append("**Status:** Passed `translation-quality-gate`.")
        lines.append("")

    lines.extend(
        [
            "| Check | Result |",
            "| --- | --- |",
            (
                "| Unexpected source-identical changed values | "
                f"{source['unexpected_source_identical_count']} / "
                f"{source['checked_entries_count']} checked "
                f"({_format_percent(source['unexpected_source_identical_ratio'])}) |"
            ),
            (
                "| Expected source-identical values ignored | "
                f"{source['expected_source_identical_count']} |"
            ),
            (
                "| Semantic QA findings | "
                f"{semantic_qa['findings_count']} "
                f"({semantic_qa.get('errors_count', 0)} errors, "
                f"{semantic_qa.get('warnings_count', 0)} warnings"
                f"{_semantic_breakdown_summary(semantic_qa)}) |"
            ),
            f"| Reverted keys | {validation['reverted_keys_count']} |",
            f"| Control-character findings | {validation['control_character_findings_count']} |",
            f"| Placeholder failures | {validation['placeholder_failures_count']} |",
            f"| Model translation failures | {validation.get('model_translation_failed_count', 0)} |",
            f"| Pipeline warnings | {report['pipeline_warnings_count']} |",
            "",
        ]
    )

    model_failure_keys = validation.get("model_translation_failed_keys", {})
    if isinstance(model_failure_keys, Mapping) and model_failure_keys:
        lines.append("### Model Translation Failures")
        lines.append("")
        for filename in sorted(model_failure_keys):
            keys = model_failure_keys[filename]
            if not isinstance(keys, Sequence) or isinstance(keys, (str, bytes)):
                continue
            for key in keys:
                lines.append(
                    f"- `{_escape_markdown_report_text(filename, 160)}` "
                    f"`{_escape_markdown_report_text(key, 160)}`"
                )
        lines.append("")

    if source.get("examples"):
        lines.append("### Source-Identical Examples")
        lines.append("")
        for example in source["examples"]:
            lines.append(
                f"- `{_escape_markdown_report_text(example['file'], 160)}` "
                f"`{_escape_markdown_report_text(example['key'], 160)}` = "
                f"`{_escape_markdown_report_text(example['value'], 100)}`"
            )
        lines.append("")

    semantic_breakdown = semantic_qa.get("source_breakdown")
    if isinstance(semantic_breakdown, Mapping):
        ai_review = semantic_breakdown.get("ai_review", {})
        rules_and_heuristics = semantic_breakdown.get("rules_and_heuristics", {})
        ai_examples = (
            ai_review.get("examples", []) if isinstance(ai_review, Mapping) else []
        )
        rule_examples = (
            rules_and_heuristics.get("examples", [])
            if isinstance(rules_and_heuristics, Mapping)
            else []
        )
    else:
        ai_examples = []
        rule_examples = []

    if ai_examples or rule_examples:
        lines.append("### Semantic QA Examples")
        lines.append("")
        _append_semantic_example_group(lines, "AI Review", ai_examples)
        _append_semantic_example_group(lines, "Rules And Heuristics", rule_examples)
    elif semantic_qa.get("examples"):
        lines.append("### Semantic QA Examples")
        lines.append("")
        for example in semantic_qa["examples"]:
            lines.append(_semantic_example_line(example))
        lines.append("")

    if source.get("control_character_examples"):
        lines.append("### Control-Character Examples")
        lines.append("")
        for example in source["control_character_examples"]:
            lines.append(
                f"- `{_escape_markdown_report_text(example['file'], 160)}` "
                f"`{_escape_markdown_report_text(example['key'], 160)}`: "
                f"{_escape_markdown_report_text(example['findings'])}"
            )
        lines.append("")

    if report["pipeline_warnings"]:
        lines.append("### Pipeline Warnings")
        lines.append("")
        for warning in report["pipeline_warnings"]:
            lines.append(
                f"- `{_escape_markdown_report_text(warning.get('file', 'unknown'), 160)}`"
            )
            for error in warning.get("errors", []):
                lines.append(f"  - {_escape_markdown_report_text(error, 180)}")
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def get_staged_diff(repo_root: str, changed_files: Sequence[str]) -> str:
    result = subprocess.run(
        [
            "git",
            "-c",
            "diff.noprefix=false",
            "-c",
            "core.quotePath=false",
            "diff",
            "--cached",
            "--unified=0",
            "--no-color",
            "--no-ext-diff",
            "--",
            *changed_files,
        ],
        cwd=repo_root,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(f"git diff failed: {result.stderr.strip()}")
    return result.stdout


def write_report(
    report: Dict[str, Any], output_json: str, output_markdown: str
) -> None:
    Path(output_json).parent.mkdir(parents=True, exist_ok=True)
    with open(output_json, "w", encoding="utf-8") as file:
        json.dump(report, file, ensure_ascii=False, indent=2)
    Path(output_markdown).parent.mkdir(parents=True, exist_ok=True)
    with open(output_markdown, "w", encoding="utf-8") as file:
        file.write(render_quality_gate_markdown(report))


def _parse_args(argv: Optional[Sequence[str]]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", required=True)
    parser.add_argument("--input-folder", required=True)
    parser.add_argument("--config", required=True)
    parser.add_argument("--validation-summary", required=True)
    parser.add_argument("--output-json", required=True)
    parser.add_argument("--output-markdown", required=True)
    parser.add_argument("--changed-files", nargs="+", required=True)
    parser.add_argument("--audit-scope", choices=["changed", "all"], default=None)
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    config, locale_codes, brand_glossary, semantic_rules = load_quality_gate_config(
        args.config
    )
    localization_profiles = load_quality_gate_localization_profiles(args.config)
    diff_text = get_staged_diff(args.repo_root, args.changed_files)
    source_stats = analyze_source_identical_changes_for_profiles(
        diff_text=diff_text,
        repo_root=args.repo_root,
        input_folder=args.input_folder,
        locale_codes=locale_codes,
        brand_glossary=brand_glossary,
        localization_profiles=localization_profiles,
        ignore_key_patterns=config.ignore_key_patterns,
        source_identical_allowlist=config.source_identical_allowlist,
    )
    audit_scope = args.audit_scope or config.semantic_qa_audit_scope
    if audit_scope == "all":
        semantic_stats = analyze_all_translation_entries_for_profiles(
            repo_root=args.repo_root,
            input_folder=args.input_folder,
            locale_codes=locale_codes,
            brand_glossary=brand_glossary,
            semantic_rules=semantic_rules,
            retained_source_word_allowlist=config.retained_source_word_allowlist,
            localization_profiles=localization_profiles,
            ignore_key_patterns=config.ignore_key_patterns,
        )
    else:
        semantic_stats = analyze_semantic_qa_changes_for_profiles(
            diff_text=diff_text,
            repo_root=args.repo_root,
            input_folder=args.input_folder,
            locale_codes=locale_codes,
            brand_glossary=brand_glossary,
            semantic_rules=semantic_rules,
            retained_source_word_allowlist=config.retained_source_word_allowlist,
            localization_profiles=localization_profiles,
            ignore_key_patterns=config.ignore_key_patterns,
        )
    report = build_quality_gate_report(
        source_stats=source_stats,
        semantic_stats=semantic_stats,
        validation_summary=load_validation_summary(args.validation_summary),
        changed_files=args.changed_files,
        input_folder=args.input_folder,
        config=config,
    )
    write_report(report, args.output_json, args.output_markdown)
    return 1 if report["blocking"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
