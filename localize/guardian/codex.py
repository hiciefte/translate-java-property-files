"""Read-only Codex CLI driver for translation-review assessment.

Review comments and repository evidence are untrusted input.  This driver never
lets Codex edit a checkout: the model receives its prompt over stdin, runs with
the CLI's read-only sandbox, and must return a schema-validated decision file.
The guardian controller remains responsible for independently authorizing and
applying any proposed replacement.
"""

from __future__ import annotations

import json
import math
import os
import subprocess
import tempfile
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Mapping, Sequence

from jsonschema import Draft202012Validator

from localize.guardian.deadline import PollDeadline, PollDeadlineExceeded
from localize.guardian.json_safety import loads_bounded_json
from localize.guardian.models import (
    CodexAuthMode,
    FeedbackEvent,
    GuardianAssessment,
    ProposedReplacement,
    RecurrenceCandidate,
)
from localize.guardian.process import (
    ProcessLimits,
    ProcessResourceError,
    WorkspaceQuota,
    run_bounded_process,
)


# Packaging contract: this JSON file must be included as package data before the
# guardian ships as a wheel. Keeping a real file is required by Codex's
# --output-schema interface.
RESULT_SCHEMA_PATH = (
    Path(__file__).resolve().parent / "schemas" / "guardian-result.schema.json"
)

_ALLOWED_ENVIRONMENT_KEYS = frozenset(
    {
        "HOME",
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
        "LOGNAME",
        "NO_COLOR",
        "CODEX_API_KEY",
        "OPENAI_API_KEY",
        "PATH",
        "REQUESTS_CA_BUNDLE",
        "SHELL",
        "SSL_CERT_DIR",
        "SSL_CERT_FILE",
        "TEMP",
        "TERM",
        "TMP",
        "TMPDIR",
        "USER",
    }
)

_AUTHENTICATION_FAILURE_MARKERS = (
    "failed to authenticate",
    "oauth session expired",
    "invalid api key",
    "incorrect api key",
    "authentication_error",
    "401 unauthorized",
    "not logged in",
    "run `codex login`",
    "run 'codex login'",
)
_CAPACITY_FAILURE_MARKERS = (
    "you've hit your usage limit",
    "you have hit your usage limit",
    "usage limit has been reached",
    "insufficient_quota",
    "billing_hard_limit_reached",
    "credit balance is too low",
)

_MAX_RESULT_BYTES = 2 * 1024 * 1024
_EVIDENCE_PERMISSION_PROFILE = "guardian_evidence"
_EVIDENCE_FILESYSTEM_POLICY = (
    'permissions.guardian_evidence.filesystem={":minimal"="read",'
    '":workspace_roots"={"."="read"}}'
)
_REASONING_EFFORTS = frozenset(
    {"low", "medium", "high", "xhigh", "max", "ultra"}
)


def guardian_assessment_permission_profile() -> str:
    """Return the named Codex permission profile used for evidence assessment."""

    return _EVIDENCE_PERMISSION_PROFILE


def guardian_assessment_permission_config(
    *, reasoning_effort: str | None = None
) -> tuple[str, ...]:
    """Return the exact credential and filesystem restrictions used for assessment."""

    settings = ["shell_environment_policy.inherit=none"]
    if reasoning_effort is not None:
        settings.append(f'model_reasoning_effort="{reasoning_effort}"')
    settings.extend(
        (
            f'default_permissions="{_EVIDENCE_PERMISSION_PROFILE}"',
            _EVIDENCE_FILESYSTEM_POLICY,
        )
    )
    return tuple(settings)


class CodexError(RuntimeError):
    """Base class for guardian Codex failures."""


class CodexAuthenticationError(CodexError):
    """Codex cannot authenticate and retrying cannot repair the session."""


class CodexCapacityError(CodexError):
    """Codex plan allowance, credits, or hard billing quota are unavailable."""


class CodexTransientError(CodexError):
    """Codex failed repeatedly for a potentially transient reason."""


class CodexTimeoutError(CodexTransientError):
    """Codex exceeded the configured deadline on every allowed attempt."""


class CodexOutputError(CodexError):
    """Codex returned output that is unsafe or does not satisfy the contract."""


class CodexExecutableError(CodexError):
    """The configured Codex executable could not be started."""


@dataclass(frozen=True)
class CodexTask:
    """One assessment prompt plus its sanitized, read-only evidence directory."""

    prompt: str
    evidence_dir: Path


@dataclass(frozen=True)
class GuardianReplacement:
    """One proposed localization-value replacement; never applied by this driver."""

    path: str
    key: str
    expected_value: str
    proposed_value: str


@dataclass(frozen=True)
class GuardianFeedbackDecision:
    """Codex's assessment of one immutable GitHub feedback revision."""

    feedback_id: str
    verdict: str
    confidence: float
    rationale: str
    replacements: tuple[GuardianReplacement, ...]


@dataclass(frozen=True)
class GuardianRecurrenceCandidate:
    """A possible systemic improvement for later, separately authorized work."""

    scope: str
    summary: str
    evidence_feedback_ids: tuple[str, ...]


@dataclass(frozen=True)
class CodexUsage:
    """Optional usage metadata observed in Codex stdout JSONL."""

    input_tokens: int | None = None
    cached_input_tokens: int | None = None
    output_tokens: int | None = None
    cost_usd: float | None = None


CodexAttemptObserver = Callable[[int, str, CodexUsage | None], None]
CodexSuccessObserver = Callable[[int, CodexUsage | None, "CodexResult"], None]


@dataclass(frozen=True)
class CodexResult:
    """Validated assessment returned by one successful Codex invocation."""

    schema_version: int
    summary: str
    feedback: tuple[GuardianFeedbackDecision, ...]
    recurrence_candidates: tuple[GuardianRecurrenceCandidate, ...]
    attempts: int
    usage: CodexUsage | None = None


def serialize_codex_result(result: CodexResult) -> str:
    """Serialize only the schema-validated decision, excluding billing metadata."""

    payload = {
        "schema_version": result.schema_version,
        "summary": result.summary,
        "feedback": [
            {
                "feedback_id": decision.feedback_id,
                "verdict": decision.verdict,
                "confidence": decision.confidence,
                "rationale": decision.rationale,
                "replacements": [
                    {
                        "path": replacement.path,
                        "key": replacement.key,
                        "expected_value": replacement.expected_value,
                        "proposed_value": replacement.proposed_value,
                    }
                    for replacement in decision.replacements
                ],
            }
            for decision in result.feedback
        ],
        "recurrence_candidates": [
            {
                "scope": candidate.scope,
                "summary": candidate.summary,
                "evidence_feedback_ids": list(candidate.evidence_feedback_ids),
            }
            for candidate in result.recurrence_candidates
        ],
    }
    _parse_semantic_result(_validate_schema(payload), attempts=0)
    serialized = json.dumps(
        payload,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )
    if len(serialized.encode("utf-8")) > _MAX_RESULT_BYTES:
        raise CodexOutputError("Codex result exceeds the 2 MiB safety limit.")
    return serialized


def parse_cached_codex_result(serialized: str) -> CodexResult:
    """Revalidate a durable result before reusing it without another model call."""

    if not isinstance(serialized, str) or len(serialized.encode("utf-8")) > _MAX_RESULT_BYTES:
        raise CodexOutputError("Cached Codex result exceeds the safety limit.")
    try:
        payload = _strict_json_loads(serialized)
    except ValueError as exc:
        raise CodexOutputError("Cached Codex result is invalid JSON.") from exc
    return _parse_semantic_result(_validate_schema(payload), attempts=0)


def _child_environment(
    *,
    isolated_home: Path,
    codex_home: Path,
    include_model_api_keys: bool = False,
    source: Mapping[str, str] | None = None,
) -> dict[str, str]:
    """Return the minimal environment Codex needs, excluding write credentials."""
    values = os.environ if source is None else source
    environment = {
        key: value
        for key, value in values.items()
        if key in _ALLOWED_ENVIRONMENT_KEYS and value
    }
    environment.setdefault("PATH", os.defpath)
    environment.setdefault("NO_COLOR", "1")
    if not include_model_api_keys:
        environment.pop("CODEX_API_KEY", None)
        environment.pop("OPENAI_API_KEY", None)
    environment["HOME"] = str(isolated_home)
    environment["CODEX_HOME"] = str(codex_home)
    return environment


def codex_auth_config(auth_mode: CodexAuthMode) -> tuple[str, ...]:
    """Pin the selected authentication surface independently of user config."""

    if auth_mode is CodexAuthMode.CHATGPT:
        return (
            'cli_auth_credentials_store="file"',
            'forced_login_method="chatgpt"',
        )
    if auth_mode is CodexAuthMode.API_KEY:
        return ('forced_login_method="api"',)
    raise ValueError("Unsupported Codex authentication mode.")


@lru_cache(maxsize=1)
def _result_validator() -> Draft202012Validator:
    try:
        schema = json.loads(RESULT_SCHEMA_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:  # pragma: no cover - packaging fault
        raise CodexOutputError(f"Could not load guardian result schema: {exc}") from exc
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema)


def _validate_schema(payload: object) -> Mapping[str, Any]:
    errors = sorted(
        _result_validator().iter_errors(payload),
        key=lambda error: tuple(str(part) for part in error.absolute_path),
    )
    if errors:
        first = errors[0]
        location = ".".join(str(part) for part in first.absolute_path) or "<root>"
        raise CodexOutputError(
            f"Codex result does not match the guardian schema at {location}: "
            f"{first.message}"
        )
    if not isinstance(payload, Mapping):  # Guaranteed by schema, keeps typing honest.
        raise CodexOutputError("Codex result must be a JSON object.")
    return payload


def _require_meaningful(value: str, label: str) -> None:
    if not value.strip():
        raise CodexOutputError(f"Codex result {label} must not be blank.")
    if "\x00" in value:
        raise CodexOutputError(f"Codex result {label} contains a NUL character.")


def _validate_repository_path(raw_path: str) -> None:
    _require_meaningful(raw_path, "replacement path")
    if "\\" in raw_path or raw_path.startswith("/"):
        raise CodexOutputError(
            f"Codex replacement path must be a normalized repository-relative path: {raw_path!r}"
        )
    raw_parts = raw_path.split("/")
    if any(part in {"", ".", ".."} for part in raw_parts):
        raise CodexOutputError(
            f"Codex replacement path must be a normalized repository-relative path: {raw_path!r}"
        )
    normalized = PurePosixPath(raw_path)
    if normalized.is_absolute() or normalized.as_posix() != raw_path:
        raise CodexOutputError(
            f"Codex replacement path must be a normalized repository-relative path: {raw_path!r}"
        )


def _parse_semantic_result(payload: Mapping[str, Any], *, attempts: int) -> CodexResult:
    summary = str(payload["summary"])
    _require_meaningful(summary, "summary")

    feedback_ids: set[str] = set()
    replacement_locations: set[tuple[str, str]] = set()
    decisions: list[GuardianFeedbackDecision] = []

    for raw_decision in payload["feedback"]:
        feedback_id = str(raw_decision["feedback_id"])
        rationale = str(raw_decision["rationale"])
        _require_meaningful(feedback_id, "feedback_id")
        _require_meaningful(rationale, f"rationale for {feedback_id!r}")
        if feedback_id in feedback_ids:
            raise CodexOutputError(f"Codex result repeats feedback_id {feedback_id!r}.")
        feedback_ids.add(feedback_id)

        replacements: list[GuardianReplacement] = []
        for raw_replacement in raw_decision["replacements"]:
            path = str(raw_replacement["path"])
            key = str(raw_replacement["key"])
            expected_value = str(raw_replacement["expected_value"])
            proposed_value = str(raw_replacement["proposed_value"])
            _validate_repository_path(path)
            _require_meaningful(key, "replacement key")
            if "\x00" in expected_value or "\x00" in proposed_value:
                raise CodexOutputError(
                    "Codex replacement values must not contain NUL characters."
                )
            if expected_value == proposed_value:
                raise CodexOutputError(
                    f"Codex replacement for {path}:{key} does not change the value."
                )
            location = (path, key)
            if location in replacement_locations:
                raise CodexOutputError(
                    f"Codex result proposes more than one replacement for {path}:{key}."
                )
            replacement_locations.add(location)
            replacements.append(
                GuardianReplacement(
                    path=path,
                    key=key,
                    expected_value=expected_value,
                    proposed_value=proposed_value,
                )
            )

        verdict = str(raw_decision["verdict"])
        # Structured Outputs cannot express the conditional allOf/if/then
        # constraint; enforce the verdict/replacement relationship locally.
        if verdict == "apply" and not replacements:
            raise CodexOutputError(
                f"Codex apply verdict for {feedback_id!r} must include a replacement."
            )
        if verdict != "apply" and replacements:
            raise CodexOutputError(
                f"Codex {verdict} verdict for {feedback_id!r} must not include "
                "replacements."
            )

        decisions.append(
            GuardianFeedbackDecision(
                feedback_id=feedback_id,
                verdict=verdict,
                confidence=float(raw_decision["confidence"]),
                rationale=rationale,
                replacements=tuple(replacements),
            )
        )

    recurrence_candidates: list[GuardianRecurrenceCandidate] = []
    for raw_candidate in payload["recurrence_candidates"]:
        candidate_summary = str(raw_candidate["summary"])
        _require_meaningful(candidate_summary, "recurrence summary")
        evidence_ids = tuple(
            str(item) for item in raw_candidate["evidence_feedback_ids"]
        )
        if len(set(evidence_ids)) != len(evidence_ids):
            raise CodexOutputError(
                "A recurrence candidate repeats an evidence feedback ID."
            )
        unknown_ids = sorted(set(evidence_ids) - feedback_ids)
        if unknown_ids:
            raise CodexOutputError(
                "A recurrence candidate references unknown feedback IDs: "
                + ", ".join(unknown_ids)
            )
        recurrence_candidates.append(
            GuardianRecurrenceCandidate(
                scope=str(raw_candidate["scope"]),
                summary=candidate_summary,
                evidence_feedback_ids=evidence_ids,
            )
        )

    return CodexResult(
        schema_version=int(payload["schema_version"]),
        summary=summary,
        feedback=tuple(decisions),
        recurrence_candidates=tuple(recurrence_candidates),
        attempts=attempts,
    )


def _contains_secret_value(value: object, secret_values: Sequence[str]) -> bool:
    if isinstance(value, str):
        return any(secret and secret in value for secret in secret_values)
    if isinstance(value, Mapping):
        return any(
            _contains_secret_value(key, secret_values)
            or _contains_secret_value(item, secret_values)
            for key, item in value.items()
        )
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return any(_contains_secret_value(item, secret_values) for item in value)
    return False


def _reject_non_json_constant(_value: str) -> None:
    raise ValueError("non-standard numeric constant")


def _reject_duplicate_object_members(
    pairs: list[tuple[str, Any]],
) -> dict[str, Any]:
    parsed: dict[str, Any] = {}
    for key, value in pairs:
        if key in parsed:
            # Do not echo an untrusted key because it could contain a credential.
            raise ValueError("duplicate object member")
        parsed[key] = value
    return parsed


def _strict_json_loads(raw_json: str) -> object:
    return loads_bounded_json(
        raw_json,
        parse_constant=_reject_non_json_constant,
        object_pairs_hook=_reject_duplicate_object_members,
    )


def _load_result(
    path: Path,
    *,
    attempts: int,
    secret_values: Sequence[str] = (),
) -> CodexResult:
    try:
        stat = path.lstat()
    except FileNotFoundError as exc:
        raise CodexOutputError("Codex did not write its required result file.") from exc
    if path.is_symlink() or not path.is_file():
        raise CodexOutputError("Codex result path is not a regular file.")
    if stat.st_size > _MAX_RESULT_BYTES:
        raise CodexOutputError("Codex result exceeds the 2 MiB safety limit.")
    try:
        payload = _strict_json_loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        raise CodexOutputError(f"Codex result is not valid UTF-8 JSON: {exc}") from exc
    if _contains_secret_value(payload, secret_values):
        raise CodexOutputError(
            "Codex result contains a credential value and was rejected."
        )
    return _parse_semantic_result(_validate_schema(payload), attempts=attempts)


def _optional_non_negative_int(value: object) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return None
    return value


def _optional_non_negative_number(value: object) -> float | None:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or value < 0
        or not math.isfinite(value)
    ):
        return None
    return float(value)


def _extract_usage(stdout: str | None) -> CodexUsage | None:
    """Best-effort extraction for Codex versions that emit usage JSONL."""
    if not stdout:
        return None
    for line in reversed(stdout.splitlines()):
        try:
            event = _strict_json_loads(line)
        except ValueError:
            continue
        if not isinstance(event, Mapping):
            continue
        raw_usage = event.get("usage")
        if not isinstance(raw_usage, Mapping):
            continue
        usage = CodexUsage(
            input_tokens=_optional_non_negative_int(raw_usage.get("input_tokens")),
            cached_input_tokens=_optional_non_negative_int(
                raw_usage.get("cached_input_tokens")
            ),
            output_tokens=_optional_non_negative_int(raw_usage.get("output_tokens")),
            cost_usd=_optional_non_negative_number(
                event.get("cost_usd", raw_usage.get("cost_usd"))
            ),
        )
        if any(
            value is not None
            for value in (
                usage.input_tokens,
                usage.cached_input_tokens,
                usage.output_tokens,
                usage.cost_usd,
            )
        ):
            return usage
    return None


def to_guardian_assessments(
    result: CodexResult,
    *,
    feedback_events: Sequence[FeedbackEvent],
    source_values: Mapping[tuple[str, str], str],
) -> tuple[GuardianAssessment, ...]:
    """Combine wire decisions with trusted event and source metadata.

    The model controls only its verdict, rationale, and proposed value fields.
    Feedback identity, locale, and source values are supplied by the controller;
    an omitted or invented feedback ID fails the whole conversion.
    """
    events_by_id: dict[str, FeedbackEvent] = {}
    for event in feedback_events:
        if event.feedback_id in events_by_id:
            raise CodexOutputError(
                f"Trusted feedback input repeats feedback ID {event.feedback_id!r}."
            )
        events_by_id[event.feedback_id] = event

    decisions_by_id = {decision.feedback_id: decision for decision in result.feedback}
    expected_ids = set(events_by_id)
    actual_ids = set(decisions_by_id)
    if actual_ids != expected_ids:
        missing = sorted(expected_ids - actual_ids)
        extra = sorted(actual_ids - expected_ids)
        details: list[str] = []
        if missing:
            details.append("missing: " + ", ".join(missing))
        if extra:
            details.append("unexpected: " + ", ".join(extra))
        raise CodexOutputError(
            "Codex feedback IDs do not match the trusted task ("
            + "; ".join(details)
            + ")."
        )

    recurrence_candidates = tuple(
        RecurrenceCandidate(
            scope=candidate.scope,
            summary=candidate.summary,
            evidence_feedback_ids=candidate.evidence_feedback_ids,
        )
        for candidate in result.recurrence_candidates
    )

    assessments: list[GuardianAssessment] = []
    # Preserve controller order rather than allowing the model to reorder work.
    for event in feedback_events:
        decision = decisions_by_id[event.feedback_id]
        replacements: list[ProposedReplacement] = []
        for replacement in decision.replacements:
            source_location = (replacement.path, replacement.key)
            if source_location not in source_values:
                raise CodexOutputError(
                    "Trusted source lookup has no value for "
                    f"{replacement.path}:{replacement.key}."
                )
            replacements.append(
                ProposedReplacement(
                    feedback_id=event.feedback_id,
                    path=replacement.path,
                    key=replacement.key,
                    locale=event.locale,
                    expected_value=replacement.expected_value,
                    proposed_value=replacement.proposed_value,
                    confidence=decision.confidence,
                    evidence=(decision.rationale,),
                    source_value=source_values[source_location],
                )
            )

        assessments.append(
            GuardianAssessment(
                feedback_id=event.feedback_id,
                verdict=decision.verdict,
                confidence=decision.confidence,
                rationale=decision.rationale,
                replacements=tuple(replacements),
                recurrence_candidates=tuple(
                    candidate
                    for candidate in recurrence_candidates
                    if event.feedback_id in candidate.evidence_feedback_ids
                ),
            )
        )
    return tuple(assessments)


def _is_authentication_failure(output: str) -> bool:
    lowered = output.casefold()
    return any(marker in lowered for marker in _AUTHENTICATION_FAILURE_MARKERS)


def _is_capacity_failure(output: str) -> bool:
    """Return whether an immediate retry cannot restore provider capacity."""

    lowered = output.casefold()
    return any(marker in lowered for marker in _CAPACITY_FAILURE_MARKERS)


def _diagnostic_detail(completed: subprocess.CompletedProcess[str]) -> str:
    """Return bounded-process diagnostics for internal failure classification."""

    return "\n".join(
        part.strip()
        for part in (completed.stderr or "", completed.stdout or "")
        if part and part.strip()
    )


def _redacted_detail(
    completed: subprocess.CompletedProcess[str], environment: Mapping[str, str]
) -> str:
    if any(environment.get(key) for key in ("CODEX_API_KEY", "OPENAI_API_KEY")):
        return "diagnostic output withheld because a model credential was present"
    detail = _diagnostic_detail(completed)
    return detail[-2000:] if detail else "no diagnostic output"


class CodexDriver:
    """Run at most two read-only Codex assessment attempts."""

    def __init__(
        self,
        *,
        model: str,
        reasoning_effort: str = "high",
        auth_mode: CodexAuthMode = CodexAuthMode.CHATGPT,
        codex_home: str | Path = "~/.local/share/localize-guardian/codex",
        executable: str = "codex",
        timeout_seconds: float = 1200,
        max_attempts: int = 2,
        deadline: PollDeadline | None = None,
    ) -> None:
        if not model.strip():
            raise ValueError("model must not be blank.")
        if not executable.strip():
            raise ValueError("executable must not be blank.")
        if reasoning_effort not in _REASONING_EFFORTS:
            raise ValueError(
                "reasoning_effort must be low, medium, high, xhigh, max, or ultra."
            )
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be greater than zero.")
        if max_attempts not in {1, 2}:
            raise ValueError("max_attempts must be either 1 or 2.")
        if not isinstance(auth_mode, CodexAuthMode):
            raise ValueError("auth_mode must be a CodexAuthMode.")
        self.model = model
        self.reasoning_effort = reasoning_effort
        self.auth_mode = auth_mode
        self.codex_home = Path(codex_home).expanduser().resolve()
        self.executable = executable
        self.timeout_seconds = timeout_seconds
        self.max_attempts = max_attempts
        self.deadline = deadline

    def _argv(self, evidence_dir: Path, output_path: Path) -> list[str]:
        config_arguments = [
            argument
            for setting in (
                *codex_auth_config(self.auth_mode),
                *guardian_assessment_permission_config(
                    reasoning_effort=self.reasoning_effort
                ),
            )
            for argument in ("-c", setting)
        ]
        return [
            self.executable,
            "--ask-for-approval",
            "never",
            *config_arguments,
            "exec",
            "--ephemeral",
            "--ignore-user-config",
            "--ignore-rules",
            "--strict-config",
            "--json",
            "--skip-git-repo-check",
            "--model",
            self.model,
            "-C",
            str(evidence_dir),
            "--output-schema",
            str(RESULT_SCHEMA_PATH.resolve()),
            "-o",
            str(output_path),
            "-",
        ]

    def run(
        self,
        task: CodexTask,
        *,
        api_key: str | None = None,
        attempt_observer: CodexAttemptObserver | None = None,
        success_observer: CodexSuccessObserver | None = None,
    ) -> CodexResult:
        prompt = task.prompt
        evidence_dir = Path(task.evidence_dir).expanduser().resolve()
        if not prompt.strip():
            raise ValueError("prompt must not be blank.")
        if "\x00" in prompt:
            raise ValueError("prompt must not contain NUL characters.")
        if not evidence_dir.is_dir():
            raise ValueError(f"evidence_dir is not a directory: {evidence_dir}")
        if api_key is not None and (
            not isinstance(api_key, str)
            or not api_key
            or any(character in api_key for character in "\r\n\x00")
        ):
            raise ValueError("api_key must be a non-empty single-line credential.")
        if self.auth_mode is CodexAuthMode.CHATGPT and api_key is not None:
            raise ValueError("api_key is forbidden in ChatGPT authentication mode.")
        if self.auth_mode is CodexAuthMode.API_KEY and api_key is None:
            raise ValueError("api_key is required in API-key authentication mode.")

        last_output_error: CodexOutputError | None = None
        timed_out = False

        with tempfile.TemporaryDirectory(prefix="localize-guardian-codex-") as temp_dir:
            temp_root = Path(temp_dir)
            isolated_home = temp_root / "home"
            isolated_home.mkdir(mode=0o700)
            if self.auth_mode is CodexAuthMode.CHATGPT:
                codex_home = self.codex_home
            else:
                codex_home = temp_root / "codex-home"
                codex_home.mkdir(mode=0o700)
            environment = _child_environment(
                isolated_home=isolated_home,
                codex_home=codex_home,
            )
            if api_key is not None:
                environment["CODEX_API_KEY"] = api_key
            secret_values = tuple(
                value
                for value in (
                    environment.get("CODEX_API_KEY"),
                    environment.get("OPENAI_API_KEY"),
                )
                if value
            )
            output_path = temp_root / "result.json"
            argv = self._argv(evidence_dir, output_path)
            workspace_quota = WorkspaceQuota.capture(
                temp_root,
                max_growth_bytes=128 * 1024 * 1024,
                max_added_entries=20_000,
                deadline=self.deadline,
            )

            for attempt in range(1, self.max_attempts + 1):
                if self.deadline is not None:
                    self.deadline.require_remaining()
                output_path.unlink(missing_ok=True)
                if attempt_observer is not None:
                    attempt_observer(attempt, "started", None)
                try:
                    effective_timeout = (
                        self.timeout_seconds
                        if self.deadline is None
                        else self.deadline.remaining(self.timeout_seconds)
                    )
                except PollDeadlineExceeded:
                    if attempt_observer is not None:
                        attempt_observer(attempt, "not_started", None)
                    raise
                deadline_bound_timeout = (
                    self.deadline is not None
                    and effective_timeout < self.timeout_seconds
                )
                try:
                    completed = run_bounded_process(
                        argv,
                        input=prompt,
                        text=True,
                        capture_output=True,
                        check=False,
                        timeout=effective_timeout,
                        env=environment,
                        start_new_session=True,
                        limits=ProcessLimits.for_timeout(
                            effective_timeout,
                            max_file_size_bytes=16 * 1024 * 1024,
                            require_linux_cgroup=True,
                        ),
                        workspace_quota=workspace_quota,
                    )
                except PollDeadlineExceeded:
                    if attempt_observer is not None:
                        attempt_observer(attempt, "failed", None)
                    raise
                except FileNotFoundError as exc:
                    if attempt_observer is not None:
                        attempt_observer(attempt, "not_started", None)
                    raise CodexExecutableError(
                        f"Codex executable was not found: {self.executable}"
                    ) from exc
                except subprocess.TimeoutExpired:
                    timed_out = True
                    if attempt_observer is not None:
                        attempt_observer(attempt, "failed", None)
                    if deadline_bound_timeout:
                        raise PollDeadlineExceeded(
                            "Guardian poll deadline was exceeded."
                        ) from None
                    if self.deadline is not None:
                        try:
                            self.deadline.require_remaining()
                        except PollDeadlineExceeded:
                            raise
                    if attempt == self.max_attempts:
                        raise CodexTimeoutError(
                            f"Codex timed out after {effective_timeout:g}s on "
                            f"{self.max_attempts} attempt(s)."
                        )
                    continue
                except ProcessResourceError as exc:
                    if attempt_observer is not None:
                        attempt_observer(attempt, "failed", None)
                    raise CodexOutputError(
                        "Codex exceeded a Guardian resource boundary."
                    ) from exc

                timed_out = False
                if completed.returncode != 0:
                    diagnostic = _diagnostic_detail(completed)
                    detail = _redacted_detail(completed, environment)
                    if attempt_observer is not None:
                        attempt_observer(
                            attempt,
                            "failed",
                            _extract_usage(completed.stdout),
                        )
                    if _is_authentication_failure(diagnostic):
                        raise CodexAuthenticationError(
                            f"Codex failed to authenticate: {detail}"
                        )
                    if _is_capacity_failure(diagnostic):
                        raise CodexCapacityError(
                            "Codex capacity is unavailable; inspect plan allowance, "
                            "credits, or API billing limits."
                        )
                    if "invalid_json_schema" in diagnostic.casefold():
                        raise CodexOutputError(
                            "Codex rejected the configured output schema; "
                            "retrying the same schema cannot repair it."
                        )
                    if attempt == self.max_attempts:
                        raise CodexTransientError(
                            f"Codex failed after {self.max_attempts} attempt(s) "
                            f"(exit {completed.returncode}): {detail}"
                        )
                    continue

                try:
                    result = _load_result(
                        output_path,
                        attempts=attempt,
                        secret_values=secret_values,
                    )
                except CodexOutputError as exc:
                    last_output_error = exc
                    if attempt_observer is not None:
                        attempt_observer(
                            attempt,
                            "failed",
                            _extract_usage(completed.stdout),
                        )
                    if attempt == self.max_attempts:
                        raise
                    continue

                usage = _extract_usage(completed.stdout)
                successful_result = CodexResult(
                    schema_version=result.schema_version,
                    summary=result.summary,
                    feedback=result.feedback,
                    recurrence_candidates=result.recurrence_candidates,
                    attempts=result.attempts,
                    usage=usage,
                )
                if success_observer is not None:
                    success_observer(attempt, usage, successful_result)
                if attempt_observer is not None:
                    attempt_observer(attempt, "succeeded", usage)
                return successful_result

        # The loop either returns or raises. These guards keep future changes
        # fail-closed if another exit path is introduced.
        if last_output_error is not None:  # pragma: no cover
            raise last_output_error
        if timed_out:  # pragma: no cover
            raise CodexTimeoutError("Codex timed out.")
        raise CodexTransientError("Codex did not produce a result.")  # pragma: no cover


__all__: Sequence[str] = (
    "CodexAuthenticationError",
    "CodexCapacityError",
    "CodexAttemptObserver",
    "CodexSuccessObserver",
    "CodexDriver",
    "CodexError",
    "CodexExecutableError",
    "CodexOutputError",
    "CodexResult",
    "CodexTask",
    "CodexTimeoutError",
    "CodexTransientError",
    "CodexUsage",
    "GuardianFeedbackDecision",
    "GuardianRecurrenceCandidate",
    "GuardianReplacement",
    "RESULT_SCHEMA_PATH",
    "codex_auth_config",
    "guardian_assessment_permission_config",
    "guardian_assessment_permission_profile",
    "parse_cached_codex_result",
    "serialize_codex_result",
    "to_guardian_assessments",
)
