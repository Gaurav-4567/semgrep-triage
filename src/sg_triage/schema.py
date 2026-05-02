"""Pydantic models: Finding, CodeContext, Verdict, Report.

This module defines the data contracts used across the entire pipeline:
  - Finding: parsed from Semgrep JSON
  - CodeContext: produced by the extractor
  - Verdict: produced by the LLM (matches the Anthropic tool-use schema)
  - TriagedFinding: Finding + Context + Verdict + verification metadata
  - Report: full output for one triage run, with aggregate stats
"""

from datetime import datetime
from enum import Enum

from pydantic import BaseModel, Field

# ----------------------------------------------------------------------------
# Enums — constrained vocabularies used throughout the pipeline
# ----------------------------------------------------------------------------


class Severity(str, Enum):
    """Semgrep severity levels. Includes CRITICAL for custom rules and rule packs
    that use it beyond Semgrep's stock INFO/WARNING/ERROR."""

    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class ResolutionMethod(str, Enum):
    """How the extractor resolved a called function's definition."""

    SAME_FILE = "same_file"
    SAME_MODULE_IMPORT = "same_module_import"


class VerdictLabel(str, Enum):
    """The three verdict buckets the LLM can return."""

    FALSE_POSITIVE = "false_positive"
    LIKELY_TRUE_POSITIVE = "likely_true_positive"
    NEEDS_HUMAN_REVIEW = "needs_human_review"


class Confidence(str, Enum):
    """LLM's confidence in its verdict."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class FPCategory(str, Enum):
    """Categories of false positive. Populated only when verdict is FALSE_POSITIVE.

    Note: business-logic / deployment-context FPs (endpoint behind WAF, internal-only,
    etc.) are deliberately not a category here — those route to NEEDS_HUMAN_REVIEW
    via prompt instructions, because the LLM cannot verify them from code alone.
    """

    TEST_CODE = "test_code"
    SANITIZED_INPUT = "sanitized_input"
    UNREACHABLE = "unreachable"
    THIRD_PARTY = "third_party"
    NOT_USER_INPUT = "not_user_input"
    FRAMEWORK_HANDLED = "framework_handled"
    FALSE_PATTERN_MATCH = "false_pattern_match"
    OTHER = "other"


# ----------------------------------------------------------------------------
# Core models
# ----------------------------------------------------------------------------


class Finding(BaseModel):
    """A single finding from a Semgrep scan."""

    # Identity / origin
    rule_id: str = Field(
        ...,
        description="Semgrep rule that fired, e.g. 'python.lang.security.audit.dangerous-subprocess'",
    )

    # Location
    file_path: str = Field(..., description="Path to the file, relative to the scanned repo root")
    start_line: int = Field(..., ge=1)
    end_line: int = Field(..., ge=1)
    start_col: int | None = None
    end_col: int | None = None

    # Description
    message: str = Field(..., description="Human-readable rule message from Semgrep")
    severity: Severity

    # Classification metadata (optional — not all rules have these)
    cwe: list[str] = Field(default_factory=list, description="CWE identifiers, e.g. ['CWE-89']")
    owasp: list[str] = Field(default_factory=list, description="OWASP categories")

    # The matched code itself (Semgrep includes this in `extra.lines`)
    matched_code: str = Field(..., description="The actual code lines that matched the rule")

    # Optional taint trace, summarized to a string for v0.1
    has_dataflow_trace: bool = False
    dataflow_trace_summary: str | None = Field(
        default=None,
        description="Human-readable summary of source -> sink path, if Semgrep provided one",
    )
    semgrep_confidence: str | None = Field(
        default=None,
        description="LOW/MEDIUM/HIGH from Semgrep metadata, if present",
    )


class CalledFunction(BaseModel):
    """A function definition resolved during code extraction."""

    name: str
    source: str = Field(..., description="The function definition source, with line numbers")
    file_path: str = Field(..., description="Where the definition was found")
    start_line: int
    resolution_method: ResolutionMethod


class CodeContext(BaseModel):
    """Code context for a finding — what gets sent to the LLM.

    Honesty principle: when extraction is incomplete, that fact is recorded in
    `extraction_notes` and surfaced to the LLM, which surfaces it to the user
    via `Verdict.missing_context`. The pipeline never silently hides gaps.
    """

    language: str = Field(..., description="Source language, e.g. 'python'")

    # Always present
    matched_code_with_lines: str = Field(
        ..., description="Matched lines, formatted with line numbers"
    )

    # Usually present (None for module-level matches or extraction failures)
    imports: str | None = None
    containing_function_name: str | None = None
    containing_function_source: str | None = None
    containing_function_start_line: int | None = None

    # Best-effort
    called_functions: list[CalledFunction] = Field(default_factory=list)

    # Honest accounting of what we couldn't extract
    extraction_notes: list[str] = Field(
        default_factory=list,
        description="Human-readable notes about extraction limitations, "
        "e.g. 'definition of foo() not resolved'",
    )


class Verdict(BaseModel):
    """LLM's triage decision on a single finding.

    This model mirrors the Anthropic tool-use input schema in prompts/triage.py.
    The LLM's tool call is parsed directly into this model; any deviation from
    the enums causes a Pydantic validation error, which the orchestrator
    catches and converts to NEEDS_HUMAN_REVIEW.
    """

    verdict: VerdictLabel
    confidence: Confidence
    reasoning: str = Field(..., description="2-5 sentences walking through the dataflow considered")
    evidence_quotes: list[str] = Field(
        default_factory=list,
        description="Verbatim quotes from the provided code supporting the verdict. "
        "Required (non-empty) when verdict is FALSE_POSITIVE.",
    )
    missing_context: list[str] = Field(
        default_factory=list,
        description="Specific things the LLM would need to see to be more confident",
    )
    fp_categories: list[FPCategory] = Field(
        default_factory=list,
        description="Categories of false positive. Empty unless verdict is FALSE_POSITIVE.",
    )
    suggested_action: str = Field(
        ..., description="One short sentence: what the human reviewer should do"
    )


class TriagedFinding(BaseModel):
    """A finding with its extracted context, LLM verdict, and verification metadata."""

    finding: Finding
    context: CodeContext
    verdict: Verdict

    # Stable identity for cache lookup across rescans.
    # Computed as hash of (rule_id, file_path, normalized matched code,
    # normalized containing function source). Survives line-number shifts
    # caused by unrelated edits but invalidates when the relevant code changes.
    fingerprint: str = Field(..., description="Stable hash for cache lookup across rescans")
    from_cache: bool = Field(default=False, description="True if the verdict was reused from cache")

    # Verifier output
    verification_passed: bool = True
    verification_notes: list[str] = Field(
        default_factory=list,
        description="Issues raised by post-LLM verifiers "
        "(e.g. 'evidence quote not found in source')",
    )

    # If verification failed and we downgraded the verdict, preserve the original
    # so the report can show 'LLM said X but we downgraded to Y because Z'.
    original_verdict: VerdictLabel | None = None

    # Bookkeeping
    llm_call_duration_seconds: float | None = None
    input_tokens: int | None = None
    output_tokens: int | None = None


# ----------------------------------------------------------------------------
# Report-level models
# ----------------------------------------------------------------------------


class RuleStats(BaseModel):
    """Aggregate stats for one Semgrep rule across the run."""

    rule_id: str
    total: int
    false_positive: int
    likely_true_positive: int
    needs_human_review: int
    fp_rate: float = Field(..., ge=0.0, le=1.0, description="false_positive / total")


class Report(BaseModel):
    """Full triage report for one Semgrep scan."""

    # Run metadata — useful for reproducibility and report comparison
    generated_at: datetime = Field(default_factory=datetime.utcnow)
    sg_triage_version: str
    prompt_version: str
    model: str
    repo_path: str
    semgrep_findings_path: str

    # The findings themselves
    triaged_findings: list[TriagedFinding]

    # Aggregate counts (denormalized for easy consumption of the JSON report)
    total_findings: int
    false_positive_count: int
    likely_true_positive_count: int
    needs_human_review_count: int

    # Per-rule breakdown — surfaces noisy rules the user may want to tune
    rule_stats: list[RuleStats] = Field(default_factory=list)
    rules_to_consider_tuning: list[str] = Field(
        default_factory=list,
        description="Rule IDs with high FP rates (>=5 findings, >=80% FP) "
        "that the user may want to disable or scope down",
    )

    # Cost / time bookkeeping
    total_input_tokens: int = 0
    total_output_tokens: int = 0
    total_duration_seconds: float = 0.0
    cache_hits: int = 0
    cache_misses: int = 0

    semgrep_parse_errors: list[str] = Field(
        default_factory=list,
        description="Files Semgrep couldn't fully parse during the scan",
    )
