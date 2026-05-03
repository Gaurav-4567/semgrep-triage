"""Tests for verifiers — both pass cases and crafted hallucination cases."""

from sg_triage.schema import (
    CodeContext,
    Confidence,
    Finding,
    FPCategory,
    Severity,
    Verdict,
    VerdictLabel,
)
from sg_triage.verifiers import verify_evidence_quotes, verify_grounding

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _finding() -> Finding:
    return Finding(
        rule_id="python.lang.security.audit.eval-detected",
        file_path="src/app.py",
        start_line=10,
        end_line=10,
        message="Detected the use of eval()",
        severity=Severity.WARNING,
        matched_code="    eval(user_input)",
    )


def _context() -> CodeContext:
    return CodeContext(
        language="python",
        matched_code_with_lines="10 |     eval(user_input)",
        imports="from flask import request",
        containing_function_name="process_data",
        containing_function_source=(
            " 8 | def process_data(data):\n"
            " 9 |     user_input = data.get('value')\n"
            "10 |     eval(user_input)\n"
        ),
        containing_function_start_line=8,
    )


def _verdict(
    label: VerdictLabel = VerdictLabel.LIKELY_TRUE_POSITIVE,
    reasoning: str = "Default reasoning.",
    evidence_quotes: list[str] | None = None,
    fp_categories: list[FPCategory] | None = None,
) -> Verdict:
    return Verdict(
        verdict=label,
        confidence=Confidence.MEDIUM,
        reasoning=reasoning,
        evidence_quotes=evidence_quotes or [],
        missing_context=[],
        fp_categories=fp_categories or [],
        suggested_action="Action.",
    )


# ---------------------------------------------------------------------------
# verify_evidence_quotes
# ---------------------------------------------------------------------------


def test_evidence_quotes_pass_when_verbatim_match():
    v = _verdict(
        label=VerdictLabel.FALSE_POSITIVE,
        evidence_quotes=["eval(user_input)"],
        fp_categories=[FPCategory.OTHER],
    )
    issues = verify_evidence_quotes(v, _finding(), _context())
    assert issues == []


def test_evidence_quotes_pass_with_whitespace_normalization():
    # Quote with extra leading whitespace and stripped indentation —
    # the kind of minor reformatting LLMs sometimes introduce.
    # Original code line is: "10 |     eval(user_input)"
    # LLM might quote it as: "    eval(user_input)" or "eval(user_input)"
    # — both should match after normalization.
    v = _verdict(
        label=VerdictLabel.FALSE_POSITIVE,
        evidence_quotes=["    eval(user_input)\n    "],
        fp_categories=[FPCategory.OTHER],
    )
    issues = verify_evidence_quotes(v, _finding(), _context())
    # Exact match fails (trailing newline + spaces), but normalized match succeeds
    assert issues == []


def test_evidence_quotes_fail_when_fabricated():
    v = _verdict(
        label=VerdictLabel.FALSE_POSITIVE,
        evidence_quotes=["sanitize_input(user_input)"],
        fp_categories=[FPCategory.SANITIZED_INPUT],
    )
    issues = verify_evidence_quotes(v, _finding(), _context())
    assert len(issues) == 1
    assert "does not appear verbatim" in issues[0]


def test_evidence_quotes_fail_partial_when_one_fabricated():
    v = _verdict(
        label=VerdictLabel.FALSE_POSITIVE,
        evidence_quotes=["eval(user_input)", "sanitize(value)"],
        fp_categories=[FPCategory.SANITIZED_INPUT],
    )
    issues = verify_evidence_quotes(v, _finding(), _context())
    assert len(issues) == 1
    assert "sanitize(value)" in issues[0]


def test_evidence_quotes_fp_verdict_with_no_quotes_fails():
    v = _verdict(
        label=VerdictLabel.FALSE_POSITIVE,
        evidence_quotes=[],
        fp_categories=[FPCategory.OTHER],
    )
    issues = verify_evidence_quotes(v, _finding(), _context())
    assert len(issues) == 1
    assert "no evidence_quotes" in issues[0]


def test_evidence_quotes_non_fp_verdict_with_no_quotes_passes():
    v = _verdict(label=VerdictLabel.NEEDS_HUMAN_REVIEW, evidence_quotes=[])
    issues = verify_evidence_quotes(v, _finding(), _context())
    assert issues == []


def test_evidence_quotes_empty_string_flagged():
    v = _verdict(
        label=VerdictLabel.FALSE_POSITIVE,
        evidence_quotes=["", "eval(user_input)"],
        fp_categories=[FPCategory.OTHER],
    )
    issues = verify_evidence_quotes(v, _finding(), _context())
    assert any("empty" in i for i in issues)


# ---------------------------------------------------------------------------
# verify_grounding
# ---------------------------------------------------------------------------


def test_grounding_passes_for_real_function_reference():
    v = _verdict(reasoning="The function `process_data` calls `eval()` on user_input.")
    issues = verify_grounding(v, _finding(), _context())
    assert issues == []


def test_grounding_passes_for_generic_security_vocabulary():
    v = _verdict(
        reasoning=(
            "The attacker can inject arbitrary code via the user input. "
            "There is no validation, sanitization, or escaping in the "
            "request handling path."
        )
    )
    issues = verify_grounding(v, _finding(), _context())
    assert issues == []


def test_grounding_fails_for_fabricated_function():
    v = _verdict(
        reasoning=("The code calls `sanitize_input()` before eval, which makes this safe.")
    )
    issues = verify_grounding(v, _finding(), _context())
    assert len(issues) == 1
    assert "sanitize_input" in issues[0]


def test_grounding_fails_for_fabricated_backtick_reference():
    v = _verdict(reasoning="The `validate_url` helper handles this safely.")
    issues = verify_grounding(v, _finding(), _context())
    assert any("validate_url" in i for i in issues)


def test_grounding_passes_for_dotted_reference_to_imported_module():
    # 'flask' appears in imports — a reference to flask.request should pass
    v = _verdict(reasoning="The data comes from flask.request which is the request object.")
    issues = verify_grounding(v, _finding(), _context())
    assert issues == []


def test_grounding_empty_reasoning_flagged():
    v = _verdict(reasoning="")
    issues = verify_grounding(v, _finding(), _context())
    assert len(issues) == 1
    assert "empty" in issues[0].lower()


def test_grounding_does_not_flag_token_appearing_in_function_name():
    # process_data appears in the containing function name; reasoning citing
    # it should pass
    v = _verdict(reasoning="The `process_data` function evaluates user input.")
    issues = verify_grounding(v, _finding(), _context())
    assert issues == []
