"""Post-LLM verifiers: detect ungrounded claims and fabricated evidence.

Runs after every LLM call. Returns a list of verification issues; an empty
list means the verdict passed. The orchestrator downgrades verdicts that
fail verification to needs_human_review, preserving the original verdict
in `original_verdict` for transparency.

Two verifiers:
- verify_evidence_quotes: every quote in evidence_quotes must appear
  verbatim in the code we sent to the LLM.
- verify_grounding: identifier-like tokens in reasoning must appear in
  the prompt context.

These don't prevent hallucination — they catch it. The realistic security
posture for an LLM tool is "assume failure, design for graceful degradation,
make the failure modes visible." That's what verifiers do.
"""

import re

from sg_triage.schema import CodeContext, Finding, Verdict, VerdictLabel

# ---------------------------------------------------------------------------
# Evidence quote verification
# ---------------------------------------------------------------------------


def verify_evidence_quotes(
    verdict: Verdict,
    finding: Finding,
    context: CodeContext,
) -> list[str]:
    """Check that each evidence quote appears verbatim in the prompt context.

    Returns a list of human-readable issues. Empty list = passed.

    Whitespace handling: tries exact match first, then whitespace-normalized.
    Quotes that match only after normalization pass with a soft note;
    quotes that don't match either way are treated as fabricated.
    """
    # FP verdicts MUST have at least one evidence quote per our schema/prompt.
    # If the LLM returned an FP with no quotes, that's a verification failure.
    if verdict.verdict == VerdictLabel.FALSE_POSITIVE and not verdict.evidence_quotes:
        return [
            "Verdict is false_positive but no evidence_quotes were provided. "
            "Per the prompt contract, FP verdicts require at least one verbatim "
            "code quote."
        ]

    if not verdict.evidence_quotes:
        return []

    haystack = _build_haystack(finding, context)
    haystack_normalized = _normalize_whitespace(haystack)

    issues: list[str] = []
    for i, quote in enumerate(verdict.evidence_quotes, start=1):
        if not quote.strip():
            issues.append(f"Evidence quote #{i} is empty.")
            continue

        if quote in haystack:
            continue  # exact match — best case

        quote_normalized = _normalize_whitespace(quote)
        if quote_normalized in haystack_normalized:
            # Matched only after whitespace normalization — soft pass with note.
            # This is intentionally NOT added as a verification issue, because
            # it doesn't indicate hallucination. Just a model formatting quirk.
            continue

        issues.append(
            f"Evidence quote #{i} does not appear verbatim in the code shown to "
            f"the LLM. Quote: {quote!r}"
        )

    return issues


# ---------------------------------------------------------------------------
# Grounding verification
# ---------------------------------------------------------------------------

# Identifier-like tokens we extract from reasoning text. These are the
# patterns most likely to be fabricated function/variable references.
_BACKTICK_TOKEN = re.compile(r"`([A-Za-z_][A-Za-z0-9_]*)`")
_CALL_TOKEN = re.compile(r"\b([a-z_][a-zA-Z0-9_]*)\s*\(")
_DOTTED_TOKEN = re.compile(r"\b([a-z_][a-zA-Z0-9_]*\.[a-z_][a-zA-Z0-9_]+)")
_CAMEL_OR_SNAKE = re.compile(r"\b([A-Z][a-zA-Z0-9]*[a-z][A-Z][A-Za-z0-9]*|[a-z]+_[a-z_0-9]+)\b")

# Whitelist: common English / security vocabulary that looks like an
# identifier but isn't a code reference. The LLM uses these as concepts.
_GENERIC_VOCAB = frozenset(
    {
        # English / general
        "this",
        "that",
        "the",
        "code",
        "data",
        "value",
        "function",
        "method",
        "variable",
        "string",
        "number",
        "object",
        "type",
        "list",
        "dict",
        "argument",
        "parameter",
        "return",
        "result",
        "error",
        "exception",
        "case",
        "example",
        "instance",
        "context",
        "approach",
        "issue",
        "concern",
        # Security vocabulary that isn't code-specific
        "attacker",
        "user",
        "input",
        "output",
        "validation",
        "sanitization",
        "injection",
        "exploit",
        "vulnerability",
        "payload",
        "request",
        "response",
        "session",
        "cookie",
        "token",
        "secret",
        "password",
        "credential",
        "authentication",
        "authorization",
        "authn",
        "authz",
        "access",
        "control",
        # Common verbs / nouns
        "use",
        "uses",
        "used",
        "using",
        "call",
        "calls",
        "called",
        "calling",
        "pass",
        "passed",
        "passing",
        "set",
        "sets",
        "setting",
        "get",
        "gets",
        "getting",
        "check",
        "checks",
        "checking",
        "see",
        "shown",
        "show",
        "seen",
        "appear",
        "appears",
        "appearing",
        "exist",
        "exists",
        "existing",
        # Noise from URLs and references
        "https",
        "http",
        "www",
        "github",
        "com",
        "org",
        "io",
    }
)


def verify_grounding(
    verdict: Verdict,
    finding: Finding,
    context: CodeContext,
) -> list[str]:
    """Check that identifier-like tokens in reasoning appear in the prompt context.

    Returns a list of suspect tokens cited in reasoning that don't appear
    anywhere in the code or context we sent to the LLM. Empty list = passed.

    Design: we only flag tokens that look like CODE references — backtick
    names, names followed by '()', dotted names, snake_case, mixed case.
    Pure English words are skipped to avoid noise.
    """
    if not verdict.reasoning.strip():
        return ["Reasoning field is empty."]

    haystack = _build_haystack(finding, context)
    cited = _extract_cited_tokens(verdict.reasoning)

    issues: list[str] = []
    flagged: set[str] = set()
    for token in cited:
        if token.lower() in _GENERIC_VOCAB:
            continue
        if token in flagged:
            continue
        if _token_appears_in(token, haystack):
            continue
        flagged.add(token)
        issues.append(
            f"Reasoning references `{token}` but this token does not appear in "
            f"the code or context shown to the LLM."
        )

    return issues


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _build_haystack(finding: Finding, context: CodeContext) -> str:
    """Concatenate everything the LLM was shown, for substring matching.

    Order doesn't matter — we only care whether tokens / quotes appear
    somewhere in the sent context.
    """
    parts: list[str] = [
        finding.matched_code,
        finding.message,
        finding.rule_id,
        finding.file_path,
        context.matched_code_with_lines,
    ]
    if context.imports:
        parts.append(context.imports)
    if context.containing_function_source:
        parts.append(context.containing_function_source)
    if context.containing_function_name:
        parts.append(context.containing_function_name)
    for cf in context.called_functions:
        parts.append(cf.source)
        parts.append(cf.name)
    return "\n".join(parts)


def _normalize_whitespace(text: str) -> str:
    """Collapse runs of whitespace into single spaces, strip leading/trailing."""
    return re.sub(r"\s+", " ", text).strip()


def _extract_cited_tokens(reasoning: str) -> list[str]:
    """Pull identifier-like tokens out of reasoning text, in order, deduped."""
    seen: set[str] = set()
    ordered: list[str] = []

    for pattern in (_BACKTICK_TOKEN, _CALL_TOKEN, _DOTTED_TOKEN, _CAMEL_OR_SNAKE):
        for match in pattern.findall(reasoning):
            # findall returns either a string (one group) or a tuple
            token = match if isinstance(match, str) else match[0]
            if token and token not in seen:
                seen.add(token)
                ordered.append(token)

    return ordered


def _token_appears_in(token: str, haystack: str) -> bool:
    """Check whether a token appears in haystack, including dotted forms.

    For a dotted token like 'os.path.join', we accept matches on either the
    full dotted form OR the rightmost component ('join'), to handle cases
    where the LLM cites `os.path.join` and the code shows `from os.path import join`.
    """
    if token in haystack:
        return True
    if "." in token:
        last = token.rsplit(".", 1)[-1]
        if last in haystack:
            return True
    return False
