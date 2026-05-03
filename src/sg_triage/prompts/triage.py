"""v0.1 triage prompt and Anthropic tool schema.

The prompt is built from composable sections. v0.1 always uses the same set;
v0.2 will add an optional `project_context` section for per-project trust
declarations (custom sanitizers, internal-only paths, etc.).
Versioning: every report records PROMPT_VERSION so a re-run with a different
prompt version can be distinguished from a re-run with the same prompt.
"""

from sg_triage.schema import CodeContext, Finding

PROMPT_VERSION = "0.1.0"


# ---------------------------------------------------------------------------
# Tool schema — what the LLM must return
# ---------------------------------------------------------------------------

TRIAGE_TOOL = {
    "name": "submit_verdict",
    "description": (
        "Submit a triage verdict for the Semgrep finding. Call this tool exactly once per finding."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "verdict": {
                "type": "string",
                "enum": [
                    "false_positive",
                    "likely_true_positive",
                    "needs_human_review",
                ],
                "description": (
                    "false_positive: concrete reason the code cannot be exploited as written. "
                    "likely_true_positive: dataflow plausibly connects untrusted input to a "
                    "dangerous sink without adequate mitigation in the code shown. "
                    "needs_human_review: any meaningful uncertainty, missing context, or "
                    "facts about deployment/network/business context that cannot be verified "
                    "from code alone."
                ),
            },
            "confidence": {
                "type": "string",
                "enum": ["low", "medium", "high"],
            },
            "reasoning": {
                "type": "string",
                "description": (
                    "2-5 sentences walking through the dataflow you considered. "
                    "Reference specific functions and variables from the provided code only."
                ),
            },
            "evidence_quotes": {
                "type": "array",
                "items": {"type": "string"},
                "description": (
                    "Direct verbatim quotes from the provided code that support the "
                    "verdict. REQUIRED (non-empty) when verdict is false_positive. "
                    "Each quote must appear character-for-character in the code shown. "
                    "These quotes will be programmatically verified."
                ),
            },
            "missing_context": {
                "type": "array",
                "items": {"type": "string"},
                "description": (
                    "Specific things you would need to see to be more confident. "
                    "Empty if none. Examples: 'callers of this function', "
                    "'definition of validate_url', 'whether this endpoint is internet-facing'."
                ),
            },
            "fp_categories": {
                "type": "array",
                "items": {
                    "type": "string",
                    "enum": [
                        "test_code",
                        "sanitized_input",
                        "unreachable",
                        "third_party",
                        "not_user_input",
                        "framework_handled",
                        "false_pattern_match",
                        "other",
                    ],
                },
                "description": "Empty unless verdict is false_positive.",
            },
            "suggested_action": {
                "type": "string",
                "description": "One short sentence: what the human reviewer should do.",
            },
        },
        "required": [
            "verdict",
            "confidence",
            "reasoning",
            "evidence_quotes",
            "missing_context",
            "suggested_action",
        ],
    },
}


# ---------------------------------------------------------------------------
# Prompt sections — composable building blocks
# ---------------------------------------------------------------------------

_ROLE = """\
You are a senior application security engineer performing false-positive triage
on findings from the Semgrep static analysis tool. For each finding, your job
is to decide — given the code context provided — whether it is a real,
exploitable vulnerability or a false positive.\
"""

_INPUT_DESCRIPTION = """\
You will be given:
- The Semgrep rule that fired: rule ID, message, severity, CWE/OWASP category
- The matched code with line numbers and the file path
- The function containing the finding (when extractable)
- Functions called by that function, when their definitions could be resolved
- The Semgrep dataflow trace, if the rule is taint-mode
- Notes about extraction limitations — things we couldn't include\
"""

_REASONING = """\
# How to reason

False-positive triage is reasoning about REACHABILITY and EXPLOITABILITY,
not pattern matching. A finding is a false positive only when you can identify
a specific, concrete reason the apparent vulnerability cannot be exploited in
this code as written. A finding is a true positive when the path from
untrusted input to a dangerous operation is plausible and unmitigated in the
code shown.

Walk the dataflow:
1. What is the dangerous operation (the sink)?
2. What data reaches that sink?
3. Where does that data originate — is it attacker-controlled?
4. Is there validation, sanitization, escaping, or parameterization between
   source and sink?
5. Are there access controls or preconditions gating this path?\
"""

_FP_PATTERNS = """\
# Common false-positive patterns

- The match is in test code, fixtures, mocks, demos, or example files
- Input is hardcoded, from config, or otherwise not attacker-controlled
- Input is properly parameterized (SQL bind variables), escaped, or validated
  by a vetted library
- The pattern matched a type annotation, comment, docstring, or unreachable
  string literal
- The code is dead or behind a feature flag that is off
- The framework handles the concern (Django ORM querysets, parameterized
  drivers, escapeHtml in templating engines)
- The match is in vendored third-party code the project doesn't maintain\
"""

_TRAP_PATTERNS = """\
# Common FALSE-NEGATIVE traps (cases that look like FPs but aren't)

- "It's behind authentication" — authenticated users are still attackers in
  most threat models; auth gates do not neutralize injection
- "The input is validated" — but the validation is a blacklist, incomplete,
  or applied inconsistently
- "It uses an ORM" — but with .raw(), .extra(), or string interpolation into
  the query
- "It's only called internally" — but "internally" includes paths reached by
  attacker-influenced data
- "It's just logging" — but the log sink is a system that interprets format
  strings (log injection, log4shell-shaped)

If you find yourself reaching for one of these as the reason something is
a FP, stop and re-examine.\
"""

_PATH_BIAS = """\
# How to use the file path

The file path is provided as evidence about code provenance (test code,
vendored dependencies, examples) — not as evidence about the security
sensitivity of the code. A finding in `auth/login.py` is not more likely
to be a true positive than the same code in `utils/helpers.py`. Reason
from the code, not the filename. The path matters only when it tells you
the code is test code, third-party, or an example — facts about what kind
of code this is, not how important it is.\
"""

_DEPLOYMENT_CONTEXT = """\
# Deployment and business context are not yours to verdict

Some findings are false positives because of facts about deployment, not the
code: the endpoint is internal-only, behind a WAF, behind authentication
that's enforced upstream, on a network not reachable from the internet, or
gated by a feature flag. You cannot verify any of these from the code alone.

When the only reason a finding might be a false positive is a fact about
deployment, network topology, or business context, the verdict is
`needs_human_review` — not `false_positive`. Note the assumption in
`suggested_action` so the human reviewer knows what to verify.\
"""

_GROUNDING = """\
# Grounding requirement

Every claim in your reasoning must refer to code that is actually present
in the context above. Do not reference functions, variables, validators, or
sanitizers that are not shown. If a relevant piece of code is not visible
to you, say so in `missing_context` rather than assuming what it does.

For `false_positive` verdicts, you must provide at least one verbatim quote
from the code in `evidence_quotes`. Quotes must match the source character
for character.

When quoting, quote the raw code only. Do NOT include the line-number
prefix (e.g., `'277 |'`) that is shown for readability — quote the code as
it appears after the `|` character. These quotes will be programmatically
verified — fabricated quotes will cause your verdict to be discarded.\
"""

_CALIBRATION = """\
# Verdict calibration — read carefully

- "false_positive" requires a specific, concrete reason the code cannot be
  exploited as written. General impressions are not enough.
- "likely_true_positive" applies when dataflow plausibly connects untrusted
  input to a dangerous sink without adequate mitigation in the code shown.
- "needs_human_review" is the correct answer whenever:
  - You cannot see where input originates
  - You cannot determine whether the code is reachable
  - Validation or sanitization happens in a function not shown
  - The Semgrep rule fired on a pattern you cannot fully evaluate from
    the snippet alone
  - The verdict depends on deployment or business context
  - You have any meaningful doubt

False positives that survive triage are an inconvenience. False negatives —
real bugs you marked as FPs — destroy user trust in this tool. Default to
human review when uncertain.

"confidence: high" on a "false_positive" verdict is a strong claim. Reserve
it for cases where the evidence in the context provided is unambiguous.\
"""

_OUTPUT = """\
# Output

Respond by calling the `submit_verdict` tool exactly once with the
structured verdict. Do not produce prose outside the tool call.\
"""


# ---------------------------------------------------------------------------
# Prompt assembly
# ---------------------------------------------------------------------------


def build_system_prompt() -> str:
    """Build the system prompt from composable sections.

    v0.1 uses a fixed set of sections. v0.2 will accept an optional
    project_context parameter that adds a per-project trust section.
    """
    sections = [
        _ROLE,
        _INPUT_DESCRIPTION,
        _REASONING,
        _FP_PATTERNS,
        _TRAP_PATTERNS,
        _PATH_BIAS,
        _DEPLOYMENT_CONTEXT,
        _GROUNDING,
        _CALIBRATION,
        _OUTPUT,
    ]
    return "\n\n".join(sections)


def build_user_message(finding: Finding, context: CodeContext) -> str:
    """Render the per-finding details into the user message."""
    parts = ["# The finding", ""]
    parts.append(f"Rule ID: {finding.rule_id}")
    parts.append(f"Rule message: {finding.message}")
    parts.append(f"Severity: {finding.severity.value}")
    if finding.cwe:
        parts.append(f"CWE: {', '.join(finding.cwe)}")
    if finding.owasp:
        parts.append(f"OWASP: {', '.join(finding.owasp)}")
    if finding.semgrep_confidence:
        parts.append(f"Semgrep's own confidence: {finding.semgrep_confidence}")
    parts.append(f"File: {finding.file_path}")
    parts.append(f"Lines: {finding.start_line}-{finding.end_line}")

    parts.append("")
    parts.append("## Matched code")
    parts.append("")
    parts.append("```python")
    parts.append(context.matched_code_with_lines)
    parts.append("```")

    if context.imports:
        parts.append("")
        parts.append("## File imports")
        parts.append("")
        parts.append("```python")
        parts.append(context.imports)
        parts.append("```")

    if context.containing_function_source:
        parts.append("")
        parts.append(f"## Containing function: `{context.containing_function_name}`")
        parts.append("")
        parts.append("```python")
        parts.append(context.containing_function_source)
        parts.append("```")
    else:
        parts.append("")
        parts.append("## Containing function")
        parts.append("")
        parts.append(
            "_The match is at module level (not inside any function). "
            "No containing function context available._"
        )

    if context.called_functions:
        parts.append("")
        parts.append(f"## Called functions ({len(context.called_functions)} resolved)")
        parts.append("")
        for cf in context.called_functions:
            parts.append(f"### `{cf.name}` (from {cf.file_path}, {cf.resolution_method.value})")
            parts.append("")
            parts.append("```python")
            parts.append(cf.source)
            parts.append("```")
            parts.append("")

    if finding.has_dataflow_trace and finding.dataflow_trace_summary:
        parts.append("")
        parts.append("## Dataflow trace")
        parts.append("")
        parts.append(finding.dataflow_trace_summary)

    if context.extraction_notes:
        parts.append("")
        parts.append("## Extraction notes")
        parts.append("")
        parts.append(
            "_The following could not be fully extracted. "
            "Treat these as missing context, not as facts about the code:_"
        )
        parts.append("")
        for note in context.extraction_notes:
            parts.append(f"- {note}")

    return "\n".join(parts)
