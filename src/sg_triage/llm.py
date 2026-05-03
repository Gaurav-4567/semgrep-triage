"""Anthropic API client wrapper: tool-use, retries, rate limiting.

Single public entry point: triage_finding(). Takes a finding + extracted
context, calls Claude with the triage prompt and tool schema, returns a
validated Verdict plus call metadata (duration, token counts).

Failure handling:
- Transient errors (rate limits, server errors, network blips): retry with
  exponential backoff up to MAX_RETRIES times.
- Tool-use enforcement: tool_choice forces the model to call submit_verdict;
  if it somehow doesn't, we treat as malformed and return needs_human_review.
- Schema violations: Pydantic validation errors are caught and converted to
  needs_human_review with a note explaining why.
- Hard failures (auth errors, invalid model, etc.): re-raised — the caller
  decides whether to skip the finding or abort the whole run.
"""

import time
from dataclasses import dataclass

import anthropic
from anthropic import Anthropic
from pydantic import ValidationError

from sg_triage.config import DEFAULT_MAX_TOKENS, DEFAULT_MODEL, DEFAULT_TEMPERATURE, get_api_key
from sg_triage.prompts.triage import TRIAGE_TOOL, build_system_prompt, build_user_message
from sg_triage.schema import (
    CodeContext,
    Confidence,
    Finding,
    Verdict,
    VerdictLabel,
)

# Retry configuration
MAX_RETRIES = 3
INITIAL_BACKOFF_SECONDS = 2.0
BACKOFF_MULTIPLIER = 2.0


@dataclass
class TriageResult:
    """Result of one LLM call: the verdict plus per-call metadata."""

    verdict: Verdict
    duration_seconds: float
    input_tokens: int
    output_tokens: int
    # If we had to synthesize a verdict due to malformed output, we record why.
    synthesized_reason: str | None = None


class LLMClient:
    """Wraps the Anthropic client with our triage-specific call pattern.

    Stateless aside from the underlying SDK client — safe to share across
    concurrent calls.
    """

    def __init__(
        self,
        api_key: str | None = None,
        model: str = DEFAULT_MODEL,
        temperature: float = DEFAULT_TEMPERATURE,
        max_tokens: int = DEFAULT_MAX_TOKENS,
    ):
        self._client = Anthropic(api_key=api_key or get_api_key())
        self.model = model
        self.temperature = temperature
        self.max_tokens = max_tokens
        # Cached system prompt (it's the same for every call in a run).
        self._system_prompt = build_system_prompt()

    def triage_finding(self, finding: Finding, context: CodeContext) -> TriageResult:
        """Call Claude to triage a single finding.

        Always returns a TriageResult — either with the LLM's verdict, or
        with a synthesized needs_human_review verdict if the call ultimately
        failed (after retries) or returned malformed output.
        """
        user_message = build_user_message(finding, context)
        start = time.monotonic()

        try:
            response = self._call_with_retry(user_message)
        except anthropic.APIError as e:
            duration = time.monotonic() - start
            return TriageResult(
                verdict=_synthesize_review_verdict(
                    f"LLM call failed after retries: {type(e).__name__}: {e}"
                ),
                duration_seconds=duration,
                input_tokens=0,
                output_tokens=0,
                synthesized_reason=f"api_error: {type(e).__name__}",
            )

        duration = time.monotonic() - start

        # Extract the tool-use block from the response
        tool_use_block = _extract_tool_use(response)
        if tool_use_block is None:
            return TriageResult(
                verdict=_synthesize_review_verdict(
                    "LLM did not call submit_verdict. Routing to human review."
                ),
                duration_seconds=duration,
                input_tokens=response.usage.input_tokens,
                output_tokens=response.usage.output_tokens,
                synthesized_reason="no_tool_use",
            )

        # Validate the tool input against our Pydantic schema
        try:
            verdict = Verdict.model_validate(tool_use_block.input)
        except ValidationError as e:
            return TriageResult(
                verdict=_synthesize_review_verdict(
                    f"LLM returned malformed verdict: {e}. Routing to human review."
                ),
                duration_seconds=duration,
                input_tokens=response.usage.input_tokens,
                output_tokens=response.usage.output_tokens,
                synthesized_reason="schema_validation_failed",
            )

        return TriageResult(
            verdict=verdict,
            duration_seconds=duration,
            input_tokens=response.usage.input_tokens,
            output_tokens=response.usage.output_tokens,
        )

    def _call_with_retry(self, user_message: str):
        """Call the Anthropic API with exponential backoff on transient errors."""
        backoff = INITIAL_BACKOFF_SECONDS
        last_error: Exception | None = None

        for attempt in range(MAX_RETRIES + 1):
            try:
                return self._client.messages.create(
                    model=self.model,
                    max_tokens=self.max_tokens,
                    temperature=self.temperature,
                    system=self._system_prompt,
                    tools=[TRIAGE_TOOL],
                    tool_choice={"type": "tool", "name": TRIAGE_TOOL["name"]},
                    messages=[{"role": "user", "content": user_message}],
                )
            except (
                anthropic.APIConnectionError,
                anthropic.APITimeoutError,
                anthropic.RateLimitError,
                anthropic.InternalServerError,
            ) as e:
                last_error = e
                if attempt == MAX_RETRIES:
                    break
                time.sleep(backoff)
                backoff *= BACKOFF_MULTIPLIER

        # Exhausted retries — re-raise so the caller can synthesize a verdict.
        assert last_error is not None
        raise last_error


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _extract_tool_use(response):
    """Find the submit_verdict tool_use block in a Messages response.

    Anthropic responses contain a list of content blocks; we want the one
    of type 'tool_use' with our tool's name. With tool_choice forced to our
    tool, this should always be present, but we defend against the unexpected.
    """
    for block in response.content:
        if getattr(block, "type", None) == "tool_use" and block.name == TRIAGE_TOOL["name"]:
            return block
    return None


def _synthesize_review_verdict(reason: str) -> Verdict:
    """Build a 'needs_human_review' verdict when the LLM call failed or
    returned unusable output.

    This is a critical safety mechanism: a failed LLM call must NEVER be
    silently treated as a false positive. Always route to human review.
    """
    return Verdict(
        verdict=VerdictLabel.NEEDS_HUMAN_REVIEW,
        confidence=Confidence.LOW,
        reasoning=reason,
        evidence_quotes=[],
        missing_context=["LLM verdict could not be obtained"],
        fp_categories=[],
        suggested_action="Review this finding manually; the LLM triage step did not complete.",
    )
