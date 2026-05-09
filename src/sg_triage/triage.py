"""Orchestration: parse findings -> extract context -> LLM -> verify -> report.

The orchestrator is the only module that knows about the full pipeline.
Other modules are stateless helpers; this is where state and concurrency
live.

For each finding:
    1. Determine if it's processable (Python only for v0.1)
    2. Compute a stable fingerprint
    3. Check the cache; on hit, use the cached verdict
    4. On miss: extract context -> call LLM -> run verifiers -> downgrade
       if verification fails -> store in cache -> assemble TriagedFinding
    5. Aggregate all TriagedFindings into a Report with per-rule stats

Concurrency: ThreadPoolExecutor with 5 workers. Each finding is processed
independently; failures in one don't affect others.

Failure handling: every per-finding step is wrapped to ensure a
TriagedFinding is always produced, even if extraction crashes or the LLM
times out. The synthesized fallback always routes to needs_human_review.
"""

from __future__ import annotations

import time
import traceback
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import suppress
from datetime import datetime
from pathlib import Path

from rich.console import Console
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)

from sg_triage import __version__
from sg_triage.cache import VerdictCache, compute_fingerprint
from sg_triage.config import DEFAULT_MODEL
from sg_triage.extractor.python_extractor import extract_context
from sg_triage.llm import LLMClient
from sg_triage.parser import parse_semgrep_output
from sg_triage.prompts.triage import PROMPT_VERSION
from sg_triage.schema import (
    CodeContext,
    Confidence,
    Finding,
    Report,
    RuleStats,
    Severity,
    TriagedFinding,
    Verdict,
    VerdictLabel,
)
from sg_triage.verifiers import verify_evidence_quotes, verify_grounding

MAX_CONCURRENT_LLM_CALLS = 5

# A rule with at least this many findings AND this fraction marked FP is
# surfaced in 'rules_to_consider_tuning'.
NOISY_RULE_MIN_FINDINGS = 5
NOISY_RULE_MIN_FP_RATE = 0.8


def run_triage(
    findings_path: Path,
    repo_path: Path,
    *,
    use_cache: bool = True,
    limit: int | None = None,
    console: Console | None = None,
) -> Report:
    """Run the full triage pipeline. Returns a Report.

    Args:
        findings_path: Semgrep JSON output file.
        repo_path: Root of the scanned repository.
        use_cache: If False, skip the cache (forces re-triage).
        limit: If set, process only the first N processable findings.
        console: Rich console for progress display. None silences output.
    """
    console = console or Console(quiet=True)
    run_started = time.monotonic()

    # ---- Phase 1: parse and split by language --------------------------
    console.print(f"[bold]Findings:[/bold] {findings_path}")
    console.print(f"[bold]Repo:[/bold] {repo_path}\n")

    findings, scan_errors = parse_semgrep_output(findings_path, repo_path)
    total_parsed = len(findings)
    python_findings, non_python = _split_by_language(findings)

    console.print(
        f"[green]Parsed {total_parsed} findings"
        f" ({len(python_findings)} Python,"
        f" {len(non_python)} other-language)."
        f" {len(scan_errors)} scan errors.[/green]"
    )

    if limit is not None and len(python_findings) > limit:
        console.print(
            f"[dim]Limiting to first {limit} of {len(python_findings)} Python findings.[/dim]"
        )
        python_findings = python_findings[:limit]

    # ---- Phase 2: process findings concurrently -----------------------
    cache = VerdictCache() if use_cache else None
    client = LLMClient()
    triaged: list[TriagedFinding] = []

    # Non-Python findings are auto-routed to needs_human_review
    for f in non_python:
        triaged.append(_synthesize_unsupported_language(f))

    if python_findings:
        triaged.extend(
            _process_concurrently(
                python_findings,
                repo_path=repo_path,
                client=client,
                cache=cache,
                console=console,
            )
        )

    # ---- Phase 3: assemble report --------------------------------------
    duration = time.monotonic() - run_started
    return _build_report(
        triaged,
        findings_path=findings_path,
        repo_path=repo_path,
        scan_errors=scan_errors,
        client_model=client.model,
        duration_seconds=duration,
    )


# ---------------------------------------------------------------------------
# Phase 2: per-finding processing
# ---------------------------------------------------------------------------


def _process_concurrently(
    findings: list[Finding],
    *,
    repo_path: Path,
    client: LLMClient,
    cache: VerdictCache | None,
    console: Console,
) -> list[TriagedFinding]:
    """Process a list of findings using a thread pool. Returns results
    in the same order as input."""
    results: list[TriagedFinding | None] = [None] * len(findings)

    progress = Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        MofNCompleteColumn(),
        TimeElapsedColumn(),
        console=console,
    )

    with progress:
        task_id = progress.add_task("Triaging...", total=len(findings))

        with ThreadPoolExecutor(max_workers=MAX_CONCURRENT_LLM_CALLS) as pool:
            future_to_index = {
                pool.submit(_process_one, f, repo_path, client, cache): i
                for i, f in enumerate(findings)
            }
            for future in as_completed(future_to_index):
                i = future_to_index[future]
                try:
                    results[i] = future.result()
                except Exception as e:
                    # Belt-and-suspenders: _process_one already catches its own
                    # exceptions. If something gets out anyway, synthesize a
                    # safe fallback rather than crashing the run.
                    results[i] = _synthesize_crash_fallback(findings[i], e)
                progress.advance(task_id)

    # mypy/pyright happiness: filter out the Nones that shouldn't exist
    return [r for r in results if r is not None]


def _process_one(
    finding: Finding,
    repo_path: Path,
    client: LLMClient,
    cache: VerdictCache | None,
) -> TriagedFinding:
    """Process a single finding end-to-end. Always returns a TriagedFinding."""
    try:
        context = extract_context(finding, repo_path)
    except Exception as e:
        return _synthesize_extraction_failure(finding, e)

    fingerprint = compute_fingerprint(
        prompt_version=PROMPT_VERSION,
        rule_id=finding.rule_id,
        file_path=finding.file_path,
        matched_code=finding.matched_code,
        containing_function_source=context.containing_function_source,
    )

    # Cache lookup
    if cache is not None:
        cached = cache.get(fingerprint)
        if cached is not None:
            cached.from_cache = True
            return cached

    # Short-circuit: if extraction yielded nothing useful, skip the LLM
    if _is_extraction_too_degraded(context):
        return _synthesize_degraded_extraction(finding, context, fingerprint)

    # LLM call
    try:
        result = client.triage_finding(finding, context)
    except Exception as e:
        return _synthesize_crash_fallback(finding, e, context=context, fingerprint=fingerprint)

    # If the LLM client had to synthesize a verdict (API error, malformed
    # output, etc.), skip verification — there's nothing to verify, and
    # the synthesized reasoning may contain Pydantic error fragments that
    # would trigger the grounding verifier as false-positive flags.
    if result.synthesized_reason:
        return TriagedFinding(
            finding=finding,
            context=context,
            verdict=result.verdict,
            fingerprint=fingerprint,
            from_cache=False,
            verification_passed=True,
            verification_notes=[
                f"LLM call did not produce a usable verdict: {result.synthesized_reason}"
            ],
            llm_call_duration_seconds=result.duration_seconds,
            input_tokens=result.input_tokens,
            output_tokens=result.output_tokens,
        )

    # Verifiers (always run, never raise).
    #
    # Hard fail (quote_issues): downgrade verdict to needs_human_review.
    # Fabricated quotes are unambiguous — if the LLM cited code that doesn't
    # exist, the verdict is built on a fabrication and we don't trust it.
    #
    # Soft warning (grounding_issues): surface to user but don't downgrade.
    # The grounding check produces a lot of false alarms (generic English
    # words, framework class names from training, reasoning by contrast).
    # In practice it catches few real hallucinations, so we make its output
    # advisory rather than authoritative. The user reads the warning and
    # interprets the verdict accordingly.
    quote_issues = verify_evidence_quotes(result.verdict, finding, context)
    grounding_issues = verify_grounding(result.verdict, finding, context)

    if quote_issues:
        # Hard fail: downgrade. Only meaningful if the verdict was more
        # confident than needs_human_review.
        if result.verdict.verdict == VerdictLabel.NEEDS_HUMAN_REVIEW:
            verdict = result.verdict
            original_label = None
        else:
            verdict, original_label = _downgrade_for_verification_failure(
                result.verdict, quote_issues
            )
        verification_passed = False
        verification_notes = quote_issues
    else:
        verdict = result.verdict
        original_label = None
        verification_passed = True
        verification_notes = []

    # Grounding issues are always advisory: they go in advisory_warnings
    # regardless of whether the verdict was downgraded. They never affect
    # verification_passed or the verdict itself.
    advisory_warnings = grounding_issues

    triaged = TriagedFinding(
        finding=finding,
        context=context,
        verdict=verdict,
        fingerprint=fingerprint,
        from_cache=False,
        verification_passed=verification_passed,
        verification_notes=verification_notes,
        advisory_warnings=advisory_warnings,
        original_verdict=original_label,
        llm_call_duration_seconds=result.duration_seconds,
        input_tokens=result.input_tokens,
        output_tokens=result.output_tokens,
    )

    # Persist to cache for future runs. Cache is a nice-to-have — if disk
    # is full or permissions are wrong, we still have a valid verdict to return.
    if cache is not None:
        with suppress(OSError):
            cache.put(triaged)
    return triaged


def _is_extraction_too_degraded(context: CodeContext) -> bool:
    """True if context lacks anything for the LLM to reason about.

    No containing function AND no called functions usually means we
    couldn't read the file or it was a module-level match in a file we
    couldn't parse. Sending only a code snippet wastes tokens for a
    guaranteed needs_human_review.
    """
    if context.containing_function_source:
        return False
    if context.called_functions:
        return False
    # Module-level matches WITH imports are still worth sending — the
    # LLM can sometimes reason about them. We only short-circuit when
    # we have essentially nothing.
    return not context.imports


def _downgrade_for_verification_failure(
    verdict: Verdict, notes: list[str]
) -> tuple[Verdict, VerdictLabel]:
    """Convert a verdict that failed verification into needs_human_review.

    Returns the new verdict and the original label so the report can
    show 'LLM said X but we downgraded to Y because Z'.
    """
    original_label = verdict.verdict
    downgraded = verdict.model_copy(
        update={
            "verdict": VerdictLabel.NEEDS_HUMAN_REVIEW,
            "confidence": Confidence.LOW,
            "fp_categories": [],
        }
    )
    return downgraded, original_label


# ---------------------------------------------------------------------------
# Synthesized fallbacks — used when something goes wrong but we still need
# a TriagedFinding to keep the pipeline running.
# ---------------------------------------------------------------------------


def _synthesize_unsupported_language(finding: Finding) -> TriagedFinding:
    context = CodeContext(
        language="unsupported",
        matched_code_with_lines=finding.matched_code,
        extraction_notes=[f"Language not yet supported (file: {finding.file_path})."],
    )
    return _synthesize_review_triaged(
        finding=finding,
        context=context,
        reason=(f"v0.1 supports Python files only; {finding.file_path} requires manual review."),
        action="Review manually. Multi-language support is planned for v0.2.",
    )


def _synthesize_degraded_extraction(
    finding: Finding,
    context: CodeContext,
    fingerprint: str,
) -> TriagedFinding:
    return _synthesize_review_triaged(
        finding=finding,
        context=context,
        reason=(
            "Could not extract enough context (no containing function or "
            "called functions) to send to the LLM."
        ),
        action="Review manually; the file may be unreadable or use an unusual structure.",
        fingerprint=fingerprint,
    )


def _synthesize_extraction_failure(finding: Finding, error: Exception) -> TriagedFinding:
    context = CodeContext(
        language="python",
        matched_code_with_lines=finding.matched_code,
        extraction_notes=[
            f"Extractor crashed: {type(error).__name__}: {error}",
        ],
    )
    return _synthesize_review_triaged(
        finding=finding,
        context=context,
        reason=f"Extractor crashed before LLM call: {type(error).__name__}",
        action="File a bug report with the rule_id and file_path.",
    )


def _synthesize_crash_fallback(
    finding: Finding,
    error: Exception,
    *,
    context: CodeContext | None = None,
    fingerprint: str | None = None,
) -> TriagedFinding:
    if context is None:
        context = CodeContext(
            language="python",
            matched_code_with_lines=finding.matched_code,
            extraction_notes=["Pipeline crashed before context extraction."],
        )
    tb = traceback.format_exception_only(type(error), error)[-1].strip()
    return _synthesize_review_triaged(
        finding=finding,
        context=context,
        reason=f"Pipeline error: {tb}",
        action="Re-run with --no-cache, or file a bug report if reproducible.",
        fingerprint=fingerprint,
    )


def _synthesize_review_triaged(
    *,
    finding: Finding,
    context: CodeContext,
    reason: str,
    action: str,
    fingerprint: str | None = None,
) -> TriagedFinding:
    """Build a TriagedFinding routed to needs_human_review with given reason."""
    if fingerprint is None:
        fingerprint = compute_fingerprint(
            prompt_version=PROMPT_VERSION,
            rule_id=finding.rule_id,
            file_path=finding.file_path,
            matched_code=finding.matched_code,
            containing_function_source=context.containing_function_source,
        )
    verdict = Verdict(
        verdict=VerdictLabel.NEEDS_HUMAN_REVIEW,
        confidence=Confidence.LOW,
        reasoning=reason,
        evidence_quotes=[],
        missing_context=["Verdict synthesized; LLM was not called."],
        fp_categories=[],
        suggested_action=action,
    )
    return TriagedFinding(
        finding=finding,
        context=context,
        verdict=verdict,
        fingerprint=fingerprint,
        from_cache=False,
        verification_passed=True,  # nothing to verify; not a failure
        verification_notes=[],
    )


# ---------------------------------------------------------------------------
# Phase 3: report assembly
# ---------------------------------------------------------------------------


def _build_report(
    triaged: list[TriagedFinding],
    *,
    findings_path: Path,
    repo_path: Path,
    scan_errors: list[str],
    client_model: str,
    duration_seconds: float,
) -> Report:
    """Aggregate per-finding results into a Report."""
    counts = {label: 0 for label in VerdictLabel}
    input_tokens = 0
    output_tokens = 0
    cache_hits = 0
    cache_misses = 0
    by_rule: dict[str, list[TriagedFinding]] = defaultdict(list)

    for t in triaged:
        counts[t.verdict.verdict] += 1
        if t.input_tokens:
            input_tokens += t.input_tokens
        if t.output_tokens:
            output_tokens += t.output_tokens
        if t.from_cache:
            cache_hits += 1
        elif t.input_tokens:
            # Only count as a real miss if we actually called the LLM
            # (synthesized fallbacks have no token usage)
            cache_misses += 1
        by_rule[t.finding.rule_id].append(t)

    rule_stats = _compute_rule_stats(by_rule)
    noisy_rules = [
        s.rule_id
        for s in rule_stats
        if s.total >= NOISY_RULE_MIN_FINDINGS and s.fp_rate >= NOISY_RULE_MIN_FP_RATE
    ]

    return Report(
        generated_at=datetime.utcnow(),
        sg_triage_version=__version__,
        prompt_version=PROMPT_VERSION,
        model=client_model or DEFAULT_MODEL,
        repo_path=str(repo_path),
        semgrep_findings_path=str(findings_path),
        triaged_findings=triaged,
        total_findings=len(triaged),
        false_positive_count=counts[VerdictLabel.FALSE_POSITIVE],
        likely_true_positive_count=counts[VerdictLabel.LIKELY_TRUE_POSITIVE],
        needs_human_review_count=counts[VerdictLabel.NEEDS_HUMAN_REVIEW],
        rule_stats=rule_stats,
        rules_to_consider_tuning=noisy_rules,
        total_input_tokens=input_tokens,
        total_output_tokens=output_tokens,
        total_duration_seconds=duration_seconds,
        cache_hits=cache_hits,
        cache_misses=cache_misses,
        semgrep_parse_errors=scan_errors,
    )


def _compute_rule_stats(
    by_rule: dict[str, list[TriagedFinding]],
) -> list[RuleStats]:
    """Per-rule aggregate stats, sorted by FP rate descending."""
    stats: list[RuleStats] = []
    for rule_id, items in by_rule.items():
        total = len(items)
        fp = sum(1 for t in items if t.verdict.verdict == VerdictLabel.FALSE_POSITIVE)
        ltp = sum(1 for t in items if t.verdict.verdict == VerdictLabel.LIKELY_TRUE_POSITIVE)
        review = sum(1 for t in items if t.verdict.verdict == VerdictLabel.NEEDS_HUMAN_REVIEW)
        stats.append(
            RuleStats(
                rule_id=rule_id,
                total=total,
                false_positive=fp,
                likely_true_positive=ltp,
                needs_human_review=review,
                fp_rate=fp / total if total else 0.0,
            )
        )
    stats.sort(key=lambda s: (-s.fp_rate, -s.total, s.rule_id))
    return stats


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _split_by_language(
    findings: list[Finding],
) -> tuple[list[Finding], list[Finding]]:
    """Separate Python findings from other-language findings."""
    python: list[Finding] = []
    other: list[Finding] = []
    for f in findings:
        if f.file_path.endswith(".py"):
            python.append(f)
        else:
            other.append(f)
    return python, other


# Suppress an unused-import warning for Severity (used implicitly through
# Finding objects; kept here so the orchestrator's imports document its
# domain surface).
_ = Severity
