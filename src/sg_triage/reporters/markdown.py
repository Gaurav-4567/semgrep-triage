"""Markdown reporter — human-readable report for sharing in PRs and chat."""

from pathlib import Path

from sg_triage.schema import (
    Report,
    Severity,
    TriagedFinding,
    VerdictLabel,
)

_VERDICT_LABEL = {
    VerdictLabel.LIKELY_TRUE_POSITIVE: "🚨 Likely true positive",
    VerdictLabel.NEEDS_HUMAN_REVIEW: "⚠️ Needs human review",
    VerdictLabel.FALSE_POSITIVE: "✅ False positive",
}

_VERDICT_ORDER = {
    VerdictLabel.LIKELY_TRUE_POSITIVE: 0,
    VerdictLabel.NEEDS_HUMAN_REVIEW: 1,
    VerdictLabel.FALSE_POSITIVE: 2,
}

_SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.ERROR: 1,
    Severity.WARNING: 2,
    Severity.INFO: 3,
}

_INPUT_COST_PER_MTOK = 3.0
_OUTPUT_COST_PER_MTOK = 15.0


def write(report: Report, path: Path) -> None:
    """Write the report as Markdown."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(_render(report), encoding="utf-8")


def _render(report: Report) -> str:
    parts = [
        _render_header(report),
        _render_summary(report),
        _render_findings(report),
        _render_rule_stats(report),
        _render_footer(report),
    ]
    return "\n\n".join(p for p in parts if p)


# ---------------------------------------------------------------------------
# Sections
# ---------------------------------------------------------------------------


def _render_header(report: Report) -> str:
    return f"# sg-triage report\n\n_Generated {report.generated_at:%Y-%m-%d %H:%M UTC}_"


def _render_summary(report: Report) -> str:
    cost = _estimate_cost(report)
    cache_total = report.cache_hits + report.cache_misses
    cache_pct = f" ({report.cache_hits * 100 // cache_total}% hit rate)" if cache_total else ""

    return (
        "## Summary\n\n"
        f"| Metric | Value |\n"
        f"|---|---|\n"
        f"| Total findings | {report.total_findings} |\n"
        f"| Likely true positive | {report.likely_true_positive_count} |\n"
        f"| Needs human review | {report.needs_human_review_count} |\n"
        f"| False positive | {report.false_positive_count} |\n"
        f"| Estimated cost | ~${cost:.3f} |\n"
        f"| Tokens (in / out) | {report.total_input_tokens} / {report.total_output_tokens} |\n"
        f"| Duration | {report.total_duration_seconds:.1f}s |\n"
        f"| Cache | {report.cache_hits} hits, {report.cache_misses} misses{cache_pct} |\n"
        f"| Model | `{report.model}` |\n"
        f"| Prompt version | `{report.prompt_version}` |"
    )


def _render_findings(report: Report) -> str:
    if not report.triaged_findings:
        return ""

    sorted_findings = sorted(
        report.triaged_findings,
        key=lambda t: (
            _VERDICT_ORDER.get(t.verdict.verdict, 99),
            _SEVERITY_ORDER.get(t.finding.severity, 99),
            t.finding.rule_id,
        ),
    )

    sections = ["## Findings"]
    for idx, t in enumerate(sorted_findings, start=1):
        sections.append(_render_one_finding(idx, t))
    return "\n\n".join(sections)


def _render_one_finding(idx: int, t: TriagedFinding) -> str:
    label = _VERDICT_LABEL[t.verdict.verdict]
    cwe_part = f" — {t.finding.cwe[0]}" if t.finding.cwe else ""
    cache_marker = " _(from cache)_" if t.from_cache else ""

    parts = [
        f"### {idx}. {label} — `{t.finding.rule_id}`",
        f"**File:** `{t.finding.file_path}:{t.finding.start_line}`  ",
        f"**Severity:** {t.finding.severity.value}  "
        f"**Confidence:** {t.verdict.confidence.value}{cwe_part}{cache_marker}",
    ]

    if t.original_verdict is not None:
        parts.append(
            f"> ⚠️ LLM originally returned `{t.original_verdict.value}` — "
            "downgraded due to verification failure."
        )

    parts.append(f"**Reasoning:** {t.verdict.reasoning}")

    if t.verdict.evidence_quotes:
        parts.append("**Evidence from the code:**")
        for q in t.verdict.evidence_quotes:
            # Quote in a code block to preserve formatting
            quote_clean = q.strip().replace("```", "ʼʼʼ")
            parts.append(f"```\n{quote_clean}\n```")

    if t.verdict.missing_context:
        parts.append("**Missing context:**")
        for m in t.verdict.missing_context:
            parts.append(f"- {m}")

    if t.verdict.fp_categories:
        cats = ", ".join(f"`{c.value}`" for c in t.verdict.fp_categories)
        parts.append(f"**FP categories:** {cats}")

    if t.verification_notes:
        parts.append("**Verifier notes:**")
        for note in t.verification_notes:
            parts.append(f"- ⚠️ {note}")

    if t.advisory_warnings:
        parts.append("**Advisory note**")
        parts.append(
            "_The grounding check flagged tokens in the reasoning that don't "
            "appear in the visible code. This often means the LLM is reasoning "
            'by contrast (e.g. "unlike pickle.loads which would be vulnerable") '
            "or referencing framework knowledge from training. It can also "
            "indicate fabrication. Read the reasoning carefully._"
        )
        for warning in t.advisory_warnings:
            parts.append(f"- ℹ️ {warning}")

    parts.append(f"**Suggested action:** {t.verdict.suggested_action}")

    return "\n\n".join(parts)


def _render_rule_stats(report: Report) -> str:
    if not report.rule_stats:
        return ""

    rows = [
        "## Per-rule statistics",
        "",
        "| Rule | Total | FP | Likely TP | Review | FP rate |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    for s in report.rule_stats:
        rows.append(
            f"| `{s.rule_id}` | {s.total} | {s.false_positive} | "
            f"{s.likely_true_positive} | {s.needs_human_review} | "
            f"{int(s.fp_rate * 100)}% |"
        )

    if report.rules_to_consider_tuning:
        rows.append("")
        rows.append("**Rules with high false-positive rates that may be worth tuning:**")
        for rule in report.rules_to_consider_tuning:
            rows.append(f"- `{rule}`")

    return "\n".join(rows)


def _render_footer(report: Report) -> str:
    parts = [
        "---",
        f"_Triaged with [sg-triage](https://github.com/Gaurav-4567/semgrep-triage) "
        f"v{report.sg_triage_version}, prompt v{report.prompt_version}._",
    ]
    if report.semgrep_parse_errors:
        parts.append(
            f"_Semgrep had {len(report.semgrep_parse_errors)} parse errors "
            "during the scan (not counted as findings)._"
        )
    return "\n\n".join(parts)


def _estimate_cost(report: Report) -> float:
    return (
        report.total_input_tokens * _INPUT_COST_PER_MTOK / 1_000_000
        + report.total_output_tokens * _OUTPUT_COST_PER_MTOK / 1_000_000
    )
