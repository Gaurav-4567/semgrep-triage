"""Rich-based terminal reporter.

Prints a per-finding panel for every triaged finding, sorted with the most
actionable items first (likely_true_positive → needs_human_review →
false_positive). Each panel shows the verdict, confidence, reasoning,
evidence quotes, and any verifier issues.

A summary block at the bottom shows aggregate counts, cost, cache stats,
and any rules flagged as noisy.
"""

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from sg_triage.schema import Report, Severity, TriagedFinding, VerdictLabel

# Hardcoded for v0.1 — prices may change. Update when adding new models.
# Sonnet 4.5 pricing per million tokens.
_INPUT_COST_PER_MTOK = 3.0
_OUTPUT_COST_PER_MTOK = 15.0

# Verdict ordering: most actionable first.
_VERDICT_ORDER = {
    VerdictLabel.LIKELY_TRUE_POSITIVE: 0,
    VerdictLabel.NEEDS_HUMAN_REVIEW: 1,
    VerdictLabel.FALSE_POSITIVE: 2,
}

# Severity ordering: most severe first.
_SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.ERROR: 1,
    Severity.WARNING: 2,
    Severity.INFO: 3,
}

# Visual style per verdict.
_VERDICT_STYLE = {
    VerdictLabel.LIKELY_TRUE_POSITIVE: "red",
    VerdictLabel.NEEDS_HUMAN_REVIEW: "yellow",
    VerdictLabel.FALSE_POSITIVE: "green",
}

_VERDICT_LABEL = {
    VerdictLabel.LIKELY_TRUE_POSITIVE: "LIKELY TRUE POSITIVE",
    VerdictLabel.NEEDS_HUMAN_REVIEW: "NEEDS HUMAN REVIEW",
    VerdictLabel.FALSE_POSITIVE: "FALSE POSITIVE",
}


def render(report: Report, console: Console | None = None) -> None:
    """Print the full report to the terminal."""
    console = console or Console()

    sorted_findings = _sort_findings(report.triaged_findings)

    if sorted_findings:
        console.print()
        console.print("[bold]Findings[/bold]")
        for idx, t in enumerate(sorted_findings, start=1):
            _render_finding_panel(idx, len(sorted_findings), t, console)

    _render_summary(report, console)


# ---------------------------------------------------------------------------
# Per-finding panel
# ---------------------------------------------------------------------------


def _render_finding_panel(idx: int, total: int, t: TriagedFinding, console: Console) -> None:
    verdict_label = t.verdict.verdict
    style = _VERDICT_STYLE[verdict_label]

    # Header line: verdict, position, rule, file
    header = Text()
    header.append(f"[{idx}/{total}] ", style="dim")
    header.append(f" {_VERDICT_LABEL[verdict_label]} ", style=f"bold white on {style}")
    header.append(f"  confidence: {t.verdict.confidence.value}\n", style="dim")
    header.append(f"{t.finding.rule_id}\n", style="bold cyan")
    header.append(
        f"{t.finding.file_path}:{t.finding.start_line}",
        style="dim",
    )
    if t.finding.cwe:
        header.append(f"  {t.finding.cwe[0]}", style="dim")
    if t.from_cache:
        header.append("  (from cache)", style="dim italic")

    # Body
    body = Text()

    # Original verdict if it was downgraded
    if t.original_verdict is not None:
        body.append("\n")
        body.append("LLM originally said: ", style="bold yellow")
        body.append(f"{t.original_verdict.value}", style="yellow")
        body.append(" — downgraded due to verification failure.\n", style="dim")

    # Reasoning
    body.append("\n")
    body.append("Reasoning\n", style="bold")
    body.append(t.verdict.reasoning + "\n")

    # Evidence quotes (if any)
    if t.verdict.evidence_quotes:
        body.append("\n")
        body.append("Evidence from the code\n", style="bold")
        for q in t.verdict.evidence_quotes:
            body.append("  > ", style="dim")
            body.append(f"{q}\n", style="white")

    # Missing context
    if t.verdict.missing_context:
        body.append("\n")
        body.append("Missing context\n", style="bold")
        for m in t.verdict.missing_context:
            body.append(f"  - {m}\n", style="dim")

    # FP categories
    if t.verdict.fp_categories:
        body.append("\n")
        body.append(
            "FP category: " + ", ".join(c.value for c in t.verdict.fp_categories) + "\n",
            style="dim",
        )

    # Verifier notes
    if t.verification_notes:
        body.append("\n")
        body.append("Verifier notes\n", style="bold yellow")
        for note in t.verification_notes:
            body.append(f"  ⚠ {note}\n", style="yellow")

    # Suggested action
    body.append("\n")
    body.append("Suggested action: ", style="bold")
    body.append(t.verdict.suggested_action + "\n")

    console.print(Panel(header + body, border_style=style, expand=True))


# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------


def _render_summary(report: Report, console: Console) -> None:
    console.print()
    console.print("=" * 70)
    console.print("[bold]Summary[/bold]")
    console.print("=" * 70)

    # Verdict counts
    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column(style="bold")
    table.add_column()
    table.add_row("Total findings", str(report.total_findings))
    table.add_row(
        "  Likely true positive",
        f"[red]{report.likely_true_positive_count}[/red]",
    )
    table.add_row(
        "  Needs human review",
        f"[yellow]{report.needs_human_review_count}[/yellow]",
    )
    table.add_row(
        "  False positive",
        f"[green]{report.false_positive_count}[/green]",
    )
    console.print(table)

    # Cost & cache
    cost = _estimate_cost(report)
    cache_total = report.cache_hits + report.cache_misses
    cache_summary = f"{report.cache_hits} hits, {report.cache_misses} misses" + (
        f" ({report.cache_hits * 100 // cache_total}% hit rate)" if cache_total else ""
    )
    console.print()
    console.print(
        f"[bold]Cost:[/bold]      ~${cost:.3f} "
        f"({report.total_input_tokens} in, "
        f"{report.total_output_tokens} out)"
    )
    console.print(f"[bold]Duration:[/bold]  {report.total_duration_seconds:.1f}s")
    console.print(f"[bold]Cache:[/bold]     {cache_summary}")
    console.print(f"[bold]Model:[/bold]     {report.model}")

    # Rules to consider tuning
    if report.rules_to_consider_tuning:
        console.print()
        console.print("[bold yellow]Rules to consider tuning[/bold yellow]")
        console.print("[dim]Rules with ≥5 findings and ≥80% false-positive rate.[/dim]")
        for rule_id in report.rules_to_consider_tuning:
            stats = next((s for s in report.rule_stats if s.rule_id == rule_id), None)
            if stats is None:
                continue
            console.print(
                f"  • {rule_id}  "
                f"[dim]({stats.false_positive}/{stats.total} FP, "
                f"{int(stats.fp_rate * 100)}%)[/dim]"
            )

    # Semgrep parse errors
    if report.semgrep_parse_errors:
        console.print()
        console.print(
            f"[dim]Semgrep had {len(report.semgrep_parse_errors)} "
            "parse errors during scan (these are not findings).[/dim]"
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _sort_findings(findings: list[TriagedFinding]) -> list[TriagedFinding]:
    """Sort by verdict actionability, then by severity (most severe first)."""
    return sorted(
        findings,
        key=lambda t: (
            _VERDICT_ORDER.get(t.verdict.verdict, 99),
            _SEVERITY_ORDER.get(t.finding.severity, 99),
            t.finding.rule_id,
        ),
    )


def _estimate_cost(report: Report) -> float:
    """Rough USD cost estimate based on Sonnet 4.5 pricing.

    Pricing may change; this is a back-of-envelope figure for UX purposes.
    Real billing comes from the Anthropic console.
    """
    input_cost = report.total_input_tokens * _INPUT_COST_PER_MTOK / 1_000_000
    output_cost = report.total_output_tokens * _OUTPUT_COST_PER_MTOK / 1_000_000
    return input_cost + output_cost
