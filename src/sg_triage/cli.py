"""Click-based command-line interface."""

from pathlib import Path

import click
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from sg_triage import __version__
from sg_triage.extractor.python_extractor import extract_context
from sg_triage.parser import SemgrepParseError, parse_semgrep_output
from sg_triage.schema import Finding

console = Console()


@click.group()
@click.version_option(__version__)
def main() -> None:
    """LLM-assisted false-positive triage for Semgrep findings."""
    pass


@main.command()
@click.argument(
    "findings_path",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
)
@click.argument(
    "repo_path",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
)
@click.option(
    "--dry-run",
    is_flag=True,
    default=False,
    help="Extract and print context for each finding without calling the LLM.",
)
@click.option(
    "--limit",
    type=int,
    default=None,
    help="Process only the first N findings. Useful for development.",
)
def triage(
    findings_path: Path,
    repo_path: Path,
    dry_run: bool,
    limit: int | None,
) -> None:
    """Triage Semgrep findings using LLM-assisted false-positive detection."""
    if not dry_run:
        console.print("[yellow]LLM triage not yet implemented. Use --dry-run for now.[/yellow]")
        raise click.Abort()

    _run_dry_run(findings_path, repo_path, limit)


def _run_dry_run(findings_path: Path, repo_path: Path, limit: int | None) -> None:
    """Parse findings and print extracted context — no LLM calls."""
    console.print(f"[bold]Loading findings from:[/bold] {findings_path}")
    console.print(f"[bold]Repo path:[/bold] {repo_path}\n")

    try:
        findings, scan_errors = parse_semgrep_output(findings_path, repo_path)
    except SemgrepParseError as e:
        console.print(f"[red]Failed to parse Semgrep output:[/red] {e}")
        raise click.Abort() from e

    total = len(findings)
    console.print(f"[green]Parsed {total} findings. {len(scan_errors)} scan errors.[/green]\n")

    python_findings, skipped = _split_by_language(findings)

    if limit is not None and len(python_findings) > limit:
        console.print(
            f"[dim]Limiting to first {limit} of {len(python_findings)} Python findings.[/dim]\n"
        )
        python_findings = python_findings[:limit]
    if skipped:
        console.print(
            f"[yellow]Skipping {len(skipped)} non-Python findings "
            f"(language support coming in future versions).[/yellow]"
        )
        skipped_rules = sorted({f.rule_id for f in skipped})
        for rule in skipped_rules[:5]:
            console.print(f"  • {rule}")
        if len(skipped_rules) > 5:
            console.print(f"  • ... and {len(skipped_rules) - 5} more")
        console.print()

    if not python_findings:
        console.print("[yellow]No Python findings to process.[/yellow]")
        return

    for idx, finding in enumerate(python_findings, start=1):
        _print_finding_context(idx, len(python_findings), finding, repo_path)


def _split_by_language(
    findings: list[Finding],
) -> tuple[list[Finding], list[Finding]]:
    """Separate Python findings from other-language findings.

    Routing is by file extension. The orchestrator (later) will route
    non-Python findings to needs_human_review; here in dry-run we just skip.
    """
    python: list[Finding] = []
    other: list[Finding] = []
    for f in findings:
        if f.file_path.endswith(".py"):
            python.append(f)
        else:
            other.append(f)
    return python, other


def _print_finding_context(idx: int, total: int, finding: Finding, repo_path: Path) -> None:
    """Pretty-print one finding's extracted context to the terminal."""
    context = extract_context(finding, repo_path)

    header = Text()
    header.append(f"[{idx}/{total}] ", style="dim")
    header.append(f"{finding.rule_id}", style="bold cyan")
    header.append(f"  {finding.severity.value}\n", style="yellow")
    header.append(f"{finding.file_path}:{finding.start_line}", style="dim")
    if finding.cwe:
        header.append(f"  {finding.cwe[0]}", style="dim")

    body = Text()
    body.append("\nMessage: ", style="bold")
    body.append(f"{finding.message}\n")

    if context.imports:
        body.append("\nImports:\n", style="bold")
        body.append(context.imports + "\n", style="white")

    body.append("\nMatched code:\n", style="bold")
    body.append(context.matched_code_with_lines + "\n", style="white")

    if context.containing_function_source:
        body.append(
            f"\nContaining function: {context.containing_function_name}\n",
            style="bold",
        )
        body.append(context.containing_function_source + "\n", style="white")
    else:
        body.append("\nNo containing function (module-level match)\n", style="dim")

    if context.called_functions:
        body.append(
            f"\nCalled functions ({len(context.called_functions)}):\n",
            style="bold",
        )
        for cf in context.called_functions:
            body.append(
                f"  • {cf.name}  [{cf.resolution_method.value}, {cf.file_path}:{cf.start_line}]\n",
                style="green",
            )

    if context.extraction_notes:
        body.append("\nExtraction notes:\n", style="bold yellow")
        for note in context.extraction_notes:
            body.append(f"  • {note}\n", style="yellow")

    console.print(Panel(header + body, expand=False, border_style="blue"))


if __name__ == "__main__":
    main()
