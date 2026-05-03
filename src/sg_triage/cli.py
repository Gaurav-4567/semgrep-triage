"""Click-based command-line interface."""

from pathlib import Path

import click
from rich.console import Console

from sg_triage import __version__
from sg_triage.reporters import json_report, markdown, terminal
from sg_triage.triage import run_triage

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
    "--limit",
    type=int,
    default=None,
    help="Process only the first N Python findings. Useful for development.",
)
@click.option(
    "--no-cache",
    is_flag=True,
    default=False,
    help="Skip the verdict cache; force re-triage of every finding.",
)
@click.option(
    "--output-json",
    type=click.Path(dir_okay=False, path_type=Path),
    default=None,
    help="Write a structured JSON report to this path.",
)
@click.option(
    "--output-md",
    type=click.Path(dir_okay=False, path_type=Path),
    default=None,
    help="Write a Markdown report to this path.",
)
@click.option(
    "--quiet",
    is_flag=True,
    default=False,
    help="Suppress per-finding terminal output; show only the summary.",
)
def triage(
    findings_path: Path,
    repo_path: Path,
    limit: int | None,
    no_cache: bool,
    output_json: Path | None,
    output_md: Path | None,
    quiet: bool,
) -> None:
    """Triage Semgrep findings using LLM-assisted false-positive detection.

    FINDINGS_PATH is the path to a Semgrep JSON output file
    (typically generated with `semgrep --json -o findings.json .`).

    REPO_PATH is the root of the repository that was scanned.
    """
    report = run_triage(
        findings_path=findings_path,
        repo_path=repo_path,
        use_cache=not no_cache,
        limit=limit,
        console=console,
    )

    if quiet:
        # Summary only — skip the per-finding panels
        from sg_triage.reporters.terminal import _render_summary

        _render_summary(report, console)
    else:
        terminal.render(report, console=console)

    if output_json is not None:
        json_report.write(report, output_json)
        console.print(f"[dim]Wrote JSON report to {output_json}[/dim]")

    if output_md is not None:
        markdown.write(report, output_md)
        console.print(f"[dim]Wrote Markdown report to {output_md}[/dim]")


if __name__ == "__main__":
    main()
