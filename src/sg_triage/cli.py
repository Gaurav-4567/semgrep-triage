"""Click-based command-line interface."""

import click

from sg_triage import __version__


@click.group()
@click.version_option(__version__)
def main() -> None:
    """LLM-assisted false-positive triage for Semgrep findings."""
    pass


@main.command()
def triage() -> None:
    """Triage a Semgrep findings file. (not yet implemented)"""
    click.echo("Not yet implemented.")


if __name__ == "__main__":
    main()
