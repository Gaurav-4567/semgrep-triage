"""JSON reporter — structured output for programmatic consumption."""

from pathlib import Path

from sg_triage.schema import Report


def write(report: Report, path: Path) -> None:
    """Write the full Report as pretty-printed JSON.

    The output schema matches the Report Pydantic model in schema.py;
    that's the source of truth for consumers.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(report.model_dump_json(indent=2), encoding="utf-8")
