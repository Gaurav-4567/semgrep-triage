"""Parses Semgrep JSON output into internal Finding models.

Handles real-world quirks observed in Semgrep output:
- `extra.lines` may be redacted ("requires login") — we read code from disk instead
- `cwe` field is sometimes a string, sometimes a list — normalized to list
- `owasp` field may be missing entirely — defaults to empty list
- Path separators are platform-dependent — normalized to forward slashes
- Unknown severities map to WARNING with a parse note
- `errors` array contains scan-health info, returned separately from findings
"""

import json
from pathlib import Path
from typing import Any

from sg_triage.schema import Finding, Severity

# Map Semgrep severity strings to our enum. Anything not here -> WARNING + note.
_SEVERITY_MAP = {
    "INFO": Severity.INFO,
    "WARNING": Severity.WARNING,
    "ERROR": Severity.ERROR,
    "CRITICAL": Severity.CRITICAL,
}


class SemgrepParseError(Exception):
    """Raised when the Semgrep JSON file is structurally invalid."""


def parse_semgrep_output(
    findings_path: Path,
    repo_path: Path,
) -> tuple[list[Finding], list[str]]:
    """Parse a Semgrep JSON output file into Findings.

    Args:
        findings_path: Path to the Semgrep JSON output file.
        repo_path: Path to the repository that was scanned. Used to read
            actual matched code from disk (since `extra.lines` is often
            redacted by Semgrep when not logged in).

    Returns:
        A tuple of (findings, scan_errors) where:
            - findings: parsed Finding objects, one per Semgrep result
            - scan_errors: human-readable strings describing files Semgrep
              couldn't fully parse during the scan

    Raises:
        SemgrepParseError: if the JSON is malformed or missing required
            top-level fields.
        FileNotFoundError: if findings_path doesn't exist.
    """
    if not findings_path.exists():
        raise FileNotFoundError(f"Semgrep findings file not found: {findings_path}")

    try:
        raw = json.loads(findings_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        raise SemgrepParseError(f"Invalid JSON in {findings_path}: {e}") from e

    if not isinstance(raw, dict) or "results" not in raw:
        raise SemgrepParseError(
            f"Expected top-level 'results' key in {findings_path}; "
            f"got keys: {list(raw.keys()) if isinstance(raw, dict) else type(raw).__name__}"
        )

    findings: list[Finding] = []
    for idx, result in enumerate(raw["results"]):
        try:
            finding = _parse_one_result(result, repo_path)
            findings.append(finding)
        except (KeyError, ValueError, TypeError) as e:
            # Skip individual malformed findings rather than failing the whole run.
            # In v0.1 we log to stderr; in v0.2 we'd surface these in the report.
            print(
                f"Warning: skipping malformed finding at index {idx}: {e}",
                flush=True,
            )

    scan_errors = _extract_scan_errors(raw.get("errors", []))

    return findings, scan_errors


def _parse_one_result(result: dict[str, Any], repo_path: Path) -> Finding:
    """Parse a single entry from the Semgrep `results` array."""
    extra = result.get("extra", {})
    metadata = extra.get("metadata", {})

    # Required structural fields
    rule_id = result["check_id"]
    raw_path = result["path"]
    file_path = _normalize_path(raw_path)

    start = result["start"]
    end = result["end"]
    start_line = start["line"]
    end_line = end["line"]
    start_col = start.get("col")
    end_col = end.get("col")

    message = extra.get("message", "")

    # Severity: defensive mapping
    severity_raw = extra.get("severity", "WARNING")
    severity = _SEVERITY_MAP.get(severity_raw, Severity.WARNING)

    # CWE: normalize string-or-list to list
    cwe = _normalize_to_list(metadata.get("cwe"))
    owasp = _normalize_to_list(metadata.get("owasp"))

    # Matched code: extra.lines may be redacted; read from disk if so
    matched_code = _resolve_matched_code(
        extra.get("lines"),
        repo_path,
        file_path,
        start_line,
        end_line,
    )

    # Semgrep's own confidence in this rule firing
    semgrep_confidence = metadata.get("confidence")

    # Dataflow trace: not present in the audit-rule findings we have, but
    # handle defensively for taint-mode rules in real-world scans.
    dataflow = extra.get("dataflow_trace")
    has_dataflow_trace = dataflow is not None
    dataflow_trace_summary = _summarize_dataflow_trace(dataflow) if dataflow else None

    return Finding(
        rule_id=rule_id,
        file_path=file_path,
        start_line=start_line,
        end_line=end_line,
        start_col=start_col,
        end_col=end_col,
        message=message,
        severity=severity,
        cwe=cwe,
        owasp=owasp,
        matched_code=matched_code,
        semgrep_confidence=semgrep_confidence,
        has_dataflow_trace=has_dataflow_trace,
        dataflow_trace_summary=dataflow_trace_summary,
    )


def _normalize_path(raw: str) -> str:
    """Normalize Windows backslash paths to forward slashes for cross-platform consistency."""
    return raw.replace("\\", "/")


def _normalize_to_list(value: Any) -> list[str]:
    """Coerce a string-or-list-or-None metadata field to a list of strings."""
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [str(v) for v in value]
    return []


def _resolve_matched_code(
    extra_lines: Any,
    repo_path: Path,
    file_path: str,
    start_line: int,
    end_line: int,
) -> str:
    """Get the actual matched code, reading from disk if Semgrep redacted it.

    Semgrep's free tier often returns `extra.lines = "requires login"`. When
    that happens (or any other obviously-not-code value), read the lines from
    the file directly using the file path and line numbers.
    """
    if isinstance(extra_lines, str) and extra_lines and extra_lines != "requires login":
        return extra_lines

    # Read from disk
    full_path = repo_path / file_path
    try:
        text = full_path.read_text(encoding="utf-8", errors="replace")
    except (FileNotFoundError, OSError):
        return f"<could not read file: {file_path}>"

    lines = text.splitlines()
    # Convert 1-indexed inclusive range to 0-indexed slice
    selected = lines[start_line - 1 : end_line]
    return "\n".join(selected)


def _summarize_dataflow_trace(trace: dict[str, Any]) -> str:
    """Reduce Semgrep's nested dataflow trace structure to a human-readable string.

    v0.1: minimal summary. The full trace structure is nested and varies by
    rule; we just note the source and sink locations if available.
    """
    parts = []
    source = trace.get("taint_source")
    if source:
        parts.append(f"Source: {source}")
    sink = trace.get("taint_sink")
    if sink:
        parts.append(f"Sink: {sink}")
    intermediate = trace.get("intermediate_vars", [])
    if intermediate:
        parts.append(f"Intermediate steps: {len(intermediate)}")
    return " | ".join(parts) if parts else "Dataflow trace present (structure unrecognized)"


def _extract_scan_errors(errors: list[Any]) -> list[str]:
    """Extract human-readable summaries of scan errors (parse failures, etc.)."""
    summaries = []
    for err in errors:
        if not isinstance(err, dict):
            continue
        path = err.get("path", "<unknown>")
        msg = err.get("message", "Unknown error").split("\n")[0]
        summaries.append(f"{path}: {msg}")
    return summaries
