"""Tests for the Semgrep parser using real Flask scan output."""

from pathlib import Path

import pytest

from sg_triage.parser import parse_semgrep_output
from sg_triage.schema import Severity


@pytest.fixture
def flask_findings_path() -> Path:
    """Path to the captured Flask Semgrep output. Update for your local path."""
    # Adjust this path to point to the findings.json you generated
    return Path("tests/fixtures/semgrep_outputs/flask_findings.json")


@pytest.fixture
def flask_repo_path() -> Path:
    """Path to your local Flask checkout. Update for your local path."""
    return Path("../flask")  # adjust to wherever you cloned Flask


def test_parses_flask_findings(flask_findings_path, flask_repo_path):
    if not flask_findings_path.exists():
        pytest.skip("Flask fixture not present")

    findings, scan_errors = parse_semgrep_output(flask_findings_path, flask_repo_path)

    # We saw 15 findings in the real scan
    assert len(findings) == 15

    # Spot checks
    eval_finding = next((f for f in findings if "eval-detected" in f.rule_id), None)
    assert eval_finding is not None
    assert eval_finding.severity == Severity.WARNING
    assert "CWE-95" in eval_finding.cwe[0]
    assert eval_finding.semgrep_confidence == "LOW"
    assert eval_finding.file_path == "src/flask/cli.py"  # forward slashes

    csrf_finding = next((f for f in findings if "django-no-csrf-token" in f.rule_id), None)
    assert csrf_finding is not None
    # CSRF rules return cwe as a string in Semgrep — verify we normalized
    assert isinstance(csrf_finding.cwe, list)
    assert len(csrf_finding.cwe) == 1
    # CSRF rule has no owasp metadata — verify we defaulted to empty list
    assert csrf_finding.owasp == []


def test_no_dataflow_traces_in_flask_scan(flask_findings_path, flask_repo_path):
    if not flask_findings_path.exists():
        pytest.skip("Flask fixture not present")
    findings, _ = parse_semgrep_output(flask_findings_path, flask_repo_path)
    # Flask scan had no taint-mode rules
    assert all(not f.has_dataflow_trace for f in findings)


def test_extracts_scan_errors(flask_findings_path, flask_repo_path):
    if not flask_findings_path.exists():
        pytest.skip("Flask fixture not present")
    _, scan_errors = parse_semgrep_output(flask_findings_path, flask_repo_path)
    # Flask scan had several template parse errors
    assert len(scan_errors) > 0
