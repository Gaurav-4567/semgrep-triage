"""Tests for the Python extractor."""

from pathlib import Path

from sg_triage.extractor.python_extractor import extract_context
from sg_triage.schema import Finding, Severity

FIXTURES = Path(__file__).parent / "fixtures" / "extractor"


def _make_finding(file_path: str, start_line: int, end_line: int, code: str) -> Finding:
    return Finding(
        rule_id="test.rule",
        file_path=file_path,
        start_line=start_line,
        end_line=end_line,
        message="test",
        severity=Severity.WARNING,
        matched_code=code,
    )


def test_extracts_top_level_function():
    finding = _make_finding("sample_module.py", 28, 28, "    eval(data)")
    ctx = extract_context(finding, FIXTURES)

    assert ctx.language == "python"
    assert ctx.containing_function_name == "top_level_function"
    assert "def top_level_function" in ctx.containing_function_source
    assert ctx.containing_function_start_line == 28


def test_extracts_method_in_class():
    # Line 18 is inside Service.fetch
    finding = _make_finding(
        "sample_module.py", 18, 18, "    response = requests.get(url, timeout=10)"
    )
    ctx = extract_context(finding, FIXTURES)

    assert ctx.containing_function_name == "fetch"
    assert "def fetch" in ctx.containing_function_source


def test_module_level_match_has_no_function():
    # Line 4 is an import — module level
    finding = _make_finding("sample_module.py", 4, 4, "import os")
    ctx = extract_context(finding, FIXTURES)

    assert ctx.containing_function_name is None
    assert ctx.containing_function_source is None
    assert any("module level" in note for note in ctx.extraction_notes)


def test_missing_file_records_note():
    finding = _make_finding("does_not_exist.py", 1, 1, "x = 1")
    ctx = extract_context(finding, FIXTURES)

    assert ctx.containing_function_name is None
    assert any("not found" in note.lower() for note in ctx.extraction_notes)


def test_matched_code_has_line_numbers():
    finding = _make_finding("sample_module.py", 28, 28, "    eval(data)")
    ctx = extract_context(finding, FIXTURES)

    assert "28 |" in ctx.matched_code_with_lines
