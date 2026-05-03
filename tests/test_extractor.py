"""Tests for the Python extractor."""

from pathlib import Path

from sg_triage.extractor.python_extractor import extract_context
from sg_triage.schema import Finding, ResolutionMethod, Severity

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


def _line_of(file_path: Path, needle: str) -> int:
    """Find the 1-indexed line number of the first line containing `needle`."""
    for i, line in enumerate(file_path.read_text().splitlines(), start=1):
        if needle in line:
            return i
    raise AssertionError(f"{needle!r} not found in {file_path}")


# ---- Stage 2: containing function ---------------------------------------


def test_extracts_top_level_function():
    line = _line_of(FIXTURES / "sample_module.py", "eval(data)")
    finding = _make_finding("sample_module.py", line, line, "    eval(data)")
    ctx = extract_context(finding, FIXTURES)

    assert ctx.language == "python"
    assert ctx.containing_function_name == "top_level_function"
    assert "def top_level_function" in ctx.containing_function_source


def test_extracts_method_in_class():
    line = _line_of(FIXTURES / "sample_module.py", "response = requests.get")
    finding = _make_finding(
        "sample_module.py", line, line, "    response = requests.get(url, timeout=10)"
    )
    ctx = extract_context(finding, FIXTURES)

    assert ctx.containing_function_name == "fetch"
    assert "def fetch" in ctx.containing_function_source


def test_module_level_match_has_no_function():
    line = _line_of(FIXTURES / "sample_module.py", "import os")
    finding = _make_finding("sample_module.py", line, line, "import os")
    ctx = extract_context(finding, FIXTURES)

    assert ctx.containing_function_name is None
    assert any("module level" in note for note in ctx.extraction_notes)


def test_missing_file_records_note():
    finding = _make_finding("does_not_exist.py", 1, 1, "x = 1")
    ctx = extract_context(finding, FIXTURES)

    assert any("not found" in note.lower() for note in ctx.extraction_notes)


def test_matched_code_has_line_numbers():
    line = _line_of(FIXTURES / "sample_module.py", "eval(data)")
    finding = _make_finding("sample_module.py", line, line, "    eval(data)")
    ctx = extract_context(finding, FIXTURES)

    assert f"{line} |" in ctx.matched_code_with_lines


# ---- Stage 3: imports ---------------------------------------------------


def test_extracts_imports():
    line = _line_of(FIXTURES / "sample_module.py", "eval(data)")
    finding = _make_finding("sample_module.py", line, line, "    eval(data)")
    ctx = extract_context(finding, FIXTURES)

    assert ctx.imports is not None
    assert "import os" in ctx.imports
    assert "from pathlib import Path" in ctx.imports
    assert "from security_utils import escape_html, validate_url" in ctx.imports


# ---- Stage 4: same-file call resolution ---------------------------------


def test_resolves_same_file_call():
    # `fetch_with_helper` calls `helper()` and `self.fetch()` — both same-file
    line = _line_of(FIXTURES / "sample_module.py", "return helper(result")
    finding = _make_finding(
        "sample_module.py", line, line, "        return helper(result['value'])"
    )
    ctx = extract_context(finding, FIXTURES)

    assert ctx.containing_function_name == "fetch_with_helper"
    names = {cf.name for cf in ctx.called_functions}
    assert "helper" in names
    assert "fetch" in names

    helper_cf = next(cf for cf in ctx.called_functions if cf.name == "helper")
    assert helper_cf.resolution_method == ResolutionMethod.SAME_FILE
    assert "def helper" in helper_cf.source


def test_skips_known_builtins():
    # eval is a builtin, should not appear in called_functions
    line = _line_of(FIXTURES / "sample_module.py", "eval(data)")
    finding = _make_finding("sample_module.py", line, line, "    eval(data)")
    ctx = extract_context(finding, FIXTURES)

    names = {cf.name for cf in ctx.called_functions}
    assert "eval" not in names


# ---- Stage 5: import-hop resolution -------------------------------------


def test_resolves_imported_function():
    # `render` calls `escape_html`, which is imported from security_utils
    line = _line_of(FIXTURES / "sample_module.py", "safe = escape_html")
    finding = _make_finding("sample_module.py", line, line, "    safe = escape_html(value)")
    ctx = extract_context(finding, FIXTURES)

    assert ctx.containing_function_name == "render"
    names = {cf.name for cf in ctx.called_functions}
    assert "escape_html" in names

    escape_cf = next(cf for cf in ctx.called_functions if cf.name == "escape_html")
    assert escape_cf.resolution_method == ResolutionMethod.SAME_MODULE_IMPORT
    assert escape_cf.file_path == "security_utils.py"
    assert "def escape_html" in escape_cf.source


# ---- Honesty: unresolved calls become notes ----------------------------


def test_unresolved_call_becomes_note():
    # `requests.get` — `requests` is imported but it's third-party, won't
    # resolve to a file. Should appear in extraction_notes.
    line = _line_of(FIXTURES / "sample_module.py", "response = requests.get")
    finding = _make_finding(
        "sample_module.py", line, line, "    response = requests.get(url, timeout=10)"
    )
    ctx = extract_context(finding, FIXTURES)

    # `get` isn't a top-level def in this repo, so it stays unresolved
    assert any("`get()` not resolved" in note for note in ctx.extraction_notes)
