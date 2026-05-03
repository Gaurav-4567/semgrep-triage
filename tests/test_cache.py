"""Tests for the verdict cache and fingerprint computation."""

import json
from pathlib import Path

from sg_triage.cache import VerdictCache, compute_fingerprint
from sg_triage.schema import (
    CodeContext,
    Confidence,
    Finding,
    Severity,
    TriagedFinding,
    Verdict,
    VerdictLabel,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _finding(rule_id: str = "test.rule", file_path: str = "src/app.py") -> Finding:
    return Finding(
        rule_id=rule_id,
        file_path=file_path,
        start_line=10,
        end_line=10,
        message="test",
        severity=Severity.WARNING,
        matched_code="    eval(user_input)",
    )


def _context() -> CodeContext:
    return CodeContext(
        language="python",
        matched_code_with_lines="10 |     eval(user_input)",
        containing_function_name="process_data",
        containing_function_source=(
            "def process_data(data):\n    user_input = data\n    eval(user_input)"
        ),
    )


def _triaged(fingerprint: str) -> TriagedFinding:
    return TriagedFinding(
        finding=_finding(),
        context=_context(),
        verdict=Verdict(
            verdict=VerdictLabel.LIKELY_TRUE_POSITIVE,
            confidence=Confidence.MEDIUM,
            reasoning="Eval on user input.",
            evidence_quotes=[],
            missing_context=[],
            fp_categories=[],
            suggested_action="Replace eval.",
        ),
        fingerprint=fingerprint,
    )


# ---------------------------------------------------------------------------
# compute_fingerprint
# ---------------------------------------------------------------------------


def test_fingerprint_is_stable_for_same_inputs():
    fp1 = compute_fingerprint(
        prompt_version="0.1.0",
        rule_id="test.rule",
        file_path="src/app.py",
        matched_code="eval(x)",
        containing_function_source="def f(): eval(x)",
    )
    fp2 = compute_fingerprint(
        prompt_version="0.1.0",
        rule_id="test.rule",
        file_path="src/app.py",
        matched_code="eval(x)",
        containing_function_source="def f(): eval(x)",
    )
    assert fp1 == fp2
    assert len(fp1) == 16


def test_fingerprint_changes_when_rule_id_changes():
    common = dict(
        prompt_version="0.1.0",
        file_path="src/app.py",
        matched_code="eval(x)",
        containing_function_source="def f(): eval(x)",
    )
    fp1 = compute_fingerprint(rule_id="rule.a", **common)
    fp2 = compute_fingerprint(rule_id="rule.b", **common)
    assert fp1 != fp2


def test_fingerprint_changes_when_containing_function_changes():
    # Catches the dangerous case: code edited around the matched line
    common = dict(
        prompt_version="0.1.0",
        rule_id="test.rule",
        file_path="src/app.py",
        matched_code="eval(x)",
    )
    fp1 = compute_fingerprint(containing_function_source="def f(): eval(x)", **common)
    fp2 = compute_fingerprint(containing_function_source="def f(): sanitize(x); eval(x)", **common)
    assert fp1 != fp2


def test_fingerprint_stable_under_whitespace_only_changes():
    common = dict(
        prompt_version="0.1.0",
        rule_id="test.rule",
        file_path="src/app.py",
        matched_code="eval(x)",
    )
    fp1 = compute_fingerprint(containing_function_source="def f():\n    eval(x)", **common)
    fp2 = compute_fingerprint(containing_function_source="def f():\n\teval(x)", **common)
    assert fp1 == fp2  # tab vs spaces shouldn't matter


def test_fingerprint_changes_when_prompt_version_changes():
    # Critical: bumping prompt_version must invalidate all old cache entries
    common = dict(
        rule_id="test.rule",
        file_path="src/app.py",
        matched_code="eval(x)",
        containing_function_source="def f(): eval(x)",
    )
    fp1 = compute_fingerprint(prompt_version="0.1.0", **common)
    fp2 = compute_fingerprint(prompt_version="0.2.0", **common)
    assert fp1 != fp2


def test_fingerprint_handles_none_containing_function():
    # Module-level matches have no containing function — must not crash
    fp = compute_fingerprint(
        prompt_version="0.1.0",
        rule_id="test.rule",
        file_path="src/app.py",
        matched_code="import x",
        containing_function_source=None,
    )
    assert len(fp) == 16


# ---------------------------------------------------------------------------
# VerdictCache
# ---------------------------------------------------------------------------


def test_cache_miss_returns_none(tmp_path: Path):
    cache = VerdictCache(cache_dir=tmp_path)
    assert cache.get("nonexistent_fingerprint") is None


def test_cache_roundtrip(tmp_path: Path):
    cache = VerdictCache(cache_dir=tmp_path)
    original = _triaged(fingerprint="abc123def456")
    cache.put(original)

    loaded = cache.get("abc123def456")
    assert loaded is not None
    assert loaded.fingerprint == "abc123def456"
    assert loaded.verdict.verdict == VerdictLabel.LIKELY_TRUE_POSITIVE
    assert loaded.from_cache is False  # stored value is always False


def test_cache_creates_directory_on_first_write(tmp_path: Path):
    cache_dir = tmp_path / "cache_subdir"
    assert not cache_dir.exists()

    cache = VerdictCache(cache_dir=cache_dir)
    cache.put(_triaged(fingerprint="abcdef0123456789"))

    assert cache_dir.exists()
    assert (cache_dir / "abcdef0123456789.json").exists()


def test_cache_corrupt_file_returns_none(tmp_path: Path):
    cache = VerdictCache(cache_dir=tmp_path)
    bad_file = tmp_path / "corrupt_fingerprint.json"
    bad_file.write_text("this is not json", encoding="utf-8")

    assert cache.get("corrupt_fingerprint") is None


def test_cache_schema_mismatch_returns_none(tmp_path: Path):
    # Simulates an old cache entry from a previous schema version
    cache = VerdictCache(cache_dir=tmp_path)
    bad_file = tmp_path / "outdated_fingerprint.json"
    bad_file.write_text(json.dumps({"verdict": "old_format"}), encoding="utf-8")

    assert cache.get("outdated_fingerprint") is None


def test_cache_strips_from_cache_flag_on_write(tmp_path: Path):
    cache = VerdictCache(cache_dir=tmp_path)
    triaged = _triaged(fingerprint="0123456789abcdef")
    triaged.from_cache = True  # caller might pass this; we should ignore it
    cache.put(triaged)

    on_disk = json.loads((tmp_path / "0123456789abcdef.json").read_text())
    assert on_disk["from_cache"] is False
