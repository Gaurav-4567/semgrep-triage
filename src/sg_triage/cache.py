"""Per-finding verdict cache, keyed by stable content fingerprint.

Cache layout:
    ~/.sg-triage/cache/<fingerprint>.json

Each file contains a serialized TriagedFinding from a previous run. On a
re-run with the same fingerprint, the cached verdict is reused — no LLM
call, no cost.

Fingerprint design:
    SHA-256(prompt_version | rule_id | file_path | normalized_matched_code |
            normalized_containing_function), truncated to 16 hex chars.

Why each component:
    - prompt_version: invalidates the entire cache when the prompt changes
      between releases. Old verdicts from a different prompt would be wrong
      to reuse — different prompt produces different verdicts.
    - rule_id: same code line might be flagged by different rules; verdicts
      are rule-specific.
    - file_path: same code in two files might have different verdicts due
      to provenance (test_ vs production).
    - matched_code: the actual flagged lines.
    - containing_function: catches changes to surrounding logic. If a
      sanitizer is removed in the same function, fingerprint changes and
      we re-triage — preventing stale "false_positive" verdicts on now-
      vulnerable code.

Known limitation: changes to *callers* or *called functions* don't
invalidate the cache. If callee behavior changes, the cached verdict may
be stale. Users can pass --no-cache to force re-triage. v0.2 will likely
extend the fingerprint.
"""

import hashlib
import json
import re
from pathlib import Path

from pydantic import ValidationError

from sg_triage.schema import TriagedFinding

# Default cache root. Per-user, machine-local. Created on first write.
DEFAULT_CACHE_DIR = Path.home() / ".sg-triage" / "cache"


def compute_fingerprint(
    *,
    prompt_version: str,
    rule_id: str,
    file_path: str,
    matched_code: str,
    containing_function_source: str | None,
) -> str:
    """Compute the cache fingerprint for a finding.

    Whitespace is normalized in code components so that pure-formatting
    edits (tabs vs spaces, trailing whitespace) don't invalidate the cache.
    """
    normalized_match = _normalize(matched_code)
    normalized_func = _normalize(containing_function_source or "")
    key = "|".join(
        [
            prompt_version,
            rule_id,
            file_path,
            normalized_match,
            normalized_func,
        ]
    )
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]


class VerdictCache:
    """File-backed cache of TriagedFindings keyed by fingerprint.

    Intentionally simple: one JSON file per fingerprint, no index, no
    locking. File operations are atomic enough for our use case (single
    process writing to its own ~/.sg-triage/cache/).
    """

    def __init__(self, cache_dir: Path | None = None):
        self.cache_dir = cache_dir or DEFAULT_CACHE_DIR

    def get(self, fingerprint: str) -> TriagedFinding | None:
        """Return the cached TriagedFinding for a fingerprint, or None.

        Returns None on any failure (missing file, malformed JSON, schema
        change). Failing silently here is correct: a cache miss just means
        we re-triage, which is always safe.
        """
        path = self._path_for(fingerprint)
        if not path.exists():
            return None
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
            return TriagedFinding.model_validate(raw)
        except (json.JSONDecodeError, ValidationError, OSError):
            # Corrupt or schema-incompatible cache entry. Treat as miss.
            return None

    def put(self, triaged: TriagedFinding) -> None:
        """Write a TriagedFinding to the cache.

        Strips any cache-status flags before writing — the cache stores the
        verdict as if it were freshly produced.
        """
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        path = self._path_for(triaged.fingerprint)

        # Reset cache-status flags before persisting. When we read this
        # back, the orchestrator sets from_cache=True itself.
        to_store = triaged.model_copy(update={"from_cache": False})

        # Atomic write: temp file + rename, so a crashed write doesn't
        # leave a partial JSON file in place.
        tmp_path = path.with_suffix(".json.tmp")
        tmp_path.write_text(
            to_store.model_dump_json(indent=2),
            encoding="utf-8",
        )
        tmp_path.replace(path)

    def _path_for(self, fingerprint: str) -> Path:
        return self.cache_dir / f"{fingerprint}.json"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_WHITESPACE_RUN = re.compile(r"\s+")


def _normalize(text: str) -> str:
    """Collapse whitespace runs to single spaces and strip ends.

    Same algorithm as the verifier's whitespace normalization, deliberately,
    so the cache and the verifier agree on what counts as 'the same code.'
    """
    return _WHITESPACE_RUN.sub(" ", text).strip()
