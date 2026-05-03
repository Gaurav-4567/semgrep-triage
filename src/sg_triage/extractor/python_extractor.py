"""Tree-sitter-based code context extraction for Python files.

Given a finding's location (file path + line range), extract surrounding code
context to send to the LLM: the enclosing function, file imports, and one-hop
call resolution. Honest about what it cannot extract — gaps are recorded in
extraction_notes and surfaced to the LLM as missing_context.
"""

from pathlib import Path

import tree_sitter_python
from tree_sitter import Language, Node, Parser

from sg_triage.schema import CodeContext, Finding

# Initialize the parser once at module load.
# tree-sitter parsers are stateless and reusable across files.
_PY_LANGUAGE = Language(tree_sitter_python.language())
_PYTHON_PARSER: Parser = Parser(_PY_LANGUAGE)


# Maximum file size we'll attempt to parse. Beyond this, skip extraction.
_MAX_FILE_BYTES = 2 * 1024 * 1024  # 2 MB


def extract_context(finding: Finding, repo_path: Path) -> CodeContext:
    """Extract code context for a Python finding.

    Args:
        finding: The Semgrep finding to extract context for.
        repo_path: Repository root, used to resolve the finding's file_path.

    Returns:
        CodeContext with whatever could be extracted. Missing pieces are
        recorded in `extraction_notes`.
    """
    notes: list[str] = []
    full_path = repo_path / finding.file_path

    # Always present: matched code with line numbers
    matched_code_with_lines = _format_with_line_numbers(finding.matched_code, finding.start_line)

    # Try to read and parse the file
    source = _read_source(full_path, notes)
    if source is None:
        return CodeContext(
            language="python",
            matched_code_with_lines=matched_code_with_lines,
            extraction_notes=notes,
        )

    tree = _PYTHON_PARSER.parse(source)
    root = tree.root_node

    if root.has_error:
        notes.append(
            "File contains syntax errors; extraction is best-effort and may be incomplete."
        )

    # Extract containing function
    containing_func_node = _find_containing_function(root, finding.start_line, finding.end_line)

    if containing_func_node is None:
        notes.append(
            "Match is at module level (not inside any function or method); "
            "function context unavailable."
        )
        containing_function_name = None
        containing_function_source = None
        containing_function_start_line = None
    else:
        containing_function_name = _get_function_name(containing_func_node, source)
        containing_function_source = _format_node_with_line_numbers(containing_func_node, source)
        containing_function_start_line = containing_func_node.start_point[0] + 1

    return CodeContext(
        language="python",
        matched_code_with_lines=matched_code_with_lines,
        containing_function_name=containing_function_name,
        containing_function_source=containing_function_source,
        containing_function_start_line=containing_function_start_line,
        extraction_notes=notes,
    )


# ---------------------------------------------------------------------------
# Source loading
# ---------------------------------------------------------------------------


def _read_source(path: Path, notes: list[str]) -> bytes | None:
    """Read source file as bytes (tree-sitter wants bytes). Returns None on failure."""
    if not path.exists():
        notes.append(f"Source file not found: {path}")
        return None
    try:
        size = path.stat().st_size
    except OSError as e:
        notes.append(f"Could not stat source file: {e}")
        return None
    if size > _MAX_FILE_BYTES:
        notes.append(f"File too large to parse ({size} bytes); skipping AST-based extraction.")
        return None
    try:
        return path.read_bytes()
    except OSError as e:
        notes.append(f"Could not read source file: {e}")
        return None


# ---------------------------------------------------------------------------
# Containing function lookup
# ---------------------------------------------------------------------------


def _find_containing_function(root: Node, start_line: int, end_line: int) -> Node | None:
    """Find the innermost function_definition node containing the given line range.

    Tree-sitter line numbers are 0-indexed; Semgrep's are 1-indexed. We convert.

    "Innermost" matters for nested functions — we want the closest enclosing one,
    not the outermost. We handle nesting by tracking depth during the walk.
    """
    target_start = start_line - 1
    target_end = end_line - 1

    best: Node | None = None
    best_depth = -1

    def walk(node: Node, depth: int) -> None:
        nonlocal best, best_depth
        if node.type == "function_definition":
            ns, ne = node.start_point[0], node.end_point[0]
            if ns <= target_start and ne >= target_end and depth > best_depth:
                best = node
                best_depth = depth
        for child in node.children:
            walk(child, depth + 1)

    walk(root, 0)
    return best


def _get_function_name(func_node: Node, source: bytes) -> str:
    """Extract the function name from a function_definition node."""
    name_node = func_node.child_by_field_name("name")
    if name_node is None:
        return "<anonymous>"
    return source[name_node.start_byte : name_node.end_byte].decode("utf-8", errors="replace")


# ---------------------------------------------------------------------------
# Formatting helpers
# ---------------------------------------------------------------------------


def _format_with_line_numbers(text: str, start_line: int) -> str:
    """Prefix each line with its line number, right-aligned."""
    lines = text.splitlines() or [""]
    width = len(str(start_line + len(lines) - 1))
    return "\n".join(f"{start_line + i:>{width}} | {line}" for i, line in enumerate(lines))


def _format_node_with_line_numbers(node: Node, source: bytes) -> str:
    """Extract a node's source text and prefix each line with its line number."""
    text = source[node.start_byte : node.end_byte].decode("utf-8", errors="replace")
    start_line = node.start_point[0] + 1
    return _format_with_line_numbers(text, start_line)
