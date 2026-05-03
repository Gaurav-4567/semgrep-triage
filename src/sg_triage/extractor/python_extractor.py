"""Tree-sitter-based code context extraction for Python files.

Given a finding's location (file path + line range), extract surrounding code
context to send to the LLM: the enclosing function, file imports, and one-hop
call resolution. Honest about what it cannot extract — gaps are recorded in
extraction_notes and surfaced to the LLM as missing_context.
"""

from pathlib import Path

import tree_sitter_python
from tree_sitter import Language, Node, Parser

from sg_triage.schema import CalledFunction, CodeContext, Finding, ResolutionMethod

# Initialize the parser once at module load.
_PY_LANGUAGE = Language(tree_sitter_python.language())
_PYTHON_PARSER: Parser = Parser(_PY_LANGUAGE)


# Maximum file size we'll attempt to parse.
_MAX_FILE_BYTES = 2 * 1024 * 1024  # 2 MB

# Built-in / stdlib names we never try to resolve definitions for.
# The LLM already knows what these do.
_KNOWN_BUILTINS = frozenset(
    {
        "len",
        "range",
        "open",
        "print",
        "int",
        "str",
        "list",
        "dict",
        "set",
        "tuple",
        "bool",
        "float",
        "bytes",
        "type",
        "isinstance",
        "issubclass",
        "hasattr",
        "getattr",
        "setattr",
        "delattr",
        "callable",
        "iter",
        "next",
        "enumerate",
        "zip",
        "map",
        "filter",
        "sorted",
        "reversed",
        "any",
        "all",
        "sum",
        "min",
        "max",
        "abs",
        "round",
        "divmod",
        "pow",
        "repr",
        "hash",
        "id",
        "vars",
        "dir",
        "format",
        "input",
        "exec",
        "eval",
        "compile",
        "globals",
        "locals",
        "super",
        "object",
        "Exception",
        "ValueError",
        "TypeError",
        "KeyError",
        "IndexError",
        "AttributeError",
        "RuntimeError",
        "FileNotFoundError",
        "OSError",
        "IOError",
        "StopIteration",
    }
)


def extract_context(finding: Finding, repo_path: Path) -> CodeContext:
    """Extract code context for a Python finding."""
    notes: list[str] = []
    full_path = repo_path / finding.file_path

    matched_code_with_lines = _format_with_line_numbers(finding.matched_code, finding.start_line)

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

    # --- Imports --------------------------------------------------------
    imports = _extract_imports(root, source)
    imports_map = _build_imports_map(root, source)

    # --- Containing function -------------------------------------------
    containing_func_node = _find_containing_function(root, finding.start_line, finding.end_line)

    if containing_func_node is None:
        notes.append(
            "Match is at module level (not inside any function or method); "
            "function context unavailable."
        )
        containing_function_name = None
        containing_function_source = None
        containing_function_start_line = None
        called_functions: list[CalledFunction] = []
    else:
        containing_function_name = _get_function_name(containing_func_node, source)
        containing_function_source = _format_node_with_line_numbers(containing_func_node, source)
        containing_function_start_line = containing_func_node.start_point[0] + 1

        # --- Called functions -----------------------------------------
        called_names = _find_call_names(containing_func_node, source)
        called_functions, unresolved = _resolve_calls(
            called_names,
            current_file=full_path,
            repo_path=repo_path,
            same_file_root=root,
            same_file_source=source,
            imports_map=imports_map,
        )
        for name in unresolved:
            notes.append(f"Definition of `{name}()` not resolved.")

    return CodeContext(
        language="python",
        matched_code_with_lines=matched_code_with_lines,
        imports=imports,
        containing_function_name=containing_function_name,
        containing_function_source=containing_function_source,
        containing_function_start_line=containing_function_start_line,
        called_functions=called_functions,
        extraction_notes=notes,
    )


# ---------------------------------------------------------------------------
# Source loading
# ---------------------------------------------------------------------------


def _read_source(path: Path, notes: list[str]) -> bytes | None:
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
    """Find the innermost function_definition node containing the given line range."""
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
    name_node = func_node.child_by_field_name("name")
    if name_node is None:
        return "<anonymous>"
    return _node_text(name_node, source)


# ---------------------------------------------------------------------------
# Imports extraction
# ---------------------------------------------------------------------------


def _extract_imports(root: Node, source: bytes) -> str | None:
    """Concatenate all top-level import statements into a single string."""
    import_lines: list[str] = []
    for child in root.children:
        if child.type in ("import_statement", "import_from_statement"):
            import_lines.append(_node_text(child, source))
    if not import_lines:
        return None
    return "\n".join(import_lines)


def _build_imports_map(root: Node, source: bytes) -> dict[str, str]:
    """Build a name -> module mapping from imports.

    For example:
        from .utils import helper       -> {"helper": ".utils"}
        from mypkg.security import escape -> {"escape": "mypkg.security"}
        import os                       -> {"os": "os"}
        import os.path as p             -> {"p": "os.path"}

    Used in stage 5 to resolve calls to imported names.
    """
    mapping: dict[str, str] = {}
    for child in root.children:
        if child.type == "import_statement":
            # `import x`, `import x.y`, `import x as y`, `import x, y as z`
            for sub in child.named_children:
                if sub.type == "dotted_name":
                    name = _node_text(sub, source)
                    mapping[name.split(".")[0]] = name
                elif sub.type == "aliased_import":
                    real = sub.child_by_field_name("name")
                    alias = sub.child_by_field_name("alias")
                    if real and alias:
                        mapping[_node_text(alias, source)] = _node_text(real, source)
        elif child.type == "import_from_statement":
            # `from x import a, b as c`
            module_node = child.child_by_field_name("module_name")
            module_name = _node_text(module_node, source) if module_node else ""
            for sub in child.named_children:
                if sub == module_node:
                    continue
                if sub.type == "dotted_name":
                    name = _node_text(sub, source)
                    mapping[name] = module_name
                elif sub.type == "aliased_import":
                    real = sub.child_by_field_name("name")
                    alias = sub.child_by_field_name("alias")
                    if real and alias:
                        mapping[_node_text(alias, source)] = module_name
    return mapping


# ---------------------------------------------------------------------------
# Call discovery & resolution
# ---------------------------------------------------------------------------


def _find_call_names(func_node: Node, source: bytes) -> list[str]:
    """Find all function call names within a function body. Deduplicated, ordered."""
    seen: set[str] = set()
    ordered: list[str] = []

    def walk(node: Node) -> None:
        if node.type == "call":
            fn = node.child_by_field_name("function")
            name = _extract_call_name(fn, source) if fn else None
            if name and name not in seen and name not in _KNOWN_BUILTINS:
                seen.add(name)
                ordered.append(name)
        for child in node.children:
            walk(child)

    walk(func_node)
    return ordered


def _extract_call_name(fn_node: Node, source: bytes) -> str | None:
    """Get the simple name of a callee.

    For `foo()` returns 'foo'.
    For `obj.method()` returns 'method'.
    For `x.y.z()` returns 'z'.
    For complex expressions (e.g. `f()()`) returns None.
    """
    if fn_node.type == "identifier":
        return _node_text(fn_node, source)
    if fn_node.type == "attribute":
        attr = fn_node.child_by_field_name("attribute")
        if attr and attr.type == "identifier":
            return _node_text(attr, source)
    return None


def _resolve_calls(
    names: list[str],
    *,
    current_file: Path,
    repo_path: Path,
    same_file_root: Node,
    same_file_source: bytes,
    imports_map: dict[str, str],
) -> tuple[list[CalledFunction], list[str]]:
    """Resolve called names to definitions. Returns (resolved, unresolved_names)."""
    resolved: list[CalledFunction] = []
    unresolved: list[str] = []

    for name in names:
        # Stage 4: same-file lookup
        same_file_def = _find_function_def_in_tree(same_file_root, same_file_source, name)
        if same_file_def is not None:
            resolved.append(
                CalledFunction(
                    name=name,
                    source=_format_node_with_line_numbers(same_file_def, same_file_source),
                    file_path=str(current_file.relative_to(repo_path)).replace("\\", "/"),
                    start_line=same_file_def.start_point[0] + 1,
                    resolution_method=ResolutionMethod.SAME_FILE,
                )
            )
            continue

        # Stage 5: import-hop lookup
        module = imports_map.get(name)
        if module is not None:
            target_file = _resolve_module_to_file(module, current_file, repo_path)
            if target_file is not None and target_file.exists():
                target_def = _find_function_def_in_file(target_file, name)
                if target_def is not None:
                    target_node, target_source = target_def
                    resolved.append(
                        CalledFunction(
                            name=name,
                            source=_format_node_with_line_numbers(target_node, target_source),
                            file_path=str(target_file.relative_to(repo_path)).replace("\\", "/"),
                            start_line=target_node.start_point[0] + 1,
                            resolution_method=ResolutionMethod.SAME_MODULE_IMPORT,
                        )
                    )
                    continue

        unresolved.append(name)

    return resolved, unresolved


def _find_function_def_in_tree(root: Node, source: bytes, name: str) -> Node | None:
    """Find a top-level or method `def name(...)`. Returns first match, or None.

    Searches both top-level functions and methods inside top-level classes.
    Does not search nested functions (deliberate — keeps resolution scope small).
    """

    def search(node: Node, depth: int) -> Node | None:
        for child in node.children:
            if child.type == "function_definition":
                if _get_function_name(child, source) == name:
                    return child
            elif child.type == "class_definition" and depth == 0:
                # Recurse into class body once to find methods
                body = child.child_by_field_name("body")
                if body:
                    found = search(body, depth + 1)
                    if found:
                        return found
            elif child.type == "decorated_definition":
                # `@decorator\ndef foo(...)` — the function_definition is a child
                inner = search(child, depth)
                if inner:
                    return inner
        return None

    return search(root, 0)


def _find_function_def_in_file(path: Path, name: str) -> tuple[Node, bytes] | None:
    """Read and parse a file, return (function_def_node, source) for a given name."""
    try:
        size = path.stat().st_size
    except OSError:
        return None
    if size > _MAX_FILE_BYTES:
        return None
    try:
        source = path.read_bytes()
    except OSError:
        return None
    tree = _PYTHON_PARSER.parse(source)
    node = _find_function_def_in_tree(tree.root_node, source, name)
    if node is None:
        return None
    return node, source


def _resolve_module_to_file(module: str, current_file: Path, repo_path: Path) -> Path | None:
    """Convert a module name (e.g. 'mypkg.utils' or '.helpers') to a file path.

    Best-effort: handles relative imports (leading dots) and dotted absolute
    paths. Tries `<module>.py` and `<module>/__init__.py`. Does not handle
    complex package layouts (namespace packages, src/ layouts beyond the
    repo root).
    """
    if not module:
        return None

    # Relative imports: leading dots
    if module.startswith("."):
        leading = len(module) - len(module.lstrip("."))
        rest = module.lstrip(".").replace(".", "/")
        # Each dot beyond the first goes up one directory
        base = current_file.parent
        for _ in range(leading - 1):
            base = base.parent
        candidate_dir = base / rest if rest else base
    else:
        # Absolute import — search relative to repo root
        candidate_dir = repo_path / module.replace(".", "/")

    # Try <name>.py and <name>/__init__.py
    if candidate_dir.with_suffix(".py").exists():
        return candidate_dir.with_suffix(".py")
    init_file = candidate_dir / "__init__.py"
    if init_file.exists():
        return init_file
    return None


# ---------------------------------------------------------------------------
# Formatting helpers
# ---------------------------------------------------------------------------


def _node_text(node: Node, source: bytes) -> str:
    return source[node.start_byte : node.end_byte].decode("utf-8", errors="replace")


def _format_with_line_numbers(text: str, start_line: int) -> str:
    """Prefix each line with its line number, right-aligned."""
    lines = text.splitlines() or [""]
    width = len(str(start_line + len(lines) - 1))
    return "\n".join(f"{start_line + i:>{width}} | {line}" for i, line in enumerate(lines))


def _format_node_with_line_numbers(node: Node, source: bytes) -> str:
    text = _node_text(node, source)
    start_line = node.start_point[0] + 1
    return _format_with_line_numbers(text, start_line)
