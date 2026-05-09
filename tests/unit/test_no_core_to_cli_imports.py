"""Architectural guard: no file under core/ may import from cli/."""

import ast
from pathlib import Path


def _collect_imports(tree: ast.Module) -> list[str]:
    imports = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imports.append(alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                imports.append(node.module)
    return imports


def test_no_core_imports_cli():
    core_root = (
        Path(__file__).parent.parent.parent
        / "automated_security_helper"
        / "core"
    )
    violations = []
    for py_file in core_root.rglob("*.py"):
        source = py_file.read_text(encoding="utf-8")
        try:
            tree = ast.parse(source, filename=str(py_file))
        except SyntaxError:
            continue
        for imp in _collect_imports(tree):
            if "automated_security_helper.cli" in imp:
                violations.append(f"{py_file}: imports {imp!r}")

    assert not violations, (
        "core/ must not import from cli/. Violations:\n" + "\n".join(violations)
    )
