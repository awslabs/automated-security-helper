# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Generated reference docs must match what their generators produce right now.

WHY THIS EXISTS
---------------
Three separate doc-vs-code divergences shipped because a generator existed but
nothing compared its output to what was committed, and because some reference
tables had no generator at all:

* ``docs/content/docs/cli-reference-generated.md`` was produced by
  ``scripts/generate_cli_docs.py`` and then drifted. Re-running the generator at
  the commit that added this module produced a file that differed from the
  committed one, so the published "auto-generated" page was not the generator's
  output. A generator whose output nobody diffs is a suggestion.

* The reporter inventory was stated in four docs and three code sites with six
  different counts. See ``scripts/generate_reporter_docs.py`` for the measured
  numbers.

* ``docs/content/docs/cli-reference.md`` documented five environment variables
  that do not exist anywhere in ``automated_security_helper/`` -- ``ASH_NO_COLOR``,
  ``ASH_QUIET``, and three ``ASH_CONTAINER_*`` names -- and named a sixth,
  ``ASH_OCI_RUNNER``, that exists only in a PowerShell helper and is not the
  variable the CLI reads (that is ``OCI_RUNNER``). These were invented rather
  than drifted, which is why no comparison against a previous version would have
  found them; only a comparison against the code does.

WHAT EACH TEST PINS, AND WHAT IT DOES NOT
-----------------------------------------
``test_cli_reference_generated_is_current`` re-runs the CLI doc generator in
process and diffs. It pins the whole rendered document, so a flag renamed, an
alias added, an envvar changed, or a command added all surface here. It does not
check that the document is *good*, only that it is current.

``test_reporter_docs_are_current`` delegates to the reporter generator's own
``--check`` mode rather than reimplementing its rendering, so the two cannot
disagree about what "current" means.

``test_documented_env_vars_exist`` compares the environment-variable column of
the hand-written CLI reference against every env-var name reachable in the
package. The reachable set is built by walking the AST for every expression that
reaches an environment lookup, NOT by grepping for names: a name assembled at
runtime from fragments would not appear as a literal anywhere, and a grep-based
check would call it absent. Any non-literal key expression is surfaced as such,
so the test can refuse to make an absence claim it cannot support.
"""

from __future__ import annotations

import ast
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
PACKAGE_ROOT = REPO_ROOT / "automated_security_helper"
SCRIPTS = REPO_ROOT / "scripts"
GENERATED_CLI_REFERENCE = REPO_ROOT / "docs/content/docs/cli-reference-generated.md"
HAND_WRITTEN_CLI_REFERENCE = REPO_ROOT / "docs/content/docs/cli-reference.md"

# Environment objects an attribute chain may resolve to for a lookup to count.
_ENV_OBJECTS = {"os.environ", "environ", "os.environb"}
_GETENV = {"os.getenv", "getenv"}
_ENV_METHODS = {"get", "setdefault", "pop", "__contains__"}


def _attr_chain(node: ast.AST) -> str:
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return ".".join(reversed(parts))


def _collect_env_names() -> tuple[set[str], list[str]]:
    """Return (literal env names reachable in the package, dynamic key sites).

    The second element is the honesty valve. Every key expression that is not a
    plain string literal lands there, and a caller that wants to assert a name is
    absent must account for those sites rather than assume the literal set is
    exhaustive.
    """
    literals: set[str] = set()
    dynamic: list[str] = []

    for path in sorted(PACKAGE_ROOT.rglob("*.py")):
        tree = ast.parse(
            path.read_text(encoding="utf-8", errors="replace"), filename=str(path)
        )
        rel = path.relative_to(REPO_ROOT)

        def record(key_node: ast.AST, shape: str, lineno: int) -> None:
            if isinstance(key_node, ast.Constant) and isinstance(key_node.value, str):
                literals.add(key_node.value)
            else:
                dynamic.append(f"{rel}:{lineno} [{shape}]")

        for node in ast.walk(tree):
            lineno = getattr(node, "lineno", 0)

            if (
                isinstance(node, ast.Subscript)
                and _attr_chain(node.value) in _ENV_OBJECTS
            ):
                record(node.slice, "subscript", lineno)

            if isinstance(node, ast.Compare):
                for op, comp in zip(node.ops, node.comparators):
                    if (
                        isinstance(op, (ast.In, ast.NotIn))
                        and _attr_chain(comp) in _ENV_OBJECTS
                    ):
                        record(node.left, "in-environ", lineno)

            if isinstance(node, ast.Call):
                if _attr_chain(node.func) in _GETENV and node.args:
                    record(node.args[0], "getenv", lineno)
                if (
                    isinstance(node.func, ast.Attribute)
                    and node.func.attr in _ENV_METHODS
                    and _attr_chain(node.func.value) in _ENV_OBJECTS
                    and node.args
                ):
                    record(node.args[0], f"environ.{node.func.attr}", lineno)
                for kw in node.keywords:
                    if kw.arg != "envvar":
                        continue
                    value = kw.value
                    if isinstance(value, ast.Constant) and isinstance(value.value, str):
                        literals.add(value.value)
                    elif isinstance(value, (ast.List, ast.Tuple)):
                        for element in value.elts:
                            record(element, "envvar-list", lineno)
                    else:
                        record(value, "envvar", lineno)

    return literals, dynamic


def _documented_env_vars() -> set[str]:
    """Env var names appearing in an 'Environment Variable' column of the CLI reference.

    Scoped to that column on purpose. The page also mentions names inside shell
    examples and as output filenames (``ashx get-genai-guide -o
    ASH_INTEGRATION_GUIDE.md``), and treating those as documented variables would
    make this test fail on a filename.
    """
    names: set[str] = set()
    lines = HAND_WRITTEN_CLI_REFERENCE.read_text(encoding="utf-8").splitlines()

    env_column_index: int | None = None
    for line in lines:
        if not line.startswith("|"):
            env_column_index = None
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        lowered = [c.lower() for c in cells]
        if "environment variable" in lowered:
            env_column_index = lowered.index("environment variable")
            continue
        if "variable" in lowered and "description" in lowered:
            # The "Additional Environment Variables" table names the column
            # simply "Variable".
            env_column_index = lowered.index("variable")
            continue
        if env_column_index is None or env_column_index >= len(cells):
            continue
        cell = cells[env_column_index]
        if set(cell) <= {"-", " "}:
            continue
        for token in cell.replace(",", " ").split():
            token = token.strip("`")
            if token.isupper() and "_" in token:
                names.add(token)
    return names


def test_cli_reference_generated_is_current() -> None:
    """The committed generated CLI reference equals what the generator emits now."""
    sys.path.insert(0, str(REPO_ROOT))
    try:
        from scripts.generate_cli_docs import generate_cli_docs
    finally:
        sys.path.pop(0)

    expected = generate_cli_docs()
    actual = GENERATED_CLI_REFERENCE.read_text(encoding="utf-8")

    if expected != actual:
        import difflib

        diff = "".join(
            difflib.unified_diff(
                actual.splitlines(keepends=True),
                expected.splitlines(keepends=True),
                fromfile="cli-reference-generated.md (committed)",
                tofile="cli-reference-generated.md (regenerated)",
                n=2,
            )
        )
        pytest.fail(
            "docs/content/docs/cli-reference-generated.md is stale.\n"
            "Regenerate with: uv run python scripts/generate_cli_docs.py\n\n" + diff
        )


def test_reporter_docs_are_current() -> None:
    """The reporter inventory tables match the registered reporter set."""
    result = subprocess.run(
        [sys.executable, str(SCRIPTS / "generate_reporter_docs.py"), "--check"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, (
        "Reporter documentation is stale relative to the registered reporter set.\n"
        "Regenerate with: uv run python scripts/generate_reporter_docs.py\n\n"
        + result.stdout
        + result.stderr
    )


def test_mcp_tool_reference_is_current() -> None:
    """The agentic-plugins tool reference matches the registered MCP surface.

    This is the gap the existing ``agentic-plugins check`` gate structurally
    cannot see. That gate rebuilds each plugin backend and byte-compares whole
    output trees against ``_base/``, which proves the copies match the source but
    says nothing about whether the source matches ``mcp_server.py``. It was
    passing while ``_base/`` was 13 tools and 3 resources behind.
    """
    result = subprocess.run(
        [sys.executable, str(SCRIPTS / "generate_mcp_tool_reference.py"), "--check"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, (
        "The MCP tool reference is stale relative to the registered tool set.\n"
        "Regenerate with: uv run python scripts/generate_mcp_tool_reference.py\n"
        "Then propagate to every plugin backend with: uv run --project "
        "ash-agent-plugins/agentic-coding/transpiler agentic-plugins build\n\n"
        + result.stdout
        + result.stderr
    )


def test_documented_env_vars_exist() -> None:
    """Every env var the CLI reference tabulates is reachable in the package.

    This is the gate that the five invented variables would have failed.
    """
    reachable, dynamic = _collect_env_names()
    documented = _documented_env_vars()

    assert documented, (
        "Parsed no environment variables out of the CLI reference's tables. The "
        "column heading probably changed; fix the parser rather than the assertion, "
        "because an empty documented set makes this test vacuous."
    )

    missing = sorted(documented - reachable)
    if missing:
        pytest.fail(
            "docs/content/docs/cli-reference.md documents environment variables that "
            f"no code in automated_security_helper/ reads: {missing}.\n"
            "Either the name is wrong (ASH_OCI_RUNNER was such a case; the CLI reads "
            "OCI_RUNNER) or the variable does not exist and the row should go.\n"
            "Before deleting a row, check these non-literal lookup sites, which this "
            "test cannot resolve to a name and which could assemble one at runtime:\n  "
            + "\n  ".join(dynamic)
        )
