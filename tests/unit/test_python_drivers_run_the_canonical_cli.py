# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Python code that starts a scan runs `ashx` and spells v4's flags.

Why this exists
---------------
Tests and scripts merged from main keep arriving with v3's way of starting a scan:
the `ash` entry point beside the interpreter, and `--fail-on-findings false`. v4's
`--fail-on-findings` is a boolean flag (`--no-fail-on-findings` turns it off) and
`scan` takes no extra arguments, so `ashx scan ... --fail-on-findings false` exits 2
with "Got unexpected extra argument(s) (false)" before any scanner runs. 48ba9262 fixed
that in #757's escape test and parity script. #786's test_trivy_java_db.py and
#793's test_sandbox_exec_services.py then came in with both again, and no Linux leg
noticed: the first skips where trivy is not installed, and the second runs only on
macOS, where every test would have failed with "the probe wrote no outcome".

`ash` is also the deprecated alias. It prints a warning on stderr, which a test that
reads stderr then sees, and on Windows under MSYS2 or Git for Windows `ash` is the
Almquist shell.

tests/unit/test_ci_runs_the_canonical_cli.py does this for workflow `run:` bodies.
This parses every Python file under tests/, scripts/ and .github/ and refuses:

* a list or tuple holding a boolean scan flag followed by "true" or "false";
* `with_name("ash")`, `which("ash")` or `find_executable("ash")`;
* a list or tuple that starts with "ash" and a subcommand.

tests/test_data is left out: it holds scanner fixtures, some deliberately broken,
and none of them start ASH.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from tests.utils.helpers import iter_repo_files

REPO = Path(__file__).resolve().parents[2]
ROOTS = ("tests", "scripts", ".github")
SKIP_DIRS = frozenset({"__pycache__", "node_modules", ".venv", "test_data"})

#: Options `ashx scan` declares as `bool | None`, so they take no value.
BOOLEAN_FLAGS = frozenset({"--fail-on-findings", "--fail-on-incomplete-scanners"})
#: Calls that resolve an executable by name.
LOOKUPS = frozenset({"with_name", "which", "find_executable"})
SUBCOMMANDS = frozenset(
    {
        "scan",
        "config",
        "dependencies",
        "mcp",
        "report",
        "plugin",
        "inspect",
        "merge",
        "image",
        "get-genai-guide",
    }
)


def _text(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def v3_spellings(source: str) -> list[tuple[int, str]]:
    """Each (line, description) in ``source`` that starts or names v3's CLI."""
    found: list[tuple[int, str]] = []
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, (ast.List, ast.Tuple)):
            items = node.elts
            for flag, value in zip(items, items[1:]):
                name, text = _text(flag), _text(value)
                if name not in BOOLEAN_FLAGS or text is None:
                    continue
                if text.lower() in {"true", "false"}:
                    usage = f"v4 takes {name} or --no-{name[2:]}"
                    found.append((flag.lineno, f"{name} {text}: {usage}"))
            if (
                len(items) >= 2
                and _text(items[0]) == "ash"
                and _text(items[1]) in SUBCOMMANDS
            ):
                found.append((node.lineno, f"argv starts `ash {_text(items[1])}`"))
        elif isinstance(node, ast.Call) and node.args:
            func = node.func
            name = func.attr if isinstance(func, ast.Attribute) else None
            if isinstance(func, ast.Name):
                name = func.id
            if name in LOOKUPS and _text(node.args[0]) == "ash":
                found.append(
                    (node.lineno, f'{name}("ash"): use CANONICAL_CLI_NAME instead')
                )
    return found


def _python_files() -> list[Path]:
    files = []
    for root in ROOTS:
        files.extend(
            path
            for path in iter_repo_files(REPO / root, skip_dirs=SKIP_DIRS)
            if path.suffix == ".py"
        )
    return sorted(files)


def test_the_walk_reads_the_drivers():
    files = {p.relative_to(REPO).as_posix() for p in _python_files()}
    # The files the rule was written for, so an empty or mis-rooted walk fails.
    assert "tests/integration/sandbox/test_sandbox_escape.py" in files
    assert "tests/integration/sandbox/test_trivy_java_db.py" in files
    assert "scripts/verify_sandbox_scanner_parity.py" in files
    assert len(files) > 500


def test_no_python_driver_starts_v3s_cli():
    hits = []
    for path in _python_files():
        rel = path.relative_to(REPO).as_posix()
        for line, what in v3_spellings(path.read_text(encoding="utf-8")):
            hits.append(f"{rel}:{line}: {what}")
    assert not hits, "\n".join(hits)


@pytest.mark.parametrize(
    "source",
    [
        'cmd = ["ashx", "scan", "--fail-on-findings", "false"]',
        'cmd = ("--fail-on-incomplete-scanners", "True")',
        'exe = Path(sys.executable).with_name("ash")',
        'exe = shutil.which("ash")',
        'exe = find_executable("ash")',
        'subprocess.run(["ash", "scan", "--source-dir", "."])',
    ],
)
def test_each_v3_spelling_is_reported(source):
    assert v3_spellings(source)


@pytest.mark.parametrize(
    "source",
    [
        'cmd = ["ashx", "scan", "--no-fail-on-findings"]',
        'cmd = ["ashx", "scan", "--fail-on-findings", "--source-dir", "false"]',
        "exe = Path(sys.executable).with_name(CANONICAL_CLI_NAME)",
        'exe = shutil.which("ashx")',
        'argv = ["ash", "--version"]',
        'text = "--fail-on-findings false"',
    ],
)
def test_v4_spellings_pass(source):
    assert v3_spellings(source) == []
