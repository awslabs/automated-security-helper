# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The self-scan's bandit entries for the product's subprocess rules match what bandit reports.

Why this exists
---------------
``.ash/.ash_alpha_plugins.yaml`` once suppressed B404, B603 and B607 for every file
under ``automated_security_helper/`` with one glob each, and pinned three more entries
to ``ferret_scanner.py`` by a line that had moved. Bandit over the tree, run the way
the alpha self-scan runs it (the repository's bandit config, ``nosec`` comments
honored), reports five B404 findings in the product and no B603 or B607 finding there.
So the globs covered a rule they never needed (B603, B607) and hid any new subprocess
import or call anywhere in the product (B404, B603, B607), which is the opposite of
the file's own one-rule-one-file policy.

What this checks
----------------
* No product-wide glob entry carries B404, B603 or B607, and no entry carries B603 or
  B607 for a product file.
* The B404 entries are one per file, each pinned to a single line that is that file's
  ``subprocess`` import.
* The set of product files with an ``import subprocess`` statement that carries no
  ``nosec`` comment is exactly the set of files with a B404 entry, so a sixth
  importing file fails here until it is pinned.
* Nothing under the product calls the standard ``subprocess`` module's process
  functions without a ``nosec`` comment, which is why no B603 or B607 entry exists.
* The two ``nosec`` comments in ``ferret_scanner.py`` that replaced its pinned entries
  are still on the import and on the call.
"""

import ast
from pathlib import Path
from typing import Any, Dict, List, Tuple

import pytest
import yaml

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[3]
SELF_SCAN = REPO_ROOT / ".ash" / ".ash_alpha_plugins.yaml"
PRODUCT = "automated_security_helper"
SUBPROCESS_RULES = ("B404", "B603", "B607")
FERRET_SCANNER = f"{PRODUCT}/plugin_modules/ash_ferret_plugins/ferret_scanner.py"

PROCESS_FUNCTIONS = frozenset(
    {
        "run",
        "Popen",
        "call",
        "check_call",
        "check_output",
        "getoutput",
        "getstatusoutput",
    }
)


def _span_has_nosec(lines: List[str], first: int, last: int) -> bool:
    """Whether a ``nosec`` comment sits on any line of a statement, as bandit reads it."""
    return any("nosec" in line for line in lines[first - 1 : last])


def subprocess_imports(source: str) -> List[Tuple[int, bool]]:
    """Each ``subprocess`` import statement as (first line, carries a nosec comment)."""
    lines = source.splitlines()
    found = []
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            hit = any(a.name == "subprocess" for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            hit = node.module == "subprocess" and node.level == 0
        else:
            continue
        if hit:
            found.append(
                (
                    node.lineno,
                    _span_has_nosec(lines, node.lineno, node.end_lineno or node.lineno),
                )
            )
    return sorted(found)


def unmarked_process_calls(source: str) -> List[int]:
    """Lines of calls to the stdlib module's process functions with no nosec comment.

    Only a module that does ``import subprocess`` itself is read: a file that binds
    another object to the name ``subprocess`` is not calling the standard module.
    """
    tree = ast.parse(source)
    imports_module = any(
        isinstance(n, ast.Import)
        and any(a.name == "subprocess" and a.asname is None for a in n.names)
        for n in ast.walk(tree)
    )
    if not imports_module:
        return []
    lines = source.splitlines()
    found = []
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "subprocess"
            and node.func.attr in PROCESS_FUNCTIONS
            and not _span_has_nosec(lines, node.lineno, node.end_lineno or node.lineno)
        ):
            found.append(node.lineno)
    return sorted(found)


def _entries() -> List[Dict[str, Any]]:
    config = yaml.safe_load(SELF_SCAN.read_text(encoding="utf-8")) or {}
    return (config.get("global_settings") or {}).get("suppressions") or []


def _product_sources() -> List[Tuple[str, str]]:
    return [
        (path.relative_to(REPO_ROOT).as_posix(), path.read_text(encoding="utf-8"))
        for path in sorted((REPO_ROOT / PRODUCT).rglob("*.py"))
    ]


def _b404_pins() -> List[Dict[str, Any]]:
    return [
        e
        for e in _entries()
        if e.get("rule_id") == "B404" and str(e.get("path", "")).startswith(PRODUCT)
    ]


def test_no_product_glob_carries_a_subprocess_rule() -> None:
    wide = [
        e
        for e in _entries()
        if e.get("rule_id") in SUBPROCESS_RULES
        and str(e.get("path", "")).startswith(PRODUCT)
        and any(ch in str(e["path"]) for ch in "*?[")
    ]
    assert wide == []


def test_no_product_entry_carries_b603_or_b607() -> None:
    entries = [
        e
        for e in _entries()
        if e.get("rule_id") in ("B603", "B607")
        and str(e.get("path", "")).startswith(PRODUCT)
    ]
    assert entries == []


def test_there_are_five_b404_pins_each_for_one_file_and_one_line() -> None:
    pins = _b404_pins()
    assert len(pins) == 5
    assert len({e["path"] for e in pins}) == 5
    for e in pins:
        assert isinstance(e.get("line_start"), int), e["path"]
        assert e.get("line_end") == e["line_start"], e["path"]
        assert str(e.get("reason") or "").strip(), e["path"]


@pytest.mark.parametrize("entry", _b404_pins(), ids=lambda e: Path(e["path"]).name)
def test_each_b404_pin_names_the_line_that_imports_subprocess(
    entry: Dict[str, Any],
) -> None:
    source = (REPO_ROOT / entry["path"]).read_text(encoding="utf-8")
    first_lines = [line for line, _ in subprocess_imports(source)]
    assert entry["line_start"] in first_lines, (
        f"{entry['path']}: the subprocess import is on line(s) {first_lines}, "
        f"not {entry['line_start']}. The file moved under the pin; set line_start "
        "and line_end to the import."
    )


def test_the_files_that_import_subprocess_are_the_files_pinned() -> None:
    importing = {
        path
        for path, source in _product_sources()
        if any(not nosec for _, nosec in subprocess_imports(source))
    }
    assert importing == {e["path"] for e in _b404_pins()}


def test_the_product_calls_no_subprocess_process_function_without_a_nosec_comment() -> (
    None
):
    offenders = [
        f"{path}:{line}"
        for path, source in _product_sources()
        for line in unmarked_process_calls(source)
    ]
    assert offenders == []


def test_the_ferret_scanner_keeps_the_nosec_comments_that_stand_for_its_old_pins() -> (
    None
):
    source = (REPO_ROOT / FERRET_SCANNER).read_text(encoding="utf-8")
    imports = subprocess_imports(source)
    assert len(imports) == 1
    assert imports[0][1] is True
    assert "nosec B404" in source.splitlines()[imports[0][0] - 1]
    assert "nosec B603 B607" in source


# Controls: the readers above, fed source whose answer is known.


@pytest.mark.parametrize(
    "source,expected",
    [
        ("import subprocess\n", [(1, False)]),
        ("import os, subprocess  # nosec B404\n", [(1, True)]),
        ("from subprocess import (\n    A,\n)  # nosec B404\n", [(1, True)]),
        ("from subprocess import SubprocessError\n", [(1, False)]),
        ("def f():\n    import subprocess\n", [(2, False)]),
        ("from x import subprocess_utils\n", []),
        ("# import subprocess\n", []),
    ],
)
def test_the_import_reader_finds_a_subprocess_import_and_its_nosec(
    source: str, expected: List[Tuple[int, bool]]
) -> None:
    assert subprocess_imports(source) == expected


@pytest.mark.parametrize(
    "source,expected",
    [
        ("import subprocess\nsubprocess.run(['a'])\n", [2]),
        ("import subprocess\nsubprocess.run(\n    ['a'],\n)  # nosec B603\n", []),
        ("import subprocess\nsubprocess.DEVNULL\n", []),
        ("from x import y as subprocess\nsubprocess.run(['a'])\n", []),
        ("import subprocess\nsubprocess.Popen(['a'])\n", [2]),
    ],
)
def test_the_call_reader_finds_a_process_call_with_no_nosec(
    source: str, expected: List[int]
) -> None:
    assert unmarked_process_calls(source) == expected
