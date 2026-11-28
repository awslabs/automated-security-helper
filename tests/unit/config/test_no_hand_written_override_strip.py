"""No module reads a ``--config-overrides`` operator by hand.

An override's key ends with its operator: ``key=`` replaces, ``key+=`` adds to the
list the key holds and ``key-=`` removes items from it. ``split_override_key``
(``automated_security_helper/utils/override_key.py``) reads the key and the operator
in one place. A module that took a trailing ``+`` off a key by hand saw ``key-=`` as a
key ending in ``-``, a path no setting has, so a trust check or a gate written that way
would let a remove edit of an operator-only key through as a write to some other path.

This test reads every module of the package and fails on a call that tests for, or
takes off, a trailing ``+`` (``removesuffix``, ``endswith``, ``rstrip`` or ``strip``
with ``"+"``), on any call that looks for a two-character operator (``"+="`` or
``"-="``), and on a comparison of a key's last character with ``"+"``, outside
``split_override_key`` itself. A lone ``"-"`` is not looked for: slug and flag code
strips hyphens for reasons of its own (``workspace/aggregation.py``,
``cli/json_input.py``), and the helper is the only place that reads it as an operator.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Iterator, List, Tuple

import pytest

pytestmark = pytest.mark.unit

#: The package this test reads, from this file's place in the repository.
PACKAGE_ROOT = Path(__file__).resolve().parents[3] / "automated_security_helper"

#: The one function allowed to read an override's operator, and the module it is in.
HELPER_MODULE = Path("utils") / "override_key.py"
HELPER_FUNCTION = "split_override_key"

#: The str methods that test for, or take off, a trailing "+".
_TRAILING_PLUS_METHODS = frozenset({"removesuffix", "endswith", "rstrip", "strip"})
#: The str methods a hand-written parse of a two-character operator would call.
_OPERATOR_METHODS = frozenset(
    {
        "removesuffix",
        "endswith",
        "rstrip",
        "partition",
        "rpartition",
        "split",
        "rsplit",
        "find",
        "rfind",
        "index",
        "rindex",
        "count",
        "replace",
    }
)
_OPERATORS = frozenset({"+=", "-="})


def _string_arguments(node: ast.Call) -> List[str]:
    """The string constants a call's first argument names: the constant itself, or
    every string constant of a tuple of them (``key.endswith(("+", "-"))``)."""
    if not node.args:
        return []
    first = node.args[0]
    if isinstance(first, ast.Constant) and isinstance(first.value, str):
        return [first.value]
    if isinstance(first, ast.Tuple):
        return [
            item.value
            for item in first.elts
            if isinstance(item, ast.Constant) and isinstance(item.value, str)
        ]
    return []


def _is_last_character(node: ast.AST) -> bool:
    """Whether ``node`` is ``x[-1]`` or ``x[-1:]``."""
    if not isinstance(node, ast.Subscript):
        return False
    index = node.slice
    if isinstance(index, ast.Slice):
        if index.upper is not None or index.step is not None:
            return False
        index = index.lower
    return (
        isinstance(index, ast.UnaryOp)
        and isinstance(index.op, ast.USub)
        and isinstance(index.operand, ast.Constant)
        and index.operand.value == 1
    )


def _is_plus(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant) and node.value == "+"


def hand_written_strips(tree: ast.AST) -> Iterator[Tuple[int, str]]:
    """``(line, what)`` for each node of ``tree`` that reads an override operator by
    hand, in the order ``ast.walk`` meets them."""
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            method = node.func.attr
            arguments = _string_arguments(node)
            if method in _TRAILING_PLUS_METHODS and "+" in arguments:
                yield node.lineno, f'.{method}("+")'
            elif method in _OPERATOR_METHODS and _OPERATORS & set(arguments):
                spelled = min(_OPERATORS & set(arguments))
                yield node.lineno, f'.{method}("{spelled}")'
        elif isinstance(node, ast.Compare):
            sides = [node.left, *node.comparators]
            if any(_is_plus(side) for side in sides) and any(
                _is_last_character(side) for side in sides
            ):
                yield node.lineno, 'a last character compared with "+"'


def _helper_lines(tree: ast.AST) -> range:
    """The lines of ``split_override_key`` in ``tree``, or an empty range."""
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == HELPER_FUNCTION:
            return range(node.lineno, (node.end_lineno or node.lineno) + 1)
    return range(0)


def strips_outside_the_helper(root: Path = PACKAGE_ROOT) -> List[str]:
    """``path:line what`` for every hand-written read of an override operator under
    ``root``, leaving out the body of ``split_override_key`` in its own module. A file
    that does not parse fails the test, so a guard cannot pass over the file it could
    not read."""
    found: List[str] = []
    for py_file in sorted(root.rglob("*.py")):
        relative = py_file.relative_to(root)
        try:
            tree = ast.parse(py_file.read_text(encoding="utf-8"), filename=str(py_file))
        except SyntaxError as exc:
            raise AssertionError(
                f"{py_file} does not parse ({exc.msg}, line {exc.lineno}): this "
                "test cannot read it"
            ) from exc
        allowed = _helper_lines(tree) if relative == HELPER_MODULE else range(0)
        for line, what in sorted(hand_written_strips(tree)):
            if line not in allowed:
                found.append(f"{relative.as_posix()}:{line} {what}")
    return found


def test_no_module_strips_an_override_operator_by_hand():
    """Every module reads an override's key and operator through
    ``split_override_key``, so each one that routes ``key+=`` routes ``key-=`` too."""
    found = strips_outside_the_helper()
    assert found == [], (
        f"{len(found)} hand-written read(s) of a --config-overrides operator; read "
        "the key and the operator with "
        "automated_security_helper.utils.override_key.split_override_key instead:\n"
        + "\n".join(found)
    )


def test_the_helper_the_rule_names_is_where_the_rule_looks():
    """The allowed function exists where the scan above exempts it, so the scan
    cannot pass because it exempts a name that no longer means anything."""
    module = PACKAGE_ROOT / HELPER_MODULE
    assert module.is_file(), f"{module} does not exist"
    tree = ast.parse(module.read_text(encoding="utf-8"), filename=str(module))
    assert len(_helper_lines(tree)) > 0, f"{module} defines no {HELPER_FUNCTION}"


def _plant(tmp_path: Path, relative: str, text: str) -> Path:
    """A package tree under ``tmp_path`` holding ``text`` at ``relative``."""
    target = tmp_path / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text, encoding="utf-8")
    return tmp_path


@pytest.mark.parametrize(
    "line",
    [
        'key = override.partition("=")[0].removesuffix("+")',
        'append = key.endswith("+")',
        'key = key.rstrip("+")',
        "key = key.removesuffix('+')",
        'if key[-1] == "+": pass',
        'if "+" == key[-1:]: pass',
        'head, _, tail = override.partition("+=")',
        'removed = override.split("-=")',
        'append = key.endswith(("+", "-"))',
        "text = f\"{key.removesuffix('+')}\"",
    ],
    ids=[
        "removesuffix-plus",
        "endswith-plus",
        "rstrip-plus",
        "removesuffix-single-quoted",
        "last-character",
        "last-slice-reversed",
        "partition-append-operator",
        "split-remove-operator",
        "endswith-tuple",
        "inside-f-string",
    ],
)
def test_the_scan_finds_a_planted_strip(tmp_path, line):
    """Control: each spelling the rule names is found in a module it reads."""
    root = _plant(tmp_path, "config/planted.py", f"{line}\n")
    found = strips_outside_the_helper(root)
    assert len(found) == 1, found
    assert found[0].startswith("config/planted.py:1 "), found


@pytest.mark.parametrize(
    "line",
    [
        'release, _, build = version.partition("+")',
        'LEADS = ("=", "+", "-", "@")',
        'stem = name.strip("-")',
        'flag = "--" + key.lstrip("-")',
        'parser.add_argument("paths", nargs="+")',
        "message = \"'+=' adds to a value\"",
        "last = key[-1]",
    ],
    ids=[
        "version-partition",
        "tuple-of-characters",
        "strip-hyphen",
        "lstrip-hyphen",
        "nargs-plus",
        "operator-in-text",
        "last-character-read",
    ],
)
def test_the_scan_leaves_other_uses_of_the_characters_alone(tmp_path, line):
    """Control: code that handles a "+" or a "-" for another reason is not flagged."""
    root = _plant(tmp_path, "utils/planted.py", f"{line}\n")
    assert strips_outside_the_helper(root) == []


def test_the_helpers_own_body_is_exempt_and_nothing_else_is(tmp_path):
    """Control: the read inside ``split_override_key`` is allowed, the same read in
    another function of that module is not, and neither is a function of that name
    in another module."""
    helper = (
        "def split_override_key(entry):\n"
        '    key = str(entry).partition("=")[0]\n'
        '    if key.endswith("+"):\n'
        '        return key[:-1], "+="\n'
        '    return key, "="\n'
        "\n"
        "def elsewhere(key):\n"
        '    return key.removesuffix("+")\n'
    )
    root = _plant(tmp_path, "utils/override_key.py", helper)
    _plant(tmp_path, "config/copy.py", helper)

    assert strips_outside_the_helper(root) == [
        'config/copy.py:3 .endswith("+")',
        'config/copy.py:8 .removesuffix("+")',
        'utils/override_key.py:8 .removesuffix("+")',
    ]


def test_a_file_that_does_not_parse_fails_the_scan(tmp_path):
    """Control: a module the scan cannot read is a failure, never a skipped file."""
    root = _plant(tmp_path, "config/broken.py", "def f(:\n")
    with pytest.raises(AssertionError, match="does not parse"):
        strips_outside_the_helper(root)


def test_the_real_package_is_read():
    """Control: the scan reads modules of the real package, so an empty result above
    is not a scan of nothing."""
    modules = list(PACKAGE_ROOT.rglob("*.py"))
    assert len(modules) > 100, f"{PACKAGE_ROOT} holds {len(modules)} modules"
    assert (PACKAGE_ROOT / "config" / "resolve_config.py") in modules
