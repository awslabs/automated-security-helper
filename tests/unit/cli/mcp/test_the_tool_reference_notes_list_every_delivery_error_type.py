# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The reference notes name the ``error_type`` values the delivery tools return.

Why this file exists
--------------------
Agents branch on ``error_type``, and the generated tool reference is the text
they read. Its prose lives in ``TOOL_NOTES`` in
``scripts/generate_mcp_tool_reference.py``. The server's own tool descriptions
are checked against a golden; these notes are not, so this file reads them
directly. It imports the script as a module (it imports no product code until
``render()`` runs).

The values a tool returns are read from the code that returns them, not listed
here: the four ``mcp_*`` wrappers of the delivery tools are parsed, and every
``error_type`` in a returned dict, and every second argument of the ``refused``
helper ``mcp_set_source_git`` uses, is collected. A name is resolved against the
constants of ``source_delivery`` and ``sessions``; ``e.error_type`` is resolved to
the values ``source_delivery`` gives ``GitCommandError``. A value a wrapper starts
returning that its note does not name fails here, and so does a note that gives an
exception's class name where the wrapper returns a string.

The notes once told clients to branch on ``error_type: SourceDeliveryBusyError``
while both wrappers return ``source_delivery_busy``, and named
``scan_target_not_permitted`` for a refusal ``set_source_git`` reports as
``local_clone_source_refused``.
"""

from __future__ import annotations

import ast
import importlib.util
import inspect
import re
import textwrap
from pathlib import Path

import pytest

from automated_security_helper.cli import mcp_tools
from automated_security_helper.cli.mcp import source_delivery as sd
from automated_security_helper.cli.mcp.error_types import McpErrorType

pytestmark = pytest.mark.unit

SCRIPT = (
    Path(__file__).resolve().parents[4] / "scripts" / "generate_mcp_tool_reference.py"
)

#: The wrapper that answers each delivery tool.
WRAPPERS = {
    "set_source_git": mcp_tools.mcp_set_source_git,
    "set_source_zip_chunk": mcp_tools.mcp_set_source_zip_chunk,
    "set_source_zip_finalize": mcp_tools.mcp_set_source_zip_finalize,
    "clear_source": mcp_tools.mcp_clear_source,
}


def _member_value(node: ast.expr) -> str:
    """The string a ``McpErrorType.NAME.value`` expression spells."""
    if (
        isinstance(node, ast.Attribute)
        and node.attr == "value"
        and isinstance(node.value, ast.Attribute)
        and isinstance(node.value.value, ast.Name)
        and node.value.value.id == "McpErrorType"
    ):
        return McpErrorType[node.value.attr].value
    raise AssertionError(f"not a McpErrorType member's value: {ast.dump(node)}")


def _is_member_value(node: ast.expr) -> bool:
    try:
        _member_value(node)
    except AssertionError:
        return False
    return True


def _git_failure_types() -> set[str]:
    """What ``GitCommandError.error_type`` can be: the constant that is the second
    argument of every ``GitCommandError(...)`` the delivery module raises, and, where
    it raises with the ``error_type`` parameter of ``_run_git_step``, the
    constant each caller passes for that parameter."""
    found = set()
    for node in ast.walk(ast.parse(inspect.getsource(sd))):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Name):
            continue
        if (
            node.func.id == "GitCommandError"
            and len(node.args) >= 2
            and _is_member_value(node.args[1])
        ):
            found.add(_member_value(node.args[1]))
        elif node.func.id == "_run_git_step":
            for keyword in node.keywords:
                if keyword.arg == "error_type" and _is_member_value(keyword.value):
                    found.add(_member_value(keyword.value))
    return found


def _values(node: ast.expr) -> set[str]:
    """The ``error_type`` strings an expression in a wrapper can be."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return {node.value}
    if _is_member_value(node):
        return {_member_value(node)}
    if isinstance(node, ast.Attribute) and node.attr == "error_type":
        return _git_failure_types()
    # The parameter of the ``refused`` helper itself: its callers are read instead.
    if isinstance(node, ast.Name):
        return set()
    raise AssertionError(f"cannot read an error_type from {ast.dump(node)}")


def _error_types_returned_by(wrapper) -> set[str]:
    found: set[str] = set()
    for node in ast.walk(ast.parse(textwrap.dedent(inspect.getsource(wrapper)))):
        if isinstance(node, ast.Dict):
            for key, value in zip(node.keys, node.values):
                if isinstance(key, ast.Constant) and key.value == "error_type":
                    found |= _values(value)
        elif (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "refused"
            and len(node.args) == 2
        ):
            found |= _values(node.args[1])
    return found


def _busy_message() -> str:
    """The text ``SourceDeliveryBusyError`` is raised with."""
    for node in ast.walk(ast.parse(inspect.getsource(sd))):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "SourceDeliveryBusyError"
            and node.args
            and isinstance(node.args[0], ast.Constant)
        ):
            return node.args[0].value
    raise AssertionError("source_delivery raises no SourceDeliveryBusyError")


@pytest.fixture(scope="module")
def tool_notes():
    spec = importlib.util.spec_from_file_location("generate_mcp_tool_reference", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.TOOL_NOTES


def _text(tool_notes, tool: str) -> str:
    notes = tool_notes[tool]
    return "\n".join(
        [notes.get("intro", ""), *notes.get("caveats", [])]
        + [note.get("notes", "") for note in notes.get("params", {}).values()]
    )


def _names(text: str, value: str) -> bool:
    """Whether ``text`` carries ``value`` as a whole word, as in
    ``error_type: value`` or ``error_type`` ``value``."""
    return (
        re.search(rf"(?<![A-Za-z0-9_]){re.escape(value)}(?![A-Za-z0-9_])", text)
        is not None
    )


def test_the_reader_finds_a_literal_a_constant_and_a_git_failure_type():
    """Control: the values below come from three different spellings in the
    wrapper, so an empty or partial read cannot satisfy the cells that follow."""
    returned = _error_types_returned_by(WRAPPERS["set_source_git"])

    assert "local_clone_source_refused" in returned
    assert McpErrorType.CLONE_TIMED_OUT.value in returned
    assert McpErrorType.GIT_CHECKOUT_FAILED.value in returned
    assert McpErrorType.SOURCE_DELIVERY_BUSY.value in _error_types_returned_by(
        WRAPPERS["set_source_zip_finalize"]
    )
    assert McpErrorType.SESSION_WORKSPACE_BUSY.value in _error_types_returned_by(
        WRAPPERS["set_source_zip_chunk"]
    )


@pytest.mark.parametrize("tool", sorted(WRAPPERS))
def test_a_delivery_tool_note_names_every_error_type_its_wrapper_returns(
    tool_notes, tool
):
    returned = _error_types_returned_by(WRAPPERS[tool])
    text = _text(tool_notes, tool)

    assert returned
    assert sorted(t for t in returned if not _names(text, t)) == []


@pytest.mark.parametrize("tool", sorted(WRAPPERS))
def test_a_delivery_tool_note_gives_no_exception_class_as_an_error_type(
    tool_notes, tool
):
    """The wrappers return strings; a client matching a class name never matches."""
    text = _text(tool_notes, tool)
    classes = [
        name
        for name, value in vars(sd).items()
        if inspect.isclass(value)
        and issubclass(value, Exception)
        and value.__module__ == sd.__name__
    ]

    assert classes
    assert [name for name in classes if name in text] == []


@pytest.mark.parametrize("tool", ["set_source_git", "set_source_zip_finalize"])
def test_the_busy_refusal_is_quoted_as_the_module_raises_it(tool_notes, tool):
    assert _busy_message() in _text(tool_notes, tool)


def test_the_finalize_note_says_what_each_kind_of_failure_returns(tool_notes):
    """A client that branches on ``error_type`` has to know a checksum mismatch or a
    refused archive has none, and that an archive that is not a zip, or a failure on
    disk, is answered with the exception's class name."""
    text = _text(tool_notes, "set_source_zip_finalize")

    assert "with no `error_type`" in text
    assert _names(text, McpErrorType.SOURCE_DELIVERY_BUSY.value)
    assert _names(text, "BadZipFile")
    assert _names(text, "OSError")
