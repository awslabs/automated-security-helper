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
helper ``mcp_set_source_git`` uses, is collected. Each value is read as a string
literal or as a ``McpErrorType`` member's ``.value`` (resolved to its wire
spelling); ``e.error_type`` is resolved to the values ``source_delivery`` gives
``GitCommandError``. A value a wrapper starts
returning that its note does not name fails here, and so does a note that gives an
exception's class name where the wrapper returns a string.

The notes once told clients to branch on ``error_type: SourceDeliveryBusyError``
while both wrappers return ``source_delivery_busy``, and named
``scan_target_not_permitted`` for a refusal ``set_source_git`` reports as
``local_clone_source_refused``. The finalize note also gave ``BadZipFile`` as the
``error_type`` of bytes that are not a zip, while the wrapper catches that exception
beside the other refusals and answers with an ``error`` alone.

The finalize note also names each rule that can refuse an archive, by the kind the
refusal carries (``SourceArchiveRefusal``). The kind is not in the response, and the
note says so. The rows hold the note to the enum: every kind the finalize can make is
named, so a kind added to the enum fails here until the note names it, and the two kinds
that only ``ash scan fs --archive`` makes are not named.
"""

from __future__ import annotations

import ast
import importlib.util
import inspect
import io
import re
import textwrap
from pathlib import Path

import pytest

from automated_security_helper.cli import mcp_tools
from automated_security_helper.cli.mcp import source_delivery as sd
from automated_security_helper.cli.mcp.error_types import McpErrorType
from automated_security_helper.utils import source_archive
from automated_security_helper.utils.source_archive import (
    SourceArchiveRefusal,
    SourceArchiveRefused,
    open_zip,
)

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

#: The two refusals that only ``ash scan fs --archive`` makes. It opens the file itself,
#: where the finalize reads the zip it assembled
#: (``test_the_two_refusals_left_out_are_made_only_by_the_archive_option``).
ARCHIVE_OPTION_ONLY = frozenset(
    {SourceArchiveRefusal.NOT_A_FILE, SourceArchiveRefusal.UNREADABLE_ARCHIVE}
)


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


def _functions_naming(tree: ast.AST, members: set[str]) -> set[str]:
    """The functions of ``tree`` that name ``SourceArchiveRefusal.<member>``."""
    found: set[str] = set()
    for function in ast.walk(tree):
        if not isinstance(function, ast.FunctionDef):
            continue
        for node in ast.walk(function):
            if (
                isinstance(node, ast.Attribute)
                and node.attr in members
                and isinstance(node.value, ast.Name)
                and node.value.id == "SourceArchiveRefusal"
            ):
                found.add(function.name)
    return found


def _with_their_callers(tree: ast.AST, names: set[str]) -> set[str]:
    """``names``, and every function of ``tree`` that calls one of them, however many
    calls away."""
    functions = [f for f in ast.walk(tree) if isinstance(f, ast.FunctionDef)]
    found = set(names)
    grew = True
    while grew:
        grew = False
        for function in functions:
            if function.name in found:
                continue
            called = {
                node.func.id
                for node in ast.walk(function)
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
            }
            if called & found:
                found.add(function.name)
                grew = True
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
    """A client that branches on ``error_type`` has to know that a checksum mismatch or
    a refused archive has none, and that a failure on disk is answered with the
    exception's class name."""
    text = _text(tool_notes, "set_source_zip_finalize")

    assert "with no `error_type`" in text
    assert _names(text, McpErrorType.SOURCE_DELIVERY_BUSY.value)
    assert _names(text, "OSError")


def test_the_finalize_note_does_not_give_bad_zip_file_as_an_error_type(tool_notes):
    assert not _names(_text(tool_notes, "set_source_zip_finalize"), "BadZipFile")


def _unsupported_compression() -> SourceArchiveRefused:
    return SourceArchiveRefused(
        SourceArchiveRefusal.UNSUPPORTED_COMPRESSION,
        "zip entry 'a.txt' is compressed with bzip2 (method 12): only stored "
        "and deflated members are read",
    )


def _not_a_zip() -> SourceArchiveRefused:
    with pytest.raises(SourceArchiveRefused) as refused:
        open_zip(io.BytesIO(b"plain text, not an archive\n"))
    return refused.value


@pytest.mark.parametrize(
    "refusal",
    [
        pytest.param(_unsupported_compression, id="unsupported-compression"),
        pytest.param(_not_a_zip, id="not-a-zip"),
    ],
)
def test_a_refused_archive_is_answered_with_an_error_and_no_kind(monkeypatch, refusal):
    """The kind a refusal carries is not in the response: the note names the kinds as
    the rules' names, and says the response has no field for one. A refusal is
    answered as the checksum mismatch is, with an ``error`` and no ``error_type``."""
    refused = refusal()

    def refuse(**_arguments):
        raise refused

    monkeypatch.setattr(sd, "set_source_zip_finalize", refuse)

    answer = mcp_tools.mcp_set_source_zip_finalize(
        "upload", "0" * 64, session_id="session"
    )

    assert answer["success"] is False
    assert str(refused) in answer["error"]
    assert "error_type" not in answer
    assert "kind" not in answer
    assert refused.kind.value not in answer.values()


def test_the_finalize_note_names_every_rule_that_can_refuse_an_archive(tool_notes):
    text = _text(tool_notes, "set_source_zip_finalize")
    made = [kind for kind in SourceArchiveRefusal if kind not in ARCHIVE_OPTION_ONLY]

    # Control: the kind the note was missing when this row was written is among them.
    assert SourceArchiveRefusal.UNSUPPORTED_COMPRESSION in made
    assert sorted(kind.value for kind in made if not _names(text, kind.value)) == []


def test_the_finalize_note_names_no_rule_that_only_the_archive_option_applies(
    tool_notes,
):
    text = _text(tool_notes, "set_source_zip_finalize")

    assert (
        sorted(kind.value for kind in ARCHIVE_OPTION_ONLY if _names(text, kind.value))
        == []
    )


def test_the_finalize_note_says_the_rule_is_not_a_field_of_the_response(tool_notes):
    text = _text(tool_notes, "set_source_zip_finalize")

    assert "the name of the rule is not a field of the response" in text


def test_the_two_refusals_left_out_are_made_only_by_the_archive_option():
    """Control for ``ARCHIVE_OPTION_ONLY``: the two kinds are named only in the helpers
    that open the file at a path, which only ``extract_source_archive`` reaches, and
    the delivery module neither calls it nor reads a file by that route. A function that
    comes to name one of them, or to call those helpers, changes this set and fails
    here, so the note is read again."""
    tree = ast.parse(inspect.getsource(source_archive))
    members = {kind.name for kind in ARCHIVE_OPTION_ONLY}

    naming = _functions_naming(tree, members)
    reaching = _with_their_callers(tree, naming)

    assert naming == {"_opened_regular_file", "_unreadable_path", "_not_a_file"}
    assert reaching == naming | {"_read_archive", "extract_source_archive"}
    delivery = inspect.getsource(sd)
    assert "extract_source_archive" not in delivery
    assert "_read_archive" not in delivery
