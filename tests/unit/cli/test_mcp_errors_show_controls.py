# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""An MCP error shows the control characters it quotes as escapes.

A tool's error quotes paths, names and the messages of the errors it caught,
and those can hold an ESC, a carriage return or a right-to-left override. The
response is JSON, which writes them as JSON escapes on the wire, but a client
decodes the string and may display it: the controls would then reach its terminal
or its view as they were. Each tool's "error", the scan registry's
"error_message" and the message a tool sends to the client's log are written
through utils/terminal_text.py's raw_controls_on_one_line: each control as its
escape, a tab and a newline included, since the field is one line; a backslash
kept as it is, so a message whose values were escaped where it was raised reads
the same; and a CI command form broken.
"""

from __future__ import annotations

import ast
import asyncio
import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pydantic_core
import pytest
from mcp.server.mcpserver import Context

pytestmark = pytest.mark.unit

ESC, CR, RLO = chr(0x1B), chr(0x0D), chr(0x202E)

#: A value holding an ESC sequence, a carriage return and a right-to-left override.
#: The ESC is lone ("ESC b" is no CSI or OSC sequence): an error's text has
#: complete sequences removed in every print.
VALUE = "a" + ESC + "b" + CR + "c" + RLO + "d"

#: VALUE as a client should read it.
SHOWN = "a\\x1bb\\x0dc\\u202ed"

_PACKAGE = Path(__file__).resolve().parents[3] / "automated_security_helper"


def _raw_controls_on_one_line(text: str) -> str:
    from automated_security_helper.utils.terminal_text import raw_controls_on_one_line

    return raw_controls_on_one_line(text)


# -- the function --------------------------------------------------------------


@pytest.mark.parametrize(
    "text, shown",
    [
        pytest.param(VALUE, SHOWN, id="controls"),
        pytest.param("a\tb\nc\r\nd", "a\\x09b\\x0ac\\x0d\\x0ad", id="layout-too"),
        pytest.param("no version", "no version", id="plain"),
        pytest.param("C:\\Users\\scan", "C:\\Users\\scan", id="windows-path"),
        pytest.param(SHOWN, SHOWN, id="already-escaped-not-doubled"),
        pytest.param("::warning::x", "\\x3a:warning::x", id="workflow-command"),
        pytest.param("x ##[group]y", "x \\x23#[group]y", id="legacy-command"),
        pytest.param("## heading", "## heading", id="bare-heading-left"),
        pytest.param("out" + chr(0xDC80), "out\\udc80", id="lone-surrogate"),
    ],
)
def test_raw_controls_on_one_line(text, shown):
    assert _raw_controls_on_one_line(text) == shown


@pytest.mark.parametrize("text", [VALUE, "a\tb\nc", SHOWN, "::x", "##vso[x"])
def test_raw_controls_on_one_line_changes_nothing_more_applied_again(text):
    once = _raw_controls_on_one_line(text)
    assert _raw_controls_on_one_line(once) == once


# -- a tool's error ------------------------------------------------------------


def _check_installation(message: str):
    """check_installation, its check raising with *message*: (result, context)."""
    from automated_security_helper.cli import mcp_server

    ctx = MagicMock(spec=Context)
    with (
        patch.object(
            mcp_server,
            "mcp_check_installation",
            AsyncMock(side_effect=RuntimeError(message)),
        ),
        patch.object(mcp_server, "logger", MagicMock()),
    ):
        result = asyncio.run(mcp_server.check_installation(ctx=ctx))
    return result, ctx


@pytest.mark.parametrize(
    "serialized",
    [
        pytest.param(json.dumps, id="json"),
        pytest.param(pydantic_core.to_json, id="pydantic"),
    ],
)
@pytest.mark.parametrize(
    "message, error",
    [
        pytest.param(
            f"cannot read '{VALUE}'",
            f"Error checking installation: cannot read '{SHOWN}'",
            id="controls",
        ),
        pytest.param(
            f"cannot read '{SHOWN}'",
            f"Error checking installation: cannot read '{SHOWN}'",
            id="escaped-where-raised",
        ),
        pytest.param(
            "first\nsecond",
            "Error checking installation: first\\x0asecond",
            id="newline",
        ),
        pytest.param(
            "no version", "Error checking installation: no version", id="plain"
        ),
        pytest.param(
            "cannot read C:\\Users\\scan",
            "Error checking installation: cannot read C:\\Users\\scan",
            id="backslash-path",
        ),
    ],
)
def test_a_tools_error_as_a_client_decodes_it(message, error, serialized):
    result, _ = _check_installation(message)

    decoded = json.loads(serialized(result))["error"]

    assert decoded == error
    assert not any(c in decoded for c in (ESC, CR, RLO, "\n")), ascii(decoded)


def test_a_tools_message_to_the_clients_log_shows_its_controls():
    _, ctx = _check_installation(f"cannot read '{VALUE}'")

    sent = [str(a) for call in ctx.error.call_args_list for a in call.args]

    assert sent == [f"Error checking installation: cannot read '{SHOWN}'"]


def test_the_shared_error_response_shows_its_controls():
    from automated_security_helper.core.resource_management.error_handling import (
        create_error_response,
    )

    response = create_error_response(RuntimeError(f"bad '{VALUE}'"), "scan")

    assert response["error"] == f"bad '{SHOWN}'"


def test_an_error_that_starts_with_a_workflow_command_is_broken():
    """A client that writes the error to a CI log would start a line with it."""
    from automated_security_helper.core.resource_management.error_handling import (
        create_error_response,
    )

    response = create_error_response(RuntimeError("::error::forged"), "scan")

    assert response["error"] == "\\x3a:error::forged"


# -- the registry's error and an error response's context -----------------------


def test_a_registry_error_comes_back_shown_from_both_tools(monkeypatch):
    """The scan registry keeps a failed scan's error as raised; the progress and
    list tools show it at the reply, and leave the registry's own copy raw."""
    from automated_security_helper.cli import mcp_tools

    entry = {
        "scan_id": "scan-1",
        "status": "failed",
        "error_message": f"ended '{VALUE}'",
    }
    registry = MagicMock()
    registry.get_scan.return_value = None
    registry.list_scans.return_value = [entry]
    registry.get_scan_count.return_value = 1
    registry.get_active_scan_count.return_value = 0
    registry.get_scan_status_counts.return_value = {"failed": 1}
    monkeypatch.setattr(mcp_tools, "get_scan_registry", lambda: registry)
    monkeypatch.setattr(
        mcp_tools, "check_scan_progress", AsyncMock(return_value=dict(entry))
    )
    monkeypatch.setattr(mcp_tools, "list_active_scans", AsyncMock(return_value=[entry]))

    progress = asyncio.run(mcp_tools.mcp_get_scan_progress("scan-1"))
    listed = asyncio.run(mcp_tools.mcp_list_active_scans())

    assert progress["error_message"] == f"ended '{SHOWN}'"
    assert [
        s["error_message"] for s in listed["active_scans"] + listed["all_scans"]
    ] == [f"ended '{SHOWN}'"] * 2
    assert entry["error_message"] == f"ended '{VALUE}'", "the registry's copy changed"


def test_a_registry_error_is_logged_once(capsys, monkeypatch):
    """What the registry holds is what the ASH log shows, once."""
    import logging

    from automated_security_helper.core.resource_management.scan_registry import (
        ScanRegistryEntry,
    )
    from automated_security_helper.utils.log import get_logger

    entry = ScanRegistryEntry("scan-1", "/tmp/src", "/tmp/out")
    entry.mark_failed(f"ended '{VALUE}'")
    monkeypatch.delenv("ASH_LOG_TO_STDERR", raising=False)
    logger = get_logger(
        name="ash-registry-error-logged-once",
        level=logging.INFO,
        show_progress=False,
        use_color=False,
        simple_format=True,
    )
    capsys.readouterr()
    try:
        logger.error(entry.to_dict()["error_message"])
    finally:
        logger.handlers = []
    written = " ".join(capsys.readouterr().out.split())

    assert f"ended '{SHOWN}'" in written, ascii(written)
    assert "\\\\x1b" not in written, ascii(written)


def test_an_error_responses_context_shows_its_controls():
    """Each string in the reply's context, nested ones included, is shown at the
    reply; the error's own context keeps them raw."""
    from automated_security_helper.core.resource_management.error_handling import (
        create_error_response,
    )
    from automated_security_helper.core.resource_management.exceptions import (
        MCPResourceError,
    )

    context = {
        "error_category": "invalid_parameter",
        "path": "/tmp/a\nb" + RLO + "c",
        "nested": {"paths": ["x" + ESC + "y", 3], "kept": None},
        "windows": "C:\\Users\\scan",
    }
    error = MCPResourceError("refused", context=context)

    response = create_error_response(error, "scan")

    assert response["context"] == {
        "error_category": "invalid_parameter",
        "path": "/tmp/a\\x0ab\\u202ec",
        "nested": {"paths": ["x\\x1by", 3], "kept": None},
        "windows": "C:\\Users\\scan",
    }
    assert error.context["path"] == "/tmp/a\nb" + RLO + "c", "the error changed"


# -- validate_config's errors and warnings -------------------------------------

#: A config key holding an ESC sequence, a right-to-left override and a newline.
KEY = "fo" + ESC + "[31mo" + RLO + "x\nz"


def _problems(result):
    """validate_config's errors and warnings, as a client decodes them."""
    decoded = json.loads(json.dumps(result))
    return decoded["errors"] + decoded["warnings"]


def _unshown(problems):
    """Each control or format character left in an entry's field or message."""
    import unicodedata

    return [
        (name, ascii(entry[name]))
        for entry in problems
        for name in ("field", "message")
        if any(unicodedata.category(c).startswith("C") for c in entry[name])
    ]


@pytest.mark.parametrize(
    "content",
    [
        pytest.param(json.dumps({"project_name": "x", KEY: 1}), id="json-key"),
        pytest.param(
            "project_name: x\n" + "a" + RLO + "b: 1\n",
            id="yaml-key",
        ),
    ],
)
def test_a_config_key_validate_config_names_is_shown(content):
    """An unknown key is named in the entry's message and taken as its field."""
    from automated_security_helper.cli.mcp_tools import mcp_validate_config

    problems = _problems(mcp_validate_config(config_content=content))

    assert any(e["field"] for e in problems), problems
    assert _unshown(problems) == []


@pytest.mark.parametrize("exists", [False, True], ids=["missing", "unparseable"])
def test_a_config_path_validate_config_names_is_shown(tmp_path, exists):
    from automated_security_helper.cli.mcp_tools import mcp_validate_config

    path = tmp_path / ("cfg" + ESC + "[31m" + RLO + "\n.yaml")
    if exists:
        path.write_text("project_name: [x\n", encoding="utf-8")

    problems = _problems(mcp_validate_config(config_path=str(path)))

    assert any("cfg" in e["message"] for e in problems), problems
    assert _unshown(problems) == []


def test_a_refused_session_id_validate_config_names_is_shown():
    """The refusal quotes the id with repr, so it is shown where it is raised;
    the reply keeps it shown, and the guard below holds the site."""
    from automated_security_helper.cli import mcp_server

    ctx = MagicMock(spec=Context)
    ctx.headers = {"mcp-session-id": "s" + ESC + "[31m" + RLO + "d"}

    problems = _problems(mcp_server.validate_config(ctx, config_content="x: 1\n"))

    assert [e["type"] for e in problems] == ["invalid_session_id"], problems
    assert _unshown(problems) == []


# -- every site ----------------------------------------------------------------

#: The modules that build what an MCP client reads.
_MCP_MODULES = [
    "cli/mcp_server.py",
    "cli/mcp_tools.py",
    "core/resource_management/error_handling.py",
    *sorted(
        p.relative_to(_PACKAGE).as_posix()
        for p in (_PACKAGE / "cli" / "mcp").glob("*.py")
    ),
]

#: The Context methods that send a message to the client's log.
_CLIENT_LOG = frozenset({"debug", "info", "warning", "error", "log"})


def _is_constant_text(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant) and isinstance(node.value, str)


#: The one-line escapers whose result holds no control character. shown_on_one_line
#: is one to one, for a message raised with its values raw (the not-UTF-8
#: refusal, tests/unit/utils/test_no_text_is_shown_twice.py).
_ONE_LINE_ESCAPERS = frozenset({"raw_controls_on_one_line", "shown_on_one_line"})


def _is_shown(node: ast.AST) -> bool:
    """A call of a one-line escaper, or str() of one."""
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "str"
        and len(node.args) == 1
    ):
        node = node.args[0]
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id in _ONE_LINE_ESCAPERS
    )


#: The reply keys whose value a client shows: a tool's error, and the message and
#: field of each of validate_config's errors and warnings.
_SHOWN_KEYS = frozenset({"error", "message", "field"})


def _unshown_error_text(path: str) -> list[str]:
    """Each "error", "message" or "field" value, each message to the client's log
    and each progress notification's message that is neither constant text nor
    written through a one-line escaper.

    Not seen: a value put in another key, a container or an attribute before it
    is returned; a message handed to the client through an alias of ctx or of one
    of its methods other than report_progress; and the scan registry's
    "error_message", which a tool returns as the registry holds it.
    """
    tree = ast.parse((_PACKAGE / path).read_text(encoding="utf-8"))
    found = []
    for node in ast.walk(tree):
        values = []
        if isinstance(node, ast.Dict):
            values += [
                v
                for k, v in zip(node.keys, node.values)
                if isinstance(k, ast.Constant) and k.value in _SHOWN_KEYS
            ]
        if isinstance(node, ast.Assign):
            values += [
                node.value
                for t in node.targets
                if isinstance(t, ast.Subscript)
                and isinstance(t.slice, ast.Constant)
                and t.slice.value in _SHOWN_KEYS
            ]
        if isinstance(node, ast.Call):
            func = node.func
            on_ctx = (
                isinstance(func, ast.Attribute)
                and isinstance(func.value, ast.Name)
                and func.value.id == "ctx"
            )
            # A message to the client's log, awaited or handed on in a lambda.
            if on_ctx and func.attr in _CLIENT_LOG and node.args:
                values.append(node.args[0])
            # A progress notification's message, on ctx or through a name for it.
            if (on_ctx and func.attr == "report_progress") or (
                isinstance(func, ast.Name) and func.id == "report_progress"
            ):
                values += [k.value for k in node.keywords if k.arg == "message"]
        for value in values:
            if not (_is_constant_text(value) or _is_shown(value)):
                found.append(f"{path}:{value.lineno}: {ast.unparse(value)[:70]}")
    return found


def test_every_error_and_client_log_message_shows_its_controls():
    """A new tool, or a new failure of one, that writes its error raw fails here."""
    assert len(_MCP_MODULES) >= 5, _MCP_MODULES
    found = [site for path in _MCP_MODULES for site in _unshown_error_text(path)]

    assert found == []
