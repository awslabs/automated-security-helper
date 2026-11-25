# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``--transport`` has one definition: the ``Transport`` enum.

Why this file exists
--------------------
The three transport spellings (``stdio``, ``streamable-http``, ``sse``) were
written out in three places: the ``--transport`` validation tuple in
``cli/mcp/__init__.py``, the known and networked sets in ``cli/mcp/sandbox.py``
and the ``HttpCaller.transport`` values in ``cli/mcp/http_sessions.py``. They are
members of ``core.enums.Transport`` now, and this file pins:

- what the enum holds and how its members read as strings;
- that the sets and constants in ``sandbox`` and ``http_sessions`` are built from
  it, not from a second copy of the spellings;
- the ``--transport`` rendering of ``ash mcp --help`` byte for byte against the
  text it had before the flip (the typer concern the old comment recorded: an
  Enum-typed option renders its metavar as ``<stdio|streamable-http|sse>`` and
  moves an unknown value from this command's exit 5 to click's exit 2, so the
  option stays a plain ``str`` and the command turns it into a member);
- the drift gate: no module under ``cli/`` compares against or lists a
  transport spelling as a literal. The gate runs in two modes, over the real
  tree (must find none) and over planted sources (must find each plant).
"""

from __future__ import annotations

import ast
import os
import re
from pathlib import Path
from typing import List

import pytest
import typer.main
from typer.testing import CliRunner

import automated_security_helper
from automated_security_helper.cli.main import app as ash_app
from automated_security_helper.cli.mcp import http_sessions, sandbox
from automated_security_helper.core.enums import (
    DEFAULT_TRANSPORT,
    TRANSPORT_HELP,
    TRANSPORT_VALUES,
    Transport,
)

pytestmark = pytest.mark.unit

_ANSI = re.compile(r"\x1b\[[0-9;]*m")

#: The help text both declarations carried by hand before the enum.
_HELP_BEFORE = "Transport: 'stdio' (default), 'streamable-http', or 'sse'."


def test_the_members_are_the_wire_spellings_in_help_order() -> None:
    assert [m.name for m in Transport] == ["STDIO", "STREAMABLE_HTTP", "SSE"]
    assert TRANSPORT_VALUES == ("stdio", "streamable-http", "sse")
    # The validation message prints this tuple's repr.
    assert repr(TRANSPORT_VALUES) == "('stdio', 'streamable-http', 'sse')"
    assert DEFAULT_TRANSPORT is Transport.STDIO


def test_a_member_equals_its_spelling_and_reads_as_it() -> None:
    for member in Transport:
        assert member == member.value
        assert str(member) == member.value
        assert f"{member}" == member.value
        assert f"{member!s:>20}" == f"{member.value:>20}"


def test_parse_is_exact_and_returns_none_for_anything_else() -> None:
    assert Transport.parse("sse") is Transport.SSE
    assert Transport.parse(Transport.SSE) is Transport.SSE
    # --transport was case-sensitive and took no padding; the env override is
    # normalized by get_server_transport before it gets here.
    for refused in ("SSE", " sse", "http", "", None, 5):
        assert Transport.parse(refused) is None, refused


def test_only_stdio_is_not_networked() -> None:
    assert {m for m in Transport if not m.is_networked} == {Transport.STDIO}


def test_sandbox_sets_are_built_from_the_enum() -> None:
    assert sandbox.KNOWN_TRANSPORTS == frozenset(Transport)
    assert sandbox._NETWORKED_TRANSPORTS == frozenset(
        {Transport.STREAMABLE_HTTP, Transport.SSE}
    )
    assert sandbox.DEFAULT_TRANSPORT is DEFAULT_TRANSPORT


def test_http_caller_constants_are_members() -> None:
    assert http_sessions.SSE is Transport.SSE
    assert http_sessions.STREAMABLE_HTTP is Transport.STREAMABLE_HTTP


@pytest.mark.parametrize(
    ("value", "networked", "unknown"),
    [
        (None, False, None),
        ("stdio", False, None),
        ("  STDIO\n", False, None),
        ("sse", True, None),
        ("Streamable-HTTP", True, None),
        ("http", True, "http"),
    ],
)
def test_the_environment_override_reads_the_same_as_before(
    monkeypatch, value, networked, unknown
) -> None:
    if value is None:
        monkeypatch.delenv(sandbox.ASH_MCP_TRANSPORT_ENV, raising=False)
    else:
        monkeypatch.setenv(sandbox.ASH_MCP_TRANSPORT_ENV, value)

    assert sandbox.transport_is_networked() is networked
    assert sandbox.unknown_transport_override() == unknown
    # get_server_transport stays a plain string: it is the environment boundary.
    assert type(sandbox.get_server_transport()) is str


def test_set_server_transport_stores_the_spelling_for_a_member(monkeypatch) -> None:
    # setenv first: monkeypatch records the variable's state when it is first
    # touched, so teardown puts back what was there (nothing), not "sse".
    monkeypatch.setenv(sandbox.ASH_MCP_TRANSPORT_ENV, "stdio")

    sandbox.set_server_transport(Transport.SSE)

    assert os.environ[sandbox.ASH_MCP_TRANSPORT_ENV] == "sse"


def test_set_server_transport_refuses_none(monkeypatch) -> None:
    # ``str(None)`` was written as the text "None", which names no transport and
    # so read as networked: a refused call is the clearer failure.
    monkeypatch.setenv(sandbox.ASH_MCP_TRANSPORT_ENV, "stdio")

    with pytest.raises(ValueError, match="not None"):
        sandbox.set_server_transport(None)  # type: ignore[arg-type]

    assert os.environ[sandbox.ASH_MCP_TRANSPORT_ENV] == "stdio"


def test_networked_means_the_transport_is_networked_not_that_it_is_not_the_default(
    monkeypatch,
) -> None:
    # Trust follows the transport's own answer. A default that is itself a
    # networked transport must not read as local because it is "the default".
    monkeypatch.delenv(sandbox.ASH_MCP_TRANSPORT_ENV, raising=False)
    monkeypatch.setattr(sandbox, "DEFAULT_TRANSPORT", Transport.SSE)

    assert sandbox.transport_is_networked() is True


# -- the --help rendering ----------------------------------------------------------


def _plain(text: str) -> str:
    return " ".join(_ANSI.sub("", text).split())


def test_the_help_text_is_byte_equal_to_the_hand_written_one() -> None:
    assert TRANSPORT_HELP == _HELP_BEFORE


def test_both_declarations_carry_the_enum_built_help_as_a_plain_str() -> None:
    from automated_security_helper.cli.mcp import mcp_command

    wrapper = typer.main.get_command(ash_app).commands["mcp"]
    own = typer.main.get_command(_single_command_app(mcp_command))

    for command in (wrapper, own):
        (param,) = [p for p in command.params if p.name == "transport"]
        assert param.help == _HELP_BEFORE
        assert param.default == "stdio"
        assert type(param.default) is str
        # A plain string option, not an Enum choice: click keeps its type name
        # (the metavar the help renders) and does not refuse a value itself.
        assert param.type.name == "str"
        assert getattr(param.type, "choices", None) is None


def _single_command_app(command):
    app = typer.Typer()
    app.command()(command)
    return app


def test_ash_mcp_help_renders_the_transport_option_as_it_did() -> None:
    result = CliRunner().invoke(
        ash_app, ["mcp", "--help"], env={"COLUMNS": "200", "NO_COLOR": "1"}
    )

    assert result.exit_code == 0, result.output
    text = _plain(result.output)
    # The option, its metavar, the help text and its default, as one run of
    # words (the same as the pre-enum rendering captured on typer 0.27.2).
    assert f"--transport <str> {_HELP_BEFORE} [default: stdio]" in text, text
    assert "<stdio|streamable-http|sse>" not in text


# -- the drift gate ------------------------------------------------------------------


def _transport_literals_in(source: str) -> List[int]:
    """Lines where ``source`` compares against or lists a transport spelling.

    A transport spelling written as a bare literal in a comparison or in a
    tuple/set/frozenset/list of literals is a second definition. Prose in a
    message or a docstring is not.
    """
    spellings = set(TRANSPORT_VALUES)
    found: List[int] = []

    def _is_spelling(node: ast.AST) -> bool:
        return isinstance(node, ast.Constant) and node.value in spellings

    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Compare):
            if _is_spelling(node.left) or any(
                _is_spelling(c) for c in node.comparators
            ):
                found.append(node.lineno)
            for comparator in node.comparators:
                if isinstance(comparator, (ast.Tuple, ast.Set, ast.List)) and any(
                    _is_spelling(e) for e in comparator.elts
                ):
                    found.append(node.lineno)
        elif isinstance(node, (ast.Tuple, ast.Set, ast.List)):
            if sum(1 for e in node.elts if _is_spelling(e)) >= 2:
                found.append(node.lineno)
    return sorted(set(found))


_PLANTS = {
    "compare": 'if transport == "streamable-http":\n    pass\n',
    "compare-left": 'if "sse" == transport:\n    pass\n',
    "not-in-tuple": 'ok = transport not in ("stdio", "sse")\n',
    "tuple": 'VALID = ("stdio", "streamable-http", "sse")\n',
    "frozenset": 'NET = frozenset({"streamable-http", "sse"})\n',
}

_MUST_NOT_FLAG = {
    "prose": 'msg = "use the streamable-http transport"\n',
    "one-literal-default": 'transport = "stdio"\n',
    "member": "if transport is Transport.SSE:\n    pass\n",
}


@pytest.mark.parametrize("name", sorted(_PLANTS))
def test_the_gate_flags_each_planted_second_definition(name: str) -> None:
    assert _transport_literals_in(_PLANTS[name]), name


@pytest.mark.parametrize("name", sorted(_MUST_NOT_FLAG))
def test_the_gate_leaves_prose_and_members_alone(name: str) -> None:
    assert _transport_literals_in(_MUST_NOT_FLAG[name]) == [], name


def test_no_module_under_cli_redefines_the_spellings() -> None:
    root = Path(automated_security_helper.__file__).parent / "cli"
    files = sorted(root.rglob("*.py"))
    # The denominator: the gate reads the whole cli tree, not an empty glob.
    assert len(files) > 20, files
    assert (root / "mcp" / "sandbox.py") in files

    offenders = {}
    for path in files:
        lines = _transport_literals_in(path.read_text(encoding="utf-8"))
        if lines:
            offenders[str(path.relative_to(root))] = lines

    assert offenders == {}, offenders
