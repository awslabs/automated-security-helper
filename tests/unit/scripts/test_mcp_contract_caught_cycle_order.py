# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""scripts/_mcp_contract.py lists a caught type's values in either read order.

Why this file exists
--------------------
Two exception classes can raise each other: a handler of ``except FirstErr as e``
raises ``SecondErr`` with ``e.error_type``, and a handler of ``except SecondErr
as e`` raises ``FirstErr`` with its own ``e.error_type``. Reading the values of
one class needs the values of the other, which needs the first again. The reader
ends that by answering "unread" for the second read of a class whose
constructions are already being read.

The reader kept every finished read. The class it met second therefore kept an
answer that held the "unread" part for the class met first, while the class met
first kept an answer with the second's values. A tool that catches only the
second class listed fewer error types when the reader met the first class
before it than when it met the second class first. The order is the order the
server declares its tools in, so a reordered module changed a generated page.

What it pins
------------
A read that ended with an "unread" answer for a class still being read above it
is not kept; it is read again once the outer read has ended. The planted package
below holds two such classes and two tools, each catching one class. The server
is written twice, with the tools in either order, and a tool lists the same
error types in both. Nothing is executed: the reader parses the source.
"""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

SERVER_HEAD = """
from automated_security_helper.cli.tools import mcp_first, mcp_second

mcp = object()
"""

SERVER_TOOL = """

@mcp.tool()
def {name}(url):
    return mcp_{name}(url)
"""

# Each class is raised on its own with a fixed type, and again from the handler
# of the other with the type the caught one carries.

TOOLS = """
class Typed(RuntimeError):
    def __init__(self, message, error_type):
        super().__init__(message)
        self.error_type = error_type


class FirstErr(Typed):
    pass


class SecondErr(Typed):
    pass


def _first_step(url):
    raise FirstErr("first", "first_kind")


def _second_step(url):
    raise SecondErr("second", "second_kind")


def relay_first(url):
    try:
        _first_step(url)
    except FirstErr as e:
        kind = e.error_type
        raise SecondErr("relayed", kind)


def relay_second(url):
    try:
        _second_step(url)
    except SecondErr as e:
        kind = e.error_type
        raise FirstErr("relayed", kind)


def mcp_first(url):
    try:
        relay_second(url)
    except FirstErr as e:
        return {"success": False, "error_type": e.error_type}
    return {"success": True}


def mcp_second(url):
    try:
        relay_first(url)
    except SecondErr as e:
        return {"success": False, "error_type": e.error_type}
    return {"success": True}
"""

BOTH_TYPES = ("first_kind", "second_kind")


def _contracts(tmp_path: Path, script_loader, order: tuple[str, ...]):
    package = tmp_path / "automated_security_helper"
    (package / "cli").mkdir(parents=True)
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "cli" / "__init__.py").write_text("", encoding="utf-8")
    server = textwrap.dedent(SERVER_HEAD).lstrip("\n") + "".join(
        textwrap.dedent(SERVER_TOOL).format(name=name) for name in order
    )
    (package / "cli" / "mcp_server.py").write_text(server, encoding="utf-8")
    (package / "cli" / "tools.py").write_text(
        textwrap.dedent(TOOLS).lstrip("\n"), encoding="utf-8"
    )
    return script_loader("_mcp_contract").tool_contracts(package)


@pytest.mark.parametrize("order", [("first", "second"), ("second", "first")])
@pytest.mark.parametrize("tool", ["first", "second"])
def test_a_tool_lists_both_types_whichever_class_the_reader_meets_first(
    tmp_path: Path, script_loader, order: tuple[str, ...], tool: str
):
    """Either class can be raised with the other's type, so each tool lists both,
    whether its own class was read first or inside the other's read."""
    contracts = _contracts(tmp_path, script_loader, order)

    assert contracts[tool].error_types == BOTH_TYPES, (
        f"{tool} listed {contracts[tool].error_types} with the tools declared "
        f"in the order {order}"
    )


@pytest.mark.parametrize("order", [("first", "second"), ("second", "first")])
def test_the_types_a_class_feeds_to_itself_through_the_other_stay_unread(
    tmp_path: Path, script_loader, order: tuple[str, ...]
):
    """Control: the part of the cycle the reader cannot follow is still reported
    unread for both tools, so reading the second class again leaves no gap
    closed that the source does not close."""
    contracts = _contracts(tmp_path, script_loader, order)

    for tool in ("first", "second"):
        assert contracts[tool].error_types_unread != (), tool
