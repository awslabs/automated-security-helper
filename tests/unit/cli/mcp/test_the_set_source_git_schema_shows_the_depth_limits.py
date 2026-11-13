# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The input schema of ``set_source_git`` shows the clone depth limits.

Why this file exists
--------------------
The depth is a whole number of commits from 1 to ``MAX_CLONE_DEPTH``. The delivery
refuses anything else as ``invalid_clone_depth`` before it creates anything, but the
schema a client reads before it calls the tool said only ``integer``, so a client
that validates its arguments against the schema learned the limits from the error.
The tool signature now declares them as schema keywords
(``json_schema_extra={"minimum": 1, "maximum": MAX_CLONE_DEPTH}``) and the schema
carries ``minimum`` and ``maximum``. ``Field(ge=1, le=MAX_CLONE_DEPTH)`` would put the
same two keywords in the schema, and would also make the argument model refuse the
call itself; see the next section.

What a client must still get
----------------------------
The limits are shown in the schema and are not enforced by it. A depth outside them
reaches the tool, and the tool answers ``invalid_clone_depth`` with ``success``,
``error`` and ``session_id``, which the tool description, the reference and the
changelog all promise. A limit the argument model enforced itself would refuse the
call before the tool ran: a framework error with no ``error_type``.

How the tests work
------------------
The tool list of the in-process server is read with ``mcp.list_tools()``; nothing
is called and no process starts. The control reads a parameter that has no limit.
The call goes through the SDK's in-memory client, so the argument model of the tool
validates the arguments as it does for a client on the wire. The depth is refused
before the allowlist, a clone or a workspace is reached, so no git runs.
"""

from __future__ import annotations

import asyncio
from typing import Any, Dict

import pytest

from automated_security_helper.cli.mcp.profile_registry import DEFAULT_SESSION_ID
from automated_security_helper.cli.mcp.source_delivery import MAX_CLONE_DEPTH
from automated_security_helper.cli.mcp_server import mcp
from tests.utils.mcp_transport_harness import local_in_memory_client

pytestmark = pytest.mark.unit


def _properties(tool_name: str) -> Dict[str, Any]:
    tools = {tool.name: tool for tool in asyncio.run(mcp.list_tools())}
    return tools[tool_name].input_schema["properties"]


def test_the_depth_parameter_shows_its_minimum_and_maximum() -> None:
    depth = _properties("set_source_git")["depth"]

    assert depth["type"] == "integer", depth
    assert depth["default"] == 1, depth
    assert depth["minimum"] == 1, depth
    assert depth["maximum"] == MAX_CLONE_DEPTH, depth


def test_control_a_parameter_without_a_limit_shows_none() -> None:
    url = _properties("set_source_git")["url"]

    assert "minimum" not in url and "maximum" not in url, url


@pytest.fixture(autouse=True)
def an_operator_who_listed_no_host(monkeypatch) -> None:
    monkeypatch.delenv("ASH_MCP_GIT_ALLOWED_HOSTS", raising=False)
    monkeypatch.delenv("ASH_MCP_TRANSPORT", raising=False)


async def _call_set_source_git(depth: Any) -> Any:
    async with local_in_memory_client() as client:
        return await client.call_tool(
            "set_source_git",
            {"url": "https://example.com/team/repo.git", "depth": depth},
        )


@pytest.mark.parametrize(
    "depth", [0, -1, MAX_CLONE_DEPTH + 1], ids=["zero", "negative", "above-the-maximum"]
)
def test_a_depth_outside_the_limits_gets_the_tools_own_answer(depth: int) -> None:
    """Fails on an argument model that enforces the limits: the call is then refused
    before the tool runs, with a framework error (``isError`` and no structured
    answer), where the tool description promises ``invalid_clone_depth``."""
    result = asyncio.run(_call_set_source_git(depth))

    assert not result.is_error, result
    answer = result.structured_content["result"]
    assert answer["success"] is False, answer
    assert answer["error_type"] == "invalid_clone_depth", answer
    assert str(depth) in answer["error"], answer
    assert answer["session_id"] == DEFAULT_SESSION_ID, answer


@pytest.mark.parametrize("depth", [2.5, "deep"], ids=["fraction", "word"])
def test_a_depth_that_is_not_a_whole_number_is_refused_before_the_tool_runs(
    depth: Any,
) -> None:
    """What the documentation says of a depth that is not a whole number: the tool's
    argument validation refuses it, with a framework error and no ``error_type``,
    before the tool body runs. Only a depth outside the range is the tool's own
    ``invalid_clone_depth``."""
    result = asyncio.run(_call_set_source_git(depth))

    assert result.is_error, result
    assert result.structured_content is None, result.structured_content


def test_control_a_depth_inside_the_limits_is_not_refused_as_a_depth() -> None:
    """Control: the limit is on the depth, not on the call. The same call with the
    deepest allowed clone is refused for its host (the operator listed none), after
    the depth passed."""
    result = asyncio.run(_call_set_source_git(MAX_CLONE_DEPTH))

    answer = result.structured_content["result"]
    assert answer["error_type"] == "clone_host_not_permitted", answer
