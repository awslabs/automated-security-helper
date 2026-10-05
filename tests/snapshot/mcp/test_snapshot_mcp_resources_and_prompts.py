# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Snapshots of what each MCP resource returns and what each prompt renders.

The wire golden pins that ``ash://help`` exists and what it is called; these pin
what a client reads from it. Resources are read and prompts rendered through the
server object (``mcp.read_resource`` / ``mcp.get_prompt``), the same path a
``resources/read`` or ``prompts/get`` request takes, so the snapshot includes
the MIME type and message structure a client receives and not only the string
the decorated function returns.

The two JSON schemas are stored as their own ``.json`` files, so a schema change
reviews as a diff of the schema rather than of one long escaped string.

Also here: the ``create_error_response`` payload for every ``ErrorCategory``.
Most tool refusals are built by it, and its default suggestions are text a
client shows a user, so the table of categories and suggestions is pinned once
rather than only through whichever tools happen to reach each category.
"""

from __future__ import annotations

from typing import Any, Dict, List

import pytest

from automated_security_helper.cli.mcp_server import mcp
from automated_security_helper.core.resource_management.error_handling import (
    ErrorCategory,
    create_error_response,
)
from automated_security_helper.core.resource_management.exceptions import (
    MCPResourceError,
)

# Resources and prompts are fixed text; the config schema's descriptions quote
# measured medians ("21.3s") that must not be masked into a different sentence.
pytestmark = pytest.mark.snapshot_masking(
    mask_durations=False, mask_duration_keys=False
)

TEXT_RESOURCES = ["ash://exit-codes", "ash://status", "ash://help"]
SCHEMA_RESOURCES = {
    "ash://schema/config": "ash_config_schema",
    "ash://schema/suppression": "ash_suppression_schema",
}


async def _read(uri: str) -> List[Dict[str, Any]]:
    return [
        {"mime_type": part.mime_type, "content": part.content}
        for part in await mcp.read_resource(uri)
    ]


def test_every_registered_resource_is_snapshotted():
    import asyncio

    registered = {str(r.uri) for r in asyncio.run(mcp.list_resources())}
    assert registered == set(TEXT_RESOURCES) | set(SCHEMA_RESOURCES)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "uri", TEXT_RESOURCES, ids=lambda uri: uri.split("://", 1)[1].replace("/", "_")
)
async def test_text_resource(uri, snapshot):
    assert await _read(uri) == snapshot(name="contents")


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "uri", sorted(SCHEMA_RESOURCES), ids=lambda uri: SCHEMA_RESOURCES[uri]
)
async def test_schema_resource(uri, snapshot, text_snapshot):
    parts = await _read(uri)
    assert [part["mime_type"] for part in parts] == snapshot(name="mime_types")
    assert len(parts) == 1
    assert parts[0]["content"] == text_snapshot("json")


@pytest.mark.asyncio
async def test_status_resource_when_the_version_lookup_fails(monkeypatch, snapshot):
    from automated_security_helper.utils import get_ash_version as module

    def _broken():
        raise RuntimeError("package metadata not found")

    monkeypatch.setattr(module, "get_ash_version", _broken)
    assert await _read("ash://status") == snapshot(name="contents")


@pytest.mark.asyncio
@pytest.mark.parametrize("name", ["run_ash_security_scan", "analyze_security_findings"])
@pytest.mark.parametrize(
    "arguments",
    [{}, {"source_dir": "/work/project"}],
    ids=["defaults_to_cwd", "explicit_source_dir"],
)
async def test_prompt(name, arguments, snapshot):
    rendered = await mcp.get_prompt(name, arguments)
    assert rendered.model_dump(mode="json", exclude_none=True) == snapshot(
        name="rendered"
    )


def test_every_registered_prompt_is_snapshotted():
    import asyncio

    registered = {p.name for p in asyncio.run(mcp.list_prompts())}
    assert registered == {"run_ash_security_scan", "analyze_security_findings"}


@pytest.mark.parametrize("category", [c.value for c in ErrorCategory])
def test_error_response_for_each_category(category, snapshot):
    error = MCPResourceError(
        f"example {category} error", context={"error_category": category}
    )
    assert create_error_response(error, operation="example_operation") == snapshot(
        name="response"
    )


def test_error_response_for_a_plain_exception(snapshot):
    response = create_error_response(
        ValueError("not an MCPResourceError"), operation="example_operation"
    )
    assert response == snapshot(name="response")
