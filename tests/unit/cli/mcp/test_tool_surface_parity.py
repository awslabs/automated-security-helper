# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The documented MCP tool surface and the registered one must be the same set.

WHY THIS EXISTS
---------------
ASH shipped four source-delivery tools that no client could call. The
implementation was written, hardened against zip traversal and git argument
injection, covered by 40 unit tests, and documented with worked examples --
and none of that caught the fact that `@mcp.tool()` was never applied, so
`tools/list` did not return them. Every individual artifact was correct. Only
the connection between them was missing, and nothing tested the connection.

That is the failure this module exists to make loud. A test that exercises a
tool function directly cannot see whether the tool is reachable over the
protocol, and a doc example cannot either. The only way to catch it is to
compare the two surfaces against each other, which is what happens below.

HOW THE TWO SIDES ARE DERIVED
-----------------------------
Deliberately from different places, because deriving both from the same source
would make the comparison vacuous:

* Registered: `await mcp.list_tools()` on the real server object. Not a regex
  over the source -- the runtime answer, the same one a client gets.
* Documented: a regex for the `mcp__ash__<name>` client-facing spelling over
  everything under `docs/`, plus the bare tool names appearing anywhere in the
  docs tree or README for the reverse direction.

The forward direction (documented implies registered) is the one that had
already broken. The reverse (registered implies documented) catches a tool added
without a mention anywhere, which is how a surface silently grows.

WHAT THIS DOES NOT CHECK
------------------------
Signatures. A tool whose documented arguments no longer match its registered
ones passes here. Names are what broke, so names are what this pins; argument
drift would need the schema compared against the examples, which is a bigger
job and a separate test.

`scripts/verify_docs_freshness.py` covers an adjacent but different thing: that
every registered tool appears in README's table. It derives the registered side
by regex and only matches `async def`, so a `def` tool is invisible to it. This
module uses the live registry and so sees those too.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Set

import pytest

REPO_ROOT = Path(__file__).resolve().parents[4]
DOCS_DIR = REPO_ROOT / "docs"
README = REPO_ROOT / "README.md"

# The client-facing spelling. MCP clients namespace a server's tools, so a tool
# registered as `set_source_git` is called as `mcp__ash__set_source_git`, and
# that is the form the docs use in examples.
MCP_TOOL_REFERENCE = re.compile(r"mcp__ash__([a-z_][a-z0-9_]*)")

# A row of README's MCP tools table: `| `name` | description | use case |`.
# The table is the closest thing ASH has to a published tool inventory, so a row
# naming a tool that does not exist is a promise to a reader that nothing keeps.
README_TOOL_TABLE_ROW = re.compile(r"^\|\s*`([a-z_][a-z0-9_]*)`\s*\|", re.MULTILINE)

# Names the docs may mention without a matching registered tool.
#
# This list is the escape hatch for prose that deliberately refers to a tool
# that does not exist yet. It must stay empty or near-empty, and every entry
# needs a reason -- an entry is a promise to a reader that something exists, so
# it should cost something to add. An entry is only legitimate when the docs say
# plainly that the tool is unavailable; naming it as though it works is the
# defect this module exists to catch, not something to exempt.
DOCUMENTED_BUT_NOT_REGISTERED_EXEMPTIONS: dict[str, str] = {
    "select_profile": (
        "mcp_select_profile is implemented and tested, but binds a config that "
        "nothing reads: bind_session_config has no readers, and the scan entry "
        "point takes a config path rather than a resolved AshConfig, so a bound "
        "config has nowhere to go. Registering it would publish a call that "
        "returns success and changes nothing. streamable-http.md documents it "
        "under 'Selecting a profile is not available yet' and says so. Remove "
        "this entry when the config is threaded through to the scan and the tool "
        "is registered."
    ),
}

# Registered tools that need no prose mention.
#
# Same discipline in the other direction. Empty by design.
REGISTERED_BUT_NOT_DOCUMENTED_EXEMPTIONS: dict[str, str] = {}


def _iter_doc_files():
    """Yield every markdown file the documented surface may be declared in."""
    if README.is_file():
        yield README
    yield from sorted(DOCS_DIR.rglob("*.md"))


def _documented_tool_names() -> Set[str]:
    """Return every tool named in the docs using the mcp__ash__ spelling."""
    found: Set[str] = set()
    for path in _iter_doc_files():
        found.update(MCP_TOOL_REFERENCE.findall(path.read_text(encoding="utf-8")))
    return found


def _docs_corpus() -> str:
    """Return the concatenated docs text, for the bare-name reverse check."""
    return "\n".join(path.read_text(encoding="utf-8") for path in _iter_doc_files())


async def _registered_tool_names() -> Set[str]:
    """Return the tool names the running server actually exposes.

    Uses the server object rather than parsing the source, so this is the set a
    client receives from `tools/list` -- the thing that was wrong.
    """
    from automated_security_helper.cli.mcp_server import mcp

    return {tool.name for tool in await mcp.list_tools()}


def test_docs_declare_at_least_one_tool() -> None:
    """Guard the guard: an empty documented set would make the rest vacuous.

    If the regex stops matching -- the docs switch spelling, the paths move --
    every set comparison below would trivially pass. This is the canary for
    that, and it is why the forward test can be trusted when it is green.
    """
    documented = _documented_tool_names()
    assert len(documented) >= 5, (
        "Expected the docs to name several mcp__ash__* tools; found "
        f"{sorted(documented)}. If the docs moved or changed spelling, fix "
        "MCP_TOOL_REFERENCE and the doc paths in this module -- do not delete "
        "this assertion, or the parity checks below stop meaning anything."
    )


@pytest.mark.asyncio
async def test_server_registers_at_least_the_known_tools() -> None:
    """Guard the other side: an empty registered set would also be vacuous."""
    registered = await _registered_tool_names()
    assert len(registered) >= 14, (
        f"Only {len(registered)} tools registered: {sorted(registered)}. The "
        "server should expose at least the original 14."
    )


@pytest.mark.asyncio
async def test_every_documented_tool_is_registered() -> None:
    """A tool the docs tell clients to call must be callable.

    This is the assertion that would have caught the source-delivery gap: the
    docs published `mcp__ash__set_source_git` and friends while `tools/list`
    returned 14 names that did not include them.
    """
    documented = _documented_tool_names()
    registered = await _registered_tool_names()

    missing = documented - registered - set(DOCUMENTED_BUT_NOT_REGISTERED_EXEMPTIONS)
    assert not missing, (
        "These tools are documented but not registered with @mcp.tool(), so no "
        f"client can call them: {sorted(missing)}.\n"
        "Either register them in automated_security_helper/cli/mcp_server.py, "
        "remove the claim from the docs, or -- if the reference is deliberately "
        "aspirational -- add the name to "
        "DOCUMENTED_BUT_NOT_REGISTERED_EXEMPTIONS with a reason."
    )


@pytest.mark.asyncio
async def test_every_registered_tool_is_mentioned_in_the_docs() -> None:
    """A tool clients can call should be findable in the docs.

    Looser than the forward direction on purpose: this matches the bare tool
    name anywhere in the docs tree or README, because ASH's docs name most tools
    without the `mcp__ash__` prefix (README's table, the stdio guide) and only
    the streamable-HTTP examples use the prefixed form. Matching bare names is
    what makes this check apply to all of them rather than a handful.
    """
    registered = await _registered_tool_names()
    corpus = _docs_corpus()

    undocumented = {
        name
        for name in registered
        if name not in corpus and name not in REGISTERED_BUT_NOT_DOCUMENTED_EXEMPTIONS
    }
    assert not undocumented, (
        f"These tools are registered but appear nowhere in the docs: "
        f"{sorted(undocumented)}.\n"
        "Add them to README.md's MCP tools table and to the relevant guide, or "
        "add the name to REGISTERED_BUT_NOT_DOCUMENTED_EXEMPTIONS with a reason."
    )


def _readme_table_tool_names() -> Set[str]:
    """Return the tool names README's MCP tools table claims exist."""
    return set(README_TOOL_TABLE_ROW.findall(README.read_text(encoding="utf-8")))


@pytest.mark.asyncio
async def test_readme_table_lists_exactly_the_registered_tools() -> None:
    """README's tool table is an inventory, so it must match the inventory.

    Both directions in one assertion because both had drifted: the table named
    `scan_directory` and `scan_directory_with_progress`, neither of which is a
    registered tool, while `list_scanners`, `validate_config` and `list_profiles`
    were registered and absent from it. A reader who trusts the table would have
    called two tools that do not exist and never learned about three that do.
    """
    registered = await _registered_tool_names()
    tabled = _readme_table_tool_names()

    ghosts = tabled - registered
    absent = registered - tabled - set(REGISTERED_BUT_NOT_DOCUMENTED_EXEMPTIONS)

    assert not ghosts, (
        f"README's MCP tools table names tools that are not registered: "
        f"{sorted(ghosts)}. Remove the rows, or register the tools."
    )
    assert not absent, (
        f"These registered tools are missing from README's MCP tools table: "
        f"{sorted(absent)}. Add a row for each."
    )


@pytest.mark.asyncio
async def test_exemptions_are_not_stale() -> None:
    """An exemption that no longer applies has to be removed.

    Otherwise the lists rot into a permanent allowlist and the gate quietly
    weakens: a name left in DOCUMENTED_BUT_NOT_REGISTERED_EXEMPTIONS after the
    tool is registered would keep suppressing a check that now passes anyway.
    """
    documented = _documented_tool_names()
    registered = await _registered_tool_names()

    for name in DOCUMENTED_BUT_NOT_REGISTERED_EXEMPTIONS:
        assert name in documented, (
            f"{name!r} is exempted as documented-but-not-registered, but the "
            "docs no longer mention it. Remove the exemption."
        )
        assert name not in registered, (
            f"{name!r} is exempted as documented-but-not-registered, but it is "
            "now registered. Remove the exemption."
        )

    for name in REGISTERED_BUT_NOT_DOCUMENTED_EXEMPTIONS:
        assert name in registered, (
            f"{name!r} is exempted as registered-but-not-documented, but it is "
            "no longer registered. Remove the exemption."
        )
        assert name not in _docs_corpus(), (
            f"{name!r} is exempted as registered-but-not-documented, but the "
            "docs now mention it. Remove the exemption."
        )
