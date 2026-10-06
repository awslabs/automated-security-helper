# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The committed MCP wire golden must equal the in-process registry, on every OS.

WHY THIS EXISTS
---------------
``.github/actions/validate-mcp/tool_surface.golden.json`` pins the server's
``tools/list``, ``resources/list``, ``resources/templates/list`` and
``prompts/list`` replies. The check that compares it against a live server,
``compare_tool_surface.py``, drives ``ashx mcp`` through the MCP Inspector, and the
CI step that runs it is skipped on Windows (the inspector install and the stdio
spawn are POSIX-only in that action). So on a Windows leg nothing compared the
surface to the golden at all: a Windows-only change to a tool schema, a resource
or a prompt would have passed every check that ran there.

This module closes that gap without a Node toolchain. It asks the server object
for the same four lists -- ``await mcp.list_tools()`` and friends, the
registration table ``tools/list`` is served from -- serializes each entry the way
the transport does (``model_dump(by_alias=True, mode="json", exclude_none=True)``),
and compares the result to the golden with the script's own normalization and
comparison functions, loaded from the script file.

ONE MECHANISM
-------------
Nothing here re-implements a normalizer. ``normalize_entries``, ``SURFACES``,
``load_golden`` and ``compare_all`` are imported from the script, so the golden
has exactly one definition of "equal" whichever check reads it. The script stays
the only writer: a mismatch here is fixed by regenerating with ``--update`` and
reviewing the diff, never by editing this test.

WHAT THIS DOES NOT COVER
------------------------
Everything between the registry and a real client: the console-script entry
point, the stdio transport and the ``initialize`` exchange. That is what the
inspector-driven step is for, and why both exist. This one runs everywhere; that
one sees the wire.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType
from typing import Any, Dict

import pytest

REPO_ROOT = Path(__file__).resolve().parents[4]
SCRIPT = REPO_ROOT / ".github" / "actions" / "validate-mcp" / "compare_tool_surface.py"

#: Which in-process accessor serves each golden surface. A new row in the
#: script's SURFACES has to be added here too; the first test below fails until
#: it is, rather than letting the new surface go uncompared.
REGISTRY_ACCESSORS = {
    "tools": "list_tools",
    "resources": "list_resources",
    "resourceTemplates": "list_resource_templates",
    "prompts": "list_prompts",
}


def _load_compare_script() -> ModuleType:
    """Import compare_tool_surface.py from its path; it is not on sys.path.

    Registered in sys.modules before executing, because the module defines a
    dataclass and ``dataclasses`` looks the defining module up by name.
    """
    name = "compare_tool_surface_for_in_process_parity"
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, SCRIPT)
    assert spec is not None and spec.loader is not None, f"cannot load {SCRIPT}"
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


async def _in_process_surface(script: ModuleType) -> Dict[str, Dict[str, Any]]:
    from automated_security_helper.cli.mcp_server import mcp

    live: Dict[str, Dict[str, Any]] = {}
    for surface in script.SURFACES:
        entries = await getattr(mcp, REGISTRY_ACCESSORS[surface.key])()
        wire = [
            entry.model_dump(by_alias=True, mode="json", exclude_none=True)
            for entry in entries
        ]
        live[surface.key] = script.live_surface({surface.key: wire}, surface)
    return live


def test_every_golden_surface_has_an_in_process_accessor() -> None:
    script = _load_compare_script()
    assert {surface.key for surface in script.SURFACES} == set(REGISTRY_ACCESSORS), (
        "compare_tool_surface.SURFACES and REGISTRY_ACCESSORS name different "
        "surfaces. Add the new surface's in-process list method to "
        "REGISTRY_ACCESSORS so the golden is checked here as well as on the wire."
    )


@pytest.mark.asyncio
async def test_the_in_process_registry_matches_the_committed_golden() -> None:
    script = _load_compare_script()
    golden = script.load_golden(script.DEFAULT_GOLDEN)
    live = await _in_process_surface(script)

    problems = script.compare_all(live, golden)

    assert not problems, (
        "The in-process MCP registry differs from "
        ".github/actions/validate-mcp/tool_surface.golden.json:\n\n"
        + "\n\n".join(problems)
        + "\n\nIf the change is intended, regenerate the golden and commit it with "
        "a 'Snapshot-Update: <reason>' trailer:\n"
        "    python .github/actions/validate-mcp/compare_tool_surface.py --update"
    )


@pytest.mark.asyncio
async def test_the_comparison_can_fail() -> None:
    """Guard the guard: a changed prompt description must produce a problem.

    Without this, a compare_all that returned [] for everything -- or an
    in-process capture that came back empty and matched an equally empty golden
    -- would keep the test above green while checking nothing. The capture is
    compared against a mutated copy of itself rather than against the golden, so
    this stays a statement about the comparison even while the golden is stale.
    """
    import copy

    script = _load_compare_script()
    live = await _in_process_surface(script)
    assert live["tools"] and live["resources"] and live["prompts"]
    mutated = copy.deepcopy(live)
    prompt = next(iter(mutated["prompts"]))
    mutated["prompts"][prompt]["description"] += " (changed)"

    problems = script.compare_all(mutated, live)

    assert len(problems) == 1, problems
    assert problems[0].startswith(f"prompt {prompt}: description changed.")
    assert "(changed)" in problems[0]
