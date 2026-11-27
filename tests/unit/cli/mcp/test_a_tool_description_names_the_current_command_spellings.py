"""A description names the commands ASH 3.9 gives, not the ones it deprecates.

A client is sent the description of every tool, resource and prompt, and an agent
told to run a command types it as written. ASH 3.9 deprecates a scan with no subject
(``ash --workspace FILE``, ``ash scan --source-dir DIR``, ``ash --mode container``),
the top-level ``ash report``, ``ash diff``, ``ash trend``, ``ash merge`` and
``ash inspect``, and ``ash build-image``, and removes them in 4.0. A description that
gives one of them sends an agent to a command that is on its way out. The spellings to
give are ``ash scan workspace FILE``, ``ash scan fs PATH``, ``ash results VERB`` and
``ash container build``.

The registry is read the way ``tools/list``, ``resources/list`` and ``prompts/list``
are served from it, so the check sees what a client is sent: the description of an
entry and every description inside its schema or arguments, not the docstring a
maintainer reads. The tool surface golden copies those descriptions, which is why it
moves with them.
"""

from __future__ import annotations

import asyncio
import re
from typing import Any, Dict, Iterator, List

import pytest

from automated_security_helper.cli.mcp_server import mcp

pytestmark = pytest.mark.unit

#: The in-process list each list request is served from, and the field that addresses
#: an entry in it. test_mcp_wire_golden_in_process.py names the same four.
SURFACES = {
    "tools": ("list_tools", "name"),
    "resources": ("list_resources", "uri"),
    "resourceTemplates": ("list_resource_templates", "uriTemplate"),
    "prompts": ("list_prompts", "name"),
}

#: A command line ASH 3.9 deprecates, in a text whose whitespace is one space: an
#: option straight after ``ash`` or ``ash scan`` (a scan with no subject),
#: ``--source-dir``, or a results command or ``build-image`` spelled at the top
#: level. ``--help`` and ``--version`` belong to the root command and are not a scan.
DEPRECATED_SPELLING = re.compile(
    r"\bash (?:scan )?--(?!help\b|version\b)"
    r"|\bash (?:report|diff|trend|merge|inspect|build-image)\b"
    r"|--source-dir\b"
)


def _one_line(text: str) -> str:
    """``text`` with each run of whitespace, a line break included, as one space."""
    return " ".join(text.split())


def _descriptions(node: Any) -> Iterator[str]:
    """Every ``description`` in a wire entry: its own and those inside its schema."""
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "description" and isinstance(value, str):
                yield value
            else:
                yield from _descriptions(value)
    elif isinstance(node, list):
        for item in node:
            yield from _descriptions(item)


def _spellings(text: str) -> List[str]:
    """Each deprecated spelling in ``text``, with the words that follow it."""
    return [
        text[match.start() : match.end() + 24]
        for match in DEPRECATED_SPELLING.finditer(text)
    ]


def _described_entries() -> Dict[str, List[str]]:
    """Every description a client is sent, under the entry it belongs to."""
    described: Dict[str, List[str]] = {}
    for surface, (accessor, identity) in SURFACES.items():
        for entry in asyncio.run(getattr(mcp, accessor)()):
            wire = entry.model_dump(by_alias=True, mode="json", exclude_none=True)
            described[f"{surface} {wire[identity]}"] = [
                _one_line(text) for text in _descriptions(wire)
            ]
    return described


def _tool_descriptions() -> Dict[str, str]:
    """Each tool's description as the registry holds it, on one line."""
    tools = asyncio.run(mcp.list_tools())
    return {tool.name: _one_line(tool.description) for tool in tools}


@pytest.mark.parametrize(
    "text",
    [
        "The MCP equivalent of `ash --workspace <file>`.",
        "Run ash scan --workspace plan.code-workspace first.",
        "Start it with ash --mode container.",
        "ash scan --source-dir src",
        "the --source-dir option",
        "ash report --format json",
        "ash diff before after",
        "ash trend",
        "ash merge a b",
        "ash inspect findings",
        "ash build-image",
    ],
)
def test_control_a_deprecated_spelling_is_found(text: str) -> None:
    assert _spellings(_one_line(text))


@pytest.mark.parametrize(
    "text",
    [
        "The MCP equivalent of `ash scan workspace <file> --dry-run`.",
        "ash scan fs . --mode container",
        "ash results merge a b",
        "ash results inspect findings",
        "ash container build --offline",
        "`ash mcp --profile NAME=path/to/ash.yaml`",
        "ash config get and ash dependencies install",
        "ash --version and ash scan --help",
        "bash --login and dash --version",
    ],
)
def test_control_a_current_spelling_is_not_found(text: str) -> None:
    assert _spellings(_one_line(text)) == []


def test_the_registry_has_descriptions_to_check() -> None:
    """The check below says nothing about the tools unless it reads some."""
    described = _described_entries()
    tools = {label for label in described if label.startswith("tools ")}

    assert "tools resolve_ash_workspace" in tools
    assert "tools run_ash_workspace_scan" in tools
    assert all(described[label] for label in tools)


def test_no_description_gives_a_deprecated_spelling() -> None:
    found = {
        label: [spelling for text in texts for spelling in _spellings(text)]
        for label, texts in _described_entries().items()
    }

    assert {label: hits for label, hits in found.items() if hits} == {}


def test_the_workspace_tools_name_the_workspace_subject() -> None:
    tools = _tool_descriptions()
    resolve = tools["resolve_ash_workspace"]
    scan = tools["run_ash_workspace_scan"]

    assert "The MCP equivalent of `ash scan workspace <file> --dry-run`." in resolve
    assert "The MCP equivalent of `ash scan workspace <file>`." in scan


@pytest.mark.parametrize(
    "named", ["NUL", "encrypted", "macOS", "Unicode", "cannot read", "damaged"]
)
def test_the_zip_finalize_description_names_what_it_refuses(named: str) -> None:
    assert named in _tool_descriptions()["set_source_zip_finalize"]
