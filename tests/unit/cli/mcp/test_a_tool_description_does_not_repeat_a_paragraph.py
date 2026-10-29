# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A tool description says each thing once.

The description of a tool is its docstring, and every client receives it. Two
changes that each added a sentence about the same behavior can end up side by side
after a merge, worded differently, and the description then repeats itself in front
of every client. The tool surface golden copies the description, so a repeat that is
generated into the golden is defended by the surface check from then on.

A paragraph is taken to repeat an earlier one when it opens with the same eight
words. Two paragraphs that open alike but go on to say different things have to be
told apart by the reader; the reader should not have to.
"""

from __future__ import annotations

import asyncio
import re
from typing import List

import pytest

from automated_security_helper.cli.mcp_server import mcp

pytestmark = pytest.mark.unit

OPENING_WORDS = 8


def _repeated_openings(description: str) -> List[str]:
    """The opening of every paragraph of ``description`` that an earlier one opened with."""
    paragraphs = [
        " ".join(paragraph.split())
        for paragraph in re.split(r"\n\s*\n", description)
        if paragraph.strip()
    ]
    seen = set()
    repeated = []
    for paragraph in paragraphs:
        opening = " ".join(paragraph.split()[:OPENING_WORDS])
        if opening in seen:
            repeated.append(opening)
        seen.add(opening)
    return repeated


def test_control_a_repeated_paragraph_is_found() -> None:
    description = (
        "Cancel it.\n\n"
        "Only a scan this session started can be cancelled; another id is refused.\n\n"
        "Only a scan this session started can be cancelled; another id is unknown."
    )

    assert _repeated_openings(description) == [
        "Only a scan this session started can be"
    ]


def test_control_paragraphs_that_open_differently_are_not_a_repeat() -> None:
    description = (
        "Cancel it.\n\n"
        "Only a scan this session started can be cancelled.\n\n"
        "A scan that has already finished cannot be cancelled."
    )

    assert _repeated_openings(description) == []


def test_every_tool_registers_a_description() -> None:
    """The test below is only a statement about the tools if there are tools to read."""
    tools = asyncio.run(mcp.list_tools())

    assert tools
    assert all(tool.description for tool in tools), [
        tool.name for tool in tools if not tool.description
    ]


def test_no_tool_description_repeats_a_paragraph() -> None:
    repeats = {
        tool.name: _repeated_openings(tool.description)
        for tool in asyncio.run(mcp.list_tools())
    }

    assert {name: found for name, found in repeats.items() if found} == {}
