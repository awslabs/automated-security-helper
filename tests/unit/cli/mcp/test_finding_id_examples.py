# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The finding ids the MCP tools give as examples have the shape ids have.

Why this exists
---------------
A flattened finding's id is ``<scanner>-<rule>-<12 hex digits>``
(``utils/finding_identity.finding_id``). The ``get_finding_details`` tool's
docstring is what an MCP client is shown, and what the generated CLI and tool
references print, so an example of another shape there, such as
``"bandit-B601-deadbeef"``, would have a client or an agent that builds an id
from it build one no finding has.

What the test checks
--------------------
Every ``e.g. "<scanner>-<rule>-<hex>"`` example in the MCP tool modules ends in the
number of hex digits a finding id carries.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from automated_security_helper.utils.finding_identity import (
    FINDING_ID_DIGEST_LENGTH,
    finding_id,
)

pytestmark = pytest.mark.unit

PACKAGE = Path(__file__).resolve().parents[4] / "automated_security_helper"
MODULES = [
    PACKAGE / "cli" / "mcp_server.py",
    PACKAGE / "cli" / "mcp_tools.py",
]
EXAMPLE = re.compile(r'e\.g\. "([A-Za-z0-9_.]+(?:-[A-Za-z0-9_.]+)*-([0-9a-f]+))"')


def _examples():
    found = []
    for module in MODULES:
        for match in EXAMPLE.finditer(module.read_text(encoding="utf-8")):
            found.append((module.name, match.group(1), match.group(2)))
    return found


def test_the_examples_are_found():
    """Control: the scan reaches the docstring the tool shows a client."""
    assert any(
        name == "mcp_server.py" and example.startswith("bandit-")
        for name, example, _ in _examples()
    ), _examples()


@pytest.mark.parametrize("module, example, digest", _examples())
def test_an_example_id_ends_in_a_finding_ids_digest(module, example, digest):
    assert len(digest) == FINDING_ID_DIGEST_LENGTH, (
        f"{module}: {example!r} ends in {len(digest)} hex digits; a finding id has "
        f"{FINDING_ID_DIGEST_LENGTH}, for example "
        f"{finding_id({'scanner': 'bandit', 'rule': 'B601'})!r}"
    )
