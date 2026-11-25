# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The scanner facets page renders the register as written, whatever it holds.

``scripts/generate_facets_reference.py`` says the page invents nothing and drops
nothing. Two properties of that, over a planted register row (the real register
holds an ``example`` on ``resource_id`` cells only, so a real-register run cannot
tell a generator that renders every example from one that renders one facet's):

* a facet's ``example`` is rendered whichever facet carries it;
* the ``unconfirmed`` state is counted in its own summary column and named in the
  state legend, so the page never reads an unread source as "cannot have it".
"""

from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace
from typing import ClassVar

import pytest

from automated_security_helper.base.scanner_facets import (
    FACET_NAMES,
    FacetDecl,
    FacetState,
    ScannerFacets,
)

pytestmark = pytest.mark.unit

SCRIPTS = Path(__file__).resolve().parents[2] / "scripts"


def _row() -> ScannerFacets:
    cells = {
        name: FacetDecl(state=FacetState.NA, reason="not carried")
        for name in FACET_NAMES
    }
    cells["rule_id"] = FacetDecl(
        state=FacetState.MAPPED,
        native_field="ruleId",
        example="PLANTED-RULE-EXAMPLE",
    )
    cells["severity"] = FacetDecl(
        state=FacetState.UNCONFIRMED,
        reason="UNCONFIRMED: read off a double; a real run would settle it",
    )
    cells["resource_id"] = FacetDecl(
        state=FacetState.MAPPED,
        native_field="resource",
        example="PLANTED-RESOURCE-EXAMPLE",
    )
    return ScannerFacets(**cells)


class _Planted:
    facets: ClassVar[ScannerFacets] = _row()


@pytest.fixture
def page(monkeypatch) -> str:
    monkeypatch.syspath_prepend(str(SCRIPTS))
    import _plugin_reference
    import generate_facets_reference

    plugin = SimpleNamespace(name="planted", cls=_Planted)
    monkeypatch.setattr(_plugin_reference, "discover", lambda kind: [plugin])
    content, _ = generate_facets_reference.generate()
    sys.modules.pop("generate_facets_reference", None)
    return content


def test_an_example_on_any_facet_is_rendered(page: str) -> None:
    assert "Example: `PLANTED-RULE-EXAMPLE`" in page
    assert "Example: `PLANTED-RESOURCE-EXAMPLE`" in page


def test_the_unconfirmed_state_has_its_own_column_and_legend_entry(page: str) -> None:
    assert (
        "| Scanner | Mapped | Mappable, dropped | Not applicable | Unconfirmed |"
        in page
    )
    # planted: 2 mapped, 0 dropped, 17 n/a, 1 unconfirmed
    assert "| [`planted`](#planted) | 2 | 0 | 17 | 1 |" in page
    assert "- `unconfirmed`:" in page
    assert "| `severity` | `unconfirmed` |" in page
