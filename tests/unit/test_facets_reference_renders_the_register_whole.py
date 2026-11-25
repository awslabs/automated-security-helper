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


def _compat_planted():
    """A planted class whose operational row carries one open-ended PIN row."""
    from automated_security_helper.base import scanner_operational_facets as opsf
    from automated_security_helper.plugin_modules.ash_builtin.scanners.zizmor_scanner import (
        ZizmorScanner,
    )

    row = opsf.RuntimeCompatRow(
        runtime=opsf.RuntimeName.PYTHON,
        tool_versions="",
        runtime_request=">=3.10,<3.15",
        resolution=opsf.CompatResolution.PIN,
        reason="PLANTED-COMPAT-REASON | with a pipe",
        upstream_issue="https://example.com/planted/issues/1",
        open_ended=True,
    )

    class Planted:
        facets: ClassVar[ScannerFacets] = _row()
        operational_facets = ZizmorScanner.operational_facets.model_copy(
            update={"runtime_compat": opsf.RuntimeCompatFacet(rows=(row,))}
        )

    return Planted


@pytest.fixture
def compat_page(monkeypatch) -> str:
    monkeypatch.syspath_prepend(str(SCRIPTS))
    import _plugin_reference
    import generate_facets_reference

    plugins = [
        SimpleNamespace(name="planted-compat", cls=_compat_planted()),
        SimpleNamespace(name="planted", cls=_Planted),
    ]
    monkeypatch.setattr(_plugin_reference, "discover", lambda kind: plugins)
    content, _ = generate_facets_reference.generate()
    sys.modules.pop("generate_facets_reference", None)
    return content


def test_the_facets_page_renders_runtime_compat_rows(compat_page: str) -> None:
    assert "## Runtime compatibility" in compat_page
    assert (
        "| [`planted-compat`](#planted-compat) | `python` | all | `>=3.10,<3.15` | "
        "`pin` | yes, [https://example.com/planted/issues/1]"
        "(https://example.com/planted/issues/1) |"
    ) in compat_page
    # the pipe in the reason must not end the table cell
    assert "PLANTED-COMPAT-REASON \\| with a pipe" in compat_page
    assert "1 of 2 scanners declare a row. The other 1 declare none" in compat_page


def test_a_scanner_with_no_operational_row_is_counted_not_listed(page: str) -> None:
    assert "0 of 1 scanners declare a row. The other 1 declare none" in page
    assert "| Scanner | Runtime | Tool versions |" not in page
