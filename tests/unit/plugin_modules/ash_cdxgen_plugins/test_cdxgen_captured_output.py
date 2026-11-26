# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""cdxgen's real output, read through the scanner.

The fixture under tests/test_data/scanners/cdxgen/captured is the file a real
cdxgen 12.9.2 run wrote (argv and version in that directory's README), so the
adapter and the declared facets are checked against the tool's own bytes and not
only against a hand-written SBOM.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from automated_security_helper.plugin_modules.ash_cdxgen_plugins.cdxgen_scanner import (
    CDXGEN_VERSION,
    CdxgenScanner,
)
from automated_security_helper.base.scanner_facets import FacetState
from automated_security_helper.schemas.cyclonedx_bom_1_6_schema import CycloneDXReport

from .test_cdxgen_scanner_behavior import _scan, _scanner

pytestmark = pytest.mark.unit

CAPTURED = (
    Path(__file__).resolve().parents[3]
    / "test_data"
    / "scanners"
    / "cdxgen"
    / "captured"
    / "cdxgen_pypi_requirements.cdx.json"
)


@pytest.fixture(scope="module")
def captured() -> dict:
    return json.loads(CAPTURED.read_text(encoding="utf-8"))


def test_the_capture_is_from_the_pinned_release(captured):
    tool = captured["metadata"]["tools"]["components"][0]
    assert tool["name"] == "cdxgen"
    assert tool["version"] == CDXGEN_VERSION
    assert captured["specVersion"] == "1.6"


def test_the_scanner_returns_the_captured_sbom(tmp_path, captured):
    report = _scan(_scanner(tmp_path), {"returncode": 0}, captured)

    assert isinstance(report, CycloneDXReport)
    assert [(c.name, c.version.root) for c in report.components] == [
        ("requests", "2.19.0")
    ]


def test_negative_control_a_capture_with_the_components_removed_reads_empty(
    tmp_path, captured
):
    stripped = {key: value for key, value in captured.items() if key != "components"}

    report = _scan(_scanner(tmp_path), {"returncode": 0}, stripped)

    assert isinstance(report, CycloneDXReport)
    assert not report.components


def test_the_package_facets_are_na_because_the_sbom_bypasses_the_flat_path(captured):
    """The capture carries name and version per component, yet no Result exists to
    map them onto: the document is returned whole, so the register declares n/a."""
    facets = CdxgenScanner.facets
    component = captured["components"][0]
    assert component["name"] == "requests"
    assert component["version"] == "2.19.0"
    for name in ("package_name", "package_version"):
        decl = getattr(facets, name)
        assert decl.state is FacetState.NA
        assert "components[]" in decl.reason


def test_every_facet_is_declared_not_applicable():
    facets = CdxgenScanner.facets
    states = {name: getattr(facets, name).state for name in type(facets).model_fields}
    assert set(states.values()) == {FacetState.NA}, states
