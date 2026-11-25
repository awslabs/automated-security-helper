# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The sdist-harvest SBOM oracle against a captured report (the CI leg).

The end-to-end CI legs do not install syft, so the online oracle in
``test_sdist_harvest_self_scan.py`` cannot produce the SBOM there. This leg
holds the same assertions (``tests/utils/sdist_harvest_oracle.py``) to a report
captured from a real run: ``polars-runtime-32`` 1.44.2's harvested
``Cargo.lock`` read by the pinned syft v1.57.2, then stamped by
``stamp_harvested_components``. The file keeps the three crates the assertions
and the suppressions concern (``rustls``, ``ring``, ``adler2``) of the 582
components the run produced, with their properties as syft and the stamping
wrote them.

It needs no network and no tool, so it runs in every leg. When the repository's
suppressions move (a polars bump, a new advisory), the online oracle is the
one that notices the drift against a live harvest; this one notices a change to
the suppression entries or the matcher against a fixed report.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tests.utils.sdist_harvest_oracle import (
    assert_linked_crate_is_listed_with_its_parent,
    assert_suppressions_match_reported_paths,
)

pytestmark = pytest.mark.integration

CAPTURED_REPORT = (
    Path(__file__).resolve().parents[1]
    / "test_data"
    / "sdist_harvest"
    / "captured-syft-polars-harvest-components.json"
)
CAPTURED_PARENT_PURL = "pkg:pypi/polars-runtime-32@1.44.2"


def _report() -> dict:
    return json.loads(CAPTURED_REPORT.read_text(encoding="utf-8"))


def test_captured_report_lists_the_linked_crate_with_its_polars_parent() -> None:
    assert_linked_crate_is_listed_with_its_parent(_report(), CAPTURED_PARENT_PURL)


def test_the_four_suppressions_match_the_captured_report_paths() -> None:
    locations = assert_linked_crate_is_listed_with_its_parent(
        _report(), CAPTURED_PARENT_PURL
    )

    assert_suppressions_match_reported_paths(locations)
