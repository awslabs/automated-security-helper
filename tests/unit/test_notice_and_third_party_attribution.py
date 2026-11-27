# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""NOTICE and THIRD-PARTY-LICENSES stay aligned with the vendored-asset inventory.

Why these tests exist
---------------------
Under the Apache-2.0 NOTICE convention the NOTICE file carries the project name
and the copyright line, nothing else; third-party names do not belong in it.
Attribution for third-party content that is copied into this repository lives in
the root THIRD-PARTY-LICENSES file instead: one ``** {project} - {source URL}``
entry per vendored project, each followed by that project's own license text,
aggregated from the per-asset license files the documentation site serves.

The inventory both files must agree with is the provenance record,
docs/content/assets/licenses/asset-provenance.txt: every asset copied into the
repository has a block there naming its Source. These tests parse that record
instead of repeating its names, so vendoring a new asset (a new provenance
block) fails here loudly until THIRD-PARTY-LICENSES carries the matching entry,
and a leftover entry whose asset was removed fails the count the same way.

Declared pip dependencies are deliberately out of scope: users obtain them from
the package registry under the upstream projects' own terms; they are not
copied into this repository, so they get no attribution file here.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[2]
NOTICE = REPO_ROOT / "NOTICE"
THIRD_PARTY_LICENSES = REPO_ROOT / "THIRD-PARTY-LICENSES"
ASSET_PROVENANCE = (
    REPO_ROOT / "docs" / "content" / "assets" / "licenses" / "asset-provenance.txt"
)


def provenance_project_names() -> list[str]:
    """First line of every provenance block that records an asset's Source."""
    text = ASSET_PROVENANCE.read_text(encoding="utf-8")
    blocks = [b for b in re.split(r"\n\s*\n", text.strip()) if b.strip()]
    names = [
        block.splitlines()[0].strip()
        for block in blocks
        if any(line.startswith("Source:") for line in block.splitlines())
    ]
    assert len(names) >= 2, (
        "the provenance parse went dead: expected at least the two known "
        f"assets, read {names!r} from {ASSET_PROVENANCE}"
    )
    return names


def test_notice_is_exactly_the_project_name_and_the_copyright_line():
    assert NOTICE.read_text(encoding="utf-8") == (
        "Automated Security Helper\n"
        "Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.\n"
    )


def test_third_party_licenses_has_one_entry_per_vendored_asset():
    assert THIRD_PARTY_LICENSES.is_file(), (
        "THIRD-PARTY-LICENSES is missing from the repository root"
    )
    text = THIRD_PARTY_LICENSES.read_text(encoding="utf-8")
    entries = [line for line in text.splitlines() if line.startswith("** ")]
    names = provenance_project_names()
    for name in names:
        matching = [entry for entry in entries if entry.startswith(f"** {name} - ")]
        assert matching, (
            f"{name!r} is in the provenance record but has no "
            f"'** {name} - <source URL>' entry in THIRD-PARTY-LICENSES"
        )
    assert len(entries) == len(names), (
        "THIRD-PARTY-LICENSES entries and provenance assets disagree: "
        f"entries={entries!r}, provenance={names!r}"
    )
