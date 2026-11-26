# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""scorecard, the alpha repository-posture scanner's tool, is a pinned tool.

Scorecard is pinned by its own module (``ash_scorecard_plugins/scorecard_install.py``)
rather than ``tool_downloads``' shared tables, so the agreement the shared coverage
test gives TOOL_VERSIONS tools -- a license entry recording the same release the
installer places -- is asserted here instead. The entry's version probe is
``scorecard version`` because ``scorecard --version`` is an unknown flag.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from automated_security_helper.plugin_modules.ash_scorecard_plugins.scorecard_install import (
    ASSETS,
    SCORECARD_VERSION,
)
from automated_security_helper.plugin_modules.ash_scorecard_plugins.scorecard_scanner import (
    ScorecardScanner,
)
from automated_security_helper.utils.tool_downloads import THIRD_PARTY_LICENSES

pytestmark = pytest.mark.unit


def test_the_license_entry_names_the_installers_pin():
    entry = THIRD_PARTY_LICENSES["scorecard"]
    assert entry.version == SCORECARD_VERSION == "v5.7.0"
    assert entry.license == "Apache-2.0"
    assert entry.repository == "https://github.com/ossf/scorecard"
    assert len(entry.commit) == 40
    # Every release archive carries a LICENSE byte-identical to the repository's at
    # the pinned commit, but install-pinned-tool never sees scorecard's archive, so
    # the staged copy is the URL-pinned one.
    license_files = [f for f in entry.files if f.name == "LICENSE"]
    assert len(license_files) == 1
    assert license_files[0].url is not None and entry.commit in license_files[0].url
    assert len(license_files[0].sha256) == 64


def test_the_version_check_is_the_version_subcommand():
    entry = THIRD_PARTY_LICENSES["scorecard"]
    assert entry.version_probe == ("scorecard", "version")
    assert not entry.executables


def test_the_register_citation_names_the_pinned_release():
    citation = ScorecardScanner.operational_facets.provenance.upstream_license
    assert citation.startswith("Apache-2.0 (source: the LICENSE file inside the ")
    assert SCORECARD_VERSION in citation
    assert THIRD_PARTY_LICENSES["scorecard"].commit[:8] in citation


def test_the_installer_covers_every_published_platform():
    # Scorecard publishes no 386 build; both Windows architectures are published.
    assert sorted(ASSETS) == [
        ("darwin", "amd64"),
        ("darwin", "arm64"),
        ("linux", "amd64"),
        ("linux", "arm64"),
        ("windows", "amd64"),
        ("windows", "arm64"),
    ]


def test_the_image_installs_and_attributes_the_pinned_scorecard():
    dockerfile = (Path(__file__).resolve().parents[3] / "Dockerfile").read_text()
    assert "ash_scorecard_plugins" in dockerfile
    assert "scorecard" in _licenses_only_line(dockerfile).split()
    assert "RUN scorecard version" in dockerfile


def test_both_stages_load_the_module():
    dockerfile = (Path(__file__).resolve().parents[3] / "Dockerfile").read_text()
    lines = [
        line
        for line in dockerfile.splitlines()
        if line.startswith("ARG ASH_ALPHA_PLUGIN_MODULES=")
    ]
    assert len(lines) == 2
    for line in lines:
        assert "automated_security_helper.plugin_modules.ash_scorecard_plugins" in line


def _licenses_only_line(dockerfile: str) -> str:
    for line in dockerfile.splitlines():
        if "--licenses-only" in line and "bandit" in line:
            return line
    raise AssertionError("the Python tools' --licenses-only line is missing")
