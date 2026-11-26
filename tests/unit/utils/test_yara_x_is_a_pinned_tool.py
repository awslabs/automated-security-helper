# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""yara-x, the alpha pattern-matching scanner's tool, is a pinned tool.

YARA-X is pinned by its own module (``ash_yara_x_plugins/yara_x_install.py``) rather
than ``tool_downloads``' shared tables, so the agreement the shared coverage test gives
TOOL_VERSIONS tools -- a license entry recording the same release the installer
places -- is asserted here instead. The executable is ``yr``, not ``yara-x``, so the
entry names it, and ``yr --version`` is the version check.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from automated_security_helper.plugin_modules.ash_yara_x_plugins.yara_x_install import (
    ASSETS,
    YARA_X_VERSION,
)
from automated_security_helper.plugin_modules.ash_yara_x_plugins.yara_x_scanner import (
    YaraXScanner,
)
from automated_security_helper.utils.tool_downloads import THIRD_PARTY_LICENSES

pytestmark = pytest.mark.unit


def test_the_license_entry_names_the_installers_pin():
    entry = THIRD_PARTY_LICENSES["yara-x"]
    assert entry.version == YARA_X_VERSION == "v1.23.0"
    assert entry.license == "BSD-3-Clause"
    assert entry.repository == "https://github.com/VirusTotal/yara-x"
    assert len(entry.commit) == 40
    # The release archives hold the executable alone, and install-pinned-tool never
    # sees them anyway, so the staged copy is the repository's LICENSE fetched at the
    # pinned commit.
    license_files = [f for f in entry.files if f.name == "LICENSE"]
    assert len(license_files) == 1
    assert license_files[0].url is not None and entry.commit in license_files[0].url
    assert len(license_files[0].sha256) == 64


def test_the_version_check_runs_the_yr_executable():
    entry = THIRD_PARTY_LICENSES["yara-x"]
    assert entry.executables == ("yr",)
    assert not entry.version_probe


def test_the_register_citation_names_the_pinned_release():
    citation = YaraXScanner.operational_facets.provenance.upstream_license
    assert citation.startswith("BSD-3-Clause (source: ")
    assert YARA_X_VERSION in citation


def test_the_installer_covers_every_published_platform():
    # YARA-X publishes no windows/arm64 build.
    assert sorted(ASSETS) == [
        ("darwin", "amd64"),
        ("darwin", "arm64"),
        ("linux", "amd64"),
        ("linux", "arm64"),
        ("windows", "amd64"),
    ]


def test_the_image_installs_and_attributes_the_pinned_yara_x():
    dockerfile = (Path(__file__).resolve().parents[3] / "Dockerfile").read_text()
    assert "ash_yara_x_plugins" in dockerfile
    assert "yara-x" in _licenses_only_line(dockerfile).split()
    assert "RUN yr --version" in dockerfile


def _licenses_only_line(dockerfile: str) -> str:
    for line in dockerfile.splitlines():
        if "--licenses-only" in line and "bandit" in line:
            return line
    raise AssertionError("the Python tools' --licenses-only line is missing")
