# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""osv-scanner, the alpha SCA scanner's tool, is a pinned tool.

OSV-Scanner is pinned by its own module (``ash_osv_scanner_plugins/osv_scanner_install.py``)
rather than ``tool_downloads``' shared tables, so the agreement the shared coverage
test gives TOOL_VERSIONS tools -- a license entry recording the same release the
installer places -- is asserted here instead. ``osv-scanner --version`` works, so the
entry keeps the default version check (the executable on PATH must report 2.7.1).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from automated_security_helper.plugin_modules.ash_osv_scanner_plugins.osv_scanner_install import (
    ASSETS,
    OSV_SCANNER_VERSION,
)
from automated_security_helper.plugin_modules.ash_osv_scanner_plugins.osv_scanner_scanner import (
    OsvScannerScanner,
)
from automated_security_helper.utils.tool_downloads import (
    THIRD_PARTY_LICENSES,
    TOOL_VERSIONS,
)

pytestmark = pytest.mark.unit


def test_the_license_entry_names_the_installers_pin():
    entry = THIRD_PARTY_LICENSES["osv-scanner"]
    assert entry.version == OSV_SCANNER_VERSION == "v2.7.1"
    assert entry.license == "Apache-2.0"
    assert entry.repository == "https://github.com/google/osv-scanner"
    assert len(entry.commit) == 40
    # The release publishes bare executables, so the LICENSE is staged from the
    # repository at the pinned commit, by URL and digest.
    license_files = [f for f in entry.files if f.name == "LICENSE"]
    assert len(license_files) == 1
    assert license_files[0].url is not None and entry.commit in license_files[0].url
    assert len(license_files[0].sha256) == 64


def test_the_version_check_is_the_executables_own():
    entry = THIRD_PARTY_LICENSES["osv-scanner"]
    assert entry.version_probe == ()
    assert entry.executable_names == ("osv-scanner",)


def test_the_shared_download_table_does_not_pin_it_twice():
    assert "osv-scanner" not in TOOL_VERSIONS


def test_the_register_citation_names_the_pinned_release():
    citation = OsvScannerScanner.operational_facets.provenance.upstream_license
    assert citation.startswith("Apache-2.0 (source: the repository LICENSE at the ")
    assert OSV_SCANNER_VERSION in citation


def test_the_installer_covers_every_published_platform():
    # OSV-Scanner publishes linux, darwin and windows builds for amd64 and arm64.
    assert sorted(ASSETS) == [
        ("darwin", "amd64"),
        ("darwin", "arm64"),
        ("linux", "amd64"),
        ("linux", "arm64"),
        ("windows", "amd64"),
        ("windows", "arm64"),
    ]


def test_the_image_installs_and_attributes_the_pinned_osv_scanner():
    dockerfile = (Path(__file__).resolve().parents[3] / "Dockerfile").read_text()
    assert "ash_osv_scanner_plugins" in dockerfile
    assert "osv-scanner" in _licenses_only_line(dockerfile).split()
    assert "RUN osv-scanner --version" in dockerfile


def _licenses_only_line(dockerfile: str) -> str:
    for line in dockerfile.splitlines():
        if "--licenses-only" in line and "bandit" in line:
            return line
    raise AssertionError("the Python tools' --licenses-only line is missing")
