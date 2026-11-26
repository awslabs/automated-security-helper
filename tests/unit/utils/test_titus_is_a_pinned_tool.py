# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""titus, the alpha secret scanner's tool, is a pinned tool.

Titus is pinned by its own module (``ash_titus_plugins/titus_install.py``) rather
than ``tool_downloads``' shared tables, so the agreement the shared coverage test
gives TOOL_VERSIONS tools -- a license entry recording the same release the
installer places -- is asserted here instead. The release assets are bare
executables, so the license entry stages the repository's LICENSE and NOTICE at the
pinned commit. The entry's version probe is ``titus version`` because ``titus
--version`` is an unknown flag.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from automated_security_helper.plugin_modules.ash_titus_plugins.titus_install import (
    ASSETS,
    TITUS_VERSION,
)
from automated_security_helper.plugin_modules.ash_titus_plugins.titus_scanner import (
    TitusScanner,
)
from automated_security_helper.utils.tool_downloads import THIRD_PARTY_LICENSES

pytestmark = pytest.mark.unit


def test_the_license_entry_names_the_installers_pin():
    entry = THIRD_PARTY_LICENSES["titus"]
    assert entry.version == TITUS_VERSION == "v1.3.0"
    assert entry.license == "Apache-2.0"
    assert entry.repository == "https://github.com/praetorian-inc/titus"
    assert len(entry.commit) == 40
    # Both files come from the repository at the pinned commit: the release
    # publishes bare executables, with no archive to read a LICENSE from.
    assert [f.name for f in entry.files] == ["LICENSE", "NOTICE"]
    for license_file in entry.files:
        assert license_file.url is not None and entry.commit in license_file.url
        assert len(license_file.sha256) == 64


def test_the_version_check_is_the_version_subcommand():
    entry = THIRD_PARTY_LICENSES["titus"]
    assert entry.version_probe == ("titus", "version")
    assert not entry.executables


def test_the_register_citation_names_the_pinned_release():
    citation = TitusScanner.operational_facets.provenance.upstream_license
    assert citation.startswith("Apache-2.0 (source: the LICENSE file in the ")
    assert TITUS_VERSION in citation


def test_the_installer_covers_every_published_platform():
    # Titus publishes no 386 build and no windows/arm64 build.
    assert sorted(ASSETS) == [
        ("darwin", "amd64"),
        ("darwin", "arm64"),
        ("linux", "amd64"),
        ("linux", "arm64"),
        ("windows", "amd64"),
    ]


def test_the_image_installs_and_attributes_the_pinned_titus():
    dockerfile = (Path(__file__).resolve().parents[3] / "Dockerfile").read_text()
    assert "ash_titus_plugins" in dockerfile
    assert "titus" in _licenses_only_line(dockerfile).split()
    assert "RUN titus version" in dockerfile


def _licenses_only_line(dockerfile: str) -> str:
    for line in dockerfile.splitlines():
        if "--licenses-only" in line and "bandit" in line:
            return line
    raise AssertionError("the Python tools' --licenses-only line is missing")
