# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""spectral, the alpha API-description scanner's tool, is a pinned tool.

Spectral is pinned by its own module (``ash_spectral_plugins/spectral_install.py``)
rather than ``tool_downloads``' shared tables, so the agreement the shared coverage
test gives TOOL_VERSIONS tools -- a license entry recording the same release the
installer places -- is asserted here instead. ``spectral --version`` prints the bare
version (``6.17.1``), so the entry needs no version probe: the image's check runs the
executable on PATH like any other bundled tool's.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from automated_security_helper.plugin_modules.ash_spectral_plugins.spectral_install import (
    ASSETS,
    DIGESTS_TAKEN_AT,
    SPECTRAL_VERSION,
)
from automated_security_helper.plugin_modules.ash_spectral_plugins.spectral_scanner import (
    SpectralScanner,
)
from automated_security_helper.utils.tool_downloads import (
    THIRD_PARTY_LICENSES,
    TOOL_VERSIONS,
)

pytestmark = pytest.mark.unit


def test_the_license_entry_names_the_installers_pin():
    entry = THIRD_PARTY_LICENSES["spectral"]
    assert entry.version == SPECTRAL_VERSION == DIGESTS_TAKEN_AT == "v6.17.1"
    assert entry.license == "Apache-2.0"
    assert entry.repository == "https://github.com/stoplightio/spectral"
    assert len(entry.commit) == 40
    # The release publishes bare executables with no license file beside them, so
    # the staged copy is the repository's, pinned by its URL at the commit and by
    # its SHA256.
    (license_file,) = entry.files
    assert license_file.name == "LICENSE"
    assert license_file.url is not None and entry.commit in license_file.url
    assert license_file.sha256 is not None and len(license_file.sha256) == 64


def test_the_version_check_is_the_executables_own_version_flag():
    entry = THIRD_PARTY_LICENSES["spectral"]
    assert entry.version_probe == ()
    assert entry.executable_names == ("spectral",)


def test_the_shared_table_does_not_pin_it_a_second_time():
    # One pin in one place: a TOOL_VERSIONS row would be a second pin, and would need
    # a register row claiming it as a PINNED_BINARY.
    assert "spectral" not in TOOL_VERSIONS


def test_the_register_citation_names_the_pinned_release():
    citation = SpectralScanner.operational_facets.provenance.upstream_license
    assert citation.startswith("Apache-2.0 (source: the repository LICENSE at the ")
    assert SPECTRAL_VERSION in citation
    assert THIRD_PARTY_LICENSES["spectral"].commit[:12] in citation


def test_the_installer_covers_every_published_platform():
    # Spectral publishes no Windows arm64 build, and its musl builds are not used.
    assert sorted(ASSETS) == [
        ("darwin", "amd64"),
        ("darwin", "arm64"),
        ("linux", "amd64"),
        ("linux", "arm64"),
        ("windows", "amd64"),
    ]


def test_the_image_installs_and_attributes_the_pinned_spectral():
    dockerfile = (Path(__file__).resolve().parents[3] / "Dockerfile").read_text()
    assert "ash_spectral_plugins" in dockerfile
    assert "spectral" in _licenses_only_line(dockerfile).split()
    assert "RUN spectral --version" in dockerfile


def _licenses_only_line(dockerfile: str) -> str:
    for line in dockerfile.splitlines():
        if "--licenses-only" in line and "bandit" in line:
            return line
    raise AssertionError("the Python tools' --licenses-only line is missing")
