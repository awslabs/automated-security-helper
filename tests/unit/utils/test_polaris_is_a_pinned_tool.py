# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""polaris, the alpha Kubernetes-manifest scanner's tool, is a pinned tool.

Polaris is pinned by its own module (``ash_polaris_plugins/polaris_install.py``)
rather than ``tool_downloads``' shared tables, so the agreement the shared
coverage test gives TOOL_VERSIONS tools -- a license entry recording the same
release the installer places -- is asserted here instead. The entry's version
probe is ``polaris version`` because ``polaris --version`` is an unknown flag.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from automated_security_helper.plugin_modules.ash_polaris_plugins.polaris_install import (
    ASSETS,
    POLARIS_VERSION,
)
from automated_security_helper.plugin_modules.ash_polaris_plugins.polaris_scanner import (
    PolarisScanner,
)
from automated_security_helper.utils.tool_downloads import THIRD_PARTY_LICENSES

pytestmark = pytest.mark.unit


def test_the_license_entry_names_the_installers_pin():
    entry = THIRD_PARTY_LICENSES["polaris"]
    assert entry.version == POLARIS_VERSION == "v10.2.6"
    assert entry.license == "Apache-2.0"
    assert entry.repository == "https://github.com/FairwindsOps/polaris"
    assert len(entry.commit) == 40
    # The archive carries a LICENSE byte-identical to the repository's at the
    # pinned commit, but install-pinned-tool never sees polaris's archive, so the
    # staged copy is the URL-pinned one.
    license_files = [f for f in entry.files if f.name == "LICENSE"]
    assert len(license_files) == 1
    assert license_files[0].url is not None and entry.commit in license_files[0].url
    assert len(license_files[0].sha256) == 64


def test_the_version_check_is_the_version_subcommand():
    entry = THIRD_PARTY_LICENSES["polaris"]
    assert entry.version_probe == ("polaris", "version")
    assert not entry.executables


def test_the_register_citation_names_the_pinned_release():
    citation = PolarisScanner.operational_facets.provenance.upstream_license
    assert citation.startswith("Apache-2.0 (source: the LICENSE file inside the ")
    assert POLARIS_VERSION in citation


def test_the_installer_covers_every_published_platform():
    # Polaris publishes no 386 build and its Windows build is amd64 only.
    assert sorted(ASSETS) == [
        ("darwin", "amd64"),
        ("darwin", "arm64"),
        ("linux", "amd64"),
        ("linux", "arm64"),
        ("windows", "amd64"),
    ]


def test_the_image_installs_and_attributes_the_pinned_polaris():
    dockerfile = (Path(__file__).resolve().parents[3] / "Dockerfile").read_text()
    assert "ash_polaris_plugins" in dockerfile
    assert "polaris" in _licenses_only_line(dockerfile)
    assert "RUN polaris version" in dockerfile


def _licenses_only_line(dockerfile: str) -> str:
    for line in dockerfile.splitlines():
        if "--licenses-only" in line and "bandit" in line:
            return line
    raise AssertionError("the Python tools' --licenses-only line is missing")
