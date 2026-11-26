# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""binskim, the alpha binary-hardening scanner's tool, is a pinned tool.

BinSkim is pinned by its own module (``ash_binskim_plugins/binskim_install.py``)
rather than ``tool_downloads``' shared tables, so the agreement the shared coverage
test gives TOOL_VERSIONS tools -- a license entry recording the same release the
installer places -- is asserted here instead. The NuGet package holds no license file,
so the entry's LICENSE is the repository's at the commit the release tag names. The
version probe sets invariant globalization because the image has no ICU, without
which the .NET runtime inside BinSkim stops before it starts.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from automated_security_helper.plugin_modules.ash_binskim_plugins.binskim_install import (
    BINSKIM_VERSION,
    RIDS,
)
from automated_security_helper.plugin_modules.ash_binskim_plugins.binskim_scanner import (
    GLOBALIZATION_INVARIANT_ENV,
    BinskimScanner,
)
from automated_security_helper.utils.tool_downloads import THIRD_PARTY_LICENSES

pytestmark = pytest.mark.unit


def test_the_license_entry_names_the_installers_pin():
    entry = THIRD_PARTY_LICENSES["binskim"]
    assert entry.version == f"v{BINSKIM_VERSION}" == "v4.4.9.14"
    assert entry.license == "MIT"
    assert entry.repository == "https://github.com/microsoft/binskim"
    assert entry.commit == "170f8f8de91851c5196acf8221bd7eb9e6d960f9"
    license_files = [f for f in entry.files if f.name == "LICENSE"]
    assert len(license_files) == 1
    assert license_files[0].url is not None and entry.commit in license_files[0].url
    assert len(license_files[0].sha256) == 64


def test_the_version_check_runs_with_invariant_globalization():
    entry = THIRD_PARTY_LICENSES["binskim"]
    assert entry.version_probe == (
        "env",
        f"{GLOBALIZATION_INVARIANT_ENV}=1",
        "BinSkim",
        "--version",
    )
    assert not entry.executables


def test_the_register_citation_names_the_pinned_release():
    citation = BinskimScanner.operational_facets.provenance.upstream_license
    assert citation.startswith("MIT (source: the LICENSE file of microsoft/binskim ")
    assert f"v{BINSKIM_VERSION}" in citation
    assert THIRD_PARTY_LICENSES["binskim"].commit in citation


def test_the_installer_covers_every_published_build():
    # The package holds no osx-arm64, 32-bit or win-arm64 build.
    assert sorted(RIDS) == [
        ("darwin", "amd64"),
        ("linux", "amd64"),
        ("linux", "arm64"),
        ("windows", "amd64"),
    ]


def test_the_image_installs_and_attributes_the_pinned_binskim():
    dockerfile = (Path(__file__).resolve().parents[3] / "Dockerfile").read_text()
    assert "ash_binskim_plugins" in dockerfile
    assert "binskim" in _licenses_only_line(dockerfile).split()
    assert f"RUN {GLOBALIZATION_INVARIANT_ENV}=1 BinSkim --version" in dockerfile


def _licenses_only_line(dockerfile: str) -> str:
    for line in dockerfile.splitlines():
        if "--licenses-only" in line and "bandit" in line:
            return line.strip("'")
    raise AssertionError("the Python tools' --licenses-only line is missing")
