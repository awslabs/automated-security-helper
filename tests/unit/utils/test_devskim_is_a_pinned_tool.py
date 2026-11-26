# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""devskim's pin stays scanner-side; the image deliberately does not carry it.

DevSkim is pinned by its own module (``ash_devskim_plugins/devskim_install.py``: the
1.0.103 NuGet package and its SHA256), not by ``tool_downloads``' shared tables. The
package holds framework-dependent .NET builds and no executable, so DevSkim runs only
where a .NET runtime is installed, and the ASH image carries none. A license entry is a
claim the image bundles the tool, so until the image has a .NET runtime (the class
credsweeper's compiler, secretlint's Node and dependency-check's Java are in), devskim
has no entry and no image wiring, and these tests pin that state so a later edit flips
it deliberately rather than by drift.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from automated_security_helper.plugin_modules.ash_devskim_plugins.devskim_install import (
    DEVSKIM_VERSION,
)
from automated_security_helper.plugin_modules.ash_devskim_plugins.devskim_scanner import (
    DevSkimScanner,
)
from automated_security_helper.utils.tool_downloads import (
    THIRD_PARTY_LICENSES,
    TOOL_VERSIONS,
)

pytestmark = pytest.mark.unit


def test_the_register_carries_the_license_read():
    citation = DevSkimScanner.operational_facets.provenance.upstream_license
    assert citation.startswith("MIT (source: LICENSE.txt in the DevSkim repository at ")
    assert "7f8e5e24f62d9ba95f261e7f45b4b1c293a59a51" in citation
    assert DEVSKIM_VERSION in citation


def test_the_shared_download_table_has_no_devskim_pin():
    assert "devskim" not in TOOL_VERSIONS


def test_the_image_does_not_claim_to_bundle_devskim():
    """No license entry and no image wiring until the image carries a .NET runtime."""
    assert "devskim" not in THIRD_PARTY_LICENSES
    dockerfile = (Path(__file__).resolve().parents[3] / "Dockerfile").read_text()
    assert "ash_devskim_plugins" not in dockerfile
    assert "devskim" not in _licenses_only_line(dockerfile)
    assert "RUN devskim" not in dockerfile
    # The measured reason is recorded where the next editor will look.
    assert "this image carries no .NET runtime" in dockerfile


def _licenses_only_line(dockerfile: str) -> str:
    for line in dockerfile.splitlines():
        if "--licenses-only" in line and "bandit" in line:
            return line
    raise AssertionError("the Python tools' --licenses-only line is missing")
