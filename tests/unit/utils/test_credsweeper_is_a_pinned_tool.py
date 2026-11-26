# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""credsweeper, the alpha secret scanner's uv tool, is a pinned tool.

A Python tool follows the bandit/checkov/guarddog shape rather than the binary
one: no release-asset table, a ``ThirdPartyLicense`` entry whose
``distribution`` is the PyPI name, license files read from the installed
wheel's dist-info, and image wiring through ``--uv-tool-pins`` (which pins
``scanners.credsweeper.options.tool_version`` to the entry's version) plus the
``--licenses-only`` line. The entry's version is the release the register's
license read was made on (the LICENSE in the 1.19.7 wheel), so the files and
commit describe the release the image installs.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from automated_security_helper.plugin_modules.ash_credsweeper_plugins.credsweeper_scanner import (
    CREDSWEEPER_DEFAULT_VERSION_CONSTRAINT,
    CredSweeperScanner,
)
from automated_security_helper.utils.tool_downloads import THIRD_PARTY_LICENSES

pytestmark = pytest.mark.unit


def test_the_license_entry_is_the_uv_tool_shape():
    entry = THIRD_PARTY_LICENSES["credsweeper"]
    assert entry.version == "1.19.7"
    assert entry.license == "MIT"
    assert entry.repository == "https://github.com/Samsung/CredSweeper"
    assert len(entry.commit) == 40
    assert entry.distribution == "credsweeper"
    assert [f.name for f in entry.files] == ["LICENSE"]


def test_the_entry_version_is_the_registers_read_and_satisfies_the_constraint():
    entry = THIRD_PARTY_LICENSES["credsweeper"]
    citation = CredSweeperScanner.operational_facets.provenance.upstream_license
    assert entry.version in citation, (
        "the register's license read and the license entry name different "
        "releases; re-read the license at the entry's version"
    )
    # The scanner's own default is a range; the image pins inside it.
    low, high = "1.19.6", "2.0.0"
    assert CREDSWEEPER_DEFAULT_VERSION_CONSTRAINT == f">={low},<{high}"
    parts = tuple(int(p) for p in entry.version.split("."))
    assert (
        tuple(int(p) for p in low.split("."))
        <= parts
        < tuple(int(p) for p in high.split("."))
    )


def test_the_image_installs_and_attributes_the_pinned_credsweeper():
    dockerfile = (Path(__file__).resolve().parents[3] / "Dockerfile").read_text()
    # Installed by `ash dependencies install` through uv with the --uv-tool-pins
    # override, which needs the plugin module loaded for that install.
    assert "ash_credsweeper_plugins" in dockerfile
    # Its license files come from the installed wheel's dist-info.
    assert "credsweeper" in _licenses_only_line(dockerfile)
    # A failed install fails the build, not the first scan that enables it.
    assert "RUN credsweeper --version" in dockerfile


def _licenses_only_line(dockerfile: str) -> str:
    for line in dockerfile.splitlines():
        if "--licenses-only" in line and "bandit" in line:
            return line
    raise AssertionError("the Python tools' --licenses-only line is missing")
