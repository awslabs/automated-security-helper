# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""ggshield, the alpha secret scanner's uv tool, is a pinned tool.

Same uv-tool shape as credsweeper (and bandit/checkov/guarddog before it): a
``ThirdPartyLicense`` entry with ``distribution`` set, license files from the
installed wheel's dist-info, and image wiring through ``--uv-tool-pins`` and
``--licenses-only``. The entry's version is the one the register's license read
cites (the 1.56.1 wheel's ``licenses/LICENSE``, whose sha256 the citation
records), which is also the scanner's own default constraint ``==1.56.1``.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from automated_security_helper.plugin_modules.ash_ggshield_plugins.ggshield_scanner import (
    GGSHIELD_DEFAULT_VERSION_CONSTRAINT,
    LICENSE_CITATION,
)
from automated_security_helper.utils.tool_downloads import THIRD_PARTY_LICENSES

pytestmark = pytest.mark.unit


def test_the_license_entry_is_the_uv_tool_shape():
    entry = THIRD_PARTY_LICENSES["ggshield"]
    assert entry.version == "1.56.1"
    assert entry.license == "MIT"
    assert entry.repository == "https://github.com/GitGuardian/ggshield"
    assert len(entry.commit) == 40
    assert entry.distribution == "ggshield"
    assert [f.name for f in entry.files] == ["LICENSE"]


def test_the_entry_version_is_the_registers_read_and_the_default_pin():
    entry = THIRD_PARTY_LICENSES["ggshield"]
    assert entry.version in LICENSE_CITATION, (
        "the register's license read and the license entry name different "
        "releases; re-read the license at the entry's version"
    )
    assert GGSHIELD_DEFAULT_VERSION_CONSTRAINT == f"=={entry.version}"


def test_the_image_installs_and_attributes_the_pinned_ggshield():
    dockerfile = (Path(__file__).resolve().parents[3] / "Dockerfile").read_text()
    assert "ash_ggshield_plugins" in dockerfile
    assert "ggshield" in _licenses_only_line(dockerfile)
    assert "RUN ggshield --version" in dockerfile


def _licenses_only_line(dockerfile: str) -> str:
    for line in dockerfile.splitlines():
        if "--licenses-only" in line and "bandit" in line:
            return line
    raise AssertionError("the Python tools' --licenses-only line is missing")
