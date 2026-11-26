# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""credsweeper's pin stays scanner-side; the image deliberately does not carry it.

The intended shape was the bandit/checkov/guarddog one (a ``ThirdPartyLicense``
entry with ``distribution``, the module in the image's alpha list, a wheel
license on the ``--licenses-only`` line), and the first image build refused it:
credsweeper 1.19.7 depends on ``pyjks``, whose ``twofish==0.3.0`` dependency is
an sdist-only C extension, and the image carries no compiler (measured in the
docs-CI image build: ``error: [Errno 2] No such file or directory: 'gcc'``).
A license entry is a claim the image bundles the tool, so until the toolchain
decision is made (the same class as secretlint's Node and dependency-check's
Java), credsweeper has no entry and no image wiring, and these tests pin that
state so a later edit flips it deliberately rather than by drift.
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


def test_the_register_carries_the_license_read():
    citation = CredSweeperScanner.operational_facets.provenance.upstream_license
    assert citation.startswith("MIT (source: the LICENSE file in the credsweeper ")
    assert "1.19.7" in citation


def test_the_scanner_constraint_brackets_the_read_release():
    low, high = "1.19.6", "2.0.0"
    assert CREDSWEEPER_DEFAULT_VERSION_CONSTRAINT == f">={low},<{high}"
    read = tuple(int(p) for p in "1.19.7".split("."))
    assert (
        tuple(int(p) for p in low.split("."))
        <= read
        < tuple(int(p) for p in high.split("."))
    )


def test_the_image_does_not_claim_to_bundle_credsweeper():
    """No license entry and no image wiring until the compiler decision is made."""
    assert "credsweeper" not in THIRD_PARTY_LICENSES
    dockerfile = (Path(__file__).resolve().parents[3] / "Dockerfile").read_text()
    assert "ash_credsweeper_plugins" not in dockerfile
    assert "credsweeper" not in _licenses_only_line(dockerfile)
    assert "RUN credsweeper --version" not in dockerfile
    # The measured reason is recorded where the next editor will look.
    assert "twofish" in dockerfile


def _licenses_only_line(dockerfile: str) -> str:
    for line in dockerfile.splitlines():
        if "--licenses-only" in line and "bandit" in line:
            return line
    raise AssertionError("the Python tools' --licenses-only line is missing")
