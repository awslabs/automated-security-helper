# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""capa's pin stays scanner-side; the image deliberately does not carry it.

capa is pinned by its own module (``ash_capa_plugins/capa_install.py``) rather than
``tool_downloads``' shared tables. The intended image shape was the Polaris one (the
module in the image's alpha list, the license on the ``--licenses-only`` line, a
version check), and the image cannot hold it: every Linux build of the v10.0.0
standalone release unpacks a libpython that needs ``GLIBC_2.38``, and the image's
bookworm base has glibc 2.36 (measured: ``capa --version`` exits 255 with "version
`GLIBC_2.38' not found" in the base image). A ``THIRD_PARTY_LICENSES`` entry is a
claim the image bundles the tool, so capa has no entry and no image wiring, the class
credsweeper is in, and these tests pin that state so a later edit flips it
deliberately rather than by drift.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from automated_security_helper.plugin_modules.ash_capa_plugins.capa_install import (
    ASSETS,
    CAPA_VERSION,
    LINUX_GLIBC_FLOOR,
)
from automated_security_helper.plugin_modules.ash_capa_plugins.capa_scanner import (
    CapaScanner,
)
from automated_security_helper.utils.tool_downloads import THIRD_PARTY_LICENSES

pytestmark = pytest.mark.unit

DOCKERFILE = Path(__file__).resolve().parents[3] / "Dockerfile"


def test_the_register_carries_the_license_read_at_the_pinned_tag():
    citation = CapaScanner.operational_facets.provenance.upstream_license
    assert citation.startswith("Apache-2.0 (source: LICENSE.txt at the v10.0.0 tag")
    assert CAPA_VERSION in citation
    # The commit the tag names and the SHA256 of the file read there.
    assert "85813ebc5b99ccdbe43147e46796d0bd6700f30a" in citation
    assert (
        "cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30" in citation
    )


def test_the_installer_covers_every_published_platform():
    # capa publishes no Windows arm64 build and no 386 build.
    assert sorted(ASSETS) == [
        ("darwin", "amd64"),
        ("darwin", "arm64"),
        ("linux", "amd64"),
        ("linux", "arm64"),
        ("windows", "amd64"),
    ]
    assert CAPA_VERSION == "v10.0.0"


def test_the_image_does_not_claim_to_bundle_capa():
    """No license entry and no image wiring while the Linux glibc floor is 2.38."""
    assert LINUX_GLIBC_FLOOR == "2.38"
    assert "capa" not in THIRD_PARTY_LICENSES
    dockerfile = DOCKERFILE.read_text()
    assert 'ash_capa_plugins"' not in dockerfile
    assert "plugin_modules.ash_capa_plugins" not in dockerfile
    assert " capa " not in f" {_licenses_only_line(dockerfile)} "
    assert "RUN capa" not in dockerfile
    # The measured reason is recorded where the next editor will look.
    assert "GLIBC_2.38" in dockerfile


def _licenses_only_line(dockerfile: str) -> str:
    for line in dockerfile.splitlines():
        if "--licenses-only" in line and "bandit" in line:
            return line
    raise AssertionError("the Python tools' --licenses-only line is missing")
