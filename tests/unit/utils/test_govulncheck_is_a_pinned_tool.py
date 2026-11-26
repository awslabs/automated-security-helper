# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""govulncheck's pin is a module version, and the image deliberately does not carry it.

The Go project publishes govulncheck as source only, so there is no release asset
to pin by digest: the pin is ``GOVULNCHECK_VERSION`` of the module
``golang.org/x/vuln``, which ``go install`` builds and checks against the Go
checksum database. That needs a Go toolchain, and govulncheck's scans need one
too (it loads packages through ``go``). The image carries none, so it does not
carry govulncheck either: no license entry (an entry is a claim the image
bundles the tool) and no module in the image's alpha list, the same class as
credsweeper's compiler, secretlint's Node and dependency-check's Java. These
tests pin that state so a later edit flips it deliberately rather than by drift.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from automated_security_helper.plugin_modules.ash_govulncheck_plugins import (
    govulncheck_scanner as gs,
)
from automated_security_helper.utils.tool_downloads import THIRD_PARTY_LICENSES

pytestmark = pytest.mark.unit

DOCKERFILE = Path(__file__).resolve().parents[3] / "Dockerfile"


def test_the_pin_is_one_release_of_the_module():
    assert gs.GOVULNCHECK_PACKAGE == "golang.org/x/vuln/cmd/govulncheck"
    assert gs.GOVULNCHECK_VERSION == "v1.9.0"


def test_the_register_carries_the_license_read_at_the_pin():
    citation = gs.GovulncheckScanner.operational_facets.provenance.upstream_license
    assert citation.startswith(
        "BSD-3-Clause (source: the LICENSE file of the golang.org/x/vuln "
        f"{gs.GOVULNCHECK_VERSION} module"
    )


def test_the_image_does_not_claim_to_bundle_govulncheck():
    """No license entry and no image wiring until the image carries a Go toolchain."""
    assert "govulncheck" not in THIRD_PARTY_LICENSES
    dockerfile = DOCKERFILE.read_text()
    assert "ash_govulncheck_plugins" not in dockerfile
    assert "install-pinned-tool govulncheck" not in dockerfile
    assert "RUN govulncheck" not in dockerfile
    # The reason is recorded where the next editor will look.
    assert "Nor is govulncheck" in dockerfile
    assert "Go toolchain" in dockerfile
