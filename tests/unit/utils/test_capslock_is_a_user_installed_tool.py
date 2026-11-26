# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""capslock's pin is scanner-side, and the image deliberately does not carry it.

Capslock publishes no release binaries, and it loads the scanned module's packages
by running the go command, which the ASH image does not carry. So it has no
``THIRD_PARTY_LICENSES`` entry (an entry is a claim the image bundles the tool), no
place in the image's alpha module list, no ``--licenses-only`` slot and no version
check in the image: the same class credsweeper, secretlint and dependency-check are
in. Like theirs, its install path is the plugin's own: ``ash dependencies install``
builds the pinned module with go (``capslock_install.py``), outside the shared
provisioning registry. What the plugin pins is the module version it is read
against and builds, the install command, the module digest the Go checksum database
records for that version, and the license read at the version's commit. These tests
pin that state so a later edit flips it deliberately rather than by drift.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from automated_security_helper.base.plugin_provisioning import (
    PROVISIONING,
    provisioning_for,
)
from automated_security_helper.plugin_modules.ash_capslock_plugins import (
    capslock_scanner as cs,
)
from automated_security_helper.plugin_modules.ash_capslock_plugins.capslock_install import (
    capslock_install_commands,
)
from automated_security_helper.plugin_modules.ash_capslock_plugins.capslock_scanner import (
    CapslockScanner,
)
from automated_security_helper.utils.tool_downloads import THIRD_PARTY_LICENSES

pytestmark = pytest.mark.unit

DOCKERFILE = Path(__file__).resolve().parents[3] / "Dockerfile"


def test_the_install_command_names_the_pinned_module_version():
    assert re.fullmatch(r"v\d+\.\d+\.\d+", cs.CAPSLOCK_VERSION)
    assert cs.INSTALL_COMMAND == (
        f"go install github.com/google/capslock/cmd/capslock@{cs.CAPSLOCK_VERSION}"
    )
    assert "@latest" not in cs.INSTALL_COMMAND


def test_the_pin_records_a_commit_a_module_digest_and_a_license_digest():
    assert re.fullmatch(r"[0-9a-f]{40}", cs.CAPSLOCK_COMMIT)
    # A dirhash h1 digest: "h1:" and the base64 of a SHA256 (44 characters).
    assert re.fullmatch(r"h1:[A-Za-z0-9+/]{43}=", cs.CAPSLOCK_MODULE_SUM)
    assert re.fullmatch(r"[0-9a-f]{64}", cs.CAPSLOCK_LICENSE_SHA256)


def test_the_register_carries_the_license_read_at_the_pin():
    citation = CapslockScanner.operational_facets.provenance.upstream_license
    assert citation.startswith("BSD-3-Clause (source: the LICENSE file of ")
    for pinned in (
        cs.CAPSLOCK_VERSION,
        cs.CAPSLOCK_COMMIT[:7],
        cs.CAPSLOCK_LICENSE_SHA256,
    ):
        assert pinned in citation


def test_the_install_is_the_plugins_own_not_the_shared_registry(tmp_path, monkeypatch):
    # The shared registry pins release assets; Capslock has none, so its pin and
    # its go install build live in the plugin module.
    assert "capslock" not in PROVISIONING
    assert provisioning_for("capslock").tool_pins == ()
    monkeypatch.setenv("ASH_BIN_PATH", str(tmp_path / "bin"))
    table = capslock_install_commands()
    assert table["linux"]["amd64"]
    assert "install_capslock" in " ".join(table["linux"]["amd64"][0].args)


def test_the_image_does_not_claim_to_bundle_capslock():
    """No license entry and no image wiring while the image carries no Go toolchain."""
    assert "capslock" not in THIRD_PARTY_LICENSES
    dockerfile = DOCKERFILE.read_text()
    assert "ash_capslock_plugins" not in dockerfile
    assert "capslock" not in _licenses_only_line(dockerfile)
    assert "RUN capslock" not in dockerfile
    # The reason is recorded where the next editor will look, with the version a
    # user installs.
    assert "Capslock (alpha scanner) is NOT in the image" in dockerfile
    assert cs.INSTALL_COMMAND in dockerfile


def _licenses_only_line(dockerfile: str) -> str:
    for line in dockerfile.splitlines():
        if "--licenses-only" in line and "bandit" in line:
            return line
    raise AssertionError("the Python tools' --licenses-only line is missing")
