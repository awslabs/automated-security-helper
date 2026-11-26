# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""cargo-audit, the alpha Rust dependency scanner's tool, is a pinned tool.

cargo-audit is pinned by its own module (``ash_cargo_audit_plugins/cargo_audit_install.py``)
rather than ``tool_downloads``' shared tables, so the agreement the shared coverage
test gives TOOL_VERSIONS tools -- a license entry recording the same release the
installer places -- is asserted here instead. The crate lives in the rustsec monorepo,
so its license files are read from the crate's directory at the tag's commit, and the
tag carries the crate's prefix.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from automated_security_helper.plugin_modules.ash_cargo_audit_plugins.cargo_audit_install import (
    ASSETS,
    CARGO_AUDIT_VERSION,
    RELEASE_TAG,
)
from automated_security_helper.plugin_modules.ash_cargo_audit_plugins.cargo_audit_scanner import (
    CargoAuditScanner,
)
from automated_security_helper.utils.tool_downloads import THIRD_PARTY_LICENSES

pytestmark = pytest.mark.unit


def test_the_license_entry_names_the_installers_pin():
    entry = THIRD_PARTY_LICENSES["cargo-audit"]
    assert entry.version == CARGO_AUDIT_VERSION == "v0.23.0"
    assert entry.tag == RELEASE_TAG == "cargo-audit/v0.23.0"
    assert entry.license == "Apache-2.0 OR MIT"
    assert entry.repository == "https://github.com/rustsec/rustsec"
    assert len(entry.commit) == 40
    assert not entry.copyleft


def test_both_license_texts_come_from_the_crate_directory_at_the_pinned_commit():
    # The archives carry byte-identical copies, but install-pinned-tool never sees
    # cargo-audit's archive, so the staged copies are the URL-pinned ones.
    entry = THIRD_PARTY_LICENSES["cargo-audit"]
    by_name = {f.name: f for f in entry.files}
    assert sorted(by_name) == ["LICENSE-APACHE", "LICENSE-MIT"]
    for name, license_file in by_name.items():
        assert license_file.url == (
            "https://raw.githubusercontent.com/rustsec/rustsec/"
            f"{entry.commit}/cargo-audit/{name}"
        )
        assert len(license_file.sha256) == 64


def test_the_version_check_is_the_plain_version_flag():
    # `cargo-audit --version` prints "cargo-audit 0.23.0", so no probe is needed.
    entry = THIRD_PARTY_LICENSES["cargo-audit"]
    assert entry.version_probe == ()
    assert entry.executable_names == ("cargo-audit",)


def test_the_register_citation_names_the_pinned_release():
    citation = CargoAuditScanner.operational_facets.provenance.upstream_license
    assert citation.startswith("Apache-2.0 OR MIT (source: ")
    assert CARGO_AUDIT_VERSION in citation


def test_the_installer_covers_every_platform_ash_names():
    # No 386 build is published, the Windows build is amd64 only, and the armv7
    # build has no ASH platform name.
    assert sorted(ASSETS) == [
        ("darwin", "amd64"),
        ("darwin", "arm64"),
        ("linux", "amd64"),
        ("linux", "arm64"),
        ("windows", "amd64"),
    ]


def test_the_image_installs_and_attributes_the_pinned_cargo_audit():
    dockerfile = (Path(__file__).resolve().parents[3] / "Dockerfile").read_text()
    assert dockerfile.count("ash_cargo_audit_plugins") == 2, (
        "both ASH_ALPHA_PLUGIN_MODULES declarations load the module"
    )
    assert "cargo-audit" in _licenses_only_line(dockerfile).split()
    assert 'RUN reported="$(cargo-audit --version)"' in dockerfile
    assert 'test "${reported}" = "cargo-audit ${CARGO_AUDIT_VERSION#v}"' in dockerfile


def test_the_dockerfile_version_arg_is_the_modules_pin():
    """The image's version check and the pin checker read this ARG; it must not drift."""
    dockerfile = (Path(__file__).resolve().parents[3] / "Dockerfile").read_text()
    args = re.findall(
        r'^ARG CARGO_AUDIT_VERSION="([^"]+)"$', dockerfile, flags=re.MULTILINE
    )
    assert args == [CARGO_AUDIT_VERSION]
    assert THIRD_PARTY_LICENSES["cargo-audit"].version == CARGO_AUDIT_VERSION


def _licenses_only_line(dockerfile: str) -> str:
    for line in dockerfile.splitlines():
        if "--licenses-only" in line and "bandit" in line:
            return line.rstrip("'")
    raise AssertionError("the Python tools' --licenses-only line is missing")
