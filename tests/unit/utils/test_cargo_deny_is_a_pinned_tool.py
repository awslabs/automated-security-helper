# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""cargo-deny, the alpha Rust dependency scanner's tool, is a pinned tool.

cargo-deny is pinned by its own module (``ash_cargo_deny_plugins/cargo_deny_install.py``)
rather than ``tool_downloads``' shared tables, so the agreement the shared coverage
test gives TOOL_VERSIONS tools -- a license entry recording the same release the
installer places -- is asserted here instead. The release is dual-licensed, so the
entry stages both license texts from the repository at the pinned commit.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from automated_security_helper.plugin_modules.ash_cargo_deny_plugins.cargo_deny_install import (
    ASSETS,
    CARGO_DENY_VERSION,
)
from automated_security_helper.plugin_modules.ash_cargo_deny_plugins.cargo_deny_scanner import (
    CargoDenyScanner,
)
from automated_security_helper.utils.tool_downloads import THIRD_PARTY_LICENSES

pytestmark = pytest.mark.unit


def test_the_license_entry_names_the_installers_pin():
    entry = THIRD_PARTY_LICENSES["cargo-deny"]
    assert entry.version == CARGO_DENY_VERSION == "0.21.0"
    assert entry.license == "MIT OR Apache-2.0"
    assert entry.repository == "https://github.com/EmbarkStudios/cargo-deny"
    assert len(entry.commit) == 40
    assert not entry.copyleft


@pytest.mark.parametrize("name", ["LICENSE-APACHE", "LICENSE-MIT"])
def test_both_license_texts_are_staged_from_the_pinned_commit(name):
    # Every release archive carries the two files byte-identical to the repository's
    # at the pinned commit, but install-pinned-tool never sees cargo-deny's archive,
    # so the staged copies are the URL-pinned ones.
    entry = THIRD_PARTY_LICENSES["cargo-deny"]
    files = [f for f in entry.files if f.name == name]
    assert len(files) == 1
    assert files[0].url is not None and entry.commit in files[0].url
    assert files[0].sha256 is not None and len(files[0].sha256) == 64


def test_the_version_check_is_the_executables_own_version_flag():
    entry = THIRD_PARTY_LICENSES["cargo-deny"]
    assert entry.version_probe == ()
    assert entry.executable_names == ("cargo-deny",)


def test_the_register_citation_names_the_pinned_release():
    citation = CargoDenyScanner.operational_facets.provenance.upstream_license
    assert citation.startswith("MIT OR Apache-2.0 (source: LICENSE-MIT and ")
    assert CARGO_DENY_VERSION in citation


def test_the_installer_covers_every_published_platform():
    # cargo-deny 0.21.0 publishes no x86_64 macOS build and no arm64 Windows build.
    assert sorted(ASSETS) == [
        ("darwin", "arm64"),
        ("linux", "amd64"),
        ("linux", "arm64"),
        ("windows", "amd64"),
    ]


def test_the_image_installs_and_attributes_the_pinned_cargo_deny():
    dockerfile = (Path(__file__).resolve().parents[3] / "Dockerfile").read_text()
    assert "ash_cargo_deny_plugins" in dockerfile
    assert "cargo-deny" in _licenses_only_line(dockerfile).split()
    assert "RUN cargo-deny --version" in dockerfile


def _licenses_only_line(dockerfile: str) -> str:
    for line in dockerfile.splitlines():
        if "--licenses-only" in line and "bandit" in line:
            return line.rstrip("'")
    raise AssertionError("the Python tools' --licenses-only line is missing")
