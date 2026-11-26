# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""kyverno, the alpha Kubernetes-policy scanner's tool, is a pinned tool.

Kyverno is pinned by its own module (``ash_kyverno_plugins/kyverno_install.py``)
rather than ``tool_downloads``' shared tables, so the agreement the shared
coverage test gives TOOL_VERSIONS tools -- a license entry recording the same
release the installer places -- is asserted here instead. The entry's version
probe is ``kyverno version`` because ``kyverno --version`` is an unknown flag.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from automated_security_helper.plugin_modules.ash_kyverno_plugins.kyverno_install import (
    ASSETS,
    KYVERNO_VERSION,
)
from automated_security_helper.plugin_modules.ash_kyverno_plugins.kyverno_scanner import (
    KyvernoScanner,
)
from automated_security_helper.utils.tool_downloads import THIRD_PARTY_LICENSES

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[3]


def test_the_license_entry_names_the_installers_pin():
    entry = THIRD_PARTY_LICENSES["kyverno"]
    assert entry.version == KYVERNO_VERSION == "v1.19.2"
    assert entry.license == "Apache-2.0"
    assert entry.repository == "https://github.com/kyverno/kyverno"
    assert len(entry.commit) == 40
    # Each archive carries a LICENSE byte-identical to the repository's at the
    # pinned commit, but install-pinned-tool never sees kyverno's archive, so the
    # staged copies are the URL-pinned ones; the NOTICE is in no archive at all.
    by_name = {f.name: f for f in entry.files}
    assert sorted(by_name) == ["LICENSE", "NOTICE"]
    for license_file in by_name.values():
        assert license_file.url is not None and entry.commit in license_file.url
        assert len(license_file.sha256 or "") == 64


def test_the_version_check_is_the_version_subcommand():
    entry = THIRD_PARTY_LICENSES["kyverno"]
    assert entry.version_probe == ("kyverno", "version")
    assert not entry.executables


def test_the_capture_was_made_by_the_release_the_entry_names():
    # `kyverno version` prints the git commit the binary was built from; the
    # captured README records it, and it is the tag commit the entry pins.
    readme = (
        (REPO_ROOT / "tests" / "test_data" / "scanners" / "kyverno" / "captured")
        .joinpath("README.md")
        .read_text(encoding="utf-8")
    )
    assert THIRD_PARTY_LICENSES["kyverno"].commit in readme
    assert KYVERNO_VERSION.lstrip("v") in readme


def test_the_register_citation_names_the_pinned_release():
    citation = KyvernoScanner.operational_facets.provenance.upstream_license
    assert citation.startswith("Apache-2.0 (source: the LICENSE file inside the ")
    assert KYVERNO_VERSION in citation


def test_the_installer_covers_every_published_platform():
    # Kyverno also publishes linux/s390x, which ASH does not install for.
    assert sorted(ASSETS) == [
        ("darwin", "amd64"),
        ("darwin", "arm64"),
        ("linux", "amd64"),
        ("linux", "arm64"),
        ("windows", "amd64"),
        ("windows", "arm64"),
    ]


def test_the_image_installs_and_attributes_the_pinned_kyverno():
    dockerfile = (REPO_ROOT / "Dockerfile").read_text()
    assert (
        dockerfile.count("automated_security_helper.plugin_modules.ash_kyverno_plugins")
        == 2
    )
    assert "kyverno" in _licenses_only_line(dockerfile).split()
    assert "RUN kyverno version" in dockerfile


def _licenses_only_line(dockerfile: str) -> str:
    for line in dockerfile.splitlines():
        if "--licenses-only" in line and "bandit" in line:
            return line
    raise AssertionError("the Python tools' --licenses-only line is missing")
