# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""cargo-audit, the alpha Rust dependency scanner's tool, is a pinned tool.

cargo-audit is pinned by its own module (``ash_cargo_audit_plugins/cargo_audit_install.py``)
rather than ``tool_downloads``' shared tables, so the agreement the shared coverage
test gives TOOL_VERSIONS tools -- a license entry recording the same release the
installer places -- is asserted here instead. The crate lives in the rustsec monorepo,
so its license files are read from the crate's directory at the tag's commit, and the
tag carries the crate's prefix, under which the weekly pin check
(``scripts/check_pinned_tool_versions.py``) looks for the crate's newer releases.
"""

from __future__ import annotations

import dataclasses
import importlib.util
import re
import sys
from pathlib import Path
from types import SimpleNamespace

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

REPO_ROOT = Path(__file__).resolve().parents[3]
DOCKERFILE = REPO_ROOT / "Dockerfile"


def _load_pin_checker():
    script = REPO_ROOT / "scripts" / "check_pinned_tool_versions.py"
    spec = importlib.util.spec_from_file_location("_check_pinned_cargo_audit", script)
    assert spec and spec.loader, f"cannot load {script}"
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


checker = _load_pin_checker()


def _pins_holding(entry) -> SimpleNamespace:
    """The pins module's shape with one license entry, cargo-audit's or a variant.

    The whole module is not enumerated here: that would make these tests about every
    other pin too, and they are about how cargo-audit's own entry is read.
    """
    return SimpleNamespace(
        TOOL_VERSIONS={},
        THIRD_PARTY_LICENSES={"cargo-audit": entry},
        CFN_NAG_GEM_VERSION="0.8.10",
        BUNDLER_VERSION="2.6.9",
    )


def _cargo_audit_pin(entry=None):
    pins = _pins_holding(entry or THIRD_PARTY_LICENSES["cargo-audit"])
    by_tool = {p.tool: p for p in checker.enumerate_pins(pins, dockerfile=DOCKERFILE)}
    return by_tool["cargo-audit"]


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


class TestThePinCheckerReadsTheReleasesUnderTheCratesPrefix:
    """The weekly pin check reads cargo-audit's releases under ``cargo-audit/``.

    The rustsec monorepo tags each crate's releases under its own prefix, and its
    ``releases/latest`` is whichever crate was released last, under a tag that is not
    a version (it was ``cargo-audit/v0.23.0`` on 2026-11-26). Asked for that, the
    check read cargo-audit as a lookup error on every weekly run and could never
    report it outdated.
    """

    def test_the_pin_carries_the_prefix_its_license_entry_records(self):
        pin = _cargo_audit_pin()
        assert (pin.kind, pin.ecosystem, pin.project) == (
            checker.DOCKERFILE_ARG,
            checker.GITHUB,
            "rustsec/rustsec",
        )
        assert pin.version == CARGO_AUDIT_VERSION
        assert pin.tag_prefix == "cargo-audit/"
        assert f"{pin.tag_prefix}{pin.version}" == RELEASE_TAG

    def test_the_lookup_is_asked_for_the_crates_releases(self):
        asked = []

        def lookup(project: str, tag_prefix: str = "") -> str:
            asked.append((project, tag_prefix))
            return "v0.24.0"

        (result,) = checker.check([_cargo_audit_pin()], {checker.GITHUB: lookup})
        assert asked == [("rustsec/rustsec", "cargo-audit/")]
        assert (result.status, result.latest) == ("outdated", "v0.24.0"), result

    def test_the_bump_steps_name_the_prefixed_tag_and_the_crate_directory(self):
        pins = SimpleNamespace(THIRD_PARTY_LICENSES=THIRD_PARTY_LICENSES)
        steps = "\n".join(checker._license_steps(pins, "cargo-audit", "v0.24.0"))
        assert 'THIRD_PARTY_LICENSES["cargo-audit"].version -> v0.24.0' in steps
        assert 'THIRD_PARTY_LICENSES["cargo-audit"].tag -> cargo-audit/v0.24.0' in steps
        # By the bare version the monorepo resolves no commit (GitHub answers 422).
        assert (
            "gh api repos/rustsec/rustsec/commits/cargo-audit/v0.24.0 --jq .sha"
            in steps
        )
        assert "commits/v0.24.0 " not in steps
        for name in ("LICENSE-APACHE", "LICENSE-MIT"):
            assert (
                "https://raw.githubusercontent.com/rustsec/rustsec/<new commit>/"
                f"cargo-audit/{name}"
            ) in steps
            assert f"rustsec/<new commit>/{name}" not in steps

    def test_a_tag_that_is_not_the_prefix_and_the_version_is_refused(self):
        entry = dataclasses.replace(
            THIRD_PARTY_LICENSES["cargo-audit"], tag="cargo-audit-latest"
        )
        with pytest.raises(checker.PinEnumerationError, match="cargo-audit-latest"):
            _cargo_audit_pin(entry)

    def test_an_entry_whose_tag_is_its_version_has_no_prefix(self):
        """Control: a repository that tags releases by version alone needs none."""
        entry = dataclasses.replace(
            THIRD_PARTY_LICENSES["cargo-audit"], tag=CARGO_AUDIT_VERSION
        )
        assert _cargo_audit_pin(entry).tag_prefix == ""
        untagged = dataclasses.replace(THIRD_PARTY_LICENSES["cargo-audit"], tag=None)
        assert _cargo_audit_pin(untagged).tag_prefix == ""


def _licenses_only_line(dockerfile: str) -> str:
    for line in dockerfile.splitlines():
        if "--licenses-only" in line and "bandit" in line:
            return line.rstrip("'")
    raise AssertionError("the Python tools' --licenses-only line is missing")
