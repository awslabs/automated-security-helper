# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The module-local install pin of cargo-audit (``cargo_audit_install.py``).

No download happens here: the tests read the pin tables and the install command
table the scanner registers. The digests themselves were read from GitHub's asset
metadata and checked against downloaded archives (see the module docstring).
"""

from __future__ import annotations

import re

import pytest

from automated_security_helper.core.exceptions import ToolNotProvisionableError
from automated_security_helper.plugin_modules.ash_cargo_audit_plugins import (
    cargo_audit_install as ci,
)

pytestmark = pytest.mark.unit

HEX64 = re.compile(r"[0-9a-f]{64}")


def test_every_asset_has_an_archive_digest_and_a_member_digest():
    assert set(ci.ASSETS.values()) == set(ci.ARCHIVE_SHA256) == set(ci.MEMBER_SHA256)
    for digest in [*ci.ARCHIVE_SHA256.values(), *ci.MEMBER_SHA256.values()]:
        assert HEX64.fullmatch(digest), digest
    assert len(set(ci.ARCHIVE_SHA256.values())) == len(ci.ARCHIVE_SHA256)
    assert len(set(ci.MEMBER_SHA256.values())) == len(ci.MEMBER_SHA256)


def test_asset_names_carry_the_pinned_version():
    for name in ci.ASSETS.values():
        assert name.startswith("cargo-audit-"), name
        assert f"-{ci.CARGO_AUDIT_VERSION}." in name, name


def test_the_release_tag_is_the_crate_prefixed_one():
    # The rustsec monorepo tags each crate's releases under its own name.
    assert ci.RELEASE_TAG == f"cargo-audit/{ci.CARGO_AUDIT_VERSION}"
    assert ci.CARGO_AUDIT_VERSION == "v0.23.0"


@pytest.mark.parametrize(
    "platform,arch,target,install_as",
    [
        ("linux", "amd64", "x86_64-unknown-linux-musl", "cargo-audit"),
        ("linux", "arm64", "aarch64-unknown-linux-gnu", "cargo-audit"),
        ("darwin", "amd64", "x86_64-apple-darwin", "cargo-audit"),
        ("darwin", "arm64", "aarch64-apple-darwin", "cargo-audit"),
        ("windows", "amd64", "x86_64-pc-windows-msvc", "cargo-audit.exe"),
    ],
)
def test_pinned_asset_resolves_a_published_pair(platform, arch, target, install_as):
    url, archive, member, name = ci.pinned_asset(platform, arch)
    assert url.startswith(
        "https://github.com/rustsec/rustsec/releases/download/"
        f"cargo-audit/{ci.CARGO_AUDIT_VERSION}/cargo-audit-{target}-"
    )
    assert HEX64.fullmatch(archive) and HEX64.fullmatch(member)
    assert name == install_as


@pytest.mark.parametrize(
    "pair", [("windows", "arm64"), ("linux", "386"), ("freebsd", "amd64")]
)
def test_an_unpublished_pair_is_refused_by_name(pair):
    with pytest.raises(ToolNotProvisionableError, match=pair[0]):
        ci.pinned_asset(*pair)


def test_a_half_applied_bump_is_refused(monkeypatch):
    monkeypatch.setitem(
        ci.ASSETS,
        ("linux", "amd64"),
        "cargo-audit-x86_64-unknown-linux-musl-v9.9.9.tgz",
    )
    with pytest.raises(ToolNotProvisionableError, match="half-applied"):
        ci.pinned_asset("linux", "amd64")


def test_the_install_table_builds_without_the_shared_pin_table(tmp_path, monkeypatch):
    monkeypatch.setenv("ASH_BIN_PATH", str(tmp_path / "bin"))
    table = ci.cargo_audit_install_commands()
    assert {(p, a) for p, arches in table.items() for a in arches} == set(ci.ASSETS)
    for arches in table.values():
        for commands in arches.values():
            (command,) = commands
            assert command.shell is False
            assert "install_cargo_audit" in " ".join(command.args)


def test_the_install_table_never_raises_without_a_bin_directory(monkeypatch):
    from automated_security_helper.utils import download_utils as du

    monkeypatch.setattr(du, "current_bin_path", lambda: None)
    table = ci.cargo_audit_install_commands()
    assert table["linux"]["amd64"], "a refusing command stands in"
    assert "install_cargo_audit" not in " ".join(table["linux"]["amd64"][0].args)


def test_an_offline_install_downloads_nothing(tmp_path, monkeypatch):
    from automated_security_helper.utils import download_utils as du

    calls = []
    monkeypatch.setattr(du, "is_offline_mode", lambda: True)
    monkeypatch.setattr(du, "download_file", lambda *a, **k: calls.append(a))
    with pytest.raises(ToolNotProvisionableError, match="offline"):
        ci.install_cargo_audit("linux", "amd64", tmp_path / "bin")
    assert calls == []
    assert not (tmp_path / "bin" / "cargo-audit").exists()
