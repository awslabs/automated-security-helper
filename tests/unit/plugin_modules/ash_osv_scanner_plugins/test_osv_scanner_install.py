# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The module-local OSV-Scanner install pin: the table, the refusals and the install.

Nothing here downloads: the install test replaces the shared verified download with a
recorder and checks what it is asked to place.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from automated_security_helper.core.exceptions import ToolNotProvisionableError
from automated_security_helper.plugin_modules.ash_osv_scanner_plugins import (
    osv_scanner_install as oi,
)

pytestmark = pytest.mark.unit

CAPTURED = (
    Path(__file__).resolve().parents[3]
    / "test_data"
    / "scanners"
    / "osv-scanner"
    / "captured"
)
HEX64 = re.compile(r"[0-9a-f]{64}")


def test_every_asset_has_one_digest():
    assert set(oi.ASSETS.values()) == set(oi.ASSET_SHA256)
    for digest in oi.ASSET_SHA256.values():
        assert HEX64.fullmatch(digest), digest
    assert len(set(oi.ASSET_SHA256.values())) == len(oi.ASSET_SHA256)


@pytest.mark.parametrize(
    "platform,arch,asset,install_as",
    [
        ("linux", "amd64", "osv-scanner_linux_amd64", "osv-scanner"),
        ("linux", "arm64", "osv-scanner_linux_arm64", "osv-scanner"),
        ("darwin", "amd64", "osv-scanner_darwin_amd64", "osv-scanner"),
        ("darwin", "arm64", "osv-scanner_darwin_arm64", "osv-scanner"),
        ("windows", "amd64", "osv-scanner_windows_amd64.exe", "osv-scanner.exe"),
        ("windows", "arm64", "osv-scanner_windows_arm64.exe", "osv-scanner.exe"),
    ],
)
def test_pinned_asset_resolves_a_published_pair(platform, arch, asset, install_as):
    url, digest, name = oi.pinned_asset(platform, arch)
    assert url == (
        "https://github.com/google/osv-scanner/releases/download/"
        f"{oi.OSV_SCANNER_VERSION}/{asset}"
    )
    assert digest == oi.ASSET_SHA256[asset]
    assert name == install_as


@pytest.mark.parametrize("pair", [("linux", "386"), ("freebsd", "amd64")])
def test_an_unpublished_pair_is_refused_by_name(pair):
    with pytest.raises(ToolNotProvisionableError, match=pair[0]):
        oi.pinned_asset(*pair)


def test_a_half_applied_bump_is_refused(monkeypatch):
    monkeypatch.setitem(oi.ASSETS, ("linux", "amd64"), "osv-scanner_linux_amd64_v9")
    with pytest.raises(ToolNotProvisionableError, match="half-applied"):
        oi.pinned_asset("linux", "amd64")


def test_the_linux_amd64_pin_is_the_asset_the_capture_was_taken_with():
    # The digest the captured README records for the run behind the fixtures.
    readme = (CAPTURED / "README.md").read_text(encoding="utf-8")
    assert oi.ASSET_SHA256["osv-scanner_linux_amd64"] in readme


def test_the_install_table_builds_without_the_shared_pin_table(tmp_path, monkeypatch):
    monkeypatch.setenv("ASH_BIN_PATH", str(tmp_path / "bin"))
    table = oi.osv_scanner_install_commands()
    assert {(p, a) for p, arches in table.items() for a in arches} == set(oi.ASSETS)
    for arches in table.values():
        for commands in arches.values():
            (command,) = commands
            assert command.shell is False
            assert "install_osv_scanner" in " ".join(command.args)
            assert Path(command.args[-1]) == (tmp_path / "bin").absolute()


def test_the_install_table_never_raises_without_a_bin_directory(monkeypatch):
    from automated_security_helper.utils import download_utils as du

    monkeypatch.setattr(du, "current_bin_path", lambda: None)
    table = oi.osv_scanner_install_commands()
    assert table["linux"]["amd64"], "a refusing command stands in"
    assert "install_osv_scanner" not in " ".join(table["linux"]["amd64"][0].args)


def test_the_install_places_the_pinned_asset_through_the_verified_download(
    tmp_path, monkeypatch
):
    from automated_security_helper.utils import download_utils as du

    calls = []

    def recorder(url, destination, rename_to=None, expected_sha256=None, force=False):
        calls.append((url, Path(destination), rename_to, expected_sha256))
        return Path(destination) / rename_to

    monkeypatch.setattr(du, "install_binary_from_url", recorder)
    placed = oi.install_osv_scanner("windows", "arm64", tmp_path / "bin")
    url, digest, name = oi.pinned_asset("windows", "arm64")
    assert calls == [(url, tmp_path / "bin", name, digest)]
    assert placed == tmp_path / "bin" / "osv-scanner.exe"
    assert (tmp_path / "bin").is_dir()


def test_the_install_refuses_an_unpublished_pair_before_any_download(
    tmp_path, monkeypatch
):
    from automated_security_helper.utils import download_utils as du

    monkeypatch.setattr(
        du,
        "install_binary_from_url",
        lambda *a, **k: pytest.fail("nothing is downloaded for an unpublished pair"),
    )
    with pytest.raises(ToolNotProvisionableError):
        oi.install_osv_scanner("linux", "386", tmp_path / "bin")
