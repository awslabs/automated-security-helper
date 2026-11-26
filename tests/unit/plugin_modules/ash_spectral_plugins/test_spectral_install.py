# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The module-local install pin for Spectral (``spectral_install.py``).

The release publishes bare executables, so each asset has one digest, the digest of
the bytes that run; the asset names carry no version, so ``DIGESTS_TAKEN_AT`` records
the release the digests were taken at. Nothing here downloads anything: the install
table's commands are read, not run.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from automated_security_helper.core.exceptions import ToolNotProvisionableError
from automated_security_helper.plugin_modules.ash_spectral_plugins import (
    spectral_install as si,
)

pytestmark = pytest.mark.unit

CAPTURED = (
    Path(__file__).resolve().parents[3]
    / "test_data"
    / "scanners"
    / "spectral"
    / "captured"
)
HEX64 = re.compile(r"[0-9a-f]{64}")


def test_every_asset_has_one_digest_and_every_digest_one_asset():
    assert set(si.ASSETS.values()) == set(si.SHA256)
    for digest in si.SHA256.values():
        assert HEX64.fullmatch(digest), digest
    assert len(set(si.SHA256.values())) == len(si.SHA256)


def test_the_digests_were_taken_at_the_pinned_version():
    assert si.DIGESTS_TAKEN_AT == si.SPECTRAL_VERSION == "v6.17.1"


@pytest.mark.parametrize(
    "platform,arch,asset,install_as",
    [
        ("linux", "amd64", "spectral-linux-x64", "spectral"),
        ("linux", "arm64", "spectral-linux-arm64", "spectral"),
        ("darwin", "amd64", "spectral-macos-x64", "spectral"),
        ("darwin", "arm64", "spectral-macos-arm64", "spectral"),
        ("windows", "amd64", "spectral.exe", "spectral.exe"),
    ],
)
def test_pinned_asset_resolves_a_published_pair(platform, arch, asset, install_as):
    url, digest, name = si.pinned_asset(platform, arch)
    assert url == (
        "https://github.com/stoplightio/spectral/releases/download/"
        f"{si.SPECTRAL_VERSION}/{asset}"
    )
    assert digest == si.SHA256[asset]
    assert name == install_as


@pytest.mark.parametrize("pair", [("windows", "arm64"), ("freebsd", "amd64")])
def test_an_unpublished_pair_is_refused_by_name(pair):
    with pytest.raises(ToolNotProvisionableError, match=pair[0]):
        si.pinned_asset(*pair)


def test_a_version_bump_without_new_digests_is_refused(monkeypatch):
    monkeypatch.setattr(si, "SPECTRAL_VERSION", "v6.99.0")
    with pytest.raises(ToolNotProvisionableError, match="half-applied"):
        si.pinned_asset("linux", "amd64")


def test_an_asset_with_no_digest_is_refused(monkeypatch):
    monkeypatch.setitem(si.ASSETS, ("linux", "amd64"), "spectral-linux-x64-renamed")
    with pytest.raises(ToolNotProvisionableError, match="half-applied"):
        si.pinned_asset("linux", "amd64")


def test_the_linux_x64_pin_is_the_executable_the_captures_came_from():
    # The same digest the captured README records for the run that produced them.
    readme = (CAPTURED / "README.md").read_text(encoding="utf-8")
    assert si.SHA256["spectral-linux-x64"] in readme


def test_the_install_table_covers_every_published_pair(tmp_path, monkeypatch):
    monkeypatch.setenv("ASH_BIN_PATH", str(tmp_path / "bin"))
    table = si.spectral_install_commands()
    assert {(p, a) for p, arches in table.items() for a in arches} == set(si.ASSETS)
    for target_platform, arches in table.items():
        for arch, commands in arches.items():
            (command,) = commands
            url, digest, install_as = si.pinned_asset(target_platform, arch)
            assert command.shell is False
            assert "install_binary_from_url" in " ".join(command.args)
            assert command.args[3:] == [url, str(tmp_path / "bin"), digest, install_as]


def test_the_install_table_never_raises_without_a_bin_directory(monkeypatch):
    from automated_security_helper.utils import download_utils as du

    monkeypatch.setattr(du, "current_bin_path", lambda: None)
    table = si.spectral_install_commands()
    (command,) = table["linux"]["amd64"]
    assert "install_binary_from_url" not in " ".join(command.args)
    assert du.NO_BIN_DIRECTORY in command.args


def test_a_broken_pin_is_a_refusing_command_not_an_exception(tmp_path, monkeypatch):
    monkeypatch.setenv("ASH_BIN_PATH", str(tmp_path / "bin"))
    monkeypatch.setattr(si, "SPECTRAL_VERSION", "v6.99.0")
    table = si.spectral_install_commands()
    assert {(p, a) for p, arches in table.items() for a in arches} == set(si.ASSETS)
    for arches in table.values():
        for (command,) in arches.values():
            assert "install_binary_from_url" not in " ".join(command.args)
            assert "half-applied" in command.args[-1]
