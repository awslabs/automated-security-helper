# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The module-local install pin of the Titus release executables.

Titus publishes bare executables, so one SHA256 per asset covers the file that runs.
The install tests below replace only the network fetch: the staged, pin-checked rename,
the receipt and the re-install check are the real ones, run in a temporary directory.
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

import pytest

from automated_security_helper.core.exceptions import (
    ToolDownloadIntegrityError,
    ToolNotProvisionableError,
)
from automated_security_helper.plugin_modules.ash_titus_plugins import (
    titus_install as ti,
)
from automated_security_helper.utils import download_utils as du

pytestmark = pytest.mark.unit

CAPTURED = (
    Path(__file__).resolve().parents[3]
    / "test_data"
    / "scanners"
    / "titus"
    / "captured"
)
HEX64 = re.compile(r"[0-9a-f]{64}")


# ---------------------------------------------------------------------------
# The pin
# ---------------------------------------------------------------------------


def test_every_asset_has_one_digest():
    assert set(ti.ASSETS.values()) == set(ti.ASSET_SHA256)
    for digest in ti.ASSET_SHA256.values():
        assert HEX64.fullmatch(digest), digest
    assert len(set(ti.ASSET_SHA256.values())) == len(ti.ASSET_SHA256)


def test_the_digests_were_taken_at_the_pinned_version():
    assert ti.TITUS_VERSION == ti.DIGESTS_TAKEN_AT == "v1.3.0"


@pytest.mark.parametrize(
    "platform,arch,asset,install_as",
    [
        ("linux", "amd64", "titus-linux-amd64", "titus"),
        ("linux", "arm64", "titus-linux-arm64", "titus"),
        ("darwin", "amd64", "titus-darwin-amd64", "titus"),
        ("darwin", "arm64", "titus-darwin-arm64", "titus"),
        ("windows", "amd64", "titus-windows-amd64.exe", "titus.exe"),
    ],
)
def test_pinned_asset_resolves_a_published_pair(platform, arch, asset, install_as):
    url, digest, name = ti.pinned_asset(platform, arch)
    assert url == (
        "https://github.com/praetorian-inc/titus/releases/download/"
        f"{ti.TITUS_VERSION}/{asset}"
    )
    assert digest == ti.ASSET_SHA256[asset]
    assert name == install_as


@pytest.mark.parametrize("pair", [("windows", "arm64"), ("freebsd", "amd64")])
def test_an_unpublished_pair_is_refused_by_name(pair):
    with pytest.raises(ToolNotProvisionableError, match=pair[0]):
        ti.pinned_asset(*pair)


def test_a_version_bump_without_its_digests_is_refused(monkeypatch):
    monkeypatch.setattr(ti, "TITUS_VERSION", "v9.9.9")
    with pytest.raises(ToolNotProvisionableError, match="half-applied"):
        ti.pinned_asset("linux", "amd64")


def test_an_asset_without_a_digest_is_refused(monkeypatch):
    monkeypatch.delitem(ti.ASSET_SHA256, "titus-linux-amd64")
    with pytest.raises(ToolNotProvisionableError, match="half-applied"):
        ti.pinned_asset("linux", "amd64")


def test_the_linux_amd64_pin_is_the_executable_that_produced_the_capture():
    # The digest the captured README records for the run that produced the fixtures.
    readme = (CAPTURED / "README.md").read_text(encoding="utf-8")
    assert ti.ASSET_SHA256["titus-linux-amd64"] in readme


def test_the_install_table_builds_without_the_shared_pin_table(tmp_path, monkeypatch):
    monkeypatch.setenv("ASH_BIN_PATH", str(tmp_path / "bin"))
    table = ti.titus_install_commands()
    assert {(p, a) for p, arches in table.items() for a in arches} == set(ti.ASSETS)
    for arches in table.values():
        for commands in arches.values():
            (command,) = commands
            assert command.shell is False
            assert "install_titus" in " ".join(command.args)


def test_the_install_table_never_raises_without_a_bin_directory(monkeypatch):
    monkeypatch.setattr(du, "current_bin_path", lambda: None)
    table = ti.titus_install_commands()
    assert table["linux"]["amd64"], "a refusing command stands in"
    assert "install_titus" not in " ".join(table["linux"]["amd64"][0].args)


# ---------------------------------------------------------------------------
# The install, with only the network fetch replaced
# ---------------------------------------------------------------------------

FAKE_BINARY = b"#!/bin/sh\necho not the real titus\n"


@pytest.fixture
def isolated(tmp_path, monkeypatch):
    """A private HOME for the receipts and a bin directory, online."""
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setattr(du, "is_offline_mode", lambda: False)
    return tmp_path / "bin"


def _serve(monkeypatch, body: bytes) -> list:
    """Make ``download_file`` write ``body`` instead of fetching; returns the calls."""
    calls: list = []

    def fake_download(url, destination, rename_to=None, expected_sha256=None, **kw):
        calls.append(url)
        landed = Path(destination) / (rename_to or url.rsplit("/", 1)[-1])
        landed.write_bytes(body)
        return landed

    monkeypatch.setattr(du, "download_file", fake_download)
    return calls


def test_a_verified_executable_is_placed_and_then_not_fetched_again(
    isolated, monkeypatch
):
    monkeypatch.setitem(
        ti.ASSET_SHA256, "titus-linux-amd64", hashlib.sha256(FAKE_BINARY).hexdigest()
    )
    calls = _serve(monkeypatch, FAKE_BINARY)
    placed = ti.install_titus("linux", "amd64", isolated)
    assert placed == isolated / "titus"
    assert placed.read_bytes() == FAKE_BINARY
    assert placed.stat().st_mode & 0o111
    release = "https://github.com/praetorian-inc/titus/releases/download/v1.3.0"
    assert calls == [f"{release}/titus-linux-amd64"]
    # The receipt names the pin, so a second install re-hashes and stops there.
    assert ti.install_titus("linux", "amd64", isolated) == placed
    assert len(calls) == 1


def test_an_executable_that_does_not_hash_to_its_pin_is_never_placed(
    isolated, monkeypatch
):
    # The real pin, and bytes that are not the release: the staged rename refuses.
    _serve(monkeypatch, FAKE_BINARY)
    with pytest.raises(ToolDownloadIntegrityError):
        ti.install_titus("linux", "amd64", isolated)
    assert not (isolated / "titus").exists()


def test_offline_with_nothing_installed_is_refused_without_a_fetch(
    tmp_path, monkeypatch
):
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setattr(du, "is_offline_mode", lambda: True)
    calls = _serve(monkeypatch, FAKE_BINARY)
    with pytest.raises(ToolNotProvisionableError, match="offline"):
        ti.install_titus("linux", "amd64", tmp_path / "bin")
    assert calls == []
