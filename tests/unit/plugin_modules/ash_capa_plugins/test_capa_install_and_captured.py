# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The module-local install pin, and the SARIF the scanner writes for real captures.

``tests/test_data/scanners/capa/captured/`` holds what capa 10.0.0 wrote for two ELF
files (see its README). The committed SARIF beside them is what ``CapaScanner.scan``
writes for those documents, served by a fake subprocess; the regeneration tests keep
the two in step, and the facets register's corpus gate reads the SARIF.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from automated_security_helper.core.exceptions import ToolNotProvisionableError
from automated_security_helper.plugin_modules.ash_capa_plugins import (
    capa_install as ci,
)
from automated_security_helper.plugin_modules.ash_capa_plugins import (
    capa_scanner as cs,
)

from .test_capa_scanner_behavior import ELF, FakeCapa, _scanner

pytestmark = pytest.mark.unit

CAPTURED = (
    Path(__file__).resolve().parents[3] / "test_data" / "scanners" / "capa" / "captured"
)
HEX64 = re.compile(r"[0-9a-f]{64}")


# ---------------------------------------------------------------------------
# Install pin
# ---------------------------------------------------------------------------


def test_every_asset_has_an_archive_digest_and_a_member_digest():
    assert set(ci.ASSETS.values()) == set(ci.ARCHIVE_SHA256) == set(ci.MEMBER_SHA256)
    for digest in [*ci.ARCHIVE_SHA256.values(), *ci.MEMBER_SHA256.values()]:
        assert HEX64.fullmatch(digest), digest
    assert len(set(ci.ARCHIVE_SHA256.values())) == len(ci.ARCHIVE_SHA256)
    assert len(set(ci.MEMBER_SHA256.values())) == len(ci.MEMBER_SHA256)
    assert not set(ci.ARCHIVE_SHA256.values()) & set(ci.MEMBER_SHA256.values())


def test_asset_names_carry_the_pinned_version():
    for name in ci.ASSETS.values():
        assert name.startswith(f"capa-{ci.CAPA_VERSION}-"), name
        assert name.endswith(".zip"), name


@pytest.mark.parametrize(
    "platform,arch,asset,install_as",
    [
        ("linux", "amd64", "capa-v10.0.0-linux.zip", "capa"),
        ("linux", "arm64", "capa-v10.0.0-linux-arm64.zip", "capa"),
        ("darwin", "amd64", "capa-v10.0.0-macos.zip", "capa"),
        ("darwin", "arm64", "capa-v10.0.0-macos-arm64.zip", "capa"),
        ("windows", "amd64", "capa-v10.0.0-windows.zip", "capa.exe"),
    ],
)
def test_pinned_asset_resolves_a_published_pair(platform, arch, asset, install_as):
    url, archive, member, name = ci.pinned_asset(platform, arch)
    assert url == (
        f"https://github.com/mandiant/capa/releases/download/{ci.CAPA_VERSION}/{asset}"
    )
    assert archive == ci.ARCHIVE_SHA256[asset]
    assert member == ci.MEMBER_SHA256[asset]
    assert name == install_as


@pytest.mark.parametrize("pair", [("windows", "arm64"), ("freebsd", "amd64")])
def test_an_unpublished_pair_is_refused_by_name(pair):
    with pytest.raises(ToolNotProvisionableError, match=pair[0]):
        ci.pinned_asset(*pair)


def test_a_half_applied_bump_is_refused(monkeypatch):
    monkeypatch.setitem(ci.ASSETS, ("linux", "amd64"), "capa-v99.0.0-linux.zip")
    with pytest.raises(ToolNotProvisionableError, match="half-applied"):
        ci.pinned_asset("linux", "amd64")


def test_the_install_table_builds_without_the_shared_pin_table(tmp_path, monkeypatch):
    monkeypatch.setenv("ASH_BIN_PATH", str(tmp_path / "bin"))
    table = ci.capa_install_commands()
    assert {(p, a) for p, arches in table.items() for a in arches} == set(ci.ASSETS)
    for arches in table.values():
        for commands in arches.values():
            (command,) = commands
            assert command.shell is False
            assert "install_capa" in " ".join(command.args)


def test_the_install_table_never_raises_without_a_bin_directory(monkeypatch):
    from automated_security_helper.utils import download_utils as du

    monkeypatch.setattr(du, "current_bin_path", lambda: None)
    table = ci.capa_install_commands()
    assert table["linux"]["amd64"], "a refusing command stands in"
    assert "install_capa" not in " ".join(table["linux"]["amd64"][0].args)


@pytest.mark.parametrize(
    "version,too_old",
    [
        ("2.34", True),
        ("2.36", True),
        ("2.37", True),
        ("2.38", False),
        ("2.39", False),
        ("2.4", True),
        ("3.0", False),
        (None, False),
        ("", False),
        ("unknown", False),
    ],
)
def test_the_glibc_floor_compares_versions_numerically(version, too_old):
    assert ci.LINUX_GLIBC_FLOOR == "2.38"
    assert ci.glibc_too_old(version) is too_old


def test_the_host_glibc_reads_the_running_library(monkeypatch):
    import os

    monkeypatch.setattr(os, "confstr", lambda name: "glibc 2.34", raising=False)
    assert ci._host_glibc() == "2.34"
    monkeypatch.setattr(os, "confstr", lambda name: "", raising=False)
    assert ci._host_glibc() is None

    def unsupported(name):
        raise ValueError(name)

    monkeypatch.setattr(os, "confstr", unsupported, raising=False)
    assert ci._host_glibc() is None


# ---------------------------------------------------------------------------
# The SARIF the scanner writes over the captured documents
# ---------------------------------------------------------------------------


def _written_sarif(name: str, tmp_path: Path, monkeypatch) -> dict:
    """What scan() writes to capa.sarif when capa prints the captured *name*.json.

    The tree holds one ELF file, ``sample.elf``, so every result is located there.
    """
    src = tmp_path / "src"
    src.mkdir()
    (src / "sample.elf").write_bytes(ELF)
    scanner = _scanner(src, tmp_path)
    monkeypatch.setattr(cs, "find_executable", lambda cmd: f"/fake/bin/{cmd}")
    fake = FakeCapa(stdout=(CAPTURED / f"{name}.json").read_text(encoding="utf-8"))
    monkeypatch.setattr(scanner, "_run_subprocess", fake(scanner))
    scanner.scan(target=src, target_type="source")
    assert [c["argv"] for c in fake.calls] == [["capa", "-q", "-j", "--", "sample.elf"]]
    written = Path(scanner.results_dir or scanner.context.output_dir).joinpath(
        "source", "capa.sarif"
    )
    return json.loads(written.read_text(encoding="utf-8"))


@pytest.mark.parametrize("name", ["positive", "mapped"])
def test_the_committed_sarif_is_what_the_scanner_writes(name, tmp_path, monkeypatch):
    committed = json.loads((CAPTURED / f"{name}.sarif").read_text(encoding="utf-8"))
    assert committed == _written_sarif(name, tmp_path, monkeypatch)


def test_the_committed_corpus_holds_both_severities_and_the_tool_version():
    levels = set()
    for name in ("positive", "mapped"):
        sarif = json.loads((CAPTURED / f"{name}.sarif").read_text(encoding="utf-8"))
        (run,) = sarif["runs"]
        assert run["tool"]["driver"]["name"] == "capa"
        assert run["tool"]["driver"]["version"] == "10.0.0"
        assert run["results"], name
        levels |= {r["level"] for r in run["results"]}
    assert levels == {"note", "none"}
