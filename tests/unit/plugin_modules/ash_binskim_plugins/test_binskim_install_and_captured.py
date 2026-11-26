# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The module-local install pin, the installer over a package built here, and the pin
against the captured run.

The installer tests never touch the network: ``download_file`` is replaced by a copy of
a small package these tests build, and the pinned digests are pointed at that package.
Everything after the download (member selection, extraction, the tree digest, the swap
into place, the link) is the installer's own code.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
import sys
import zipfile
from pathlib import Path
from typing import Dict, List, Optional

import pytest

from automated_security_helper.core.exceptions import (
    ToolDownloadIntegrityError,
    ToolNotProvisionableError,
)
from automated_security_helper.plugin_modules.ash_binskim_plugins import (
    binskim_install as bi,
)
from automated_security_helper.utils import download_utils as du

pytestmark = pytest.mark.unit

CAPTURED = (
    Path(__file__).resolve().parents[3]
    / "test_data"
    / "scanners"
    / "binskim"
    / "captured"
)
HEX64 = re.compile(r"[0-9a-f]{64}")

posix_only = pytest.mark.skipif(
    sys.platform == "win32", reason="links and modes are POSIX behavior"
)

#: Installing a build other than Windows' places a symbolic link, which needs a
#: privilege on Windows.
needs_symlinks = pytest.mark.skipif(
    sys.platform == "win32", reason="a symbolic link needs a privilege on Windows"
)


# ---------------------------------------------------------------------------
# The pin
# ---------------------------------------------------------------------------


def test_every_build_has_a_tree_digest_and_an_executable_digest():
    assert set(bi.RIDS.values()) == set(bi.TREE_SHA256) == set(bi.EXECUTABLE_SHA256)
    for digest in [
        bi.PACKAGE_SHA256,
        *bi.TREE_SHA256.values(),
        *bi.EXECUTABLE_SHA256.values(),
    ]:
        assert HEX64.fullmatch(digest), digest
    assert len(set(bi.TREE_SHA256.values())) == len(bi.TREE_SHA256)
    assert len(set(bi.EXECUTABLE_SHA256.values())) == len(bi.EXECUTABLE_SHA256)


def test_the_package_url_names_the_pinned_version_on_nuget():
    assert bi.PACKAGE_URL == (
        "https://api.nuget.org/v3-flatcontainer/microsoft.codeanalysis.binskim/"
        f"{bi.BINSKIM_VERSION}/microsoft.codeanalysis.binskim."
        f"{bi.BINSKIM_VERSION}.nupkg"
    )
    assert bi.BINSKIM_VERSION == "4.4.9.14"


@pytest.mark.parametrize(
    "platform,arch,rid,install_as",
    [
        ("linux", "amd64", "linux-x64", "BinSkim"),
        ("linux", "arm64", "linux-arm64", "BinSkim"),
        ("darwin", "amd64", "osx-x64", "BinSkim"),
        ("windows", "amd64", "win-x64", "BinSkim.exe"),
    ],
)
def test_pinned_build_resolves_a_published_pair(platform, arch, rid, install_as):
    found_rid, tree, executable, name = bi.pinned_build(platform, arch)
    assert (found_rid, name) == (rid, install_as)
    assert tree == bi.TREE_SHA256[rid] and executable == bi.EXECUTABLE_SHA256[rid]


@pytest.mark.parametrize(
    "pair", [("darwin", "arm64"), ("windows", "arm64"), ("freebsd", "amd64")]
)
def test_an_unpublished_pair_is_refused_by_name(pair):
    with pytest.raises(ToolNotProvisionableError, match=pair[0]):
        bi.pinned_build(*pair)


def test_a_half_applied_bump_is_refused(monkeypatch):
    monkeypatch.delitem(bi.TREE_SHA256, "linux-x64")
    with pytest.raises(ToolNotProvisionableError, match="half-applied"):
        bi.pinned_build("linux", "amd64")


def test_the_tree_digest_is_order_free_and_covers_names_and_bytes():
    files = [("b", "1" * 64), ("a", "2" * 64)]
    assert bi.tree_digest(files) == bi.tree_digest(list(reversed(files)))
    assert bi.tree_digest(files) != bi.tree_digest([("c", "1" * 64), ("a", "2" * 64)])
    assert bi.tree_digest(files) != bi.tree_digest([("b", "3" * 64), ("a", "2" * 64)])


def test_the_install_table_builds_without_the_shared_pin_table(tmp_path, monkeypatch):
    monkeypatch.setenv("ASH_BIN_PATH", str(tmp_path / "bin"))
    table = bi.binskim_install_commands()
    assert {(p, a) for p, arches in table.items() for a in arches} == set(bi.RIDS)
    for arches in table.values():
        for commands in arches.values():
            (command,) = commands
            assert command.shell is False
            assert "install_binskim" in " ".join(command.args)


def test_the_install_table_never_raises_without_a_bin_directory(monkeypatch):
    monkeypatch.setattr(du, "current_bin_path", lambda: None)
    table = bi.binskim_install_commands()
    assert table["linux"]["amd64"], "a refusing command stands in"
    assert "install_binskim" not in " ".join(table["linux"]["amd64"][0].args)


# ---------------------------------------------------------------------------
# The pin against the captured run
# ---------------------------------------------------------------------------


def test_the_captured_runs_are_of_the_pinned_release():
    for name in ("positive", "negative"):
        log = json.loads((CAPTURED / f"{name}.sarif").read_text(encoding="utf-8"))
        driver = log["runs"][0]["tool"]["driver"]
        assert driver["semanticVersion"] == bi.BINSKIM_VERSION, name


def test_the_package_pin_is_the_one_the_capture_readme_records():
    readme = (CAPTURED / "README.md").read_text(encoding="utf-8")
    assert bi.PACKAGE_SHA256 in readme
    assert bi.EXECUTABLE_SHA256["linux-x64"] in readme


# ---------------------------------------------------------------------------
# The installer, over a package built here
# ---------------------------------------------------------------------------

#: The files of the two builds in the test package.
LINUX_FILES: Dict[str, bytes] = {
    "BinSkim": b"\x7fELF the apphost",
    "BinSkim.dll": b"the assembly",
    "createdump": b"\x7fELF a helper",
}
WINDOWS_FILES: Dict[str, bytes] = {
    "BinSkim.exe": b"MZ the apphost",
    "BinSkim.dll": b"the assembly",
}


def _digests(files: Dict[str, bytes]) -> List[tuple]:
    return [(name, hashlib.sha256(data).hexdigest()) for name, data in files.items()]


def _package(path: Path, extra: Optional[Dict[str, bytes]] = None) -> Path:
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("Microsoft.CodeAnalysis.BinSkim.nuspec", b"<package/>")
        archive.writestr("src/Example.cs", b"class Example {}")
        archive.writestr("tools/ReleaseHistory.md", b"# history")
        for name, data in LINUX_FILES.items():
            archive.writestr(f"tools/linux-x64/{name}", data)
        for name, data in WINDOWS_FILES.items():
            archive.writestr(f"tools/win-x64/{name}", data)
        for name, data in (extra or {}).items():
            archive.writestr(name, data)
    return path


@pytest.fixture
def downloads(tmp_path, monkeypatch):
    """Point the pins at a package built here and record every download."""
    package = _package(tmp_path / "package.nupkg")
    calls: List[dict] = []

    def fake_download(url, destination, rename_to=None, expected_sha256=None, **kw):
        calls.append(
            {"url": url, "sha256": expected_sha256, "max_bytes": kw.get("max_bytes")}
        )
        landed = Path(destination) / (rename_to or "package.nupkg")
        shutil.copyfile(package, landed)
        return landed

    monkeypatch.setattr(du, "download_file", fake_download)
    monkeypatch.setattr(du, "is_offline_mode", lambda: False)
    monkeypatch.setitem(
        bi.TREE_SHA256, "linux-x64", bi.tree_digest(_digests(LINUX_FILES))
    )
    monkeypatch.setitem(
        bi.EXECUTABLE_SHA256,
        "linux-x64",
        hashlib.sha256(LINUX_FILES["BinSkim"]).hexdigest(),
    )
    monkeypatch.setitem(
        bi.TREE_SHA256, "win-x64", bi.tree_digest(_digests(WINDOWS_FILES))
    )
    monkeypatch.setitem(
        bi.EXECUTABLE_SHA256,
        "win-x64",
        hashlib.sha256(WINDOWS_FILES["BinSkim.exe"]).hexdigest(),
    )
    return calls


def _no_staging_left(bin_dir: Path) -> bool:
    return not [p for p in os.listdir(bin_dir) if p.startswith(".binskim-")]


#: The two builds of the test package: (platform, arch, rid, files, executable).
BUILDS = [
    pytest.param(
        ("linux", "amd64", "linux-x64", LINUX_FILES, "BinSkim"),
        id="linux",
        marks=needs_symlinks,
    ),
    pytest.param(
        ("windows", "amd64", "win-x64", WINDOWS_FILES, "BinSkim.exe"), id="windows"
    ),
]


@pytest.mark.parametrize("build", BUILDS)
def test_the_install_places_the_build_and_verifies_the_package(
    tmp_path, downloads, build
):
    platform_name, arch, rid, files, executable_name = build
    bin_dir = tmp_path / "bin"
    executable = bi.install_binskim(platform_name, arch, bin_dir)
    tree = bin_dir / f"binskim-4.4.9.14-{rid}"
    assert executable == tree / executable_name
    assert sorted(os.listdir(tree)) == sorted(files)
    for name, data in files.items():
        assert (tree / name).read_bytes() == data
    assert downloads == [
        {
            "url": bi.PACKAGE_URL,
            "sha256": bi.PACKAGE_SHA256,
            "max_bytes": bi.PACKAGE_MAX_BYTES,
        }
    ]
    assert _no_staging_left(bin_dir)


@posix_only
def test_only_the_executable_is_executable_and_a_link_names_it(tmp_path, downloads):
    bin_dir = tmp_path / "bin"
    bi.install_binskim("linux", "amd64", bin_dir)
    tree = bin_dir / "binskim-4.4.9.14-linux-x64"
    assert stat.S_IMODE(os.stat(tree / "BinSkim").st_mode) == 0o755
    assert stat.S_IMODE(os.stat(tree / "createdump").st_mode) == 0o644
    assert stat.S_IMODE(os.stat(tree / "BinSkim.dll").st_mode) == 0o644
    link = bin_dir / "BinSkim"
    assert link.is_symlink()
    assert os.readlink(link) == "binskim-4.4.9.14-linux-x64/BinSkim"
    assert link.read_bytes() == LINUX_FILES["BinSkim"]


def test_windows_gets_the_build_and_no_link(tmp_path, downloads):
    bin_dir = tmp_path / "bin"
    executable = bi.install_binskim("windows", "amd64", bin_dir)
    assert executable == bin_dir / "binskim-4.4.9.14-win-x64" / "BinSkim.exe"
    assert sorted(os.listdir(executable.parent)) == sorted(WINDOWS_FILES)
    assert not os.path.lexists(bin_dir / "BinSkim.exe")
    assert not os.path.lexists(bin_dir / "BinSkim")


@pytest.mark.parametrize("build", BUILDS)
def test_a_second_install_downloads_nothing(tmp_path, downloads, build):
    platform_name, arch, *_ = build
    bin_dir = tmp_path / "bin"
    bi.install_binskim(platform_name, arch, bin_dir)
    bi.install_binskim(platform_name, arch, bin_dir)
    assert len(downloads) == 1


@pytest.mark.parametrize("build", BUILDS)
@pytest.mark.parametrize("change", ["bytes", "extra", "missing"])
def test_a_build_that_changed_on_disk_is_installed_again(
    tmp_path, downloads, change, build
):
    platform_name, arch, rid, files, _executable = build
    bin_dir = tmp_path / "bin"
    bi.install_binskim(platform_name, arch, bin_dir)
    tree = bin_dir / f"binskim-4.4.9.14-{rid}"
    if change == "bytes":
        (tree / "BinSkim.dll").write_bytes(b"replaced")
    elif change == "extra":
        (tree / "planted.dll").write_bytes(b"planted")
    else:
        (tree / "BinSkim.dll").unlink()
    bi.install_binskim(platform_name, arch, bin_dir)
    assert len(downloads) == 2
    assert sorted(os.listdir(tree)) == sorted(files)
    assert (tree / "BinSkim.dll").read_bytes() == files["BinSkim.dll"]
    assert _no_staging_left(bin_dir)


@posix_only
def test_a_link_planted_at_the_build_name_is_replaced_not_followed(tmp_path, downloads):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (elsewhere / "keep").write_bytes(b"not ours")
    os.symlink(elsewhere, bin_dir / "binskim-4.4.9.14-linux-x64")
    bi.install_binskim("linux", "amd64", bin_dir)
    tree = bin_dir / "binskim-4.4.9.14-linux-x64"
    assert not tree.is_symlink() and tree.is_dir()
    assert sorted(os.listdir(elsewhere)) == ["keep"]
    assert _no_staging_left(bin_dir)


def test_a_build_that_does_not_match_its_tree_pin_is_refused(
    tmp_path, downloads, monkeypatch
):
    monkeypatch.setitem(bi.TREE_SHA256, "linux-x64", "0" * 64)
    bin_dir = tmp_path / "bin"
    with pytest.raises(ToolDownloadIntegrityError, match="tree digest"):
        bi.install_binskim("linux", "amd64", bin_dir)
    assert not os.path.lexists(bin_dir / "binskim-4.4.9.14-linux-x64")
    assert not os.path.lexists(bin_dir / "BinSkim")
    assert _no_staging_left(bin_dir)


def test_an_executable_that_does_not_match_its_pin_is_refused(
    tmp_path, downloads, monkeypatch
):
    monkeypatch.setitem(bi.EXECUTABLE_SHA256, "linux-x64", "0" * 64)
    bin_dir = tmp_path / "bin"
    with pytest.raises(ToolDownloadIntegrityError, match="executable digest"):
        bi.install_binskim("linux", "amd64", bin_dir)
    assert not os.path.lexists(bin_dir / "binskim-4.4.9.14-linux-x64")
    assert _no_staging_left(bin_dir)


@pytest.mark.parametrize(
    "member",
    [
        "tools/linux-x64/sub/evil",
        "tools/linux-x64/../escape",
        "tools/linux-x64/.hidden",
        "tools/linux-x64/a:b",
    ],
)
def test_a_member_that_is_not_a_plain_file_name_is_refused(tmp_path, member):
    package = _package(tmp_path / "bad.nupkg", extra={member: b"x"})
    staging = tmp_path / "staging"
    staging.mkdir()
    with pytest.raises(ToolDownloadIntegrityError, match="not a plain file"):
        bi._extract_build(package, "linux-x64", staging)


def test_a_symbolic_link_member_is_refused(tmp_path):
    package = tmp_path / "link.nupkg"
    with zipfile.ZipFile(package, "w") as archive:
        info = zipfile.ZipInfo("tools/linux-x64/BinSkim")
        info.external_attr = (stat.S_IFLNK | 0o777) << 16
        archive.writestr(info, "/etc/passwd")
    staging = tmp_path / "staging"
    staging.mkdir()
    with pytest.raises(ToolDownloadIntegrityError, match="not a plain file"):
        bi._extract_build(package, "linux-x64", staging)


def test_a_package_without_the_build_is_refused(tmp_path):
    package = _package(tmp_path / "package.nupkg")
    staging = tmp_path / "staging"
    staging.mkdir()
    with pytest.raises(ToolDownloadIntegrityError, match="no tools/osx-x64/ build"):
        bi._extract_build(package, "osx-x64", staging)


def test_a_file_that_is_not_a_zip_is_refused(tmp_path):
    package = tmp_path / "package.nupkg"
    package.write_bytes(b"not a zip")
    staging = tmp_path / "staging"
    staging.mkdir()
    with pytest.raises(ToolDownloadIntegrityError, match="not a readable zip"):
        bi._extract_build(package, "linux-x64", staging)


def test_offline_with_nothing_installed_downloads_nothing(
    tmp_path, downloads, monkeypatch
):
    monkeypatch.setattr(du, "is_offline_mode", lambda: True)
    with pytest.raises(ToolNotProvisionableError, match="offline"):
        bi.install_binskim("linux", "amd64", tmp_path / "bin")
    assert downloads == []


# ---------------------------------------------------------------------------
# What the scanner finds
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "system,machine,expected",
    [
        ("Linux", "x86_64", ("linux", "amd64")),
        ("Linux", "aarch64", ("linux", "arm64")),
        ("Darwin", "arm64", ("darwin", "arm64")),
        ("Windows", "AMD64", ("windows", "amd64")),
        ("FreeBSD", "amd64", None),
        ("Linux", "riscv64", None),
    ],
)
def test_host_platform_uses_the_dependencies_vocabulary(
    monkeypatch, system, machine, expected
):
    monkeypatch.setattr(bi.platform, "system", lambda: system)
    monkeypatch.setattr(bi.platform, "machine", lambda: machine)
    assert bi.host_platform() == expected


def test_installed_executable_finds_the_build_for_this_host(
    tmp_path, downloads, monkeypatch
):
    bin_dir = tmp_path / "bin"
    monkeypatch.setattr(bi, "host_platform", lambda: ("windows", "amd64"))
    assert bi.installed_executable(bin_dir) is None
    executable = bi.install_binskim("windows", "amd64", bin_dir)
    assert bi.installed_executable(bin_dir) == executable


def test_installed_executable_has_nothing_for_an_unpublished_host(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(bi, "host_platform", lambda: ("darwin", "arm64"))
    assert bi.installed_executable(tmp_path) is None
