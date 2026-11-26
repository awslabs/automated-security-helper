# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The module-local install pin and installer, and the scanner over a real DevSkim run.

``tests/test_data/scanners/devskim/captured/`` holds what ``devskim analyze`` 1.0.103
wrote (see its README). The capture tests read those files, so the severity mapping is
pinned over output the tool produced, not over a hand-built document.

The installer tests never download: ``download_file`` is replaced by a copy of a package
built here with the same layout as the real one (``tools/<tfm>/any/...``), so what is
measured is the unpacking, the launcher, the receipt and the re-check, not the network.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
import shutil
import stat
import zipfile
from pathlib import Path
from typing import Dict, List, Optional

import pytest

from automated_security_helper.core.exceptions import ToolNotProvisionableError
from automated_security_helper.plugin_modules.ash_devskim_plugins import (
    devskim_install as di,
)
from automated_security_helper.plugin_modules.ash_devskim_plugins import (
    devskim_scanner as ds,
)
from automated_security_helper.utils import download_utils as du

from .test_devskim_scanner_behavior import FakeDevSkim, _findings, _run, _scanner

pytestmark = pytest.mark.unit

CAPTURED = (
    Path(__file__).resolve().parents[3]
    / "test_data"
    / "scanners"
    / "devskim"
    / "captured"
)
HEX64 = re.compile(r"[0-9a-f]{64}")


# ---------------------------------------------------------------------------
# Install pin
# ---------------------------------------------------------------------------


def test_the_pin_names_one_stable_release_and_its_package():
    assert di.DEVSKIM_VERSION == "1.0.103"
    assert "-" not in di.DEVSKIM_VERSION
    assert di.DEVSKIM_PACKAGE == "Microsoft.CST.DevSkim.CLI"
    assert di.NUPKG_URL == (
        "https://api.nuget.org/v3-flatcontainer/microsoft.cst.devskim.cli/1.0.103/"
        "microsoft.cst.devskim.cli.1.0.103.nupkg"
    )
    assert HEX64.fullmatch(di.NUPKG_SHA256)
    assert di.MEMBER_PREFIX == "tools/net8.0/any/"


def test_the_pin_is_the_package_the_capture_was_run_from():
    readme = (CAPTURED / "README.md").read_text(encoding="utf-8")
    assert di.NUPKG_SHA256 in readme
    assert "devskim 1.0.103+7f8e5e24f6" in readme


def test_the_install_table_covers_linux_and_darwin_and_not_windows(
    tmp_path, monkeypatch
):
    bin_dir = tmp_path / "bin"
    monkeypatch.setenv("ASH_BIN_PATH", str(bin_dir))
    table = di.devskim_install_commands()
    assert {(p, a) for p, arches in table.items() for a in arches} == set(di.PLATFORMS)
    assert "windows" not in table
    for arches in table.values():
        for commands in arches.values():
            (command,) = commands
            assert command.shell is False
            assert command.args[1] == "-c"
            assert "install_devskim" in command.args[2]
            assert command.args[3] == str(bin_dir.absolute())


def test_the_install_table_never_raises_without_a_bin_directory(monkeypatch):
    monkeypatch.setattr(du, "current_bin_path", lambda: None)
    table = di.devskim_install_commands()
    assert table["linux"]["amd64"], "a refusing command stands in"
    assert "install_devskim" not in " ".join(table["linux"]["amd64"][0].args)


def test_the_launcher_rolls_forward_and_quotes_the_entry_point():
    script = di.launcher_script(Path("/opt/a b/it's $HOME/devskim.dll"))
    first, second = script.splitlines()
    assert first == "#!/bin/sh"
    assert shlex.split(second) == [
        "exec",
        "dotnet",
        "--roll-forward",
        "Major",
        "/opt/a b/it's $HOME/devskim.dll",
        "$@",
    ]
    assert second.endswith(' "$@"')


# ---------------------------------------------------------------------------
# Unpacking and installing (a package built here, never downloaded)
# ---------------------------------------------------------------------------

_BUILD: Dict[str, bytes] = {
    "tools/net8.0/any/devskim.dll": b"the net8.0 entry point",
    "tools/net8.0/any/devskim.runtimeconfig.json": b'{"runtimeOptions": {}}',
    "tools/net8.0/any/runtimes/linux-x64/native/libgit2-3f4182d.so": b"native",
    "tools/net10.0/any/devskim.dll": b"another build",
    "LICENSE.txt": b"MIT",
    "Microsoft.CST.DevSkim.CLI.nuspec": b"<package/>",
}

_UNPACKED = {
    "devskim.dll",
    "devskim.runtimeconfig.json",
    "runtimes/linux-x64/native/libgit2-3f4182d.so",
}


def _package(
    path: Path,
    members: Dict[str, bytes],
    *,
    symlink: Optional[str] = None,
) -> Path:
    with zipfile.ZipFile(path, "w") as archive:
        for name, data in members.items():
            archive.writestr(name, data)
        if symlink is not None:
            info = zipfile.ZipInfo(symlink)
            info.external_attr = (stat.S_IFLNK | 0o777) << 16
            archive.writestr(info, "/etc/passwd")
    return path


def test_only_the_pinned_build_is_unpacked_with_its_digests(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    files = di.extract_build(_package(tmp_path / "p.nupkg", _BUILD), root)
    assert set(files) == _UNPACKED
    for relative, digest in files.items():
        data = _BUILD[di.MEMBER_PREFIX + relative]
        assert digest == hashlib.sha256(data).hexdigest()
        assert root.joinpath(*relative.split("/")).read_bytes() == data
    assert (root / "devskim.dll").read_bytes() == b"the net8.0 entry point"


@pytest.mark.parametrize(
    "member",
    [
        "tools/net8.0/any/../../escape.txt",
        "tools/net8.0/any/runtimes/../../../escape.txt",
        "tools/net8.0/any//etc/escape.txt",
        "tools/net8.0/any/./devskim.deps.json",
        "tools/net8.0/any/runtimes\\..\\escape.txt",
        "tools/net8.0/any/C:/escape.txt",
    ],
)
def test_a_member_that_is_not_a_plain_relative_path_refuses_the_package(
    tmp_path, member
):
    root = tmp_path / "root"
    root.mkdir()
    package = _package(tmp_path / "p.nupkg", {**_BUILD, member: b"x"})
    with pytest.raises(ToolNotProvisionableError, match="plain relative path"):
        di.extract_build(package, root)
    assert not (tmp_path / "escape.txt").exists()


def test_a_link_member_refuses_the_package(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    package = _package(
        tmp_path / "p.nupkg", _BUILD, symlink="tools/net8.0/any/link.dll"
    )
    with pytest.raises(ToolNotProvisionableError, match="not a regular file"):
        di.extract_build(package, root)
    assert not (root / "link.dll").is_symlink()


def test_a_package_without_the_pinned_build_is_refused(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    members = {k: v for k, v in _BUILD.items() if not k.startswith(di.MEMBER_PREFIX)}
    with pytest.raises(ToolNotProvisionableError, match="devskim.dll"):
        di.extract_build(_package(tmp_path / "p.nupkg", members), root)


@pytest.fixture
def installer(tmp_path, monkeypatch):
    """A home for the receipts, ASH online, and a download that copies a local package."""
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setattr(du, "is_offline_mode", lambda: False)
    package = _package(tmp_path / "built.nupkg", _BUILD)
    calls: List[dict] = []

    def download_file(
        url, destination, rename_to=None, expected_sha256=None, *, mode, max_bytes
    ):
        calls.append({"url": url, "sha256": expected_sha256, "max_bytes": max_bytes})
        landed = Path(destination) / (rename_to or "download")
        shutil.copyfile(package, landed)
        return landed

    monkeypatch.setattr(du, "download_file", download_file)
    return calls


def test_the_install_unpacks_the_build_and_writes_the_launcher(tmp_path, installer):
    bin_dir = tmp_path / "bin"
    launcher = di.install_devskim(bin_dir)
    home = di.install_home(bin_dir.absolute())
    assert launcher == bin_dir.absolute() / "devskim"
    assert launcher.read_text(encoding="utf-8") == di.launcher_script(
        home / "devskim.dll"
    )
    assert stat.S_IMODE(launcher.stat().st_mode) == 0o755
    assert (home / "devskim.dll").read_bytes() == b"the net8.0 entry point"
    unpacked = {p.relative_to(home).as_posix() for p in home.rglob("*") if p.is_file()}
    assert unpacked == _UNPACKED
    assert sorted(os.listdir(home.parent)) == [di.DEVSKIM_VERSION]
    assert installer == [
        {
            "url": di.NUPKG_URL,
            "sha256": di.NUPKG_SHA256,
            "max_bytes": di.NUPKG_MAX_BYTES,
        }
    ]
    assert di.installed_tree_matches(bin_dir.absolute()) is True


def test_a_second_install_of_an_intact_tree_downloads_nothing(tmp_path, installer):
    bin_dir = tmp_path / "bin"
    di.install_devskim(bin_dir)
    di.install_devskim(bin_dir)
    assert len(installer) == 1


def test_a_changed_unpacked_file_is_not_installed_and_is_replaced(tmp_path, installer):
    bin_dir = (tmp_path / "bin").absolute()
    di.install_devskim(bin_dir)
    dll = di.install_home(bin_dir) / "devskim.dll"
    dll.write_bytes(b"substituted")
    assert di.installed_tree_matches(bin_dir) is False
    di.install_devskim(bin_dir)
    assert len(installer) == 2
    assert dll.read_bytes() == b"the net8.0 entry point"


def test_a_changed_launcher_is_not_installed(tmp_path, installer):
    bin_dir = (tmp_path / "bin").absolute()
    launcher = di.install_devskim(bin_dir)
    launcher.write_text("#!/bin/sh\nexec /bin/true\n", encoding="utf-8")
    assert di.installed_tree_matches(bin_dir) is False


def test_an_unpacked_file_replaced_by_a_link_is_not_installed(tmp_path, installer):
    bin_dir = (tmp_path / "bin").absolute()
    di.install_devskim(bin_dir)
    dll = di.install_home(bin_dir) / "devskim.dll"
    elsewhere = tmp_path / "elsewhere.dll"
    elsewhere.write_bytes(b"the net8.0 entry point")
    dll.unlink()
    dll.symlink_to(elsewhere)
    assert di.installed_tree_matches(bin_dir) is False


def test_a_link_at_the_builds_directory_is_replaced_not_written_through(
    tmp_path, installer
):
    bin_dir = (tmp_path / "bin").absolute()
    bin_dir.mkdir()
    target = tmp_path / "planted"
    target.mkdir()
    (bin_dir / di.HOME_DIR_NAME).symlink_to(target)
    di.install_devskim(bin_dir)
    assert not (bin_dir / di.HOME_DIR_NAME).is_symlink()
    assert list(target.iterdir()) == []
    assert di.installed_tree_matches(bin_dir) is True


def test_offline_with_nothing_installed_refuses_and_downloads_nothing(
    tmp_path, installer, monkeypatch
):
    monkeypatch.setattr(du, "is_offline_mode", lambda: True)
    with pytest.raises(ToolNotProvisionableError, match="offline"):
        di.install_devskim(tmp_path / "bin")
    assert installer == []


def test_offline_with_an_intact_install_succeeds(tmp_path, installer, monkeypatch):
    bin_dir = (tmp_path / "bin").absolute()
    di.install_devskim(bin_dir)
    monkeypatch.setattr(du, "is_offline_mode", lambda: True)
    assert di.install_devskim(bin_dir) == bin_dir / "devskim"
    assert len(installer) == 1


def test_a_failed_unpack_leaves_no_build_behind(tmp_path, installer, monkeypatch):
    bin_dir = (tmp_path / "bin").absolute()

    def refuse(package, root):
        raise ToolNotProvisionableError("refused for the test")

    monkeypatch.setattr(di, "extract_build", refuse)
    with pytest.raises(ToolNotProvisionableError, match="refused for the test"):
        di.install_devskim(bin_dir)
    assert not (bin_dir / "devskim").exists()
    assert sorted(os.listdir(bin_dir / di.HOME_DIR_NAME)) == []


# ---------------------------------------------------------------------------
# The scanner over the captured run
# ---------------------------------------------------------------------------


def _capture(name: str) -> dict:
    return json.loads((CAPTURED / name).read_text(encoding="utf-8"))


def _raw_results(name: str) -> List[dict]:
    return _capture(name)["runs"][0]["results"]


def test_devskim_writes_the_level_from_its_own_severity():
    pairs = {
        (r["properties"]["DevSkimSeverity"], r["level"])
        for r in _raw_results("positive.sarif")
    }
    assert pairs == {
        ("Critical", "error"),
        ("Important", "error"),
        ("Moderate", "warning"),
        ("BestPractice", "note"),
        ("ManualReview", "note"),
    }


def test_the_capture_covers_every_row_of_the_severity_table():
    named = {
        r["properties"]["DevSkimSeverity"].lower()
        for r in _raw_results("positive.sarif")
    }
    assert named == set(ds.DEVSKIM_SEVERITY_MAP)


def test_the_inline_ignore_comment_does_not_hide_its_finding():
    # The run behind the capture passed --disable-supression: the md5 call that
    # carries a DevSkim ignore comment is reported.
    source = (CAPTURED / "in" / "pos" / "hashing.py").read_text(encoding="utf-8")
    assert "DevSkim: ignore DS126858" in source.splitlines()[8]
    located = {
        (
            r["ruleId"],
            r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
            r["locations"][0]["physicalLocation"]["region"]["startLine"],
        )
        for r in _raw_results("positive.sarif")
    }
    assert ("DS126858", "hashing.py", 9) in located


def test_every_rule_of_the_capture_carries_its_guidance_page():
    rules = _capture("positive.sarif")["runs"][0]["tool"]["driver"]["rules"]
    assert {r["id"] for r in rules} == {
        r["ruleId"] for r in _raw_results("positive.sarif")
    }
    for rule in rules:
        assert rule["helpUri"] == (
            f"https://github.com/Microsoft/DevSkim/blob/main/guidance/{rule['id']}.md"
        )


@pytest.fixture
def on_path(monkeypatch):
    monkeypatch.setattr(ds, "find_executable", lambda cmd: f"/fake/bin/{cmd}")


def test_the_captured_report_becomes_these_findings(tmp_path, on_path, monkeypatch):
    scanner = _scanner(CAPTURED / "in" / "pos", tmp_path)
    text = (CAPTURED / "positive.sarif").read_text(encoding="utf-8")
    report = _run(scanner, FakeDevSkim(text=text), monkeypatch)
    assert sorted(_findings(report)) == [
        ("DS126858", "error", "CRITICAL", "hashing.py", 5),
        ("DS126858", "error", "CRITICAL", "hashing.py", 9),
        ("DS137138", "warning", "MEDIUM", "request.js", 1),
        ("DS140021", "note", "LOW", "copy.c", 8),
        ("DS176209", "none", "INFO", "notes.py", 1),
        ("DS185832", "error", "HIGH", "copy.c", 4),
        ("DS189424", "none", "INFO", "request.js", 4),
    ]
    for result in report.get_all_results():
        assert "security" in result.properties.tags
        assert getattr(result.properties, "DevSkimConfidence", None) == "High"


def test_the_negative_capture_is_a_clean_scan(tmp_path, on_path, monkeypatch):
    scanner = _scanner(CAPTURED / "in" / "neg", tmp_path)
    text = (CAPTURED / "negative.sarif").read_text(encoding="utf-8")
    report = _run(scanner, FakeDevSkim(text=text), monkeypatch)
    assert _findings(report) == []
