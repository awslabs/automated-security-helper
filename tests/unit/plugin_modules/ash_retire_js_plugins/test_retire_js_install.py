# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""retire_js_install: the locked npm tree, its digest, and the install around npm ci.

``npm`` is replaced by a fake that lays out a tree shaped like the one ``npm ci``
writes (one directory per locked package, npm's own ``.bin`` and
``.package-lock.json`` beside them), so these run without Node or a network. The
fake tree is not the real one, so the tests that install pin ``TREE_SHA256`` to the
fake tree's digest; the real digest is held to its well-formed shape here and to the
real tree by the desk run recorded in the module docstring.
"""

from __future__ import annotations

import base64
import json
import os
import re
import subprocess  # nosec B404 - CompletedProcess and constants only; nothing is started
import sys
from pathlib import Path
from typing import Any, Dict, List

import pytest

from automated_security_helper.core.exceptions import ToolNotProvisionableError
from automated_security_helper.plugin_modules.ash_retire_js_plugins import (
    retire_js_install as ri,
)
from automated_security_helper.utils import download_utils as du
from automated_security_helper.utils import subprocess_utils

pytestmark = pytest.mark.unit

#: The platform this host installs for: the command is a link on POSIX and a .cmd shim
#: on Windows, and a link cannot be made on a Windows host without a privilege.
HOST_PLATFORM = "windows" if os.name == "nt" else "linux"


def _names() -> List[str]:
    return sorted(path.split("/", 1)[1] for path in ri.LOCKED_PACKAGES)


def _write_fake_tree(project: Path, marker: str = "fake") -> None:
    """Lay out, under ``project``, what ``npm ci`` writes for the lockfile."""
    modules = project / "node_modules"
    for path, entry in ri.LOCKED_PACKAGES.items():
        package = project.joinpath(*path.split("/"))
        package.mkdir(parents=True, exist_ok=True)
        name = path.split("/", 1)[1]
        manifest = {"name": name, "version": entry["version"], "marker": marker}
        (package / "package.json").write_text(json.dumps(manifest), encoding="utf-8")
        (package / "index.js").write_text(f"// {name} {marker}\n", encoding="utf-8")
    cli = modules / "retire" / "lib" / "cli.js"
    cli.parent.mkdir(parents=True, exist_ok=True)
    cli.write_text("#!/usr/bin/env node\nconsole.log('6.1.1')\n", encoding="utf-8")
    (modules / ".bin").mkdir(exist_ok=True)
    (modules / ".package-lock.json").write_text("{}\n", encoding="utf-8")


def _fake_digest(tmp_path: Path) -> str:
    reference = tmp_path / "reference"
    _write_fake_tree(reference)
    return ri.tree_digest(reference)


class FakeNpm:
    """Stands in for ``subprocess`` in the installer module: records each npm run."""

    DEVNULL = subprocess.DEVNULL
    TimeoutExpired = subprocess.TimeoutExpired

    def __init__(self, returncode: int = 0, stderr: str = "", marker: str = "fake"):
        self.returncode = returncode
        self.stderr = stderr
        self.marker = marker
        self.calls: List[Dict[str, Any]] = []

    def run(self, argv, cwd=None, **kwargs):
        project = Path(cwd)
        self.calls.append(
            {
                "argv": list(argv),
                "cwd": project,
                "package.json": json.loads((project / "package.json").read_text()),
                "package-lock.json": json.loads(
                    (project / "package-lock.json").read_text()
                ),
                "kwargs": kwargs,
            }
        )
        if self.returncode == 0:
            _write_fake_tree(project, self.marker)
        return subprocess.CompletedProcess(argv, self.returncode, "", self.stderr)


@pytest.fixture
def online(monkeypatch):
    monkeypatch.setattr(du, "is_offline_mode", lambda: False)
    monkeypatch.setattr(
        subprocess_utils,
        "find_executable",
        lambda command: "/fake/bin/npm" if command == "npm" else None,
    )


@pytest.fixture
def npm(monkeypatch, online):
    fake = FakeNpm()
    monkeypatch.setattr(ri, "subprocess", fake)
    return fake


@pytest.fixture
def pinned_to_fake(monkeypatch, tmp_path):
    monkeypatch.setattr(ri, "TREE_SHA256", _fake_digest(tmp_path))


def _leftovers(bin_dir: Path) -> List[str]:
    return sorted(p.name for p in bin_dir.iterdir() if p.name.startswith("."))


class TestTheLockfile:
    def test_it_names_retire_at_the_pinned_release_and_nothing_else_at_the_root(self):
        lock = ri.lockfile()
        assert lock["lockfileVersion"] == 3
        assert lock["packages"][""]["dependencies"] == {"retire": ri.RETIRE_VERSION}
        assert ri.PACKAGE_JSON["dependencies"] == {"retire": ri.RETIRE_VERSION}
        assert set(lock["packages"]) == {"", *ri.LOCKED_PACKAGES}

    def test_retire_is_the_pinned_release_and_its_command_is_lib_cli_js(self):
        retire = ri.LOCKED_PACKAGES["node_modules/retire"]
        assert retire["version"] == ri.RETIRE_VERSION == "6.1.1"
        assert retire["bin"] == {"retire": "lib/cli.js"}

    @pytest.mark.parametrize("path", sorted(ri.LOCKED_PACKAGES))
    def test_every_package_is_pinned_by_the_registry_integrity(self, path):
        entry = ri.LOCKED_PACKAGES[path]
        name = path.split("/", 1)[1]
        version = entry["version"]
        assert re.fullmatch(r"\d+\.\d+\.\d+", version), version
        assert entry["resolved"] == (
            f"https://registry.npmjs.org/{name}/-/{name}-{version}.tgz"
        )
        algorithm, _, digest = entry["integrity"].partition("-")
        assert algorithm == "sha512"
        assert len(base64.b64decode(digest, validate=True)) == 64

    @pytest.mark.parametrize("path", sorted(ri.LOCKED_PACKAGES))
    def test_every_declared_dependency_is_locked_inside_its_range(self, path):
        """The lock closes over the tree: npm ci would refuse a dependency it lacks."""
        for name, wanted in ri.LOCKED_PACKAGES[path].get("dependencies", {}).items():
            locked = ri.LOCKED_PACKAGES.get(f"node_modules/{name}")
            assert locked is not None, f"{path} depends on {name}, which is not locked"
            have = tuple(int(p) for p in locked["version"].split("."))
            if wanted.startswith("^"):
                floor = tuple(int(p) for p in wanted[1:].split("."))
                assert have[0] == floor[0] and have >= floor, (name, wanted, have)
            else:
                assert locked["version"] == wanted, (name, wanted, have)

    def test_the_tree_digest_is_a_real_sha256(self):
        assert re.fullmatch(r"[0-9a-f]{64}", ri.TREE_SHA256)
        assert set(ri.TREE_SHA256) != {"0"}
        assert ri.TREE_FILE_COUNT > len(ri.LOCKED_PACKAGES)


class TestTheTreeDigest:
    def test_npm_s_own_entries_are_not_part_of_it(self, tmp_path):
        _write_fake_tree(tmp_path)
        before = ri.tree_digest(tmp_path)
        (tmp_path / "node_modules" / ".bin" / "extra").write_text("x")
        (tmp_path / "node_modules" / ".package-lock.json").write_text('{"v": 2}\n')
        assert ri.tree_digest(tmp_path) == before

    def test_a_changed_or_added_package_file_changes_it(self, tmp_path):
        _write_fake_tree(tmp_path)
        before = ri.tree_digest(tmp_path)
        cli = tmp_path / "node_modules" / "retire" / "lib" / "cli.js"
        cli.write_text(cli.read_text() + "// patched\n")
        changed = ri.tree_digest(tmp_path)
        assert changed != before
        (tmp_path / "node_modules" / "zod" / "extra.js").write_text("1\n")
        assert ri.tree_digest(tmp_path) not in (before, changed)

    def test_it_does_not_depend_on_where_the_tree_is(self, tmp_path):
        _write_fake_tree(tmp_path / "one")
        _write_fake_tree(tmp_path / "two" / "deeper")
        assert ri.tree_digest(tmp_path / "one") == ri.tree_digest(
            tmp_path / "two" / "deeper"
        )

    def test_a_missing_package_is_refused(self, tmp_path):
        _write_fake_tree(tmp_path)
        (tmp_path / "node_modules" / "walkdir" / "package.json").unlink()
        (tmp_path / "node_modules" / "walkdir" / "index.js").unlink()
        (tmp_path / "node_modules" / "walkdir").rmdir()
        with pytest.raises(ValueError, match="walkdir"):
            ri.tree_digest(tmp_path)

    @pytest.mark.skipif(os.name == "nt", reason="links need a privilege on Windows")
    def test_a_link_inside_a_package_is_refused(self, tmp_path):
        _write_fake_tree(tmp_path)
        (tmp_path / "node_modules" / "zod" / "link.js").symlink_to("index.js")
        with pytest.raises(ValueError, match="not a regular file"):
            ri.tree_digest(tmp_path)


class TestTheTreeProblem:
    def test_the_pinned_tree_has_none(self, tmp_path, pinned_to_fake):
        tree = tmp_path / "tree"
        _write_fake_tree(tree)
        assert ri.tree_problem(tree) is None

    def test_a_missing_tree(self, tmp_path, pinned_to_fake):
        assert "does not exist" in ri.tree_problem(tmp_path / "absent")

    def test_an_extra_package_beside_the_locked_ones(self, tmp_path, pinned_to_fake):
        tree = tmp_path / "tree"
        _write_fake_tree(tree)
        (tree / "node_modules" / "planted").mkdir()
        assert "extra: planted" in ri.tree_problem(tree)

    def test_files_that_do_not_hash_to_the_pin(self, tmp_path, pinned_to_fake):
        tree = tmp_path / "tree"
        _write_fake_tree(tree, marker="other")
        problem = ri.tree_problem(tree)
        assert "not to the pinned tree digest" in problem
        assert ri.TREE_SHA256 in problem


class TestInstall:
    def test_npm_ci_installs_the_lockfile_and_the_command_points_into_the_tree(
        self, tmp_path, npm, pinned_to_fake
    ):
        bin_dir = tmp_path / "bin"
        command = ri.install_retire(HOST_PLATFORM, "amd64", bin_dir)

        assert len(npm.calls) == 1
        call = npm.calls[0]
        assert call["argv"][0] == "/fake/bin/npm"
        assert call["argv"][1] == "ci"
        for flag in (
            "--ignore-scripts",
            "--install-strategy=hoisted",
            "--bin-links",
            "--engine-strict",
            "--no-audit",
            "--no-fund",
        ):
            assert flag in call["argv"], flag
        cache = [a for a in call["argv"] if a.startswith("--cache=")]
        assert len(cache) == 1 and not Path(cache[0][len("--cache=") :]).exists()
        assert call["package.json"] == ri.PACKAGE_JSON
        assert call["package-lock.json"] == ri.lockfile()
        assert call["cwd"].parent == bin_dir

        tree = bin_dir / ri.TREE_DIRECTORY
        assert ri.tree_problem(tree) is None
        assert (tree / "package-lock.json").is_file()
        if HOST_PLATFORM == "windows":
            assert command == bin_dir / "retire.cmd"
            assert command.read_bytes() == ri.windows_shim().encode("utf-8")
        else:
            assert command == bin_dir / "retire"
            assert os.readlink(command) == (
                f"{ri.TREE_DIRECTORY}/node_modules/retire/lib/cli.js"
            )
            assert (
                command.resolve()
                == (tree / "node_modules" / "retire" / "lib" / "cli.js").resolve()
            )
            assert (tree.stat().st_mode & 0o777) == 0o755
        assert _leftovers(bin_dir) == []

    def test_a_tree_in_place_that_hashes_to_the_pin_is_kept_without_npm(
        self, tmp_path, npm, pinned_to_fake
    ):
        """The non-root image stage's case: the tree is there, its receipt is not."""
        bin_dir = tmp_path / "bin"
        _write_fake_tree(bin_dir / ri.TREE_DIRECTORY)
        ri.install_retire(HOST_PLATFORM, "amd64", bin_dir)
        assert npm.calls == []
        assert (bin_dir / ri._command_name(HOST_PLATFORM)).exists()

    def test_a_tree_in_place_that_changed_is_installed_again(
        self, tmp_path, npm, pinned_to_fake
    ):
        bin_dir = tmp_path / "bin"
        tree = bin_dir / ri.TREE_DIRECTORY
        _write_fake_tree(tree)
        cli = tree / "node_modules" / "retire" / "lib" / "cli.js"
        cli.write_text("#!/usr/bin/env node\nconsole.log('substituted')\n")
        ri.install_retire(HOST_PLATFORM, "amd64", bin_dir)
        assert len(npm.calls) == 1
        assert ri.tree_problem(tree) is None
        assert "substituted" not in cli.read_text()
        assert _leftovers(bin_dir) == []

    def test_a_staged_tree_that_does_not_hash_to_the_pin_installs_nothing(
        self, tmp_path, npm, monkeypatch
    ):
        monkeypatch.setattr(ri, "TREE_SHA256", "f" * 64)
        bin_dir = tmp_path / "bin"
        with pytest.raises(ToolNotProvisionableError, match="not the one ASH pins"):
            ri.install_retire(HOST_PLATFORM, "amd64", bin_dir)
        assert not (bin_dir / ri.TREE_DIRECTORY).exists()
        assert not (bin_dir / ri._command_name(HOST_PLATFORM)).exists()
        assert _leftovers(bin_dir) == []

    def test_a_failing_npm_ci_installs_nothing_and_says_what_npm_said(
        self, tmp_path, monkeypatch, online, pinned_to_fake
    ):
        fake = FakeNpm(returncode=1, stderr="npm error code EINTEGRITY")
        monkeypatch.setattr(ri, "subprocess", fake)
        bin_dir = tmp_path / "bin"
        with pytest.raises(ToolNotProvisionableError, match="EINTEGRITY"):
            ri.install_retire(HOST_PLATFORM, "amd64", bin_dir)
        assert not (bin_dir / ri.TREE_DIRECTORY).exists()
        assert _leftovers(bin_dir) == []

    def test_offline_installs_nothing(self, tmp_path, monkeypatch, npm, pinned_to_fake):
        monkeypatch.setattr(du, "is_offline_mode", lambda: True)
        with pytest.raises(ToolNotProvisionableError, match="offline"):
            ri.install_retire(HOST_PLATFORM, "amd64", tmp_path / "bin")
        assert npm.calls == []

    def test_no_npm_on_path_is_refused_by_name(self, tmp_path, monkeypatch, npm):
        monkeypatch.setattr(subprocess_utils, "find_executable", lambda command: None)
        with pytest.raises(ToolNotProvisionableError, match="npm is not on PATH"):
            ri.install_retire(HOST_PLATFORM, "amd64", tmp_path / "bin")
        assert npm.calls == []

    def test_an_unlisted_platform_is_refused(self, tmp_path):
        with pytest.raises(ToolNotProvisionableError, match="linux/386"):
            ri.install_retire("linux", "386", tmp_path / "bin")


class TestTheCommand:
    def test_the_windows_shim_runs_node_on_the_tree_s_cli_with_every_argument(self):
        shim = ri.windows_shim()
        assert shim.startswith("@ECHO off\r\n")
        assert (
            'node "%~dp0ash-retire-js\\node_modules\\retire\\lib\\cli.js" %*\r\n'
            in shim
        )

    def test_the_windows_shim_is_written_once_and_kept(self, tmp_path):
        command = ri.place_command(tmp_path, "windows")
        assert command == tmp_path / "retire.cmd"
        before = command.stat().st_mtime_ns
        assert ri.place_command(tmp_path, "windows") == command
        assert command.stat().st_mtime_ns == before
        assert _leftovers(tmp_path) == []

    @pytest.mark.skipif(os.name == "nt", reason="links need a privilege on Windows")
    def test_a_wrong_link_is_replaced(self, tmp_path):
        (tmp_path / "retire").symlink_to("/somewhere/else/retire")
        command = ri.place_command(tmp_path, "linux")
        assert os.readlink(command) == (
            f"{ri.TREE_DIRECTORY}/node_modules/retire/lib/cli.js"
        )
        assert _leftovers(tmp_path) == []


class TestTheInstallCommands:
    def test_every_platform_runs_the_installer_into_the_bin_directory(
        self, tmp_path, monkeypatch
    ):
        monkeypatch.setattr(du, "current_bin_path", lambda: tmp_path / "bin")
        table = ri.retire_install_commands()
        for platform, arch in ri.INSTALL_PLATFORMS:
            (command,) = table[platform][arch]
            assert command.shell is False
            assert command.args[:2] == [sys.executable, "-c"]
            assert command.args[3:5] == [platform, arch]
            assert Path(command.args[5]) == (tmp_path / "bin").absolute()

    def test_with_no_bin_directory_every_command_refuses_with_the_reason(
        self, monkeypatch
    ):
        monkeypatch.setattr(du, "current_bin_path", lambda: None)
        table = ri.retire_install_commands()
        for platform, arch in ri.INSTALL_PLATFORMS:
            (command,) = table[platform][arch]
            assert command.args[-1] == du.NO_BIN_DIRECTORY

    def test_the_script_names_this_module_s_installer(self):
        assert (
            f"from {ri.__name__} import install_retire; "
            "install_retire(sys.argv[1], sys.argv[2], Path(sys.argv[3]))"
        ) in ri._INSTALL_SCRIPT


def test_the_six_packages_are_the_ones_the_module_docstring_names():
    assert _names() == [
        "astronomical",
        "commander",
        "meriyah",
        "retire",
        "walkdir",
        "zod",
    ]
    assert ri.PACKAGE_JSON["private"] is True
