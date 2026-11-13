# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Every command ``ash dependencies install`` runs starts in an empty directory.

The installer takes the current directory as the source tree, and it used to run
each plugin's install commands there, so a package manager that reads settings from
its working directory read the scanned repository's. The operator's own settings (in
HOME, or set globally) still apply: they are the operator's, not the repository's.

What each tool reads from its working directory, measured with npm 10.9.4, RubyGems
3.4.19 and Bundler 2.4.19:

- npm reads a project ``.npmrc`` there for every command that is not global. The npm
  builder's ``npm install -g`` reads only the user and global npmrc, so it was not
  affected; an npm command a plugin declares itself may not be global.
- RubyGems reads no ``.gemrc`` from the working directory, only the user's and the
  system's. ``gem install -g`` reads the Gemfile there.
- Bundler reads ``.bundle/config`` from the app directory, which is the working
  directory when it holds the Gemfile. ASH runs no bundler command itself.

Each test plants the file in the directory the installer is run from and runs one
command through the installer's ``run_command``. Its control runs the same command
from that directory, as the installer used to, and finds the planted setting applied.
uv tool commands read only the user's uv configuration (measured with uv 0.12.22),
so uv has no case here; Python commands are in
tests/unit/utils/test_python_children_import_nothing_from_their_cwd.py.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path
from typing import Dict, List

import pytest

from automated_security_helper.cli import dependencies as dependencies_module
from tests.utils.helpers import bound_run_command

# The real npm and gem, on purpose: what each reads from its working directory is
# the question, and the unit tests' tool guard would answer for both names with a
# stand-in that exits 1 (tests/utils/tool_guard.py GUARDED_TOOLS). The module is
# listed in tests/unit/conftest.py REAL_TOOL_MODULES; the HOME check still applies,
# and the tools write only under the HOME the `machine` fixture gives them.
pytestmark = [
    pytest.mark.integration,
    pytest.mark.runs_real_tools(
        reason="what the real npm and gem read from their working directory is what "
        "these tests measure"
    ),
]

#: Variables through which the operator's environment could set the same settings,
#: cleared so the planted file and the user file are the only sources.
_SETTING_PREFIXES = ("npm_config_", "NPM_CONFIG_", "BUNDLE_", "GEM_", "GEMRC")


def _tool(name: str) -> str:
    found = shutil.which(name)
    if found is None:
        pytest.skip(f"{name} is not installed")
    return found


def _write(root: Path, files: Dict[str, str]) -> None:
    for relative, content in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")


@pytest.fixture
def machine(tmp_path, monkeypatch):
    """A repository and a home directory, with nothing else setting the tools up."""
    for key in list(os.environ):
        if key.startswith(_SETTING_PREFIXES):
            monkeypatch.delenv(key)
    home, repo = tmp_path / "home", tmp_path / "repo"
    home.mkdir()
    repo.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("GEM_HOME", str(tmp_path / "gems"))
    return home, repo


def _control(argv: List[str], repo: Path) -> str:
    """The command run from the repository, the way the installer used to run it."""
    result = subprocess.run(
        argv,
        cwd=repo,
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )
    return result.stdout + result.stderr


def _through_the_installer(argv: List[str], repo: Path, monkeypatch) -> str:
    printed: List[str] = []
    monkeypatch.setattr(
        dependencies_module,
        "print",
        lambda *a, **_k: printed.append(" ".join(map(str, a))),
    )
    monkeypatch.chdir(repo)
    bound_run_command(monkeypatch)
    dependencies_module.run_command(argv)
    return "\n".join(printed)


NPM_FILES = {".npmrc": "registry=http://127.0.0.1:9/planted-npmrc/\n"}
NPM_USER = {".npmrc": "registry=http://127.0.0.1:8/user-npmrc/\n"}
GEMFILE = {
    "Gemfile": 'source "http://127.0.0.1:9/planted-gemfile/"\ngem "ash-planted-gem-zz"\n'
}
GEM_USER = {".gemrc": ":sources:\n- http://127.0.0.1:8/user-gemrc/\n"}
BUNDLE_FILES = {
    "Gemfile": 'source "http://127.0.0.1:9/planted-gemfile/"\n',
    ".bundle/config": (
        '---\nBUNDLE_MIRROR__HTTPS://RUBYGEMS__ORG/: "http://127.0.0.1:9/planted-mirror/"\n'
    ),
}

CASES = [
    pytest.param(
        "npm",
        ["config", "get", "registry"],
        NPM_FILES,
        NPM_USER,
        "planted-npmrc",
        "user-npmrc",
        id="npm-project-npmrc",
    ),
    pytest.param(
        "gem",
        # --explain resolves and lists what would be installed, without installing.
        # Both sources are refused ports on this host, so nothing is fetched.
        ["install", "-g", "--explain"],
        GEMFILE,
        GEM_USER,
        "ash-planted-gem-zz",
        "cannot find gem dependencies file",
        id="gem-gemfile",
    ),
    pytest.param(
        "bundle",
        ["config", "get", "mirror.https://rubygems.org"],
        BUNDLE_FILES,
        {},
        "planted-mirror",
        "You have not configured a value",
        id="bundler-local-config",
    ),
]


@pytest.mark.parametrize(
    ("tool", "args", "planted", "user", "planted_marker", "clean_marker"), CASES
)
def test_control_the_tool_applies_the_planted_file_from_the_repository(
    machine, tool, args, planted, user, planted_marker, clean_marker
):
    home, repo = machine
    _write(repo, planted)
    _write(home, user)
    output = _control([_tool(tool), *args], repo)
    assert planted_marker in output, output


@pytest.mark.parametrize(
    ("tool", "args", "planted", "user", "planted_marker", "clean_marker"), CASES
)
def test_the_installer_runs_the_tool_without_the_repositorys_settings(
    machine, monkeypatch, tool, args, planted, user, planted_marker, clean_marker
):
    home, repo = machine
    _write(repo, planted)
    _write(home, user)
    output = _through_the_installer([_tool(tool), *args], repo, monkeypatch)
    assert planted_marker not in output, output
    assert clean_marker in output, output


def test_the_users_own_npmrc_still_applies(machine, monkeypatch):
    """The operator's settings are the operator's; only the repository's are dropped."""
    home, repo = machine
    _write(home, NPM_USER)
    npm = _tool("npm")
    output = _through_the_installer(
        [npm, "config", "get", "registry"], repo, monkeypatch
    )
    assert "user-npmrc" in output, output


def test_each_command_starts_in_a_new_empty_directory_that_is_removed(
    tmp_path, monkeypatch
):
    """Recorded from the spawn itself, so it holds for a tool these tests cannot run."""
    seen = []

    def record(args, cwd=None, **_kwargs):
        seen.append((list(args), Path(cwd) if cwd is not None else None))
        assert seen[-1][1] is not None and list(seen[-1][1].iterdir()) == []
        return subprocess.CompletedProcess(args, 0, "", "")

    from automated_security_helper.utils import subprocess_utils

    monkeypatch.setattr(subprocess_utils, "run_command", record)
    monkeypatch.chdir(tmp_path)
    for argv in (
        ["npm", "install", "-g", "x"],
        ["gem", "install", "x"],
        ["apt-get", "install", "-y", "x"],
        ["uv", "tool", "install", "x"],
    ):
        dependencies_module.run_command(argv)
    cwds = [cwd for _args, cwd in seen]
    assert len(cwds) == 4 and len(set(cwds)) == 4, cwds
    for cwd in cwds:
        assert cwd != tmp_path and tmp_path not in cwd.parents
        assert not cwd.exists()
