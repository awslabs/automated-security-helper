# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""`ash dependencies install`: panels, per-command lines and the results table.

The plugins, and the install commands they declare, are the real built-in ones. What
is replaced is everything that touches the machine:

- ``run_command`` never runs anything; each scenario decides its exit codes.
- ``find_executable`` answers from the scenario, in every module that imported it,
  so no tool actually installed on the test machine shows up.
- uv answers every ``--version`` probe the uv-managed scanners make while they are
  constructed with one fixed version, without running uv.
- ``sys.executable`` is pinned, because several scanners install by running
  ``<python> -c ...`` and the interpreter path is a fact about the test machine.

The installer reads ``platform.system()`` and ``platform.machine()``, and so do the
commands the plugins declare, so every scenario renders once per host in ALL_HOSTS on
every OS.
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath, PureWindowsPath

import pytest
from rich.console import Console

from automated_security_helper.utils import uv_tool_runner
from automated_security_helper.utils.uv_tool_runner import UVToolRunner
from tests.snapshot.support.cli import (
    ALL_HOSTS,
    DISPLAYED_CWD,
    displayed_cwd,
    run_cli,
    simulated_host,
)

pytestmark = pytest.mark.unit

PINNED_PYTHON = "python3"
REAL_PYTHON = sys.executable

#: The snapshots are POSIX text by construction: the commands they record name POSIX
#: paths.
_POSIX_TEXT = pytest.mark.skipif(
    os.name == "nt",
    reason="the recorded install output is POSIX by construction: its commands name POSIX paths",
)


def _hosts(*left_unmarked: str) -> list:
    """ALL_HOSTS as parameters, skipped on Windows except the hosts named.

    The hosts left unmarked are ones whose Windows ids fail in some other way than
    by reading differently from the recorded POSIX text.
    """
    return [
        pytest.param(
            host, id=host.id, marks=() if host.id in left_unmarked else _POSIX_TEXT
        )
        for host in ALL_HOSTS
    ]


@dataclass
class Scenario:
    """What the fake machine does: which installs fail, which tools end up on PATH."""

    failing_tools: frozenset[str] = frozenset()
    absent_tools: frozenset[str] = frozenset()
    ran: list[list[str]] = field(default_factory=list)

    def run_command(self, args, shell=False):
        self.ran.append(list(args))
        # Matched within each argument: "bandit[sarif,toml]>=1.7.0" installs bandit.
        failed = any(tool in arg for arg in args for tool in self.failing_tools)
        return 1 if failed else 0

    def find_executable(self, command, *args, **kwargs):
        if command is None or command in self.absent_tools:
            return None
        return f"bin/{command}"


SCENARIOS = {
    "success": Scenario(),
    # bandit's install fails on every host; grype (no build for some hosts) and npm
    # (which ASH never installs) are absent afterwards.
    "partial-failure": Scenario(
        failing_tools=frozenset({"bandit"}),
        absent_tools=frozenset({"bandit", "grype", "npm"}),
    ),
}


@pytest.fixture
def project_dir(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, snapshot_normalizer
) -> Path:
    project = tmp_path / "demo-project"
    project.mkdir()
    monkeypatch.chdir(project)
    # The bin path is printed absolute in every install command that names it (the
    # panel shows it as given); displayed_cwd keeps the absolute form's length, and so
    # the wrapping, the same on every machine.
    for spelling in (PurePosixPath(DISPLAYED_CWD), PureWindowsPath(DISPLAYED_CWD)):
        snapshot_normalizer.add_root(spelling, "WORKSPACE")
    # install_dependencies writes os.environ["ASH_BIN_PATH"] itself; setting it here
    # first means monkeypatch restores the real value afterwards. The absolute form
    # of the --bin-path the tests pass, as the command computes it under
    # displayed_cwd, so the run ends without the ASH_BIN_PATH hint: it quotes a
    # Windows path differently from a POSIX one, and
    # tests/unit/cli/test_dependencies_bin_path.py checks it.
    monkeypatch.setenv("ASH_BIN_PATH", str(Path(DISPLAYED_CWD, "bin")))
    # cfn-nag's Windows check reads it; pinned unset so the warning is the same on
    # a developer machine with a Ruby DevKit as on CI.
    monkeypatch.delenv("RI_DEVKIT", raising=False)
    return project


def _fake_machine(monkeypatch: pytest.MonkeyPatch, scenario: Scenario) -> None:
    from automated_security_helper.cli import dependencies
    from automated_security_helper.utils import subprocess_utils

    real_find_executable = subprocess_utils.find_executable
    for module in list(sys.modules.values()):
        if getattr(module, "find_executable", None) is real_find_executable:
            monkeypatch.setattr(module, "find_executable", scenario.find_executable)
    # The install command looks a tool up as a scan of the tree would
    # (find_executable_for_scan, anchored to the source directory), which does not
    # route through find_executable; the scenario answers that lookup too.
    monkeypatch.setattr(
        dependencies,
        "find_executable_for_scan",
        lambda command, root: scenario.find_executable(command),
    )
    monkeypatch.setattr(dependencies, "run_command", scenario.run_command)
    monkeypatch.setattr(dependencies, "clear_find_executable_cache", lambda: None)
    monkeypatch.setattr(sys, "executable", PINNED_PYTHON)
    # Built at import, before the snapshot terminal was pinned; rebuild it now.
    monkeypatch.setattr(dependencies, "console", Console(legacy_windows=False))
    # The uv-managed scanners probe `uv tool run <tool> --version` while they are
    # constructed. Whether that answers, and how fast, is a fact about the machine:
    # without uv, or under load, each one logs a WARNING into the output.
    monkeypatch.setattr(uv_tool_runner, "get_uv_tool_runner", _FakeUvRunner)
    # Whether cdk-nag needs installing is decided at import, from the installed
    # metadata of aws-cdk-lib, cdk-nag and constructs: with ASH's `cdk` extra in the
    # venv (CI runs `uv sync --extra cdk`) the row reads ALREADY PRESENT and its pip
    # command is skipped; without it, INSTALLED. Pinned to the extra being absent,
    # which is the case that prints the pip command a user would run.
    from automated_security_helper.plugin_modules.ash_builtin.scanners import (
        cdk_nag_scanner,
    )

    monkeypatch.setattr(cdk_nag_scanner, "_CDK_AVAILABLE", False)
    monkeypatch.setattr(
        cdk_nag_scanner,
        "_CDK_MISSING_DISTRIBUTIONS",
        list(cdk_nag_scanner._CDK_REQUIRED_DISTRIBUTIONS),
    )
    monkeypatch.setattr(cdk_nag_scanner, "_cdk_nag_version", "unavailable")
    # Whether cfn-nag's gem can build its native extension is read from the real
    # machine, not from the faked PATH: on macOS by the developer directory on disk
    # (`_macos_developer_tools_present`), on Linux by ruby.h beside the ruby on PATH
    # (`_ruby_headers_present`). Regenerated on a Linux machine, the darwin goldens
    # recorded the gem install as having no path (no developer directory there) and
    # read red on a macOS machine, where it does. Pinned to a buildable toolchain,
    # the case whose output names the gem install a user would run.
    from automated_security_helper.plugin_modules.ash_builtin.scanners import (
        cfn_nag_scanner,
    )

    monkeypatch.setattr(cfn_nag_scanner, "_macos_developer_tools_present", lambda: True)
    monkeypatch.setattr(
        cfn_nag_scanner, "_ruby_headers_present", lambda *args, **kwargs: True
    )
    # Which installer adds cdk-nag's packages depends on the environment running the
    # test: pip where it is importable, uv where it is not (a `uv sync` venv). Pinned
    # to pip, the command a user of a pip or pipx install sees.
    from automated_security_helper.utils import python_installer

    monkeypatch.setattr(python_installer, "pip_is_importable", lambda: True)
    monkeypatch.setattr(python_installer, "is_uv_tool_environment", lambda: False)


class _FakeUvRunner(UVToolRunner):
    """A uv that is installed and reports every tool at one fixed version."""

    def __init__(self) -> None:
        super().__init__()
        self._uv_available_cache = True

    def uv_availability(self):
        return True, None

    def get_tool_version(self, tool_name, package_name=None, *args, **kwargs):
        return "0.0.0-snapshot"

    def is_tool_installed(self, tool_name):
        # Asked after the install for a uv-managed tool the scenario left off
        # PATH; uv lists nothing on the fake machine.
        return False

    def __getattribute__(self, name):
        # Anything else that would start a subprocess is a probe this fake does not
        # pin yet; fail loudly rather than let it reach the real machine.
        allowed = {
            "is_uv_available",
            "uv_availability",
            "get_tool_version",
            "is_tool_installed",
            "uv_executable",
        }
        if (
            not name.startswith("_")
            and name not in allowed
            and callable(getattr(UVToolRunner, name, None))
        ):
            raise AssertionError(f"unpinned uv probe during the snapshot: {name}")
        return super().__getattribute__(name)


@pytest.mark.parametrize("host", _hosts("freebsd-riscv64"))
@pytest.mark.parametrize(
    "scenario_name, exit_code",
    [
        pytest.param("success", 0, id="success"),
        pytest.param("partial-failure", 1, id="partial-failure"),
    ],
)
def test_dependencies_install(
    scenario_name, exit_code, host, project_dir, monkeypatch, text_snapshot
):
    scenario = Scenario(
        failing_tools=SCENARIOS[scenario_name].failing_tools,
        absent_tools=SCENARIOS[scenario_name].absent_tools,
    )
    _fake_machine(monkeypatch, scenario)

    with simulated_host(monkeypatch, host), displayed_cwd(monkeypatch):
        run = run_cli(["dependencies", "install", "--bin-path", "bin"])

    assert run.exit_code == exit_code, run.output
    assert "Dependency installation results" in run.output
    assert scenario.ran, "no install command reached run_command"
    assert all(REAL_PYTHON not in cmd for cmd in scenario.ran), scenario.ran
    assert text_snapshot("txt") == run.document


@pytest.mark.parametrize("host", ALL_HOSTS, ids=lambda h: h.id)
def test_dependencies_install_bad_selection(
    host, project_dir, monkeypatch, text_snapshot
):
    scenario = Scenario()
    _fake_machine(monkeypatch, scenario)

    with simulated_host(monkeypatch, host), displayed_cwd(monkeypatch):
        run = run_cli(
            [
                "dependencies",
                "install",
                "--bin-path",
                "bin",
                "--tool",
                "grype",
                "--tool",
                "gryp",
            ]
        )

    assert run.exit_code == 2, run.output
    assert scenario.ran == [], "a bad selection must install nothing"
    assert text_snapshot("txt") == run.document


@pytest.mark.parametrize("host", _hosts("freebsd-riscv64", "windows-arm64"))
def test_dependencies_install_selected_tool(
    host, project_dir, monkeypatch, text_snapshot
):
    scenario = Scenario()
    _fake_machine(monkeypatch, scenario)

    with simulated_host(monkeypatch, host), displayed_cwd(monkeypatch):
        run = run_cli(
            [
                "dependencies",
                "install",
                "--bin-path",
                "bin",
                "-t",
                "scanner",
                "--tool",
                "grype",
                "--tool",
                "semgrep",
            ]
        )

    assert run.exit_code == 0, run.output
    assert text_snapshot("txt") == run.document
