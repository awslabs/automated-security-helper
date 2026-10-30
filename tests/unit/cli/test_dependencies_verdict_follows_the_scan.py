# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The install verdict counts the tools a scan here would run, and only those.

``ash dependencies install`` exits 1 when a tool it treats as needed is absent after
the install, and it treats as needed only what a scan here would run. A scanner
whose configuration disables it is not selected, and a scanner that declares the
platform unsupported (``unsupported_platform_reason``, semgrep on Windows) is
SKIPPED. Neither is looked for, so neither can make the scan fail, and neither fails
the install: semgrep absent on Windows, or cfn-nag absent with ``enabled: false``.

The other direction is kept on purpose. cfn-nag on Windows without a Ruby DevKit
declares no install command, and a scan that selects it reports it MISSING and
fails: it declares no platform decline (the scanner's docstring says why), and its
dependency check is ``find_executable("cfn_nag_scan")``. A plain install there
fails, naming it. The two CI jobs on windows-latest that install tools
(external-target scan, multi-project attribution) scan with bandit and checkov only,
so they install those two, and nothing else, with ``--tool``.

The machine is the snapshot tests' fake one: the built-in plugins and their real
commands, with ``run_command`` and ``find_executable`` answered by the scenario.
"""

from __future__ import annotations

import importlib.util
import re
import shlex
import sys
from pathlib import Path

import pytest

from tests.snapshot.dependencies.test_snapshot_dependencies_install import (
    Scenario,
    _fake_machine,
)
from tests.snapshot.support.cli import (
    LINUX_AMD64,
    WINDOWS_AMD64,
    run_cli,
    simulated_host,
)

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[3]


@pytest.fixture
def project(tmp_path, monkeypatch):
    project = tmp_path / "demo-project"
    project.mkdir()
    monkeypatch.chdir(project)
    # The absolute form of the --bin-path the tests pass, which the install
    # exports: a lookup ignores a relative ASH_BIN_PATH, with a warning.
    monkeypatch.setenv("ASH_BIN_PATH", str(project / "bin"))
    monkeypatch.delenv("RI_DEVKIT", raising=False)
    return project


def _install(monkeypatch, host, absent, *args):
    scenario = Scenario(absent_tools=frozenset(absent))
    _fake_machine(monkeypatch, scenario)
    with simulated_host(monkeypatch, host):
        run = run_cli(["dependencies", "install", "--bin-path", "bin", *args])
    plain = re.sub(r"\x1b\[[0-9;]*m", "", run.output)
    return run, " ".join(plain.split())


def _status_of(output: str, plugin: str) -> str:
    """The Status cell of ``plugin``'s row in the results table, unwrapped."""
    plain = re.sub(r"\x1b\[[0-9;]*m", "", output)
    rows = [line.split("│") for line in plain.splitlines() if line.startswith("│")]
    cells: list = []
    for columns in rows:
        if len(columns) != 9:
            continue
        name, status = columns[1].strip(), columns[6].strip()
        if name == plugin:
            cells = [status]
        elif cells and not name:
            cells.append(status)
        elif cells:
            break
    return " ".join(cell for cell in cells if cell)


def _failure_line(out: str) -> str:
    """The red reason line of the panel, or "" when the run passed."""
    return out.split("Installation Incomplete", 1)[1] if "Incomplete" in out else ""


def test_a_scanner_the_scan_skips_on_this_platform_does_not_fail_it(
    project, monkeypatch
):
    run, out = _install(monkeypatch, WINDOWS_AMD64, {"semgrep"})
    assert "semgrep" not in _failure_line(out), out
    assert run.exit_code == 0, out
    assert (
        "Not available on this platform: semgrep (semgrep publishes no Windows build)"
        in out
    ), out
    assert _status_of(run.output, "semgrep") == "NOT AVAILABLE ON THIS PLATFORM", out


def test_the_same_scanner_absent_where_scans_run_it_fails(project, monkeypatch):
    run, out = _install(monkeypatch, LINUX_AMD64, {"semgrep"})
    assert run.exit_code == 1, out
    assert "needed tool(s) still absent after install: semgrep" in out, out
    assert "Not available on this platform" not in out, out


def test_a_scanner_its_configuration_disables_does_not_fail_it(project, monkeypatch):
    run, out = _install(
        monkeypatch,
        LINUX_AMD64,
        {"cfn_nag_scan"},
        "--config-overrides",
        "scanners.cfn-nag.enabled=false",
    )
    assert "cfn-nag" not in _failure_line(out), out
    assert run.exit_code == 0, out
    assert "Disabled in the configuration, not counted: cfn-nag" in out, out
    assert _status_of(run.output, "cfn-nag") == "DISABLED IN CONFIG", out


def test_cfn_nag_on_windows_without_a_devkit_fails_a_plain_install(
    project, monkeypatch
):
    """The scan reports it MISSING, so the install fails, naming it."""
    from automated_security_helper.base.scanner_plugin import ScannerPluginBase
    from automated_security_helper.plugin_modules.ash_builtin.scanners.cfn_nag_scanner import (
        CfnNagScanner,
    )

    # What a scan decides with: no platform decline, so ScanPhase goes on to the
    # dependency check, which is find_executable(command).
    assert (
        CfnNagScanner.unsupported_platform_reason
        is ScannerPluginBase.unsupported_platform_reason
    )
    assert (
        CfnNagScanner.validate_plugin_dependencies
        is ScannerPluginBase.validate_plugin_dependencies
    )

    run, out = _install(monkeypatch, WINDOWS_AMD64, {"cfn_nag_scan"})
    assert run.exit_code == 1, out
    assert "needed tool(s) still absent after install: cfn-nag" in out, out
    assert "No install path on this platform: cfn-nag" in out, out


def test_the_ci_jobs_install_on_windows_passes(project, monkeypatch):
    """What external-target scan and multi-project attribution run on windows-latest."""
    run, out = _install(
        monkeypatch,
        WINDOWS_AMD64,
        {"cfn_nag_scan"},
        "--tool",
        "bandit",
        "--tool",
        "checkov",
    )
    assert run.exit_code == 0, out


def _gate_scanners(script: str):
    path = REPO_ROOT / "scripts" / script
    spec = importlib.util.spec_from_file_location(f"ash_gate_probe_{path.stem}", path)
    assert spec is not None and spec.loader is not None, path
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
    finally:
        sys.modules.pop(spec.name, None)
    return tuple(module.GATE_SCANNERS)


@pytest.mark.parametrize(
    "job, script",
    [
        ("external-target-scan", "verify_external_target_scan.py"),
        ("multi-project-attribution", "verify_multi_project_attribution.py"),
    ],
)
def test_the_ci_jobs_install_exactly_the_scanners_their_gate_runs(job, script):
    import yaml

    workflow = yaml.safe_load(
        (REPO_ROOT / ".github" / "workflows" / "ash-unified-ci.yml").read_text(
            encoding="utf-8"
        )
    )
    installs = [
        step["run"]
        for step in workflow["jobs"][job]["steps"]
        if "ash dependencies install" in step.get("run", "")
    ]
    assert len(installs) == 1, installs
    argv = shlex.split(installs[0])
    assert argv[:3] == ["ash", "dependencies", "install"], argv
    requested = [argv[i + 1] for i, arg in enumerate(argv) if arg == "--tool"]
    assert sorted(requested) == sorted(_gate_scanners(script)), argv


def test_a_requested_tool_counts_even_where_a_scan_skips_it(project, monkeypatch):
    """--tool is an explicit request: its failure is the run's."""
    run, out = _install(monkeypatch, WINDOWS_AMD64, {"semgrep"}, "--tool", "semgrep")
    assert run.exit_code == 1, out
    assert "requested tool(s) still not on PATH: semgrep" in out, out
    assert "Not available on this platform: semgrep" in out, out


def test_a_requested_tool_its_configuration_disables_still_counts(project, monkeypatch):
    scenario = Scenario(
        failing_tools=frozenset({"cfn-nag"}), absent_tools=frozenset({"cfn_nag_scan"})
    )
    _fake_machine(monkeypatch, scenario)
    with simulated_host(monkeypatch, LINUX_AMD64):
        run = run_cli(
            [
                "dependencies",
                "install",
                "--bin-path",
                "bin",
                "--tool",
                "cfn-nag",
                "--config-overrides",
                "scanners.cfn-nag.enabled=false",
            ]
        )
    out = " ".join(re.sub(r"\x1b\[[0-9;]*m", "", run.output).split())
    assert run.exit_code == 1, out
    assert "1 install command(s) failed" in out, out
    # Counted, so not listed as not counted.
    assert "not counted" not in out, out


def _run(monkeypatch, host, scenario, *args):
    _fake_machine(monkeypatch, scenario)
    with simulated_host(monkeypatch, host):
        run = run_cli(["dependencies", "install", "--bin-path", "bin", *args])
    return run, " ".join(re.sub(r"\x1b\[[0-9;]*m", "", run.output).split())


def test_a_failed_install_of_a_scanner_the_scan_skips_here_does_not_fail_it(
    project, monkeypatch
):
    """The rule itself: the verdict reads only what a scan here would run."""
    scenario = Scenario(failing_tools=frozenset({"semgrep"}))
    run, out = _run(monkeypatch, WINDOWS_AMD64, scenario)
    assert any("semgrep" in " ".join(cmd) for cmd in scenario.ran), scenario.ran
    assert re.search(r"Commands run: \d+ \(1 failed\)", out), out
    assert "install command(s) failed" not in out, out
    assert run.exit_code == 0, out


def test_a_disabled_plugin_that_raises_does_not_fail_it(project, monkeypatch):
    from automated_security_helper.plugin_modules.ash_builtin.scanners.cfn_nag_scanner import (
        CfnNagScanner,
    )

    def _boom(self, platform, arch):
        raise RuntimeError("cfn-nag stand-in cannot list its commands")

    monkeypatch.setattr(CfnNagScanner, "get_installation_commands", _boom)
    run, out = _run(
        monkeypatch,
        LINUX_AMD64,
        Scenario(),
        "--config-overrides",
        "scanners.cfn-nag.enabled=false",
    )
    assert "cfn-nag stand-in cannot list its commands" in out, out
    assert "plugin error(s)" not in out, out
    assert "Disabled in the configuration, not counted: cfn-nag" in out, out
    assert run.exit_code == 0, out


def test_a_requested_plugin_that_is_disabled_and_will_not_build_fails_the_run(
    project, monkeypatch
):
    """--tool names it, so its failure is this run's whatever its section says.

    A plugin that fails to construct is named by its class, and the tally
    matched requested names against declared ones, so the failure was listed as
    disabled and not counted and the run exited 0, "Installation Complete".
    """
    from automated_security_helper.plugin_modules.ash_builtin.scanners.cfn_nag_scanner import (
        CfnNagScanner,
    )

    def _boom(self, context):
        raise RuntimeError("cfn-nag stand-in cannot be built")

    monkeypatch.setattr(CfnNagScanner, "model_post_init", _boom)
    run, out = _run(
        monkeypatch,
        LINUX_AMD64,
        Scenario(),
        "--tool",
        "cfn-nag",
        "--config-overrides",
        "scanners.cfn-nag.enabled=false",
    )
    assert "cfn-nag stand-in cannot be built" in out, out
    assert "plugin error(s): CfnNagScanner" in out, out
    assert "not counted" not in out, out
    assert run.exit_code == 1, out


def test_a_platform_hook_that_raises_is_named_and_the_install_still_runs(
    project, monkeypatch
):
    from automated_security_helper.plugin_modules.ash_builtin.scanners import (
        semgrep_scanner,
    )

    def _boom(self):
        raise RuntimeError("hook stand-in failed")

    monkeypatch.setattr(
        semgrep_scanner.SemgrepScanner, "unsupported_platform_reason", _boom
    )
    scenario = Scenario()
    _fake_machine(monkeypatch, scenario)
    with simulated_host(monkeypatch, LINUX_AMD64):
        run = run_cli(
            ["dependencies", "install", "--bin-path", "bin", "--tool", "semgrep"]
        )
    out = " ".join(re.sub(r"\x1b\[[0-9;]*m", "", run.output).split())
    assert run.exit_code == 1, out
    assert "could not tell whether a scan runs semgrep" in out, out
    assert "Error getting installation commands" not in out, out
    assert any("semgrep" in " ".join(cmd) for cmd in scenario.ran), scenario.ran


def test_no_install_commands_is_said_only_when_none_ran(capsys):
    import typer

    from automated_security_helper.cli.dependencies import (
        PluginInstallOutcome,
        _report_and_exit,
    )

    outcomes = [
        PluginInstallOutcome(
            name="opengrep",
            plugin_type="scanner",
            command="opengrep",
            commands_attempted=1,
            commands_succeeded=1,
            executable="/bin/opengrep",
            disabled_by_config=True,
        ),
        PluginInstallOutcome(
            name="npm-audit", plugin_type="scanner", command="npm", executable=None
        ),
    ]
    with pytest.raises(typer.Exit):
        _report_and_exit(outcomes, requested_tools=[])
    out = " ".join(capsys.readouterr().out.split())
    assert "no install commands were run" not in out, out
    assert "needed tool(s) still absent after install: npm-audit" in out, out
