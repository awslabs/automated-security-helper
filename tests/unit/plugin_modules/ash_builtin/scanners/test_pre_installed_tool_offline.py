# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Issue #520: a pre-installed scanner under ASH_OFFLINE must run, not re-resolve.

The reported failure: bandit[sarif,toml] is installed and on PATH, but
``uv tool list`` cannot see it (the tool dir moved with $HOME on the CI
runner). The scanner logged "Using pre-installed bandit", then ran
``uv tool run --offline --from 'bandit[sarif,toml]>=1.7.0,<2.0.0' bandit``,
which failed to resolve, and the scan reported ERROR with uv's resolver text.

Only ``subprocess.run`` is faked. Everything above it is real: the
installation-info lookup (``uv tool list``), PATH lookup, the scanner's
validation branch, the pre-installed verification, ``_run_subprocess``'s choice
between uv and direct execution, and the SARIF read. A fake that bypassed the
selection logic could not have failed on main; this one did (see the PR).
"""

import os
import subprocess
import sys
from pathlib import Path

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.plugin_modules.ash_builtin.scanners.bandit_scanner import (
    BanditScanner,
    BanditScannerConfig,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.checkov_scanner import (
    CheckovScanner,
    CheckovScannerConfig,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.semgrep_scanner import (
    SemgrepScanner,
    SemgrepScannerConfig,
)
from automated_security_helper.utils import subprocess_utils, uv_tool_runner
from automated_security_helper.utils.pre_installed_tool import (
    reset_pre_installed_tool_cache,
)

pytestmark = pytest.mark.skipif(
    sys.platform == "win32",
    reason="fakes a POSIX venv layout (bin/python next to the tool); Windows "
    "launchers are .exe files this fixture does not model",
)

# Verbatim shape of the stderr in the issue.
UV_RESOLVE_FAILURE = """  x No solution found when resolving tool dependencies:
  `-> Because sarif-om was not found in the cache and bandit>=1.9.4
      depends on sarif-om>=1.0.4, we can conclude that bandit>=1.9.4
      cannot be used.

hint: Packages were unavailable because the network was disabled. When the network is disabled, registry packages may
only be read from the cache.
"""

EMPTY_SARIF = (
    '{"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "Bandit"}}, '
    '"results": []}]}'
)


def _completed(argv, returncode=0, stdout="", stderr=""):
    return subprocess.CompletedProcess(argv, returncode, stdout, stderr)


class FakeHost:
    """A host where ``tool`` is installed in a venv whose bin dir is on PATH,
    and uv's tool dir and cache are empty, as on the reporter's CI runner."""

    def __init__(self, tmp_path: Path, tool: str, env_satisfies: bool = True):
        self.tool = tool
        self.env_satisfies = env_satisfies
        venv_bin = tmp_path / "tool-venv" / "bin"
        venv_bin.mkdir(parents=True)
        for name in ("python", tool):
            path = venv_bin / name
            path.write_text("#!/bin/sh\nexit 0\n")
            path.chmod(0o755)
        self.tool_path = str(venv_bin / tool)
        self.calls: list[list[str]] = []
        self.ran_direct = False

    def run(self, argv, *args, **kwargs):
        argv = [str(a) for a in argv]
        self.calls.append(argv)
        exe = Path(argv[0]).name

        if exe in ("uv", "uv.exe"):
            sub = argv[1:3]
            if argv[1:] == ["--version"]:
                return _completed(argv, stdout="uv 0.12.19\n")
            if sub == ["tool", "list"]:
                return _completed(argv, stdout="No tools installed\n")
            if sub == ["tool", "run"]:
                if "--offline" in argv:
                    return _completed(argv, 1, stderr=UV_RESOLVE_FAILURE)
                return _completed(argv, 1, stderr="network unreachable\n")
            if sub == ["pip", "install"] and "--dry-run" in argv:
                requirement = argv[-1]
                if self.env_satisfies or "sarif" not in requirement:
                    return _completed(argv, stderr="Would make no changes\n")
                return _completed(
                    argv,
                    1,
                    stderr="  x No solution found when resolving dependencies:\n"
                    "  `-> Because sarif-om was not found in the cache\n",
                )
            raise AssertionError(f"unexpected uv call: {argv}")

        if argv[0] == self.tool_path or exe == self.tool:
            if argv[1:] == ["--version"]:
                return _completed(argv, stdout=f"{self.tool} 1.9.4\n")
            self.ran_direct = True
            if "--output" in argv:
                Path(argv[argv.index("--output") + 1]).write_text(EMPTY_SARIF)
            return _completed(argv, 0)

        raise AssertionError(f"unexpected subprocess call: {argv}")


@pytest.fixture
def offline_host(tmp_path, monkeypatch):
    def make(tool, env_satisfies=True, offline=True):
        host = FakeHost(tmp_path, tool, env_satisfies)
        monkeypatch.setenv(
            "PATH", f"{Path(host.tool_path).parent}{os.pathsep}{os.environ['PATH']}"
        )
        if offline:
            monkeypatch.setenv("ASH_OFFLINE", "YES")
        else:
            monkeypatch.delenv("ASH_OFFLINE", raising=False)
        monkeypatch.setattr(subprocess, "run", host.run)
        return host

    yield make


@pytest.fixture(autouse=True)
def _fresh_caches():
    def reset():
        uv_tool_runner._reset_uv_tool_runner_caches()
        uv_tool_runner.reset_uv_tool_runner()
        subprocess_utils.clear_find_executable_cache()
        reset_pre_installed_tool_cache()

    reset()
    yield
    reset()


@pytest.fixture
def plugin_context(tmp_path):
    context = PluginContext(
        source_dir=tmp_path / "src",
        output_dir=tmp_path / "out",
        work_dir=tmp_path / "work",
        config=get_default_config(),
    )
    for d in (context.source_dir, context.output_dir, context.work_dir):
        d.mkdir(parents=True)
    (context.source_dir / "app.py").write_text("print('hi')\n")
    return context


def test_offline_pre_installed_bandit_scans_instead_of_erroring(
    offline_host, plugin_context
):
    """The #520 reproduction, end to end through validate and scan."""
    host = offline_host("bandit")
    scanner = BanditScanner(context=plugin_context, config=BanditScannerConfig())

    assert scanner.validate_plugin_dependencies() is True
    report = scanner.scan(target=plugin_context.source_dir, target_type="source")

    assert report.runs is not None and report.runs[0].results == []
    assert host.ran_direct, "the verified binary on PATH must be what ran"
    uv_runs = [c for c in host.calls if c[1:3] == ["tool", "run"]]
    # The version probe may ask uv, but only offline: an online probe is a
    # network install under ASH_OFFLINE, and it is what left uv's cache
    # half-filled when its timeout cut it off.
    probes = [c for c in uv_runs if c[-1] == "--version"]
    assert all("--offline" in c for c in probes), probes
    offline_resolves = [c for c in uv_runs if c[-1] != "--version"]
    assert offline_resolves == [], (
        "an offline `uv tool run --from` re-resolve is the reported failure; "
        f"it must not be attempted for a verified pre-installed tool: {offline_resolves}"
    )


def test_verification_checks_the_extras_the_scan_needs(offline_host, plugin_context):
    """'Pre-installed' is verified against bandit[sarif,toml] and the constraint."""
    host = offline_host("bandit")
    scanner = BanditScanner(context=plugin_context, config=BanditScannerConfig())

    assert scanner.validate_plugin_dependencies() is True

    dry_runs = [c for c in host.calls if c[1:3] == ["pip", "install"]]
    assert dry_runs, "the environment's extras were never checked"
    assert dry_runs[0][-1] == "bandit[sarif,toml]>=1.7.0,<2.0.0"
    assert dry_runs[0][dry_runs[0].index("--python") + 1] == str(
        Path(host.tool_path).parent / "python"
    )
    assert {"--dry-run", "--offline", "--no-cache"} <= set(dry_runs[0])


def test_offline_pre_installed_bandit_without_sarif_is_missing_with_a_named_reason(
    offline_host, plugin_context
):
    offline_host("bandit", env_satisfies=False)
    scanner = BanditScanner(context=plugin_context, config=BanditScannerConfig())

    assert scanner.validate_plugin_dependencies() is False
    reason = scanner.dependency_unavailable_reason
    assert reason is not None
    assert "missing extra: sarif" in reason
    assert "uv tool install 'bandit[sarif,toml]>=1.7.0,<2.0.0'" in reason


def test_online_pre_installed_bandit_without_sarif_keeps_uv(
    offline_host, plugin_context
):
    """Online, uv can fetch the missing extra, so the uv path stays."""
    offline_host("bandit", env_satisfies=False, offline=False)
    scanner = BanditScanner(context=plugin_context, config=BanditScannerConfig())

    assert scanner.validate_plugin_dependencies() is True
    assert scanner.use_uv_tool is True
    assert scanner.dependency_unavailable_reason is None


@pytest.mark.parametrize(
    "scanner_cls, config_cls, tool",
    [
        (BanditScanner, BanditScannerConfig, "bandit"),
        (CheckovScanner, CheckovScannerConfig, "checkov"),
        (SemgrepScanner, SemgrepScannerConfig, "semgrep"),
    ],
)
def test_every_uv_backed_scanner_runs_a_verified_pre_installed_tool_directly(
    offline_host, plugin_context, tmp_path, monkeypatch, scanner_cls, config_cls, tool
):
    """The class, not the instance: all three shared the same branch."""
    rules = tmp_path / "semgrep-rules"
    rules.mkdir()
    (rules / "p-ci.yaml").write_text("rules: []\n")
    monkeypatch.setenv("SEMGREP_RULES_CACHE_DIR", str(rules))
    offline_host(tool)
    scanner = scanner_cls(context=plugin_context, config=config_cls())

    assert scanner.validate_plugin_dependencies() is True
    assert scanner.use_uv_tool is False, (
        f"{tool}: a verified pre-installed binary must run directly offline"
    )


def test_unexplained_offline_resolve_failure_is_named_in_the_scan_error(
    offline_host, plugin_context, monkeypatch
):
    """When nothing verifiable is on PATH, the uv failure is explained, not raw."""
    host = offline_host("bandit")
    # Remove the interpreter so the binary cannot be verified; uv stays in charge.
    (Path(host.tool_path).parent / "python").unlink()
    scanner = BanditScanner(context=plugin_context, config=BanditScannerConfig())

    assert scanner.validate_plugin_dependencies() is True
    assert scanner.use_uv_tool is True

    with pytest.raises(Exception) as excinfo:
        scanner.scan(target=plugin_context.source_dir, target_type="source")

    message = str(excinfo.value)
    assert (
        "Offline mode: uv could not resolve 'bandit[sarif,toml]>=1.7.0,<2.0.0'"
        in message
    )
    assert message.index("Offline mode:") < message.index("No solution found")
