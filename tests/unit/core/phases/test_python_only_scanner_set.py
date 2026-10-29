"""``--python-only`` runs exactly the scanners that need nothing but Python.

A plugin that declares no dependencies and no install commands is not Python-only
on that alone, so a scanner that runs a native tool and says nothing about it does
not run under ``--python-only``: snyk-code (the Snyk CLI, which uploads the source),
ferret-scan (a Go binary) and cdk-nag (which needs Node.js through jsii). Scanners
answer ``is_python_only`` for themselves; one that does not counts only when it runs
its tool through uv.

The set is pinned over every built-in and community scanner ASH ships, constructed
for real, and then through ScanPhase, which is what ``--python-only`` reaches.
"""

from __future__ import annotations

from typing import ClassVar, Literal
from unittest.mock import MagicMock, patch

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.base.plugin_config import plugin_config_key
from automated_security_helper.base.scanner_plugin import (
    ScannerPluginBase,
    ScannerPluginConfigBase,
)
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.constants import ASH_WORK_DIR_NAME
from automated_security_helper.core.enums import ScannerStatus
from automated_security_helper.core.phases.scan_phase import ScanPhase
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.plugin_modules import (
    ash_builtin,
    ash_ferret_plugins,
    ash_snyk_plugins,
    ash_trivy_plugins,
)

pytestmark = pytest.mark.unit

AshConfig.model_rebuild()
AshAggregatedResults.model_rebuild()

#: What each shipped scanner needs. Python-only: a Python package ASH installs with
#: uv (bandit, cfn-lint, checkov, semgrep, zizmor) or imports (detect-secrets).
#: zizmor's wheel carries its native binary, as semgrep's carries semgrep-core.
PYTHON_ONLY = {"bandit", "cfn-lint", "checkov", "detect-secrets", "semgrep", "zizmor"}
NOT_PYTHON_ONLY = {
    "actionlint",  # a native binary, from its pinned release asset
    "cdk-nag",  # Node.js, through jsii
    "cfn-guard",  # a native binary, from its pinned release asset
    "cfn-nag",  # a Ruby gem
    "ferret-scan",  # a Go binary
    "gitleaks",  # a native binary, from its pinned release asset
    "grype",
    "npm-audit",  # npm, yarn or pnpm
    "opengrep",
    "snyk-code",  # the Snyk CLI
    "syft",
    "trivy",  # a native binary, from its pinned release asset
    "trivy-repo",
}

SHIPPED = [
    *ash_builtin.ASH_SCANNERS,
    *ash_snyk_plugins.ASH_SCANNERS,
    *ash_ferret_plugins.ASH_SCANNERS,
    *ash_trivy_plugins.ASH_SCANNERS,
]


@pytest.fixture(autouse=True)
def _no_uv_tool_probe(monkeypatch):
    """bandit, checkov and semgrep probe their version with `uv tool run` when built.

    That probe writes under HOME and the XDG cache dir, and checkov's update check
    reaches PyPI. Python-only selection does not depend on the version, so the
    probe answers None here, as in test_dependencies_install_applies_uv_tool_pins.
    """
    from automated_security_helper.base.uv_tool_mixin import UVToolMixin

    monkeypatch.setattr(UVToolMixin, "_get_uv_tool_version", lambda *_a, **_k: None)


@pytest.fixture(autouse=True)
def no_tool_starts(tmp_path_factory, monkeypatch):
    """Recording stand-ins first on PATH; no test here may start a tool.

    Building the shipped scanners probed ``opengrep --version`` on the host's
    opengrep, which the uv runner double above does not see; the probes are
    answered as on a host without the tools (``stub_tool_probes``).
    """
    from tests.utils.tool_guard import (
        install_tool_guard,
        reset_tool_lookup_caches,
        stub_tool_probes,
    )

    guard = install_tool_guard(monkeypatch, tmp_path_factory.mktemp("guard-bin"))
    stub_tool_probes(monkeypatch)
    yield guard
    reset_tool_lookup_caches()
    assert guard.started == [], f"the test started tools: {guard.started}"


@pytest.fixture
def context(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "app.py").write_text("x = 1\n", encoding="utf-8")
    output = tmp_path / "output"
    (output / ASH_WORK_DIR_NAME).mkdir(parents=True)
    return PluginContext(
        source_dir=source,
        output_dir=output,
        work_dir=output / ASH_WORK_DIR_NAME,
        config=get_default_config(),
    )


class _RecordingRunner:
    """A uv tool runner that runs nothing and records what it was asked."""

    def __init__(self, asked):
        self.asked = asked

    def is_uv_available(self):
        return True

    def get_tool_version(self, tool_name, package_name=None):
        self.asked.append(tool_name)
        return None


@pytest.fixture
def uv_tool_requests(tmp_path, monkeypatch):
    """What the scanners ask uv to run, with HOME and the XDG dirs on tmp."""
    from automated_security_helper.utils import uv_tool_runner

    home = tmp_path / "home"
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("XDG_CACHE_HOME", str(home / ".cache"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(home / ".config"))
    asked: list[str] = []
    monkeypatch.setattr(
        uv_tool_runner, "get_uv_tool_runner", lambda: _RecordingRunner(asked)
    )
    return home, asked


def test_building_the_scanners_runs_no_tool(context, uv_tool_requests, no_tool_starts):
    """checkov's, semgrep's and bandit's version probe runs `uv tool run`.

    Against a real uv that writes checkov/update_checker_cache.json under the cache
    dir and .semgrep/settings.yml under HOME, and checkov's update check reaches
    PyPI, so a test that builds the shipped scanners must not let the probe run.
    """
    home, asked = uv_tool_requests

    list(_instances(context))

    assert asked == [], f"the version probe asked uv to run {asked}"
    assert not (home / ".cache" / "checkov").exists()
    assert not (home / ".semgrep").exists()
    assert no_tool_starts.started == [], (
        f"building the scanners started tools: {no_tool_starts.started}"
    )


def _instances(context):
    config = context.config
    for cls in SHIPPED:
        yield cls(
            config=config.get_plugin_config(
                plugin_type="scanner", plugin_name=plugin_config_key(cls)
            ),
            context=context,
        )


def test_every_shipped_scanner_answers_correctly(context):
    answers = {
        scanner.config.name: scanner.is_python_only() for scanner in _instances(context)
    }

    assert set(answers) == PYTHON_ONLY | NOT_PYTHON_ONLY, (
        "a shipped scanner was added or renamed; classify it here"
    )
    wrong = {
        name: answer
        for name, answer in answers.items()
        if answer != (name in PYTHON_ONLY)
    }
    assert wrong == {}, f"is_python_only() answers wrongly for {wrong}"


def test_python_only_runs_exactly_the_python_only_set(context):
    aggregated = AshAggregatedResults()
    phase = ScanPhase(
        plugin_context=context,
        plugins=SHIPPED,
        progress_display=MagicMock(),
        asharp_model=aggregated,
    )
    phase.validation_manager = MagicMock()
    with (
        patch.object(
            ScannerPluginBase, "validate_plugin_dependencies", return_value=True
        ),
        patch(
            "automated_security_helper.core.phases.scan_phase.ScannerExecutor"
        ) as executor,
    ):
        for scanner_class in SHIPPED:
            patch.object(
                scanner_class, "validate_plugin_dependencies", return_value=True
            ).start()
        double = MagicMock()
        double.completed_scanners = []
        double.run_parallel.return_value = aggregated
        double.run_sequential.return_value = aggregated
        executor.return_value = double
        try:
            results = phase._execute_phase(
                aggregated_results=aggregated, python_based_plugins_only=True
            )
        finally:
            patch.stopall()
        queued = {name for name, _, _ in executor.call_args.kwargs["scanner_tasks"]}

    assert queued == PYTHON_ONLY
    for name in NOT_PYTHON_ONLY:
        row = results.scanner_results[name]
        assert row.status == ScannerStatus.SKIPPED, (name, row)
        assert "--python-only" in (row.skipped_reason or ""), (name, row)


class _Config(ScannerPluginConfigBase):
    name: Literal["undeclared-tool"] = "undeclared-tool"


def _undeclared(use_uv_tool: bool):
    class _Undeclared(ScannerPluginBase):
        def model_post_init(self, context):
            if self.config is None:
                self.config = _Config()
            self.command = "undeclared-tool"
            self.use_uv_tool = use_uv_tool
            super().model_post_init(context)

        def _execute_scan(self, target, target_type, global_ignore_paths):
            raise NotImplementedError

    return _Undeclared


def test_a_scanner_that_declares_nothing_and_runs_a_binary_is_not_python_only(
    context,
):
    """The old default: no declared dependencies read as Python-only."""
    assert _undeclared(use_uv_tool=False)(context=context).is_python_only() is False


def test_a_scanner_that_declares_nothing_and_runs_through_uv_is_python_only(context):
    assert _undeclared(use_uv_tool=True)(context=context).is_python_only() is True


def test_a_declaration_wins(context):
    class _Declared(_undeclared(use_uv_tool=True)):
        python_only: ClassVar[bool | None] = False

    assert _Declared(context=context).is_python_only() is False


def test_the_example_scanner_plugin_is_python_only(context):
    """examples/ash_plugins_example's scanner runs in-process and starts nothing.

    It declared nothing, so after the default changed --python-only left the
    example out, though it is the shape the plugin guide holds up. Loaded from its
    path, with the plugin manager's registration stubbed (see
    test_plugin_context_shared_state.py).
    """
    import importlib.util
    import sys
    from pathlib import Path

    from automated_security_helper.plugins import ash_plugin_manager

    path = (
        Path(__file__).resolve().parents[4]
        / "examples"
        / "ash_plugins_example"
        / "my_ash_plugins"
        / "scanner.py"
    )
    module_name = "_ash_example_plugin_scanner_python_only"
    spec = importlib.util.spec_from_file_location(module_name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    try:
        with patch.object(ash_plugin_manager, "register_plugin_module"):
            spec.loader.exec_module(module)
        scanner = module.ExampleScanner(context=context)
        assert scanner.is_python_only() is True
    finally:
        sys.modules.pop(module_name, None)


def test_an_in_process_scanner_that_declares_true_is_python_only(context):
    """The scanner plugin guide's example: no uv tool, python_only = True."""

    class _InProcess(_undeclared(use_uv_tool=False)):
        python_only: ClassVar[bool | None] = True

    assert _InProcess(context=context).is_python_only() is True
