# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The uv-backed scanners' dependency checks probe the spec the scan runs under.

``get_uv_tool_command`` probes ``uv tool run --from <spec> <tool> --version`` when
it is given the ``--from`` spec the scan itself runs under, and the bare ``uv tool
run <tool> --version`` otherwise. The two resolve different environments
(``UVToolMixin._uv_from_spec`` says why), so a bare probe answers for an
environment the scan never uses and warms the wrong entry-point cache for the
scanners to race on. Every scanner's check called the resolver bare. Here the
resolver is stood in for and its arguments recorded, and each branch of a check
that reaches it is driven in turn; no process starts.

One scanner is also driven through the real resolver with the process boundary
replaced, so ``--from`` and the pinned spec are read on the probe's own argv.
"""

from __future__ import annotations

import os
import subprocess  # nosec B404
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.plugin_modules.ash_builtin.scanners import (
    bandit_scanner,
    cfn_lint_scanner,
    checkov_scanner,
    semgrep_scanner,
    zizmor_scanner,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.bandit_scanner import (
    BanditScanner,
    BanditScannerConfig,
    BanditScannerConfigOptions,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.cfn_lint_scanner import (
    CfnLintScanner,
    CfnLintScannerConfig,
    CfnLintScannerConfigOptions,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.checkov_scanner import (
    CheckovScanner,
    CheckovScannerConfig,
    CheckovScannerConfigOptions,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.semgrep_scanner import (
    SemgrepScanner,
    SemgrepScannerConfig,
    SemgrepScannerConfigOptions,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.zizmor_scanner import (
    ZizmorScanner,
    ZizmorScannerConfig,
    ZizmorScannerConfigOptions,
)
from automated_security_helper.utils import uv_tool_runner
from automated_security_helper.utils.config_trust import record_provenance
from automated_security_helper.utils.uv_tool_runner import (
    _reset_uv_tool_runner_caches,
)

pytestmark = pytest.mark.unit

#: The uv the real-resolver test finds. The probe spawns it with the process
#: boundary replaced, so nothing is created at this path.
UV_PATH = os.path.abspath("/opt/uv/bin/uv")


@pytest.fixture
def context(tmp_path: Path) -> PluginContext:
    config = get_default_config()
    # The options came from the operator, as cfn-lint reads them.
    record_provenance(config, in_tree=[], trusted=AshConfig(), config_overrides=[])
    context = PluginContext(
        source_dir=tmp_path / "src",
        output_dir=tmp_path / "out",
        work_dir=tmp_path / "work",
        config=config,
    )
    for directory in (context.source_dir, context.output_dir, context.work_dir):
        directory.mkdir(parents=True)
    return context


class _Resolver:
    """A stand-in for ``get_uv_tool_command`` that records how it was asked."""

    def __init__(self, answer=None):
        self.answer = answer
        self.calls: list[tuple[str, dict]] = []

    def __call__(self, tool_name, **kwargs):
        self.calls.append((tool_name, dict(kwargs)))
        return self.answer


def _uv_absent(monkeypatch, scanner_class) -> None:
    """The runner reports uv unavailable; the check asks the resolver directly."""
    monkeypatch.setattr(
        scanner_class, "_validate_uv_tool_availability", lambda self: False
    )


def _install_fails(monkeypatch, scanner_class) -> None:
    """uv is present, the tool is not installed, and the explicit install fails,
    so the check reaches its last resort, the resolver."""
    monkeypatch.setattr(
        scanner_class, "_validate_uv_tool_availability", lambda self: True
    )
    monkeypatch.setattr(
        scanner_class, "_get_tool_installation_info", lambda self: {"available": False}
    )
    monkeypatch.setattr(
        scanner_class, "_install_uv_tool", lambda self, *args, **kwargs: False
    )
    monkeypatch.setattr(scanner_class, "_is_offline_mode", lambda self: False)


def _bandit(context, monkeypatch) -> BanditScanner:
    return BanditScanner(
        context=context,
        config=BanditScannerConfig(options=BanditScannerConfigOptions()),
    )


def _checkov(context, monkeypatch) -> CheckovScanner:
    return CheckovScanner(
        context=context,
        config=CheckovScannerConfig(options=CheckovScannerConfigOptions()),
    )


def _cfn_lint(context, monkeypatch) -> CfnLintScanner:
    return CfnLintScanner(
        context=context,
        config=CfnLintScannerConfig(
            enabled=True, options=CfnLintScannerConfigOptions()
        ),
    )


def _semgrep(context, monkeypatch) -> SemgrepScanner:
    monkeypatch.delenv("SEMGREP_RULES_CACHE_DIR", raising=False)
    monkeypatch.setattr(SemgrepScanner, "_scanner_offline", lambda self: False)
    monkeypatch.setattr(
        SemgrepScanner, "unsupported_platform_reason", lambda self: None
    )
    return SemgrepScanner(
        context=context,
        config=SemgrepScannerConfig(options=SemgrepScannerConfigOptions(offline=False)),
    )


def _zizmor(context, monkeypatch) -> ZizmorScanner:
    return ZizmorScanner(
        context=context,
        config=ZizmorScannerConfig(enabled=True, options=ZizmorScannerConfigOptions()),
    )


#: (module whose resolver is patched, scanner builder, scanner class, arrange,
#: the method that reaches the resolver, what the pinned spec starts with).
ROWS = [
    pytest.param(
        bandit_scanner,
        _bandit,
        BanditScanner,
        _uv_absent,
        "validate_plugin_dependencies",
        "bandit[sarif,toml]",
        id="bandit-uv-absent",
    ),
    pytest.param(
        bandit_scanner,
        _bandit,
        BanditScanner,
        _install_fails,
        "validate_plugin_dependencies",
        "bandit[sarif,toml]",
        id="bandit-install-failed",
    ),
    pytest.param(
        checkov_scanner,
        _checkov,
        CheckovScanner,
        _uv_absent,
        "validate_plugin_dependencies",
        "checkov",
        id="checkov-uv-absent",
    ),
    pytest.param(
        checkov_scanner,
        _checkov,
        CheckovScanner,
        _install_fails,
        "validate_plugin_dependencies",
        "checkov",
        id="checkov-install-failed",
    ),
    pytest.param(
        cfn_lint_scanner,
        _cfn_lint,
        CfnLintScanner,
        _uv_absent,
        "validate_plugin_dependencies",
        "cfn-lint[sarif]",
        id="cfn-lint-uv-absent",
    ),
    pytest.param(
        cfn_lint_scanner,
        _cfn_lint,
        CfnLintScanner,
        _install_fails,
        "validate_plugin_dependencies",
        "cfn-lint[sarif]",
        id="cfn-lint-install-failed",
    ),
    pytest.param(
        semgrep_scanner,
        _semgrep,
        SemgrepScanner,
        _uv_absent,
        "_validate_tool_dependencies",
        "semgrep>=1.125.0,<2.0.0",
        id="semgrep-uv-absent",
    ),
    # No semgrep install-failed row: after a failed install, semgrep's last resort
    # looks the binary up on PATH itself and never asks the resolver (its own test
    # file pins that), so the uv-absent row above is its one resolver call.
    pytest.param(
        zizmor_scanner,
        _zizmor,
        ZizmorScanner,
        _install_fails,
        "_resolve_through_uv",
        "zizmor>=1.29.0,<2.0.0",
        id="zizmor-install-failed",
    ),
]


@pytest.mark.parametrize(
    ("module", "build", "scanner_class", "arrange", "check", "spec_head"), ROWS
)
def test_the_check_hands_the_resolver_the_scans_own_spec(
    context, monkeypatch, module, build, scanner_class, arrange, check, spec_head
):
    """Fails at the base on every row: the resolver was asked with the tool name
    alone, so ``from_spec`` is not among its arguments."""
    scanner = build(context, monkeypatch)
    arrange(monkeypatch, scanner_class)
    resolver = _Resolver(answer=None)
    monkeypatch.setattr(module, "get_uv_tool_command", resolver)

    getattr(scanner, check)()

    spec = scanner._uv_from_spec()
    assert spec is not None and spec.startswith(spec_head), (
        "premise: the scan runs under a pinned spec"
    )
    ((asked, kwargs),) = resolver.calls
    assert asked == scanner.command
    assert "from_spec" in kwargs, "the probe was asked bare"
    assert kwargs["from_spec"] == spec


def test_the_probe_argv_carries_the_pinned_spec(context, monkeypatch):
    """Through the real resolver: the spawned probe is
    ``uv tool run --from <the scan's spec> bandit --version``."""
    monkeypatch.delenv("ASH_OFFLINE", raising=False)
    monkeypatch.delenv("UV_OFFLINE", raising=False)
    spawn = MagicMock(
        return_value=subprocess.CompletedProcess([], 0, "bandit 1.8.6\n", "")
    )
    monkeypatch.setattr(uv_tool_runner, "spawn_run", spawn)
    monkeypatch.setattr(uv_tool_runner, "find_uv_or_none", lambda: UV_PATH)
    monkeypatch.setattr(uv_tool_runner, "find_executable", lambda name: None)
    scanner = _bandit(context, monkeypatch)
    _uv_absent(monkeypatch, BanditScanner)
    _reset_uv_tool_runner_caches()
    try:
        assert scanner.validate_plugin_dependencies() is True
    finally:
        _reset_uv_tool_runner_caches()

    spec = scanner._uv_from_spec()
    assert spec is not None and spec.startswith("bandit[sarif,toml]")
    argv = spawn.call_args.args[0]
    assert argv[:3] == [UV_PATH, "tool", "run"]
    assert argv[-4:] == ["--from", spec, "bandit", "--version"]


@pytest.mark.parametrize("scanner_offline", [True, False], ids=["offline", "online"])
def test_semgreps_own_offline_mode_reaches_the_real_resolvers_probe(
    context, monkeypatch, scanner_offline
):
    """Through the real resolver, with ASH online: semgrep's check passes its own
    offline mode as the resolver's ``offline`` keyword, and the spawned probe
    carries it as ``--offline`` and ``UV_OFFLINE=1``; online, neither. Every other
    semgrep test replaces the resolver with a ``**kwargs`` stub, so a keyword the
    resolver does not accept would raise TypeError on every host where uv is not
    available to the runner and no test would see it; this row calls the real
    signature.

    Fails at the base: the resolver was asked without ``offline``, so the probe of
    a scanner with ``options.offline: true`` ran online under ASH online.
    """
    monkeypatch.delenv("ASH_OFFLINE", raising=False)
    monkeypatch.delenv("UV_OFFLINE", raising=False)
    spawn = MagicMock(return_value=subprocess.CompletedProcess([], 0, "1.180.0\n", ""))
    monkeypatch.setattr(uv_tool_runner, "spawn_run", spawn)
    monkeypatch.setattr(uv_tool_runner, "find_uv_or_none", lambda: UV_PATH)
    monkeypatch.setattr(uv_tool_runner, "find_executable", lambda name: None)
    scanner = _semgrep(context, monkeypatch)
    # The scanner's own mode, as the mixin resolves it from options.offline; ASH's
    # mode stays off (ASH_OFFLINE unset), so only the keyword can carry it.
    monkeypatch.setattr(
        SemgrepScanner, "_is_offline_mode", lambda self: scanner_offline
    )
    _uv_absent(monkeypatch, SemgrepScanner)
    _reset_uv_tool_runner_caches()
    try:
        assert scanner._validate_tool_dependencies() is True
    finally:
        _reset_uv_tool_runner_caches()

    spec = scanner._uv_from_spec()
    assert spec is not None and spec.startswith("semgrep")
    argv = spawn.call_args.args[0]
    env = spawn.call_args.kwargs["env"]
    assert argv[0] == UV_PATH
    assert argv[-4:] == ["--from", spec, "semgrep", "--version"]
    assert ("--offline" in argv) is scanner_offline, argv
    assert (env.get("UV_OFFLINE") == "1") is scanner_offline, sorted(
        key for key in env if key.startswith("UV_")
    )
