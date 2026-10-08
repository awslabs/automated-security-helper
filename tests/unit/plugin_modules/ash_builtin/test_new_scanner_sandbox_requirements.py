# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""What the new builtin scanners get from the scanner sandbox, through the real policy.

A scanner that declares no ``sandbox_requirements`` gets the strict default: no
network, the baseline read-only paths, its results directory as the only writable
place, and the baseline environment allowlist. Two of the new scanners cannot work
under that default:

* ``trivy`` (and ``trivy-repo``, which shares ``TrivyScannerBase``) downloads the
  vulnerability database into its cache when online and reads ``TRIVY_*`` settings;
* ``cfn-guard`` reads its rules bundle from ``rules_root()``, ASH's own install
  location beside the bin directory, which the baseline does not expose.

actionlint, cfn-lint, gitleaks and zizmor declare the strict default. Grants derived
from options or the environment (zizmor's online audits, gitleaks' GITLEAKS_*
variables) wait for the sandbox's grant gates. Each test builds the policy with
``build_scanner_policy``, the function every sandboxed spawn goes through, so a
declaration the policy ignores fails here.
"""

from __future__ import annotations

import sys
from types import SimpleNamespace

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.plugin_modules.ash_builtin.scanners.actionlint_scanner import (
    ActionlintScanner,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.cfn_guard_scanner import (
    CfnGuardScanner,
    CfnGuardScannerConfig,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.cfn_lint_scanner import (
    CfnLintScanner,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.gitleaks_scanner import (
    GitleaksScanner,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.trivy_scanner import (
    TrivyScanner,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.zizmor_scanner import (
    GITHUB_TOKEN_ENV_VARS,
    ZizmorScanner,
)
from automated_security_helper.plugin_modules.ash_trivy_plugins.trivy_repo_scanner import (
    TrivyRepoScanner,
)
from automated_security_helper.utils.rules_bundles import RULES_DIR_ENV
from automated_security_helper.utils.sandbox.policy import (
    SandboxRequirements,
    build_scanner_policy,
)


@pytest.fixture
def layout(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    source = tmp_path / "src"
    source.mkdir()
    output = source / ".ash" / "ash_output"
    output.mkdir(parents=True)
    return SimpleNamespace(home=home, source=source, output=output, tmp=tmp_path)


def _policy(layout, name, requirements, *, offline=False):
    return build_scanner_policy(
        name,
        requirements,
        argv0=sys.executable,
        source_dir=layout.source,
        output_dir=layout.output,
        results_dir=layout.output / "scanners" / name,
        scan_target=layout.source,
        cwd=layout.source,
        offline=offline,
        network_scanners=None,
    )


def _real(paths):
    return {p.resolve() for p in paths}


def _context(layout) -> PluginContext:
    return PluginContext(
        source_dir=layout.source,
        output_dir=layout.output,
        work_dir=layout.output / "converted",
        config=get_default_config(),
    )


@pytest.mark.parametrize("scanner_class", [TrivyScanner, TrivyRepoScanner])
def test_both_trivy_scanners_get_a_network_and_their_database_cache(
    layout, monkeypatch, scanner_class
):
    cache = layout.tmp / "trivy-cache"
    cache.mkdir()
    monkeypatch.setenv("TRIVY_CACHE_DIR", str(cache))

    policy = _policy(layout, "trivy", scanner_class.sandbox_requirements)

    assert policy.network is True
    assert cache.resolve() in _real(policy.cache)
    env = policy.filter_env({"TRIVY_DB_REPOSITORY": "mirror.example/trivy-db"})
    assert env["TRIVY_DB_REPOSITORY"] == "mirror.example/trivy-db"
    # The declaration lives on the shared base, so the two cannot drift apart.
    assert scanner_class.sandbox_requirements is TrivyScanner.sandbox_requirements
    offline = _policy(layout, "trivy", scanner_class.sandbox_requirements, offline=True)
    assert offline.network is False


def test_cfn_guard_reads_the_rules_root_from_the_environment(layout, monkeypatch):
    rules = layout.tmp / "cfn-guard-rules"
    rules.mkdir()
    monkeypatch.setenv(RULES_DIR_ENV, str(rules))
    scanner = CfnGuardScanner(context=_context(layout), config=CfnGuardScannerConfig())

    policy = _policy(layout, "cfn-guard", scanner.sandbox_requirements)

    assert rules.resolve() in _real(policy.read_only)
    assert policy.network is False


def test_cfn_guard_reads_the_default_rules_root_beside_the_bin_path(
    layout, monkeypatch
):
    bin_path = layout.home / ".ash" / "bin"
    bin_path.mkdir(parents=True)
    default_rules = layout.home / ".ash" / "share" / "cfn-guard-rules"
    default_rules.mkdir(parents=True)
    monkeypatch.delenv(RULES_DIR_ENV, raising=False)
    monkeypatch.setenv("ASH_BIN_PATH", str(bin_path))
    scanner = CfnGuardScanner(context=_context(layout), config=CfnGuardScannerConfig())

    policy = _policy(layout, "cfn-guard", scanner.sandbox_requirements)

    assert default_rules.resolve() in _real(policy.read_only)
    # Only the rules directory: the rest of ~/.ash/share stays hidden.
    assert (layout.home / ".ash" / "share").resolve() not in _real(policy.read_only)


@pytest.mark.parametrize(
    "scanner_class", [ActionlintScanner, CfnLintScanner, GitleaksScanner, ZizmorScanner]
)
def test_the_others_declare_the_strict_default(layout, scanner_class):
    declared = scanner_class.sandbox_requirements
    assert declared == SandboxRequirements()
    policy = _policy(layout, scanner_class.__name__, declared)
    default = _policy(layout, scanner_class.__name__, SandboxRequirements())
    assert policy.network is False
    assert _real(policy.read_only) == _real(default.read_only)
    assert _real(policy.cache) == _real(default.cache)


def test_no_option_or_environment_grant_reaches_gitleaks_or_zizmor(layout):
    """The variables these tools read are dropped until the grant gates exist."""
    env = {
        "GITLEAKS_CONFIG": "/etc/gitleaks.toml",
        "GITLEAKS_CONFIG_TOML": "title = 'x'",
        **dict.fromkeys(GITHUB_TOKEN_ENV_VARS, "ghp_example"),
    }
    for scanner_class in (GitleaksScanner, ZizmorScanner):
        kept = _policy(layout, "x", scanner_class.sandbox_requirements).filter_env(env)
        assert not set(env) & set(kept), scanner_class.__name__
