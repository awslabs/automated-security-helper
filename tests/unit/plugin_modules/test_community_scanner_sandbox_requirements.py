# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""What the community scanners get from the scanner sandbox, through the real policy.

A scanner that declares no ``sandbox_requirements`` gets the strict default: no
network, the baseline read-only paths, its results directory as the only writable
place, and the baseline environment allowlist. Four of the community scanners cannot
work under that default:

* ``trivy`` and ``trivy-repo`` download the vulnerability database into their cache
  when online and read ``TRIVY_*`` settings;
* ``cfn-guard`` reads its rules bundle from ``rules_root()``, which is outside ASH's
  bin directory, the only part of ``~/.ash`` the baseline exposes;
* ``gitleaks`` leaves config resolution to gitleaks when ``GITLEAKS_CONFIG`` or
  ``GITLEAKS_CONFIG_TOML`` is set, so both have to reach it, and so does the file
  ``GITLEAKS_CONFIG`` names;
* ``zizmor`` with ``online_audits`` calls the GitHub API with a token the sandbox
  would drop as credential-shaped.

actionlint and cfn-lint need nothing beyond the default and declare nothing. Each test
builds the policy with ``build_scanner_policy``, the function every sandboxed spawn
goes through, so a declaration that the policy ignores fails here.
"""

from __future__ import annotations

import sys
from types import SimpleNamespace

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.plugin_modules.ash_actionlint_plugins.actionlint_scanner import (
    ActionlintScanner,
)
from automated_security_helper.plugin_modules.ash_cfn_plugins.cfn_guard_scanner import (
    CfnGuardScanner,
    CfnGuardScannerConfig,
)
from automated_security_helper.plugin_modules.ash_cfn_plugins.cfn_lint_scanner import (
    CfnLintScanner,
)
from automated_security_helper.plugin_modules.ash_gitleaks_plugins.gitleaks_scanner import (
    GitleaksScanner,
)
from automated_security_helper.plugin_modules.ash_trivy_plugins.trivy_repo_scanner import (
    TrivyRepoScanner,
)
from automated_security_helper.plugin_modules.ash_trivy_plugins.trivy_scanner import (
    TrivyScanner,
)
from automated_security_helper.plugin_modules.ash_zizmor_plugins.zizmor_scanner import (
    GITHUB_TOKEN_ENV_VARS,
    ZizmorScanner,
    ZizmorScannerConfig,
    ZizmorScannerConfigOptions,
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
    assert (
        _policy(
            layout, "trivy", scanner_class.sandbox_requirements, offline=True
        ).network
        is False
    )


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


def test_gitleaks_passes_its_config_variables_and_mounts_the_named_file(
    layout, monkeypatch
):
    config_file = layout.tmp / "operator" / "gitleaks.toml"
    config_file.parent.mkdir()
    config_file.write_text('title = "operator rules"\n')
    monkeypatch.setenv("GITLEAKS_CONFIG", str(config_file))

    policy = _policy(layout, "gitleaks", GitleaksScanner.sandbox_requirements)

    assert config_file.resolve() in _real(policy.read_only)
    assert policy.network is False
    env = policy.filter_env(
        {
            "GITLEAKS_CONFIG": str(config_file),
            "GITLEAKS_CONFIG_TOML": "title = 'inline'",
        }
    )
    assert env["GITLEAKS_CONFIG"] == str(config_file)
    assert env["GITLEAKS_CONFIG_TOML"] == "title = 'inline'"


def test_gitleaks_without_gitleaks_config_mounts_nothing_extra(layout, monkeypatch):
    monkeypatch.delenv("GITLEAKS_CONFIG", raising=False)
    declared = _policy(layout, "gitleaks", GitleaksScanner.sandbox_requirements)
    default = _policy(layout, "gitleaks", SandboxRequirements())
    assert _real(declared.read_only) == _real(default.read_only)


def _zizmor(layout, monkeypatch, **options) -> ZizmorScanner:
    monkeypatch.setattr(
        ZizmorScanner, "_get_uv_tool_version", lambda self, *_: "1.30.1"
    )
    return ZizmorScanner(
        context=_context(layout),
        config=ZizmorScannerConfig(
            enabled=True, options=ZizmorScannerConfigOptions(**options)
        ),
    )


def test_zizmor_offline_audits_get_no_network_and_no_token(layout, monkeypatch):
    scanner = _zizmor(layout, monkeypatch)

    policy = _policy(layout, "zizmor", scanner.sandbox_requirements)

    assert policy.network is False
    env = policy.filter_env(dict.fromkeys(GITHUB_TOKEN_ENV_VARS, "ghp_example"))
    assert not set(GITHUB_TOKEN_ENV_VARS) & set(env)


def test_zizmor_online_audits_get_a_network_and_the_token(layout, monkeypatch):
    scanner = _zizmor(layout, monkeypatch, online_audits=True)

    policy = _policy(layout, "zizmor", scanner.sandbox_requirements)

    assert policy.network is True
    env = policy.filter_env(dict.fromkeys(GITHUB_TOKEN_ENV_VARS, "ghp_example"))
    assert {name: env.get(name) for name in GITHUB_TOKEN_ENV_VARS} == dict.fromkeys(
        GITHUB_TOKEN_ENV_VARS, "ghp_example"
    )
    # --offline still wins: the sandbox grants no network whatever is declared.
    offline = _policy(layout, "zizmor", scanner.sandbox_requirements, offline=True)
    assert offline.network is False


@pytest.mark.parametrize("scanner_class", [ActionlintScanner, CfnLintScanner])
def test_actionlint_and_cfn_lint_declare_the_strict_default(layout, scanner_class):
    declared = scanner_class.sandbox_requirements
    assert declared == SandboxRequirements()
    policy = _policy(layout, scanner_class.__name__, declared)
    default = _policy(layout, scanner_class.__name__, SandboxRequirements())
    assert policy.network is False
    assert _real(policy.read_only) == _real(default.read_only)
    assert _real(policy.cache) == _real(default.cache)
