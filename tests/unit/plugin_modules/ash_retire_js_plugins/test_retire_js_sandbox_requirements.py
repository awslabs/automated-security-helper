# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""What the retire.js alpha scanner gets from the scanner sandbox.

The scanner declares one grant over the strict default: the network, for the
vulnerability repository retire.js fetches on every run. Nothing else is granted:
the read-only paths, the cache paths and the environment allowlist are the default's,
and the results directory is the only writable place. The policy is built with
``build_scanner_policy``, the function every sandboxed spawn goes through, so a
declaration the policy ignores fails here.
"""

from __future__ import annotations

import sys
from types import SimpleNamespace

import pytest

from automated_security_helper.plugin_modules.ash_retire_js_plugins.retire_js_scanner import (
    RetireJsScanner,
)
from automated_security_helper.utils.sandbox.policy import (
    SandboxRequirements,
    build_scanner_policy,
)

pytestmark = pytest.mark.unit


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


def _policy(layout, requirements, *, offline=False):
    return build_scanner_policy(
        "retire-js",
        requirements,
        argv0=sys.executable,
        source_dir=layout.source,
        output_dir=layout.output,
        results_dir=layout.output / "scanners" / "retire-js",
        scan_target=layout.source,
        cwd=layout.source,
        offline=offline,
        network_scanners=None,
    )


def _real(paths):
    return {p.resolve() for p in paths}


def test_the_declaration_is_the_default_plus_the_network():
    assert RetireJsScanner.sandbox_requirements == SandboxRequirements(network=True)
    assert RetireJsScanner.sandbox_requirements != SandboxRequirements()


def test_the_policy_grants_the_network_online_and_nothing_else(layout):
    declared = RetireJsScanner.sandbox_requirements
    policy = _policy(layout, declared)
    default = _policy(layout, SandboxRequirements())
    assert policy.network is True
    assert default.network is False
    assert _real(policy.read_only) == _real(default.read_only)
    assert _real(policy.cache) == _real(default.cache)
    assert _real(policy.writable) == _real(default.writable)
    assert policy.results_dir == layout.output / "scanners" / "retire-js"


def test_a_widened_declaration_is_seen_by_the_comparison(layout):
    """The control for the test above: a requirement that grants one more place to
    read yields a different policy, so equal policies mean equal grants."""
    extra = layout.tmp / "extra"
    extra.mkdir()
    widened = _policy(
        layout,
        SandboxRequirements(network=True, read_paths=(str(extra),)),
    )
    declared = _policy(layout, RetireJsScanner.sandbox_requirements)
    assert extra.resolve() in _real(widened.read_only)
    assert _real(widened.read_only) != _real(declared.read_only)


def test_the_network_is_never_granted_offline(layout):
    """The scanner is skipped under --offline; the policy agrees if it is built anyway."""
    policy = _policy(layout, RetireJsScanner.sandbox_requirements, offline=True)
    assert policy.network is False


def test_no_tree_or_host_variable_reaches_the_tool(layout):
    policy = _policy(layout, RetireJsScanner.sandbox_requirements)
    passed = policy.filter_env(
        {
            "RETIRE_JSREPO": "https://attacker.invalid/repo.json",
            "NODE_OPTIONS": "--require=/tmp/x.js",
            "NPM_CONFIG_REGISTRY": "https://attacker.invalid/",
        }
    )
    assert passed.keys() == {"HOME"} | set(policy.extra_env)
