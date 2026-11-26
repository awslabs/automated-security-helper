# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""What the YARA-X alpha scanner gets from the scanner sandbox.

It declares the strict default: no network, the baseline read-only paths, the results
directory as the only writable place, and the baseline environment allowlist. The
operator's rules path outside the scanned tree is not mounted into a sandbox yet (grants
derived from options wait for the sandbox's grant gates), so a sandboxed run reads rules
only from places the baseline already exposes.

The policy is built with ``build_scanner_policy``, the function every sandboxed spawn
goes through, so a declaration the policy ignores fails here.
"""

from __future__ import annotations

import sys
from types import SimpleNamespace

import pytest

from automated_security_helper.plugin_modules.ash_yara_x_plugins.yara_x_scanner import (
    YaraXScanner,
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


def _policy(layout, requirements):
    return build_scanner_policy(
        "yara-x",
        requirements,
        argv0=sys.executable,
        source_dir=layout.source,
        output_dir=layout.output,
        results_dir=layout.output / "scanners" / "yara-x",
        scan_target=layout.source,
        cwd=layout.source,
        offline=False,
        network_scanners=None,
    )


def _real(paths):
    return {p.resolve() for p in paths}


def test_yara_x_declares_the_strict_default(layout):
    declared = YaraXScanner.sandbox_requirements
    assert declared == SandboxRequirements()
    policy = _policy(layout, declared)
    default = _policy(layout, SandboxRequirements())
    assert policy.network is False
    assert _real(policy.read_only) == _real(default.read_only)
    assert _real(policy.cache) == _real(default.cache)


def test_the_results_directory_is_the_only_writable_place(layout):
    policy = _policy(layout, YaraXScanner.sandbox_requirements)
    default = _policy(layout, SandboxRequirements())
    assert _real(policy.writable) == _real(default.writable)
    assert (layout.output / "scanners" / "yara-x").resolve() in _real(policy.writable)


def test_only_the_baseline_environment_reaches_the_sandbox(layout):
    policy = _policy(layout, YaraXScanner.sandbox_requirements)
    passed = policy.filter_env(
        {
            "YARA_X_RULES": "/etc/rules",
            "YARA_RULES": "/etc/rules",
            "AWS_SECRET_ACCESS_KEY": "not-a-real-secret",
        }
    )
    assert passed.keys() == {"HOME"} | set(policy.extra_env)


def test_the_rules_path_is_not_mounted_so_the_scan_is_not_given_a_grant(layout):
    """A rules directory outside the tree is not in the policy's read-only paths.

    This pins the limit the module header names: grants derived from options wait for
    the sandbox's grant gates. When they land this test changes with the declaration.
    """
    rules = layout.tmp / "operator-rules"
    rules.mkdir()
    policy = _policy(layout, YaraXScanner.sandbox_requirements)
    assert rules.resolve() not in _real(policy.read_only)
