# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""What the skillcheck community scanner gets from the scanner sandbox.

It declares a network (the tool looks each skill's SHA-256 up in the Mondoo database)
and nothing else: the baseline read-only paths, the results directory as the only
writable place, and the baseline environment allowlist. The policy is built with
``build_scanner_policy``, the function every sandboxed spawn goes through, so a
declaration the policy ignores fails here.
"""

from __future__ import annotations

import sys
from types import SimpleNamespace

import pytest

from automated_security_helper.plugin_modules.ash_skillcheck_plugins.skillcheck_scanner import (
    SkillcheckScanner,
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
        "skillcheck",
        requirements,
        argv0=sys.executable,
        source_dir=layout.source,
        output_dir=layout.output,
        results_dir=layout.output / "scanners" / "skillcheck",
        scan_target=layout.source,
        cwd=layout.source,
        offline=offline,
        network_scanners=None,
    )


def _real(paths):
    return {p.resolve() for p in paths}


def test_skillcheck_declares_a_network_and_nothing_else(layout):
    declared = SkillcheckScanner.sandbox_requirements
    assert declared == SandboxRequirements(network=True)
    policy = _policy(layout, declared)
    default = _policy(layout, SandboxRequirements())
    assert policy.network is True
    assert _real(policy.read_only) == _real(default.read_only)
    assert _real(policy.cache) == _real(default.cache)


def test_offline_withholds_the_network(layout):
    assert (
        _policy(layout, SkillcheckScanner.sandbox_requirements, offline=True).network
        is False
    )


def test_no_variable_beyond_the_baseline_is_passed(layout):
    policy = _policy(layout, SkillcheckScanner.sandbox_requirements)
    passed = policy.filter_env({"SKILLCHECK_TOKEN": "x", "MONDOO_CONFIG_BASE64": "x"})
    assert passed.keys() == {"HOME"} | set(policy.extra_env)
