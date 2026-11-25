# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""What the Cppcheck community scanner gets from the scanner sandbox.

It declares the strict default: no network, the baseline read-only paths, the
results directory as the only writable place, and the baseline environment
allowlist. Cppcheck reads its checks and ``std.cfg`` from its own installation and
makes no network call.

The policy is built with ``build_scanner_policy``, the function every sandboxed
spawn goes through, so a declaration the policy ignores fails here.
"""

from __future__ import annotations

import sys
from types import SimpleNamespace

import pytest

from automated_security_helper.plugin_modules.ash_cppcheck_plugins.cppcheck_scanner import (
    CppcheckScanner,
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
        "cppcheck",
        requirements,
        argv0=sys.executable,
        source_dir=layout.source,
        output_dir=layout.output,
        results_dir=layout.output / "scanners" / "cppcheck",
        scan_target=layout.source,
        cwd=layout.source,
        offline=False,
        network_scanners=None,
    )


def _real(paths):
    return {p.resolve() for p in paths}


def test_cppcheck_declares_the_strict_default(layout):
    declared = CppcheckScanner.sandbox_requirements
    assert declared == SandboxRequirements()
    policy = _policy(layout, declared)
    default = _policy(layout, SandboxRequirements())
    assert policy.network is False
    assert _real(policy.read_only) == _real(default.read_only)
    assert _real(policy.cache) == _real(default.cache)
    assert policy.extra_env == default.extra_env


def test_the_results_directory_is_the_only_writable_place(layout):
    policy = _policy(layout, CppcheckScanner.sandbox_requirements)
    results = (layout.output / "scanners" / "cppcheck").resolve()
    assert results in _real(policy.writable)
    assert layout.source.resolve() not in _real(policy.writable)


def test_no_tool_variable_is_passed_into_the_sandbox(layout):
    policy = _policy(layout, CppcheckScanner.sandbox_requirements)
    passed = policy.filter_env(
        {"CPPCHECK_OPTS": "--inline-suppr", "CPPCHECK_ADDON": "evil", "HOME": "x"}
    )
    assert passed.keys() == {"HOME"} | set(policy.extra_env)
