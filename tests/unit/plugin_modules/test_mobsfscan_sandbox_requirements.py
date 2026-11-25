# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""What the mobsfscan community scanner gets from the scanner sandbox.

It declares the strict default: no network, the baseline read-only paths, the
results directory as the only writable place, and the baseline environment
allowlist. The rules ship inside the mobsfscan package and a scan makes no network
call, and mobsfscan reads no environment variable that changes what it scans.

The policy is built with ``build_scanner_policy``, the function every sandboxed
spawn goes through, so a declaration the policy ignores fails here.
"""

from __future__ import annotations

import sys
from types import SimpleNamespace

import pytest

from automated_security_helper.plugin_modules.ash_mobsfscan_plugins.mobsfscan_scanner import (
    MobsfscanScanner,
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
        "mobsfscan",
        requirements,
        argv0=sys.executable,
        source_dir=layout.source,
        output_dir=layout.output,
        results_dir=layout.output / "scanners" / "mobsfscan",
        scan_target=layout.source,
        cwd=layout.source,
        offline=False,
        network_scanners=None,
    )


def _real(paths):
    return {p.resolve() for p in paths}


def test_mobsfscan_declares_the_strict_default(layout):
    declared = MobsfscanScanner.sandbox_requirements
    assert declared == SandboxRequirements()
    policy = _policy(layout, declared)
    default = _policy(layout, SandboxRequirements())
    assert policy.network is False
    assert _real(policy.read_only) == _real(default.read_only)
    assert _real(policy.cache) == _real(default.cache)


def test_the_environment_is_the_baseline_allowlist(layout):
    policy = _policy(layout, MobsfscanScanner.sandbox_requirements)
    assert policy.filter_env(
        {"MOBSFSCAN_CONFIG": "x", "SEMGREP_APP_TOKEN": "y"}
    ).keys() == {"HOME"} | set(policy.extra_env)


def test_the_results_directory_is_the_only_writable_place(layout):
    policy = _policy(layout, MobsfscanScanner.sandbox_requirements)
    default = _policy(layout, SandboxRequirements())
    assert _real(policy.writable) == _real(default.writable)
    assert layout.source.resolve() not in _real(policy.writable)
