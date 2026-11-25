# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""What the njsscan community scanner gets from the scanner sandbox.

It declares the strict default: no network, the baseline read-only paths, the
results directory as the only writable place, and the baseline environment
allowlist. njsscan reads its rules from inside its own package (a uv tool
directory the baseline exposes), and ASH writes its empty config file outside the
scanned tree, so nothing option- or environment-derived is granted and the plugin
has no option that would need a grant.

The policy is built with ``build_scanner_policy``, the function every sandboxed
spawn goes through, so a declaration the policy ignores fails here.
"""

from __future__ import annotations

import sys
from types import SimpleNamespace

import pytest

from automated_security_helper.plugin_modules.ash_njsscan_plugins.njsscan_scanner import (
    NjsscanScanner,
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
        "njsscan",
        requirements,
        argv0=sys.executable,
        source_dir=layout.source,
        output_dir=layout.output,
        results_dir=layout.output / "scanners" / "njsscan",
        scan_target=layout.source,
        cwd=layout.source,
        offline=False,
        network_scanners=None,
    )


def _real(paths):
    return {p.resolve() for p in paths}


def test_njsscan_declares_the_strict_default(layout):
    declared = NjsscanScanner.sandbox_requirements
    assert declared == SandboxRequirements()
    policy = _policy(layout, declared)
    default = _policy(layout, SandboxRequirements())
    assert policy.network is False
    assert _real(policy.read_only) == _real(default.read_only)
    assert _real(policy.cache) == _real(default.cache)


def test_the_results_directory_is_the_only_writable_place(layout):
    policy = _policy(layout, NjsscanScanner.sandbox_requirements)
    writable = _real(policy.writable)
    assert (layout.output / "scanners" / "njsscan").resolve() in writable
    assert layout.source.resolve() not in writable


def test_no_environment_variable_is_passed_beyond_the_baseline(layout):
    policy = _policy(layout, NjsscanScanner.sandbox_requirements)
    passed = policy.filter_env(
        {
            "NJSSCAN_CONFIG": "/etc/njsscan.yml",
            "SEMGREP_APP_TOKEN": "not-a-real-token",
            "SEMGREP_SEND_METRICS": "on",
        }
    )
    assert passed.keys() == {"HOME"} | set(policy.extra_env)
    assert NjsscanScanner.sandbox_requirements.env_names == ()
