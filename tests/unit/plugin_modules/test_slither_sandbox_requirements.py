# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""What the Slither alpha scanner gets from the scanner sandbox.

It declares the strict default: no network, the baseline read-only paths, the
results directory as the only writable place, and the baseline environment
allowlist. Slither is installed by the operator, so the tool's own directories are
whatever the baseline exposes for a tool on PATH; a project build that needs solc
downloads or npm packages has no network under the sandbox and fails.

The policy is built with ``build_scanner_policy``, the function every sandboxed
spawn goes through, so a declaration the policy ignores fails here.
"""

from __future__ import annotations

import sys
from types import SimpleNamespace

import pytest

from automated_security_helper.plugin_modules.ash_slither_plugins.slither_scanner import (
    SlitherScanner,
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
        "slither",
        requirements,
        argv0=sys.executable,
        source_dir=layout.source,
        output_dir=layout.output,
        results_dir=layout.output / "scanners" / "slither",
        scan_target=layout.source,
        cwd=layout.source,
        offline=False,
        network_scanners=None,
    )


def _real(paths):
    return {p.resolve() for p in paths}


def test_slither_declares_the_strict_default(layout):
    declared = SlitherScanner.sandbox_requirements
    assert declared == SandboxRequirements()
    policy = _policy(layout, declared)
    default = _policy(layout, SandboxRequirements())
    assert policy.network is False
    assert _real(policy.read_only) == _real(default.read_only)
    assert _real(policy.cache) == _real(default.cache)


def test_the_results_directory_is_the_only_writable_place_it_adds(layout):
    policy = _policy(layout, SlitherScanner.sandbox_requirements)
    default = _policy(layout, SandboxRequirements())
    assert _real(policy.writable) == _real(default.writable)
    assert (layout.output / "scanners" / "slither").resolve() in _real(policy.writable)


def test_no_tool_variable_is_passed_into_the_sandbox(layout):
    policy = _policy(layout, SlitherScanner.sandbox_requirements)
    passed = policy.filter_env(
        {
            "SLITHER_CONFIG": "/etc/slither.json",
            "SOLC_VERSION": "0.4.1",
            "SOLC_SELECT_DIR": "/elsewhere",
        }
    )
    assert passed.keys() == {"HOME"} | set(policy.extra_env)
