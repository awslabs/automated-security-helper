# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""What the Malcontent community scanner gets from the scanner sandbox.

It declares the strict default: no network, the baseline read-only paths, the results
directory as the only writable place, and the baseline environment allowlist. Nothing
here needs more: the rules are embedded in the binary and ``analyze`` of a path makes no
network call.

The policy is built with ``build_scanner_policy``, the function every sandboxed spawn
goes through, so a declaration the policy ignores fails here.
"""

from __future__ import annotations

import sys
from types import SimpleNamespace

import pytest

from automated_security_helper.plugin_modules.ash_malcontent_plugins.malcontent_scanner import (
    MalcontentScanner,
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
        "malcontent",
        requirements,
        argv0=sys.executable,
        source_dir=layout.source,
        output_dir=layout.output,
        results_dir=layout.output / "scanners" / "malcontent",
        scan_target=layout.source,
        cwd=layout.source,
        offline=False,
        network_scanners=None,
    )


def _real(paths):
    return {p.resolve() for p in paths}


def test_malcontent_declares_the_strict_default(layout):
    declared = MalcontentScanner.sandbox_requirements
    assert declared == SandboxRequirements()
    policy = _policy(layout, declared)
    default = _policy(layout, SandboxRequirements())
    assert policy.network is False
    assert _real(policy.read_only) == _real(default.read_only)
    assert _real(policy.cache) == _real(default.cache)


def test_no_variable_beyond_the_baseline_reaches_malcontent(layout):
    policy = _policy(layout, MalcontentScanner.sandbox_requirements)
    passed = policy.filter_env(
        {"MALCONTENT_TOKEN": "x", "OCI_AUTH": "y", "AWS_ACCESS_KEY_ID": "z"}
    )
    assert passed.keys() == {"HOME"} | set(policy.extra_env)
