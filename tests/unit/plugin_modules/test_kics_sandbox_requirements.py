# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""What the KICS community scanner gets from the scanner sandbox.

It declares the strict default: no network, the baseline read-only paths, the
results directory as the only writable place, and the baseline environment
allowlist. KICS reads ``KICS_*`` environment variables as options (queries path,
config, ignore handling); ASH fixes those on the command line, so none is passed
into a sandboxed run, and the scanned tree cannot choose them through the
environment either.

The policy is built with ``build_scanner_policy``, the function every sandboxed
spawn goes through, so a declaration the policy ignores fails here.
"""

from __future__ import annotations

import sys
from types import SimpleNamespace

import pytest

from automated_security_helper.plugin_modules.ash_kics_plugins.kics_scanner import (
    KicsScanner,
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
        "kics",
        requirements,
        argv0=sys.executable,
        source_dir=layout.source,
        output_dir=layout.output,
        results_dir=layout.output / "scanners" / "kics",
        scan_target=layout.source,
        cwd=layout.source,
        offline=False,
        network_scanners=None,
    )


def _real(paths):
    return {p.resolve() for p in paths}


def test_kics_declares_the_strict_default(layout):
    declared = KicsScanner.sandbox_requirements
    assert declared == SandboxRequirements()
    policy = _policy(layout, declared)
    default = _policy(layout, SandboxRequirements())
    assert policy.network is False
    assert _real(policy.read_only) == _real(default.read_only)
    assert _real(policy.cache) == _real(default.cache)


def test_a_kics_run_is_granted_no_network(layout):
    """KICS' crash reporter can reach sentry.io; the sandbox grants no network."""
    assert _policy(layout, KicsScanner.sandbox_requirements).network is False


def test_the_kics_option_variables_are_not_passed_into_the_sandbox(layout):
    policy = _policy(layout, KicsScanner.sandbox_requirements)
    passed = policy.filter_env(
        {
            "KICS_QUERIES_PATH": "/tmp/attacker-queries",
            "KICS_CONFIG": "/tmp/attacker.config",
            "KICS_LIBRARIES_PATH": "/tmp/attacker-libraries",
            "KICS_EXCLUDE_PATHS": "/",
        }
    )
    assert passed.keys() == {"HOME"} | set(policy.extra_env)
