# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""What the pip-audit alpha scanner gets from the scanner sandbox.

pip-audit asks a vulnerability service about every dependency, so the scanner
declares ``network=True`` (granted online, never under ``--offline``) and nothing
else: no environment prefix, no extra read path. The policy is built with
``build_scanner_policy``, the function every sandboxed spawn goes through, so a
declaration the policy ignores fails here.
"""

from __future__ import annotations

import sys
from types import SimpleNamespace

import pytest

from automated_security_helper.plugin_modules.ash_pip_audit_plugins.pip_audit_scanner import (
    PipAuditScanner,
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
    return SimpleNamespace(source=source, output=output)


def _policy(layout, requirements, *, offline=False):
    return build_scanner_policy(
        "pip-audit",
        requirements,
        argv0=sys.executable,
        source_dir=layout.source,
        output_dir=layout.output,
        results_dir=layout.output / "scanners" / "pip-audit",
        scan_target=layout.source,
        cwd=layout.source,
        offline=offline,
        network_scanners=None,
    )


def test_pip_audit_declares_network_and_nothing_else():
    declared = PipAuditScanner.sandbox_requirements
    assert declared == SandboxRequirements(network=True)
    assert declared.network is True


def test_the_network_is_granted_online(layout):
    policy = _policy(layout, PipAuditScanner.sandbox_requirements)
    assert policy.network is True


def test_the_network_is_refused_offline(layout):
    policy = _policy(layout, PipAuditScanner.sandbox_requirements, offline=True)
    assert policy.network is False


def test_a_strict_default_declaration_would_get_no_network(layout):
    """Control: the grant above comes from the declaration, not the policy."""
    assert _policy(layout, SandboxRequirements()).network is False


def test_only_the_baseline_environment_is_passed(layout):
    policy = _policy(layout, PipAuditScanner.sandbox_requirements)
    passed = policy.filter_env(
        {"PIP_INDEX_URL": "https://example.invalid/simple", "PIP_AUDIT_X": "1"}
    )
    assert passed.keys() == {"HOME"} | set(policy.extra_env)
