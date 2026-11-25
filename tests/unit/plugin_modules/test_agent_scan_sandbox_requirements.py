# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""What the agent-scan community scanner gets from the scanner sandbox.

Snyk Agent Scan posts the skill files to Snyk's analysis API, so the scanner declares
``network=True`` (granted online, never under ``--offline``) and passes ``SNYK_TOKEN``
through by name, as snyk-code does; nothing else: no environment prefix, no extra read
path. The policy is built with ``build_scanner_policy``, the function every sandboxed
spawn goes through, so a declaration the policy ignores fails here.
"""

from __future__ import annotations

import sys
from types import SimpleNamespace

import pytest

from automated_security_helper.plugin_modules.ash_agent_scan_plugins.agent_scan_scanner import (
    AgentScanScanner,
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
        "agent-scan",
        requirements,
        argv0=sys.executable,
        source_dir=layout.source,
        output_dir=layout.output,
        results_dir=layout.output / "scanners" / "agent-scan",
        scan_target=layout.source,
        cwd=layout.source,
        offline=offline,
        network_scanners=None,
    )


def test_agent_scan_declares_network_and_the_token_name_and_nothing_else():
    declared = AgentScanScanner.sandbox_requirements
    assert declared == SandboxRequirements(network=True, env_names=("SNYK_TOKEN",))
    assert declared.network is True


def test_the_network_is_granted_online(layout):
    policy = _policy(layout, AgentScanScanner.sandbox_requirements)
    assert policy.network is True


def test_the_network_is_refused_offline(layout):
    policy = _policy(layout, AgentScanScanner.sandbox_requirements, offline=True)
    assert policy.network is False


def test_a_strict_default_declaration_would_get_no_network_and_no_token(layout):
    """Control: the grants above come from the declaration, not the policy."""
    policy = _policy(layout, SandboxRequirements())
    assert policy.network is False
    assert "SNYK_TOKEN" not in policy.filter_env({"SNYK_TOKEN": "x"})


def test_the_token_is_passed_by_name_and_no_other_environment_is(layout):
    policy = _policy(layout, AgentScanScanner.sandbox_requirements)
    passed = policy.filter_env(
        {
            "SNYK_TOKEN": "x",
            "SNYK_API": "https://example.invalid/",
            "AGENT_SCAN_ENVIRONMENT": "ci",
            "OTHER_TOKEN": "y",
        }
    )
    assert passed.keys() == {"HOME", "SNYK_TOKEN"} | set(policy.extra_env)
