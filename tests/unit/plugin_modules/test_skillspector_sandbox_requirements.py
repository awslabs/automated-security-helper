# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""What the SkillSpector community scanner gets from the scanner sandbox.

SkillSpector runs with ``--no-llm``, reads only the skill directory and the rules
in its package, and needs no network (measured at 2.13.7 inside an empty network
namespace), so the scanner declares the strict default: no network, the baseline
environment only. That also keeps ``SKILLSPECTOR_PROVIDER`` and every provider
credential out of the tool. The policy is built with ``build_scanner_policy``,
the function every sandboxed spawn goes through, so a declaration the policy
ignores fails here.
"""

from __future__ import annotations

import sys
from types import SimpleNamespace

import pytest

from automated_security_helper.plugin_modules.ash_skillspector_plugins.skillspector_scanner import (
    SkillSpectorScanner,
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
        "skillspector",
        requirements,
        argv0=sys.executable,
        source_dir=layout.source,
        output_dir=layout.output,
        results_dir=layout.output / "scanners" / "skillspector",
        scan_target=layout.source,
        cwd=layout.source,
        offline=offline,
        network_scanners=None,
    )


def test_skillspector_declares_the_strict_default():
    assert SkillSpectorScanner.sandbox_requirements == SandboxRequirements()
    assert SkillSpectorScanner.sandbox_requirements.network is False


def test_no_network_is_granted_online_or_offline(layout):
    declared = SkillSpectorScanner.sandbox_requirements
    assert _policy(layout, declared).network is False
    assert _policy(layout, declared, offline=True).network is False


def test_a_network_declaration_would_be_granted_online(layout):
    """Control: the refusal above comes from the declaration, not the policy."""
    assert _policy(layout, SandboxRequirements(network=True)).network is True


def test_only_the_baseline_environment_is_passed(layout):
    policy = _policy(layout, SkillSpectorScanner.sandbox_requirements)
    passed = policy.filter_env(
        {
            "SKILLSPECTOR_PROVIDER": "openai",
            "SKILLSPECTOR_MODEL": "x",
            "OPENAI_API_KEY": "not-a-key",
            "ANTHROPIC_API_KEY": "not-a-key",
            "LANGCHAIN_TRACING_V2": "true",
        }
    )
    assert passed.keys() == {"HOME"} | set(policy.extra_env)
