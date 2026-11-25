# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""What the skill-scanner community scanner gets from the scanner sandbox.

It declares the strict default: no network, the baseline read-only paths, the
results directory as the only writable place, and the baseline environment
allowlist. The tool's ``SKILL_SCANNER_*`` variables (model keys and names for
analyzers ASH never turns on) are not passed into the sandbox.

The policy is built with ``build_scanner_policy``, the function every sandboxed
spawn goes through, so a declaration the policy ignores fails here.
"""

from __future__ import annotations

import sys
from types import SimpleNamespace

import pytest

from automated_security_helper.plugin_modules.ash_skill_scanner_plugins.skill_scanner_scanner import (
    SkillScannerScanner,
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
        "skill_scanner",
        requirements,
        argv0=sys.executable,
        source_dir=layout.source,
        output_dir=layout.output,
        results_dir=layout.output / "scanners" / "skill_scanner",
        scan_target=layout.source,
        cwd=layout.source,
        offline=False,
        network_scanners=None,
    )


def _real(paths):
    return {p.resolve() for p in paths}


def test_skill_scanner_declares_the_strict_default(layout):
    declared = SkillScannerScanner.sandbox_requirements
    assert declared == SandboxRequirements()
    policy = _policy(layout, declared)
    default = _policy(layout, SandboxRequirements())
    assert policy.network is False
    assert _real(policy.read_only) == _real(default.read_only)
    assert _real(policy.cache) == _real(default.cache)


def test_the_model_and_service_variables_are_not_passed_into_the_sandbox(layout):
    policy = _policy(layout, SkillScannerScanner.sandbox_requirements)
    passed = policy.filter_env(
        {
            "SKILL_SCANNER_LLM_API_KEY": "placeholder",
            "SKILL_SCANNER_LLM_MODEL": "placeholder",
            "VIRUSTOTAL_API_KEY": "placeholder",
            "AI_DEFENSE_API_KEY": "placeholder",
        }
    )
    assert passed.keys() == {"HOME"} | set(policy.extra_env)
