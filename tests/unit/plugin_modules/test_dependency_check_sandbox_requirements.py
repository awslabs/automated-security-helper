# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""What the dependency-check community scanner gets from the scanner sandbox.

It declares ``network=True`` (the NVD database download), the ``JAVA_`` variable
prefix and ``NVD_API_KEY``. The policy is built with ``build_scanner_policy``, the
function every sandboxed spawn goes through, so a declaration the policy ignores
fails here.
"""

from __future__ import annotations

import sys
from types import SimpleNamespace

import pytest

from automated_security_helper.plugin_modules.ash_dependency_check_plugins.dependency_check_scanner import (
    NVD_API_KEY_ENV,
    DependencyCheckScanner,
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
        "dependency-check",
        requirements,
        argv0=sys.executable,
        source_dir=layout.source,
        output_dir=layout.output,
        results_dir=layout.output / "scanners" / "dependency-check",
        scan_target=layout.source,
        cwd=layout.source,
        offline=offline,
        network_scanners=None,
    )


def test_declaration_asks_for_network_java_env_and_the_nvd_key():
    declared = DependencyCheckScanner.sandbox_requirements
    assert isinstance(declared, SandboxRequirements)
    assert declared.network is True
    assert declared.env_prefixes == ("JAVA_",)
    assert NVD_API_KEY_ENV in declared.env_names


def test_the_policy_grants_the_network_online(layout):
    declared = DependencyCheckScanner.sandbox_requirements
    strict = _policy(layout, SandboxRequirements())
    granted = _policy(layout, declared)
    assert granted.network is True
    assert strict.network is False


def test_the_policy_withholds_the_network_offline(layout):
    declared = DependencyCheckScanner.sandbox_requirements
    assert _policy(layout, declared, offline=True).network is False


def test_the_nvd_key_reaches_the_tool_and_other_secrets_do_not(layout):
    declared = DependencyCheckScanner.sandbox_requirements
    env = {
        NVD_API_KEY_ENV: "nvd-key-value",
        "JAVA_HOME": "/opt/java",
        "AWS_SECRET_ACCESS_KEY": "other-secret",
        "SOME_API_TOKEN": "other-token",
    }
    kept = _policy(layout, declared).filter_env(env)
    assert kept[NVD_API_KEY_ENV] == "nvd-key-value"
    assert kept["JAVA_HOME"] == "/opt/java"
    assert "AWS_SECRET_ACCESS_KEY" not in kept
    assert "SOME_API_TOKEN" not in kept
    # A scanner without the declaration does not receive the key.
    assert NVD_API_KEY_ENV not in _policy(layout, SandboxRequirements()).filter_env(env)
