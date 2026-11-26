# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""What the dotnet-vulnerable alpha scanner gets from the scanner sandbox.

It declares a network (the advisory lookup reads the NuGet sources) and the
``DOTNET_`` and ``NUGET_`` environment prefixes, and nothing else. The policy is
built with ``build_scanner_policy``, the function every sandboxed spawn goes
through, so a declaration the policy ignores fails here.
"""

from __future__ import annotations

import sys
from types import SimpleNamespace

import pytest

from automated_security_helper.plugin_modules.ash_dotnet_vulnerable_plugins.dotnet_vulnerable_scanner import (
    DotnetVulnerableScanner,
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


def _policy(layout, requirements, *, offline=False, network_scanners=None):
    return build_scanner_policy(
        "dotnet-vulnerable",
        requirements,
        argv0=sys.executable,
        source_dir=layout.source,
        output_dir=layout.output,
        results_dir=layout.output / "scanners" / "dotnet-vulnerable",
        scan_target=layout.source,
        cwd=layout.source,
        offline=offline,
        network_scanners=network_scanners,
    )


def test_it_declares_a_network_and_the_sdk_prefixes_only():
    declared = DotnetVulnerableScanner.sandbox_requirements
    assert declared == SandboxRequirements(
        network=True, env_prefixes=("DOTNET_", "NUGET_")
    )
    assert declared.network_requires_grant is False


def test_the_declared_network_reaches_the_policy_online_only(layout):
    declared = DotnetVulnerableScanner.sandbox_requirements
    assert _policy(layout, declared).network is True
    assert _policy(layout, declared, offline=True).network is False


def test_an_operator_network_scanner_list_that_omits_it_takes_the_network_away(layout):
    declared = DotnetVulnerableScanner.sandbox_requirements
    assert _policy(layout, declared, network_scanners=[]).network is False
    assert (
        _policy(layout, declared, network_scanners=["dotnet-vulnerable"]).network
        is True
    )


def test_only_the_sdk_variables_are_passed_in_and_credentials_are_not(layout):
    policy = _policy(layout, DotnetVulnerableScanner.sandbox_requirements)
    passed = policy.filter_env(
        {
            "DOTNET_NOLOGO": "1",
            "NUGET_PACKAGES": "/cache/nuget",
            "NUGET_TOKEN": "secret-value",
            "VSS_NUGET_EXTERNAL_FEED_ENDPOINTS": "{}",
            "AWS_SECRET_ACCESS_KEY": "secret-value",
        }
    )
    assert passed["DOTNET_NOLOGO"] == "1"
    assert passed["NUGET_PACKAGES"] == "/cache/nuget"
    assert "NUGET_TOKEN" not in passed
    assert "VSS_NUGET_EXTERNAL_FEED_ENDPOINTS" not in passed
    assert "AWS_SECRET_ACCESS_KEY" not in passed
