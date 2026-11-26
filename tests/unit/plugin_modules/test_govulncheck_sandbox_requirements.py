# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""What the govulncheck alpha scanner gets from the scanner sandbox.

govulncheck reads the Go vulnerability database over the network and Go may fetch
modules, so it declares ``network=True``; the Go build and module caches are
read-only cache paths and the ``GO`` environment prefix is passed through. The
policy is built with ``build_scanner_policy``, the function every sandboxed spawn
goes through, so a declaration the policy ignores fails here.
"""

from __future__ import annotations

import sys
from types import SimpleNamespace

import pytest

from automated_security_helper.plugin_modules.ash_govulncheck_plugins.govulncheck_scanner import (
    GovulncheckScanner,
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


def _policy(layout, requirements, *, offline=False):
    return build_scanner_policy(
        "govulncheck",
        requirements,
        argv0=sys.executable,
        source_dir=layout.source,
        output_dir=layout.output,
        results_dir=layout.output / "scanners" / "govulncheck",
        scan_target=layout.source,
        cwd=layout.source,
        offline=offline,
        network_scanners=None,
    )


def test_govulncheck_declares_network_and_the_go_caches():
    declared = GovulncheckScanner.sandbox_requirements
    assert declared != SandboxRequirements()
    assert declared.network is True
    assert declared.env_prefixes == ("GO",)
    assert "~/go/pkg/mod" in declared.cache_paths
    assert "~/.cache/go-build" in declared.cache_paths


def test_the_policy_grants_the_network_online_and_never_offline(layout):
    declared = GovulncheckScanner.sandbox_requirements
    assert _policy(layout, declared).network is True
    assert _policy(layout, declared, offline=True).network is False


def test_go_variables_pass_and_unrelated_ones_do_not(layout):
    policy = _policy(layout, GovulncheckScanner.sandbox_requirements)
    passed = policy.filter_env(
        {"GOFLAGS": "-mod=mod", "GOPROXY": "https://proxy.golang.org", "SECRET": "x"}
    )
    assert passed.get("GOFLAGS") == "-mod=mod"
    assert passed.get("GOPROXY") == "https://proxy.golang.org"
    assert "SECRET" not in passed
