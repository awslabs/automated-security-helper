# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""What the cdxgen scanner gets from the scanner sandbox.

cdxgen declares the strict default: no network (the scan always passes
``--no-install-deps``), the baseline read-only paths, the results directory as the
only writable place, and the baseline environment allowlist. The policy is built
with ``build_scanner_policy``, the function every sandboxed spawn goes through, so
a declaration the policy ignores fails here.
"""

from __future__ import annotations

import sys
from types import SimpleNamespace

import pytest

from automated_security_helper.plugin_modules.ash_cdxgen_plugins.cdxgen_scanner import (
    CdxgenScanner,
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
        "cdxgen",
        requirements,
        argv0=sys.executable,
        source_dir=layout.source,
        output_dir=layout.output,
        results_dir=layout.output / "scanners" / "cdxgen",
        scan_target=layout.source,
        cwd=layout.source,
        offline=offline,
        network_scanners=None,
    )


def _real(paths):
    return {p.resolve() for p in paths}


def test_cdxgen_declares_the_strict_default():
    assert CdxgenScanner.sandbox_requirements == SandboxRequirements()
    assert CdxgenScanner.sandbox_requirements.network is False
    assert CdxgenScanner.sandbox_requirements.env_prefixes == ()


def test_the_policy_built_from_the_declaration_has_no_network(layout):
    policy = _policy(layout, CdxgenScanner.sandbox_requirements)
    default = _policy(layout, SandboxRequirements())
    assert policy.network is False
    assert _real(policy.read_only) == _real(default.read_only)
    assert _real(policy.cache) == _real(default.cache)


def test_the_policy_passes_only_the_baseline_environment(layout):
    policy = _policy(layout, CdxgenScanner.sandbox_requirements)
    filtered = policy.filter_env(
        {"CDXGEN_TOKEN": "x", "FETCH_LICENSE": "true", "NODE_OPTIONS": "--inspect"}
    )
    assert filtered.keys() == {"HOME"} | set(policy.extra_env)


def test_a_negative_control_a_network_grant_would_show(layout):
    granted = _policy(layout, SandboxRequirements(network=True))
    assert granted.network is True
