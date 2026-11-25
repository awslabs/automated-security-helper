# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""What the ScanCode community scanner gets from the scanner sandbox.

It declares the strict default: no network (the license index ships in the
``scancode-toolkit`` package), the baseline read-only paths, the results directory as
the only writable place, and the baseline environment allowlist.

The policy is built with ``build_scanner_policy``, the function every sandboxed spawn
goes through, so a declaration the policy ignores fails here.
"""

from __future__ import annotations

import sys
from types import SimpleNamespace

import pytest

from automated_security_helper.core.enums import OfflineStrategy
from automated_security_helper.plugin_modules.ash_scancode_plugins.scancode_scanner import (
    ScanCodeScanner,
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
        "scancode",
        requirements,
        argv0=sys.executable,
        source_dir=layout.source,
        output_dir=layout.output,
        results_dir=layout.output / "scanners" / "scancode",
        scan_target=layout.source,
        cwd=layout.source,
        offline=False,
        network_scanners=None,
    )


def _real(paths):
    return {p.resolve() for p in paths}


def test_scancode_declares_the_strict_default(layout):
    declared = ScanCodeScanner.sandbox_requirements
    assert declared == SandboxRequirements()
    policy = _policy(layout, declared)
    default = _policy(layout, SandboxRequirements())
    assert policy.network is False
    assert _real(policy.read_only) == _real(default.read_only)
    assert _real(policy.cache) == _real(default.cache)


def test_the_declaration_matches_the_offline_strategy():
    # A scan with no network is declared as bundled, not as a network fetch.
    assert ScanCodeScanner.offline_strategy is OfflineStrategy.BUNDLED
    assert ScanCodeScanner.sandbox_requirements.network is False


def test_a_requirements_change_would_change_the_policy(layout):
    # Planted control: a network grant is visible in the policy, so the equality
    # checks above can fail.
    granted = _policy(layout, SandboxRequirements(network=True))
    assert granted.network is True
