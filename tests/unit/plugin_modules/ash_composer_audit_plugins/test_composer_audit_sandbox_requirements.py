# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""What the composer-audit alpha scanner gets from the scanner sandbox.

It declares a network need and nothing else: Composer fetches advisories from
Packagist when the audit runs. The policy is built with ``build_scanner_policy``,
the function every sandboxed spawn goes through, so a declaration the policy
ignores fails here.
"""

from __future__ import annotations

import sys
from types import SimpleNamespace

import pytest

from automated_security_helper.plugin_modules.ash_composer_audit_plugins.composer_audit_scanner import (
    ComposerAuditScanner,
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
        "composer-audit",
        requirements,
        argv0=sys.executable,
        source_dir=layout.source,
        output_dir=layout.output,
        results_dir=layout.output / "scanners" / "composer-audit",
        scan_target=layout.source,
        cwd=layout.source,
        offline=offline,
        network_scanners=None,
    )


def test_composer_audit_declares_network_only():
    declared = ComposerAuditScanner.sandbox_requirements
    assert declared == SandboxRequirements(network=True)
    assert declared.network_requires_grant is False


def test_the_policy_grants_the_network_online_and_not_offline(layout):
    declared = ComposerAuditScanner.sandbox_requirements
    assert _policy(layout, declared).network is True
    assert _policy(layout, declared, offline=True).network is False


def test_the_network_need_is_the_only_difference_from_the_default(layout):
    declared = _policy(layout, ComposerAuditScanner.sandbox_requirements)
    default = _policy(layout, SandboxRequirements())
    assert default.network is False
    assert {p.resolve() for p in declared.read_only} == {
        p.resolve() for p in default.read_only
    }
    assert {p.resolve() for p in declared.cache} == {p.resolve() for p in default.cache}
    # Composer policy variables are not passed through to the audit.
    assert "COMPOSER_POLICY" not in declared.filter_env({"COMPOSER_POLICY": "0"})
