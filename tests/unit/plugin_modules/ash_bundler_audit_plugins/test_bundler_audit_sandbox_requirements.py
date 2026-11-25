# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""What the bundler-audit community scanner gets from the scanner sandbox.

It declares the strict default plus the three things the tool needs: the network
(the ruby-advisory-db git clone or pull), the advisory database directory as a cache
path, and the user gem directories as read paths. The policy is built with
``build_scanner_policy``, the function every sandboxed spawn goes through, so a
declaration the policy ignores fails here.
"""

from __future__ import annotations

import sys
from types import SimpleNamespace

import pytest

from automated_security_helper.plugin_modules.ash_bundler_audit_plugins.bundler_audit_scanner import (
    ADVISORY_DB_PATH,
    BundlerAuditScanner,
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
    return SimpleNamespace(home=home, source=source, output=output)


def _policy(layout, requirements, *, offline=False):
    return build_scanner_policy(
        "bundler_audit",
        requirements,
        argv0=sys.executable,
        source_dir=layout.source,
        output_dir=layout.output,
        results_dir=layout.output / "scanners" / "bundler_audit",
        scan_target=layout.source,
        cwd=layout.source,
        offline=offline,
        network_scanners=None,
    )


def _real(paths):
    return {p.resolve() for p in paths}


def test_the_declaration_is_exactly_network_database_and_gem_dirs():
    declared = BundlerAuditScanner.sandbox_requirements
    assert declared == SandboxRequirements(
        network=True,
        cache_paths=(ADVISORY_DB_PATH,),
        read_paths=("~/.local/share/gem", "~/.gem/ruby", "$GEM_HOME"),
    )


def test_online_the_policy_grants_the_network_and_the_database_cache(layout):
    policy = _policy(layout, BundlerAuditScanner.sandbox_requirements)
    default = _policy(layout, SandboxRequirements())
    assert default.network is False
    assert policy.network is True
    database = (layout.home / ".local/share/ruby-advisory-db").resolve()
    assert database in _real(policy.cache)
    assert database not in _real(default.cache)


def test_offline_the_policy_withholds_the_network(layout):
    policy = _policy(layout, BundlerAuditScanner.sandbox_requirements, offline=True)
    assert policy.network is False


def test_no_credential_or_config_variable_is_passed_in(layout):
    policy = _policy(layout, BundlerAuditScanner.sandbox_requirements)
    passed = policy.filter_env(
        {
            "BUNDLE_GEMFILE": "/etc/Gemfile",
            "BUNDLER_AUDIT_CONFIG": "/etc/audit.yml",
            "AWS_SECRET_ACCESS_KEY": "x",
        }
    )
    assert passed.keys() == {"HOME"} | set(policy.extra_env)
