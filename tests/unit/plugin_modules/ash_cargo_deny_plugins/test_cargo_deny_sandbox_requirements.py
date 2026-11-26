# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""What the cargo-deny alpha scanner gets from the scanner sandbox.

It declares the network (the RustSec advisory database is fetched when the scan
runs), the cargo cache directories (cargo-deny keeps the database under
``CARGO_HOME`` and cargo keeps its registry there), the rustup toolchain as
read-only, and the ``CARGO_`` and ``RUSTUP_`` environment prefixes. Everything
else is the strict default.

The policy is built with ``build_scanner_policy``, the function every sandboxed
spawn goes through, so a declaration the policy ignores fails here.
"""

from __future__ import annotations

import sys
from types import SimpleNamespace

import pytest

from automated_security_helper.plugin_modules.ash_cargo_deny_plugins.cargo_deny_scanner import (
    CargoDenyScanner,
)
from automated_security_helper.utils.sandbox.policy import (
    SandboxRequirements,
    build_scanner_policy,
)

pytestmark = pytest.mark.unit


@pytest.fixture
def layout(tmp_path, monkeypatch):
    home = tmp_path / "home"
    (home / ".cargo").mkdir(parents=True)
    (home / ".rustup").mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.delenv("CARGO_HOME", raising=False)
    monkeypatch.delenv("RUSTUP_HOME", raising=False)
    source = tmp_path / "src"
    source.mkdir()
    output = source / ".ash" / "ash_output"
    output.mkdir(parents=True)
    return SimpleNamespace(home=home, source=source, output=output, tmp=tmp_path)


def _policy(layout, requirements, *, offline=False):
    return build_scanner_policy(
        "cargo-deny",
        requirements,
        argv0=sys.executable,
        source_dir=layout.source,
        output_dir=layout.output,
        results_dir=layout.output / "scanners" / "cargo-deny",
        scan_target=layout.source,
        cwd=layout.source,
        offline=offline,
        network_scanners=None,
    )


def _real(paths):
    return {p.resolve() for p in paths}


def test_the_declaration_is_not_the_strict_default():
    assert CargoDenyScanner.sandbox_requirements != SandboxRequirements()


def test_the_policy_grants_the_network_online(layout):
    policy = _policy(layout, CargoDenyScanner.sandbox_requirements)
    assert policy.network is True


def test_the_network_is_not_granted_under_offline(layout):
    policy = _policy(layout, CargoDenyScanner.sandbox_requirements, offline=True)
    assert policy.network is False


def test_the_cargo_and_rustup_directories_are_in_the_policy(layout):
    declared = CargoDenyScanner.sandbox_requirements
    policy = _policy(layout, declared)
    default = _policy(layout, SandboxRequirements())
    reachable = _real(policy.read_only) | _real(policy.cache)
    reachable_by_default = _real(default.read_only) | _real(default.cache)
    assert (layout.home / ".cargo").resolve() in reachable
    assert (layout.home / ".rustup").resolve() in reachable
    assert (layout.home / ".cargo").resolve() not in reachable_by_default


def test_only_the_cargo_and_rustup_variables_are_passed_in(layout):
    policy = _policy(layout, CargoDenyScanner.sandbox_requirements)
    passed = policy.filter_env(
        {
            "CARGO_HOME": str(layout.home / ".cargo"),
            "RUSTUP_HOME": str(layout.home / ".rustup"),
            "SOME_OTHER_TOKEN": "x",
            "OPENAI_API_KEY": "x",
        }
    )
    assert "CARGO_HOME" in passed and "RUSTUP_HOME" in passed
    assert "SOME_OTHER_TOKEN" not in passed
    assert "OPENAI_API_KEY" not in passed


def test_the_strict_default_passes_neither_cargo_variable(layout):
    policy = _policy(layout, SandboxRequirements())
    passed = policy.filter_env({"CARGO_HOME": "/x", "RUSTUP_HOME": "/y"})
    assert "CARGO_HOME" not in passed and "RUSTUP_HOME" not in passed
