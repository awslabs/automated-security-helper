# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""What the BinSkim alpha scanner gets from the scanner sandbox.

No network, the baseline read-only paths, the results directory as the only writable
place, and the baseline environment allowlist plus one name:
``DOTNET_SYSTEM_GLOBALIZATION_INVARIANT``, the variable the scanner sets on every run
so the .NET runtime inside BinSkim starts on a host with no ICU. BinSkim reads files
and its rules are compiled in, so it needs nothing else.

The policy is built with ``build_scanner_policy``, the function every sandboxed spawn
goes through, so a declaration the policy ignores fails here.
"""

from __future__ import annotations

import sys
from types import SimpleNamespace

import pytest

from automated_security_helper.plugin_modules.ash_binskim_plugins.binskim_scanner import (
    GLOBALIZATION_INVARIANT_ENV,
    BinskimScanner,
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
        "binskim",
        requirements,
        argv0=sys.executable,
        source_dir=layout.source,
        output_dir=layout.output,
        results_dir=layout.output / "scanners" / "binskim",
        scan_target=layout.source,
        cwd=layout.source,
        offline=False,
        network_scanners=None,
    )


def _real(paths):
    return {p.resolve() for p in paths}


def test_binskim_declares_the_default_and_one_variable(layout):
    declared = BinskimScanner.sandbox_requirements
    assert declared == SandboxRequirements(env_names=(GLOBALIZATION_INVARIANT_ENV,))
    assert GLOBALIZATION_INVARIANT_ENV == "DOTNET_SYSTEM_GLOBALIZATION_INVARIANT"
    policy = _policy(layout, declared)
    default = _policy(layout, SandboxRequirements())
    assert policy.network is False
    assert _real(policy.read_only) == _real(default.read_only)
    assert _real(policy.cache) == _real(default.cache)


def test_the_results_directory_is_the_only_writable_place(layout):
    policy = _policy(layout, BinskimScanner.sandbox_requirements)
    default = _policy(layout, SandboxRequirements())
    assert _real(policy.writable) == _real(default.writable)
    assert (layout.output / "scanners" / "binskim").resolve() in _real(policy.writable)


def test_the_invariant_variable_reaches_the_sandbox_and_nothing_else_does(layout):
    policy = _policy(layout, BinskimScanner.sandbox_requirements)
    passed = policy.filter_env(
        {
            GLOBALIZATION_INVARIANT_ENV: "1",
            "DOTNET_ROOT": "/opt/dotnet",
            "DOTNET_STARTUP_HOOKS": "/tmp/hook.dll",
            "_NT_SYMBOL_PATH": "srv*https://msdl.microsoft.com/download/symbols",
            "AWS_SECRET_ACCESS_KEY": "x",
        }
    )
    assert passed[GLOBALIZATION_INVARIANT_ENV] == "1"
    assert passed.keys() == {"HOME", GLOBALIZATION_INVARIANT_ENV} | set(
        policy.extra_env
    )


def test_without_the_declaration_the_variable_would_be_dropped(layout):
    """The planted control: the baseline allowlist alone does not pass it."""
    policy = _policy(layout, SandboxRequirements())
    passed = policy.filter_env({GLOBALIZATION_INVARIANT_ENV: "1"})
    assert GLOBALIZATION_INVARIANT_ENV not in passed
