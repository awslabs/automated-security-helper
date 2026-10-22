# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""What the hadolint and GuardDog community scanners get from the scanner sandbox.

Both declare the strict default: no network, the baseline read-only paths, the
results directory as the only writable place, and the baseline environment
allowlist. Grants derived from the environment or from options (hadolint's
``HADOLINT_*`` policy variables and user-level config, GuardDog's ``verify``
network and ``GUARDDOG_*`` variables) wait for the sandbox's grant gates, so a
sandboxed GuardDog ``verify`` runs without a network until then.

The policy is built with ``build_scanner_policy``, the function every sandboxed
spawn goes through, so a declaration the policy ignores fails here.
"""

from __future__ import annotations

import importlib
import sys
from types import SimpleNamespace

import pytest

from automated_security_helper.utils.sandbox.policy import (
    SandboxRequirements,
    build_scanner_policy,
)


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


def _policy(layout, name, requirements, *, offline=False):
    return build_scanner_policy(
        name,
        requirements,
        argv0=sys.executable,
        source_dir=layout.source,
        output_dir=layout.output,
        results_dir=layout.output / "scanners" / name,
        scan_target=layout.source,
        cwd=layout.source,
        offline=offline,
        network_scanners=None,
    )


def _real(paths):
    return {p.resolve() for p in paths}


@pytest.mark.parametrize(
    "module, name",
    [
        (
            "automated_security_helper.plugin_modules.ash_hadolint_plugins.hadolint_scanner",
            "HadolintScanner",
        ),
        (
            "automated_security_helper.plugin_modules.ash_guarddog_plugins.guarddog_scanner",
            "GuardDogScanner",
        ),
    ],
)
def test_hadolint_and_guarddog_declare_the_strict_default(layout, module, name):
    scanner_class = getattr(importlib.import_module(module), name)
    declared = scanner_class.sandbox_requirements
    assert declared == SandboxRequirements()
    policy = _policy(layout, name, declared)
    default = _policy(layout, name, SandboxRequirements())
    assert policy.network is False
    assert _real(policy.read_only) == _real(default.read_only)
    assert _real(policy.cache) == _real(default.cache)
    assert policy.filter_env(
        {"HADOLINT_IGNORE": "x", "GUARDDOG_PARALLELISM": "4"}
    ).keys() == {"HOME"} | set(policy.extra_env)
