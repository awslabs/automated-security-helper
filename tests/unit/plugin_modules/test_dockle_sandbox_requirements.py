# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""What the Dockle alpha scanner gets from the scanner sandbox.

It declares a network need that follows the operator's ``image`` option
(``network_requires_grant``), so the network is granted only where the operator's
trusted configuration lists ``dockle`` in ``sandbox.network_scanners``. ``DOCKLE_``
variables (``DOCKLE_IGNORES``, ``DOCKLE_HOST``) pass the environment filter; a
credential-shaped name under the prefix does not.

The policy is built with ``build_scanner_policy``, the function every sandboxed
spawn goes through, so a declaration the policy ignores fails here.
"""

from __future__ import annotations

import sys
from types import SimpleNamespace

import pytest

from automated_security_helper.plugin_modules.ash_dockle_plugins.dockle_scanner import (
    DockleScanner,
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


def _policy(layout, requirements, *, network_scanners=None, offline=False):
    return build_scanner_policy(
        "dockle",
        requirements,
        argv0=sys.executable,
        source_dir=layout.source,
        output_dir=layout.output,
        results_dir=layout.output / "scanners" / "dockle",
        scan_target=layout.source,
        cwd=layout.output / "scanners" / "dockle",
        offline=offline,
        network_scanners=network_scanners,
    )


def test_dockle_declares_a_network_need_that_needs_a_grant():
    declared = DockleScanner.sandbox_requirements
    assert declared.network is True
    assert declared.network_requires_grant is True
    assert declared.env_prefixes == ("DOCKLE_",)
    # Distinct from the strict default, which asks for nothing.
    assert declared != SandboxRequirements()


def test_no_grant_means_no_network(layout):
    policy = _policy(layout, DockleScanner.sandbox_requirements)
    assert policy.network is False


def test_a_trusted_grant_for_dockle_opens_the_network(layout):
    policy = _policy(
        layout, DockleScanner.sandbox_requirements, network_scanners=["dockle"]
    )
    assert policy.network is True


def test_a_grant_for_another_scanner_does_not_open_it(layout):
    policy = _policy(
        layout, DockleScanner.sandbox_requirements, network_scanners=["grype"]
    )
    assert policy.network is False


def test_the_dockle_variables_pass_and_a_credential_shaped_one_does_not(layout):
    policy = _policy(layout, DockleScanner.sandbox_requirements)
    passed = policy.filter_env(
        {
            "DOCKLE_IGNORES": "CIS-DI-0001",
            "DOCKLE_PASSWORD": "placeholder",
            "UNRELATED_SETTING": "x",
        }
    )
    assert passed.get("DOCKLE_IGNORES") == "CIS-DI-0001"
    assert "DOCKLE_PASSWORD" not in passed
    assert "UNRELATED_SETTING" not in passed
