# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""What the restrict-only check of a delivered ``sandbox`` section refuses.

* ``network_scanners: null`` gives each scanner the network its own declaration
  asks for, which is more than a server list that names some scanners. It is
  refused beside a delivered list that names a scanner the server's does not.
* The reason for a replaced sandbox mode is returned to the client, so it does
  not quote a mode the trusted config read from the environment.
* With ``network_scanners`` unset, a scanner's declared need decides whether a
  delivered list may name it. When two classes declare one scanner name, the
  answer does not depend on the order they are found in.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import List

import pytest

from automated_security_helper.base import scanner_plugin
from automated_security_helper.config import client_config_policy as ccp
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.utils.sandbox.policy import SandboxRequirements

pytestmark = pytest.mark.unit


def _refusals(document: dict, rules: ccp.ClientConfigRules, tmp_path: Path) -> list:
    found = ccp.client_file_denials(
        {tmp_path / "delivered.yaml": document},
        rules,
        scanned_root=tmp_path,
        all_delivered=True,
    )
    return [(denial.key, denial.reason) for _, denials in found for denial in denials]


def test_a_null_network_scanners_widens_a_list_the_server_set(tmp_path: Path) -> None:
    base = AshConfig.model_validate(
        {"sandbox": {"mode": "auto", "network_scanners": ["bandit"]}}
    )

    refusals = _refusals(
        {"sandbox": {"network_scanners": None}}, ccp.rules_from(base), tmp_path
    )

    assert [key for key, _ in refusals] == ["sandbox.network_scanners"], refusals


def test_control_a_null_network_scanners_matches_a_server_that_set_none(
    tmp_path: Path,
) -> None:
    rules = ccp.rules_from(AshConfig())
    assert rules.base.sandbox.network_scanners is None

    assert _refusals({"sandbox": {"network_scanners": None}}, rules, tmp_path) == []


def test_control_a_section_without_network_scanners_is_not_a_null(
    tmp_path: Path,
) -> None:
    base = AshConfig.model_validate(
        {"sandbox": {"mode": "auto", "network_scanners": ["bandit"]}}
    )
    rules = ccp.rules_from(base)

    assert _refusals({"sandbox": {"extra_read_paths": []}}, rules, tmp_path) == []


def _mode_refusal(base: AshConfig, tmp_path: Path) -> str:
    [(key, reason)] = _refusals(
        {"sandbox": {"mode": "off"}}, ccp.rules_from(base), tmp_path
    )
    assert key == "sandbox.mode"
    return reason


def test_the_mode_reason_does_not_quote_a_mode_read_from_the_environment(
    tmp_path: Path,
) -> None:
    base = AshConfig.model_validate({"sandbox": {"mode": "bwrap"}})
    base._environment_values = ["bwrap"]

    reason = _mode_refusal(base, tmp_path)

    assert reason.startswith("replaces the server's sandbox mode"), reason
    assert "bwrap" not in reason, reason


def test_control_the_mode_reason_names_a_mode_that_was_not_read_from_it(
    tmp_path: Path,
) -> None:
    base = AshConfig.model_validate({"sandbox": {"mode": "bwrap"}})

    assert "'bwrap'" in _mode_refusal(base, tmp_path)


def _twin_scanner(network: bool) -> type:
    """A scanner class that declares the name ``zz-twin-scanner`` and a need."""
    config_class = type(
        "TwinConfig",
        (),
        {"model_fields": {"name": SimpleNamespace(default="zz-twin-scanner")}},
    )
    return type(
        "TwinScanner",
        (),
        {
            "model_fields": {"config": SimpleNamespace(annotation=config_class)},
            "sandbox_requirements": SandboxRequirements(network=network),
        },
    )


def _found_in_this_order(monkeypatch, classes: List[type]) -> None:
    """Make ``classes`` the scanner classes the check walks, in this order."""
    stand_in = SimpleNamespace(__subclasses__=lambda: list(classes))
    monkeypatch.setattr(scanner_plugin, "ScannerPluginBase", stand_in)


@pytest.mark.parametrize(
    "needs,gets_a_network",
    [
        ([False, True], False),
        ([True, False], False),
        ([True], True),
        ([False], False),
        ([], False),
    ],
    ids=[
        "no-network-found-first",
        "network-found-first",
        "one-class-with-a-network",
        "one-class-without",
        "no-class",
    ],
)
def test_two_classes_with_one_scanner_name_give_one_answer(
    monkeypatch, needs: List[bool], gets_a_network: bool
) -> None:
    _found_in_this_order(monkeypatch, [_twin_scanner(need) for need in needs])
    server = SimpleNamespace(network_scanners=None)

    assert ccp._scanner_gets_network("zz-twin-scanner", server) is gets_a_network
