# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Rules that could not be established refuse a delivered config, and say why.

* ``client_file_denials`` judges a delivered file against the rules it is given.
  Unreadable rules carry a placeholder policy and an empty base, so a file
  judged against them was checked against defaults the server does not hold
  (the validate tool did this when it skipped its own unreadable check). It now
  refuses a delivered file for them, as ``apply_client_config_rules`` does.
* A config that carries overrides an MCP client supplied but no delivered file
  is still refused for unreadable rules, and the text says overrides, not a
  delivered config.
* The reason for two sections that read as one plugin is returned to the client,
  so it does not quote a key the trusted config read from the environment.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from automated_security_helper.config import client_config_policy as ccp
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.exceptions import ASHConfigPolicyUnreadableError

pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
def _no_workspace_root(monkeypatch) -> None:
    """No file is a client's by where it sits, unless a test says so."""
    monkeypatch.delenv("ASH_MCP_WORKSPACE_ROOT", raising=False)


def test_a_delivered_file_is_refused_for_unreadable_rules(tmp_path: Path) -> None:
    rules = ccp.unreadable_rules("the bound profile is not registered")

    with pytest.raises(ASHConfigPolicyUnreadableError) as refused:
        ccp.client_file_denials(
            {tmp_path / "delivered.yaml": {"project_name": "client"}},
            rules,
            scanned_root=tmp_path,
            all_delivered=True,
        )

    text = str(refused.value)
    assert "the bound profile is not registered" in text, text
    assert "delivered" in text, text


def test_a_file_the_client_did_not_deliver_is_not_refused_for_unreadable_rules(
    tmp_path: Path,
) -> None:
    """Held, not raised: only a delivered file needs the rules."""
    rules = ccp.unreadable_rules("the bound profile is not registered")

    found = ccp.client_file_denials(
        {tmp_path / "operator.yaml": {"project_name": "operator"}},
        rules,
        scanned_root=tmp_path,
    )

    assert found == []


def _overrides_only(tmp_path: Path, *, all_delivered: bool) -> str:
    with pytest.raises(ASHConfigPolicyUnreadableError) as refused:
        ccp.apply_client_config_rules(
            AshConfig(),
            {tmp_path / "operator.yaml": {"project_name": "operator"}},
            rules=ccp.unreadable_rules("the bound profile is not registered"),
            trusted_config_path=None,
            source_dir=None,
            permit_base=None,
            all_delivered=all_delivered,
            client_overrides=True,
        )
    return str(refused.value)


def test_overrides_alone_are_refused_without_claiming_a_delivered_config(
    tmp_path: Path,
) -> None:
    text = _overrides_only(tmp_path, all_delivered=False)

    assert "the bound profile is not registered" in text, text
    assert "overrides" in text, text
    assert "delivered" not in text, text


def test_control_a_delivered_file_with_overrides_is_still_called_delivered(
    tmp_path: Path,
) -> None:
    text = _overrides_only(tmp_path, all_delivered=True)

    assert "A config an MCP client delivered cannot be checked" in text, text


def test_the_clash_reason_does_not_quote_a_key_read_from_the_environment() -> None:
    profile = AshConfig.model_validate(
        {
            "reporters": {
                "bedrock-summary": {"options": {"aws_region": "eu-west-1"}},
                "bedrock-summary-reporter": {"options": {"aws_region": "us-east-1"}},
            }
        }
    )
    profile._environment_values = ["bedrock-summary-reporter"]

    reason = ccp.rules_from(profile).unreadable

    assert reason is not None and "same plugin" in reason, reason
    assert "'bedrock-summary'" in reason, reason
    assert "bedrock-summary-reporter" not in reason, reason


def test_control_the_clash_reason_names_both_keys_when_none_was_read_from_it() -> None:
    profile = AshConfig.model_validate(
        {
            "reporters": {
                "bedrock-summary": {"options": {"aws_region": "eu-west-1"}},
                "bedrock-summary-reporter": {"options": {"aws_region": "us-east-1"}},
            }
        }
    )

    reason = ccp.rules_from(profile).unreadable

    assert reason is not None, reason
    assert "'bedrock-summary'" in reason and "'bedrock-summary-reporter'" in reason
