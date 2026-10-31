# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""What a refusal names, who an entry is marked as coming from, and a plugin
section that is not a mapping.

* A refusal of delivered files names the denied fields of every delivered file
  of the chain, not the first file's alone.
* A suppression an operator's own file adds with a ``patch`` op is the
  operator's, so it is not marked ``client_supplied``.
* A trusted config that is, or extends, a file an MCP client delivered is
  replaced by the server's default config, and the log says so.
* A trusted plugin section that holds a scalar has no option value to compare a
  delivered default with, and does not make the comparison raise.
"""

from __future__ import annotations

import logging
from pathlib import Path
from types import SimpleNamespace
from typing import Iterator, List

import pytest

from automated_security_helper.config import client_config_policy as ccp
from automated_security_helper.config import resolve_config
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.exceptions import ASHConfigFieldDeniedError
from automated_security_helper.utils.log import ASH_LOGGER

pytestmark = pytest.mark.unit


@pytest.fixture
def warnings() -> Iterator[List[str]]:
    """Warnings ASH logs during the test."""
    seen: List[str] = []

    class _Keep(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            seen.append(record.getMessage())

    handler = _Keep(level=logging.WARNING)
    ASH_LOGGER.addHandler(handler)
    try:
        yield seen
    finally:
        ASH_LOGGER.removeHandler(handler)


def test_a_refusal_names_the_denied_fields_of_every_delivered_file(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.setattr(ccp, "DENIED_FIELD_HANDLING", "refuse")
    documents = {
        tmp_path / "first.yaml": {"fail_on_findings": False},
        tmp_path / "second.yaml": {
            "reporters": {"BedrockSummary": {"options": {"aws_region": "r"}}}
        },
    }

    with pytest.raises(ASHConfigFieldDeniedError) as refused:
        ccp.apply_client_config_rules(
            AshConfig(),
            documents,
            rules=ccp.rules_from(AshConfig()),
            trusted_config_path=None,
            source_dir=None,
            permit_base=None,
            all_delivered=True,
        )

    text = str(refused.value)
    assert "first.yaml" in text and "fail_on_findings" in text, text
    assert "second.yaml" in text and "aws_region" in text, text


def test_control_a_refusal_of_one_file_names_it_once(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.setattr(ccp, "DENIED_FIELD_HANDLING", "refuse")

    with pytest.raises(ASHConfigFieldDeniedError) as refused:
        ccp.apply_client_config_rules(
            AshConfig(),
            {tmp_path / "only.yaml": {"fail_on_findings": False}},
            rules=ccp.rules_from(AshConfig()),
            trusted_config_path=None,
            source_dir=None,
            permit_base=None,
            all_delivered=True,
        )

    assert str(refused.value).count("only.yaml") == 1, str(refused.value)


def _operators_entry() -> dict:
    return {"path": "app.py", "reason": "the operator's patch"}


def test_a_suppression_an_operator_file_adds_by_patch_is_not_marked(
    tmp_path: Path,
) -> None:
    config = AshConfig.model_validate(
        {"global_settings": {"suppressions": [_operators_entry()]}}
    )
    operator = tmp_path / "operator.yaml"
    documents = {
        operator: {
            "patch": [
                {
                    "op": "add",
                    "path": "/global_settings/suppressions/-",
                    "value": _operators_entry(),
                }
            ]
        }
    }

    marked = ccp._mark_client_supplied(
        config, documents, AshConfig(), lambda _path: False
    )

    assert [s.client_supplied for s in marked.global_settings.suppressions] == [False]


def test_control_a_suppression_no_operator_file_holds_is_marked(
    tmp_path: Path,
) -> None:
    config = AshConfig.model_validate(
        {"global_settings": {"suppressions": [_operators_entry()]}}
    )
    operator = tmp_path / "operator.yaml"

    marked = ccp._mark_client_supplied(
        config, {operator: {"project_name": "operator"}}, AshConfig(), lambda _p: False
    )

    assert [s.client_supplied for s in marked.global_settings.suppressions] == [True]


def test_a_trusted_config_a_client_delivered_falls_back_with_a_warning(
    tmp_path: Path, monkeypatch, warnings: List[str]
) -> None:
    root = tmp_path / "ash-mcp"
    delivered = root / "session-a" / "source" / "ash.yaml"
    delivered.parent.mkdir(parents=True)
    delivered.write_text("", encoding="utf-8")
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(root))
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    operator = SimpleNamespace(
        config=AshConfig.model_validate({"project_name": "operator"}),
        chain=[delivered],
        names={},
    )
    monkeypatch.setattr(
        resolve_config, "_load_operator_config", lambda *args, **kwargs: operator
    )

    trusted = ccp._trusted_config(tmp_path / "operator.yaml", None, None)

    assert trusted.project_name != "operator"
    assert any("default config is the trusted config" in text for text in warnings), (
        warnings
    )


def test_control_a_trusted_config_the_operator_holds_is_used_without_a_warning(
    tmp_path: Path, monkeypatch, warnings: List[str]
) -> None:
    monkeypatch.delenv("ASH_MCP_WORKSPACE_ROOT", raising=False)
    operator = SimpleNamespace(
        config=AshConfig.model_validate({"project_name": "operator"}),
        chain=[tmp_path / "operator.yaml"],
        names={},
    )
    monkeypatch.setattr(
        resolve_config, "_load_operator_config", lambda *args, **kwargs: operator
    )

    trusted = ccp._trusted_config(tmp_path / "operator.yaml", None, None)

    assert trusted.project_name == "operator"
    assert not [text for text in warnings if "trusted config" in text], warnings


def test_a_scalar_trusted_plugin_section_has_no_value_to_compare() -> None:
    base = SimpleNamespace(get_plugin_config=lambda _kind, _name: "disabled")
    document = {"scanners": {"trivy-repo": {"options": {"ignore_file": None}}}}
    denial = SimpleNamespace(
        pointer="/scanners/trivy-repo/options/ignore_file", from_patch=False
    )

    assert ccp._writes_plugin_default(document, denial, base) is True


def test_control_a_trusted_option_value_still_denies_the_delivered_default() -> None:
    base = SimpleNamespace(
        get_plugin_config=lambda _kind, _name: {
            "options": {"ignore_file": "/ops/.trivyignore"}
        }
    )
    document = {"scanners": {"trivy-repo": {"options": {"ignore_file": None}}}}
    denial = SimpleNamespace(
        pointer="/scanners/trivy-repo/options/ignore_file", from_patch=False
    )

    assert ccp._writes_plugin_default(document, denial, base) is False
