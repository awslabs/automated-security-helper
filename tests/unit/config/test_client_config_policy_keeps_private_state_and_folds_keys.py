# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Two readings of ``config/client_config_policy.py``.

* ``_writes_plugin_default`` forgives a denial only where the trusted base has
  no value for the option. A plugin scanner's section is a plain dict, so the
  trusted base can spell the option ``ignore-file``; the lookup reads either
  spelling, as every other option lookup here does, so a delivered file writing
  the option's default is still denied where the trusted base set a value.
* The drop handling rebuilds the config without the denied fields and keeps
  everything its load recorded (the private attributes: the values its files
  read from the environment among them), as ``apply_config_overrides`` keeps
  them for its rebuild; a rebuild that kept only the resolution warnings
  printed and recorded the environment values the file read.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from automated_security_helper.config import client_config_policy as ccp
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.client_config_policy import (
    _writes_plugin_default,
    apply_client_config_rules,
)

pytestmark = pytest.mark.unit


def test_a_kebab_spelled_trusted_option_still_denies_the_delivered_default():
    base = AshConfig.model_validate(
        {"scanners": {"trivy-repo": {"options": {"ignore-file": "/ops/.trivyignore"}}}}
    )
    document = {"scanners": {"trivy-repo": {"options": {"ignore_file": None}}}}
    denial = SimpleNamespace(
        pointer="/scanners/trivy-repo/options/ignore_file", from_patch=False
    )

    assert _writes_plugin_default(document, denial, base) is False


def test_without_a_trusted_value_the_delivered_default_is_forgiven():
    base = AshConfig()
    document = {"scanners": {"trivy-repo": {"options": {"ignore_file": None}}}}
    denial = SimpleNamespace(
        pointer="/scanners/trivy-repo/options/ignore_file", from_patch=False
    )

    assert _writes_plugin_default(document, denial, base) is True


def test_a_dropped_config_keeps_what_its_load_recorded(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(ccp, "DENIED_FIELD_HANDLING", "drop")
    root = tmp_path / "ash-mcp"
    client = root / "session-a" / "source" / "ash.yaml"
    client.parent.mkdir(parents=True)
    client.write_text("", encoding="utf-8")
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(root))
    document = {"project_name": "c", "fail_on_findings": False}
    config = AshConfig.model_validate(document)
    config._environment_values = ["planted-environment-value"]

    dropped = apply_client_config_rules(
        config,
        {client: document},
        rules=None,
        trusted_config_path=None,
        source_dir=None,
        permit_base=None,
    )

    assert dropped.fail_on_findings is True
    assert "planted-environment-value" in dropped._environment_values
    assert len(dropped._resolution_warnings) == 1
