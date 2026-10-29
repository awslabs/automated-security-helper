# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""An override respelling an existing section is refused, naming the real key.

An operator who writes ``--config-overrides reporters.AwsSecurityHub.enabled=
false`` against a config whose own section is ``aws-security-hub`` must never
get a silent no-op: the override would land as a new extra, the reporter would
read its exact section and stay enabled, findings would go off the host, and
the run would report success. A non-exact spelling of an existing section
(one the fold reads as the same name) is refused with the real key, so the
operator reruns with the section's own spelling. An override that matches no
existing section still lands as written.
"""

from __future__ import annotations

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli.main import app
from automated_security_helper.config.resolve_config import (
    apply_config_overrides,
    load_config_file_for_run,
)
from automated_security_helper.core.exceptions import ASHConfigValidationError

pytestmark = pytest.mark.unit


@pytest.fixture
def off_host_config(tmp_path, monkeypatch):
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    path = tmp_path / "ash.yaml"
    path.write_text(
        "project_name: t\nreporters:\n  aws-security-hub:\n    enabled: true\n",
        encoding="utf-8",
    )
    return path


def test_an_off_host_disable_under_a_respelling_is_refused(off_host_config):
    _, config = load_config_file_for_run(off_host_config)

    with pytest.raises(ASHConfigValidationError) as refused:
        apply_config_overrides(config, ["reporters.AwsSecurityHub.enabled=false"])

    text = str(refused.value)
    assert "reporters.aws-security-hub" in text, text


def test_the_cli_refuses_and_names_the_real_key(off_host_config, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    result = CliRunner().invoke(
        app,
        [
            "config",
            "get",
            "--config",
            str(off_host_config),
            "--config-overrides",
            "reporters.AwsSecurityHub.enabled=false",
        ],
    )
    assert result.exit_code == 3, result.output
    assert "reporters.aws-security-hub" in result.output, result.output


def test_an_unknown_section_with_an_existing_variant_is_refused(tmp_path, monkeypatch):
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    path = tmp_path / "ash.yaml"
    path.write_text(
        "project_name: t\nscanners:\n  my-scanner:\n    enabled: true\n",
        encoding="utf-8",
    )
    _, config = load_config_file_for_run(path)

    with pytest.raises(ASHConfigValidationError) as refused:
        apply_config_overrides(config, ["scanners.MyScanner.enabled=false"])

    assert "scanners.my-scanner" in str(refused.value), str(refused.value)


def test_control_an_override_matching_no_section_lands_as_written(
    tmp_path, monkeypatch
):
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    path = tmp_path / "ash.yaml"
    path.write_text(
        "project_name: t\nscanners:\n  my-scanner:\n    enabled: true\n",
        encoding="utf-8",
    )
    _, config = load_config_file_for_run(path)

    updated = apply_config_overrides(config, ["scanners.OtherTool.enabled=false"])

    extras = updated.scanners.model_extra or {}
    assert extras["my-scanner"]["enabled"] is True, extras
    assert extras.get("OtherTool", {}).get("enabled") is False, extras
