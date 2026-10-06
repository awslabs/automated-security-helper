# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""`ash config init`, `ash config get`, and the defaults a user is handed.

The defaults differ on Windows (semgrep and opengrep are off there), so every surface
that renders them is snapshotted once per host in CONFIG_HOSTS, on every OS.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from tests.snapshot.support.cli import CONFIG_HOSTS, run_cli, simulated_host


@pytest.fixture
def project_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    # A fixed directory name, because `config init` uses it as the project_name.
    project = tmp_path / "demo-project"
    project.mkdir()
    monkeypatch.chdir(project)
    return project


@pytest.mark.parametrize("host", CONFIG_HOSTS, ids=lambda h: h.id)
def test_config_init_writes_default_config(
    host, project_dir, monkeypatch, text_snapshot
):
    with simulated_host(monkeypatch, host):
        run = run_cli(["config", "init"])

    assert run.exit_code == 0, run.output
    written = project_dir / ".ash" / ".ash.yaml"
    assert written.is_file()
    assert text_snapshot("txt")(name="stdout") == run.document
    assert text_snapshot("yaml")(name="ash-yaml") == written.read_text(encoding="utf-8")
    assert text_snapshot("txt")(name="gitignore") == (
        project_dir / ".ash" / ".gitignore"
    ).read_text(encoding="utf-8")


def test_config_init_refuses_to_overwrite(project_dir, text_snapshot):
    assert run_cli(["config", "init"]).exit_code == 0

    run = run_cli(["config", "init"])

    assert run.exit_code == 1
    assert text_snapshot("txt") == run.document


@pytest.mark.parametrize("host", CONFIG_HOSTS, ids=lambda h: h.id)
def test_default_config(host, monkeypatch, text_snapshot):
    """The effective defaults, as ``get_default_config`` hands them to a scan."""
    from automated_security_helper.cli.config import IndentableYamlDumper
    from automated_security_helper.config.default_config import get_default_config

    with simulated_host(monkeypatch, host):
        dumped = yaml.dump(
            get_default_config().model_dump(
                by_alias=True, exclude_defaults=False, exclude_none=False
            ),
            Dumper=IndentableYamlDumper,
            default_flow_style=False,
            sort_keys=False,
        )

    assert text_snapshot("yaml") == dumped


CUSTOM_CONFIG = """\
project_name: snapshot-demo
fail_on_findings: false
global_settings:
  severity_threshold: HIGH
  ignore_paths:
    - path: build/**
      reason: Generated output
scanners:
  bandit:
    enabled: true
    options:
      confidence_level: high
  checkov:
    enabled: false
reporters:
  html:
    enabled: false
"""


@pytest.mark.parametrize("host", CONFIG_HOSTS, ids=lambda h: h.id)
def test_config_get_renders_resolved_yaml(
    host, project_dir, monkeypatch, text_snapshot
):
    (project_dir / "custom.yaml").write_text(CUSTOM_CONFIG, encoding="utf-8")

    with simulated_host(monkeypatch, host):
        run = run_cli(
            [
                "config",
                "get",
                "custom.yaml",
                "--config-overrides",
                "global_settings.severity_threshold=LOW",
            ]
        )

    assert run.exit_code == 0, run.output
    assert "severity_threshold: LOW" in run.output
    assert text_snapshot("txt") == run.document


def test_config_get_missing_file(project_dir, text_snapshot):
    run = run_cli(["config", "get", "does-not-exist.yaml"])

    assert run.exit_code == 1
    assert text_snapshot("txt") == run.document
