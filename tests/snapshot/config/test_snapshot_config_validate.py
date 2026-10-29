# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""`ash config validate` and `ash config validate-plugin-dependencies`."""

from __future__ import annotations

from pathlib import Path

import pytest

from tests.snapshot.support.cli import run_cli

pytestmark = pytest.mark.unit

VALID_CONFIG = """\
project_name: snapshot-demo
global_settings:
  severity_threshold: MEDIUM
scanners:
  bandit:
    enabled: true
"""

# One of each problem ConfigValidator reports, so the numbered list shows them all.
INVALID_CONFIG = """\
fail_on_findings: true
build:
  build_mode: online
legacy_option: 1
scanners:
  bandit:
    name: bandit
    tool_version: "1.7.0"
reporters:
  html:
    extension: html
converters:
  archive:
    install_timeout: 10
global_settings:
  ignore_paths:
    - path: vendor
      reason: third party code
fail_on_findings: false
"""


@pytest.fixture
def project_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    project = tmp_path / "demo-project"
    (project / "vendor").mkdir(parents=True)
    (project / "valid.yaml").write_text(VALID_CONFIG, encoding="utf-8")
    (project / "invalid.yaml").write_text(INVALID_CONFIG, encoding="utf-8")
    (project / "broken.yaml").write_text("project_name: [unclosed\n", encoding="utf-8")
    monkeypatch.chdir(project)
    return project


# 3 is the exit code a scan gives for a config it refuses; validate gives the same.
# invalid.yaml's `build_mode: online` is the one value the model refuses; every
# other problem in it is a warning, because a scan accepts it.
@pytest.mark.parametrize(
    "config, exit_code",
    [
        pytest.param("valid.yaml", 0, id="valid"),
        pytest.param("invalid.yaml", 3, id="invalid"),
        pytest.param("broken.yaml", 3, id="broken"),
        pytest.param("missing.yaml", 3, id="missing"),
    ],
)
def test_config_validate(config, exit_code, project_dir, text_snapshot):
    run = run_cli(["config", "validate", "--config", config])

    assert run.exit_code == exit_code, run.output
    assert text_snapshot("txt") == run.document


def test_config_validate_numbers_every_error(project_dir):
    run = run_cli(["config", "validate", "--config", "invalid.yaml"])

    # Guards the snapshot above against an input that stops exercising a check.
    for expected in (
        "Invalid value at 'build.build_mode'",
        "Top-level field 'project_name' is not set",
        "Top-level field 'build' is an internal field",
        "Unknown top-level field 'legacy_option'",
        "Duplicate top-level field 'fail_on_findings'",
        "Scanner 'bandit' contains internal-only field 'name'",
        "Reporter 'html' contains internal-only field 'extension'",
        "Converter 'archive' contains internal-only field 'install_timeout'",
        "'vendor'",
    ):
        assert expected in run.output, expected


@pytest.mark.parametrize(
    "args, exit_code",
    [
        (["valid.yaml"], 0),
        (["invalid.yaml"], 3),
        (["missing.yaml"], 3),
        (["valid.yaml", "--config-overrides", "fail_on_findings=maybe"], 3),
    ],
    ids=["valid", "invalid", "missing", "bad-override"],
)
def test_config_validate_plugin_dependencies(
    args, exit_code, project_dir, text_snapshot
):
    run = run_cli(["config", "validate-plugin-dependencies", *args])

    assert run.exit_code == exit_code, run.output
    assert text_snapshot("txt") == run.document
