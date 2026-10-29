# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Naming a disabled AWS reporter does not run it.

Why this exists
---------------
``--output-formats`` and the config's ``output_formats`` accept the four AWS
reporter names, so an operator can keep, say, ``aws-security-hub`` alongside
``sarif``. The lists only narrow the enabled reporters. These tests hold that
line for the reporters that contact AWS: with each one disabled in the
configuration, naming it through either list must not reach its dependency check
(which calls AWS), its ``report()`` or the disk.

Driven end to end through ``ash scan --use-existing --phases report`` with the AWS
plugin module loaded, so the CLI parsing, the config resolution and the real
report phase are all on the path. Every AWS reporter's dependency check and
``report`` are replaced by tripwires, and ``boto3`` session and client creation
raise, so nothing here can contact AWS even if the guard fails.

Known limitations
-----------------
* All four are disabled in every case. An enabled AWS reporter's dependency check
  runs before the format filter whether or not it is named; that is outside what
  naming changes and is not asserted here.
"""

from pathlib import Path
from typing import List
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

import automated_security_helper.plugin_modules.ash_aws_plugins as aws_plugins
from automated_security_helper.cli.main import app
from automated_security_helper.core.enums import ScannerStatus
from automated_security_helper.models.asharp_model import (
    AshAggregatedResults,
    ScannerTargetStatusInfo,
)

pytestmark = pytest.mark.unit

AWS_MODULE = "automated_security_helper.plugin_modules.ash_aws_plugins"
AWS_NAMES = ("aws-security-hub", "bedrock-summary-reporter", "cloudwatch-logs", "s3")
DISABLE_ALL = [f"reporters.{name}.enabled=false" for name in AWS_NAMES]


@pytest.fixture(autouse=True)
def no_aws(monkeypatch, tmp_path):
    """No route to AWS even past the tripwires: no real credentials or endpoint."""
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")  # pragma: allowlist secret
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_EC2_METADATA_DISABLED", "true")
    monkeypatch.setenv("AWS_CONFIG_FILE", str(tmp_path / "no-aws-config"))
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", str(tmp_path / "no-aws-creds"))

    def refuse(*args, **kwargs):
        raise AssertionError("a botocore request was attempted")

    monkeypatch.setattr("botocore.endpoint.Endpoint._send", refuse)


@pytest.fixture
def tripwires():
    """Record and refuse any dependency check, report or boto3 session/client."""
    calls: List[str] = []

    def trip(label):
        def _refuse(*args, **kwargs):
            calls.append(label)
            raise AssertionError(f"{label} was called for a disabled reporter")

        return _refuse

    patches = []
    for cls in aws_plugins.ASH_REPORTERS:
        patches.append(
            patch.object(
                cls,
                "validate_plugin_dependencies",
                trip(f"{cls.__name__}.validate_plugin_dependencies"),
            )
        )
        patches.append(patch.object(cls, "report", trip(f"{cls.__name__}.report")))
    patches.append(patch("boto3.Session", trip("boto3.Session")))
    patches.append(patch("boto3.client", trip("boto3.client")))
    for item in patches:
        item.start()
    try:
        yield calls
    finally:
        for item in patches:
            item.stop()


def _scan_report_phase(tmp_path: Path, extra: List[str]):
    source = tmp_path / "src"
    source.mkdir()
    output = tmp_path / "out"
    # --use-existing refuses results that hold no scanner results and no findings
    # (utils/inner_run_outcome.existing_results_problem), as a run that stopped
    # before its scan recorded anything leaves; these results record one scanner
    # that ran, so the report phase runs over them.
    results = AshAggregatedResults()
    results.scanner_results["bandit"] = ScannerTargetStatusInfo(
        status=ScannerStatus.PASSED
    )
    results.save_model(output)
    overrides: List[str] = []
    for override in DISABLE_ALL:
        overrides += ["--config-overrides", override]
    result = CliRunner().invoke(
        app,
        [
            "scan",
            "--source-dir",
            str(source),
            "--output-dir",
            str(output),
            "--mode",
            "local",
            "--use-existing",
            "--phases",
            "report",
            "--ash-plugin-modules",
            AWS_MODULE,
            "--no-progress",
            "--no-color",
            *overrides,
            *extra,
        ],
    )
    reports = output / "reports"
    written = sorted(p.name for p in reports.iterdir()) if reports.exists() else []
    return result, written


@pytest.mark.parametrize("name", AWS_NAMES)
def test_naming_it_on_the_command_line_runs_nothing(name, tmp_path, tripwires):
    result, written = _scan_report_phase(tmp_path, ["-f", f"sarif,{name}"])

    assert result.exit_code == 0, result.output
    assert tripwires == []
    assert written == ["ash.sarif"]
    assert f"'{name}'" in result.output and "disabled" in result.output


@pytest.mark.parametrize("name", AWS_NAMES)
def test_naming_it_in_the_config_runs_nothing(name, tmp_path, tripwires):
    result, written = _scan_report_phase(
        tmp_path, ["--config-overrides", f'output_formats=["sarif", "{name}"]']
    )

    assert result.exit_code == 0, result.output
    assert tripwires == []
    assert written == ["ash.sarif"]
    assert f"'{name}'" in result.output and "disabled" in result.output
