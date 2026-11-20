# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import json

import boto3
import botocore.session
import pytest

from automated_security_helper.models.workspace import WorkspaceResults
from tests.unit.cli.test_report_format_output import (
    _model_with_one_low_finding,
    _report,
    _write_results,
)

pytestmark = pytest.mark.unit


def test_offline_asff_cli(tmp_path, monkeypatch):
    _write_results(tmp_path)

    def refuse(*args, **kwargs):
        raise AssertionError("AWS access requested")

    monkeypatch.setattr(boto3, "Session", refuse)
    monkeypatch.setattr(botocore.session.Session, "get_credentials", refuse)
    result = _report(
        tmp_path,
        "asff",
        "--config-overrides",
        "ash_plugin_modules+=[automated_security_helper.plugin_modules.ash_aws_plugins]",
        "--config-overrides",
        "reporters.aws-security-hub.enabled=true",
        "--config-overrides",
        "reporters.asff.options.account_id=123456789012",
        "--config-overrides",
        "reporters.asff.options.aws_region=us-gov-west-1",
        "--config-overrides",
        "reporters.asff.options.findings_scope=example",
    )
    assert result.exit_code == 0, result.output
    assert len(json.loads(result.stdout)["Findings"]) == 1


def _asff(output_dir, account="123456789012", region="cn-north-1", root=None):
    args = [
        "--config-overrides",
        f"reporters.asff.options.account_id={account}",
        "--config-overrides",
        f"reporters.asff.options.aws_region={region}",
        "--config-overrides",
        "reporters.asff.options.findings_scope=example",
    ]
    if root:
        args += ["--config-overrides", f"reporters.asff.options.scan_root={root}"]
    return _report(output_dir, "asff", *args)


def test_offline_partition_ignores_profile_and_sessions(tmp_path, monkeypatch):
    _write_results(tmp_path)
    monkeypatch.setenv("AWS_PROFILE", "missing-offline-profile")

    def refuse(*args, **kwargs):
        raise AssertionError("AWS session requested")

    monkeypatch.setattr(boto3, "Session", refuse)
    monkeypatch.setattr(botocore.session, "get_session", refuse)
    result = _asff(tmp_path)
    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout)["Findings"][0]["ProductArn"] == (
        "arn:aws-cn:securityhub:cn-north-1:123456789012:product/123456789012/default"
    )


@pytest.mark.parametrize(
    "account,expected",
    [
        ("123", None),
        ("123456789012", "123456789012"),
        ('"012345678901"', "012345678901"),
    ],
)
def test_offline_account_id_requires_twelve_digits(tmp_path, account, expected):
    _write_results(tmp_path)
    result = _asff(tmp_path, account=account)
    if expected is None:
        assert result.exit_code != 0
        assert not result.stdout
    else:
        assert result.exit_code == 0, result.output
        assert json.loads(result.stdout)["Findings"][0]["AwsAccountId"] == expected


def test_offline_paths_do_not_follow_export_host_symlinks(tmp_path, monkeypatch):
    from automated_security_helper.schemas.sarif_schema_model import (
        ArtifactLocation,
        Location,
        PhysicalLocation,
        PhysicalLocation2,
    )

    original = tmp_path / "original"
    export_root = tmp_path / "export-root"
    model = _model_with_one_low_finding()
    result = model.sarif.runs[0].results[0]
    result.locations = [
        Location(
            physicalLocation=PhysicalLocation(
                root=PhysicalLocation2(
                    artifactLocation=ArtifactLocation(
                        uri=(original / "file.py").as_uri()
                    )
                )
            )
        )
    ]
    _write_results(tmp_path, model)
    monkeypatch.chdir(tmp_path)
    missing_root = _asff(tmp_path)
    assert missing_root.exit_code != 0
    assert not missing_root.stdout
    assert "reporters.asff.options.scan_root" in missing_root.stderr
    before = _asff(tmp_path, root=export_root)
    assert before.exit_code == 0, before.output
    try:
        export_root.symlink_to(original, target_is_directory=True)
    except OSError as error:
        pytest.skip(f"Cannot create a directory symlink: {error}")
    after = _asff(tmp_path, root=export_root)
    assert after.exit_code == 0, after.output
    first = json.loads(before.stdout)["Findings"][0]
    second = json.loads(after.stdout)["Findings"][0]
    assert first["Id"] == second["Id"]
    assert first["Resources"][0]["Id"] == second["Resources"][0]["Id"]
    assert first["ProductFields"]["ash/file"] == second["ProductFields"]["ash/file"]
    matching = _asff(tmp_path, root=original)
    assert matching.exit_code == 0, matching.output
    assert (
        json.loads(matching.stdout)["Findings"][0]["ProductFields"]["ash/file"]
        == "file.py"
    )


def test_empty_legacy_results_produce_empty_findings(tmp_path):
    model = _model_with_one_low_finding()
    model.sarif.runs[0].results = []
    _write_results(tmp_path, model)
    result = _asff(tmp_path)
    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout) == {"Findings": []}


def test_workspace_aggregate_requires_per_project_export(tmp_path):
    model = _model_with_one_low_finding()
    model.workspace = WorkspaceResults(
        workspace_file=str(tmp_path / "project.code-workspace"),
        workspace_root=str(tmp_path),
        exit_code=0,
    )
    _write_results(tmp_path, model)

    result = _asff(tmp_path)

    assert result.exit_code != 0
    assert not result.stdout
    assert "asff exports one project at a time" in result.stderr


def test_corrupt_metadata_is_rejected(tmp_path):
    _write_results(tmp_path)
    path = tmp_path / "ash_aggregated_results.json"
    data = json.loads(path.read_text())
    data["metadata"] = "corrupt"
    path.write_text(json.dumps(data))
    assert _asff(tmp_path).exit_code != 0
