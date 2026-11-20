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


@pytest.fixture
def ash_warnings():
    """The warnings ASH logs while a test runs (ASH's logger does not propagate)."""
    import logging

    from automated_security_helper.utils.log import ASH_LOGGER

    records = []

    class _Collect(logging.Handler):
        def emit(self, record):
            if record.levelno >= logging.WARNING:
                records.append(record.getMessage())

    handler = _Collect(level=logging.DEBUG)
    previous = ASH_LOGGER.level
    ASH_LOGGER.addHandler(handler)
    ASH_LOGGER.setLevel(logging.DEBUG)
    try:
        yield records
    finally:
        ASH_LOGGER.removeHandler(handler)
        ASH_LOGGER.setLevel(previous)


def _model_with_the_finding_at(path):
    from automated_security_helper.schemas.sarif_schema_model import (
        ArtifactLocation,
        Location,
        PhysicalLocation,
        PhysicalLocation2,
    )

    model = _model_with_one_low_finding()
    model.sarif.runs[0].results[0].locations = [
        Location(
            physicalLocation=PhysicalLocation(
                root=PhysicalLocation2(
                    artifactLocation=ArtifactLocation(uri=path.as_uri())
                )
            )
        )
    ]
    return model


def _export(tmp_path, model, root):
    from automated_security_helper.base.plugin_context import PluginContext
    from automated_security_helper.plugin_modules.ash_builtin.reporters.asff_reporter import (
        AsffReporter,
        AsffReporterConfig,
        AsffReporterOptions,
    )

    options = AsffReporterOptions(
        account_id="123456789012",
        aws_region="us-east-1",
        findings_scope="example",
        scan_root=root,
    )
    reporter = AsffReporter(
        context=PluginContext(source_dir=tmp_path, output_dir=tmp_path / "out"),
        config=AsffReporterConfig(options=options),
    )
    return json.loads(reporter.report(model))["Findings"]


def test_a_scan_root_that_is_a_prefix_of_no_finding_path_warns(tmp_path, ash_warnings):
    recorded = tmp_path / "recorded"
    model = _model_with_the_finding_at(recorded / "file.py")

    [finding] = _export(tmp_path, model, (tmp_path / "elsewhere").as_posix())

    assert len(ash_warnings) == 1, ash_warnings
    assert "is not a prefix of any of the 1 absolute finding paths" in ash_warnings[0]
    assert "specific to the machine that scanned" in ash_warnings[0]
    # The export still runs, with the paths as the results recorded them.
    assert finding["ProductFields"]["ash/file"].endswith("recorded/file.py")


def test_a_scan_root_over_the_finding_paths_does_not_warn(tmp_path, ash_warnings):
    recorded = tmp_path / "recorded"
    model = _model_with_the_finding_at(recorded / "file.py")

    [finding] = _export(tmp_path, model, recorded.as_posix())

    assert ash_warnings == []
    assert finding["ProductFields"]["ash/file"] == "file.py"


def test_a_scan_root_with_no_absolute_finding_path_does_not_warn(
    tmp_path, ash_warnings
):
    # The finding records no path at all, so the root has nothing to match.
    _export(
        tmp_path, _model_with_one_low_finding(), (tmp_path / "elsewhere").as_posix()
    )

    assert ash_warnings == []


def test_the_earlier_account_option_spelling_is_accepted():
    """``aws_account_id`` is what the reporter's options were called before."""
    from automated_security_helper.config.ash_config import AshConfig

    config = AshConfig.model_validate(
        {"reporters": {"asff": {"options": {"aws_account_id": "123456789012"}}}}
    )

    assert config.reporters.asff.options.account_id == "123456789012"
    assert config.reporters.asff.options.model_dump()["account_id"] == "123456789012"


def test_account_id_wins_over_the_earlier_spelling_when_both_are_set():
    from automated_security_helper.plugin_modules.ash_builtin.reporters.asff_reporter import (
        AsffReporterOptions,
    )

    both = AsffReporterOptions.model_validate(
        {"account_id": "111111111111", "aws_account_id": "222222222222"}
    )
    null_and_earlier = AsffReporterOptions.model_validate(
        {"account_id": None, "aws_account_id": "222222222222"}
    )

    assert both.account_id == "111111111111"
    assert null_and_earlier.account_id == "222222222222"


def test_the_earlier_account_option_spelling_is_accepted_as_an_override(tmp_path):
    _write_results(tmp_path)
    result = _report(
        tmp_path,
        "asff",
        "--config-overrides",
        "reporters.asff.options.aws_account_id=123456789012",
        "--config-overrides",
        "reporters.asff.options.aws_region=us-east-1",
        "--config-overrides",
        "reporters.asff.options.findings_scope=example",
    )
    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout)["Findings"][0]["AwsAccountId"] == "123456789012"


def test_results_that_stored_the_earlier_asff_options_still_load(
    tmp_path, ash_warnings
):
    """An aggregated-results file from before the rename keeps its stored config.

    The stored config is read with unknown keys tolerated (utils/unknown_keys.py),
    so the file loads; the earlier ``aws_account_id`` is a spelling of the option
    now, so it also lands in ``account_id`` and is not reported as unknown.
    """
    from automated_security_helper.models.asharp_model import AshAggregatedResults

    _write_results(tmp_path)
    path = tmp_path / "ash_aggregated_results.json"
    data = json.loads(path.read_text())
    data["ash_config"]["reporters"]["asff"] = {
        "enabled": False,
        "extension": "asff",
        "name": "asff",
        "options": {"aws_account_id": "123456789012", "aws_region": "us-east-1"},
    }
    path.write_text(json.dumps(data), encoding="utf-8")

    loaded = AshAggregatedResults.load_model(path)

    assert loaded is not None
    options = loaded.ash_config.reporters.asff.options
    assert options.account_id == "123456789012"
    assert options.aws_region == "us-east-1"
    assert not [w for w in ash_warnings if "unknown key" in w], ash_warnings


def test_results_that_stored_an_asff_option_this_version_lacks_still_load(
    tmp_path, ash_warnings
):
    """The stored-config tolerance itself: a key the model does not declare is kept
    and reported, and the results load."""
    from automated_security_helper.models.asharp_model import AshAggregatedResults

    _write_results(tmp_path)
    path = tmp_path / "ash_aggregated_results.json"
    data = json.loads(path.read_text())
    data["ash_config"]["reporters"]["asff"]["options"] = {
        "account_id": "123456789012",
        "retired_option": "x",
    }
    path.write_text(json.dumps(data), encoding="utf-8")

    loaded = AshAggregatedResults.load_model(path)

    assert loaded is not None
    assert loaded.ash_config.reporters.asff.options.account_id == "123456789012"
    assert [w for w in ash_warnings if "unknown key" in w], ash_warnings
