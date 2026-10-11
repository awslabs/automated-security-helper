# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""A cloud reporter's dependency check and its report run only when the run uses it.

The AWS reporters' dependency checks contact AWS (Security Hub calls
``DescribeHub``, the others STS), so:

* a scan whose operator enabled Security Hub but asked for other formats
  (``-f sarif``) neither checks nor runs it;
* ``ash report --format <cloud reporter>`` refuses a reporter the operator did not
  enable, and runs one they did;
* workspace reporting does not check a per-project reporter, which it does not
  run at workspace level.

Every test runs with no ``AWS_*`` credentials, a loopback endpoint and botocore's
request method replaced by a recorder that refuses every request, so nothing
here can reach AWS. ``test_cloud_reporters_require_operator_config.py`` covers the
defaults and the operator control.
"""

import json

import boto3
import botocore.client
import botocore.exceptions
import pytest
from typer.testing import CliRunner

from automated_security_helper.plugin_modules.ash_aws_plugins.security_hub_reporter import (
    SecurityHubReporter,
)
from tests.utils.secret_bearing_scan import isolate_from_aws

AWS_PLUGIN_MODULE = "automated_security_helper.plugin_modules.ash_aws_plugins"

ENABLE_SECURITY_HUB = f"""
ash_plugin_modules:
  - {AWS_PLUGIN_MODULE}
reporters:
  aws-security-hub:
    enabled: true
    options:
      aws_region: us-east-1
      aws_profile: null
      account_id: "123456789012"
"""


@pytest.fixture
def requests(monkeypatch, tmp_path):
    """Every botocore request made, each refused."""
    isolate_from_aws(monkeypatch, tmp_path)
    made = []

    def refusing_request(client, operation_name, api_params):
        made.append((client.meta.service_model.service_name, operation_name))
        raise botocore.exceptions.ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "refused by the test"}},
            operation_name,
        )

    monkeypatch.setattr(botocore.client.BaseClient, "_make_api_call", refusing_request)
    return made


@pytest.fixture
def sessions(monkeypatch):
    made = []
    real_session = boto3.Session

    def recording_session(*args, **kwargs):
        made.append(kwargs)
        return real_session(*args, **kwargs)

    monkeypatch.setattr(boto3, "Session", recording_session)
    return made


@pytest.fixture
def security_hub_runs(monkeypatch):
    ran = []
    original = SecurityHubReporter.report

    def recording_report(self, model):
        ran.append(type(self).__name__)
        return original(self, model)

    monkeypatch.setattr(SecurityHubReporter, "report", recording_report)
    return ran


def _source_tree(root):
    source_dir = root / "src"
    source_dir.mkdir(parents=True, exist_ok=True)
    (source_dir / "app.py").write_text("value = 1\n", encoding="utf-8")
    return source_dir


def _operator_config(root):
    path = root / "operator" / "ash.yaml"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(ENABLE_SECURITY_HUB, encoding="utf-8")
    return path


def _stored_results(output_dir):
    from automated_security_helper.config.default_config import get_default_config
    from automated_security_helper.models.asharp_model import AshAggregatedResults

    output_dir.mkdir(parents=True, exist_ok=True)
    stored = AshAggregatedResults()
    stored.ash_config = get_default_config()
    (output_dir / "ash_aggregated_results.json").write_text(
        stored.model_dump_json(by_alias=True), encoding="utf-8"
    )


class TestAScanChecksOnlyTheReportersItUses:
    def test_an_enabled_cloud_reporter_is_not_checked_when_other_formats_are_asked_for(
        self, tmp_path, requests, sessions, security_hub_runs
    ):
        from automated_security_helper.interactions.run_ash_scan import run_ash_scan

        output_dir = tmp_path / "out"
        run_ash_scan(
            source_dir=str(_source_tree(tmp_path)),
            output_dir=str(output_dir),
            config=str(_operator_config(tmp_path)),
            scanners=["detect-secrets"],
            output_formats=["sarif"],
            offline=True,
            progress=False,
            quiet=True,
            show_summary=False,
            fail_on_findings=False,
            color=False,
        )

        assert (output_dir / "reports" / "ash.sarif").exists()
        assert requests == []
        assert sessions == []
        assert security_hub_runs == []

    def test_the_same_reporter_is_checked_when_no_formats_are_asked_for(
        self, tmp_path, requests, sessions, security_hub_runs
    ):
        """Control: with every enabled reporter selected, its check runs."""
        from automated_security_helper.interactions.run_ash_scan import run_ash_scan

        run_ash_scan(
            source_dir=str(_source_tree(tmp_path)),
            output_dir=str(tmp_path / "out"),
            config=str(_operator_config(tmp_path)),
            scanners=["detect-secrets"],
            offline=True,
            progress=False,
            quiet=True,
            show_summary=False,
            fail_on_findings=False,
            color=False,
        )

        assert ("securityhub", "DescribeHub") in requests


class TestReportCommand:
    def _report(self, output_dir, *extra, report_format="aws-security-hub"):
        from automated_security_helper.cli.main import app

        return CliRunner().invoke(
            app,
            [
                "report",
                "--format",
                report_format,
                "--output-dir",
                str(output_dir),
                "--log-level",
                "ERROR",
                "--no-color",
                *extra,
            ],
        )

    def test_a_cloud_reporter_the_operator_did_not_enable_is_refused(
        self, tmp_path, requests, sessions, security_hub_runs
    ):
        output_dir = tmp_path / "out"
        _stored_results(output_dir)

        result = self._report(output_dir)

        assert result.exit_code == 1, result.output
        # rich wraps the message at the console width; compare it with the line
        # breaks and runs of spaces collapsed to one space.
        assert "not enabled" in " ".join(result.output.split())
        assert security_hub_runs == []
        assert requests == []
        assert sessions == []

    def test_a_cloud_reporter_the_operator_enabled_runs(
        self, tmp_path, requests, security_hub_runs
    ):
        """Control: the operator's override turns it on."""
        output_dir = tmp_path / "out"
        _stored_results(output_dir)

        result = self._report(
            output_dir,
            "--config-overrides",
            "reporters.aws-security-hub.enabled=true",
        )

        assert result.exit_code == 0, result.output
        assert security_hub_runs == ["SecurityHubReporter"]
        assert json.loads(result.output)["findings_count"] == 0

    def _s3_operator_config(self, root, enabled_line=""):
        """An operator config with every option S3 needs to upload, and ``enabled_line``."""
        path = root / "operator" / "ash-s3.yaml"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            "ash_plugin_modules:\n"
            f"  - {AWS_PLUGIN_MODULE}\n"
            "reporters:\n"
            "  s3:\n"
            f"{enabled_line}"
            "    options:\n"
            "      bucket_name: b\n"
            "      aws_region: us-east-1\n"
            "      max_retries: 0\n",
            encoding="utf-8",
        )
        return path

    @pytest.mark.parametrize(
        "enabled_line",
        ["", "    enabled: false\n"],
        ids=["no-enabled-key", "enabled-false"],
    )
    def test_an_s3_section_that_does_not_enable_it_is_refused(
        self, tmp_path, requests, sessions, enabled_line
    ):
        """Complete options are not enough: only ``enabled: true`` lets it upload."""
        output_dir = tmp_path / "out"
        _stored_results(output_dir)
        config = self._s3_operator_config(tmp_path, enabled_line)

        result = self._report(output_dir, "--config", str(config), report_format="s3")

        assert result.exit_code == 1, result.output
        assert "not enabled" in " ".join(result.output.split())
        assert requests == []
        assert sessions == []

    def test_an_s3_section_that_enables_it_reaches_put_object(self, tmp_path, requests):
        """Control: the same options with ``enabled: true`` get as far as PutObject.

        Called directly rather than through CliRunner: the refused upload logs an
        error, and a record pytest's live logging writes during an invoke swaps
        sys.stdout under CliRunner, which then fails reading its own closed
        output stream.
        """
        import typer

        from automated_security_helper.cli.report import report_command
        from automated_security_helper.core.enums import AshLogLevel

        output_dir = tmp_path / "out"
        _stored_results(output_dir)
        config = self._s3_operator_config(tmp_path, "    enabled: true\n")

        # The refused upload leaves the reporter with no receipt, so the
        # command exits 1 after the attempt.
        with pytest.raises(typer.Exit):
            report_command(
                report_format="s3",
                output_dir=str(output_dir),
                log_level=AshLogLevel.ERROR,
                config=str(config),
                config_overrides=None,
                verbose=False,
                debug=False,
                color=False,
            )

        assert ("s3", "PutObject") in requests


class TestWorkspaceReporting:
    def test_a_per_project_reporter_is_not_checked_at_workspace_level(
        self, tmp_path, requests, sessions
    ):
        from automated_security_helper.base.plugin_context import PluginContext
        from automated_security_helper.config.ash_config import AshConfig
        from automated_security_helper.workspace.reporting import (
            _selected_reporters,
        )

        checked = []

        class _EnabledSecurityHub(SecurityHubReporter):
            def validate_plugin_dependencies(self):
                checked.append(type(self).__name__)
                return super().validate_plugin_dependencies()

        context = PluginContext(
            source_dir=tmp_path,
            output_dir=tmp_path / "out",
            work_dir=tmp_path / "out" / "work",
            config=AshConfig(),
        )

        selected = list(
            _selected_reporters(
                context=context,
                config_lookup=lambda key: {
                    "enabled": True,
                    "options": {"aws_region": "us-east-1"},
                },
                output_formats=[],
                python_based_plugins_only=False,
                reporter_classes=[_EnabledSecurityHub],
            )
        )

        assert [skipped for _, _, skipped in selected] == [None]
        assert checked == []
        assert requests == []
        assert sessions == []
