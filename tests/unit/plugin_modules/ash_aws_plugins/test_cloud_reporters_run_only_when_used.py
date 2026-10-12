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


#: For each reporter that defaults to off, an operator section with every option
#: its dependency check needs, so the only thing keeping it from contacting AWS
#: is ``enabled``. The request each check makes first is the control.
COMPLETE_SECTIONS = {
    "s3": (
        (
            "    options:\n"
            "      bucket_name: b\n"
            "      aws_region: us-east-1\n"
            "      max_retries: 0\n"
        ),
        ("sts", "GetCallerIdentity"),
    ),
    "cloudwatch-logs": (
        (
            "    options:\n"
            "      aws_region: us-east-1\n"
            "      log_group_name: g\n"
            "      max_retries: 0\n"
        ),
        ("sts", "GetCallerIdentity"),
    ),
    "aws-security-hub": (
        (
            '    options:\n      aws_region: us-east-1\n      account_id: "123456789012"\n'
        ),
        ("securityhub", "DescribeHub"),
    ),
}


class TestACompleteSectionWithoutEnabledContactsNothing:
    """Options alone do not turn a cloud reporter on; its ``enabled`` default does not either."""

    def _scan(self, root, name, enabled_line):
        from automated_security_helper.interactions.run_ash_scan import run_ash_scan

        options, _ = COMPLETE_SECTIONS[name]
        config = root / "operator" / "ash.yaml"
        config.parent.mkdir(parents=True, exist_ok=True)
        config.write_text(
            "ash_plugin_modules:\n"
            f"  - {AWS_PLUGIN_MODULE}\n"
            "reporters:\n"
            f"  {name}:\n"
            f"{enabled_line}"
            f"{options}",
            encoding="utf-8",
        )
        run_ash_scan(
            source_dir=str(_source_tree(root)),
            output_dir=str(root / "out"),
            config=str(config),
            scanners=["detect-secrets"],
            offline=True,
            progress=False,
            quiet=True,
            show_summary=False,
            fail_on_findings=False,
            color=False,
        )

    @pytest.mark.parametrize("guards", ["both", "default-only"])
    @pytest.mark.parametrize("name", sorted(COMPLETE_SECTIONS))
    def test_a_section_with_every_option_but_enabled_contacts_nothing(
        self, tmp_path, monkeypatch, requests, sessions, name, guards
    ):
        """Two things keep it off: its ``enabled: false`` default, and the rule that
        an off-host reporter runs only when its section enables it. With
        ``default-only`` the rule is switched off, so the default is checked on
        its own rather than hidden behind the rule.
        """
        if guards == "default-only":
            monkeypatch.setattr(
                "automated_security_helper.core.phases.report_phase."
                "off_host_reporter_refused",
                lambda reporter_class, plugin_config: False,
            )

        self._scan(tmp_path, name, "")

        assert requests == []
        assert sessions == []

    @pytest.mark.parametrize("name", sorted(COMPLETE_SECTIONS))
    def test_the_same_section_with_enabled_true_reaches_aws(
        self, tmp_path, requests, name
    ):
        """Control: the options are enough for the check to make its request."""
        self._scan(tmp_path, name, "    enabled: true\n")

        assert COMPLETE_SECTIONS[name][1] in requests


def _aws_reporter_configs():
    from automated_security_helper.plugin_modules.ash_aws_plugins.bedrock_summary_reporter import (
        BedrockSummaryReporterConfig,
    )
    from automated_security_helper.plugin_modules.ash_aws_plugins.cloudwatch_logs_reporter import (
        CloudWatchLogsReporterConfig,
    )
    from automated_security_helper.plugin_modules.ash_aws_plugins.s3_reporter import (
        S3ReporterConfig,
    )
    from automated_security_helper.plugin_modules.ash_aws_plugins.security_hub_reporter import (
        SecurityHubReporterConfig,
    )

    return [
        BedrockSummaryReporterConfig,
        CloudWatchLogsReporterConfig,
        S3ReporterConfig,
        SecurityHubReporterConfig,
    ]


@pytest.mark.parametrize(
    "config_class", _aws_reporter_configs(), ids=lambda cls: cls.__name__
)
def test_every_aws_reporter_ships_disabled(config_class):
    assert config_class().enabled is False


class TestTheEnvironmentIsReadWhenAConfigIsBuilt:
    """A reporter's region and profile come from the environment of the run, not of the import.

    Reading them when the module was imported fixed whatever ``AWS_REGION`` and
    ``AWS_PROFILE`` the importing process had for every later config: a test
    that removes them, or an MCP server whose environment changes, still saw the
    old values.
    """

    @pytest.mark.parametrize(
        "config_class", _aws_reporter_configs(), ids=lambda cls: cls.__name__
    )
    def test_region_and_profile_follow_the_environment(self, monkeypatch, config_class):
        for name in ("AWS_REGION", "AWS_DEFAULT_REGION", "AWS_PROFILE"):
            monkeypatch.delenv(name, raising=False)
        monkeypatch.setenv("AWS_REGION", "eu-west-2")
        monkeypatch.setenv("AWS_PROFILE", "profile-read-at-construction")

        # CloudWatch Logs has no profile option.
        has_profile = "aws_profile" in type(config_class().options).model_fields

        options = config_class().options

        assert options.aws_region == "eu-west-2"
        if has_profile:
            assert options.aws_profile == "profile-read-at-construction"

        monkeypatch.setenv("AWS_REGION", "ap-south-1")
        monkeypatch.delenv("AWS_PROFILE")

        options = config_class().options

        assert options.aws_region == "ap-south-1"
        if has_profile:
            assert options.aws_profile is None


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

    @staticmethod
    def _plugin_config(root):
        """An operator config that names the AWS plugin module and sets nothing else.

        ``ash report`` loads the plugin modules the config names, as a scan does,
        so without one the AWS reporters are not there to refuse or run.
        """
        path = root / "operator" / "ash-aws.yaml"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            f"ash_plugin_modules:\n  - {AWS_PLUGIN_MODULE}\n", encoding="utf-8"
        )
        return path

    def test_a_cloud_reporter_the_operator_did_not_enable_is_refused(
        self, tmp_path, requests, sessions, security_hub_runs
    ):
        output_dir = tmp_path / "out"
        _stored_results(output_dir)

        result = self._report(
            output_dir, "--config", str(self._plugin_config(tmp_path))
        )

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
            "--config",
            str(self._plugin_config(tmp_path)),
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


class TestMergeCommand:
    """``ash merge`` sends merged findings off the host only on the operator's ``--config``."""

    S3_SECTION = {
        "enabled": True,
        "options": {"bucket_name": "b", "aws_region": "us-east-1", "max_retries": 0},
    }

    def _merge(self, tmp_path, shard_reporters, config=None):
        import typer

        from automated_security_helper.cli.merge import merge_command
        from automated_security_helper.config.ash_config import AshConfig
        from automated_security_helper.core.enums import AshLogLevel
        from tests.unit.cli.test_merge import build_shards, write_shards

        shards = build_shards(2)
        for shard in shards:
            shard.ash_config.reporters = AshConfig.model_validate(
                {"reporters": shard_reporters}
            ).reporters
        paths = write_shards(tmp_path / "artifacts", shards)
        try:
            merge_command(
                results=paths,
                output_dir=str(tmp_path / "merged"),
                output_formats=None,
                min_severity="low",
                ignore_suppressions=False,
                fail_on_findings=False,
                fail_on_incomplete_scanners=None,
                config=str(config) if config else None,
                log_level=AshLogLevel.ERROR,
                verbose=False,
                debug=False,
                color=False,
            )
        except typer.Exit:
            pass

    def test_shards_that_enable_s3_send_nothing(self, tmp_path, requests, sessions):
        self._merge(tmp_path, {"s3": self.S3_SECTION})

        assert requests == []
        assert sessions == []

    def test_the_operators_config_that_enables_s3_reaches_put_object(
        self, tmp_path, monkeypatch, requests
    ):
        """Control: with the operator's --config enabling it, the upload is attempted.

        The stub answers the dependency check (GetCallerIdentity, HeadBucket), so
        the reporter gets as far as its upload, which is refused like every other
        request. The shards' ``enabled: false`` does not stop it.
        """
        refusing = botocore.client.BaseClient._make_api_call
        answers = {
            "GetCallerIdentity": {"Account": "123456789012", "Arn": "a", "UserId": "u"},
            "HeadBucket": {},
        }

        def answering_identity(client, operation_name, api_params):
            if operation_name in answers:
                requests.append(
                    (client.meta.service_model.service_name, operation_name)
                )
                return answers[operation_name]
            return refusing(client, operation_name, api_params)

        monkeypatch.setattr(
            botocore.client.BaseClient, "_make_api_call", answering_identity
        )
        config = TestReportCommand._s3_operator_config(
            None, tmp_path, "    enabled: true\n"
        )

        self._merge(tmp_path, {"s3": {"enabled": False}}, config=config)

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

    @pytest.mark.parametrize(
        "output_formats, expect_checked",
        [(["sarif"], False), (["aws-security-hub"], True)],
        ids=["not-requested", "requested"],
    )
    def test_a_workspace_reporter_is_checked_only_when_its_format_is_requested(
        self, tmp_path, requests, sessions, output_formats, expect_checked
    ):
        """The format filter comes before the dependency check.

        A reporter that emits a workspace-level artefact is checked at workspace
        level, but only once ``--output-format`` has selected it: the check can
        contact AWS, and a reporter the run will not use has no reason to.
        """
        from automated_security_helper.base.plugin_context import PluginContext
        from automated_security_helper.base.reporter_plugin import (
            ReporterWorkspaceBehaviour,
        )
        from automated_security_helper.config.ash_config import AshConfig
        from automated_security_helper.workspace.reporting import (
            SKIP_NOT_REQUESTED,
            _selected_reporters,
        )

        checked = []

        class _MergedSecurityHub(SecurityHubReporter):
            workspace_behaviour = ReporterWorkspaceBehaviour.MERGED

            def validate_plugin_dependencies(self):
                checked.append(type(self).__name__)
                self.dependencies_satisfied = True
                return True

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
                output_formats=output_formats,
                python_based_plugins_only=False,
                reporter_classes=[_MergedSecurityHub],
            )
        )

        skipped = [reason for _, _, reason in selected]
        if expect_checked:
            assert checked == ["_MergedSecurityHub"]
            assert skipped == [None]
        else:
            assert checked == []
            assert skipped == [SKIP_NOT_REQUESTED]
        assert requests == []
        assert sessions == []


def test_no_output_format_names_an_aws_reporter():
    """docs/content/docs/plugins/aws/index.md says `-f` never selects an AWS reporter.

    If an ExportFormat ever names one, `ash scan -f <it>` would run it, and that
    page, and the CHANGELOG entry for the default-off change, need rewriting.
    """
    from automated_security_helper.core.enums import ExportFormat

    aws_names = {config_class().name for config_class in _aws_reporter_configs()}

    assert aws_names == {
        "aws-security-hub",
        "bedrock-summary-reporter",
        "cloudwatch-logs",
        "s3",
    }
    assert aws_names.isdisjoint(member.value for member in ExportFormat)
