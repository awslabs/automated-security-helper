# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""A cloud reporter's section that sets options but not ``enabled`` is named once.

The S3, CloudWatch Logs, Security Hub and Bedrock summary reporters now ship
``enabled: false``. A config written for an earlier release set their options
and relied on the reporter's default, so it now uploads nothing, and nothing
said so. Each run now logs one WARNING per such reporter, naming the reporter and
the key that turns it on. The warning changes nothing: the reporter still does
not run, and the option values (bucket names, account ids) are not logged.

Every test runs with no usable ``AWS_*`` credentials and botocore's request
method replaced by a recorder that refuses every request, so nothing here can
reach AWS.
"""

import logging

import boto3
import botocore.client
import botocore.exceptions
import pytest

from automated_security_helper.utils.log import ASH_LOGGER
from tests.utils.secret_bearing_scan import isolate_from_aws

AWS_PLUGIN_MODULE = "automated_security_helper.plugin_modules.ash_aws_plugins"

#: Option values that must never appear in a warning.
BUCKET = "probe-bucket-4c1e"
PREFIX = "arn:aws:s3:::probe-prefix-4c1e/"
ACCOUNT = "000000000001"
LOG_GROUP = "probe-log-group-4c1e"

#: For each reporter that ships off, a section that sets one option and no
#: ``enabled``: what a config written for an earlier release looks like.
OPTIONS_ONLY = {
    "s3": f"    options:\n      bucket_name: {BUCKET}\n",
    "cloudwatch-logs": f"    options:\n      log_group_name: {LOG_GROUP}\n",
    "aws-security-hub": f'    options:\n      account_id: "{ACCOUNT}"\n',
    "bedrock-summary-reporter": "    options:\n      aws_region: us-west-2\n",
}


@pytest.fixture(autouse=True)
def _fresh_warnings():
    """Each test starts with no reporter already warned about in this process."""
    from automated_security_helper.base.reporter_plugin import (
        reset_unenabled_off_host_section_warnings,
    )

    reset_unenabled_off_host_section_warnings()
    yield
    reset_unenabled_off_host_section_warnings()


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
        made.append(sorted(kwargs))
        return real_session(*args, **kwargs)

    monkeypatch.setattr(boto3, "Session", recording_session)
    return made


@pytest.fixture
def warnings_logged():
    """The messages ASH logs at WARNING or above while the test runs.

    Collected by a filter on the logger, not a handler: a scan sets the logger up
    again (``utils.log.get_logger``), which drops every handler it had but keeps
    its filters.
    """
    records = []

    class _Collect(logging.Filter):
        def filter(self, record):
            if record.levelno >= logging.WARNING:
                records.append(record.getMessage())
            return True

    collect = _Collect()
    ASH_LOGGER.addFilter(collect)
    try:
        yield records
    finally:
        ASH_LOGGER.removeFilter(collect)


def _about(key, messages):
    """The warnings that tell the operator to set ``reporters.<key>.enabled``."""
    return [m for m in messages if f"reporters.{key}.enabled" in m]


def _source_tree(root):
    source_dir = root / "src"
    source_dir.mkdir(parents=True, exist_ok=True)
    (source_dir / "app.py").write_text("value = 1\n", encoding="utf-8")
    return source_dir


def _operator_config(root, reporters_yaml):
    path = root / "operator" / "ash.yaml"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        f"ash_plugin_modules:\n  - {AWS_PLUGIN_MODULE}\nreporters:\n{reporters_yaml}",
        encoding="utf-8",
    )
    return path


def _section(key, enabled_line="", options=None):
    options = OPTIONS_ONLY[key] if options is None else options
    return f"  {key}:\n{enabled_line}{options}"


def _scan(root, config=None, **kwargs):
    from automated_security_helper.interactions.run_ash_scan import run_ash_scan

    run_ash_scan(
        source_dir=str(kwargs.pop("source_dir", None) or _source_tree(root)),
        output_dir=str(root / "out"),
        config=str(config) if config else None,
        scanners=["detect-secrets"],
        offline=True,
        progress=False,
        quiet=True,
        show_summary=False,
        fail_on_findings=False,
        color=False,
        **kwargs,
    )


@pytest.mark.integration
class TestASectionWithOptionsButNoEnabled:
    @pytest.mark.parametrize("key", sorted(OPTIONS_ONLY))
    def test_is_named_once_and_sends_nothing(
        self, tmp_path, requests, sessions, warnings_logged, key
    ):
        _scan(tmp_path, _operator_config(tmp_path, _section(key)))

        assert requests == []
        assert sessions == []
        named = _about(key, warnings_logged)
        assert len(named) == 1, warnings_logged
        assert f"reporters.{key}.enabled: true" in named[0]
        assert f"--config-overrides reporters.{key}.enabled=true" in named[0]

    def test_the_warning_names_no_option_value(
        self, tmp_path, requests, warnings_logged
    ):
        options = (
            "    options:\n"
            f"      bucket_name: {BUCKET}\n"
            f"      key_prefix: {PREFIX}\n"
            "      aws_region: us-east-1\n"
        )
        _scan(tmp_path, _operator_config(tmp_path, _section("s3", options=options)))

        assert len(_about("s3", warnings_logged)) == 1, warnings_logged
        logged = "\n".join(warnings_logged)
        for value in (BUCKET, PREFIX, "probe-prefix-4c1e"):
            assert value not in logged

    def test_options_set_with_config_overrides_are_named_too(
        self, tmp_path, requests, warnings_logged
    ):
        _scan(
            tmp_path,
            config_overrides=[f"reporters.s3.options.bucket_name={BUCKET}"],
            ash_plugin_modules=[AWS_PLUGIN_MODULE],
        )

        assert requests == []
        assert len(_about("s3", warnings_logged)) == 1, warnings_logged

    def test_a_repository_config_is_named_and_turns_nothing_on(
        self, tmp_path, requests, sessions, warnings_logged
    ):
        """The section in the scanned repository's own config enables nothing.

        Its options do not reach the report phase: the operator's settings replace
        them, with a warning naming each key it ignored. So nothing is sent, and no
        warning tells the operator to turn on a section only the repository wrote.
        """
        source_dir = _source_tree(tmp_path)
        repo_config = source_dir / ".ash" / ".ash.yaml"
        repo_config.parent.mkdir(parents=True, exist_ok=True)
        repo_config.write_text(f"reporters:\n{_section('s3')}", encoding="utf-8")

        _scan(
            tmp_path,
            source_dir=source_dir,
            ash_plugin_modules=[AWS_PLUGIN_MODULE],
        )

        assert requests == []
        assert sessions == []
        assert _about("s3", warnings_logged) == []
        assert any("reporters.s3.options.bucket_name" in m for m in warnings_logged)
        assert not any(BUCKET in message for message in warnings_logged)

    def test_formats_that_leave_the_reporter_out_name_nothing(
        self, tmp_path, requests, warnings_logged
    ):
        """With ``-f sarif`` the reporter does not run whatever ``enabled`` says,
        so there is nothing to tell the operator to set."""
        _scan(
            tmp_path,
            _operator_config(tmp_path, _section("s3")),
            output_formats=["sarif"],
        )

        assert requests == []
        assert _about("s3", warnings_logged) == []


@pytest.mark.integration
class TestNoWarning:
    def test_when_enabled_is_true_and_the_reporter_runs(
        self, tmp_path, monkeypatch, requests, warnings_logged
    ):
        """Control: ``enabled: true`` with the same kind of section uploads.

        The stub answers the dependency check (GetCallerIdentity, HeadBucket), so
        the reporter gets as far as its upload, which is refused like every other
        request.
        """
        refusing = botocore.client.BaseClient._make_api_call
        answers = {
            "GetCallerIdentity": {"Account": ACCOUNT, "Arn": "a", "UserId": "u"},
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
        options = (
            "    options:\n"
            f"      bucket_name: {BUCKET}\n"
            "      aws_region: us-east-1\n"
            "      max_retries: 0\n"
        )
        _scan(
            tmp_path,
            _operator_config(
                tmp_path, _section("s3", "    enabled: true\n", options=options)
            ),
        )

        assert ("s3", "PutObject") in requests
        assert _about("s3", warnings_logged) == []

    @pytest.mark.parametrize("key", sorted(OPTIONS_ONLY))
    def test_when_enabled_is_false(self, tmp_path, requests, warnings_logged, key):
        _scan(
            tmp_path,
            _operator_config(tmp_path, _section(key, "    enabled: false\n")),
        )

        assert requests == []
        assert _about(key, warnings_logged) == []

    def test_when_there_is_no_section(self, tmp_path, requests, warnings_logged):
        _scan(tmp_path, ash_plugin_modules=[AWS_PLUGIN_MODULE])

        assert requests == []
        assert [m for m in warnings_logged if ".enabled" in m] == []


@pytest.mark.integration
class TestAWorkspaceRun:
    def test_names_the_reporter_once_for_every_project(
        self, tmp_path, requests, sessions, warnings_logged
    ):
        """Each project's report phase reads the same section; one warning says so.

        The operator's config is outside the workspace, as an operator's is: one
        inside the scanned tree is the repository's, and its AWS settings are ignored.
        """
        from automated_security_helper.workspace.plan import ProjectPlan, WorkspacePlan

        workspace_root = tmp_path / "ws"
        projects = []
        for key in ("api", "web"):
            project_dir = workspace_root / key
            project_dir.mkdir(parents=True)
            (project_dir / "app.py").write_text("value = 1\n", encoding="utf-8")
            projects.append(
                ProjectPlan(
                    key=key,
                    relative_path=key,
                    path=project_dir.as_posix(),
                    label=key,
                    display_label=key,
                    severity_threshold="LOW",
                )
            )
        plan = WorkspacePlan(
            workspace_file=(workspace_root / "dev.code-workspace").as_posix(),
            workspace_root=workspace_root.as_posix(),
            projects=projects,
        )

        _scan(
            tmp_path,
            _operator_config(tmp_path / "op", _section("s3")),
            source_dir=workspace_root,
            workspace_plan=plan,
        )

        assert requests == []
        assert sessions == []
        assert len(_about("s3", warnings_logged)) == 1, warnings_logged


@pytest.mark.unit
class TestMerge:
    def _merge(self, tmp_path, config, overrides=None):
        import typer

        from automated_security_helper.cli.merge import merge_command
        from automated_security_helper.core.enums import AshLogLevel
        from tests.unit.cli.test_merge import build_shards, write_shards

        paths = write_shards(tmp_path / "artifacts", build_shards(2))
        try:
            merge_command(
                results=paths,
                output_dir=str(tmp_path / "merged"),
                output_formats=None,
                min_severity="low",
                ignore_suppressions=False,
                fail_on_findings=False,
                fail_on_incomplete_scanners=None,
                config=str(config),
                config_overrides=overrides,
                log_level=AshLogLevel.ERROR,
                verbose=False,
                debug=False,
                color=False,
            )
        except typer.Exit:
            pass

    def test_the_operators_overrides_without_enabled_are_named(
        self, tmp_path, requests, sessions, warnings_logged
    ):
        """Overrides that aim S3 and do not enable it: the warning names the key."""
        plugin_only = tmp_path / "operator" / "plugins.yaml"
        plugin_only.parent.mkdir(parents=True, exist_ok=True)
        plugin_only.write_text(
            f"ash_plugin_modules:\n  - {AWS_PLUGIN_MODULE}\n", encoding="utf-8"
        )

        self._merge(
            tmp_path,
            plugin_only,
            overrides=[
                f"reporters.s3.options.bucket_name={BUCKET}",
                "reporters.s3.options.aws_region=us-east-1",
            ],
        )

        assert requests == []
        assert sessions == []
        named = _about("s3", warnings_logged)
        assert len(named) == 1, warnings_logged
        assert BUCKET not in named[0]

    def test_a_config_file_section_is_named_as_not_the_operators(
        self, tmp_path, requests, sessions, warnings_logged
    ):
        """A --config file's S3 options are ignored, and the warning names the override.

        ``ash merge`` takes an off-host reporter's ``enabled`` and destination from
        ``--config-overrides`` only (the shards do not record which tree was
        scanned), so the file's section is named in that warning, by key and not
        by value, rather than in the one about a missing ``enabled``.
        """
        self._merge(tmp_path, _operator_config(tmp_path, _section("s3")))

        assert requests == []
        assert sessions == []
        assert _about("s3", warnings_logged) == []
        named = [
            m
            for m in warnings_logged
            if m.startswith("Ignoring")
            and "reporters.s3.options.bucket_name" in m
            and "--config-overrides" in m
        ]
        assert len(named) == 1, warnings_logged
        assert BUCKET not in named[0]

    def test_the_operators_enabled_false_is_not(
        self, tmp_path, requests, warnings_logged
    ):
        self._merge(
            tmp_path,
            _operator_config(tmp_path, _section("s3", "    enabled: false\n")),
        )

        assert requests == []
        assert _about("s3", warnings_logged) == []
