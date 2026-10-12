# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""``ash report`` takes an off-host reporter's ``enabled`` and destination from the operator's overrides.

Stored results do not record which tree they were scanned from. A config file
``ash report`` reads (``--config``, or ``ASH_CONFIG``) may be that tree's own
``.ash/.ash.yaml``, and when the tree is neither a git checkout nor under the
working directory nothing marks it as the repository's: a CI job that scans a
directory and then runs ``ash report --format s3 --config <tree>/.ash/.ash.yaml``
from elsewhere uploaded the findings to the bucket the repository chose.

So in ``ash report`` a config file's ``enabled`` and destination options of the
reporters that send findings off the host (``config/reporter_trust.py``) are
replaced with the defaults and ``--config-overrides``, with a warning naming
what was ignored and the override that sets it. The file's other settings, such
as a local reporter's options, still apply.

Every test runs with no ``AWS_*`` credentials, a loopback endpoint and botocore's
request method replaced by a recorder, which answers the S3 reporter's
dependency check (``GetCallerIdentity``, ``HeadBucket``) so that a reporter that
runs gets as far as ``PutObject``, and refuses every other request.
"""

import logging
from pathlib import Path
from typing import List, NamedTuple, Optional

import boto3
import botocore.client
import botocore.exceptions
import pytest
import typer

from automated_security_helper.utils.log import ASH_LOGGER
from tests.utils.secret_bearing_scan import isolate_from_aws

AWS_PLUGIN_MODULE = "automated_security_helper.plugin_modules.ash_aws_plugins"


class Request(NamedTuple):
    service: str
    operation: str
    region: Optional[str]
    bucket: Optional[str]


@pytest.fixture
def requests(monkeypatch, tmp_path) -> List[Request]:
    """Every botocore request made; the S3 dependency check answered, the rest refused."""
    isolate_from_aws(monkeypatch, tmp_path)
    made: List[Request] = []
    answers = {
        ("sts", "GetCallerIdentity"): {
            "Account": "123456789012",
            "Arn": "arn:aws:iam::123456789012:user/operator",
            "UserId": "operator",
        },
        ("s3", "HeadBucket"): {},
    }

    def recording_request(client, operation_name, api_params):
        service = client.meta.service_model.service_name
        made.append(
            Request(
                service,
                operation_name,
                client.meta.region_name,
                api_params.get("Bucket") if isinstance(api_params, dict) else None,
            )
        )
        if (service, operation_name) in answers:
            return dict(answers[(service, operation_name)])
        raise botocore.exceptions.ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "refused by the test"}},
            operation_name,
        )

    monkeypatch.setattr(botocore.client.BaseClient, "_make_api_call", recording_request)
    return made


@pytest.fixture
def sessions(monkeypatch) -> List[dict]:
    """The keyword arguments of every boto3 session built."""
    made: List[dict] = []
    real_session = boto3.Session

    def recording_session(*args, **kwargs):
        made.append(kwargs)
        return real_session(*args, **kwargs)

    monkeypatch.setattr(boto3, "Session", recording_session)
    return made


@pytest.fixture
def warnings_logged():
    """The messages ASH logs at WARNING or above while the test runs.

    Collected by a filter on the logger, not a handler: the command sets the
    logger up again (``utils.log.get_logger``), which drops every handler it had
    but keeps its filters.
    """
    records: List[str] = []

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


def _s3_section(bucket: str, region: str, enabled: bool = True) -> str:
    return (
        "reporters:\n"
        "  s3:\n"
        f"    enabled: {'true' if enabled else 'false'}\n"
        "    options:\n"
        f"      bucket_name: {bucket}\n"
        f"      aws_region: {region}\n"
        "      max_retries: 0\n"
    )


def _module_list() -> str:
    return f"ash_plugin_modules:\n  - {AWS_PLUGIN_MODULE}\n"


def _outside_every_checkout(path: Path) -> None:
    """Precondition: no directory holding ``path`` is a git checkout.

    Inside one, the file would be held to the repository's rules for that reason
    alone, and a test of the case nothing else marks would pass vacuously.
    """
    holding = [path, *path.parents]
    assert not any((p / ".git").exists() for p in holding), holding


def _layout(tmp_path: Path, tree_config: str) -> tuple:
    """A scanned tree that is not a git checkout, beside the report's working directory.

    Returns (working directory, the tree's config file, output directory with
    stored results of a scan).
    """
    from automated_security_helper.config.default_config import get_default_config
    from automated_security_helper.models.asharp_model import AshAggregatedResults

    tree = tmp_path / "data" / "src"
    (tree / ".ash").mkdir(parents=True)
    (tree / "app.py").write_text("value = 1\n", encoding="utf-8")
    tree_file = tree / ".ash" / ".ash.yaml"
    tree_file.write_text(tree_config, encoding="utf-8")
    _outside_every_checkout(tree_file)

    work = tmp_path / "work"
    output_dir = work / ".ash" / "ash_output"
    output_dir.mkdir(parents=True)
    stored = AshAggregatedResults()
    stored.ash_config = get_default_config()
    (output_dir / "ash_aggregated_results.json").write_text(
        stored.model_dump_json(by_alias=True), encoding="utf-8"
    )
    return work, tree_file, output_dir


def _report(
    report_format: str,
    output_dir: Path,
    config: Optional[str] = None,
    overrides: Optional[List[str]] = None,
) -> int:
    """Run ``ash report`` in this process and return its exit code.

    Called directly rather than through CliRunner: a refused upload logs an error,
    and a record pytest's live logging writes during an invoke swaps sys.stdout
    under CliRunner, which then fails reading its own closed output stream.
    """
    from automated_security_helper.cli.report import report_command
    from automated_security_helper.core.enums import AshLogLevel

    try:
        report_command(
            report_format=report_format,
            output_dir=str(output_dir),
            # INFO, so the warnings reach the logger's filters.
            log_level=AshLogLevel.INFO,
            config=config,
            config_overrides=overrides,
            verbose=False,
            debug=False,
            color=False,
        )
    except typer.Exit as exit_:
        return int(exit_.exit_code)
    return 0


def _ignored(key: str, messages: List[str]) -> List[str]:
    return [
        message
        for message in messages
        if message.startswith("Ignoring")
        and key in message
        and "--config-overrides" in message
    ]


class TestAConfigFileDoesNotTurnAnOffHostReporterOn:
    @pytest.mark.parametrize(
        "module_from",
        ["the-tree-config", "an-operator-override"],
    )
    def test_the_scanned_trees_config_sends_nothing(
        self, tmp_path, monkeypatch, requests, sessions, warnings_logged, module_from
    ):
        """CI's shape: a scan of a directory, then ``ash report`` from another one."""
        tree_config = _s3_section("repository-bucket", "eu-west-1")
        overrides = None
        if module_from == "the-tree-config":
            tree_config = _module_list() + tree_config
        else:
            overrides = [f"ash_plugin_modules=[{AWS_PLUGIN_MODULE}]"]
        work, _, output_dir = _layout(tmp_path, tree_config)
        monkeypatch.chdir(work)

        code = _report(
            "s3", output_dir, config="../data/src/.ash/.ash.yaml", overrides=overrides
        )

        assert code == 1
        assert requests == [], requests
        assert sessions == [], sessions
        assert _ignored("reporters.s3.enabled", warnings_logged), warnings_logged

    def test_ash_config_naming_the_trees_file_sends_nothing(
        self, tmp_path, monkeypatch, requests, sessions, warnings_logged
    ):
        """``ASH_CONFIG`` is the same choice as ``--config``."""
        work, tree_file, output_dir = _layout(
            tmp_path, _module_list() + _s3_section("repository-bucket", "eu-west-1")
        )
        monkeypatch.chdir(work)
        monkeypatch.setenv("ASH_CONFIG", str(tree_file))

        code = _report("s3", output_dir)

        assert code == 1
        assert requests == [], requests
        assert sessions == [], sessions
        assert _ignored("reporters.s3.enabled", warnings_logged), warnings_logged

    def test_a_file_outside_every_tree_does_not_turn_it_on_either(
        self, tmp_path, monkeypatch, requests, sessions, warnings_logged
    ):
        """An operator's file and the tree's look the same to ``ash report``.

        It may not be the repository's, but stored results cannot say which tree
        was scanned, so it is held to the same rule; the warning names the
        override that turns the reporter on.
        """
        work, _, output_dir = _layout(tmp_path, "")
        operator_file = tmp_path / "ops" / "ash.yaml"
        operator_file.parent.mkdir()
        operator_file.write_text(
            _module_list() + _s3_section("operator-bucket", "us-west-2"),
            encoding="utf-8",
        )
        _outside_every_checkout(operator_file)
        monkeypatch.chdir(work)

        code = _report("s3", output_dir, config=str(operator_file))

        assert code == 1
        assert requests == [], requests
        assert sessions == [], sessions
        assert _ignored("reporters.s3.enabled", warnings_logged), warnings_logged


class TestTheOperatorsOverridesStillDecide:
    def test_overrides_turn_it_on_and_aim_it_past_the_files_values(
        self, tmp_path, monkeypatch, requests
    ):
        """Control: the overrides send it, to the operator's bucket and region."""
        work, _, output_dir = _layout(
            tmp_path, _module_list() + _s3_section("repository-bucket", "eu-west-1")
        )
        monkeypatch.chdir(work)

        # The refused upload leaves the reporter with no receipt: exit 1 after it.
        _report(
            "s3",
            output_dir,
            config="../data/src/.ash/.ash.yaml",
            overrides=[
                "reporters.s3.enabled=true",
                "reporters.s3.options.bucket_name=operator-bucket",
                "reporters.s3.options.aws_region=us-west-2",
                "reporters.s3.options.max_retries=0",
            ],
        )

        puts = [r for r in requests if (r.service, r.operation) == ("s3", "PutObject")]
        assert puts == [Request("s3", "PutObject", "us-west-2", "operator-bucket")], (
            requests
        )
        assert all(r.bucket in (None, "operator-bucket") for r in requests), requests
        assert all(r.region == "us-west-2" for r in requests), requests

    @pytest.mark.parametrize(
        "tree_option, summary_shown",
        [("", True), ("    options:\n      include_summary: false\n", False)],
        ids=["default", "summary-off"],
    )
    def test_a_local_reporters_setting_from_the_file_still_applies(
        self, tmp_path, monkeypatch, capsys, requests, tree_option, summary_shown
    ):
        """Only off-host reporters' settings are held back; the text report's are not."""
        tree_config = "reporters:\n  text:\n    enabled: true\n" + tree_option
        work, _, output_dir = _layout(tmp_path, tree_config)
        monkeypatch.chdir(work)

        code = _report("text", output_dir, config="../data/src/.ash/.ash.yaml")

        assert code == 0
        assert ("SUMMARY" in capsys.readouterr().out) is summary_shown
        assert requests == []
