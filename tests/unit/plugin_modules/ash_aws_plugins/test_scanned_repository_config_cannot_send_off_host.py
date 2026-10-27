# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""A scanned repository's own config neither turns on nor aims the reporters that send findings off the host.

The S3, CloudWatch Logs and Security Hub reporters send findings to an AWS
destination with the host's credentials, so whether one runs, and where it
sends, is the operator's choice (``config/reporter_trust.py``). Each test scans a
git checkout whose ``.ash/.ash.yaml`` sets a cloud reporter's section, with the
AWS plugin module loaded by the operator and every destination the reporter
needs also available from the operator's environment, and checks that:

* the repository's ``enabled: true`` makes no AWS session, client or request,
  and the reporter is built but neither checked nor run, also when the operator
  enabled a different cloud reporter;
* when the operator enables the reporter, the region, bucket, log group or
  account the repository set are dropped, and every request carries the
  operator's;
* an operator config kept in a git checkout of its own (an ops repository),
  not the scanned one, still turns the reporter on and aims it.

botocore's request method is replaced by a recorder that answers the calls a
reporter makes on its way to sending (STS ``GetCallerIdentity``, S3
``HeadBucket`` and ``PutObject``, CloudWatch Logs ``CreateLogStream`` and
``PutLogEvents``, Security Hub ``DescribeHub``) and refuses any other, with no
credentials and a loopback endpoint, so nothing here can reach AWS.
"""

import logging
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, NamedTuple, Optional, Tuple

import boto3
import botocore.client
import botocore.exceptions
import pytest
import yaml

from automated_security_helper.plugin_modules.ash_aws_plugins.cloudwatch_logs_reporter import (
    CloudWatchLogsReporter,
)
from automated_security_helper.plugin_modules.ash_aws_plugins.s3_reporter import (
    S3Reporter,
)
from automated_security_helper.plugin_modules.ash_aws_plugins.security_hub_reporter import (
    SecurityHubReporter,
)
from automated_security_helper.utils.log import ASH_LOGGER
from tests.utils.secret_bearing_scan import isolate_from_aws

AWS_PLUGIN_MODULE = "automated_security_helper.plugin_modules.ash_aws_plugins"

OPERATOR_REGION = "us-west-2"
REPOSITORY_REGION = "eu-west-1"


@dataclass(frozen=True)
class CloudReporter:
    """One cloud reporter, the services it calls, and each side's destination."""

    key: str
    cls: type
    #: Services only this reporter calls (STS is shared by all of them).
    services: Tuple[str, ...]
    #: The request that carries findings, or for Security Hub's stub report the
    #: one its dependency check makes.
    send: Tuple[str, str]
    #: The request parameter that names the destination, if any.
    destination_param: Optional[str]
    #: The destination options the repository's config sets.
    repository_options: Dict[str, Any]
    #: The operator's destination, as the request parameter's value.
    operator_destination: Optional[str]
    #: The ``--config-overrides`` that aim it, beyond ``enabled``. CloudWatch Logs
    #: takes its log group from the operator's environment instead.
    operator_overrides: Tuple[str, ...]
    #: The operator's own config section for it, for an operator config file.
    operator_section: Dict[str, Any]


REPORTERS = {
    "s3": CloudReporter(
        key="s3",
        cls=S3Reporter,
        services=("s3",),
        send=("s3", "PutObject"),
        destination_param="Bucket",
        repository_options={
            "bucket_name": "repository-bucket",
            "aws_region": REPOSITORY_REGION,
            "key_prefix": "repository-prefix/",
        },
        operator_destination="operator-bucket",
        operator_overrides=(
            "reporters.s3.options.bucket_name=operator-bucket",
            f"reporters.s3.options.aws_region={OPERATOR_REGION}",
            "reporters.s3.options.max_retries=0",
        ),
        operator_section={
            "enabled": True,
            "options": {
                "bucket_name": "operator-bucket",
                "aws_region": OPERATOR_REGION,
                "max_retries": 0,
            },
        },
    ),
    "cloudwatch-logs": CloudReporter(
        key="cloudwatch-logs",
        cls=CloudWatchLogsReporter,
        services=("logs",),
        send=("logs", "PutLogEvents"),
        destination_param="logGroupName",
        repository_options={
            "log_group_name": "repository-group",
            "log_stream_name": "repository-stream",
            "aws_region": REPOSITORY_REGION,
        },
        operator_destination="operator-group",
        operator_overrides=(),
        operator_section={
            "enabled": True,
            "options": {
                "log_group_name": "operator-group",
                "aws_region": OPERATOR_REGION,
            },
        },
    ),
    "aws-security-hub": CloudReporter(
        key="aws-security-hub",
        cls=SecurityHubReporter,
        services=("securityhub",),
        send=("securityhub", "DescribeHub"),
        destination_param=None,
        repository_options={
            "aws_region": REPOSITORY_REGION,
            "account_id": "222222222222",
        },
        operator_destination=None,
        # No account id: the reporter asks STS for the operator's (answered).
        operator_overrides=(
            f"reporters.aws-security-hub.options.aws_region={OPERATOR_REGION}",
        ),
        operator_section={
            "enabled": True,
            "options": {"aws_region": OPERATOR_REGION, "account_id": "111111111111"},
        },
    ),
}

ANSWERS: Dict[Tuple[str, str], Dict[str, Any]] = {
    ("sts", "GetCallerIdentity"): {
        "Account": "111111111111",
        "Arn": "arn:aws:iam::111111111111:user/operator",
        "UserId": "operator",
    },
    ("s3", "HeadBucket"): {},
    ("s3", "PutObject"): {"ETag": '"0"'},
    ("logs", "CreateLogStream"): {},
    ("logs", "PutLogEvents"): {"nextSequenceToken": "1"},
    ("securityhub", "DescribeHub"): {
        "HubArn": f"arn:aws:securityhub:{OPERATOR_REGION}:111111111111:hub/default"
    },
}


class Request(NamedTuple):
    service: str
    operation: str
    region: Optional[str]
    params: Dict[str, Any]


class CloudCalls:
    """The boto3 sessions and clients built and the requests made, answered or refused."""

    def __init__(self) -> None:
        self.sessions: List[Dict[str, Any]] = []
        self.clients: List[str] = []
        self.requests: List[Request] = []

    def any(self) -> bool:
        return bool(self.sessions or self.clients or self.requests)

    def to(self, services: Tuple[str, ...]) -> List[Request]:
        return [r for r in self.requests if r.service in services]


@pytest.fixture
def cloud(monkeypatch, tmp_path) -> CloudCalls:
    """No credentials, a loopback endpoint, and the operator's environment.

    The environment names a complete destination for each reporter (region, S3
    bucket, CloudWatch Logs group), so a reporter the repository turned on would
    have somewhere to send.
    """
    isolate_from_aws(monkeypatch, tmp_path)
    monkeypatch.setenv("AWS_REGION", OPERATOR_REGION)
    monkeypatch.setenv("ASH_S3_BUCKET_NAME", "operator-bucket")
    monkeypatch.setenv("ASH_CLOUDWATCH_LOG_GROUP_NAME", "operator-group")
    calls = CloudCalls()
    real_session = boto3.Session
    real_client = boto3.client

    def recording_session(*args, **kwargs):
        calls.sessions.append(kwargs)
        return real_session(*args, **kwargs)

    def recording_client(service_name, *args, **kwargs):
        calls.clients.append(service_name)
        return real_client(service_name, *args, **kwargs)

    def recording_request(client, operation_name, api_params):
        service = client.meta.service_model.service_name
        calls.requests.append(
            Request(
                service,
                operation_name,
                client.meta.region_name,
                dict(api_params) if isinstance(api_params, dict) else {},
            )
        )
        if (service, operation_name) in ANSWERS:
            return dict(ANSWERS[(service, operation_name)])
        raise botocore.exceptions.ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "refused by the test"}},
            operation_name,
        )

    monkeypatch.setattr(boto3, "Session", recording_session)
    monkeypatch.setattr(boto3, "client", recording_client)
    monkeypatch.setattr(botocore.client.BaseClient, "_make_api_call", recording_request)
    return calls


def _recording(monkeypatch, method_name: str) -> List[str]:
    """Names of the cloud reporters whose ``method_name`` ran."""
    seen: List[str] = []
    for reporter in REPORTERS.values():
        original = getattr(reporter.cls, method_name)

        def recorded(self, *args, _original=original, _name=reporter.cls.__name__):
            seen.append(_name)
            return _original(self, *args)

        monkeypatch.setattr(reporter.cls, method_name, recorded)
    return seen


@pytest.fixture
def constructed(monkeypatch) -> List[str]:
    """Names of the cloud reporters the run built, whether or not it used them.

    A check that a reporter contacted nothing passes vacuously if the run never
    built it, so each test asserts on this first.
    """
    return _recording(monkeypatch, "model_post_init")


@pytest.fixture
def checked(monkeypatch) -> List[str]:
    """Names of the cloud reporters whose dependency check ran (it contacts AWS)."""
    return _recording(monkeypatch, "validate_plugin_dependencies")


@pytest.fixture
def reported(monkeypatch) -> List[str]:
    """Names of the cloud reporters whose ``report`` ran."""
    return _recording(monkeypatch, "report")


@pytest.fixture
def warnings_logged():
    """The messages ASH logs at WARNING or above while the test runs.

    Collected by a filter on the logger, not a handler: the scan sets the logger
    up again (``utils.log.get_logger``), which drops every handler it had but
    keeps its filters.
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


def _ignored_from_the_checkout(
    messages: List[str], checkout: Path, setting: str
) -> List[str]:
    """The warnings saying ``setting`` from the checkout's own config was ignored.

    Proof that the scan read the repository's config, so a test that no AWS
    request was made is not passing because the file was never seen.
    """
    return [
        m
        for m in messages
        if m.startswith("Ignoring") and setting in m and checkout.name in m
    ]


def _git_checkout(path: Path, files: Dict[str, str]) -> Path:
    """A git checkout at ``path`` holding ``files``, committed."""
    path.mkdir(parents=True)
    for name, text in files.items():
        target = path / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")
    for args in (
        ["init", "-q"],
        ["add", "-A"],
        [
            "-c",
            "user.name=test",
            "-c",
            "user.email=test@example.invalid",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "-q",
            "-m",
            "fixture",
        ],
    ):
        subprocess.run(["git", "-C", str(path), *args], check=True, capture_output=True)
    assert (path / ".git").is_dir()
    return path


def _scanned_checkout(tmp_path: Path, reporters: Dict[str, Any]) -> Path:
    """The scanned repository: a git checkout whose ``.ash/.ash.yaml`` sets ``reporters``."""
    files = {"app.py": "value = 1\n"}
    if reporters:
        files[".ash/.ash.yaml"] = yaml.safe_dump({"reporters": reporters})
    return _git_checkout(tmp_path / "checkout", files)


def _scan(
    tmp_path: Path,
    monkeypatch,
    source_dir: Path,
    overrides: Tuple[str, ...] = (),
    config: Optional[Path] = None,
) -> Path:
    """Scan ``source_dir`` in this process, from an empty working directory."""
    from automated_security_helper.interactions.run_ash_scan import run_ash_scan

    work = tmp_path / "work"
    work.mkdir(exist_ok=True)
    monkeypatch.chdir(work)
    output_dir = tmp_path / "out"
    run_ash_scan(
        source_dir=str(source_dir),
        output_dir=str(output_dir),
        config=str(config) if config else None,
        config_overrides=list(overrides) or None,
        scanners=["detect-secrets"],
        offline=True,
        progress=False,
        quiet=True,
        show_summary=False,
        fail_on_findings=False,
        fail_on_incomplete_scanners=False,
        color=False,
        # The operator loads the AWS plugins (--ash-plugin-modules).
        ash_plugin_modules=[AWS_PLUGIN_MODULE],
    )
    # The scan finished, so an empty record means the reporter was not used, not
    # that the run stopped first.
    assert (output_dir / "ash_aggregated_results.json").exists()
    return output_dir


def _repository_values(reporter: CloudReporter) -> List[Any]:
    return list(reporter.repository_options.values())


def _assert_sent_to_the_operator(calls: CloudCalls, reporter: CloudReporter) -> None:
    sent = [r for r in calls.requests if (r.service, r.operation) == reporter.send]
    assert sent, calls.requests
    for request in calls.to(reporter.services):
        assert request.region == OPERATOR_REGION, request
        if reporter.destination_param is not None:
            assert request.params.get(reporter.destination_param) == (
                reporter.operator_destination
            ), request
    repository = [str(value) for value in _repository_values(reporter)]
    for request in calls.requests:
        assert request.region not in repository, request
        assert not [
            value
            for value in request.params.values()
            if any(str(value).startswith(chosen) for chosen in repository)
        ], request
    for session in calls.sessions:
        assert session.get("region_name") not in repository, session


@pytest.mark.parametrize("key", list(REPORTERS))
class TestTheRepositoryCannotTurnOneOn:
    def test_its_enabled_true_reaches_no_aws(
        self,
        tmp_path,
        monkeypatch,
        cloud,
        constructed,
        checked,
        reported,
        warnings_logged,
        key,
    ):
        """The operator loads the AWS plugins and enables nothing: no session, client or request."""
        reporter = REPORTERS[key]
        checkout = _scanned_checkout(
            tmp_path,
            {key: {"enabled": True, "options": dict(reporter.repository_options)}},
        )

        _scan(tmp_path, monkeypatch, checkout)

        assert _ignored_from_the_checkout(
            warnings_logged, checkout, f"reporters.{key}.enabled"
        ), warnings_logged
        assert reporter.cls.__name__ in constructed
        assert checked == []
        assert reported == []
        assert not cloud.any(), (cloud.sessions, cloud.clients, cloud.requests)


@pytest.mark.parametrize("key", ["cloudwatch-logs", "aws-security-hub"])
def test_the_operator_enabling_s3_does_not_let_the_repository_enable_another(
    tmp_path, monkeypatch, cloud, constructed, checked, reported, warnings_logged, key
):
    """The operator enables S3 (bucket and region from its environment); the repository enables another.

    The other reporter is built but not checked or run, and nothing reaches its
    service. S3 runs: the control that the report phase used the cloud reporters.
    """
    reporter = REPORTERS[key]
    checkout = _scanned_checkout(tmp_path, {key: {"enabled": True}})

    _scan(tmp_path, monkeypatch, checkout, overrides=("reporters.s3.enabled=true",))

    assert _ignored_from_the_checkout(
        warnings_logged, checkout, f"reporters.{key}.enabled"
    ), warnings_logged
    assert reporter.cls.__name__ in constructed
    assert reporter.cls.__name__ not in checked
    assert reporter.cls.__name__ not in reported
    assert cloud.to(reporter.services) == []
    assert "S3Reporter" in reported
    assert ("s3", "PutObject") in [(r.service, r.operation) for r in cloud.requests]


@pytest.mark.parametrize("key", list(REPORTERS))
def test_the_operator_enabling_it_sends_only_to_the_operators_destination(
    tmp_path, monkeypatch, cloud, constructed, reported, warnings_logged, key
):
    """The operator enables it; the repository sets only where it sends. The repository's values are dropped."""
    reporter = REPORTERS[key]
    checkout = _scanned_checkout(
        tmp_path, {key: {"options": dict(reporter.repository_options)}}
    )

    _scan(
        tmp_path,
        monkeypatch,
        checkout,
        overrides=(f"reporters.{key}.enabled=true", *reporter.operator_overrides),
    )

    # An override replaces the repository's value before the config is confined,
    # so the options the operator does not set are the ones named as ignored:
    # proof that the scan read the repository's file.
    overridden = {
        override.partition("=")[0].rsplit(".", 1)[-1]
        for override in reporter.operator_overrides
    }
    not_overridden = [o for o in reporter.repository_options if o not in overridden]
    assert not_overridden
    for option in not_overridden:
        assert _ignored_from_the_checkout(
            warnings_logged, checkout, f"reporters.{key}.options.{option}"
        ), (option, warnings_logged)
    assert reporter.cls.__name__ in constructed
    assert reporter.cls.__name__ in reported
    _assert_sent_to_the_operator(cloud, reporter)


def test_a_destination_written_beside_options_is_not_read(
    tmp_path, monkeypatch, cloud, reported, warnings_logged
):
    """``reporters.s3: {enabled: true, bucket_name: ...}``, the bucket outside ``options``.

    A reporter section keeps unknown keys, but the S3 reporter reads its bucket
    and region from ``options`` only, so these name no destination: with the
    operator enabling S3, the upload goes to the operator's bucket and region. The
    ``key_prefix`` under ``options`` is the repository's too, and is named as
    ignored, which shows the scan read the file.
    """
    checkout = _scanned_checkout(
        tmp_path,
        {
            "s3": {
                "enabled": True,
                "bucket_name": "repository-bucket",
                "aws_region": REPOSITORY_REGION,
                "options": {"key_prefix": "repository-prefix/"},
            }
        },
    )

    _scan(tmp_path, monkeypatch, checkout, overrides=("reporters.s3.enabled=true",))

    assert _ignored_from_the_checkout(
        warnings_logged, checkout, "reporters.s3.options.key_prefix"
    ), warnings_logged
    assert "S3Reporter" in reported
    _assert_sent_to_the_operator(cloud, REPORTERS["s3"])


@pytest.mark.parametrize("key", list(REPORTERS))
def test_an_operator_config_outside_every_checkout_turns_it_on_and_aims_it(
    tmp_path, monkeypatch, cloud, constructed, reported, key
):
    """Control: the operator's config file in a plain directory is the operator's."""
    reporter = REPORTERS[key]
    checkout = _scanned_checkout(
        tmp_path, {key: {"options": dict(reporter.repository_options)}}
    )
    operator_file = tmp_path / "ops" / "ash.yaml"
    operator_file.parent.mkdir()
    operator_file.write_text(
        yaml.safe_dump({"reporters": {key: reporter.operator_section}}),
        encoding="utf-8",
    )

    _scan(tmp_path, monkeypatch, checkout, config=operator_file)

    assert reporter.cls.__name__ in constructed
    assert reporter.cls.__name__ in reported
    _assert_sent_to_the_operator(cloud, reporter)


@pytest.mark.parametrize("key", list(REPORTERS))
def test_a_config_in_an_ops_checkout_does_not_turn_it_on_or_aim_it(
    tmp_path, monkeypatch, cloud, constructed, checked, reported, warnings_logged, key
):
    """A config file inside any git checkout is held to the repository's rules, an ops repository's too.

    The file names the reporter's section with ``enabled: true`` and a
    destination, in a git checkout that is not the scanned one. A file in a git
    checkout may have been written by a repository, so it does not turn the
    reporter on or aim it: nothing is checked, run or requested, and the warning
    gives the remedy every confinement warning ends with (move the file outside
    every git checkout, or pass the setting with --config-overrides). The same
    file outside every checkout does turn it on (the control above).
    """
    from automated_security_helper.config.confinement_remedy import KEEP_A_SETTING

    reporter = REPORTERS[key]
    checkout = _scanned_checkout(
        tmp_path, {key: {"options": dict(reporter.repository_options)}}
    )
    ops = _git_checkout(
        tmp_path / "ops",
        {"ash.yaml": yaml.safe_dump({"reporters": {key: reporter.operator_section}})},
    )

    _scan(tmp_path, monkeypatch, checkout, config=ops / "ash.yaml")

    named = [
        m
        for m in warnings_logged
        if m.startswith("Ignoring")
        and f"reporters.{key}.enabled" in m
        and (ops / "ash.yaml").as_posix() in m
    ]
    assert len(named) == 1, warnings_logged
    assert named[0].endswith(KEEP_A_SETTING), named[0]
    assert reporter.cls.__name__ in constructed
    assert reporter.cls.__name__ not in checked
    assert reporter.cls.__name__ not in reported
    assert not cloud.any(), (cloud.sessions, cloud.clients, cloud.requests)


class TestInAFreshProcess:
    """``ash scan`` in a new interpreter, as the CLI runs it.

    The tests above import the AWS reporter modules, so their config models are
    registered before the scan resolves its config. A fresh ``ash scan`` resolves
    it before any AWS plugin module is imported, and then only
    ``reporter_trust.REPORTER_ENABLED_DEFAULTS`` stands for the reporters' own
    defaults. Each run here scans a git checkout whose config sets a section for
    all three reporters, with every destination in the operator's environment and
    the AWS module named by ``--ash-plugin-modules``, and records each botocore
    request the child makes (answering the dependency checks, refusing the rest).
    """

    _DRIVER = (
        "import json, sys\n"
        "import botocore.client, botocore.exceptions\n"
        "answers = json.loads(sys.argv[2])\n"
        "requests = []\n"
        "def recording(client, operation, params):\n"
        "    service = client.meta.service_model.service_name\n"
        "    requests.append({\n"
        "        'service': service, 'operation': operation,\n"
        "        'region': client.meta.region_name,\n"
        "        'params': {k: str(v) for k, v in params.items()\n"
        "                   if k in ('Bucket', 'Key', 'logGroupName', 'logStreamName')},\n"
        "    })\n"
        "    answer = answers.get(service + '.' + operation)\n"
        "    if answer is not None:\n"
        "        return dict(answer)\n"
        "    raise botocore.exceptions.ClientError(\n"
        "        {'Error': {'Code': 'AccessDenied', 'Message': 'refused'}}, operation)\n"
        "botocore.client.BaseClient._make_api_call = recording\n"
        "import logging\n"
        "from automated_security_helper.utils.log import ASH_LOGGER\n"
        "ignoring = []\n"
        "class _Collect(logging.Filter):\n"
        "    def filter(self, record):\n"
        "        message = record.getMessage()\n"
        "        if message.startswith('Ignoring'):\n"
        "            ignoring.append(message)\n"
        "        return True\n"
        "ASH_LOGGER.addFilter(_Collect())\n"
        "from typer.testing import CliRunner\n"
        "from automated_security_helper.cli.main import app\n"
        "result = CliRunner().invoke(app, json.loads(sys.argv[1]))\n"
        "print('RESULT ' + json.dumps({\n"
        "    'exit': result.exit_code,\n"
        "    'requests': requests,\n"
        "    'ignoring': ignoring,\n"
        "    'output': result.output[-3000:],\n"
        "}))\n"
    )

    def _run(self, tmp_path, monkeypatch, sections, *extra_args) -> Dict[str, Any]:
        import json
        import os
        import sys

        from tests.utils.helpers import importing_this_checkout

        isolate_from_aws(monkeypatch, tmp_path)
        checkout = _scanned_checkout(tmp_path, sections)
        environment = {
            name: value
            for name, value in os.environ.items()
            if not name.startswith("ASH_")
        }
        environment.update(
            {
                "AWS_REGION": OPERATOR_REGION,
                "ASH_S3_BUCKET_NAME": "operator-bucket",
                "ASH_CLOUDWATCH_LOG_GROUP_NAME": "operator-group",
            }
        )
        work = tmp_path / "work"
        work.mkdir()
        output_dir = tmp_path / "out"
        argv = [
            "scan",
            "--source-dir",
            str(checkout),
            "--output-dir",
            str(output_dir),
            "--scanners",
            "detect-secrets",
            "--no-progress",
            "--no-fail-on-incomplete-scanners",
            "--ash-plugin-modules",
            AWS_PLUGIN_MODULE,
            *extra_args,
        ]
        answers = {f"{s}.{o}": answer for (s, o), answer in ANSWERS.items()}
        run = subprocess.run(
            [
                sys.executable,
                "-I",
                "-c",
                importing_this_checkout(self._DRIVER),
                json.dumps(argv),
                json.dumps(answers),
            ],
            cwd=work,
            env=environment,
            capture_output=True,
            text=True,
            timeout=600,
        )
        assert run.returncode == 0, (run.returncode, run.stderr[-3000:])
        line = [row for row in run.stdout.splitlines() if row.startswith("RESULT ")]
        assert line, (run.stdout[-3000:], run.stderr[-3000:])
        measured = json.loads(line[-1][len("RESULT ") :])
        # The scan itself finished, so no request means none was attempted.
        assert (output_dir / "ash_aggregated_results.json").exists(), measured
        return measured

    @pytest.mark.parametrize(
        "enabled",
        [True, False, None],
        ids=["enabled-true", "enabled-false", "no-enabled"],
    )
    def test_the_repositorys_section_reaches_no_aws(
        self, tmp_path, monkeypatch, enabled
    ):
        """Whatever ``enabled`` the repository writes, none of the three contacts AWS."""
        sections: Dict[str, Any] = {}
        for key, reporter in REPORTERS.items():
            section: Dict[str, Any] = {"options": dict(reporter.repository_options)}
            if enabled is not None:
                section["enabled"] = enabled
            sections[key] = section

        measured = self._run(tmp_path, monkeypatch, sections)

        # The child read the checkout's config: its destinations were named as
        # ignored for each reporter.
        for key in REPORTERS:
            assert [
                m for m in measured["ignoring"] if f"reporters.{key}.options." in m
            ], (key, measured["ignoring"])
        assert measured["requests"] == [], measured

    def test_control_the_operators_override_reaches_put_object(
        self, tmp_path, monkeypatch
    ):
        """Control: the child records requests, and the operator's S3 reaches its bucket."""
        measured = self._run(
            tmp_path,
            monkeypatch,
            {"s3": {"options": dict(REPORTERS["s3"].repository_options)}},
            "--config-overrides",
            "reporters.s3.enabled=true",
        )

        puts = [
            request
            for request in measured["requests"]
            if (request["service"], request["operation"]) == ("s3", "PutObject")
        ]
        assert [put["params"]["Bucket"] for put in puts] == ["operator-bucket"], (
            measured
        )
        assert all(put["region"] == OPERATOR_REGION for put in puts), measured
