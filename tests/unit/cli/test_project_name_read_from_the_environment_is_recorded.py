# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A project name read from the environment is recorded as its reference in
every results file and every off-host send.

WHY THIS EXISTS
---------------
The scan names the project the configuration names: ScanExecutionEngine sets
``metadata.project_name`` from ``config.project_name``, so the run's own
reports say which project they describe. When the configuration reads the name
from the environment (``project_name: ${VAR}``), ``config.project_name`` is the
variable's value by then, so the engine sets the metadata to the reference the
file wrote instead, and the reports name the project by it. The results file,
the merged results and the JSON the S3 and CloudWatch Logs reporters send off
the host are dumps of those results, and each records the metadata the way the
configuration's own record has the field (config_validator.record_of_metadata,
through record_of_config): the reference the file wrote, never the value.

WHAT IT CHECKS
--------------
Two shards are scanned from a tree whose configuration reads ``project_name``
from ASH_PROBE_VALUE, the first with the operator's overrides turning S3 and
CloudWatch Logs on. ``ash merge`` merges them with the same settings, given in
an operator configuration file outside the tree (``--config``), and ``ash
report`` sends a shard with each reporter, with the overrides. Every command
runs in a child whose AWS endpoints are a loopback stand-in that keeps each
request's body.
- Control: the run read the variable. The configuration writes the bare
  ``${ASH_PROBE_VALUE}``, which refuses the configuration when the variable is
  unset, and every scan exits 0. The shard's own summary report names the
  project by that reference, and holds no value.
- Control: each sender sent. A PutObject body and a PutLogEvents body were
  recorded from the scan, from the merge and from the report.
- Each results file records ``metadata.project_name`` as the reference the
  file wrote, and holds no value.
- No request body or target holds the value.

The value is counted after removing whitespace and U+2500-U+257F, and its
12-character prefix is counted too, so a value wrapped or cut still counts.
Failures name the file, the JSON path or the request target, never the text.

LIMITS
------
- The merge gets the operator's settings from the file ``--config`` names, not from ``--config-overrides``.
- The scan's own reports are checked in
  tests/unit/cli/test_outputs_hold_no_value_read_from_the_environment.py; the
  first control here reads one of them.
- One reference shape, ``${VAR}``; the recording itself is shape-blind
  (tests/unit/config/test_config_record_as_written.py covers the shapes).
"""

from __future__ import annotations

import http.server
import json
import re
import subprocess
import sys
import threading

import pytest

from tests.utils import aws_stand_in as stand_in
from tests.utils.helpers import importing_this_checkout
from tests.utils.tool_guard import CHILD_TOOL_PROBE_STUBS

CANARY = "ash-canary-7f3e-0123456789"
PREFIX = CANARY[:12]
REFERENCE = "${ASH_PROBE_VALUE}"
_SQUEEZE = re.compile(r"[\s─-╿]")
AWS = "automated_security_helper.plugin_modules.ash_aws_plugins"
OPERATOR = [
    f'ash_plugin_modules+=["{AWS}"]',
    "reporters.s3.enabled=true",
    "reporters.s3.options.bucket_name=operator-bucket",
    "reporters.s3.options.aws_region=us-east-1",
    "reporters.s3.options.max_retries=0",
    "reporters.cloudwatch-logs.enabled=true",
    "reporters.cloudwatch-logs.options.aws_region=us-east-1",
    "reporters.cloudwatch-logs.options.log_group_name=operator-group",
    "reporters.cloudwatch-logs.options.log_stream_name=operator-stream",
    "reporters.cloudwatch-logs.options.max_retries=0",
]
#: The same settings as the operator's configuration file, for ``ash merge``.
OPERATOR_FILE = f"""\
ash_plugin_modules:
  - {AWS}
reporters:
  s3:
    enabled: true
    options:
      bucket_name: operator-bucket
      aws_region: us-east-1
      max_retries: 0
  cloudwatch-logs:
    enabled: true
    options:
      aws_region: us-east-1
      log_group_name: operator-group
      log_stream_name: operator-stream
      max_retries: 0
"""
RESULTS = ("shard0", "shard1", "merged")


def _holds_value(text: str) -> bool:
    return PREFIX in _SQUEEZE.sub("", text)


def _paths(node, at=""):
    """The JSON paths of every string holding the value or its prefix; a string
    that is itself JSON is walked too, marked <json>."""
    found = []
    if isinstance(node, dict):
        for key, value in node.items():
            if _holds_value(str(key)):
                found.append(f"{at}/<key>")
            found += _paths(value, f"{at}/{key}")
    elif isinstance(node, list):
        for index, value in enumerate(node):
            found += _paths(value, f"{at}[{index}]")
    elif isinstance(node, str) and _holds_value(node):
        try:
            inner = json.loads(node)
        except ValueError:
            inner = None
        found += (
            _paths(inner, f"{at}<json>") if isinstance(inner, (dict, list)) else [at]
        )
    return found


def _where(text: str):
    try:
        return _paths(json.loads(text))
    except ValueError:
        return ["<not JSON>"] if _holds_value(text) else []


def _verb(target: str) -> str:
    """A request target without its object key, which a reporter may build from
    the project name."""
    verb, _, path = target.partition(" ")
    if path.startswith("/"):
        return f"{verb} /{path.split('/')[1]}/..."
    return verb if _holds_value(target) else target


@pytest.fixture(scope="module")
def runs(tmp_path_factory):
    work = tmp_path_factory.mktemp("project-name")
    # Outside the scanned tree and the working directory: the operator's.
    operator = tmp_path_factory.mktemp("operator") / "ash-operator.yaml"
    operator.write_text(OPERATOR_FILE, encoding="utf-8")
    requests: list = []
    bodies: list = []
    # The stand-in, keeping each PutObject's body as well.
    handler = type(
        "_Recording",
        (stand_in._AwsStandIn,),
        {
            "requests": requests,
            "bodies": bodies,
            "security_hub": False,
            "stored_findings": [],
            "put_bodies": True,
        },
    )
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    endpoint = f"http://127.0.0.1:{server.server_address[1]}"
    env = stand_in.child_aws_env(work, endpoint)
    env.update(ASH_PROBE_VALUE=CANARY, COLUMNS="300")
    env.pop("ASH_CONFIG", None)

    (work / "src" / ".ash").mkdir(parents=True)
    (work / "src" / "app.py").write_text("print('hello')\n", encoding="utf-8")
    (work / "src" / ".ash" / ".ash.yaml").write_text(
        f"project_name: {REFERENCE}\n", encoding="utf-8"
    )
    overrides = [
        arg for override in OPERATOR for arg in ("--config-overrides", override)
    ]

    # The child's probes are answered first (CHILD_TOOL_PROBE_STUBS): it found the
    # uv installed with ASH beside its interpreter, and detect-secrets' dependency
    # check ran ``uv tool run detect-secrets --version`` for real.
    def ash(*argv: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            [
                sys.executable,
                "-c",
                importing_this_checkout(
                    CHILD_TOOL_PROBE_STUBS
                    + "from automated_security_helper.cli.main import app; app()"
                ),
                *argv,
            ],
            capture_output=True,
            text=True,
            timeout=900,
            cwd=work,
            env=env,
            check=False,
        )

    steps = {}
    sent_by = []
    try:
        for index in (0, 1):
            scan_argv = [
                "scan",
                "--no-progress",
                "--source-dir",
                "src",
                "--output-dir",
                f"shard{index}",
                "--scanners",
                "detect-secrets",
                "--no-fail-on-incomplete-scanners",
                "--no-fail-on-findings",
                "--shard-index",
                str(index),
                "--shard-count",
                "2",
            ]
            before = len(bodies)
            steps[f"scan{index}"] = ash(*scan_argv, *(overrides if index == 0 else []))
            sent_by += [f"scan{index}"] * (len(bodies) - before)
        merge_argv = ["merge", "--output-dir", "merged", "--no-fail-on-findings"]
        for index in (0, 1):
            merge_argv += [
                "--results",
                str(work / f"shard{index}" / "ash_aggregated_results.json"),
            ]
        before = len(bodies)
        steps["merge"] = ash(*merge_argv, "--no-color", "--config", str(operator))
        sent_by += ["merge"] * (len(bodies) - before)
        for fmt in ("s3", "cloudwatch-logs"):
            before = len(bodies)
            steps[f"report-{fmt}"] = ash(
                "report",
                "--format",
                fmt,
                "--output-dir",
                str(work / "shard0"),
                "--no-color",
                *overrides,
            )
            sent_by += ["report"] * (len(bodies) - before)
    finally:
        server.shutdown()
        server.server_close()
    return {
        "work": work,
        "steps": steps,
        "requests": requests,
        "bodies": list(zip(sent_by, bodies)),
    }


def _the_run_read_the_value(runs) -> None:
    for name in ("scan0", "scan1", "merge"):
        assert runs["steps"][name].returncode == 0, (
            name,
            runs["steps"][name].returncode,
            _where(runs["steps"][name].stderr),
        )
    # A bare ${VAR} whose variable is unset refuses the configuration with exit
    # 3, so the scans exiting 0 is the variable read. The summary names the
    # project by the reference the configuration wrote.
    summary = runs["work"] / "shard0" / "reports" / "ash.summary.txt"
    assert summary.is_file()
    text = summary.read_text(encoding="utf-8", errors="replace")
    assert REFERENCE in text, "the summary does not name the project's reference"
    assert not _holds_value(text), "the summary holds the project name's value"


def test_the_run_read_the_value(runs):
    _the_run_read_the_value(runs)


@pytest.mark.parametrize("results", RESULTS)
def test_each_results_file_records_the_reference(runs, results):
    _the_run_read_the_value(runs)
    path = runs["work"] / results / "ash_aggregated_results.json"
    text = path.read_text(encoding="utf-8")
    # A boolean, so a failure names where the value is and never shows it.
    recorded = json.loads(text)["metadata"]["project_name"] == REFERENCE
    assert recorded, _where(text)
    assert _where(text) == []


@pytest.mark.parametrize("sender", ["scan0", "merge", "report"])
def test_no_off_host_body_holds_the_value(runs, sender):
    _the_run_read_the_value(runs)
    sent = [(target, body) for who, (target, body) in runs["bodies"] if who == sender]
    # The control: this sender reached both services with a body.
    assert {_verb(target).split(" ")[0] for target, _ in sent} >= {
        "PutObject",
        "Logs_20140328.PutLogEvents",
    }, sorted({_verb(target) for target, _ in sent})
    leaked = [
        (_verb(target), _where(body))
        for target, body in sent
        if _holds_value(body) or _holds_value(target)
    ]
    assert leaked == []


def test_no_request_target_holds_the_value(runs):
    _the_run_read_the_value(runs)
    assert [_verb(what) for _, what in runs["requests"] if _holds_value(what)] == []
