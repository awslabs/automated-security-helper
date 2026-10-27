# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""What ASH prints and writes of a configuration that reads the environment
holds the reference the file wrote, never the value it read.

WHY THIS EXISTS
---------------
A configuration can read a value or a mapping key from the environment
(``project_name: ${ASH_X}``, or ``${ASH_X}:`` as a key). The results file
records each one as the reference its file wrote (config_validator
record_of_config). ``ash config get`` and the scan's own reports are made from
that record, so they hold the reference:

- ``ash config get`` prints each such key and value as its reference;
- ScanExecutionEngine sets ``metadata.project_name`` to the reference the file
  wrote, so ash.flat.json, ash.html, ash.summary.md and ash.summary.txt print
  the reference.

A CI job keeps those reports as artifacts, so whatever they hold leaves the host.

WHAT IT CHECKS
--------------
One tree's configuration reads four settings from four variables, each set to a
value made for this run: project_name, an ignore path's reason, a suppression's
reason and a reporters section key. ``ash config get`` prints it, and one scan
runs detect-secrets with every report format the tree ships. The scan keeps a
finding and suppresses its copy in another file. A second scan runs with
``--debug``.

- ``ash config get`` prints each key and value as its reference, and none of
  the values.
- No report, no other file of the output directory (ash.log among them), no
  line of either scan's console and no answer of an MCP tool that reads results
  holds the value of project_name, the ignore path's reason or the key.
- Controls: the scan ran, suppressed as many findings as it kept and scanned
  nothing under the ignored path, the results file records each setting as its
  reference, each report named here was written, and the ``--debug`` scan's
  console holds DEBUG lines.

A value is counted after removing whitespace and U+2500-U+257F, and its
12-character prefix is counted too, so a value wrapped or cut still counts.
Failures name the output and the setting, never the value.

LIMITS
------
- A suppression's reason is checked in ``config get`` only. A suppressed
  finding's SARIF justification quotes the reason, and that text is not checked
  here.
- One reference shape, ``${VAR}``; the recording itself is shape-blind
  (tests/unit/config/test_config_record_as_written.py covers the shapes).
- The reports a scan writes are checked as the scan writes them. ``ash report``
  renders the results file, which holds the references.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import secrets
import subprocess
import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from tests.utils.helpers import importing_this_checkout
from tests.utils.tool_guard import CHILD_TOOL_PROBE_STUBS

#: The variables, by the setting each one supplies. None of the names ends in a
#: suffix a configuration may not read (``_KEY``, ``_TOKEN`` and the rest).
VARIABLES = {
    "project_name": "ASH_OUTPUT_NAME",
    "ignore path reason": "ASH_OUTPUT_IGNORED",
    "suppression reason": "ASH_OUTPUT_SUPPRESSED",
    "reporters key": "ASH_OUTPUT_SECTION",
}
#: The settings the reports, files, consoles and MCP answers are checked for.
CHECKED = ("project_name", "ignore path reason", "reporters key")

CONFIG = """project_name: ${ASH_OUTPUT_NAME}
global_settings:
  ignore_paths:
    - path: ignored/**
      reason: ${ASH_OUTPUT_IGNORED}
  suppressions:
    - rule_id: "*"
      path: suppressed.py
      reason: ${ASH_OUTPUT_SUPPRESSED}
reporters:
  yaml:
    enabled: true
  spdx:
    enabled: true
  ${ASH_OUTPUT_SECTION}:
    enabled: false
"""

#: Report formats every line of ASH ships, and the file each writes.
REPORTS = {
    "text": "ash.summary.txt",
    "markdown": "ash.summary.md",
    "html": "ash.html",
    "flat-json": "ash.flat.json",
    "csv": "ash.csv",
    "sarif": "ash.sarif",
    "junitxml": "ash.junit.xml",
    "ocsf": "ash.ocsf.json",
    "cyclonedx": "ash.cdx.json",
    "yaml": "ash.yaml",
    "spdx": "ash.spdx.json",
}
#: Formats asked for too where this tree has them; their files are checked
#: with every other file of the output directory.
MORE_FORMATS = ("github-ghas", "gitlab-sast", "gitlab-cyclonedx", "unused-suppressions")

_SQUEEZE = re.compile(r"[\s─-╿]")


def _formats() -> str:
    from automated_security_helper.core.enums import ExportFormat

    shipped = {member.value for member in ExportFormat}
    return ",".join([*REPORTS, *(name for name in MORE_FORMATS if name in shipped)])


def _holds(value: str, text: str) -> bool:
    return value[:12] in _SQUEEZE.sub("", text)


def _names_reference(variable: str, text: str) -> bool:
    return "${" + variable + "}" in _SQUEEZE.sub("", text)


def _held(run, text: str, settings=CHECKED) -> list:
    """The settings whose value ``text`` holds, by name."""
    return [name for name in settings if _holds(run["values"][name], text)]


def _context() -> MagicMock:
    from mcp.server.mcpserver import Context

    context = MagicMock(spec=Context)
    context.headers = {}
    for level in ("info", "warning", "error", "debug"):
        setattr(context, level, AsyncMock())
    return context


async def _mcp_answers(output: Path) -> dict:
    from automated_security_helper.cli import mcp_server
    from automated_security_helper.models.asharp_model import AshAggregatedResults

    results = output / "ash_aggregated_results.json"
    model = AshAggregatedResults.from_json(results.read_text(encoding="utf-8"))
    finding = model.to_flat_vulnerabilities()[0].id
    ctx = _context()
    return {
        "get_scan_results": await mcp_server.get_scan_results(
            ctx, output_dir=str(output)
        ),
        "get_scan_summary": await mcp_server.get_scan_summary(
            ctx, output_dir=str(output)
        ),
        "get_scan_result_paths": await mcp_server.get_scan_result_paths(
            ctx, output_dir=str(output)
        ),
        "explain_finding": await mcp_server.explain_finding(
            ctx, finding_id=finding, results_path=str(results)
        ),
        "diff_scan_results": await mcp_server.diff_scan_results(
            ctx, before_path=str(results), after_path=str(results)
        ),
        "suggest_suppression": await mcp_server.suggest_suppression(
            ctx, finding_id=finding, results_path=str(results), justification="test"
        ),
    }


@pytest.fixture(scope="module")
def run(tmp_path_factory):
    work = tmp_path_factory.mktemp("environment-outputs")
    # Each value is made here, for this run only.
    values = {name: "ashv" + secrets.token_hex(12) for name in VARIABLES}
    env = dict(os.environ)
    env.pop("ASH_CONFIG", None)
    env.update(
        {VARIABLES[name]: value for name, value in values.items()},
        COLUMNS="300",
        NO_COLOR="1",
    )

    source = work / "src"
    (source / ".ash").mkdir(parents=True)
    (source / "ignored").mkdir()
    # A keyword detect-secrets reports, made here too.
    finding = f'password = "{secrets.token_hex(10)}"\n'
    for name in ("app.py", "suppressed.py", "ignored/skip.py"):
        (source / name).write_text(finding, encoding="utf-8")
    config = source / ".ash" / ".ash.yaml"
    config.write_text(CONFIG, encoding="utf-8")

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

    def scan(output: Path, *more: str) -> subprocess.CompletedProcess:
        return ash(
            "scan",
            "--source-dir",
            str(source),
            "--output-dir",
            str(output),
            "--config",
            str(config),
            "--scanners",
            "detect-secrets",
            "--output-formats",
            _formats(),
            "--no-progress",
            "--no-fail-on-findings",
            "--no-fail-on-incomplete-scanners",
            *more,
        )

    output = work / "out"
    steps = {
        "config get": ash("config", "get", "--no-color", str(config)),
        "scan": scan(output),
        "scan --debug": scan(work / "out-debug", "--debug"),
    }
    answers = {}
    if (output / "ash_aggregated_results.json").is_file():
        with pytest.MonkeyPatch.context() as patch:
            patch.setenv("ASH_MCP_ALLOWED_ROOTS", str(work))
            answers = asyncio.run(_mcp_answers(output))
    return {
        "values": values,
        "steps": steps,
        "output": output,
        "answers": answers,
    }


def _the_scan_ran(run) -> dict:
    scan = run["steps"]["scan"]
    assert scan.returncode == 0, (scan.returncode, _held(run, scan.stderr))
    results = run["output"] / "ash_aggregated_results.json"
    assert results.is_file()
    data = json.loads(results.read_text(encoding="utf-8"))
    stats = data["metadata"]["summary_stats"]
    # app.py and suppressed.py hold the same line, so the suppression applied
    # when as many findings are suppressed as kept; ignored/ was not scanned.
    assert stats["actionable"] >= 1, stats["severity_counts"]
    assert stats["severity_counts"]["suppressed"] == stats["actionable"], stats[
        "severity_counts"
    ]
    return data


def test_the_scan_ran(run):
    _the_scan_ran(run)


def test_the_results_record_each_setting_as_its_reference(run):
    data = _the_scan_ran(run)
    config = data["ash_config"]
    # Booleans, so a failure never shows what the field holds.
    recorded = {
        "project_name": config["project_name"] == "${ASH_OUTPUT_NAME}",
        "ignore path reason": config["global_settings"]["ignore_paths"][0]["reason"]
        == "${ASH_OUTPUT_IGNORED}",
        "reporters key": "${ASH_OUTPUT_SECTION}" in config["reporters"],
    }
    assert [field for field, ok in recorded.items() if not ok] == []
    assert _held(run, json.dumps(data)) == []


@pytest.mark.parametrize("setting", list(VARIABLES))
def test_config_get_prints_the_reference_not_the_value(run, setting):
    shown = run["steps"]["config get"]
    assert shown.returncode == 0, (shown.returncode, _held(run, shown.stderr))
    printed = shown.stdout + shown.stderr
    # Booleans, so a failure names the setting and never shows the value.
    holds_value = _holds(run["values"][setting], printed)
    names_reference = _names_reference(VARIABLES[setting], printed)
    assert not holds_value, f"config get prints the value of the {setting}"
    assert names_reference, f"config get does not name the {setting}'s reference"


@pytest.mark.parametrize("report", list(REPORTS))
def test_no_report_holds_a_value(run, report):
    _the_scan_ran(run)
    path = run["output"] / "reports" / REPORTS[report]
    assert path.is_file(), f"{report}: {path.name} was not written"
    text = path.read_text(encoding="utf-8", errors="replace")
    assert _held(run, text) == [], report


def test_no_other_output_file_holds_a_value(run):
    _the_scan_ran(run)
    named = {run["output"] / "reports" / name for name in REPORTS.values()}
    checked = []
    holding = []
    for path in sorted(run["output"].rglob("*")):
        if not path.is_file() or path in named:
            continue
        checked.append(path.name)
        text = path.read_bytes().decode("utf-8", "replace")
        holding += [
            (path.relative_to(run["output"]).as_posix(), name)
            for name in _held(run, text)
        ]
    # The control: ash.log is among the files read.
    assert "ash.log" in checked, checked
    assert holding == []


@pytest.mark.parametrize("step", ["scan", "scan --debug"])
def test_the_scan_console_holds_no_value(run, step):
    _the_scan_ran(run)
    scan = run["steps"][step]
    assert scan.returncode == 0, (scan.returncode, _held(run, scan.stderr))
    printed = scan.stdout + scan.stderr
    if step == "scan --debug":
        # The control, a boolean so a failure shows no console text: the
        # console holds the scan's DEBUG lines.
        debug_lines = "DEBUG" in printed
        assert debug_lines
    assert _held(run, printed) == []


def test_no_mcp_results_answer_holds_a_value(run):
    _the_scan_ran(run)
    answers = run["answers"]
    # The control: every tool answered.
    assert sorted(answers) == [
        "diff_scan_results",
        "explain_finding",
        "get_scan_result_paths",
        "get_scan_results",
        "get_scan_summary",
        "suggest_suppression",
    ]
    for tool, answer in answers.items():
        assert answer.get("success") is not False, (tool, answer.get("error_type"))
    holding = [
        (tool, name)
        for tool, answer in answers.items()
        for name in _held(run, json.dumps(answer, default=str))
    ]
    assert holding == []
