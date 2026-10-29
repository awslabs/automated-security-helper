# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A shard's recorded configuration keeps each environment reference as the
file wrote it, and nothing merge or report prints from it holds the value.

A scan records its configuration in its results file, and ``ash merge`` and
``ash report`` read that record instead of the configuration's files. The
configuration here reads the canary from the environment as ``project_name``,
as reporter options written three ways (``${VAR}``, ``${VAR:default}`` and an
explicit ``!ENV ${VAR}``), and as a key, a section under ``scanners`` that no
plugin reads (one the scan leaves as it is). The canary is in the environment
of all three commands, as it would be for a collector that has the same
secrets.

Asserted: both recorded configurations (the shard's, and the merged one, which
merge does not resolve again) hold each reference exactly as written and not
the canary, and the canary is in none of what ``ash merge --debug`` and ``ash
report --debug`` print or log, while the debug line that shows a reporter's
section is written. The scan's own summary names the project by its reference
(the control); tests/unit/cli/test_outputs_hold_no_value_read_from_the_environment.py
checks the scan's reports.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli.main import app
from tests.utils.tool_guard import install_tool_guard, reset_tool_lookup_caches

pytestmark = pytest.mark.unit

CANARY = "ash-canary-7f3e-0123456789"
SECRET = "${ASH_PROBE_VALUE}"
WITH_DEFAULT = "${ASH_PROBE_VALUE:fallback}"
TAGGED = "!ENV ${ASH_PROBE_VALUE}"
CONFIG = (
    f"project_name: {SECRET}\n"
    "reporters:\n"
    "  gitlab-cyclonedx:\n"
    "    options:\n"
    f"      language_override: {SECRET}\n"
    f"      input_file_path_override: {WITH_DEFAULT}\n"
    f"      package_manager_override: {TAGGED}\n"
    "scanners:\n"
    f"  {SECRET}:\n"
    "    enabled: false\n"
)
SHOWN_SECTION = "Found config for reporter plugin gitlab-cyclonedx"
# Where the record holds each reference, and the text the file writes there.
AS_WRITTEN = {
    ("project_name",): SECRET,
    ("reporters", "gitlab-cyclonedx", "options", "language_override"): SECRET,
    (
        "reporters",
        "gitlab-cyclonedx",
        "options",
        "input_file_path_override",
    ): WITH_DEFAULT,
    ("reporters", "gitlab-cyclonedx", "options", "package_manager_override"): TAGGED,
}


def _log_files(directory: Path) -> list[Path]:
    return sorted(
        path
        for path in directory.rglob("*")
        if path.is_file() and path.name.endswith((".log", ".log.jsonl"))
    )


@pytest.fixture(scope="module")
def runs(tmp_path_factory: pytest.TempPathFactory):
    """One shard scan, then ash merge --debug and ash report --debug over it.

    The scan's logger writes the JSONL log as well as ash.log in every run.
    """
    from automated_security_helper.utils import log, uv_tool_runner

    root = tmp_path_factory.mktemp("recorded")
    (root / "src" / ".ash").mkdir(parents=True)
    (root / "src" / "app.py").write_text("print('hello')\n", encoding="utf-8")
    (root / "src" / ".ash" / ".ash.yaml").write_text(CONFIG, encoding="utf-8")
    get_logger = log.get_logger

    def both(*args, **kwargs):
        kwargs["log_format"] = "BOTH"
        return get_logger(*args, **kwargs)

    runner = CliRunner()
    # Module-scoped, so this runs before any test's tool guard
    # (tests/unit/conftest.py) is in: it gets one of its own, with the same check.
    with pytest.MonkeyPatch.context() as mp:
        guard = install_tool_guard(
            mp,
            root / "guard-bin",
            own_directories=(tmp_path_factory.getbasetemp(),),
        )
        # The recorded configuration does not depend on whether detect-secrets is
        # installed, so its availability probe (uv tool run detect-secrets
        # --version) is not run: no uv is found, as under the child-process stubs
        # in tests/utils/tool_guard.py (CHILD_TOOL_PROBE_STUBS).
        mp.setattr(uv_tool_runner.UVToolRunner, "is_uv_available", lambda self: False)
        mp.setattr(uv_tool_runner, "find_uv_or_none", lambda: None)
        mp.setattr(uv_tool_runner, "_uv_command_cache", {})
        mp.setattr(uv_tool_runner, "_uv_command_binary", {})
        mp.setenv("ASH_PROBE_VALUE", CANARY)
        mp.delenv("ASH_CONFIG", raising=False)
        mp.setattr(log, "get_logger", both)
        mp.chdir(root)
        env = {"COLUMNS": "300"}
        scan = runner.invoke(
            app,
            [
                "scan",
                "--no-progress",
                "--source-dir",
                "src",
                "--output-dir",
                "shard",
                "--scanners",
                "detect-secrets",
                "--no-fail-on-incomplete-scanners",
                "--no-fail-on-findings",
                "--shard-index",
                "0",
                "--shard-count",
                "1",
            ],
            env=env,
        )
        shard_results = root / "shard" / "ash_aggregated_results.json"
        merge = runner.invoke(
            app,
            [
                "merge",
                "--results",
                str(shard_results),
                "--output-dir",
                "merged",
                "--no-fail-on-findings",
                "--debug",
            ],
            env=env,
        )
        report = runner.invoke(
            app,
            [
                "report",
                "--format",
                "gitlab-cyclonedx",
                "--output-dir",
                str(root / "shard"),
                "--debug",
            ],
            env=env,
        )
        started = guard.tool_starts
    reset_tool_lookup_caches()
    return {
        "root": root,
        "scan": scan,
        "merge": merge,
        "report": report,
        "tool_starts": started,
    }


def test_the_three_commands_start_no_tool(runs):
    """The scan asks for detect-secrets, and nothing here may start a tool to
    find out whether it is installed: that would depend on the host's uv and
    network, and write to the host's uv cache."""
    assert runs["tool_starts"] == [], runs["tool_starts"]


def _recorded_config(results_file: Path) -> str:
    data = json.loads(results_file.read_text(encoding="utf-8"))
    return json.dumps(data.get("ash_config"))


def _assert_as_written(results_file: Path) -> None:
    """Each reference where the file wrote it, and the key's reference as the key."""
    record = json.loads(results_file.read_text(encoding="utf-8"))["ash_config"]
    shown = {}
    for path in AS_WRITTEN:
        node = record
        for key in path:
            # A reporter's section is dumped under its alias or its field name
            # (the merged results are written without aliases).
            if isinstance(node, dict) and key not in node:
                key = key.replace("-", "_")
            node = node.get(key) if isinstance(node, dict) else None
        shown[path] = node
    assert shown == AS_WRITTEN, shown
    assert SECRET in (record.get("scanners") or {}), sorted(
        record.get("scanners") or {}
    )


def _assert_the_run_read_the_value(runs) -> None:
    """The control in every test here: the shard results were written, and the
    run read the canary from the environment. The configuration writes the bare
    ``${ASH_PROBE_VALUE}``, which refuses the configuration when the variable is
    unset, so the scan exiting 0 is the variable read. A canary absent because
    it was never read would otherwise pass every test. The run's own report
    names the project by the reference the configuration wrote."""
    assert runs["scan"].exit_code == 0, runs["scan"].output
    assert (runs["root"] / "shard" / "ash_aggregated_results.json").is_file()
    summary = (runs["root"] / "shard" / "reports" / "ash.summary.txt").read_text(
        encoding="utf-8"
    )
    assert f"Project: {SECRET}" in summary, summary
    assert CANARY not in summary


def test_the_scan_ran_with_the_value(runs):
    _assert_the_run_read_the_value(runs)


def _assert_no_value_recorded(results: Path) -> None:
    text = results.read_text(encoding="utf-8")
    # The control: the configuration was recorded, with the reporter's section.
    assert "gitlab-cyclonedx" in _recorded_config(results), text
    assert CANARY not in text, [
        line.strip() for line in text.splitlines() if CANARY in line
    ]
    _assert_as_written(results)
    # The project name the results carry for their reports is the reference too.
    metadata = json.loads(text)["metadata"]
    assert metadata["project_name"] == SECRET, metadata


def test_the_shard_records_each_reference_as_written(runs):
    _assert_the_run_read_the_value(runs)
    _assert_no_value_recorded(runs["root"] / "shard" / "ash_aggregated_results.json")


def test_the_merged_results_record_each_reference_as_written(runs):
    """merge reads the shard's record and does not resolve it again."""
    _assert_the_run_read_the_value(runs)
    assert runs["merge"].exit_code == 0, runs["merge"].output
    _assert_no_value_recorded(runs["root"] / "merged" / "ash_aggregated_results.json")


@pytest.mark.parametrize("command", ["merge", "report"])
def test_debug_output_holds_no_env_value(runs, command):
    _assert_the_run_read_the_value(runs)
    result = runs[command]
    directory = runs["root"] / ("merged" if command == "merge" else "shard")
    channels = {
        "stdout": result.stdout,
        "stderr": result.stderr,
        **{
            path.relative_to(runs["root"]).as_posix(): path.read_text(
                encoding="utf-8", errors="replace"
            )
            for path in _log_files(directory)
        },
    }
    # The control: the command ran, and the debug line showing a reporter's
    # section was written. Neither command writes a log file of its own (the
    # report's logs go to stderr); any log under its directory is read.
    assert result.exit_code == 0, result.output
    assert any(SHOWN_SECTION in text for text in channels.values()), list(channels)
    leaked = [name for name, text in channels.items() if CANARY in text]
    assert leaked == [], leaked


def test_the_scan_logs_hold_no_env_value(runs):
    _assert_the_run_read_the_value(runs)
    logs = _log_files(runs["root"] / "shard")
    # The control: both log files were written.
    assert {"ash.log", "ash.log.jsonl"} <= {path.name for path in logs}, logs
    leaked = [
        path.name
        for path in logs
        if CANARY in path.read_text(encoding="utf-8", errors="replace")
    ]
    assert leaked == [], leaked
