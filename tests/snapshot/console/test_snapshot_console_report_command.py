# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``ash report --format <f>`` for every ``ExportFormat`` value, through the real CLI.

``report_command`` writes a reporter's output to stdout exactly as the reporter produced it
when stdout is not a terminal, which it never is here (it pretty-prints JSON and renders
Markdown only on an interactive terminal). Formats with no reporter plugin print an error and
the list of formats that do exist, to stderr, recorded under a ``[stderr]`` heading. Each
format gets its own snapshot, headed by the command line and the exit code.

The results file is written the way a scan leaves it: metrics populated by
``populate_metrics_from_unified_source``, then ``AshAggregatedResults.save_model`` into
``tmp_path``. The command runs with the cwd moved there, so no ASH config from the repository
checkout is picked up and the plugin context's source dir is the temp tree. The process-wide
rich console is replaced with one pinned to 100 columns that writes to whatever
``sys.stdout`` is at the time, which is ``CliRunner``'s capture buffer during the call.

Run at ``--log-level ERROR``, which keeps ASH's INFO and WARNING log lines out of the
document. Those lines go to the same stdout, and they cannot be pinned: rich's log handler
prints the wall-clock time on a line only when the second has changed since the previous
line, so whether a line starts with a timestamp or with blanks depends on where a second
boundary fell during the run. The cost is that a reporter's WARNING, which an operator at
the default level sees, is not covered here.

The clock is pinned (``pinned_clock``, at ``REPORT_RENDERED_AT``) in every module that
stamps "now" into a report: ``FlatVulnerability.detected_at`` in every CSV, flat-JSON and
YAML row, the text and markdown reporters' "generated" line, the HTML footer and the OCSF
``time`` fields. Without it those differ on every run, and the CSV reporter's lines are
long enough that rich folds them at 100 columns in the middle of the timestamp, so no
masking rule could even find them. Pinned, each is a value a user reads and the snapshot
shows it as written.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli.main import app
from automated_security_helper.core.enums import ExportFormat
from automated_security_helper.core.unified_metrics import (
    populate_metrics_from_unified_source,
)
from tests.snapshot.console.console_inputs import (
    route_rich_print,
    scan_results_model,
    stdout_console,
)


#: The instant every reporter reads as "now" while a report renders.
REPORT_RENDERED_AT = datetime(2026, 1, 15, 12, 30, 0, tzinfo=timezone.utc)


@pytest.fixture
def results_dir(tmp_path, monkeypatch):
    output = tmp_path / "ash_output"
    populate_metrics_from_unified_source(scan_results_model()).save_model(output)
    monkeypatch.chdir(tmp_path)
    return output


@pytest.mark.parametrize("report_format", [f.value for f in ExportFormat])
def test_report_command(
    report_format, pinned_clock, results_dir, text_snapshot, monkeypatch
):
    route_rich_print(monkeypatch, stdout_console(100))
    pinned_clock.set(REPORT_RENDERED_AT)

    result = CliRunner().invoke(
        app,
        [
            "report",
            "--format",
            report_format,
            "--output-dir",
            results_dir.as_posix(),
            "--log-level",
            "ERROR",
        ],
    )

    # stdout is the report alone; an error goes to stderr, so a format with no
    # reporter records its message under a separate heading.
    document = (
        f"$ ash report --format {report_format} --log-level ERROR\n"
        f"[exit {result.exit_code}]\n"
        f"{result.stdout}"
    )
    if result.stderr:
        document += f"\n[stderr]\n{result.stderr}"
    assert document == text_snapshot("txt")
