# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Every exit-1 coverage message shows the names it quotes, and logs as text.

Under ``ash merge`` the names come from shard results any job in the matrix wrote,
and the merged model reaches the same _compute_exit_code an ordinary scan does.
Under real ``ash merge`` children, a scanner named "x\\e[31m\\n::error
title=merge::orphan" (in "Scan ran no scanners") and a converter error
"boom\\n##[error]r" (in "Conversion incomplete") are shown with ESC and the line
break written out, so no stdout line starts "::error" or "##[error]". The rules
arm and the stale-database arm show the names they quote the same way.
"""

from __future__ import annotations

import logging
import re
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from automated_security_helper.interactions import run_ash_scan
from automated_security_helper.interactions.run_ash_scan import (
    ScanIncompleteness,
    _compute_exit_code,
)
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.utils.content_db_staleness import ContentDbAgeRecord

pytestmark = pytest.mark.unit

#: ESC, and a newline that would start a GitHub Actions workflow command.
_HOSTILE = "x\x1b[31m\n::error title=merge::orphan"

#: A newline that would start GitHub's legacy annotation form.
_LEGACY = "x\n##[error]v1"

#: A control character a terminal acts on: C0 other than the newline, DEL and C1.
_RAW_CONTROL = re.compile(r"[\x00-\x09\x0b-\x1f\x7f-\x9f]")


def _assert_shown_not_obeyed(text: str) -> None:
    assert not _RAW_CONTROL.search(text), repr(text)
    # "::" at a line start, or "##" with an optional name and "[" anywhere; a
    # bare "##", a Markdown heading's, is no command.
    lines = re.split(r"[\r\n]", text)
    assert not [line for line in lines if line.lstrip().startswith("::")], repr(text)
    assert not re.search(r"##[A-Za-z]*\[", text), repr(text)


def _stale(name: str) -> ContentDbAgeRecord:
    now = datetime(2026, 10, 12, tzinfo=timezone.utc)
    return ContentDbAgeRecord(
        name=name,
        scanner=name,
        built=now - timedelta(days=30),
        measured_by="a test",
        max_age=timedelta(days=1),
        measured_at=now,
        policy="fail",
        bound_source="a test",
        bound_is_tool_default=False,
        refresh="run the refresh",
    )


_ARMS = {
    "incomplete-scanner": lambda name: ScanIncompleteness(
        scanners=((name, "ERROR"),), observed=((name, "ERROR"),)
    ),
    "no-scanner-ran": lambda name: ScanIncompleteness(
        no_scanner_ran=True, observed=((name, "SKIPPED"),)
    ),
    "conversion-incomplete": lambda name: ScanIncompleteness(
        converters=((name, f"boom\n{name}"),)
    ),
    "rule-not-evaluated": lambda name: ScanIncompleteness(unevaluated_rules=(name,)),
    "stale-database": lambda name: ScanIncompleteness(
        stale_content_databases=(_stale(name),)
    ),
}


@pytest.fixture
def scan_log(caplog, monkeypatch):
    """ASH's logger, where the exit code's reasons go, into caplog only."""
    from automated_security_helper.utils.log import ASH_LOGGER

    monkeypatch.setattr(ASH_LOGGER, "handlers", [caplog.handler])
    caplog.set_level(logging.ERROR, logger=ASH_LOGGER.name)
    return caplog


@pytest.mark.parametrize(
    "name", [_HOSTILE, _LEGACY, "[/x]"], ids=["esc", "legacy", "markup"]
)
@pytest.mark.parametrize("arm", sorted(_ARMS))
def test_the_message_shows_the_name_and_logs_as_text(scan_log, monkeypatch, arm, name):
    incompleteness = _ARMS[arm](name)
    monkeypatch.setattr(
        run_ash_scan, "scan_incompleteness", lambda *args, **kwargs: incompleteness
    )
    opts = SimpleNamespace(
        fail_on_incomplete_scanners=True,
        fail_on_findings=None,
        shard_index=None,
        shard_count=None,
    )

    assert _compute_exit_code(AshAggregatedResults(), opts) == 1

    assert scan_log.records, arm
    for record in scan_log.records:
        message = record.getMessage()
        _assert_shown_not_obeyed(message)
        # Text, not markup: "[/x]" raised MarkupError on a Rich handler.
        assert getattr(record, "markup", True) is False, message


@pytest.fixture
def ash_log(tmp_path, monkeypatch):
    """ASH's logger set up as a scan sets it up, ash.log under *tmp_path*: a reader."""
    from automated_security_helper.utils.log import ASH_LOGGER, get_logger

    monkeypatch.delenv("ASH_LOG_TO_STDERR", raising=False)
    monkeypatch.setattr(ASH_LOGGER, "handlers", [])
    get_logger(
        name="ash",
        level=logging.INFO,
        output_dir=tmp_path,
        show_progress=True,
        use_color=False,
    )

    def read() -> str:
        for handler in ASH_LOGGER.handlers:
            handler.flush()
        # Its bytes: text mode would turn a bare carriage return into "\n".
        return (tmp_path / "ash.log").read_bytes().decode("utf-8")

    yield read
    for handler in ASH_LOGGER.handlers:
        handler.close()


#: What each arm's line in ash.log starts with.
_SAYS = {
    "incomplete-scanner": "Scan incomplete: ",
    "no-scanner-ran": "Scan ran no scanners: ",
    "conversion-incomplete": "Conversion incomplete",
    "rule-not-evaluated": "rule(s) could not be evaluated",
    "stale-database": "content database(s) are past their declared age bound",
}


@pytest.mark.parametrize("arm", sorted(_ARMS))
def test_the_message_reaches_ash_log_shown_once(ash_log, monkeypatch, arm):
    """Through run_ash_scan's own logger, which is not under "ash", these would
    never reach ash.log, and logging's last resort would write them to stderr.
    Each is one ASH message: in ash.log, the name's ESC and newline shown once."""
    incompleteness = _ARMS[arm](_HOSTILE)
    monkeypatch.setattr(
        run_ash_scan, "scan_incompleteness", lambda *args, **kwargs: incompleteness
    )
    opts = SimpleNamespace(
        fail_on_incomplete_scanners=True,
        fail_on_findings=None,
        shard_index=None,
        shard_count=None,
    )

    assert _compute_exit_code(AshAggregatedResults(), opts) == 1

    # Each line's message, after ash.log's tab-separated time, level and place.
    lines = [line.split("\t", 3)[3] for line in ash_log().splitlines()]
    said = [line for line in lines if _SAYS[arm] in line]
    assert said, lines
    assert "x\\x1b[31m\\x0a::error title=merge::orphan" in said[0], said
    assert not [line for line in lines if "\\\\x" in line], lines
    for line in lines:
        _assert_shown_not_obeyed(line)


def test_no_results_reaches_ash_log(ash_log):
    opts = SimpleNamespace(
        fail_on_incomplete_scanners=True,
        fail_on_findings=None,
        shard_index=None,
        shard_count=None,
    )

    assert _compute_exit_code(None, opts) == 1

    assert "ASH scan produced no results" in ash_log()
