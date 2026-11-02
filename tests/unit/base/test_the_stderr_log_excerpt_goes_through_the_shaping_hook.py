# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The failure message's stderr log excerpt is shaped by the plugin's text hook.

``_tool_text_for_records`` is the hook a plugin overrides to hide what its
tool echoes back from its own input. ``_process_command_response`` applies it
to a run's stdout and stderr before the recorded lines are split. The failure
message of ``_describe_scan_failure`` quotes the tool's stderr log too, and
quoted it as the tool wrote it, so a plugin that hid a value from the
recorded lines still printed it in the message. The excerpt now goes through
the same hook, labelled "stderr", before it is redacted and cut. A hook that
raises, or answers something that is not text, drops the excerpt and the
message names the log instead of quoting it.
"""

from __future__ import annotations

import logging

import pytest

from tests.unit.base.test_a_rejected_runs_notification_excerpt_is_redacted import (
    _context,
)
from tests.unit.base.test_scanner_plugin_coverage import _scanner

pytestmark = pytest.mark.unit

PLANTED = "hunter2-planted-password"


def _results_file(tmp_path, log_text):
    results = tmp_path / "scanners" / "stub" / "results.json"
    results.parent.mkdir(parents=True)
    (results.parent / "StubScanner.stderr.log").write_text(log_text, encoding="utf-8")
    return results


def test_a_shaping_hook_hides_what_the_log_excerpt_would_quote(tmp_path, monkeypatch):
    scanner = _scanner(_context(tmp_path, ()))
    results = _results_file(tmp_path, f"bad credentials {PLANTED} in the config\n")
    seen: dict[str, str] = {}

    def _without_the_planted(self, text, stream):
        seen[stream] = text
        return text.replace(PLANTED, "[removed]")

    monkeypatch.setattr(type(scanner), "_tool_text_for_records", _without_the_planted)

    detail = scanner._describe_scan_failure(RuntimeError("broke"), results)

    assert PLANTED not in detail, detail
    assert "bad credentials [removed] in the config" in detail, detail
    # The hook was given the log's own text, under the stderr label.
    assert set(seen) == {"stderr"}, seen
    assert PLANTED in seen["stderr"], seen


def test_the_hook_shapes_the_log_beside_a_note_ash_wrote(tmp_path, monkeypatch):
    scanner = _scanner(_context(tmp_path, ()))
    results = _results_file(tmp_path, f"saw {PLANTED} again\n")
    scanner._plugin_log("the run timed out", level=logging.ERROR)
    monkeypatch.setattr(
        type(scanner),
        "_tool_text_for_records",
        lambda self, text, stream: text.replace(PLANTED, "[removed]"),
    )

    detail = scanner._describe_scan_failure(RuntimeError("broke"), results)

    assert PLANTED not in detail, detail
    assert "saw [removed] again" in detail, detail
    assert "the run timed out" in detail, detail


@pytest.mark.parametrize(
    "answer",
    [RuntimeError("shaping broke on SHAPECANARY-4d2"), None, 7],
    ids=["raises", "answers None", "answers a number"],
)
def test_a_broken_hook_drops_the_excerpt_and_names_the_log(
    tmp_path, monkeypatch, answer
):
    scanner = _scanner(_context(tmp_path, ()))
    results = _results_file(tmp_path, f"bad credentials {PLANTED} here\n")

    def _broken(self, text, stream):
        if isinstance(answer, Exception):
            raise answer
        return answer

    monkeypatch.setattr(type(scanner), "_tool_text_for_records", _broken)

    detail = scanner._describe_scan_failure(RuntimeError("broke"), results)

    assert PLANTED not in detail, detail
    assert "bad credentials" not in detail, detail
    assert "SHAPECANARY" not in detail, detail
    assert "Stderr was captured but could not be shown" in detail, detail
    assert "StubScanner.stderr.log" in detail, detail


def test_the_default_hook_keeps_the_log_text(tmp_path):
    """The control: with no override the excerpt is the log's text."""
    scanner = _scanner(_context(tmp_path, ()))
    results = _results_file(tmp_path, "the tool wrote this\n")

    detail = scanner._describe_scan_failure(RuntimeError("broke"), results)

    assert "the tool wrote this" in detail, detail
    assert "could not be shown" not in detail, detail
