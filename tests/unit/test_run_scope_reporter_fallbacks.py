# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The session-end scope reporter's own fallbacks cannot print a value.

The failure these pin
---------------------
The reporter composes its message from scope LABELS -- whatever name the
opening code chose, plus a raising close's type name -- so no piece of it is
this module's own text. The composed message is redacted before it is
written, and when that redaction itself raises the fallback names only the
COUNT; when the open-scopes read raises with an exception whose str() also
raises, the read arm's note says the text is not shown. Before these
fallbacks, a mutant that dropped either one survived every committed cell.
"""

from types import SimpleNamespace

import pytest


class _Recorder:
    def __init__(self):
        self.lines = []

    def write_line(self, message, **kwargs):
        self.lines.append(message)


def _session(recorder):
    pluginmanager = SimpleNamespace(
        get_plugin=lambda name: recorder if name == "terminalreporter" else None
    )
    config = SimpleNamespace(pluginmanager=pluginmanager)
    return SimpleNamespace(config=config, exitstatus=pytest.ExitCode.OK)


def test_a_raising_message_redaction_reports_the_count_only(monkeypatch):
    import tests.conftest as root_conftest

    monkeypatch.setattr(
        root_conftest, "_open_run_log_scopes", lambda: {"scope-Zq7Kx9Lm2Pw4Nv"}
    )
    import sys

    log_module = sys.modules.get("automated_security_helper.utils.log")
    assert log_module is not None, "the suite conftest imports ASH at load"
    monkeypatch.setattr(log_module, "close_run_log_scope", lambda scope: None)

    def _raises(text):
        raise TypeError("redaction drift")

    monkeypatch.setattr(root_conftest, "redacted_environment_values", _raises)
    recorder = _Recorder()
    session = _session(recorder)

    root_conftest._report_run_log_scopes_still_open(session)

    assert recorder.lines, "the reporter wrote nothing"
    line = recorder.lines[0]
    assert "could not be redacted" in line, line
    # The count names the guard's entries, since an entry can also be the
    # could-not-be-read notice or a close failure, not only an open scope.
    assert "the run log scope guard had 1 entry" in line, line
    assert "Zq7K" not in line, line
    assert session.exitstatus == pytest.ExitCode.TESTS_FAILED


def test_a_scopes_read_whose_error_text_is_unprintable_is_still_named(monkeypatch):
    import tests.conftest as root_conftest

    class _MuteDriftError(Exception):
        def __str__(self):
            raise ValueError("no text")

    def _raising_read():
        raise _MuteDriftError

    monkeypatch.setattr(root_conftest, "_open_run_log_scopes", _raising_read)
    recorder = _Recorder()
    session = _session(recorder)

    root_conftest._report_run_log_scopes_still_open(session)

    assert recorder.lines, "the reporter wrote nothing"
    line = recorder.lines[0]
    assert "could not be read" in line, line
    assert "its text could not be redacted, so it is not shown" in line, line
    assert "_MuteDriftError" in line, line
    assert session.exitstatus == pytest.ExitCode.TESTS_FAILED
