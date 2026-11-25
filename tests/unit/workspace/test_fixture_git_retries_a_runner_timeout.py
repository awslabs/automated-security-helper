# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The fixture git helper runs a call once more when a loaded runner times it out.

A ``git add`` of four small files hit the helper's 30 s bound on a loaded Windows
runner. The helper builds fixture repositories only, so it retries a timeout once with
the same bound and logs one line; a second timeout raises as it did before.
"""

from __future__ import annotations

import logging
import subprocess

import pytest

from tests.unit.workspace.test_execution import _FIXTURE_GIT_LOG, _git


pytestmark = pytest.mark.unit


def _timeout(argv, **kwargs):
    raise subprocess.TimeoutExpired(argv, kwargs["timeout"])


class _Collect(logging.Handler):
    """Collects what the fixture helper's own logger emits, whatever else is configured."""

    def __init__(self) -> None:
        super().__init__(level=logging.WARNING)
        self.records: list[logging.LogRecord] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)


def test_a_timeout_is_retried_once_and_the_retry_result_is_returned(
    tmp_path, monkeypatch
):
    calls = []
    done = subprocess.CompletedProcess(["git"], 0, stdout="ok", stderr="")

    def run(argv, **kwargs):
        calls.append(kwargs["timeout"])
        if len(calls) == 1:
            return _timeout(argv, **kwargs)
        return done

    monkeypatch.setattr(subprocess, "run", run)
    # Other tests in the same worker change logging: ASH's get_logger turns propagation
    # off, a configured logger can be disabled, and logging.disable can silence a level.
    # Any of them leaves caplog's root handler with nothing to see. The handler goes on
    # the helper's own logger, and the three switches are put back for this test only.
    handler = _Collect()
    was_disabled = _FIXTURE_GIT_LOG.disabled
    was_level = _FIXTURE_GIT_LOG.level
    was_silenced = logging.root.manager.disable
    _FIXTURE_GIT_LOG.disabled = False
    _FIXTURE_GIT_LOG.setLevel(logging.WARNING)  # also clears the enabled-for cache
    logging.disable(logging.NOTSET)
    _FIXTURE_GIT_LOG.addHandler(handler)
    try:
        result = _git(tmp_path, "add", ".")
    finally:
        _FIXTURE_GIT_LOG.removeHandler(handler)
        logging.disable(was_silenced)
        _FIXTURE_GIT_LOG.setLevel(was_level)
        _FIXTURE_GIT_LOG.disabled = was_disabled

    assert result is done
    assert calls == [30, 30]
    retries = [r for r in handler.records if "retrying once" in r.getMessage()]
    assert len(retries) == 1


def test_two_timeouts_raise(tmp_path, monkeypatch):
    calls = []

    def run(argv, **kwargs):
        calls.append(1)
        return _timeout(argv, **kwargs)

    monkeypatch.setattr(subprocess, "run", run)
    with pytest.raises(subprocess.TimeoutExpired):
        _git(tmp_path, "add", ".")

    assert len(calls) == 2
