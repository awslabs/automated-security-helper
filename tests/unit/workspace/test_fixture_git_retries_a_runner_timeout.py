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

from tests.unit.workspace.test_execution import _git


pytestmark = pytest.mark.unit


def _timeout(argv, **kwargs):
    raise subprocess.TimeoutExpired(argv, kwargs["timeout"])


def test_a_timeout_is_retried_once_and_the_retry_result_is_returned(
    tmp_path, monkeypatch, caplog
):
    calls = []
    done = subprocess.CompletedProcess(["git"], 0, stdout="ok", stderr="")

    def run(argv, **kwargs):
        calls.append(kwargs["timeout"])
        if len(calls) == 1:
            return _timeout(argv, **kwargs)
        return done

    monkeypatch.setattr(subprocess, "run", run)
    with caplog.at_level(logging.WARNING):
        result = _git(tmp_path, "add", ".")

    assert result is done
    assert calls == [30, 30]
    retries = [r for r in caplog.records if "retrying once" in r.getMessage()]
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
