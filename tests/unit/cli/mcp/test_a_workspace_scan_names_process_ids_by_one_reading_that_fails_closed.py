# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Whether a workspace scan names process ids is one reading, and it fails closed.

A reason for a tool a cancel could not end names the pid of that tool, and a
remote client is not told it. Two things let it through or let the readings
differ:

* ``_project_coverage`` and ``_project_verdicts`` named the pids unless the
  caller said otherwise, so a new call that forgot the flag handed them to a
  remote client. They now name none unless asked.
* ``caller_is_remote`` was evaluated once per closed project, once for the
  reasons recorded at a cancel and once for the response, at different moments
  (one on the worker thread after a cancelled call had returned), so the stored
  and the returned readings could differ. ``_scan_workspace`` reads it once and
  hands the answer on, and ``_close_registrations`` reads it once per call.
"""

from __future__ import annotations

from typing import Any, Dict
from unittest.mock import patch

import pytest

from automated_security_helper.core.resource_management.scan_registry import (
    ScanRegistry,
)
from automated_security_helper.utils.subprocess_utils import (
    COULD_NOT_STOP_REASON,
    could_not_stop_default,
)
from tests.unit.cli.mcp.test_workspace_verdict_projection import (
    _module,
    _outcome,
    _payload,
)

pytestmark = pytest.mark.unit

PID = 4242


def test_the_verdicts_name_no_process_id_unless_asked():
    payload = _payload(
        _outcome("api", unstoppable_tools={"bandit": could_not_stop_default(PID)})
    )

    verdicts = _module()._project_verdicts(payload, {"api": "scan-1"})

    # RED at the base: the default named the pid, so a call that forgot the flag
    # handed it to a remote client.
    assert verdicts[0]["unstoppable_tools"] == {"bandit": COULD_NOT_STOP_REASON}


def test_the_coverage_names_no_process_id_unless_asked():
    outcome = _outcome(
        "api", unstoppable_tools={"bandit": could_not_stop_default(PID)}
    )

    coverage = _module()._project_coverage(outcome)

    assert [row["reason"] for row in coverage["could_not_stop"]] == [
        COULD_NOT_STOP_REASON
    ]


def test_a_local_caller_that_asks_for_the_pid_still_reads_it():
    """Control, green on both sides: the flag is honored when it is passed."""
    reason = could_not_stop_default(PID)
    payload = _payload(_outcome("api", unstoppable_tools={"bandit": reason}))

    verdicts = _module()._project_verdicts(
        payload, {"api": "scan-1"}, name_process_ids=True
    )
    coverage = _module()._project_coverage(
        payload.projects[0], name_process_ids=True
    )

    assert verdicts[0]["unstoppable_tools"] == {"bandit": reason}
    assert coverage["could_not_stop"][0]["reason"] == reason


def _close(tmp_path, count: int, **close_kwargs: Any) -> Dict[str, int]:
    """Close ``count`` completed projects; how often the caller was asked about."""
    ws = _module()
    registry = ScanRegistry()
    registered: Dict[str, str] = {}
    outcomes = []
    for index in range(count):
        key = f"project-{index}"
        directory = tmp_path / key
        directory.mkdir()
        registered[key] = registry.register_scan(
            directory_path=str(directory), output_directory=str(directory)
        )
        outcomes.append(_outcome(key, output_path=str(directory)))
    payload = _payload(*outcomes)
    asked = {"count": 0}

    def caller_is_remote(session_id):
        asked["count"] += 1
        return True

    with (
        patch.object(ws, "get_scan_registry", return_value=registry),
        patch.object(ws, "caller_is_remote", side_effect=caller_is_remote),
    ):
        ws._close_registrations(
            registered, payload, session_id="the-calling-session", **close_kwargs
        )
    return asked


def test_closing_three_projects_reads_the_caller_once(tmp_path):
    asked = _close(tmp_path, 3)

    # RED at the base: once per completed project, so three.
    assert asked["count"] == 1


def test_a_reading_the_caller_already_took_is_not_taken_again(tmp_path):
    asked = _close(tmp_path, 3, name_process_ids=False)

    assert asked["count"] == 0
