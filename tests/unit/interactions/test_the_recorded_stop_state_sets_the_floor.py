# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The exit-1 floor keys on the recorded could-not-stop state alone.

Built on the helpers of test_a_child_ash_could_not_stop_fails_the_run.py,
which drive a real ScanPhase. The state can arrive without a timeout: a failed
wait whose stop the kernel refused records post_run_error and the carrier, and
the floor holds for it too.
"""

import pytest

from interactions.test_a_child_ash_could_not_stop_fails_the_run import (
    _exit_code_and_log,
    _results_of_a_run,
)

pytestmark = pytest.mark.unit


def test_a_post_run_could_not_stop_sets_the_floor_without_a_timeout(tmp_path):
    response = {
        "returncode": None,
        "post_run_error": True,
        "spawn_failed": False,
        "could_not_stop": True,
        "error": "ASH stopped the tool after: reading failed; ASH could not stop "
        "the tool (pid 4243), which may still be running",
    }
    results = _results_of_a_run(tmp_path, response)
    code, logged = _exit_code_and_log(
        results, tmp_path, fail_on_incomplete_scanners=False
    )
    assert code == 1, (code, logged)
