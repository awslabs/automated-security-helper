# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The uv runner copies the could-not-stop state onto its typed result.

Both result builders are covered: the converted result built from a response
whose error can be shown, and the rebuilt one for an error that cannot.
"""

from unittest.mock import patch

import pytest

from automated_security_helper.utils.uv_tool_runner import (
    UVToolRunner,
    _reset_uv_tool_runner_caches,
)

pytestmark = pytest.mark.unit

_RCWOH = (
    "automated_security_helper.utils.subprocess_utils.run_command_with_output_handling"
)


class _Unprintable:
    def __str__(self):
        raise RuntimeError("the error cannot be shown")


@pytest.fixture(autouse=True)
def _isolate_module_caches():
    _reset_uv_tool_runner_caches()
    yield
    _reset_uv_tool_runner_caches()


@pytest.fixture
def runner():
    r = UVToolRunner(uv_executable="uv")
    r._uv_available_cache = True
    return r


@pytest.mark.parametrize(
    "flag", ["timed_out", "post_run_error"], ids=["timeout", "failed-wait"]
)
def test_the_converted_result_keeps_the_carrier(runner, tmp_path, flag):
    results_dir = tmp_path / "results"
    results_dir.mkdir()
    with patch(_RCWOH) as mock_run:
        mock_run.return_value = {
            "returncode": None,
            "stdout": "",
            "stderr": "",
            flag: True,
            "could_not_stop": True,
            "error": "the run's reason, with no marker",
        }
        result = runner.run_tool("bandit", args=[], results_dir=results_dir)
    assert getattr(result, flag, False) is True, result
    assert getattr(result, "could_not_stop", False) is True, result


@pytest.mark.parametrize(
    "flag", ["timed_out", "post_run_error"], ids=["timeout", "failed-wait"]
)
def test_the_rebuilt_result_keeps_the_carrier(runner, tmp_path, flag):
    results_dir = tmp_path / "results"
    results_dir.mkdir()
    with patch(_RCWOH) as mock_run:
        mock_run.return_value = {
            "returncode": None,
            "stdout": "",
            "stderr": "",
            flag: True,
            "could_not_stop": True,
            "error": _Unprintable(),
        }
        result = runner.run_tool("bandit", args=[], results_dir=results_dir)
    assert getattr(result, flag, False) is True, result
    assert getattr(result, "could_not_stop", False) is True, result
