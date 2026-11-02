# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The scanner base owns the four readings of a flagged run.

``ScannerPluginBase.scan`` says "timed out", "could not start", "ran, but ASH
could not record the output" or "did not finish" before it reads a results file
the run may never have written. Four scanners that override ``scan()`` (syft,
ferret, snyk-code, trivy-repo) each kept an identical copy of those readings,
and the copies read the values hook bare: a hook that raised replaced the
timeout as the scan's error. The readings are one base method now,
``_refuse_flagged_response(response, timeout)``, which ``scan()`` calls and an
overriding scanner can call; the hook is read once, guarded.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from automated_security_helper.core.exceptions import ScannerError
from tests.unit.base.scanner_support import (
    build_scanner,
    execute_writing,
    populated_target,
)

pytestmark = pytest.mark.unit


def _raising_hook(*_args, **_kwargs):
    raise RuntimeError("hook broke on HOOKCANARY-81")


def test_a_timed_out_run_names_the_timeout_and_the_option(plugin_context):
    scanner = build_scanner(plugin_context)

    with pytest.raises(ScannerError) as excinfo:
        scanner._refuse_flagged_response({"timed_out": True}, 5)

    message = str(excinfo.value)
    assert "timed out after '5' s" in message, message
    assert "scanners.stub.options.scan_timeout" in message, message
    assert "produced no results file" in message, message


def test_a_raising_values_hook_does_not_replace_the_timeout(plugin_context):
    scanner = build_scanner(plugin_context)

    with patch.object(scanner, "_values_to_redact", side_effect=_raising_hook):
        with pytest.raises(ScannerError) as excinfo:
            scanner._refuse_flagged_response({"timed_out": True}, 5)

    message = str(excinfo.value)
    assert "timed out" in message, message
    assert "The limit is not shown" in message, message
    assert "HOOKCANARY" not in message, message


def test_a_run_that_could_not_start_is_named(plugin_context):
    scanner = build_scanner(plugin_context)

    with pytest.raises(ScannerError) as excinfo:
        scanner._refuse_flagged_response({"spawn_failed": True}, None)

    assert "could not start its tool" in str(excinfo.value)


def test_a_run_whose_output_could_not_be_recorded_is_named_with_its_error(
    plugin_context,
):
    scanner = build_scanner(plugin_context)

    with pytest.raises(ScannerError) as excinfo:
        scanner._refuse_flagged_response(
            {"post_run_error": True, "error": "the log broke"}, None
        )

    message = str(excinfo.value)
    assert "ran, but ASH could not record the scanner's output" in message, message
    assert "the log broke" in message, message


def test_a_run_ended_by_a_signal_is_named_with_its_error(plugin_context):
    scanner = build_scanner(plugin_context)

    with pytest.raises(ScannerError) as excinfo:
        scanner._refuse_flagged_response(
            {"signaled": True, "error": "ended on signal 9"}, None
        )

    message = str(excinfo.value)
    assert "did not finish" in message, message
    assert "ended on signal 9" in message, message


def test_a_raising_hook_withholds_the_error_text_of_a_recorded_failure(plugin_context):
    scanner = build_scanner(plugin_context)

    with patch.object(scanner, "_values_to_redact", side_effect=_raising_hook):
        with pytest.raises(ScannerError) as excinfo:
            scanner._refuse_flagged_response(
                {"post_run_error": True, "error": "saw HOOKCANARY in the log"}, None
            )

    message = str(excinfo.value)
    assert "ran, but ASH could not record the scanner's output" in message, message
    assert "HOOKCANARY" not in message, message


@pytest.mark.parametrize(
    "response",
    [None, "text", {}, {"returncode": 0}, {"timed_out": False, "signaled": None}],
    ids=["none", "text", "empty", "plain run", "false flags"],
)
def test_a_response_with_no_flag_is_left_alone(plugin_context, response):
    scanner = build_scanner(plugin_context)

    assert scanner._refuse_flagged_response(response, 5) is None


def test_scan_reads_a_flagged_run_through_the_base_method(plugin_context, tmp_path):
    """scan() routes a flagged response through the method, with the timeout it ran
    under, so an override of the method changes what the template says."""
    scanner = build_scanner(plugin_context, execute_scan=execute_writing(None))
    scanner.config.options.scan_timeout = 7
    target = populated_target(tmp_path)
    seen = []

    class _Reached(Exception):
        pass

    def _record(self, response, timeout):
        seen.append((response, timeout))
        raise _Reached

    with (
        patch.object(type(scanner), "_run_subprocess", return_value={"signaled": True}),
        patch.object(type(scanner), "_refuse_flagged_response", _record),
        pytest.raises(Exception) as excinfo,
    ):
        scanner.scan(target=target, target_type="source")

    assert seen == [({"signaled": True}, 7)], (seen, excinfo.value)
