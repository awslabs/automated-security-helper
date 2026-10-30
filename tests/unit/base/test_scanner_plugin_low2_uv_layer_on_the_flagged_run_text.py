# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A uv run's flagged-response text gets the uv layer, not only the plain one.

``scan()`` raises one message for a run that ended on a signal ASH did not send
(``signaled``) and one for a run whose output ASH could not record
(``post_run_error``). Both quote the response's error through
``_text_without_hooked_values``, which matched a configured value only as it was
written. uv respells a version it quotes ("9.9.9-RC777" prints as "9.9.9rc777"),
so the respelled form was left in the message. For a uv run the text now goes
through ``shown_uv_output``, as the stderr lines and the log excerpt do. A raise
from that layer leaves the text out and keeps the headline: the plain layer
would print the respelled form, and the real error is still not replaced.
"""

from __future__ import annotations

import pytest

from automated_security_helper.core.exceptions import ScannerError
from tests.unit.base.test_a_spawn_failure_headline_quotes_none_of_the_run import (
    _Answering,
    _Config,
    _context,
)

pytestmark = pytest.mark.unit

#: An environment-read version, as the config wrote it, and as uv prints it.
VALUE = "9.9.9-RC777"
RESPELLED = "9.9.9rc777"

FLAGS = [
    pytest.param("signaled", "did not finish", id="signaled"),
    pytest.param(
        "post_run_error",
        "ran, but ASH could not record the scanner's output",
        id="post-run-error",
    ),
]


class _UvRun(_Answering):
    """A template scanner whose run is answered with ``response``, run through uv
    with no plugin-built inputs."""

    def _uv_run_inputs_for_records(self):
        return ()


class _UvRunWhoseInputsRaise(_Answering):
    """The same, whose inputs hook raises: a raise from the uv layer's setup."""

    def _uv_run_inputs_for_records(self):
        raise RuntimeError("the inputs could not be built")


def _message(tmp_path, scanner_class, flag, error_text, *, uv=True) -> str:
    context = _context(tmp_path)
    scanner = scanner_class(
        config=_Config(),
        context=context,
        response={"returncode": 3, flag: True, "error": error_text},
        hook_values=(VALUE,),
        stores_the_stderr=False,
    )
    # After construction, so the run's setup does not read them while building.
    scanner.command = "planted-tool"
    scanner.use_uv_tool = uv
    with pytest.raises(ScannerError) as excinfo:
        scanner.scan(target=context.source_dir, target_type="source")
    return str(excinfo.value)


@pytest.mark.parametrize("flag,headline", FLAGS)
def test_a_value_uv_respelled_is_hidden_in_a_flagged_runs_message(
    tmp_path, flag, headline
):
    message = _message(
        tmp_path, _UvRun, flag, f"uv was ended while it resolved {RESPELLED}"
    )

    assert headline in message, message
    assert "while it resolved" in message, message
    assert RESPELLED not in message, message
    assert VALUE not in message, message


@pytest.mark.parametrize("flag,headline", FLAGS)
def test_a_value_as_written_is_still_hidden_in_a_flagged_runs_message(
    tmp_path, flag, headline
):
    message = _message(
        tmp_path, _UvRun, flag, f"uv was ended while it resolved {VALUE}"
    )

    assert headline in message, message
    assert VALUE not in message, message


@pytest.mark.parametrize("spelling", [VALUE, RESPELLED], ids=["written", "respelled"])
@pytest.mark.parametrize("flag,headline", FLAGS)
def test_a_raise_from_the_uv_layer_withholds_the_text_and_keeps_the_headline(
    tmp_path, flag, headline, spelling
):
    # The plain layer matches a value only as it was written, so it would
    # print the form uv respelled: the text is left out, as it is when the
    # values hook raises, and the headline still says what happened.
    message = _message(
        tmp_path,
        _UvRunWhoseInputsRaise,
        flag,
        f"uv was ended while it resolved {spelling}",
    )

    assert headline in message, message
    assert "text not shown" in message, message
    assert "while it resolved" not in message, message
    assert VALUE not in message, message
    assert RESPELLED not in message, message
