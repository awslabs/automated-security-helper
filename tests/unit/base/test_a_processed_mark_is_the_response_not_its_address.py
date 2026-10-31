# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The "already processed" mark is the response object, retired when recorded.

``_run_subprocess`` folds a response into exit_code and errors exactly once:
the uv path asks whether the runner already processed the response before it
processes it itself. The mark was the response's ``id()`` in a set, and only
two paths discarded it; the refused-run and spawn-failure paths left it, so a
later response allocated at a recycled address would have read as already
processed and never reached exit_code and errors. The mark is now the object
itself (a held reference keeps its address taken) and every recorder retires
it.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from tests.unit.base.scanner_support import build_scanner as _scanner

pytestmark = pytest.mark.unit

_RUNNER = (
    "automated_security_helper.utils.subprocess_utils.run_command_with_output_handling"
)


def _response(returncode: int = 0) -> dict:
    return {"stdout": "", "stderr": "", "returncode": returncode}


def test_the_mark_holds_the_response_itself(plugin_context):
    scanner = _scanner(plugin_context)
    response = _response()

    scanner._process_command_response(response)
    # The caller sets the mark, after its own call (the uv mixin does); the
    # accumulator itself sets none.
    assert not scanner._was_processed(response)
    scanner._mark_processed(response)

    assert scanner._was_processed(response)
    # Held by identity, so the address cannot be recycled while marked, and an
    # equal but distinct dict is not the same response.
    assert any(seen is response for seen in scanner._processed_responses)
    assert not scanner._was_processed(_response())


def test_recording_retires_the_mark(plugin_context):
    scanner = _scanner(plugin_context)
    response = _response()
    scanner._process_command_response(response)
    scanner._mark_processed(response)
    assert scanner._was_processed(response)

    scanner._record_response(response, None, set())

    assert not scanner._was_processed(response)
    assert scanner._processed_responses == []


def test_the_spawn_failure_recorder_retires_the_mark_too(plugin_context):
    # The handler records a spawn failure through _record_spawn_failure
    # directly, outside _record_response; that route must retire the mark as
    # well, or a refused start would leave it behind.
    scanner = _scanner(plugin_context)
    failure = {
        "stdout": "",
        "stderr": "the tool was not run",
        "returncode": 127,
        "spawn_failed": True,
    }
    scanner._process_command_response(failure)
    scanner._mark_processed(failure)
    assert scanner._was_processed(failure)

    scanner._record_spawn_failure(failure)

    assert not scanner._was_processed(failure)


def test_a_refused_run_leaves_no_mark(plugin_context, tmp_path, monkeypatch):
    """The run is refused when the tool cannot start, and the handler records
    the failure through the spawn-failure recorder. The uv mixin marks a
    response right after it processes it; the marking stand-in below does the
    same, so the failure reaches the recorder marked. A recorder that left the
    mark would leave the response in the list for the plugin's life."""
    scanner = _scanner(plugin_context)
    scanner.use_uv_tool = False
    real = type(scanner)._process_command_response
    marked: list[dict] = []

    def _process_then_mark(self, response):
        real(self, response)
        self._mark_processed(response)
        marked.append(response)

    monkeypatch.setattr(type(scanner), "_process_command_response", _process_then_mark)

    with patch(_RUNNER, side_effect=OSError("could not start")):
        response = scanner._run_subprocess(
            ["stub-tool", "scan"], results_dir=str(tmp_path / "results")
        )

    assert response["spawn_failed"] is True
    # The stand-in did mark the failure on its way through: without this the
    # assertions below would pass for a run that never reached the recorder.
    assert any(seen is response for seen in marked), marked
    assert not scanner._was_processed(response)
    assert len(scanner._processed_responses) == 0, scanner._processed_responses
