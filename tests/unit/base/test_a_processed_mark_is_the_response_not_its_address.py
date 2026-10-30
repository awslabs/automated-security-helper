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

from types import SimpleNamespace

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.constants import ASH_WORK_DIR_NAME
from tests.unit.base.test_scanner_plugin_coverage import _scanner

pytestmark = pytest.mark.unit


@pytest.fixture
def plugin_context(tmp_path):
    source_dir = tmp_path / "source"
    source_dir.mkdir()
    output_dir = tmp_path / "output"
    output_dir.mkdir()
    work_dir = output_dir / ASH_WORK_DIR_NAME
    work_dir.mkdir()
    return PluginContext(
        source_dir=source_dir,
        output_dir=output_dir,
        work_dir=work_dir,
        config=AshConfig(project_name="test"),
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


def test_a_retired_mark_does_not_shadow_the_next_response(plugin_context):
    scanner = _scanner(plugin_context)
    first = _response(returncode=1)
    scanner._process_command_response(first)
    scanner._mark_processed(first)
    scanner._record_response(first, None, set())

    second = _response(returncode=3)
    assert not scanner._was_processed(second)
    scanner._process_command_response(second)

    assert scanner.exit_code == 3


def test_the_uv_handlers_failed_copy_takes_over_the_mark(plugin_context, monkeypatch):
    """When processing a uv run's response raises after the response was marked,
    the handler returns a copy with the error added, and that copy is what the
    dispatcher sees. The mark has to move to the copy: left on the original,
    the dispatcher read the copy as unprocessed and processed the same run's
    output and error lines a second time."""
    scanner = _scanner(plugin_context)
    original = type(scanner)._process_command_response

    def process_then_raise(self, response):
        original(self, response)
        raise RuntimeError("handling raised after the mark was set")

    monkeypatch.setattr(type(scanner), "_process_command_response", process_then_raise)

    failed = scanner._uv_response(
        SimpleNamespace(stdout="", stderr="", returncode=0), None
    )

    assert failed.get("post_run_error") is True
    assert scanner._was_processed(failed)
    # The original response's mark is retired with the move: one mark, the copy's.
    assert len(scanner._processed_responses) == 1
