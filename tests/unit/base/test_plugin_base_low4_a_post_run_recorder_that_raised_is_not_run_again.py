# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A post-run recorder that raised has had its one call.

``_run_subprocess`` records a response once per recorder. When something after the
run raises, its handler flags the response ``post_run_error`` and calls the
recorders the raise skipped. It also re-armed the ``post_run_error`` recorder,
because that recorder may have run before as a no-op on the unflagged response.
If it had instead raised, that raise was the error the handler caught, and calling
it again raised again: the recorder's text was added to the response's reason a
second time ("X; X"), and its side effects happened twice, against the rule that
a recorder that raised counts as run and is never called again.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Dict, List
from unittest.mock import patch

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.base.scanner_plugin import (
    ScannerPluginBase,
    ScannerPluginConfigBase,
)
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.utils import subprocess_utils

pytestmark = pytest.mark.unit

PluginContext.model_rebuild()
AshConfig.model_rebuild()
AshAggregatedResults.model_rebuild()

BROKE = "the post-run recorder broke"
CLEAN_RUN = {"returncode": 0, "stdout": "", "stderr": ""}


class _Config(ScannerPluginConfigBase):
    name: str = "post-run-recorder"


def _scanner_class(always: bool, fired: List[bool]):
    class _Scanner(ScannerPluginBase):
        def validate_plugin_dependencies(self) -> bool:
            return True

        def _execute_scan(self, target, target_type, global_ignore_paths):
            raise NotImplementedError("the runner is all this test calls")

        def _record_post_run_error(self, response: Dict[str, Any]) -> None:
            if always or not fired:
                fired.append(True)
                raise RuntimeError(BROKE)
            fired.append(False)
            super()._record_post_run_error(response)

    return _Scanner


def _run(tmp_path: Path, always: bool):
    source = tmp_path / "source"
    source.mkdir()
    output = tmp_path / "output"
    output.mkdir()
    context = PluginContext(
        source_dir=source,
        output_dir=output,
        work_dir=tmp_path / "work",
        config=AshConfig(project_name="post-run-recorder"),
    )
    fired: List[bool] = []
    scanner = _scanner_class(always, fired)(config=_Config(), context=context)

    with patch.object(
        subprocess_utils,
        "run_command_with_output_handling",
        side_effect=lambda *args, **kwargs: dict(CLEAN_RUN),
    ):
        try:
            response = scanner._run_subprocess(
                command=[sys.executable, "-c", "pass"],
                results_dir=tmp_path / "results",
                timeout=5,
            )
        except RuntimeError as error:
            pytest.fail(f"the recorder's error raised out of _run_subprocess: {error}")
    return scanner, response, fired


@pytest.mark.parametrize("always", [True, False], ids=["raises-always", "raises-once"])
def test_a_recorder_that_raised_is_called_once_and_named_once(tmp_path, always):
    scanner, response, fired = _run(tmp_path, always)

    assert fired == [True], fired
    error = response.get("error") or ""
    assert error.count(BROKE) == 1, response


def test_the_response_keeps_its_code_and_is_flagged_as_a_post_run_error(tmp_path):
    scanner, response, fired = _run(tmp_path, always=True)

    assert fired == [True]
    assert response.get("post_run_error") is True, response
    assert response.get("returncode") == 0, response
