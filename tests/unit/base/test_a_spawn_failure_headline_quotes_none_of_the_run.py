# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The headline of a "could not start its tool" failure quotes none of the run's text.

Why this file exists
--------------------
``scan()`` raises one message for a tool that could not start (``spawn_failed``).
Its first sentence used to end with the response's ``stderr`` (or its ``error``),
and ``_describe_scan_failure`` then added the same text again after "Stderr:".
The two copies were not redacted alike. The stored copy, the one in the scanner's
``errors``, is made by ``_process_command_response``, which for a uv run applies
the uv layer with the run's plugin-built inputs. The headline copy was the
response's text as the runner wrote it, and where an executor redacts the whole
message it gets only the plain-value layer, which matches a value as written and
so misses what uv respells and the ``--from`` and ``--with`` inputs that hold
one. Now the headline says only that the tool could not start and produced no
results file, and the stderr appears once, after "Stderr:".

What these cells measure
------------------------
The headline, and the Stderr part's single copy. The stand-in below returns the
response a production spawn failure returns, after the one step each such path in
``_run_subprocess`` takes before it returns (``_process_command_response``). It
does not run the recorders, which add their own lines to ``errors``; how those
lines are redacted is a separate question these cells do not answer.

No tool runs. The value is a placeholder-shaped string no real configuration
holds.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Tuple

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.base.scanner_plugin import (
    ScannerPluginBase,
    ScannerPluginConfigBase,
)
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.models.asharp_model import AshAggregatedResults

PluginContext.model_rebuild()
AshConfig.model_rebuild()
AshAggregatedResults.model_rebuild()

PLANTED = "PLACEHOLDERVALUE0001"

#: What a failed spawn's response says. It names the planted value the way a
#: command line holding an environment-read option does.
RUN_TEXT = f"could not run /opt/tool --token={PLANTED}"

#: The first part of the message's text after the headline: the failure's own
#: parenthetical (exit code and verdict) comes before it.
STDERR_PART = ". Stderr: "


class _Config(ScannerPluginConfigBase):
    name: str = "spawnfail"


class _Answering(ScannerPluginBase):
    """A template scanner whose run is answered with ``response``, after the step
    a production spawn-failure path takes before it returns, and whose values hook
    answers with ``hook_values``."""

    response: Dict[str, Any] = {}
    hook_values: Tuple[str, ...] = (PLANTED,)
    #: Set after construction, so the scan is what meets the raising hook
    #: whatever the constructor does with one.
    hook_raises: bool = False
    #: Whether the stand-in stores the response's stderr in ``errors`` as
    #: ``_run_subprocess`` does. Off, the message holds only what ``scan()`` itself
    #: put in it.
    stores_the_stderr: bool = True

    def validate_plugin_dependencies(self) -> bool:
        return True

    def _execute_scan(self, target, target_type, global_ignore_paths):
        results_file = Path(self.results_dir) / "results.sarif"
        results_file.parent.mkdir(parents=True, exist_ok=True)
        return ["planted-tool", "--scan"], results_file, None

    def _run_subprocess(self, *args, **kwargs):
        response = dict(self.response)
        if self.stores_the_stderr:
            self._process_command_response(response)
        return response

    def _values_to_redact(self):
        if self.hook_raises:
            raise RuntimeError("no values")
        return self.hook_values


def _context(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "app.py").write_text("print('x')\n")
    output = tmp_path / "output"
    output.mkdir()
    return PluginContext(
        source_dir=source,
        output_dir=output,
        work_dir=tmp_path / "work",
        config=AshConfig(project_name="test"),
    )


def _scanner(tmp_path, response, **fields):
    context = _context(tmp_path)
    scanner = _Answering(config=_Config(), context=context, response=response)
    for name, value in fields.items():
        setattr(scanner, name, value)
    return scanner, context


def _scan_message(scanner, context) -> str:
    with pytest.raises(ScannerError) as excinfo:
        scanner.scan(target=context.source_dir, target_type="source")
    return str(excinfo.value)


def _headline_part(message: str) -> str:
    """The message up to its Stderr part: the headline and the exit-code verdict."""
    return message.split(STDERR_PART, 1)[0]


@pytest.mark.parametrize("key", ["stderr", "error"])
def test_the_headline_quotes_neither_the_stderr_nor_the_error(tmp_path, key):
    """Nothing stored the run's text, so the message holds what ``scan()`` wrote
    itself, and none of the response's text is in it."""
    scanner, context = _scanner(
        tmp_path,
        {"spawn_failed": True, "returncode": 127, key: RUN_TEXT},
        stores_the_stderr=False,
    )

    message = _scan_message(scanner, context)

    assert "could not start its tool, so it produced no results file." in message, (
        message
    )
    assert "could not run /opt/tool" not in message, message
    assert PLANTED not in message, message


def test_a_spawn_failure_reports_its_stderr_once(tmp_path):
    """The Stderr part carries the stored copy, and the headline adds no second."""
    scanner, context = _scanner(
        tmp_path, {"spawn_failed": True, "returncode": 127, "stderr": RUN_TEXT}
    )

    message = _scan_message(scanner, context)

    assert "could not start its tool" in message, message
    assert message.count("could not run /opt/tool") == 1, message
    assert STDERR_PART in message, message
    assert "could not run /opt/tool" not in _headline_part(message), message
    assert PLANTED not in message, message


def test_a_spawn_failure_with_a_failing_values_hook_names_the_failure_only(tmp_path):
    """The hook that names the values to hide raised, so the stderr could not be
    stored: the message names the failure and quotes nothing of the run."""
    scanner, context = _scanner(
        tmp_path,
        {"spawn_failed": True, "returncode": 127, "stderr": RUN_TEXT},
        hook_raises=True,
    )

    message = _scan_message(scanner, context)

    assert "could not start its tool" in message, message
    assert "could not run /opt/tool" not in message, message
    assert PLANTED not in message, message


def test_a_uv_run_spawn_failure_adds_no_copy_beside_the_strongly_redacted_one(
    tmp_path,
):
    """For a uv run the stored copy goes through the uv layer with the run's
    plugin-built inputs. The headline adds no second copy of the stderr, which
    would carry the input's spelling as the runner wrote it, and the stored copy
    appears once. What the uv layer itself hides is the business of its own
    cells (tests/unit/utils/test_uv_tool_runner.py)."""
    planted_input = f"placeholder-extra=={PLANTED}"
    marker = "the runner refused to spawn it"

    class _UvRun(_Answering):
        def _uv_run_inputs_for_records(self):
            return (planted_input,)

    context = _context(tmp_path)
    scanner = _UvRun(
        config=_Config(),
        context=context,
        response={
            "spawn_failed": True,
            "returncode": 127,
            "stderr": f"{marker} --from {planted_input}",
        },
    )
    # After construction, so the run's setup does not read them while building.
    scanner.command = "planted-tool"
    scanner.use_uv_tool = True

    message = _scan_message(scanner, context)

    headline = _headline_part(message)
    assert "could not start its tool" in headline, message
    assert marker not in headline, message
    assert "placeholder-extra" not in headline, message
    assert message.count(marker) == 1, message
    assert PLANTED not in message, message
