# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A refused scanner result names the launch that produced it.

When a tool exits outside ``success_exit_codes`` the failure read "scan failed:
its tool exited with code N ... Stderr not read ...": the code, but not WHICH
resolved file ran, nor whether the run went through uv tool run or directly.
checkov resolves differently on the two arms, so a CI read of that message
could not tell which binary to look at, and a diagnosis started from the wrong
one.

Now the run's response carries the arm (``launch_arm``, tagged by
``_run_subprocess``) and the program the spawn layer resolved
(``resolved_program``, the spawned argv's first element), the scanner records
them beside the exit code (``_record_target_exit_code``), and the refusal
names them: "its tool (launched directly as /resolved/fake-tool) exited with
code 7, ...". A response that carries neither (a test double, an override's
own dict) keeps the old message.

The tool here is faked through the monkeypatched resolution layer: the fake
``run_command_with_output_handling`` answers what the real one's
``_resolve_for_spawn`` pass produces, so no process is spawned and nothing
touches the network. The uv arm's carry through ``uv_tool_runner`` and
``_uv_response`` follows the same pattern as ``could_not_stop`` and is pinned
here at the response level (the wording), not by running uv.
"""

from __future__ import annotations

from pathlib import Path
from typing import ClassVar, Optional
from unittest.mock import MagicMock

import pytest

from automated_security_helper.base.scanner_plugin import ScannerPluginBase
from automated_security_helper.core.exceptions import ScannerError

pytestmark = pytest.mark.unit


def _fake_scanner(tmp_path: Path, response: Optional[dict] = None):
    """A scanner over the real template whose run answers ``response``."""
    source_dir = tmp_path / "src"
    source_dir.mkdir(parents=True, exist_ok=True)
    (source_dir / "app.py").write_text("print('x')\n", encoding="utf-8")
    output_dir = tmp_path / "out"
    results_file = output_dir / "scanners" / "fake" / "results.json"

    class _FakeScanner(ScannerPluginBase):
        fake_response: ClassVar[Optional[dict]] = response
        fake_results_file: ClassVar[Path] = results_file

        def model_post_init(self, context) -> None:
            return None

        def validate_plugin_dependencies(self) -> bool:
            return True

        def _execute_scan(self, target, target_type, global_ignore_paths):
            return (["fake-tool", "--scan"], self.fake_results_file, None)

        def _run_subprocess(self, command, results_dir=None, **kwargs):
            answered = dict(self.fake_response or {})
            self.exit_code = answered.get("returncode")
            return answered

    context = MagicMock()
    context.source_dir = source_dir
    context.output_dir = output_dir
    context.work_dir = tmp_path / "work"
    scanner = _FakeScanner.model_construct()
    scanner.context = context
    scanner.config = MagicMock()
    scanner.config.name = "fake-tool"
    scanner.errors = []
    scanner.output = []
    scanner.exit_code = 0
    scanner.results_dir = output_dir / "scanners" / "fake"
    return scanner


def _failure(scanner, target: Path) -> str:
    with pytest.raises(ScannerError) as raised:
        scanner.scan(target=target, target_type="source")
    return str(raised.value)


def test_a_refused_direct_run_names_the_resolved_program(tmp_path):
    """The record ties the refused code to the resolved file and the arm."""
    scanner = _fake_scanner(
        tmp_path,
        response={
            "returncode": 7,
            "launch_arm": "direct",
            "resolved_program": "/resolved/bin/fake-tool",
        },
    )

    message = _failure(scanner, tmp_path / "src")

    assert "launched directly as /resolved/bin/fake-tool" in message
    assert "exited with code 7" in message


def test_a_refused_uv_run_names_uv_and_the_arm(tmp_path):
    """On the uv arm the resolved program is uv itself, and the message says
    the run went through uv tool run."""
    scanner = _fake_scanner(
        tmp_path,
        response={
            "returncode": 7,
            "launch_arm": "uv-tool",
            "resolved_program": "/resolved/bin/uv",
        },
    )

    message = _failure(scanner, tmp_path / "src")

    assert "launched through uv tool run as /resolved/bin/uv" in message
    assert "exited with code 7" in message


def test_a_response_without_launch_info_keeps_the_old_message(tmp_path):
    """The control: a response that carries no launch (an override's own dict,
    a test double) refuses with the old wording and claims nothing."""
    scanner = _fake_scanner(tmp_path, response={"returncode": 7})

    message = _failure(scanner, tmp_path / "src")

    assert "its tool exited with code 7" in message
    assert "launched" not in message


def test_a_launch_is_never_carried_from_the_previous_target(tmp_path):
    """A second run whose response carries no launch does not reuse the first
    run's: the record is set for every response, None included."""
    scanner = _fake_scanner(
        tmp_path,
        response={
            "returncode": 7,
            "launch_arm": "direct",
            "resolved_program": "/resolved/bin/fake-tool",
        },
    )
    first = _failure(scanner, tmp_path / "src")
    assert "launched directly" in first

    type(scanner).fake_response = {"returncode": 7}
    second = _failure(scanner, tmp_path / "src")

    assert "its tool exited with code 7" in second
    assert "launched" not in second


def test_the_direct_arm_tags_the_response_with_the_resolved_program(
    tmp_path, monkeypatch
):
    """The chain under the template: the real ``_run_subprocess`` hands the
    command to the runner, whose monkeypatched resolution answers the resolved
    argv0; the response comes back tagged with the arm, and the refusal built
    from it names both."""
    resolved = str(tmp_path / "resolved" / "fake-tool")

    def _resolving_runner(command, **kwargs):
        # What the real runner returns after _resolve_for_spawn replaced the
        # copied argv's first element: the tool ran and exited 7.
        assert command[0] == "fake-tool"
        return {"returncode": 7, "resolved_program": resolved}

    monkeypatch.setattr(
        "automated_security_helper.utils.subprocess_utils."
        "run_command_with_output_handling",
        _resolving_runner,
    )

    scanner = _fake_scanner(tmp_path)
    scanner.command = "fake-tool"
    scanner.use_uv_tool = False
    # The real base _run_subprocess, not the fixture's stub.
    run = ScannerPluginBase._run_subprocess.__get__(scanner)
    # The values hook reads the mocked config on this double; the real run
    # refuses a broken hook, so the double answers "no values" cleanly.
    monkeypatch.setattr(type(scanner), "_values_to_redact", lambda self: ())

    response = run(
        command=["fake-tool", "--scan"],
        results_dir=scanner.results_dir,
        cwd=tmp_path / "src",
    )

    assert response["launch_arm"] == "direct"
    assert response["resolved_program"] == resolved

    scanner._record_target_exit_code(response)
    with pytest.raises(Exception) as raised:
        scanner._refuse_rejected_exit_code()

    message = str(raised.value)
    assert f"launched directly as {resolved}" in message
    assert "exited with code 7" in message
