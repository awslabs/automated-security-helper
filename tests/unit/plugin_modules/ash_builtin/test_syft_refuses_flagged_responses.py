# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""syft's own scan() refuses a run the subprocess layer flagged, as the template does.

``SyftScanner.scan`` overrides the template's ``scan()`` and read the results file
straight after the run. A killed tool writes no file, so a timeout surfaced as
"No such file or directory"; a tool that could not start the same; a tool that
ran while ASH could not record its output (exit 0, a file that may be complete)
was graded on that file; a tool a signal ASH did not send ended was graded on a
partial file. The four readings ``ScannerPluginBase.scan`` makes for every
template scanner now run here too, before the file is read.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.plugin_modules.ash_builtin.scanners.syft_scanner import (
    SyftScanner,
    SyftScannerConfig,
    SyftScannerConfigOptions,
)
from automated_security_helper.schemas.cyclonedx_bom_1_6_schema import CycloneDXReport

pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
def _offline(monkeypatch):
    monkeypatch.setenv("ASH_OFFLINE", "YES")


@pytest.fixture
def scanner(tmp_path) -> SyftScanner:
    context = PluginContext(
        source_dir=tmp_path / "src",
        output_dir=tmp_path / "out",
        work_dir=tmp_path / "out" / "converted",
        config=get_default_config(),
    )
    for path in (context.source_dir, context.output_dir, context.work_dir):
        path.mkdir(parents=True, exist_ok=True)
    (context.source_dir / "requirements.txt").write_text("requests==2.19.0\n")
    scanner = SyftScanner(
        context=context, config=SyftScannerConfig(options=SyftScannerConfigOptions())
    )
    scanner.dependencies_satisfied = True
    return scanner


def _scan_with(scanner: SyftScanner, response: dict, *, write_results: bool = False):
    def run(command, **kwargs):
        if write_results:
            (value,) = [a for a in command if str(a).startswith("cyclonedx-json=")]
            destination = Path(str(value).split("=", 1)[1])
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text(
                json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.6"})
            )
        return response

    with (
        patch.object(scanner, "_pre_scan", return_value=True),
        patch.object(scanner, "_post_scan"),
        patch.object(scanner, "_run_subprocess", side_effect=run),
    ):
        return scanner.scan(
            target=Path(scanner.context.source_dir), target_type="source"
        )


def test_a_timed_out_run_is_reported_as_a_timeout(scanner):
    """A results file is present, as a killed tool can leave a partial one: the
    flag is read before the file, so the file is not what grades the run."""
    with pytest.raises(ScannerError) as excinfo:
        _scan_with(scanner, {"returncode": -9, "timed_out": True}, write_results=True)

    message = str(excinfo.value)
    assert "timed out" in message, message
    assert "scan_timeout" in message, message
    assert "No such file" not in message, message


def test_a_tool_that_could_not_start_is_reported_as_such(scanner):
    with pytest.raises(ScannerError) as excinfo:
        _scan_with(
            scanner, {"returncode": 127, "spawn_failed": True}, write_results=True
        )

    message = str(excinfo.value)
    assert "could not start" in message, message
    assert "No such file" not in message, message


def test_a_run_whose_output_could_not_be_recorded_is_not_graded_on_its_file(scanner):
    """Exit 0 and a complete-looking file: the template refuses it, so does syft."""
    with pytest.raises(ScannerError) as excinfo:
        _scan_with(
            scanner,
            {"returncode": 0, "post_run_error": True, "error": "disk full"},
            write_results=True,
        )

    assert "could not record" in str(excinfo.value), str(excinfo.value)


def test_a_run_a_foreign_signal_ended_did_not_finish(scanner):
    with pytest.raises(ScannerError) as excinfo:
        _scan_with(
            scanner,
            {"returncode": -15, "signaled": True, "error": "ended by SIGTERM"},
            write_results=True,
        )

    assert "did not finish" in str(excinfo.value), str(excinfo.value)


def test_the_wrapped_error_carries_no_unredacted_original(scanner):
    """The catch-all redacts the text it raises. The exception it caught is not
    redacted, so it must not ride along on the new error: raised inside the
    except block it would be its __context__ (and `from None` would only hide it
    from the traceback printer, not from a reader of the object)."""

    def run(command, **kwargs):
        raise RuntimeError("the tool's own words, as written")

    with (
        patch.object(scanner, "_pre_scan", return_value=True),
        patch.object(scanner, "_post_scan"),
        patch.object(scanner, "_run_subprocess", side_effect=run),
    ):
        with pytest.raises(ScannerError) as excinfo:
            scanner.scan(target=Path(scanner.context.source_dir), target_type="source")

    assert "scan failed" in str(excinfo.value), str(excinfo.value)
    assert excinfo.value.__context__ is None
    assert excinfo.value.__cause__ is None


def test_control_an_unflagged_run_is_graded_on_its_file(scanner):
    """The file the fake wrote is parsed and returned as the SBOM model: None, a
    bool or a swallowed error would all have passed a looser check."""
    report = _scan_with(scanner, {"returncode": 0}, write_results=True)

    assert isinstance(report, CycloneDXReport), type(report)
    assert report.bomFormat == "CycloneDX", report
