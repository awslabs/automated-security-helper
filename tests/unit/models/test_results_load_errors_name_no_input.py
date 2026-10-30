# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A results file that does not load is described by field, not by its input.

pydantic's text for a ValidationError quotes each refused input
(``input_value='...'``). The configuration a results file records can hold a
value read from the environment where the scan ran, so every place that reports
a results file failing to load shows ``error_text`` of the error: the field and
the problem, with no input (utils/error_text.py).

One cell per place: the MCP results reader and its error response, the
"assessable results" probe's log line, ``ash inspect findings``, and the
read-back of a container or Nix scan.
"""

from __future__ import annotations

import json
import re
import traceback
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import typer

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.resource_management import scan_tracking
from automated_security_helper.core.resource_management.exceptions import (
    MCPResourceError,
)
from automated_security_helper.interactions import run_ash_scan as module
from automated_security_helper.interactions.run_ash_scan import (
    ScanOptions,
    _run_container_mode,
    _run_nix_mode,
)
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.utils.subprocess_utils import create_completed_process

pytestmark = pytest.mark.unit

RESULTS = "ash_aggregated_results.json"
FIELD = "severity_threshold"
# A value the record holds where the field refuses it, as an earlier ASH
# version recorded a value read from the environment.
CANARY = "ash-canary-7f3e-0123456789"


def _record() -> dict:
    model = AshAggregatedResults()
    model.ash_config = AshConfig(project_name="demo")
    data = json.loads(model.model_dump_json(by_alias=True))
    data["ash_config"]["global_settings"]["severity_threshold"] = CANARY
    return data


def _assert_no_value(text: str) -> None:
    """Whitespace and box-drawing characters removed, so a value wrapped across
    lines or a panel border still counts; and its leading part, so a truncated
    one does too."""
    squeezed = re.sub(r"[\s─-╿]", "", text)
    assert CANARY not in squeezed and CANARY[:12] not in squeezed, text


def test_the_record_s_own_error_quotes_the_value():
    """Control: loaded as it is, pydantic's text for this record quotes it."""
    with pytest.raises(ValueError) as refused:
        AshAggregatedResults.model_validate(_record())
    assert CANARY in str(refused.value)


@pytest.fixture
def output_dir(tmp_path: Path) -> Path:
    directory = tmp_path / "out"
    directory.mkdir()
    (directory / RESULTS).write_text(json.dumps(_record()), encoding="utf-8")
    return directory


def test_the_mcp_results_reader_names_the_field(output_dir):
    with pytest.raises(MCPResourceError) as refused:
        scan_tracking.get_scan_results(output_dir)
    text = f"{refused.value}\n{json.dumps(refused.value.context, default=str)}"
    assert FIELD in text, text
    _assert_no_value(text)
    # As the MCP server's logger.exception would render it.
    _assert_no_value("".join(traceback.format_exception(refused.value)))

    response = scan_tracking.get_scan_results_with_error_handling(output_dir)
    text = json.dumps(response, default=str)
    assert FIELD in text, text
    _assert_no_value(text)


def test_the_mcp_handler_s_own_catch_names_the_field(output_dir):
    """Any error reaching the handler's catch-all: its response and its log."""
    try:
        AshAggregatedResults.model_validate(_record())
    except ValueError as error:
        refused = error
    with (
        patch.object(scan_tracking, "get_scan_results", side_effect=refused),
        patch.object(scan_tracking, "_logger") as log,
    ):
        response = scan_tracking.get_scan_results_with_error_handling(output_dir)
    text = f"{json.dumps(response, default=str)}\n" + " ".join(
        str(call) for call in log.mock_calls
    )
    assert FIELD in text, text
    _assert_no_value(text)


def test_the_assessable_results_probe_logs_the_field(output_dir):
    with patch.object(scan_tracking, "_logger") as log:
        assert scan_tracking.load_aggregated_results_model(output_dir) is None
    text = " ".join(str(call) for call in log.mock_calls)
    assert FIELD in text, text
    _assert_no_value(text)


def test_inspect_findings_names_the_field(output_dir, capsys):
    from automated_security_helper.cli.inspect.inspect_findings_app import (
        findings_command,
    )

    # A results file that does not load ends the command with exit code 1; the
    # error is printed before the exit.
    with pytest.raises(typer.Exit) as exited:
        findings_command(output_dir=output_dir, report_file=RESULTS)
    assert exited.value.exit_code == 1
    printed = capsys.readouterr()
    text = f"{printed.out}\n{printed.err}"
    assert FIELD in text, text
    _assert_no_value(text)


@pytest.mark.parametrize("mode", ["container", "nix"])
def test_an_outer_scan_s_read_back_names_the_field(tmp_path, monkeypatch, mode):
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    source = tmp_path / "src"
    source.mkdir()
    (source / "app.py").write_text("x = 1\n", encoding="utf-8")
    opts = ScanOptions(source_dir=source, output_dir=tmp_path / "out")

    def inner(*args, **kwargs):
        opts.output_dir.mkdir(parents=True, exist_ok=True)
        (opts.output_dir / RESULTS).write_text(json.dumps(_record()), encoding="utf-8")
        return create_completed_process(args=[], returncode=0, stdout="", stderr="")

    logger = MagicMock()
    runner = "run_ash_container" if mode == "container" else "run_ash_nix"
    wrapper = _run_container_mode if mode == "container" else _run_nix_mode
    with (
        patch.object(module, runner, side_effect=inner),
        patch.object(module, "nix_preflight", lambda: None),
    ):
        with pytest.raises(SystemExit) as exited:
            wrapper(opts, logger)

    assert exited.value.code == 1
    text = " ".join(str(call) for call in logger.mock_calls)
    assert FIELD in text, text
    _assert_no_value(text)
