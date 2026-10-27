# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A refused-input record keeps only the keys its model defines.

RefusedInputInfo (path, member, reason) took any other key it was given, so a key
in a results file ASH reads back (``ash report``, a shard given to ``ash merge``,
``ash scan --use-existing``) went into every record and report written from it.
No ASH writer sets another key: the two places that make a record, a converter's
refusal (``ConverterPluginBase``) and the archive converter's partial extraction,
set those three. Such a key is dropped, and each of those three readers, and
the MCP server's get_scan_results, logs one warning that says how many keys were
dropped and from which file, naming neither a key nor its value: both come from
the file.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from typer.testing import CliRunner

from automated_security_helper.models.asharp_model import (
    AshAggregatedResults,
    ConverterStatusInfo,
    RefusedInputInfo,
)
from automated_security_helper.utils.log import ASH_LOGGER

RESULTS = "ash_aggregated_results.json"
PLANTED_KEYS = {"x_planted_key": "planted-value-1", "y_planted_key": "planted-value-2"}


@pytest.fixture
def warnings(caplog):
    """ASH's warnings, through pytest's capture handler (ASH's own handler renders
    to a console and leaves nothing in ``caplog.records``)."""
    saved_handlers = ASH_LOGGER.handlers
    saved_propagate = ASH_LOGGER.propagate
    ASH_LOGGER.handlers = [caplog.handler]
    ASH_LOGGER.propagate = False
    caplog.set_level(logging.WARNING, logger=ASH_LOGGER.name)
    try:
        yield caplog
    finally:
        ASH_LOGGER.handlers = saved_handlers
        ASH_LOGGER.propagate = saved_propagate


def _write_results(directory: Path) -> Path:
    """A results file whose one refused-input record carries two planted keys."""
    model = AshAggregatedResults()
    model.converter_results = {
        "archive": ConverterStatusInfo(
            refused_inputs=[
                RefusedInputInfo(
                    path="lib/b.tar", member="link.js", reason="it is a link"
                )
            ]
        )
    }
    data = json.loads(model.model_dump_json(by_alias=True))
    data["converter_results"]["archive"]["refused_inputs"][0].update(PLANTED_KEYS)
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / RESULTS
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def _assert_nothing_planted(text: str) -> None:
    for key, value in PLANTED_KEYS.items():
        assert key not in text, key
        assert value not in text, value


def _assert_one_warning_naming(warnings, results_file: Path) -> None:
    dropped = [
        record.getMessage()
        for record in warnings.records
        if "refused-input record" in record.getMessage()
    ]
    assert len(dropped) == 1, [r.getMessage() for r in warnings.records]
    assert "Dropped 2 keys" in dropped[0], dropped[0]
    assert str(results_file) in dropped[0], dropped[0]
    for record in warnings.records:
        _assert_nothing_planted(record.getMessage())


def test_a_record_drops_a_key_it_does_not_define():
    record = RefusedInputInfo.model_validate(
        {"path": "lib/b.tar", "reason": "it is a link", **PLANTED_KEYS}
    )

    assert record.model_dump() == {
        "path": "lib/b.tar",
        "member": None,
        "reason": "it is a link",
    }


def test_ash_report_drops_the_keys_and_says_so_once(tmp_path, warnings):
    from automated_security_helper.cli.main import app

    output_dir = tmp_path / "out"
    results_file = _write_results(output_dir)

    result = CliRunner().invoke(
        app, ["report", "--format", "yaml", "--output-dir", str(output_dir)]
    )

    assert result.exit_code == 0, result.output
    assert "converter_results" in result.stdout
    _assert_nothing_planted(result.output)
    _assert_one_warning_naming(warnings, results_file)


def test_an_ash_merge_shard_drops_the_keys_and_says_so_once(tmp_path, warnings):
    from automated_security_helper.cli.merge import load_shard_results

    results_file = _write_results(tmp_path / "shard-1")

    ((loaded_from, model),) = load_shard_results([tmp_path / "shard-1"])

    assert loaded_from.resolve() == results_file.resolve()
    _assert_nothing_planted(model.model_dump_json(by_alias=True))
    _assert_one_warning_naming(warnings, loaded_from)


def test_use_existing_drops_the_keys_and_says_so_once(tmp_path, warnings, monkeypatch):
    from automated_security_helper.config.ash_config import AshConfig
    from automated_security_helper.core.constants import ASH_WORK_DIR_NAME
    from automated_security_helper.core.orchestrator import ASHScanOrchestrator

    monkeypatch.delenv("ASH_CONFIG", raising=False)
    results_file = _write_results(tmp_path / "previous")
    source = tmp_path / "src"
    source.mkdir()
    output = tmp_path / "out"
    engines = []

    def engine(**kwargs):
        engines.append(kwargs)
        return MagicMock()

    orchestrator = ASHScanOrchestrator(
        source_dir=source,
        output_dir=output,
        work_dir=output / ASH_WORK_DIR_NAME,
        config_path=None,
        config_overrides=None,
        no_cleanup=True,
        metadata=None,
        ash_plugin_modules=[],
        existing_results_path=results_file,
    )
    with (
        patch(
            "automated_security_helper.core.orchestrator.resolve_config",
            return_value=AshConfig(project_name="demo"),
        ),
        patch(
            "automated_security_helper.core.orchestrator.ScanExecutionEngine",
            side_effect=engine,
        ),
    ):
        orchestrator.initialize()

    model = engines[0]["asharp_model"]
    _assert_nothing_planted(model.model_dump_json(by_alias=True))
    _assert_one_warning_naming(warnings, results_file)


def test_the_mcp_scan_results_drop_the_keys_and_say_so_once(tmp_path, warnings):
    from automated_security_helper.core.resource_management.scan_tracking import (
        get_scan_results,
    )

    output_dir = tmp_path / "out"
    results_file = _write_results(output_dir)

    reply = json.dumps(get_scan_results(output_dir=output_dir))

    assert "refused_inputs" in reply
    _assert_nothing_planted(reply)
    _assert_one_warning_naming(warnings, results_file)
