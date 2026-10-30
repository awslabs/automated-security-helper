# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The engine's unmatched-directory warning quotes an environment-read path by
its reference.

Why this exists
---------------
After the final suppression pass the engine warns once for each suppression
whose path ends in ``/`` and matched nothing
(``suppression_matcher.warn_unmatched_directory_suppressions``). The warning can
quote a path the config file read from the environment by the reference the
file wrote, but only given the config's environment record, and the engine
passed none: that one warning printed the value, where every other message
about a suppression shows the reference. The engine now hands the warning its
config, and the record is built from it.

The test drives the engine's own method with the three things it reads (the
context, the results, the changed set) and the two collaborators it calls
replaced by stubs, so what is measured is the engine's call: with the config,
the reference is quoted and the resolved value is absent.
"""

from __future__ import annotations

import logging
from pathlib import Path
from types import SimpleNamespace

import pytest

from automated_security_helper.core import execution_engine
from automated_security_helper.core.execution_engine import ScanExecutionEngine
from automated_security_helper.models.core import AshSuppression
from automated_security_helper.utils import sarif_utils, suppression_matcher
from automated_security_helper.utils.log import ASH_LOGGER

pytestmark = pytest.mark.unit

REFERENCE = "${ASH_ENGINE_DIR}/"


@pytest.fixture
def ash_warnings():
    records: list[logging.LogRecord] = []

    class _Collect(logging.Handler):
        def emit(self, record):
            records.append(record)

    handler = _Collect(level=logging.WARNING)
    ASH_LOGGER.addHandler(handler)
    yield records
    ASH_LOGGER.removeHandler(handler)


def test_the_warning_quotes_the_reference_through_the_engines_call(
    tmp_path: Path, ash_warnings, monkeypatch
):
    """Red at the base: the engine passed neither a record nor the config, so
    the warning quoted ``resolved-dir/``, the value."""
    suppression = AshSuppression(path="resolved-dir/", rule_id="R1", reason="r")
    config = SimpleNamespace(
        global_settings=SimpleNamespace(suppressions=[suppression])
    )
    asked_for: list = []

    def record_of(given):
        asked_for.append(given)
        return {id(suppression): {"path": REFERENCE}}

    monkeypatch.setattr(suppression_matcher, "recorded_suppressions", record_of)
    # The pass itself is not under test: the SARIF goes through unchanged.
    monkeypatch.setattr(
        sarif_utils, "apply_suppressions_to_sarif", lambda **kw: kw["sarif_report"]
    )
    monkeypatch.setattr(
        execution_engine,
        "populate_metrics_from_unified_source",
        lambda aggregated_results: aggregated_results,
    )

    engine = ScanExecutionEngine.__new__(ScanExecutionEngine)
    engine._context = SimpleNamespace(
        config=config,
        ignore_suppressions=False,
        source_dir=tmp_path,
        output_dir=tmp_path / "out",
        work_dir=tmp_path / "work",
    )
    engine._results = SimpleNamespace(sarif=object(), used_suppressions=[])
    engine._asharp_model = engine._results
    engine._changed_files = None
    monkeypatch.setattr(engine, "_drop_findings_outside_changed_files", lambda: None)

    engine._apply_final_suppressions()

    assert asked_for == [config]
    messages = [record.getMessage() for record in ash_warnings]
    assert len(messages) == 1, messages
    assert f"'{REFERENCE}'" in messages[0]
    assert "resolved-dir" not in messages[0]
