# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The scan execution engine places a converted finding by its recorded source.

Why this exists
---------------
``filter_results_to_changed_files`` places a finding in a converted file (a
notebook's Python, an archive member) by the source the converter read, through
its ``converted_sources`` mapping, and keeps the finding when the mapping names
no source. The engine is the one production caller, and for a while nothing built
that mapping: every converted finding was kept under ``--changed-files-only``,
so a change to ``README.md`` alone reported, and gated on, every finding in every
notebook of the repository. The converters now record what they converted
(``scan_output_dirs.record_converted_sources``, one ``converted-sources.json`` per
converter under the work directory) and the engine reads it back
(``converted_sources_of``) into the filter. These tests drive that wiring from the
engine, with the file the converters write.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from types import SimpleNamespace

import pytest

from automated_security_helper.core.execution_engine import ScanExecutionEngine
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.schemas.sarif_schema_model import (
    ArtifactLocation,
    Location,
    Message1,
    PhysicalLocation,
    PhysicalLocation2,
    PropertyBag,
    Region,
    Result,
    Run,
    SarifReport,
    Tool,
    ToolComponent,
)
from automated_security_helper.utils.finding_identity import CONVERTED_PATH_PROPERTY
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.scan_output_dirs import (
    CONVERTED_SOURCES_FILE_NAME,
)

pytestmark = pytest.mark.unit

CONVERTED = "jupyter/analysis-converted.py"
SOURCE = "nb/analysis.ipynb"


@pytest.fixture
def ash_warnings(caplog):
    """ASH's own WARNING records; ``utils.log`` sets ``ASH_LOGGER.propagate = False``
    (the shape ``tests/unit/utils/test_changed_files.py`` uses)."""
    saved_handlers = ASH_LOGGER.handlers
    saved_propagate = ASH_LOGGER.propagate
    saved_disabled = ASH_LOGGER.disabled
    ASH_LOGGER.handlers = [*saved_handlers, caplog.handler]
    ASH_LOGGER.propagate = False
    ASH_LOGGER.disabled = False
    caplog.set_level(logging.WARNING, logger=ASH_LOGGER.name)
    try:
        yield lambda: [
            record.getMessage()
            for record in caplog.records
            if record.levelno >= logging.WARNING
        ]
    finally:
        ASH_LOGGER.handlers = saved_handlers
        ASH_LOGGER.propagate = saved_propagate
        ASH_LOGGER.disabled = saved_disabled


@pytest.fixture
def layout(tmp_path):
    """A scanned tree, an output directory with its work directory, and a results
    model holding one finding in the converted notebook, marked as the scanner
    executor marks it (``converted_path`` relative to the work directory)."""
    source_dir = tmp_path / "repo"
    (source_dir / "nb").mkdir(parents=True)
    (source_dir / "nb" / "analysis.ipynb").write_text("{}", encoding="utf-8")
    (source_dir / "other.py").write_text("x = 1\n", encoding="utf-8")
    output_dir = tmp_path / "out"
    work_dir = output_dir / "work"
    (work_dir / "jupyter").mkdir(parents=True)
    converted = work_dir / CONVERTED
    converted.write_text("x = 1\n", encoding="utf-8")

    result = Result(
        message=Message1(text="finding in the notebook"),
        locations=[
            Location(
                physicalLocation=PhysicalLocation(
                    root=PhysicalLocation2(
                        artifactLocation=ArtifactLocation(uri=str(converted)),
                        region=Region(startLine=1),
                    )
                )
            )
        ],
    )
    result.properties = PropertyBag()
    setattr(result.properties, CONVERTED_PATH_PROPERTY, CONVERTED)
    results = AshAggregatedResults()
    results.sarif = SarifReport(
        version="2.1.0",
        runs=[Run(tool=Tool(driver=ToolComponent(name="test-tool")), results=[result])],
    )
    return SimpleNamespace(
        source_dir=source_dir, output_dir=output_dir, work_dir=work_dir, results=results
    )


def _record(work_dir: Path) -> None:
    """The file a converter writes beside its output (``record_converted_sources``)."""
    (work_dir / "jupyter" / CONVERTED_SOURCES_FILE_NAME).write_text(
        json.dumps({CONVERTED: SOURCE}), encoding="utf-8"
    )


def _engine(layout, changed: set[Path]) -> ScanExecutionEngine:
    """An engine with the three things the changed-files filter reads, and no
    plugin loading: the context's directories, the results and the changed set."""
    engine = ScanExecutionEngine.__new__(ScanExecutionEngine)
    engine._context = SimpleNamespace(
        source_dir=layout.source_dir,
        output_dir=layout.output_dir,
        work_dir=layout.work_dir,
    )
    engine._results = layout.results
    engine._asharp_model = layout.results
    engine._changed_files = changed
    return engine


def _findings(engine: ScanExecutionEngine) -> list:
    return engine._results.sarif.runs[0].results


def test_a_converted_finding_whose_source_changed_is_reported(layout):
    _record(layout.work_dir)
    engine = _engine(layout, {(layout.source_dir / SOURCE).resolve()})

    engine._drop_findings_outside_changed_files()

    assert len(_findings(engine)) == 1


def test_a_converted_finding_whose_source_did_not_change_is_dropped(layout):
    """A change to another file alone no longer reports every notebook finding."""
    _record(layout.work_dir)
    engine = _engine(layout, {(layout.source_dir / "other.py").resolve()})

    engine._drop_findings_outside_changed_files()

    assert _findings(engine) == []


def test_without_a_recorded_source_the_finding_is_kept_and_said_once(
    layout, ash_warnings
):
    """No converter record: kept rather than dropped, and the two narrowings the
    engine makes (after the scan phase, at the report phase) say so once."""
    engine = _engine(layout, {(layout.source_dir / "other.py").resolve()})

    engine._drop_findings_outside_changed_files()
    engine._drop_findings_outside_changed_files()

    assert len(_findings(engine)) == 1
    said = [m for m in ash_warnings() if "located in converted files" in m]
    assert len(said) == 1, ash_warnings()
