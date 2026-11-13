# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A model the results hold but do not own keeps a name that is not UTF-8 as it was given.

The results' own models (SARIF, the aggregated results, the flattened findings) hold a
file name that is not valid UTF-8 in its record form, the surrogate written as
``\\udcNN``. They also hold models that are not theirs:

- the live AshConfig the run was given, whose ignore paths and suppressions the
  scanners and the result filters keep reading after the results are built;
- a plugin's own model in a SARIF property bag;
- a CycloneDX component.

Building the results must leave each of these as it was given: the same object, with
the same name. An ignore path rewritten in place stops matching the file it names, so
the file is scanned and reported. Each is written in the record form when the results
are dumped, and the results file reads back.

Values that may hold a lone surrogate are compared through ascii(): pytest's diff of
two such str cannot be sent between workers.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
from pydantic import BaseModel

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.execution_engine import ScanExecutionEngine
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.schemas.cyclonedx_bom_1_6_schema import (
    Component,
    CycloneDXReport,
)
from automated_security_helper.schemas.sarif_schema_model import (
    ArtifactLocation,
    Location,
    Message,
    PhysicalLocation,
    PropertyBag,
    Result,
    Run,
    SarifReport,
    Tool,
    ToolComponent,
)
from automated_security_helper.utils.suppression_matcher import ignore_path_matches

pytestmark = pytest.mark.unit

# Decoded with surrogateescape on every platform: os.fsdecode gives that on POSIX,
# but on Windows the filesystem encoding is UTF-8 with surrogatepass (PEP 529), so
# the lone 0xe9 would raise UnicodeDecodeError while this module is collected.
ODD = b"secr\xe9t.py".decode(sys.getfilesystemencoding(), "surrogateescape")
RECORDED = "secr\\udce9t.py"


def _config() -> AshConfig:
    return AshConfig(
        global_settings={
            "ignore_paths": [{"path": ODD, "reason": "not scanned"}],
            "suppressions": [{"path": ODD, "rule_id": "R1", "reason": "reviewed"}],
        }
    )


def _given(config: AshConfig) -> str:
    return ascii(
        (
            config.global_settings.ignore_paths[0].path,
            config.global_settings.suppressions[0].path,
        )
    )


def test_the_config_the_results_record_is_left_as_given(tmp_path: Path):
    config = _config()

    model = AshAggregatedResults(ash_config=config)

    assert model.ash_config is config
    assert _given(config) == ascii((ODD, ODD))
    assert ignore_path_matches(ODD, config.global_settings.ignore_paths[0].path)
    model.save_model(tmp_path)
    stored = json.loads((tmp_path / "ash_aggregated_results.json").read_bytes())
    path = stored["ash_config"]["global_settings"]["ignore_paths"][0]["path"]
    assert ascii(path) == ascii(RECORDED)


def test_the_engine_leaves_the_runs_config_as_given(tmp_path: Path):
    """The scan engine builds the results from the run's config; the scanners read
    that same config afterwards."""
    config = _config()
    context = PluginContext(
        source_dir=tmp_path, output_dir=tmp_path / "out", config=config
    )

    ScanExecutionEngine(context=context, show_progress=False, show_summary=False)

    assert context.config is config
    assert _given(config) == ascii((ODD, ODD))


class _PluginRow(BaseModel):
    """A plugin's own model, as a plugin puts one in a result's property bag."""

    file: str


def test_a_plugin_model_in_a_property_bag_is_left_as_given():
    row = _PluginRow(file=ODD)

    result = Result(
        ruleId="R1",
        message=Message(text="finding"),
        locations=[
            Location(
                physicalLocation=PhysicalLocation(
                    artifactLocation=ArtifactLocation(uri="app.py")
                )
            )
        ],
        properties=PropertyBag(row=row),
    )

    assert ascii(row.file) == ascii(ODD)
    report = SarifReport(
        runs=[Run(tool=Tool(driver=ToolComponent(name="scripted")), results=[result])]
    )
    stored = json.loads(report.model_dump_json())
    written = stored["runs"][0]["results"][0]["properties"]["row"]["file"]
    assert ascii(written) == ascii(RECORDED)
    assert ascii(row.file) == ascii(ODD)


def test_a_cyclonedx_component_is_left_as_given(tmp_path: Path):
    component = Component(type="library", name=ODD)

    model = AshAggregatedResults(cyclonedx=CycloneDXReport(components=[component]))

    assert ascii(component.name) == ascii(ODD)
    model.save_model(tmp_path)
    stored = json.loads((tmp_path / "ash_aggregated_results.json").read_bytes())
    assert ascii(stored["cyclonedx"]["components"][0]["name"]) == ascii(RECORDED)
    assert ascii(component.name) == ascii(ODD)
