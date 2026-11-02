# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The debug line for a skipped config suppression describes what was read.

A config entry is not added to a result that already carries a suppression in
effect. A suppression that is ``rejected`` or ``underReview`` is not in effect,
so the entry is added beside it. The debug line written for the skipped entry
used to say that only the first suppression is ever applied, which is wrong
once a result can carry two; it now names the in-effect case it describes.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.constants import ASH_WORK_DIR_NAME
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.models.core import AshSuppression
from automated_security_helper.schemas.sarif_schema_model import (
    ArtifactLocation,
    Kind1,
    Location,
    Message,
    PhysicalLocation2,
    Region,
    Result,
    Run,
    SarifReport,
    State,
    Suppression,
    Tool,
    ToolComponent,
)
from automated_security_helper.utils import sarif_utils

pytestmark = pytest.mark.unit

AshConfig.model_rebuild()
AshAggregatedResults.model_rebuild()


def _result(state: State | None) -> Result:
    return Result(
        ruleId="RULE-1",
        level="error",
        message=Message(text="finding"),
        locations=[
            Location(
                physicalLocation=PhysicalLocation2(
                    artifactLocation=ArtifactLocation(uri="app.py"),
                    region=Region(startLine=3, endLine=3),
                )
            )
        ],
        suppressions=[Suppression(kind=Kind1.inSource, state=state)],
    )


def _report(result: Result) -> SarifReport:
    return SarifReport(
        version="2.1.0",
        runs=[
            Run(
                tool=Tool(driver=ToolComponent(name="scripted")),
                results=[result],
            )
        ],
    )


def _context(tmp_path: Path) -> PluginContext:
    source = tmp_path / "src"
    output = source / ".ash" / "ash_output"
    (output / ASH_WORK_DIR_NAME).mkdir(parents=True)
    config = AshConfig(
        project_name="u-x2-1",
        global_settings={
            "suppressions": [
                AshSuppression(rule_id="RULE-1", path="app.py", reason="known")
            ]
        },
    )
    return PluginContext(
        source_dir=source,
        output_dir=output,
        work_dir=output / ASH_WORK_DIR_NAME,
        config=config,
    )


def _debug_lines_for_rule(monkeypatch, tmp_path, state: State | None) -> list[str]:
    logger = MagicMock()
    monkeypatch.setattr(sarif_utils, "ASH_LOGGER", logger)
    sarif_utils.apply_suppressions_to_sarif(_report(_result(state)), _context(tmp_path))
    messages = [str(call.args[0]) for call in logger.debug.call_args_list if call.args]
    return [m for m in messages if "RULE-1" in m]


@pytest.mark.parametrize("state", [None, State.accepted])
def test_the_skip_line_names_the_suppression_in_effect(monkeypatch, tmp_path, state):
    lines = _debug_lines_for_rule(monkeypatch, tmp_path, state)

    assert any("already in effect" in line for line in lines)
    assert not any("Only the first suppression" in line for line in lines)


@pytest.mark.parametrize("state", [State.rejected, State.underReview])
def test_no_skip_line_is_written_when_the_suppression_is_not_in_effect(
    monkeypatch, tmp_path, state
):
    lines = _debug_lines_for_rule(monkeypatch, tmp_path, state)

    assert not any("already in effect" in line for line in lines)
    assert not any("Only the first suppression" in line for line in lines)
