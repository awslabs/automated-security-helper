# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The suppression passes read suppression state before skipping a result.

A suppression whose ``state`` is ``rejected`` or ``underReview`` has not taken
effect (SARIF 3.35.4), and every consumer reads it that way. The passes in
``apply_suppressions_to_sarif`` counted any suppression object: a result that
carried only a rejected suppression was skipped by the inline-comment pass, and
a matching config entry returned as applied without being added, so the
operator could not suppress a finding whose scanner-supplied suppression a
reviewer had rejected, while the exit code failed the scan on it.
"""

from __future__ import annotations

from pathlib import Path

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
from automated_security_helper.utils.sarif_utils import (
    apply_suppressions_to_sarif,
    is_result_suppressed,
)

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


def _context(tmp_path: Path, config: AshConfig | None = None) -> PluginContext:
    source = tmp_path / "src"
    output = source / ".ash" / "ash_output"
    (output / ASH_WORK_DIR_NAME).mkdir(parents=True)
    return PluginContext(
        source_dir=source,
        output_dir=output,
        work_dir=output / ASH_WORK_DIR_NAME,
        config=config or AshConfig(project_name="u-x2-1"),
    )


def _write_source_with_inline_comment(tmp_path: Path) -> None:
    (tmp_path / "src" / "app.py").write_text(
        "import os\n\nx = 1  # ash-ignore: RULE-1 known\n", encoding="utf-8"
    )


def _config_with_entry() -> AshConfig:
    return AshConfig(
        project_name="u-x2-1",
        global_settings={
            "suppressions": [
                AshSuppression(rule_id="RULE-1", path="app.py", reason="known")
            ]
        },
    )


@pytest.mark.parametrize("state", [State.rejected, State.underReview])
def test_an_inline_comment_applies_beside_a_suppression_not_in_effect(tmp_path, state):
    context = _context(tmp_path)
    _write_source_with_inline_comment(tmp_path)
    result = _result(state)
    assert is_result_suppressed(result) is False

    report = apply_suppressions_to_sarif(_report(result), context)

    kept = report.runs[0].results[0]
    justifications = [s.justification for s in kept.suppressions]
    assert "(ASH inline) known" in justifications
    assert is_result_suppressed(kept) is True


@pytest.mark.parametrize("state", [State.rejected, State.underReview])
def test_a_config_entry_applies_beside_a_suppression_not_in_effect(tmp_path, state):
    context = _context(tmp_path, _config_with_entry())
    result = _result(state)

    report = apply_suppressions_to_sarif(_report(result), context)

    kept = report.runs[0].results[0]
    justifications = [s.justification or "" for s in kept.suppressions]
    assert any(
        j.startswith("(ASH) Suppressing finding for rule 'RULE-1'")
        for j in justifications
    )
    assert is_result_suppressed(kept) is True


@pytest.mark.parametrize("state", [None, State.accepted])
def test_a_suppression_in_effect_still_keeps_a_second_one_out(tmp_path, state):
    context = _context(tmp_path, _config_with_entry())
    _write_source_with_inline_comment(tmp_path)
    result = _result(state)

    report = apply_suppressions_to_sarif(_report(result), context)

    kept = report.runs[0].results[0]
    assert len(kept.suppressions) == 1
    assert kept.suppressions[0].state == state
