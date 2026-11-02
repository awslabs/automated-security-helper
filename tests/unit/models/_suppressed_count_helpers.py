# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Builders the suppressed-count tests of the aggregated results share.

``dict_report`` is the per-target report the processor writes for a scanner that
returned a dict, ``suppressed_result`` a SARIF result with a suppression in effect,
and ``build_model`` a model holding either. They live here, not in a test module, so
a test file imports them without importing (and re-running) another test file, and a
rename of a test file breaks nothing else.
"""

from __future__ import annotations

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.schemas.sarif_schema_model import (
    Message,
    PropertyBag,
    Result,
    Run,
    SarifReport,
    Suppression,
    Tool,
    ToolComponent,
)

AshConfig.model_rebuild()
AshAggregatedResults.model_rebuild()

SCANNER = "shape-tool"
OTHER = "other-tool"


def dict_report(suppressed: int, scanner: str = SCANNER) -> dict:
    """The per-target report the processor writes for a graded dict result."""
    counts = {
        "suppressed": suppressed,
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
    }
    return {
        "scanner_name": scanner,
        "target_type": "source",
        "status": "PASSED",
        "finding_count": suppressed,
        "severity_counts": counts,
        "raw_results": {"severity_counts": counts},
    }


def suppressed_result(scanner: str, rule: str) -> Result:
    return Result(
        ruleId=rule,
        level="error",
        message=Message(text=f"{rule} found"),
        properties=PropertyBag(scanner_name=scanner),
        suppressions=[Suppression(kind="external", justification="reviewed")],
    )


def build_model(
    reports: dict[str, dict] | None = None,
    sarif_results: list[Result] | None = None,
) -> AshAggregatedResults:
    model = AshAggregatedResults()
    model.ash_config = get_default_config()
    if reports:
        model.additional_reports = {
            scanner: {"source": report} for scanner, report in reports.items()
        }
    if sarif_results:
        model.sarif = SarifReport(
            version="2.1.0",
            runs=[
                Run(
                    tool=Tool(driver=ToolComponent(name=SCANNER, version="1.0.0")),
                    results=sarif_results,
                    properties=PropertyBag(),
                )
            ],
        )
    return model


def row_total(model: AshAggregatedResults) -> int:
    return sum(row.suppressed_finding_count for row in model.scanner_results.values())
