# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A suppression from a delivered tree's own config is marked as such in SARIF.

A delivered repository's suppressions are honored, as the CLI honors a
repository's, and ``client_config_policy`` marks each one ``client_supplied``.
The SARIF suppression it produces carries ``properties.clientSupplied`` and says
so in its justification, so a reader can tell it from the operator's.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.models.core import AshSuppression
from automated_security_helper.schemas.sarif_schema_model import (
    ArtifactLocation,
    Location,
    Message,
    PhysicalLocation2,
    Region,
    Result,
    Run,
    SarifReport,
    Tool,
    ToolComponent,
)
from automated_security_helper.utils.sarif_utils import apply_suppressions_to_sarif


def _report() -> SarifReport:
    return SarifReport(
        version="2.1.0",
        runs=[
            Run(
                tool=Tool(driver=ToolComponent(name="bandit", version="1")),
                results=[
                    Result(
                        ruleId="B602",
                        message=Message(text="subprocess with shell=True"),
                        locations=[
                            Location(
                                physicalLocation=PhysicalLocation2(
                                    artifactLocation=ArtifactLocation(uri="app.py"),
                                    region=Region(startLine=3, endLine=3),
                                )
                            )
                        ],
                    )
                ],
            )
        ],
    )


@pytest.mark.parametrize("client_supplied", [True, False])
def test_the_suppression_says_whose_config_it_came_from(
    tmp_path: Path, client_supplied: bool
) -> None:
    suppression = AshSuppression(
        path="app.py",
        rule_id="B602",
        reason="delivered",
        client_supplied=client_supplied,
    )
    config = AshConfig(
        project_name="p", global_settings={"suppressions": [suppression]}
    )
    context = PluginContext(
        source_dir=tmp_path, output_dir=tmp_path / "out", config=config
    )

    report = apply_suppressions_to_sarif(_report(), context)

    [applied] = report.runs[0].results[0].suppressions
    properties = applied.properties.model_dump() if applied.properties else {}
    if client_supplied:
        assert properties.get("clientSupplied") is True
        assert "client-supplied config" in applied.justification
    else:
        assert "clientSupplied" not in properties
        assert "client-supplied" not in applied.justification


@pytest.mark.parametrize("client_supplied", [True, False])
def test_a_client_supplied_ignore_path_keeps_the_finding_suppressed(
    tmp_path: Path, client_supplied: bool
) -> None:
    """The client's own ignore path leaves a trace; the operator's still drops."""
    from automated_security_helper.models.core import IgnorePathWithReason

    ignore = IgnorePathWithReason(
        path="app.py", reason="delivered", client_supplied=client_supplied
    )
    config = AshConfig(project_name="p", global_settings={"ignore_paths": [ignore]})
    context = PluginContext(
        source_dir=tmp_path, output_dir=tmp_path / "out", config=config
    )

    results = apply_suppressions_to_sarif(_report(), context).runs[0].results

    if not client_supplied:
        assert results == []
        return
    [result] = results
    [applied] = result.suppressions
    assert applied.properties.model_dump().get("clientSupplied") is True
    assert "client-supplied config" in applied.justification
    assert "app.py" in applied.justification
