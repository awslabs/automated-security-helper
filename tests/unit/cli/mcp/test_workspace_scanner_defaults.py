# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The MCP workspace tool and the operator's default scanner selection.

A nonempty ``scanners`` argument limits every project to those scanners, as
``--only-scanners`` does, and does not add to the operator's default. The plan
check and the execution settle the same selection, and a refusal that comes from
the operator's config names the MCP parameters for what the caller gave.
"""

from __future__ import annotations

import inspect
import json
from pathlib import Path
from typing import Any, List

import pytest

from automated_security_helper.cli.mcp.workspace import _scan_options
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.exceptions import ScannerSelectionError
from automated_security_helper.interactions.run_ash_scan import (
    build_project_scan_settings,
)
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.workspace.execution import (
    execute_workspace,
    refuse_unresolvable_scanner_selection,
    settled_scanner_selection,
)
from automated_security_helper.workspace.resolver import resolve_workspace

pytestmark = pytest.mark.unit

AshConfig.model_rebuild()


class _Recorder:
    built: List[dict] = []

    def __init__(self, **kwargs: Any) -> None:
        self.kwargs = kwargs
        _Recorder.built.append(kwargs)

    @classmethod
    def create(cls, **kwargs: Any) -> "_Recorder":
        return cls(**kwargs)

    def execute_scan(self, phases=None):
        return AshAggregatedResults()


@pytest.fixture(autouse=True)
def _reset():
    _Recorder.built = []
    yield
    _Recorder.built = []


@pytest.fixture
def workspace(tmp_path: Path):
    root = tmp_path / "ws"
    for name in ("api", "web"):
        (root / name / "src").mkdir(parents=True)
        (root / name / "src" / "app.py").write_text("print('x')\n", encoding="utf-8")
    (root / ".ash").mkdir()
    (root / ".ash" / "ash-workspace.yaml").write_text(
        "workspace:\n  additional_scanners:\n    - trivy\n", encoding="utf-8"
    )
    (root / "dev.code-workspace").write_text(
        json.dumps({"folders": [{"path": "api"}, {"path": "web"}]}),
        encoding="utf-8",
    )
    operator = tmp_path / "operator" / "ash.yaml"
    operator.parent.mkdir()
    operator.write_text("default_scanners:\n  only: [bandit]\n", encoding="utf-8")
    plan = resolve_workspace(root / "dev.code-workspace", default_config=str(operator))
    return plan, str(operator)


def _settings(plan, config, scanners=None, excluded=None):
    return build_project_scan_settings(
        _scan_options(
            plan,
            output_dir=str(Path(plan.workspace_root).parent / "out"),
            config_overrides=None,
            scanners=scanners,
            excluded_scanners=excluded,
            offline=False,
            allow_missing_projects=False,
            config_path=config,
        )
    )


def _enabled_by_project():
    return {
        Path(kwargs["source_dir"]).name: kwargs["enabled_scanners"]
        for kwargs in _Recorder.built
    }


def _run(plan, settings):
    return execute_workspace(plan, settings, orchestrator_factory=_Recorder.create)


def test_a_nonempty_scanners_argument_limits_every_project_to_it(workspace):
    plan, config = workspace

    _run(plan, _settings(plan, config, scanners=["trivy"]))

    assert _enabled_by_project() == {"api": ["trivy"], "web": ["trivy"]}


def test_a_scanners_argument_does_not_add_to_the_default(workspace):
    plan, config = workspace

    _run(plan, _settings(plan, config, scanners=["checkov"]))

    assert _enabled_by_project() == {"api": ["checkov"], "web": ["checkov"]}


def test_no_scanners_argument_runs_the_default_and_the_required_names(workspace):
    plan, config = workspace

    _run(plan, _settings(plan, config))

    assert _enabled_by_project() == {
        "api": ["bandit", "trivy"],
        "web": ["bandit", "trivy"],
    }


def test_the_plan_check_and_the_execution_settle_the_same_selection(workspace):
    plan, config = workspace
    for scanners in (None, ["trivy"], ["bandit", "checkov"]):
        _Recorder.built = []
        settings = _settings(plan, config, scanners=scanners)

        settled = settled_scanner_selection(plan, settings)
        _run(plan, settings)

        assert {tuple(v) for v in _enabled_by_project().values()} == {
            tuple(settled.enabled_scanners)
        }


def test_an_exclusion_is_handed_to_every_project_beside_the_mcp_scanners(workspace):
    plan, config = workspace

    _run(
        plan,
        _settings(plan, config, scanners=["trivy", "bandit"], excluded=["trivy"]),
    )

    assert [kwargs["excluded_scanners"] for kwargs in _Recorder.built] == [
        ["trivy"],
        ["trivy"],
    ]


def test_a_cancelled_config_selection_names_the_mcp_parameters(workspace):
    plan, config = workspace
    settings = _settings(plan, config, excluded=["bandit", "trivy"])

    with pytest.raises(ScannerSelectionError) as refusal:
        refuse_unresolvable_scanner_selection(plan, settings)

    text = str(refusal.value)
    assert "default_scanners in the ASH config" in text
    assert "the excluded_scanners parameter" in text
    assert "--exclude-scanners" not in text


def test_a_cancelled_scanners_argument_keeps_the_mcp_wording(workspace):
    plan, config = workspace
    settings = _settings(plan, config, scanners=["trivy"], excluded=["trivy"])

    with pytest.raises(ScannerSelectionError) as refusal:
        refuse_unresolvable_scanner_selection(plan, settings)

    assert "the scanners parameter" in str(refusal.value)


def test_resolve_workspace_takes_no_selection_argument():
    names = set(inspect.signature(resolve_workspace).parameters)

    assert not names & {"scanners", "excluded_scanners", "only_scanners"}
