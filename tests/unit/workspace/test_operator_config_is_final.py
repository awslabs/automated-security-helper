# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""In workspace mode, a field the operator's ``--config`` sets is final for every project.

A project's own config fills only the fields the operator's file leaves unset.
The plan (``--dry-run``) and the scan resolve the same layered config, and the
workspace policy applies after the layering, as before.
"""

from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Any, Dict, List

import pytest
import yaml

from automated_security_helper.models.workspace import WorkspaceExitCode
from automated_security_helper.workspace.execution import (
    ProjectScanSettings,
    execute_workspace,
)
from automated_security_helper.workspace.resolver import resolve_workspace


@pytest.fixture(autouse=True)
def _no_ash_config(monkeypatch):
    monkeypatch.delenv("ASH_CONFIG", raising=False)


def _workspace(root: Path, folders: List[str]) -> Path:
    path = root / "dev.code-workspace"
    path.write_text(
        json.dumps({"folders": [{"path": p} for p in folders]}), encoding="utf-8"
    )
    return path


def _project(root: Path, relative: str, config: Dict[str, Any] | None = None) -> Path:
    project = root / relative
    project.mkdir(parents=True, exist_ok=True)
    if config is not None:
        (project / ".ash").mkdir(exist_ok=True)
        (project / ".ash" / "ash.yaml").write_text(
            yaml.safe_dump(config), encoding="utf-8"
        )
    return project


def _operator(tmp_path: Path, config: Dict[str, Any]) -> Path:
    path = tmp_path / "operator" / "ash.yaml"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(config), encoding="utf-8")
    return path


def _sarif_with_one_error() -> Dict[str, Any]:
    return {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "ASH"}},
                "results": [
                    {
                        "ruleId": "R0",
                        "level": "error",
                        "message": {"text": "fixture"},
                        "properties": {"scanner_name": "bandit"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "src/app.py"}
                                }
                            }
                        ],
                    }
                ],
                "invocations": [],
            }
        ],
    }


class _Orchestrator:
    """Returns results carrying the config it was handed, as the real one does."""

    built: List["_Orchestrator"] = []
    behaviour: Dict[str, Dict[str, Any]] = {}
    lock = threading.Lock()

    def __init__(self, **kwargs: Any) -> None:
        self.kwargs = kwargs
        self.key = Path(kwargs["source_dir"]).name
        with _Orchestrator.lock:
            _Orchestrator.built.append(self)

    @classmethod
    def create(cls, **kwargs: Any) -> "_Orchestrator":
        return cls(**kwargs)

    def execute_scan(self, phases=None):
        from automated_security_helper.models.asharp_model import (
            AshAggregatedResults,
            ScannerTargetStatusInfo,
        )
        from automated_security_helper.schemas.sarif_schema_model import SarifReport

        spec = _Orchestrator.behaviour.get(self.key, {})
        model = AshAggregatedResults()
        model.ash_config = self.kwargs["resolved_config"]
        model.sarif = SarifReport.model_validate(
            spec.get("sarif")
            or {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "ASH"}}}]}
        )
        for name, status in (spec.get("scanners") or {"bandit": "PASSED"}).items():
            model.scanner_results[name] = ScannerTargetStatusInfo(
                status=status,
                excluded=False,
                dependencies_satisfied=status != "MISSING",
            )
        return model


@pytest.fixture(autouse=True)
def _reset_orchestrator():
    _Orchestrator.built = []
    _Orchestrator.behaviour = {}
    yield
    _Orchestrator.built = []
    _Orchestrator.behaviour = {}


def _scan(tmp_path: Path, plan, operator: Path | None):
    settings = ProjectScanSettings(
        output_dir=tmp_path / "out",
        phases=("scan",),
        default_config_path=operator.as_posix() if operator else None,
    )
    return execute_workspace(plan, settings, orchestrator_factory=_Orchestrator.create)


def _resolved(key: str):
    return next(o for o in _Orchestrator.built if o.key == key).kwargs[
        "resolved_config"
    ]


def test_the_plan_takes_the_threshold_the_operator_sets(tmp_path):
    root = tmp_path / "work"
    _project(root, "api", {"global_settings": {"severity_threshold": "LOW"}})
    operator = _operator(
        tmp_path, {"global_settings": {"severity_threshold": "CRITICAL"}}
    )

    plan = resolve_workspace(_workspace(root, ["api"]), default_config=operator)

    project = plan.active_projects[0]
    assert project.severity_threshold == "CRITICAL"
    assert project.config_source == (
        (root / "api" / ".ash" / "ash.yaml").resolve().as_posix()
    )
    assert project.operator_config == operator.resolve().as_posix()


def test_a_field_the_operator_leaves_unset_comes_from_the_project(tmp_path):
    root = tmp_path / "work"
    _project(root, "api", {"scanners": {"bandit": {"enabled": False}}})
    operator = _operator(tmp_path, {"fail_on_findings": True})

    plan = resolve_workspace(_workspace(root, ["api"]), default_config=operator)

    assert "bandit" not in plan.active_projects[0].scanners


def test_a_project_without_a_config_takes_the_operators_file_alone(tmp_path):
    root = tmp_path / "work"
    _project(root, "api")
    operator = _operator(
        tmp_path, {"global_settings": {"severity_threshold": "CRITICAL"}}
    )

    plan = resolve_workspace(_workspace(root, ["api"]), default_config=operator)

    project = plan.active_projects[0]
    assert project.config_source == operator.resolve().as_posix()
    assert project.operator_config is None
    assert project.severity_threshold == "CRITICAL"


def test_the_plan_and_the_scan_agree_on_a_layered_field(tmp_path):
    root = tmp_path / "work"
    _project(
        root,
        "api",
        {
            "global_settings": {"severity_threshold": "LOW"},
            "scanners": {"bandit": {"options": {"confidence_level": "high"}}},
        },
    )
    operator = _operator(
        tmp_path, {"global_settings": {"severity_threshold": "CRITICAL"}}
    )
    plan = resolve_workspace(_workspace(root, ["api"]), default_config=operator)

    _scan(tmp_path, plan, operator)

    resolved = _resolved("api")
    assert resolved.global_settings.severity_threshold == "CRITICAL"
    assert (
        resolved.global_settings.severity_threshold
        == plan.active_projects[0].severity_threshold
    )
    assert resolved.scanners.bandit.options.confidence_level == "high"


def test_fail_on_findings_the_operator_sets_is_final(tmp_path):
    root = tmp_path / "work"
    _project(root, "api", {"fail_on_findings": False})
    operator = _operator(tmp_path, {"fail_on_findings": True})
    plan = resolve_workspace(_workspace(root, ["api"]), default_config=operator)
    _Orchestrator.behaviour["api"] = {"sarif": _sarif_with_one_error()}

    outcome = _scan(tmp_path, plan, operator)

    assert outcome.payload.projects[0].actionable_finding_count == 1
    assert outcome.exit_code == WorkspaceExitCode.ACTIONABLE_FINDINGS


def test_fail_on_incomplete_scanners_the_operator_sets_is_final(tmp_path):
    root = tmp_path / "work"
    _project(root, "api", {"fail_on_incomplete_scanners": False})
    operator = _operator(tmp_path, {"fail_on_incomplete_scanners": True})
    plan = resolve_workspace(_workspace(root, ["api"]), default_config=operator)
    _Orchestrator.behaviour["api"] = {
        "scanners": {"bandit": "PASSED", "cfn-nag": "MISSING"}
    }

    outcome = _scan(tmp_path, plan, operator)

    assert outcome.payload.projects[0].incomplete_scanners == ["cfn-nag"]
    assert outcome.exit_code == WorkspaceExitCode.INTERNAL_ERROR


def test_the_project_still_decides_what_the_operator_leaves_unset(tmp_path):
    """Control for the two above: without the operator's field the project's holds."""
    root = tmp_path / "work"
    _project(root, "api", {"fail_on_incomplete_scanners": False})
    operator = _operator(tmp_path, {"fail_on_findings": True})
    plan = resolve_workspace(_workspace(root, ["api"]), default_config=operator)
    _Orchestrator.behaviour["api"] = {
        "scanners": {"bandit": "PASSED", "cfn-nag": "MISSING"}
    }

    outcome = _scan(tmp_path, plan, operator)

    assert outcome.exit_code == WorkspaceExitCode.SUCCESS


def test_the_workspace_ceiling_applies_after_the_layering(tmp_path):
    root = tmp_path / "work"
    _project(root, "api", {"global_settings": {"severity_threshold": "LOW"}})
    (root / "ash-workspace.yaml").write_text(
        "workspace:\n  max_severity_threshold: MEDIUM\n", encoding="utf-8"
    )
    operator = _operator(
        tmp_path, {"global_settings": {"severity_threshold": "CRITICAL"}}
    )

    plan = resolve_workspace(_workspace(root, ["api"]), default_config=operator)

    project = plan.active_projects[0]
    assert project.severity_threshold == "CRITICAL"
    assert project.effective_severity_threshold == "MEDIUM"
    assert project.threshold_tightened_by_policy is True


def test_a_grant_only_the_project_sets_is_still_dropped(tmp_path):
    root = tmp_path / "work"
    _project(root, "api", {"sandbox": {"extra_read_paths": ["/project/x"]}})
    operator = _operator(tmp_path, {"fail_on_findings": True})
    plan = resolve_workspace(_workspace(root, ["api"]), default_config=operator)

    _scan(tmp_path, plan, operator)

    resolved = _resolved("api")
    assert resolved.sandbox.extra_read_paths == []
    assert resolved.fail_on_findings is True


def test_the_dry_run_names_the_operators_file(tmp_path):
    root = tmp_path / "work"
    _project(root, "api", {"project_name": "api"})
    operator = _operator(tmp_path, {"fail_on_findings": True})

    plan = resolve_workspace(_workspace(root, ["api"]), default_config=operator)

    assert operator.resolve().as_posix() in plan.render()
