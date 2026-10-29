# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A link at a workspace report path refuses the workspace run.

The workspace report step writes each merged or workspace-scoped reporter's file and
``reports/workspace-reports.json`` in the workspace output directory, which nothing
clears between runs. A link already at one of those names refuses the run before
any project is scanned. One that appears while the projects are scanned is refused
when the report step starts, before anything is written there.

Driven through ``execute_workspace`` with a stand-in orchestrator, so "before any
project is scanned" is observable as "no orchestrator was built". The refusal is
caught as ``ASHValidationError``, which predates the check.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any, Callable, List, Literal, Optional

import pytest
from pydantic import ConfigDict

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.base.reporter_plugin import (
    ReporterPluginBase,
    ReporterPluginConfigBase,
    ReporterWorkspaceBehaviour,
)
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.exceptions import ASHValidationError
from automated_security_helper.plugin_modules.ash_builtin import ASH_REPORTERS
from automated_security_helper.workspace.execution import (
    ProjectScanSettings,
    execute_workspace,
)
from automated_security_helper.workspace.plan import ProjectPlan, WorkspacePlan
from automated_security_helper.workspace.reporting import MANIFEST_FILENAME

pytestmark = pytest.mark.skipif(
    sys.platform == "win32", reason="creating symlinks needs privileges on Windows"
)

MARKER = "TARGET-OF-A-LINK-IN-REPORTS-71c4"


def _default_config(reporter_class: type) -> Any:
    context = PluginContext(
        source_dir=Path("unused"), output_dir=Path("unused"), config=AshConfig()
    )
    return reporter_class(context=context).config


def _report_file(reporter_class: type) -> str:
    return f"ash.{_default_config(reporter_class).extension}"


def _with_behaviour(*behaviours: ReporterWorkspaceBehaviour) -> List[type]:
    """The reporters on by default that declare one of ``behaviours``."""
    return [
        cls
        for cls in ASH_REPORTERS
        if cls.workspace_behaviour in behaviours and _default_config(cls).enabled
    ]


#: Reporters that write a workspace-level file, and so whose names are checked.
EMITTING = _with_behaviour(
    ReporterWorkspaceBehaviour.MERGED, ReporterWorkspaceBehaviour.WORKSPACE_SCOPED
)


class _Orchestrator:
    """Stands in for ASHScanOrchestrator; records that a project was started."""

    built: List["_Orchestrator"] = []
    #: Run inside execute_scan, as a project's scan would run.
    during_scan: Optional[Callable[[], None]] = None

    def __init__(self, **kwargs: Any) -> None:
        self.kwargs = kwargs
        _Orchestrator.built.append(self)

    @classmethod
    def create(cls, **kwargs: Any) -> "_Orchestrator":
        return cls(**kwargs)

    def execute_scan(self, phases=None):
        from automated_security_helper.models.asharp_model import AshAggregatedResults

        if _Orchestrator.during_scan is not None:
            _Orchestrator.during_scan()
        return AshAggregatedResults()


@pytest.fixture(autouse=True)
def _reset():
    _Orchestrator.built = []
    _Orchestrator.during_scan = None
    yield
    _Orchestrator.built = []
    _Orchestrator.during_scan = None


def _plan(tmp_path: Path) -> WorkspacePlan:
    root = tmp_path / "ws"
    projects = []
    for key in ("api", "web"):
        (root / key / "src").mkdir(parents=True)
        (root / key / "src" / "app.py").write_text("x = 1\n", encoding="utf-8")
        projects.append(
            ProjectPlan(
                key=key,
                relative_path=key,
                path=(root / key).as_posix(),
                label=key,
                display_label=key,
                severity_threshold="MEDIUM",
            )
        )
    workspace_file = root / "fixture.code-workspace"
    workspace_file.write_text(
        json.dumps({"folders": [{"path": "api"}, {"path": "web"}]}), encoding="utf-8"
    )
    return WorkspacePlan(
        workspace_file=workspace_file.as_posix(),
        workspace_root=root.as_posix(),
        projects=projects,
    )


def _run(tmp_path: Path, extra_reporters=(), output_formats=()):
    return execute_workspace(
        _plan(tmp_path),
        ProjectScanSettings(
            output_dir=tmp_path / "out",
            phases=("scan", "report"),
            max_parallel_projects=1,
            output_formats=tuple(output_formats),
        ),
        orchestrator_factory=_Orchestrator.create,
        reporter_classes=[*ASH_REPORTERS, *extra_reporters],
    )


def _reports(tmp_path: Path) -> Path:
    return tmp_path / "out" / "reports"


def _plant_link(tmp_path: Path, name: str) -> Path:
    outside = tmp_path / "outside" / f"{name}.target"
    outside.parent.mkdir(parents=True, exist_ok=True)
    outside.write_text(MARKER, encoding="utf-8")
    _reports(tmp_path).mkdir(parents=True, exist_ok=True)
    (_reports(tmp_path) / name).symlink_to(outside)
    return outside


def _refusal_naming(path: Path) -> str:
    return re.escape(f"{path.as_posix()} is a symlink")


def test_a_link_at_the_manifest_refuses_the_run_before_any_project(tmp_path):
    outside = _plant_link(tmp_path, MANIFEST_FILENAME)

    with pytest.raises(
        ASHValidationError,
        match=_refusal_naming(_reports(tmp_path) / MANIFEST_FILENAME),
    ):
        _run(tmp_path)

    assert _Orchestrator.built == []
    assert outside.read_text(encoding="utf-8") == MARKER
    assert [path.name for path in _reports(tmp_path).iterdir()] == [MANIFEST_FILENAME]


@pytest.mark.parametrize("reporter_class", EMITTING, ids=lambda cls: cls.__name__)
def test_a_link_at_a_workspace_reporters_file_refuses_the_run_before_any_project(
    reporter_class, tmp_path
):
    name = _report_file(reporter_class)
    outside = _plant_link(tmp_path, name)

    with pytest.raises(
        ASHValidationError, match=_refusal_naming(_reports(tmp_path) / name)
    ):
        _run(tmp_path)

    assert _Orchestrator.built == []
    assert outside.read_text(encoding="utf-8") == MARKER


def test_a_link_that_appears_during_the_scan_is_refused_before_the_report_step_writes(
    tmp_path,
):
    """Checked again when the report step starts: nothing is written in reports/."""
    planted: List[Path] = []

    def plant() -> None:
        if not planted:
            planted.append(_plant_link(tmp_path, MANIFEST_FILENAME))

    _Orchestrator.during_scan = plant

    with pytest.raises(
        ASHValidationError,
        match=_refusal_naming(_reports(tmp_path) / MANIFEST_FILENAME),
    ):
        _run(tmp_path)

    assert len(_Orchestrator.built) == 2
    assert planted[0].read_text(encoding="utf-8") == MARKER
    assert [path.name for path in _reports(tmp_path).iterdir()] == [MANIFEST_FILENAME]


def test_a_link_at_a_per_project_reporters_name_is_not_examined(tmp_path):
    """A per-project reporter writes nothing in the workspace's reports/."""
    per_project = _with_behaviour(ReporterWorkspaceBehaviour.PER_PROJECT)
    assert per_project
    name = _report_file(per_project[0])
    outside = _plant_link(tmp_path, name)

    result = _run(tmp_path)

    assert result.report_outcome is not None
    assert result.report_outcome.manifest_path is not None
    assert (_reports(tmp_path) / name).is_symlink()
    assert outside.read_text(encoding="utf-8") == MARKER


class _EscapingNameConfig(ReporterPluginConfigBase):
    """A default is not validated, so this reaches the name check unchanged."""

    model_config = ConfigDict(validate_default=False)

    name: Literal["escaping-per-project"] = "escaping-per-project"
    extension: str = "../escaping-per-project.txt"
    enabled: bool = True


class _EscapingPerProject(ReporterPluginBase[_EscapingNameConfig]):
    """A per-project reporter, so it writes only in each project's own reports/."""

    workspace_behaviour = ReporterWorkspaceBehaviour.PER_PROJECT

    def model_post_init(self, context):
        if self.config is None:
            self.config = _EscapingNameConfig()
        return super().model_post_init(context)

    def report(self, model) -> str:  # pragma: no cover - refused before it runs
        raise AssertionError("refused before any project is scanned")


def test_a_per_project_reporters_name_outside_reports_refuses_before_any_project(
    tmp_path,
):
    """Each project's report phase would refuse it, after that project's whole scan."""
    with pytest.raises(
        ASHValidationError, match=re.escape("'ash.../escaping-per-project.txt'")
    ):
        _run(tmp_path, extra_reporters=[_EscapingPerProject])

    assert _Orchestrator.built == []


def test_a_per_project_reporter_not_requested_is_not_examined(tmp_path):
    """Narrowing --output-format past it lets the run go ahead."""
    result = _run(
        tmp_path, extra_reporters=[_EscapingPerProject], output_formats=["sarif"]
    )

    assert len(_Orchestrator.built) == 2
    assert result.report_outcome is not None


@pytest.mark.parametrize(
    "behaviour",
    [ReporterWorkspaceBehaviour.MERGED, ReporterWorkspaceBehaviour.PER_PROJECT],
    ids=["merged", "per-project"],
)
def test_a_companion_name_outside_reports_refuses_before_any_project(
    tmp_path, behaviour
):
    """Not only when the report step starts, after every project was scanned."""
    from tests.unit.core.phases.test_companion_file_names_refuse_the_run import (
        ESCAPING,
        _CompanionEscaper,
    )

    class _Escaper(_CompanionEscaper):
        workspace_behaviour = behaviour

    with pytest.raises(ASHValidationError, match=re.escape(repr(ESCAPING))):
        _run(tmp_path, extra_reporters=[_Escaper])

    assert _Orchestrator.built == []


def test_the_workspace_report_step_refuses_a_dangling_reports_dir(tmp_path):
    """Refused, rather than failing with FileExistsError when it creates reports/."""
    from automated_security_helper.utils.report_path_links import (
        ReportPathLinkRefused,
    )
    from automated_security_helper.workspace.aggregation import WorkspaceAggregator
    from automated_security_helper.workspace.reporting import (
        REPORTS_DIR_NAME,
        emit_workspace_reports,
    )

    root = tmp_path / "ws"
    root.mkdir()
    plan = WorkspacePlan(
        workspace_file=(root / "fixture.code-workspace").as_posix(),
        workspace_root=root.as_posix(),
        projects=[],
    )
    output_dir = tmp_path / "out"
    results_path = WorkspaceAggregator(plan=plan, output_dir=output_dir).write(
        exit_code=0, wall_clock_seconds=0.1
    )
    reports = output_dir / REPORTS_DIR_NAME
    if reports.exists():
        reports.rmdir()
    reports.symlink_to(tmp_path / "nothing", target_is_directory=True)

    with pytest.raises(ReportPathLinkRefused):
        emit_workspace_reports(
            plan=plan, output_dir=output_dir, results_path=results_path
        )
