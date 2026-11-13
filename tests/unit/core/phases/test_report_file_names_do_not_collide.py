# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Two reporters do not write the same file in the reports directory.

Each reporter's report goes to ``reports/ash.<extension>``, and some write files of
their own beside it. When two selected reporters name the same file, the one that
runs last replaces the other's: an ``extension`` that names another reporter's
file, such as ``reporters.cyclonedx.extension: sarif``, left ``reports/ash.sarif``
holding the CycloneDX document, and the exit code was counted from it.

So the run is refused before any reporter writes, in the report phase and in the
workspace report step. Names are compared case-folded and without trailing dots
and spaces, because case-insensitive file systems and Windows treat such names as
the same file. A reporter that names one of its own files twice is not refused:
the Bedrock summary reporter writes its main markdown file itself, by default
under the name the report phase writes it to.
"""

from __future__ import annotations

from pathlib import Path
from typing import Iterable, List, Optional, Tuple

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.base.reporter_plugin import (
    ReporterPluginBase,
    ReporterPluginConfigBase,
    ReporterWorkspaceBehaviour,
    reporter_file_names,
    write_report_file,
)
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.exceptions import ASHValidationError
from automated_security_helper.core.phases.report_phase import ReportPhase
from automated_security_helper.core.progress import LiveProgressDisplay
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.utils.report_path_links import (
    ReportNameCollision,
    ReportPathRefused,
    refuse_colliding_report_names,
)

pytestmark = pytest.mark.unit


def _reporter(
    name: str,
    extension: str,
    companions: Iterable[str] = (),
    behaviour: ReporterWorkspaceBehaviour = ReporterWorkspaceBehaviour.MERGED,
) -> type:
    """A reporter named ``name`` that writes ``ash.<extension>`` and ``companions``."""
    config_class = type(
        f"_{name}_config",
        (ReporterPluginConfigBase,),
        {
            "__annotations__": {"name": str, "extension": str, "enabled": bool},
            "name": name,
            "extension": extension,
            "enabled": True,
        },
    )
    declared = tuple(companions)

    class _Reporter(ReporterPluginBase[config_class]):  # type: ignore[valid-type]
        workspace_behaviour = behaviour

        def model_post_init(self, context):
            if self.config is None:
                self.config = config_class()
            return super().model_post_init(context)

        def companion_file_names(self) -> Tuple[str, ...]:
            return declared

        def report(self, model) -> Optional[str]:
            reports = Path(self.context.output_dir) / "reports"
            for companion in declared:
                write_report_file(reports, companion, name)
            return name

    _Reporter.__name__ = f"_{name.replace('-', '_')}"
    return _Reporter


def _report_phase(tmp_path: Path, reporters: List[type], config=None, formats=None):
    output_dir = tmp_path / "out"
    reports = output_dir / "reports"
    reports.mkdir(parents=True, exist_ok=True)
    phase = ReportPhase(
        plugins=reporters,
        plugin_context=PluginContext(
            source_dir=tmp_path / "src",
            output_dir=output_dir,
            work_dir=output_dir / "work",
            config=config or AshConfig(),
        ),
        progress_display=LiveProgressDisplay(show_progress=False),
        asharp_model=AshAggregatedResults(),
    )
    phase._execute_phase(
        report_dir=reports,
        aggregated_results=AshAggregatedResults(),
        cli_output_formats=formats,
        python_based_plugins_only=False,
    )
    return reports


@pytest.mark.parametrize(
    "second",
    ["first.json", "FIRST.json", "first.json.", "first.json  ", "First.Json. ."],
    ids=["same", "case", "trailing-dot", "trailing-spaces", "all-three"],
)
def test_two_reporters_writing_one_file_refuse_the_run(tmp_path, second):
    reporters = [_reporter("aaa-first", "first.json"), _reporter("bbb-second", second)]

    with pytest.raises(ReportNameCollision) as refused:
        _report_phase(tmp_path, reporters, formats=["aaa-first", "bbb-second"])

    message = str(refused.value)
    assert "aaa-first reporter" in message, message
    assert "bbb-second reporter" in message, message
    assert repr(f"ash.{second}") in message, message
    assert "different extension" in message, message
    assert isinstance(refused.value, ReportPathRefused)
    assert list((tmp_path / "out" / "reports").iterdir()) == []


def test_a_file_one_reporter_writes_beside_its_report_collides_too(tmp_path):
    reporters = [
        _reporter("aaa-first", "first.json"),
        _reporter("bbb-second", "second.json", companions=["ASH.first.json"]),
    ]

    with pytest.raises(ReportNameCollision) as refused:
        _report_phase(tmp_path, reporters, formats=["aaa-first", "bbb-second"])

    assert "'ASH.first.json'" in str(refused.value), str(refused.value)
    assert list((tmp_path / "out" / "reports").iterdir()) == []


def test_a_reporter_that_writes_its_own_report_file_itself_is_not_refused(tmp_path):
    """As the Bedrock summary reporter does with its default ``output_file``."""
    reporters = [
        _reporter("aaa-first", "first.md", companions=["ash.first.md"]),
        _reporter("bbb-second", "second.json"),
    ]

    reports = _report_phase(tmp_path, reporters, formats=["aaa-first", "bbb-second"])

    assert sorted(path.name for path in reports.iterdir()) == [
        "ash.first.md",
        "ash.second.json",
    ]


def _builtin(name: str) -> type:
    """The built-in reporter class configured as ``name``, imported directly."""
    from automated_security_helper.plugin_modules.ash_builtin.reporters.cyclonedx_reporter import (
        CycloneDXReporter,
    )
    from automated_security_helper.plugin_modules.ash_builtin.reporters.github_ghas_reporter import (
        GHASReporter,
    )
    from automated_security_helper.plugin_modules.ash_builtin.reporters.sarif_reporter import (
        SarifReporter,
    )

    return {
        "cyclonedx": CycloneDXReporter,
        "github-ghas": GHASReporter,
        "sarif": SarifReporter,
    }[name]


@pytest.mark.parametrize(
    ("extension", "owner"),
    [("sarif", "sarif"), ("ghas.sarif", "github-ghas"), ("SARIF", "sarif")],
)
def test_an_extension_naming_another_reporters_file_refuses_the_run(
    tmp_path, extension, owner
):
    """A config that gives the CycloneDX report the SARIF report's name, for one."""
    config = AshConfig.model_validate(
        {"reporters": {"cyclonedx": {"extension": extension}}}
    )

    with pytest.raises(ReportNameCollision) as refused:
        _report_phase(
            tmp_path,
            [_builtin(owner), _builtin("cyclonedx")],
            config=config,
            formats=[owner, "cyclonedx"],
        )

    message = str(refused.value)
    assert message.startswith(f"The {owner} reporter"), message
    assert "the cyclonedx reporter" in message, message
    assert list((tmp_path / "out" / "reports").iterdir()) == []


def test_the_shipped_reporters_do_not_collide(tmp_path):
    """Every reporter ASH ships, as configured by default, has names of its own."""
    from automated_security_helper.plugin_modules.ash_aws_plugins import (
        ASH_REPORTERS as AWS_REPORTERS,
    )
    from automated_security_helper.workspace.reporting import MANIFEST_FILENAME
    from tests.utils.helpers import builtin_reporter_classes

    context = PluginContext(
        source_dir=Path("unused"), output_dir=Path("unused"), config=AshConfig()
    )
    instances = [
        cls(context=context) for cls in (*builtin_reporter_classes(), *AWS_REPORTERS)
    ]
    assert len(instances) >= 19

    refuse_colliding_report_names(
        tmp_path,
        [
            (f"the {instance.config.name} reporter", reporter_file_names(instance))
            for instance in instances
        ]
        + [("the workspace report step", (MANIFEST_FILENAME,))],
    )


# The workspace report step, through execute_workspace with a stand-in orchestrator,
# so "before any project is scanned" is "no orchestrator was built".


@pytest.mark.parametrize(
    "behaviour",
    [ReporterWorkspaceBehaviour.MERGED, ReporterWorkspaceBehaviour.PER_PROJECT],
    ids=["merged", "per-project"],
)
def test_the_workspace_preflight_refuses_colliding_names_before_any_project(
    tmp_path, behaviour
):
    """A per-project reporter's names collide in each project's reports/ instead."""
    from tests.unit.workspace import test_workspace_report_path_links as links

    reporters = [
        _reporter("aaa-first", "first.json", behaviour=behaviour),
        _reporter("bbb-second", "First.json", behaviour=behaviour),
    ]
    links._Orchestrator.built = []
    try:
        with pytest.raises(ASHValidationError, match="bbb-second reporter"):
            links._run(tmp_path, extra_reporters=reporters)
        assert links._Orchestrator.built == []
    finally:
        links._Orchestrator.built = []


def test_a_merged_reporter_naming_the_manifest_refuses_the_workspace_report_step(
    tmp_path,
):
    from automated_security_helper.workspace.aggregation import WorkspaceAggregator
    from automated_security_helper.workspace.plan import WorkspacePlan
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

    with pytest.raises(ReportNameCollision) as refused:
        emit_workspace_reports(
            plan=plan,
            output_dir=output_dir,
            results_path=results_path,
            reporter_classes=[
                _reporter(
                    "aaa-first", "first.json", companions=["Workspace-Reports.json"]
                )
            ],
        )

    assert "the workspace report step" in str(refused.value), str(refused.value)
    assert list((output_dir / REPORTS_DIR_NAME).iterdir()) == []
