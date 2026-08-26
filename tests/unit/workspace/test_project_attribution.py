# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A per-project artefact has to say which project it is.

Why this is part of the reporter contract and not a nice-to-have
---------------------------------------------------------------
Ten of the nineteen reporters are ruled PER_PROJECT: no workspace-level artefact,
the per-project files are the answer. For that ruling to be true, the N artefacts
have to be *distinguishable*. For the fifteen file-based reporters they are, by
path -- ``projects/api/reports/ash.ghas.sarif`` versus
``projects/web/reports/...``. For the four that publish to a shared destination
they were not:

* ``s3`` derives its object key from ``metadata.summary_stats.start`` with one
  shared ``key_prefix``, so two projects starting in the same instant overwrote
  each other. Under a workspace that is the default case, not a remote one --
  projects run concurrently.
* ``cloudwatch_logs`` published N events to one log stream with nothing in the
  payload naming the project.
* ``security_hub`` and ``bedrock_summary`` had the same gap in their payloads.

And ``metadata.project_name`` -- which ``html``, ``markdown`` and ``text`` print
as "Project:" -- was the literal string ``"ASH"`` for every project, because it is
hardcoded in ``AshAggregatedResults``'s default and is never derived from
``AshConfig.project_name``. So every per-project human-readable report named the
same project.

The seam these tests span
-------------------------
Attribution is set by ``execute_workspace`` and honoured by the orchestrator, and
those are two different pieces of code. Testing only the first would pass against
an orchestrator that ignored what it was handed -- which is exactly what the
orchestrator did before this, since its ``metadata`` parameter was declared and
never read. So both ends are asserted: that the workspace passes the right thing,
and that the orchestrator puts it where reporters look.
"""

import json
from pathlib import Path

import pytest

from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.schemas.sarif_schema_model import SarifReport
from automated_security_helper.workspace.execution import (
    ProjectScanSettings,
    execute_workspace,
)
from automated_security_helper.workspace.plan import ProjectPlan, WorkspacePlan

WORKSPACE_PROJECT_KEY = "workspace_project"


def _plan(root: Path, *projects) -> WorkspacePlan:
    """*projects* are ``(key, display_label)`` pairs."""
    (root).mkdir(parents=True, exist_ok=True)
    (root / "fixture.code-workspace").write_text(
        json.dumps({"folders": [{"path": key} for key, _ in projects]}),
        encoding="utf-8",
    )
    entries = []
    for key, label in projects:
        (root / key / "src").mkdir(parents=True, exist_ok=True)
        entries.append(
            ProjectPlan(
                key=key,
                relative_path=key,
                path=(root / key).as_posix(),
                label=label,
                display_label=label,
                severity_threshold="MEDIUM",
            )
        )
    return WorkspacePlan(
        workspace_file=(root / "fixture.code-workspace").as_posix(),
        workspace_root=root.as_posix(),
        projects=entries,
    )


class _RecordingOrchestrator:
    """Records the ``metadata`` it was constructed with, per project."""

    seen: dict = {}

    def __init__(self, **kwargs):
        self.key = Path(kwargs["source_dir"]).name
        _RecordingOrchestrator.seen[self.key] = kwargs.get("metadata")

    @classmethod
    def create(cls, **kwargs):
        return cls(**kwargs)

    def execute_scan(self, phases=None):
        model = AshAggregatedResults()
        model.sarif = SarifReport.model_validate({"version": "2.1.0", "runs": []})
        return model


@pytest.fixture(autouse=True)
def _reset_recorder():
    _RecordingOrchestrator.seen = {}
    yield
    _RecordingOrchestrator.seen = {}


class TestTheWorkspaceHandsEachProjectItsOwnIdentity:
    def test_each_project_is_given_its_label_and_key(self, tmp_path):
        plan = _plan(tmp_path / "ws", ("api", "Payments API"), ("web", "web"))
        execute_workspace(
            plan,
            ProjectScanSettings(output_dir=tmp_path / "out", phases=("scan",)),
            orchestrator_factory=_RecordingOrchestrator.create,
        )

        assert _RecordingOrchestrator.seen["api"] == {
            "project_name": "Payments API",
            WORKSPACE_PROJECT_KEY: "api",
        }
        assert _RecordingOrchestrator.seen["web"] == {
            "project_name": "web",
            WORKSPACE_PROJECT_KEY: "web",
        }

    def test_two_projects_never_receive_the_same_identity(self, tmp_path):
        """The property that makes the PER_PROJECT ruling honest.

        Asserted as distinctness rather than against literals, because the defect
        was not a wrong name -- it was the *same* name for every project, which any
        per-project literal assertion would still have passed against.
        """
        plan = _plan(tmp_path / "ws", ("api", "api"), ("web", "web"), ("cli", "cli"))
        execute_workspace(
            plan,
            ProjectScanSettings(output_dir=tmp_path / "out", phases=("scan",)),
            orchestrator_factory=_RecordingOrchestrator.create,
        )

        identities = [
            (value["project_name"], value[WORKSPACE_PROJECT_KEY])
            for value in _RecordingOrchestrator.seen.values()
        ]
        assert len(identities) == 3
        assert len(set(identities)) == 3


class TestTheOrchestratorHonoursWhatItIsHanded:
    """The other half of the seam.

    ``ASHScanOrchestrator.metadata`` was declared and read nowhere -- a dead
    parameter. So "the workspace passes the right thing" proved nothing on its
    own, and this is the assertion that closes the gap.
    """

    @staticmethod
    def _orchestrator(tmp_path, metadata):
        from automated_security_helper.core.orchestrator import ASHScanOrchestrator

        source = tmp_path / "src"
        source.mkdir(parents=True, exist_ok=True)
        return ASHScanOrchestrator.create(
            source_dir=source,
            output_dir=tmp_path / "out",
            metadata=metadata,
        )

    def test_the_metadata_reaches_the_results_model(self, tmp_path):
        orchestrator = self._orchestrator(
            tmp_path, {"project_name": "Payments API", WORKSPACE_PROJECT_KEY: "api"}
        )
        metadata = orchestrator.execution_engine._asharp_model.metadata

        assert metadata.project_name == "Payments API"
        assert getattr(metadata, WORKSPACE_PROJECT_KEY) == "api"

    def test_no_metadata_leaves_the_defaults_alone(self, tmp_path):
        """A single-directory scan is unchanged, so no existing output moves."""
        orchestrator = self._orchestrator(tmp_path, None)
        metadata = orchestrator.execution_engine._asharp_model.metadata

        assert metadata.project_name == "ASH"
        assert getattr(metadata, WORKSPACE_PROJECT_KEY, None) is None

    def test_an_empty_name_is_refused_rather_than_written(self, tmp_path):
        """``project_name`` has a min_length validator, so it must not be bypassed.

        Assigning past a pydantic validator is easy to do by accident and the
        result is a model that cannot be serialised later, a long way from the
        assignment. Better to ignore an unusable value here and keep the default.
        """
        orchestrator = self._orchestrator(tmp_path, {"project_name": "   "})
        assert (
            orchestrator.execution_engine._asharp_model.metadata.project_name == "ASH"
        )


class TestS3KeysCannotCollideAcrossProjects:
    """``PutObject`` overwrites, so a colliding key loses a project's report.

    The reporter is PER_PROJECT, so in a workspace it runs N times against N
    single-project models -- each with ``workspace=None``, because a project does
    not know it is in a workspace. ``metadata.workspace_project`` is how it finds
    out, which is the whole reason that field exists.
    """

    @staticmethod
    def _key(tmp_path, project, start):
        from unittest.mock import MagicMock, patch

        from automated_security_helper.base.plugin_context import PluginContext
        from automated_security_helper.config.ash_config import AshConfig
        from automated_security_helper.plugin_modules.ash_aws_plugins.s3_reporter import (
            S3Reporter,
            S3ReporterConfig,
            S3ReporterConfigOptions,
        )

        model = AshAggregatedResults()
        model.metadata.summary_stats.start = start
        if project is not None:
            setattr(model.metadata, WORKSPACE_PROJECT_KEY, project)

        reporter = S3Reporter(
            context=PluginContext(
                source_dir=tmp_path,
                output_dir=tmp_path / "out",
                config=AshConfig(),
            ),
            config=S3ReporterConfig(
                options=S3ReporterConfigOptions(
                    bucket_name="fixture-bucket",
                    aws_region="us-east-1",
                )
            ),
        )

        captured = {}

        # *args because patch.object replaces the bound method with a plain
        # function, so it receives self and the client positionally.
        def _capture(*args, **kwargs):
            captured.update(kwargs)

        with patch("boto3.Session", MagicMock()):
            with patch.object(S3Reporter, "_put_object_with_retry", _capture):
                reporter.report(model)
        return captured["Key"]

    def test_two_projects_with_the_same_start_time_get_different_keys(self, tmp_path):
        """The collision, reproduced and then closed.

        Identical timestamps on purpose: concurrent projects in one workspace can
        and do start within the same resolution of this value, and before the
        project was in the key that made one report silently replace the other.
        """
        shared = "2026-08-25T00:00:00+00:00"
        api = self._key(tmp_path, "api", shared)
        web = self._key(tmp_path, "web", shared)

        assert api != web
        assert "api" in api
        assert "web" in web

    def test_a_single_directory_scan_keeps_its_existing_key_shape(self, tmp_path):
        """No workspace attribution means the key is what it has always been.

        Composed from the reporter's own default ``key_prefix`` rather than
        written out, so this asserts "nothing was inserted" rather than pinning
        the prefix's current value -- which is ``ash-reports/`` and is not this
        test's business.
        """
        from automated_security_helper.plugin_modules.ash_aws_plugins.s3_reporter import (
            S3ReporterConfigOptions,
        )

        start = "2026-08-25T00:00:00+00:00"
        prefix = S3ReporterConfigOptions.model_fields["key_prefix"].default
        assert self._key(tmp_path, None, start) == f"{prefix}ash-report-{start}.json"

    def test_the_project_segment_is_the_only_difference(self, tmp_path):
        """Pins where the project goes, so the workspace key stays predictable.

        Without this, the collision test above would pass against a key that had
        become unrecognisable to anyone with a lifecycle rule or a bucket prefix
        filter written against the old shape.
        """
        from automated_security_helper.plugin_modules.ash_aws_plugins.s3_reporter import (
            S3ReporterConfigOptions,
        )

        start = "2026-08-25T00:00:00+00:00"
        prefix = S3ReporterConfigOptions.model_fields["key_prefix"].default
        assert (
            self._key(tmp_path, "api", start) == f"{prefix}api/ash-report-{start}.json"
        )
