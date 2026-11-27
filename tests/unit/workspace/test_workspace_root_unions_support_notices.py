"""The workspace results file records the support notices of every project, by id.

Why this exists
---------------
The metadata of a workspace's unified results file is written fresh, with only the
keys the writer names, so a key a project's own metadata holds reaches the root only
if the writer carries it. Each project's scan records what it met: the rows raised at
the start of a run are the same for every project, and a row raised at a decision (a
scanner that is skipped, a sandbox backend that falls back) is recorded only by the
projects that reached the decision. A root that kept the first project's notices alone
would drop the others'.

The writer takes each project's ``metadata.support_notices`` in workspace-file order
and records them united by id, the first record of an id kept. It writes no key when no
project recorded one, so the results of a workspace on a fully supported
configuration are written as they were before the field existed.

The controls are the same file with no notice in any project, and a project that
holds none beside one that does.
"""

import json
from pathlib import Path

import pytest

from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.workspace.aggregation import WorkspaceAggregator
from automated_security_helper.workspace.plan import WorkspacePlan
from tests.unit.models._support_notice_helpers import (
    CPU_ID,
    POLYFILL_ID,
    SANDBOX_ID,
    cpu_notice,
    polyfill_notice,
    sandbox_notice,
)

pytestmark = pytest.mark.unit


def _written(tmp_path: Path, per_project, run: int = 1):
    """The unified file the writer makes for projects holding ``per_project``'s
    notices, as parsed JSON and as the results model reads it back."""
    plan = WorkspacePlan(
        workspace_file=(tmp_path / "platform.code-workspace").as_posix(),
        workspace_root=tmp_path.as_posix(),
        projects=[],
    )
    aggregator = WorkspaceAggregator(plan=plan, output_dir=tmp_path / f"out{run}")
    path = aggregator.write(
        exit_code=0, wall_clock_seconds=1.0, support_notices=per_project
    )
    text = path.read_text(encoding="utf-8")
    return json.loads(text), AshAggregatedResults.model_validate_json(text)


def _ids(document: dict) -> list[str]:
    return [notice["id"] for notice in document["metadata"]["support_notices"]]


class TestEveryProjectsNoticesAreRecorded:
    def test_a_later_projects_notice_reaches_the_root(self, tmp_path):
        document, model = _written(
            tmp_path, [[cpu_notice()], [sandbox_notice(), polyfill_notice()]]
        )

        assert _ids(document) == [CPU_ID, SANDBOX_ID, POLYFILL_ID]
        assert [notice.id for notice in model.metadata.support_notices] == [
            CPU_ID,
            SANDBOX_ID,
            POLYFILL_ID,
        ]

    def test_the_root_holds_each_notice_whole(self, tmp_path):
        document, model = _written(tmp_path, [[], [cpu_notice()]])

        assert document["metadata"]["support_notices"] == [
            cpu_notice().model_dump(mode="json")
        ]
        assert model.metadata.support_notices == [cpu_notice()]

    def test_a_notice_two_projects_share_is_recorded_once_as_the_first_has_it(
        self, tmp_path
    ):
        first = cpu_notice(found="avx2 is missing (polars-runtime-32 1.44.2).")
        second = cpu_notice(
            found="avx2 and fma are missing (polars-runtime-32 1.44.2)."
        )

        document, _ = _written(tmp_path, [[first], [second, sandbox_notice()]])

        assert _ids(document) == [CPU_ID, SANDBOX_ID]
        assert document["metadata"]["support_notices"][0]["found"] == first.found

    def test_the_order_is_the_workspace_file_order_of_the_projects(self, tmp_path):
        document, _ = _written(
            tmp_path, [[polyfill_notice()], [sandbox_notice()], [cpu_notice()]]
        )

        assert _ids(document) == [POLYFILL_ID, SANDBOX_ID, CPU_ID]

    def test_a_project_holding_none_beside_one_that_does_records_the_one(
        self, tmp_path
    ):
        document, _ = _written(tmp_path, [None, [], [cpu_notice()], None])

        assert _ids(document) == [CPU_ID]


class TestAWorkspaceOnASupportedConfigurationWritesNoKey:
    @pytest.mark.parametrize(
        "per_project",
        [
            pytest.param(None, id="no projects given"),
            pytest.param([], id="no project"),
            pytest.param([None, None], id="projects that recorded none"),
            pytest.param([[], []], id="projects that recorded an empty list"),
        ],
    )
    def test_the_key_is_absent_and_the_model_reads_none(self, tmp_path, per_project):
        document, model = _written(tmp_path, per_project)

        assert "support_notices" not in document["metadata"], sorted(
            document["metadata"]
        )
        assert model.metadata.support_notices is None
