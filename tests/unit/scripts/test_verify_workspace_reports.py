# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""scripts/verify_workspace_reports.py: the fixture and the check runner.

* the api fixture project declares no project_name, as the docstring says, so
  the label's key fallback is exercised;
* a check that raises is recorded as its own problem and the other checks
  still run;
* an empty merged CSV is a recorded problem, not an IndexError.
"""

from __future__ import annotations

from pathlib import Path

import pytest

pytestmark = pytest.mark.unit


@pytest.fixture
def reports(script_loader):
    return script_loader("verify_workspace_reports")


class TestFixture:
    def test_the_api_project_declares_no_project_name(self, reports, tmp_path: Path):
        reports.build_workspace(tmp_path)
        api_config = (tmp_path / "api" / ".ash" / "ash.yaml").read_text(
            encoding="utf-8"
        )
        web_config = (tmp_path / "web" / ".ash" / "ash.yaml").read_text(
            encoding="utf-8"
        )
        assert "project_name" not in api_config
        assert "project_name: web-app" in web_config

    def test_the_expected_metadata_name_falls_back_to_the_key(self, reports):
        by_key = {project.key: project for project in reports.FIXTURE_PROJECTS}
        assert by_key["api"].declared_name is None
        assert by_key["api"].expected_project_name == "api"
        assert by_key["web"].expected_project_name == "web-app"


class TestRunChecks:
    def test_a_raising_check_is_recorded_and_the_rest_still_run(
        self, reports, tmp_path
    ):
        def missing_artefact(output_dir):
            raise reports.GateFailure("expected file does not exist: ash.csv")

        def key_error(output_dir):
            raise KeyError("reporters")

        def fine(output_dir):
            return ["fine: one problem"]

        problems = reports.run_checks(tmp_path, (missing_artefact, key_error, fine))
        assert problems == [
            "missing_artefact: could not finish; GateFailure: expected file does not exist: ash.csv",
            "key_error: could not finish; KeyError: 'reporters'",
            "fine: one problem",
        ]

    def test_an_unexpected_exception_still_propagates(self, reports, tmp_path):
        def broken(output_dir):
            raise RuntimeError("not a shape of the report tree")

        with pytest.raises(RuntimeError):
            reports.run_checks(tmp_path, (broken,))


class TestCsv:
    def test_an_empty_csv_is_a_recorded_problem(self, reports):
        assert reports.csv_problems("", {"api", "web"}) == [
            "csv: ash.csv is empty or starts with a blank row, so it names no project"
        ]

    def test_a_blank_first_row_is_a_recorded_problem(self, reports):
        problems = reports.csv_problems("\nworkspace_project\napi\n", {"api"})
        assert len(problems) == 1 and "blank row" in problems[0]

    def test_a_complete_csv_is_clean(self, reports):
        text = "workspace_project,rule\napi,B602\nweb,B403\n"
        assert reports.csv_problems(text, {"api", "web"}) == []

    def test_a_missing_project_is_named(self, reports):
        text = "workspace_project,rule\napi,B602\n"
        assert reports.csv_problems(text, {"api", "web"}) == [
            "csv: projects in rows are ['api'], expected ['api', 'web']"
        ]
