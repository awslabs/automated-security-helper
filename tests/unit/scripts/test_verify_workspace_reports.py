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

import json
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

    def test_a_null_field_and_an_unparsable_junit_file_are_recorded(
        self, reports, tmp_path
    ):
        """Both are shapes a malformed report tree produces, not gate defects.

        A field present but null raises AttributeError where the check reads
        it; a truncated ash.junit.xml raises ParseError out of fromstring. Both
        escaped the tuple and aborted the gate, losing the problems collected.
        """

        def null_workspace(output_dir):
            flat = {"workspace": None}
            return [flat.get("workspace", {}).get("projects")]

        def truncated_junit(output_dir):
            from defusedxml import ElementTree

            ElementTree.fromstring("<testsuites><testsuite")
            return []

        def fine(output_dir):
            return ["fine: one problem"]

        problems = reports.run_checks(tmp_path, (null_workspace, truncated_junit, fine))
        assert len(problems) == 3
        assert problems[0].startswith(
            "null_workspace: could not finish; AttributeError"
        )
        assert problems[1].startswith("truncated_junit: could not finish; ParseError")
        assert problems[2] == "fine: one problem"

    def test_an_unexpected_exception_still_propagates(self, reports, tmp_path):
        def broken(output_dir):
            raise RuntimeError("not a shape of the report tree")

        with pytest.raises(RuntimeError):
            reports.run_checks(tmp_path, (broken,))


class TestChildEnvironment:
    def test_ash_variables_and_safepath_are_dropped(self, reports):
        """At the base the child got a copy of the whole environment."""
        env = reports.child_environment(
            {
                "PATH": "/usr/bin",
                "ASH_CONFIG": "/elsewhere/ash.yaml",
                "ASH_EXCLUDED_SCANNERS": "bandit",
                "PYTHONSAFEPATH": "1",
                "ASHY": "kept",
            }
        )
        assert not [key for key in env if key.startswith("ASH_")]
        assert "PYTHONSAFEPATH" not in env
        assert env["ASHY"] == "kept"
        assert env["PYTHONIOENCODING"] == "utf-8"
        assert env["PYTHONUTF8"] == "1"


def _manifest_entry(**fields):
    entry = {
        "behaviour": "merged",
        "considered": True,
        "covers_projects": True,
        "workspace_artifact": None,
        "per_project_artifacts": [],
        "missing_per_project_artifacts": [],
    }
    entry.update(fields)
    return entry


def _write_manifest(output_dir: Path, reports, overrides=None) -> Path:
    """A manifest and report tree where every merged artefact is present and ruled."""
    reports_dir = output_dir / reports.REPORTS_DIR_NAME
    reports_dir.mkdir(parents=True, exist_ok=True)
    entries = {}
    for name, filename in reports.EXPECTED_MERGED_ARTIFACTS.items():
        (reports_dir / filename).write_text("x", encoding="utf-8")
        behaviour = (
            "workspace-scoped"
            if name in reports.WORKSPACE_SCOPED_REPORTERS
            else "merged"
        )
        entries[name] = _manifest_entry(
            behaviour=behaviour,
            covers_projects=behaviour == "merged",
            workspace_artifact=f"{reports.REPORTS_DIR_NAME}/{filename}",
        )
    for name, filename in reports.EXPECTED_PER_PROJECT_ARTIFACTS.items():
        pointers = []
        for project in reports.FIXTURE_PROJECTS:
            path = Path("projects") / project.key / "reports" / filename
            (output_dir / path).parent.mkdir(parents=True, exist_ok=True)
            (output_dir / path).write_text("x", encoding="utf-8")
            pointers.append({"project": project.key, "path": path.as_posix()})
        entries[name] = _manifest_entry(
            behaviour="per-project",
            covers_projects=False,
            per_project_artifacts=pointers,
        )
    for name, fields in (overrides or {}).items():
        entries[name].update(fields)
    manifest = {
        "projects": [project.key for project in reports.FIXTURE_PROJECTS],
        "reporters": entries,
    }
    (reports_dir / reports.MANIFEST_FILENAME).write_text(
        json.dumps(manifest), encoding="utf-8"
    )
    return output_dir


class TestManifest:
    def test_a_complete_manifest_is_clean(self, reports, tmp_path):
        assert reports.check_manifest(_write_manifest(tmp_path, reports)) == []

    def test_the_expected_artifact_is_printed_with_its_directory(
        self, reports, tmp_path
    ):
        """At the base the message printed the bare filename as the expected value."""
        out = _write_manifest(
            tmp_path, reports, {"csv": {"workspace_artifact": "ash.csv"}}
        )
        problems = reports.check_manifest(out)
        assert problems == [
            "csv: manifest says workspace_artifact='ash.csv', expected 'reports/ash.csv'"
        ]

    def test_a_merged_reporter_ruled_workspace_scoped_is_reported(
        self, reports, tmp_path
    ):
        """At the base behaviour and covers_projects were read for per-project only."""
        out = _write_manifest(
            tmp_path,
            reports,
            {"csv": {"behaviour": "workspace-scoped", "covers_projects": False}},
        )
        problems = reports.check_manifest(out)
        assert "csv: behaviour is 'workspace-scoped', expected 'merged'" in problems
        assert any(p.startswith("csv: covers_projects is False") for p in problems)

    def test_a_merged_reporter_that_recorded_an_error_is_reported(
        self, reports, tmp_path
    ):
        out = _write_manifest(tmp_path, reports, {"sarif": {"error": "boom"}})
        problems = reports.check_manifest(out)
        assert problems == [
            "sarif: recorded an error although its artefact was written: boom"
        ]


class TestOcsf:
    def test_an_entry_without_metadata_is_a_recorded_problem(self, reports):
        """At the base finding['metadata'] raised KeyError on an error document."""
        ocsf = [
            {"error": "the reporter fell back"},
            {"metadata": {"labels": ["workspace_project:api"]}},
            {"metadata": {"labels": ["workspace_project:web"]}},
        ]
        problems = reports.ocsf_problems(ocsf, {"api", "web"})
        assert len(problems) == 1
        assert problems[0].startswith("ocsf: entry 0 carries no metadata")

    def test_labelled_projects_are_read(self, reports):
        ocsf = [{"metadata": {"labels": ["workspace_project:api"]}}]
        assert reports.ocsf_problems(ocsf, {"api", "web"}) == [
            "ocsf: labelled projects are ['api']"
        ]


class TestTextLabels:
    TEXT = (
        "Scanner results\n"
        "api/src/marker.py:2  B602\n"
        "\n"
        "PROJECTS\n"
        "-----------------------------\n"
        "Project         Threshold  Findings\n"
        "-----------------------------\n"
        "web-app (web)   LOW        1\n"
        "\n"
    )

    def test_a_label_only_mentioned_in_a_path_is_not_a_row(self, reports):
        """At the base `'api' in text` was satisfied by the finding path api/src."""
        problems = reports.text_label_problems(self.TEXT, ["api", "web-app (web)"])
        assert problems == ["text: no PROJECTS row labelled 'api'"]

    def test_a_label_that_is_a_cell_is_found(self, reports):
        text = self.TEXT.replace(
            "web-app (web)   LOW        1\n",
            "web-app (web)   LOW        1\napi             LOW        1\n",
        )
        assert reports.text_label_problems(text, ["api", "web-app (web)"]) == []


class TestArguments:
    def test_the_description_survives_a_stripped_docstring(self, reports, monkeypatch):
        """At the base __doc__.splitlines() crashed under python -OO."""
        monkeypatch.setattr(reports, "__doc__", None)
        assert reports._parse_args([]).timeout == 900.0


class TestTimedOutScan:
    def test_a_timed_out_scan_is_a_failed_run_not_a_traceback(
        self, reports, tmp_path, monkeypatch, capsys
    ):
        """At the base TimeoutExpired escaped main and no FAILED report was printed."""
        import subprocess

        def mkdtemp(suffix=None, prefix=None, dir=None) -> str:  # noqa: A002 - tempfile's name
            # tempfile.mkdtemp's full signature, so the stand-in survives the
            # gate passing the parent directory or the prefix positionally.
            scratch = tmp_path / f"{prefix or ''}scratch"
            scratch.mkdir()
            return str(scratch)

        def fake_run_scan(definition, output_dir, timeout):
            raise subprocess.TimeoutExpired(
                cmd=["ash"], timeout=timeout, output="partial out", stderr=None
            )

        monkeypatch.setattr(reports.tempfile, "mkdtemp", mkdtemp)
        monkeypatch.setattr(reports, "run_scan", fake_run_scan)
        assert reports.main(["--timeout", "7"]) == 1
        out = capsys.readouterr().out
        assert "FAILED" in out
        assert "did not finish within 7 seconds" in out
        assert "partial out" in out


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
