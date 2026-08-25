# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Merging per-project results without changing any project's verdict.

The three properties these tests exist to hold:

* A project's actionable count is what ``ash --source-dir P`` would compute. The
  equivalence is asserted against ``_compute_exit_code`` itself rather than
  reasoned about, because that function is the definition.
* Path conversion happens once, through Phase 0's ``to_workspace_pattern``, and a
  path it refuses is counted rather than dropped. Dropping is a silent false
  negative.
* Each SARIF run stays coherent with exactly one root, so a consumer that
  ingests against a single repository root does not mis-locate findings.
"""

import json

import pytest

from automated_security_helper.models.workspace import (
    ProjectRunStatus,
    WorkspaceProjectResult,
)
from automated_security_helper.workspace.aggregation import (
    NOT_ABSOLUTE,
    PROJECT_ROOT_URI_BASE_ID,
    WorkspaceAggregator,
    count_actionable_results,
    has_finding_at_min_severity,
    project_relative_uri,
    project_root_uri,
    rebase_run_for_project,
    to_workspace_uri,
)
from automated_security_helper.workspace.plan import ProjectPlan, WorkspacePlan


def _plan(tmp_path, *keys):
    return WorkspacePlan(
        workspace_file=(tmp_path / "fixture.code-workspace").as_posix(),
        workspace_root=tmp_path.as_posix(),
        projects=[
            ProjectPlan(
                key=key,
                relative_path=key,
                path=(tmp_path / key).as_posix(),
                label=key,
                display_label=key,
                severity_threshold="MEDIUM",
            )
            for key in keys
        ],
    )


def _result(
    uri="src/app.py",
    *,
    level="error",
    severity=None,
    suppressed=False,
    scanner="bandit",
):
    """One SARIF result, shaped the way ASH's scanners actually emit them.

    ``message`` is present because the SARIF schema requires it, and
    ``properties.scanner_name`` because that is the only attribution ASH carries
    -- every scanner merges into one run whose driver is ASH itself.
    """
    entry = {
        "ruleId": "B307",
        "level": level,
        "message": {"text": "fixture finding"},
        "locations": [
            {"physicalLocation": {"artifactLocation": {"uri": uri}}},
        ],
        "properties": {},
    }
    if scanner is not None:
        entry["properties"]["scanner_name"] = scanner
    if severity is not None:
        entry["properties"]["issue_severity"] = severity
    if suppressed:
        entry["suppressions"] = [{"kind": "external"}]
    return entry


def _run(*results):
    return {
        "tool": {"driver": {"name": "ASH"}},
        "results": list(results),
        "invocations": [],
    }


class TestWorkspaceUriConversion:
    def test_a_project_relative_path_gains_the_project_prefix(self):
        assert to_workspace_uri("src/app.py", "api") == "api/src/app.py"

    def test_a_nested_project_prefix_is_applied_whole(self):
        assert to_workspace_uri("src/app.py", "apps/web") == "apps/web/src/app.py"

    def test_a_rooted_uri_is_refused_when_there_is_no_project_path(self):
        """Reverses an earlier expectation, deliberately.

        This used to assert ``/src/app.py`` -> ``api/src/app.py``, borrowing
        ``to_workspace_pattern``'s rule that a leading separator means
        project-rooted. That rule is right for an operator-written pattern and
        wrong for a scanner-emitted URI, which names a real file that the prefix
        relocates. With no project path to relativize against, refusing is the
        only honest answer -- and the caller counts it.
        """
        assert to_workspace_uri("/src/app.py", "api") is None

    def test_a_rooted_uri_is_relativized_when_the_project_path_is_known(self):
        assert (
            to_workspace_uri("/ws/api/src/app.py", "api", "/ws/api") == "api/src/app.py"
        )

    def test_a_file_scheme_uri_is_unwrapped_before_conversion(self):
        assert (
            to_workspace_uri("file:///ws/api/src/app.py", "api", "/ws/api")
            == "api/src/app.py"
        )

    def test_a_backslash_path_is_normalised(self):
        assert to_workspace_uri("src\\app.py", "api") == "api/src/app.py"

    def test_a_path_the_converter_refuses_returns_none(self):
        """Not an exception and not a silent pass-through -- the caller counts it."""
        assert to_workspace_uri("../outside/app.py", "api") is None

    def test_a_drive_anchored_path_returns_none(self):
        assert to_workspace_uri("C:/Windows/app.py", "api") is None

    def test_an_empty_uri_returns_none(self):
        assert to_workspace_uri("", "api") is None


class TestAbsoluteScannerUris:
    """The shapes real scanners emit, and why prefixing them was wrong.

    ``scripts/verify_external_target_scan.py`` records three different URI shapes
    from one healthy run. They appear whenever the process working directory
    differs from ``source_dir``, which in workspace mode it must for all but one
    project -- so these are the default here, not an edge case.

    Prefixing an absolute path relocates a real file to somewhere that names
    nothing, and the old code did it silently: two of the three shapes were not
    even counted as unconvertible, which defeated the counter's whole purpose.
    """

    PROJECT = "/ws/api"

    @pytest.mark.parametrize(
        "uri,expected",
        [
            # bandit: absolute, rooted.
            ("/ws/api/src/insecure_app.py", "api/src/insecure_app.py"),
            # checkov: absolute with the leading separator already stripped
            # upstream. No leading-separator test can catch this one.
            ("ws/api/src/insecure_bucket.tf", "api/src/insecure_bucket.tf"),
            # detect-secrets: relative to the process cwd, which we cannot know.
            ("../../../../ws/api/src/app.py", None),
            # The ordinary case, unchanged.
            ("src/ok.py", "api/src/ok.py"),
            # Absolute and outside the project: refused, never prefixed.
            ("/somewhere/else/x.py", None),
            ("/ws/other-project/x.py", None),
            # file:// scheme on an absolute path.
            ("file:///ws/api/src/f.py", "api/src/f.py"),
            # The project root itself names a directory, not a finding.
            ("/ws/api", None),
        ],
    )
    def test_the_measured_shapes(self, uri, expected):
        assert to_workspace_uri(uri, "api", self.PROJECT) == expected

    @pytest.mark.parametrize(
        "uri",
        [
            "C:/ws/api/src/w.py",
            "/C:/ws/api/src/w.py",
            "file:///C:/ws/api/src/w.py",
            "C:\\ws\\api\\src\\w.py",
        ],
    )
    def test_a_windows_project_relativizes_every_drive_spelling(self, uri):
        """file:///C:/x reduces to /C:/x, so a drive arrives spelled three ways."""
        assert to_workspace_uri(uri, "api", "C:/ws/api") == "api/src/w.py"

    def test_a_relative_windows_uri_still_converts(self):
        assert to_workspace_uri("src\\w.py", "api", "C:/ws/api") == "api/src/w.py"

    def test_a_nested_project_prefix_is_applied_after_relativizing(self):
        assert (
            to_workspace_uri("/ws/apps/web/src/a.py", "apps/web", "/ws/apps/web")
            == "apps/web/src/a.py"
        )

    def test_a_sibling_project_sharing_a_name_prefix_is_not_swallowed(self):
        """/ws/api-v2 is not inside /ws/api, however similar the text looks."""
        assert to_workspace_uri("/ws/api-v2/src/a.py", "api", "/ws/api") is None

    def test_project_relative_uri_distinguishes_its_three_answers(self):
        """None and NOT_ABSOLUTE mean different things and must not be conflated."""
        assert project_relative_uri("/ws/api/src/a.py", "/ws/api") == "src/a.py"
        assert project_relative_uri("/elsewhere/a.py", "/ws/api") is None
        assert project_relative_uri("src/a.py", "/ws/api") is NOT_ABSOLUTE

    def test_the_ambiguous_nesting_is_read_as_absolute(self):
        """Documented, not accidental.

        A project at /ws/api containing its own path as a subtree -- ws/api/src
        under /ws/api -- makes a project-relative 'ws/api/src/x.py' textually
        identical to a separator-stripped absolute one. Resolved in favour of
        absolute, because that nesting is pathological while checkov's shape is
        routine. No filesystem check: aggregation must not depend on the tree
        still being present, and reading the same SARIF twice must not give two
        answers.
        """
        assert project_relative_uri("ws/api/src/x.py", "/ws/api") == "src/x.py"


class TestProjectRootUri:
    def test_the_root_uri_ends_with_a_separator(self):
        """SARIF wants a directory URI, and a consumer joins onto it."""
        assert project_root_uri("/w/api").endswith("/")

    def test_the_root_uri_carries_the_file_scheme(self):
        assert project_root_uri("/w/api").startswith("file://")

    def test_a_trailing_separator_is_not_doubled(self):
        assert not project_root_uri("/w/api/").endswith("//")


class TestRebaseRun:
    def test_the_run_declares_the_project_root_as_a_uri_base(self, tmp_path):
        plan = _plan(tmp_path, "api")
        run, _ = rebase_run_for_project(_run(_result()), plan.projects[0])
        base = run["originalUriBaseIds"][PROJECT_ROOT_URI_BASE_ID]["uri"]
        assert base.startswith("file://")
        assert base.endswith("api/")

    def test_result_uris_stay_project_relative(self, tmp_path):
        """One run, one root. Rewriting the URI would break that coherence."""
        plan = _plan(tmp_path, "api")
        run, _ = rebase_run_for_project(_run(_result("src/app.py")), plan.projects[0])
        location = run["results"][0]["locations"][0]["physicalLocation"]
        assert location["artifactLocation"]["uri"] == "src/app.py"

    def test_result_uris_are_anchored_to_the_project_root_base(self, tmp_path):
        plan = _plan(tmp_path, "api")
        run, _ = rebase_run_for_project(_run(_result()), plan.projects[0])
        location = run["results"][0]["locations"][0]["physicalLocation"]
        assert location["artifactLocation"]["uriBaseId"] == PROJECT_ROOT_URI_BASE_ID

    def test_an_existing_uri_base_id_is_left_alone(self, tmp_path):
        """A scanner that already anchored its output knows better than we do."""
        plan = _plan(tmp_path, "api")
        entry = _result()
        entry["locations"][0]["physicalLocation"]["artifactLocation"]["uriBaseId"] = (
            "SRCROOT"
        )
        run, _ = rebase_run_for_project(_run(entry), plan.projects[0])
        location = run["results"][0]["locations"][0]["physicalLocation"]
        assert location["artifactLocation"]["uriBaseId"] == "SRCROOT"

    def test_every_result_carries_the_project_key(self, tmp_path):
        plan = _plan(tmp_path, "api")
        run, _ = rebase_run_for_project(
            _run(_result(), _result("src/other.py")), plan.projects[0]
        )
        assert [r["properties"]["workspace_project"] for r in run["results"]] == [
            "api",
            "api",
        ]

    def test_every_result_carries_its_workspace_relative_path(self, tmp_path):
        plan = _plan(tmp_path, "api")
        run, _ = rebase_run_for_project(_run(_result("src/app.py")), plan.projects[0])
        assert run["results"][0]["properties"]["workspace_uri"] == "api/src/app.py"

    def test_the_run_itself_carries_the_project_attribution(self, tmp_path):
        """So a consumer can select one project by selecting a run."""
        plan = _plan(tmp_path, "api")
        run, _ = rebase_run_for_project(_run(_result()), plan.projects[0])
        assert run["properties"]["workspace_project"] == "api"
        assert run["properties"]["workspace_project_path"] == "api"

    def test_an_unconvertible_path_is_counted_and_the_finding_is_kept(self, tmp_path):
        plan = _plan(tmp_path, "api")
        run, unconvertible = rebase_run_for_project(
            _run(_result("../escapes/app.py")), plan.projects[0]
        )
        assert unconvertible == 1
        assert len(run["results"]) == 1
        assert "workspace_uri" not in run["results"][0]["properties"]

    def test_a_result_with_no_location_survives(self, tmp_path):
        plan = _plan(tmp_path, "api")
        entry = {"ruleId": "B307", "level": "error"}
        run, unconvertible = rebase_run_for_project(_run(entry), plan.projects[0])
        assert len(run["results"]) == 1
        assert unconvertible == 0

    def test_an_absolute_uri_is_rewritten_to_project_relative(self, tmp_path):
        """The run declares one root; every path inside it must be relative to it."""
        plan = _plan(tmp_path, "api")
        absolute = (tmp_path / "api" / "src" / "app.py").as_posix()
        run, unconvertible = rebase_run_for_project(
            _run(_result(absolute)), plan.projects[0]
        )
        artifact = run["results"][0]["locations"][0]["physicalLocation"][
            "artifactLocation"
        ]
        assert artifact["uri"] == "src/app.py"
        assert artifact["uriBaseId"] == PROJECT_ROOT_URI_BASE_ID
        assert run["results"][0]["properties"]["workspace_uri"] == "api/src/app.py"
        assert unconvertible == 0

    def test_an_absolute_uri_outside_the_project_gets_no_uri_base_id(self, tmp_path):
        """An artifactLocation with both an absolute uri and a base ID is
        self-contradictory, and GitHub code scanning mis-locates or rejects it."""
        plan = _plan(tmp_path, "api")
        outside = (tmp_path / "elsewhere" / "x.py").as_posix()
        run, unconvertible = rebase_run_for_project(
            _run(_result(outside)), plan.projects[0]
        )
        artifact = run["results"][0]["locations"][0]["physicalLocation"][
            "artifactLocation"
        ]
        assert artifact["uri"] == outside
        assert "uriBaseId" not in artifact
        assert "workspace_uri" not in run["results"][0]["properties"]
        assert unconvertible == 1

    def test_a_relative_uri_still_gets_the_base_id(self, tmp_path):
        plan = _plan(tmp_path, "api")
        run, _ = rebase_run_for_project(_run(_result("src/app.py")), plan.projects[0])
        artifact = run["results"][0]["locations"][0]["physicalLocation"][
            "artifactLocation"
        ]
        assert artifact["uriBaseId"] == PROJECT_ROOT_URI_BASE_ID

    def test_unconvertible_counts_findings_not_locations(self, tmp_path):
        """One finding with three bad locations is one loss, not three."""
        plan = _plan(tmp_path, "api")
        entry = _result("../a.py")
        physical = entry["locations"][0]["physicalLocation"]
        entry["locations"] = [
            {"physicalLocation": {"artifactLocation": {"uri": "../a.py"}}},
            {"physicalLocation": {"artifactLocation": {"uri": "/gone/b.py"}}},
            {"physicalLocation": {"artifactLocation": {"uri": "../../c.py"}}},
        ]
        assert physical is not None
        run, unconvertible = rebase_run_for_project(_run(entry), plan.projects[0])
        assert unconvertible == 1
        assert "workspace_uri" not in run["results"][0]["properties"]

    def test_a_finding_with_one_good_location_is_not_counted(self, tmp_path):
        """It has a workspace-relative path, so nothing was lost."""
        plan = _plan(tmp_path, "api")
        entry = _result("../a.py")
        entry["locations"] = [
            {"physicalLocation": {"artifactLocation": {"uri": "../a.py"}}},
            {"physicalLocation": {"artifactLocation": {"uri": "C:/b.py"}}},
            {"physicalLocation": {"artifactLocation": {"uri": "src/c.py"}}},
        ]
        run, unconvertible = rebase_run_for_project(_run(entry), plan.projects[0])
        assert unconvertible == 0
        assert run["results"][0]["properties"]["workspace_uri"] == "api/src/c.py"

    def test_two_bad_findings_count_twice(self, tmp_path):
        """Per-finding, not per-run: the counter still scales with real losses."""
        plan = _plan(tmp_path, "api")
        run, unconvertible = rebase_run_for_project(
            _run(_result("../a.py"), _result("../b.py")), plan.projects[0]
        )
        assert unconvertible == 2

    def test_the_input_run_is_not_mutated(self, tmp_path):
        """The caller may still be holding the model this dict came from."""
        plan = _plan(tmp_path, "api")
        original = _run(_result())
        snapshot = json.dumps(original, sort_keys=True)
        rebase_run_for_project(original, plan.projects[0])
        assert json.dumps(original, sort_keys=True) == snapshot


class TestActionableCounting:
    @pytest.mark.parametrize(
        "threshold,expected",
        [("ALL", 4), ("LOW", 3), ("MEDIUM", 2), ("HIGH", 1), ("CRITICAL", 1)],
    )
    def test_the_level_ladder_matches_the_shipped_qualifying_levels(
        self, threshold, expected
    ):
        results = [
            _result(level="error"),
            _result(level="warning"),
            _result(level="note"),
            _result(level="none"),
        ]
        assert count_actionable_results(results, threshold) == expected

    def test_issue_severity_takes_precedence_over_the_level(self):
        """A HIGH finding at level note is still HIGH."""
        results = [_result(level="note", severity="HIGH")]
        assert count_actionable_results(results, "HIGH") == 1

    def test_an_unrecognised_issue_severity_falls_back_to_the_level(self):
        results = [_result(level="error", severity="SPICY")]
        assert count_actionable_results(results, "HIGH") == 1

    def test_a_suppressed_finding_is_never_actionable(self):
        results = [_result(level="error", suppressed=True)]
        assert count_actionable_results(results, "ALL") == 0

    def test_a_missing_level_is_read_as_note(self):
        entry = {"ruleId": "B307"}
        assert count_actionable_results([entry], "LOW") == 1
        assert count_actionable_results([entry], "MEDIUM") == 0

    def test_the_threshold_is_matched_case_insensitively(self):
        """run_ash_scan upper-cases the configured value; the ladder does not."""
        results = [_result(level="warning")]
        assert count_actionable_results(results, "medium") == 1

    def test_no_threshold_means_no_gate(self):
        results = [_result(level="error")]
        assert count_actionable_results(results, None) == 0


class TestMinSeverityGate:
    def test_the_default_gate_admits_an_ordinary_finding(self):
        assert has_finding_at_min_severity([_result(level="note")], "low") is True

    def test_level_none_also_admits_at_the_default_gate(self):
        """Parity, not preference.

        ``_compute_exit_code``'s level map has no entry for ``none`` and defaults
        a miss to ``low``, so a level-``none`` finding satisfies --min-severity
        low there. Mapping ``none`` to ``info`` here would read more sensibly and
        would make the workspace verdict differ from the standalone one, which is
        the one thing this module must not do.
        """
        assert has_finding_at_min_severity([_result(level="none")], "low") is True

    def test_the_gate_rejects_a_run_of_informational_findings(self):
        assert has_finding_at_min_severity([_result(level="note")], "medium") is False

    def test_a_suppressed_finding_does_not_satisfy_the_gate(self):
        assert (
            has_finding_at_min_severity(
                [_result(level="error", suppressed=True)], "low"
            )
            is False
        )

    def test_a_none_threshold_admits_everything(self):
        assert has_finding_at_min_severity([], "none") is True

    def test_a_high_gate_rejects_a_warning(self):
        assert has_finding_at_min_severity([_result(level="warning")], "high") is False


class TestParityWithComputeExitCode:
    """The invariant, asserted against the function that defines it.

    ``_compute_exit_code`` reads the persisted SARIF and counts against
    ``global_settings.severity_threshold``. If this aggregator's count ever
    diverges, a project's workspace verdict stops matching its standalone one --
    which is the single thing this whole design exists to prevent.
    """

    @staticmethod
    def _standalone_exit_code(tmp_path, results, threshold):
        """What ``ash --source-dir P`` would exit with, for this SARIF.

        Both the persisted file and the in-memory model are populated, because
        ``_compute_exit_code`` reads both and they gate different things: the file
        drives the threshold count, and the in-memory ``sarif`` drives the
        ``--min-severity`` gate that can zero it. Populating only one produces a
        verdict no real scan can reach, and the test would then be pinning
        nothing.
        """
        from automated_security_helper.config.ash_config import AshConfig
        from automated_security_helper.interactions.run_ash_scan import (
            ScanOptions,
            _compute_exit_code,
        )
        from automated_security_helper.models.asharp_model import AshAggregatedResults
        from automated_security_helper.schemas.sarif_schema_model import SarifReport

        document = {"version": "2.1.0", "runs": [_run(*results)]}
        reports = tmp_path / "reports"
        reports.mkdir(parents=True, exist_ok=True)
        (reports / "ash.sarif").write_text(json.dumps(document), encoding="utf-8")

        config = AshConfig()
        config.global_settings.severity_threshold = threshold
        model = AshAggregatedResults(ash_config=config)
        model.sarif = SarifReport.model_validate(document)
        opts = ScanOptions(source_dir=tmp_path, output_dir=tmp_path)
        return _compute_exit_code(model, opts, None)

    def _mine(self, results, threshold, min_severity="low"):
        """The workspace verdict for one project, as the executor derives it."""
        actionable = count_actionable_results(results, threshold)
        if actionable and not has_finding_at_min_severity(results, min_severity):
            actionable = 0
        return actionable

    @pytest.mark.parametrize("threshold", ["ALL", "LOW", "MEDIUM", "HIGH", "CRITICAL"])
    @pytest.mark.parametrize("level", ["error", "warning", "note", "none"])
    def test_one_finding_agrees_on_the_verdict(self, tmp_path, threshold, level):
        results = [_result(level=level)]
        standalone = self._standalone_exit_code(tmp_path, results, threshold)
        assert (standalone == 2) == (self._mine(results, threshold) > 0)

    @pytest.mark.parametrize("threshold", ["ALL", "LOW", "MEDIUM", "HIGH", "CRITICAL"])
    @pytest.mark.parametrize("severity", ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"])
    def test_an_issue_severity_agrees_on_the_verdict(
        self, tmp_path, threshold, severity
    ):
        """The arm that decides most real findings: scanners set issue_severity."""
        results = [_result(level="note", severity=severity)]
        standalone = self._standalone_exit_code(tmp_path, results, threshold)
        assert (standalone == 2) == (self._mine(results, threshold) > 0)

    @pytest.mark.parametrize("threshold", ["ALL", "LOW", "MEDIUM", "HIGH", "CRITICAL"])
    def test_a_mixed_run_agrees_on_the_verdict(self, tmp_path, threshold):
        results = [
            _result(level="error"),
            _result(level="warning"),
            _result(level="note"),
            _result(level="error", suppressed=True),
            _result(level="note", severity="CRITICAL"),
        ]
        standalone = self._standalone_exit_code(tmp_path, results, threshold)
        assert (standalone == 2) == (self._mine(results, threshold) > 0)

    @pytest.mark.parametrize("threshold", ["ALL", "LOW", "MEDIUM", "HIGH", "CRITICAL"])
    def test_a_fully_suppressed_run_agrees_on_the_verdict(self, tmp_path, threshold):
        results = [_result(level="error", suppressed=True)]
        standalone = self._standalone_exit_code(tmp_path, results, threshold)
        assert standalone == 0
        assert self._mine(results, threshold) == 0

    @pytest.mark.parametrize("threshold", ["ALL", "LOW", "MEDIUM", "HIGH", "CRITICAL"])
    def test_an_empty_run_agrees_on_the_verdict(self, tmp_path, threshold):
        standalone = self._standalone_exit_code(tmp_path, [], threshold)
        assert standalone == 0
        assert self._mine([], threshold) == 0


class TestAggregatorOutput:
    @staticmethod
    def _outcome(key, **kwargs):
        return WorkspaceProjectResult(
            project=key,
            relative_path=key,
            display_label=key,
            status=ProjectRunStatus.COMPLETED,
            output_path=f"projects/{key}",
            **kwargs,
        )

    def test_the_unified_file_parses_as_json(self, tmp_path):
        """The writer streams rather than dumping one object, so this is not free."""
        plan = _plan(tmp_path, "api", "web")
        aggregator = WorkspaceAggregator(plan=plan, output_dir=tmp_path / "out")
        for key in ("api", "web"):
            aggregator.add(
                self._outcome(key),
                _run(_result()),
                plan.projects[0 if key == "api" else 1],
            )
        path = aggregator.write(exit_code=0, wall_clock_seconds=1.0)
        parsed = json.loads(path.read_text(encoding="utf-8"))
        assert len(parsed["sarif"]["runs"]) == 2

    def test_the_unified_file_validates_as_the_aggregated_results_model(self, tmp_path):
        from automated_security_helper.models.asharp_model import AshAggregatedResults

        plan = _plan(tmp_path, "api")
        aggregator = WorkspaceAggregator(plan=plan, output_dir=tmp_path / "out")
        aggregator.add(self._outcome("api"), _run(_result()), plan.projects[0])
        path = aggregator.write(exit_code=0, wall_clock_seconds=1.0)
        model = AshAggregatedResults.model_validate_json(
            path.read_text(encoding="utf-8")
        )
        assert model.workspace is not None
        assert [p.project for p in model.workspace.projects] == ["api"]

    def test_one_run_per_project_in_project_order(self, tmp_path):
        plan = _plan(tmp_path, "api", "web")
        aggregator = WorkspaceAggregator(plan=plan, output_dir=tmp_path / "out")
        # Added out of order, as a parallel run would deliver them.
        aggregator.add(self._outcome("web"), _run(_result()), plan.projects[1])
        aggregator.add(self._outcome("api"), _run(_result()), plan.projects[0])
        path = aggregator.write(exit_code=0, wall_clock_seconds=1.0)
        parsed = json.loads(path.read_text(encoding="utf-8"))
        attributions = [
            run["properties"]["workspace_project"] for run in parsed["sarif"]["runs"]
        ]
        assert attributions == ["api", "web"]

    def test_the_run_index_recorded_per_project_selects_that_project(self, tmp_path):
        plan = _plan(tmp_path, "api", "web")
        aggregator = WorkspaceAggregator(plan=plan, output_dir=tmp_path / "out")
        aggregator.add(self._outcome("web"), _run(_result()), plan.projects[1])
        aggregator.add(self._outcome("api"), _run(_result()), plan.projects[0])
        path = aggregator.write(exit_code=0, wall_clock_seconds=1.0)
        parsed = json.loads(path.read_text(encoding="utf-8"))
        for entry in parsed["workspace"]["projects"]:
            run = parsed["sarif"]["runs"][entry["sarif_run_index"]]
            assert run["properties"]["workspace_project"] == entry["project"]

    def test_a_project_with_no_run_records_no_run_index(self, tmp_path):
        plan = _plan(tmp_path, "api")
        aggregator = WorkspaceAggregator(plan=plan, output_dir=tmp_path / "out")
        aggregator.add(
            WorkspaceProjectResult(
                project="api",
                relative_path="api",
                display_label="api",
                status=ProjectRunStatus.SKIPPED,
                output_path="projects/api",
            ),
            None,
            plan.projects[0],
        )
        path = aggregator.write(exit_code=0, wall_clock_seconds=1.0)
        parsed = json.loads(path.read_text(encoding="utf-8"))
        assert parsed["workspace"]["projects"][0]["sarif_run_index"] is None
        assert parsed["sarif"]["runs"] == []

    def test_unconvertible_paths_are_reported_in_the_payload(self, tmp_path):
        plan = _plan(tmp_path, "api")
        aggregator = WorkspaceAggregator(plan=plan, output_dir=tmp_path / "out")
        aggregator.add(
            self._outcome("api"), _run(_result("../escapes.py")), plan.projects[0]
        )
        path = aggregator.write(exit_code=0, wall_clock_seconds=1.0)
        parsed = json.loads(path.read_text(encoding="utf-8"))
        assert parsed["workspace"]["unconvertible_finding_paths"] == 1

    def test_the_spool_is_removed_after_writing(self, tmp_path):
        plan = _plan(tmp_path, "api")
        out = tmp_path / "out"
        aggregator = WorkspaceAggregator(plan=plan, output_dir=out)
        aggregator.add(self._outcome("api"), _run(_result()), plan.projects[0])
        aggregator.write(exit_code=0, wall_clock_seconds=1.0)
        assert not aggregator.spool_dir.exists()

    def test_only_one_run_is_held_in_memory_at_a_time(self, tmp_path):
        """Peak memory scales with max_parallel_projects, not with project count.

        Asserted structurally: after add() returns, the aggregator holds no
        reference to the run it was given, only a spooled file. A regression that
        starts accumulating runs on the instance fails here.
        """
        plan = _plan(tmp_path, "api", "web")
        aggregator = WorkspaceAggregator(plan=plan, output_dir=tmp_path / "out")
        aggregator.add(self._outcome("api"), _run(_result()), plan.projects[0])
        aggregator.add(self._outcome("web"), _run(_result()), plan.projects[1])
        held = [
            value
            for value in vars(aggregator).values()
            if isinstance(value, dict) and "results" in value
        ]
        assert held == []

    def test_scanner_results_sums_across_projects(self, tmp_path):
        plan = _plan(tmp_path, "api", "web")
        aggregator = WorkspaceAggregator(plan=plan, output_dir=tmp_path / "out")
        aggregator.add(
            self._outcome("api", scanners={"bandit": "PASSED"}),
            _run(_result()),
            plan.projects[0],
        )
        aggregator.add(
            self._outcome("web", scanners={"bandit": "FAILED"}),
            _run(_result(), _result("src/two.py")),
            plan.projects[1],
        )
        path = aggregator.write(exit_code=0, wall_clock_seconds=1.0)
        parsed = json.loads(path.read_text(encoding="utf-8"))
        assert parsed["scanner_results"]["bandit"]["finding_count"] == 3

    def test_scanner_results_sums_actionable_across_projects(self, tmp_path):
        """The rollup's actionable count was hardcoded to zero by construction.

        ``core/resource_management/result_filters.py`` reads this key and
        republishes it as ``actionable_findings``, so a zero here tells a consumer
        that a workspace with real findings has none -- fail-open, with the
        correct value two keys away in the same file.
        """
        plan = _plan(tmp_path, "api", "web")
        aggregator = WorkspaceAggregator(plan=plan, output_dir=tmp_path / "out")
        aggregator.add(
            self._outcome(
                "api", scanners={"bandit": "FAILED"}, actionable_finding_count=2
            ),
            _run(_result(), _result("src/two.py")),
            plan.projects[0],
        )
        aggregator.add(
            self._outcome(
                "web", scanners={"bandit": "FAILED"}, actionable_finding_count=1
            ),
            _run(_result()),
            plan.projects[1],
        )
        parsed = json.loads(
            aggregator.write(exit_code=2, wall_clock_seconds=1.0).read_text(
                encoding="utf-8"
            )
        )
        assert parsed["scanner_results"]["bandit"]["actionable_finding_count"] == 3

    def test_the_rollup_total_equals_the_sum_of_the_per_project_totals(self, tmp_path):
        """The invariant that makes the rollup safe to read at all."""
        plan = _plan(tmp_path, "api", "web")
        aggregator = WorkspaceAggregator(plan=plan, output_dir=tmp_path / "out")
        for index, key in enumerate(("api", "web")):
            results = [_result(), _result("src/two.py", scanner="checkov")]
            actionable = count_actionable_results(
                results, plan.projects[index].severity_threshold
            )
            aggregator.add(
                self._outcome(
                    key,
                    scanners={"bandit": "FAILED", "checkov": "FAILED"},
                    actionable_finding_count=actionable,
                ),
                _run(*results),
                plan.projects[index],
            )
        parsed = json.loads(
            aggregator.write(exit_code=2, wall_clock_seconds=1.0).read_text(
                encoding="utf-8"
            )
        )
        rollup = sum(
            entry["actionable_finding_count"]
            for entry in parsed["scanner_results"].values()
        )
        per_project = sum(
            entry["actionable_finding_count"]
            for entry in parsed["workspace"]["projects"]
        )
        assert rollup == per_project

    def test_a_project_whose_actionable_count_is_zero_contributes_zero(self, tmp_path):
        """This is how the --min-severity gate reaches the rollup.

        That gate is a whole-scan switch in ``_compute_exit_code``, not a
        per-finding filter, so the aggregator cannot re-derive it. Taking the
        project's own zero as authoritative keeps the rollup from exceeding the
        per-project total.
        """
        plan = _plan(tmp_path, "api")
        aggregator = WorkspaceAggregator(plan=plan, output_dir=tmp_path / "out")
        aggregator.add(
            self._outcome(
                "api", scanners={"bandit": "PASSED"}, actionable_finding_count=0
            ),
            _run(_result(level="error"), _result("src/two.py", level="error")),
            plan.projects[0],
        )
        parsed = json.loads(
            aggregator.write(exit_code=0, wall_clock_seconds=1.0).read_text(
                encoding="utf-8"
            )
        )
        entry = parsed["scanner_results"]["bandit"]
        assert entry["actionable_finding_count"] == 0
        assert entry["finding_count"] == 2

    def test_actionable_is_judged_against_each_project_own_threshold(self, tmp_path):
        """A looser project contributes less from identical findings."""
        plan = _plan(tmp_path, "strict", "lax")
        plan.projects[0].severity_threshold = "LOW"
        plan.projects[1].severity_threshold = "CRITICAL"
        aggregator = WorkspaceAggregator(plan=plan, output_dir=tmp_path / "out")
        for index, key in enumerate(("strict", "lax")):
            results = [_result(level="warning")]
            actionable = count_actionable_results(
                results, plan.projects[index].severity_threshold
            )
            aggregator.add(
                self._outcome(
                    key,
                    scanners={"bandit": "FAILED"},
                    actionable_finding_count=actionable,
                ),
                _run(*results),
                plan.projects[index],
            )
        parsed = json.loads(
            aggregator.write(exit_code=2, wall_clock_seconds=1.0).read_text(
                encoding="utf-8"
            )
        )
        # strict contributes 1 at LOW, lax contributes 0 at CRITICAL.
        assert parsed["scanner_results"]["bandit"]["actionable_finding_count"] == 1
        assert parsed["scanner_results"]["bandit"]["finding_count"] == 2

    def test_scanner_results_takes_the_worst_status(self, tmp_path):
        plan = _plan(tmp_path, "api", "web")
        aggregator = WorkspaceAggregator(plan=plan, output_dir=tmp_path / "out")
        aggregator.add(
            self._outcome("api", scanners={"bandit": "PASSED"}), None, plan.projects[0]
        )
        aggregator.add(
            self._outcome("web", scanners={"bandit": "ERROR"}), None, plan.projects[1]
        )
        path = aggregator.write(exit_code=0, wall_clock_seconds=1.0)
        parsed = json.loads(path.read_text(encoding="utf-8"))
        assert parsed["scanner_results"]["bandit"]["status"] == "ERROR"
