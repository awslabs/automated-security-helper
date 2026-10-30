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
import sys
from pathlib import Path

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
from automated_security_helper.utils.output_dir_links import OutputDirLinkRefused
from automated_security_helper.workspace.execution import _coverage_fields
from automated_security_helper.workspace.plan import ProjectPlan, WorkspacePlan

pytestmark = pytest.mark.unit


def incomplete_scanners_for_project(results):
    """Names of the incomplete scanners, read as a single scan reads them."""
    from automated_security_helper.interactions.run_ash_scan import (
        scan_incompleteness,
    )

    return [name for name, _status in scan_incompleteness(results, gate=True).scanners]


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

    def test_a_backslash_in_a_sanitized_uri_is_part_of_the_name(self):
        """The project's scan wrote "/" for its separators when it sanitized the
        URI, so a backslash left in it is part of a POSIX file name. Under a
        Windows project path it is a separator (test_a_relative_windows_uri_still_converts)."""
        assert to_workspace_uri("src\\app.py", "api") == "api/src\\app.py"
        assert to_workspace_uri("src/app.py", "api") == "api/src/app.py"

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
            # Unrooted: project-relative, whatever its components spell. checkov's
            # separator-stripped absolute shape does not reach the aggregator in
            # workspace mode (sanitize_sarif_paths relativizes it against the
            # project first), and reading an unrooted URI as absolute relocated
            # the routine src-layout finding below.
            ("ws/api/src/insecure_bucket.tf", "api/ws/api/src/insecure_bucket.tf"),
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

    def test_an_unrooted_uri_spelling_the_projects_path_stays_relative(self):
        """Documented, not accidental.

        A project at /ws/api whose files spell its own absolute path -- ws/api/src
        under /ws/api -- makes a project-relative 'ws/api/src/x.py' textually
        identical to a separator-stripped absolute one. Read as project-relative:
        the stripped shape does not reach the aggregator in workspace mode, while
        this nesting is the routine container layout (the workspace mounted at
        /src, a src-layout project at /src/api holding src/api/x.py). No
        filesystem check: aggregation must not depend on the tree still being
        present, and reading the same SARIF twice must not give two answers.
        """
        assert project_relative_uri("ws/api/src/x.py", "/ws/api") is NOT_ABSOLUTE
        assert project_relative_uri("src/api/x.py", "/src/api") is NOT_ABSOLUTE


class TestProjectRootUri:
    """Why these take ``tmp_path`` instead of a POSIX literal.

    ``project_root_uri`` calls ``Path.as_uri()``, which refuses any path its own
    platform reads as relative. ``/w/api`` is absolute on POSIX but on Windows it
    has a root and no drive, and the Windows flavour's ``is_absolute()`` requires
    both -- so the literal raised ``ValueError: relative path can't be expressed
    as a file URI`` on all four windows-latest rows of the matrix while every
    POSIX row passed.

    Production never supplies that shape. The one caller is
    ``rebase_run_for_project``, which passes ``project.path``; the resolver sets
    that from ``candidate.resolved.as_posix()`` and ``resolved`` comes from
    ``Path.resolve()``, which on Windows is always drive-qualified. So the bug was
    in the fixture, and anchoring the input with ``.absolute()`` or ``.resolve()``
    inside ``project_root_uri`` would have been the wrong repair twice over: it
    would silently bind a rootless path to whatever the current drive happens to
    be, and it would stop ``as_uri()`` rejecting a genuinely relative path.

    ``tmp_path`` is drive-qualified on Windows and rooted on POSIX, which is the
    shape production supplies on both.
    """

    def test_the_root_uri_ends_with_a_separator(self, tmp_path):
        """SARIF wants a directory URI, and a consumer joins onto it."""
        assert project_root_uri((tmp_path / "api").as_posix()).endswith("/")

    def test_the_root_uri_carries_the_file_scheme(self, tmp_path):
        assert project_root_uri((tmp_path / "api").as_posix()).startswith("file://")

    def test_a_root_path_uri_is_not_given_a_second_separator(self, tmp_path):
        """The filesystem anchor is the only input that reaches the guard.

        ``as_uri()`` normalises a trailing separator away -- ``/w/api/`` and
        ``/w/api`` both give ``file:///w/api`` -- so a directory spelled with a
        trailing slash exercises the branch that *appends*, never the branch that
        declines to. This test used to pass ``/w/api/`` and was named for the
        trailing separator, and it held with the guard deleted: it could not fail.
        The anchor is the one input whose URI already ends in a separator,
        ``file:///`` on POSIX and ``file:///C:/`` on Windows, so it is the only
        input the guard is there for.

        Asserted as equality with ``as_uri()`` rather than as ``not
        endswith("//")``. The POSIX anchor's correct URI *is* ``file:///``, which
        ends with two separators -- joining onto it gives ``file:///src/app.py``,
        exactly right -- so the old spelling would report a violation here on
        Linux while staying green on Windows, inverting the split it is meant to
        close.
        """
        assert project_root_uri(tmp_path.anchor) == Path(tmp_path.anchor).as_uri()


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

    def test_a_missing_level_is_read_as_the_missing_level(self):
        """MISSING_SARIF_LEVEL, "warning" (MEDIUM); it was "note" here."""
        entry = {"ruleId": "B307"}
        assert count_actionable_results([entry], "MEDIUM") == 1
        assert count_actionable_results([entry], "HIGH") == 0

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

    def test_a_declared_severity_decides_over_the_level(self):
        """issue_severity first, as run_ash_scan._severity_filters_finding reads it.

        The workspace gate read the level alone, so a scanner's declared HIGH at
        level note never met --min-severity high, and a declared LOW at level
        error always did.
        """
        assert (
            has_finding_at_min_severity(
                [_result(level="note", severity="HIGH")], "high"
            )
            is True
        )
        assert (
            has_finding_at_min_severity(
                [_result(level="error", severity="LOW")], "high"
            )
            is False
        )


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

        ``scanner_results`` is populated for the same reason, and it was added when
        the completeness gate was introduced. Measured: with ``scanner_results``
        left empty, ``get_unified_scanner_metrics`` still derives one entry per
        ``properties.scanner_name`` in the SARIF, and
        ``ScannerStatisticsCalculator`` gives a scanner it has no
        ``scanner_results`` record for the status **ERROR** -- findings attributed
        to a scanner the report has no evidence ran. That is fail-closed and right,
        but wherever the gate is enabled it made every case here exit 1 on
        completeness before the threshold count was ever consulted, so all 36
        parity assertions were comparing ``False`` against the aggregator and
        pinning nothing about thresholds. ``fail_on_incomplete_scanners`` defaults
        to False, so populating the entries is what keeps this fixture independent
        of that default rather than reliant on it.

        A real scan always writes a ``scanner_results`` entry for every scanner --
        measured at 10 of 10 on a local run, including the three that were MISSING
        -- so PASSED entries here make the model one a real scan could produce
        rather than weakening the comparison.
        """
        from automated_security_helper.config.ash_config import AshConfig
        from automated_security_helper.core.enums import ScannerStatus
        from automated_security_helper.interactions.run_ash_scan import (
            ScanOptions,
            _compute_exit_code,
        )
        from automated_security_helper.models.asharp_model import (
            AshAggregatedResults,
            ScannerTargetStatusInfo,
        )
        from automated_security_helper.schemas.sarif_schema_model import SarifReport

        document = {"version": "2.1.0", "runs": [_run(*results)]}
        reports = tmp_path / "reports"
        reports.mkdir(parents=True, exist_ok=True)
        (reports / "ash.sarif").write_text(json.dumps(document), encoding="utf-8")

        config = AshConfig()
        config.global_settings.severity_threshold = threshold
        model = AshAggregatedResults(ash_config=config)
        model.sarif = SarifReport.model_validate(document)
        for entry in results:
            scanner = (entry.get("properties") or {}).get("scanner_name")
            if scanner:
                model.scanner_results[str(scanner)] = ScannerTargetStatusInfo(
                    status=ScannerStatus.PASSED,
                    excluded=False,
                    dependencies_satisfied=True,
                )
        opts = ScanOptions(source_dir=tmp_path, output_dir=tmp_path)
        return _compute_exit_code(model, opts, None)

    def _mine(self, results, threshold, min_severity="low", threshold_for=None):
        """The workspace verdict for one project, as the executor derives it.

        The ``--min-severity`` gate is handed the same two thresholds the count
        used, as ``_scan_one_project`` hands them, so a finding its own scanner's
        threshold made non-actionable cannot be the one that keeps the count.
        """
        actionable = count_actionable_results(
            results, threshold, threshold_for=threshold_for
        )
        if actionable and not has_finding_at_min_severity(
            results, min_severity, threshold, threshold_for=threshold_for
        ):
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

    @pytest.mark.parametrize(
        ("scanners", "standalone_expected"),
        [
            (["bandit"], 0),
            (["semgrep"], 2),
            (["bandit", "semgrep"], 2),
        ],
        ids=["own-stricter", "project-wide", "both"],
    )
    def test_a_scanners_own_threshold_agrees_through_real_config(
        self, tmp_path, scanners, standalone_expected
    ):
        """The per-scanner arm, read from a recorded config and not a monkeypatch.

        bandit's own ``options.severity_threshold`` is CRITICAL under a
        project-wide MEDIUM; a HIGH from bandit passes and a HIGH from semgrep
        fails. ``_compute_exit_code`` on the left, the workspace counter with the
        executor's resolver on the right, both reading the same ``AshConfig``.
        """
        from automated_security_helper.config.ash_config import AshConfig
        from automated_security_helper.core.enums import ScannerStatus
        from automated_security_helper.interactions.run_ash_scan import (
            ScanOptions,
            _compute_exit_code,
        )
        from automated_security_helper.models.asharp_model import (
            AshAggregatedResults,
            ScannerTargetStatusInfo,
        )
        from automated_security_helper.schemas.sarif_schema_model import SarifReport
        from automated_security_helper.workspace.aggregation import (
            actionable_results_by_scanner,
        )
        from automated_security_helper.workspace.execution import (
            _scanner_threshold_resolver,
        )

        results = [
            _result(level="warning", severity="HIGH", scanner=name) for name in scanners
        ]
        document = {"version": "2.1.0", "runs": [_run(*results)]}
        reports = tmp_path / "reports"
        reports.mkdir(parents=True, exist_ok=True)
        (reports / "ash.sarif").write_text(json.dumps(document), encoding="utf-8")
        config = AshConfig()
        config.global_settings.severity_threshold = "MEDIUM"
        config.scanners.bandit.options.severity_threshold = "CRITICAL"
        model = AshAggregatedResults(ash_config=config)
        model.sarif = SarifReport.model_validate(document)
        for name in scanners:
            model.scanner_results[name] = ScannerTargetStatusInfo(
                status=ScannerStatus.PASSED, excluded=False, dependencies_satisfied=True
            )

        standalone = _compute_exit_code(
            model, ScanOptions(source_dir=tmp_path, output_dir=tmp_path), None
        )
        project = _plan(tmp_path, "api").projects[0]
        mine = actionable_results_by_scanner(
            results, "MEDIUM", threshold_for=_scanner_threshold_resolver(model, project)
        )

        assert standalone == standalone_expected
        assert (standalone == 2) == (sum(mine.values()) > 0)
        assert mine.get("bandit", 0) == 0
        assert mine.get("semgrep", 0) == (1 if "semgrep" in scanners else 0)

    @pytest.mark.parametrize(
        ("bandit_threshold", "standalone_expected"),
        [("CRITICAL", 0), (None, 2)],
        ids=["below-its-scanners-threshold", "control-no-own-threshold"],
    )
    def test_a_result_at_the_minimum_below_its_scanners_threshold_keeps_no_count(
        self, tmp_path, bandit_threshold, standalone_expected
    ):
        """``--min-severity medium`` over a semgrep LOW and a bandit MEDIUM.

        The semgrep LOW is actionable under the project-wide LOW and below the
        minimum; the bandit MEDIUM meets the minimum. With bandit's own
        ``options.severity_threshold`` CRITICAL that MEDIUM was never counted, so
        no counted finding meets the minimum and the single scan exits 0. The
        workspace gate read the bandit MEDIUM by severity alone and kept the
        semgrep count standing, exit 2, for the same project. The control, with no
        own threshold, has the bandit MEDIUM counted and qualifying on both sides.
        """
        from automated_security_helper.config.ash_config import AshConfig
        from automated_security_helper.core.enums import ScannerStatus
        from automated_security_helper.interactions.run_ash_scan import (
            ScanOptions,
            _compute_exit_code,
        )
        from automated_security_helper.models.asharp_model import (
            AshAggregatedResults,
            ScannerTargetStatusInfo,
        )
        from automated_security_helper.schemas.sarif_schema_model import SarifReport
        from automated_security_helper.workspace.execution import (
            _scanner_threshold_resolver,
        )

        results = [
            _result(level="note", scanner="semgrep"),
            _result(level="warning", scanner="bandit"),
        ]
        document = {"version": "2.1.0", "runs": [_run(*results)]}
        reports = tmp_path / "reports"
        reports.mkdir(parents=True, exist_ok=True)
        (reports / "ash.sarif").write_text(json.dumps(document), encoding="utf-8")
        config = AshConfig()
        config.global_settings.severity_threshold = "LOW"
        if bandit_threshold is not None:
            config.scanners.bandit.options.severity_threshold = bandit_threshold
        model = AshAggregatedResults(ash_config=config)
        model.sarif = SarifReport.model_validate(document)
        for name in ("semgrep", "bandit"):
            model.scanner_results[name] = ScannerTargetStatusInfo(
                status=ScannerStatus.PASSED, excluded=False, dependencies_satisfied=True
            )

        standalone = _compute_exit_code(
            model,
            ScanOptions(
                source_dir=tmp_path, output_dir=tmp_path, min_severity="medium"
            ),
            None,
        )
        project = _plan(tmp_path, "api").projects[0]
        mine = self._mine(
            results,
            "LOW",
            min_severity="medium",
            threshold_for=_scanner_threshold_resolver(model, project),
        )

        assert standalone == standalone_expected
        assert (standalone == 2) == (mine > 0)


class TestCompletenessParityWithComputeExitCode:
    """The other half of the same invariant, on the pass that was not mirrored.

    ``_compute_exit_code`` asks two questions in order: did the selected scanners
    run, and did they find anything. The class above pins the second. This pins
    the first, which the workspace layer did not mirror at all -- so a project
    whose scanners never ran reported zero findings, and zero findings read as a
    pass. ``ash --source-dir P`` exited 1 on that project and the same P inside a
    workspace exited 0.

    Asserted as an agreement between the two derivations rather than against
    literals, for the same reason the threshold parity is: a test that hardcoded 1
    on one side would keep passing if the other side stopped answering.
    """

    @staticmethod
    def _model(scanner_statuses, invocations=None):
        """One project's results, with ``scanner_results`` as a real scan writes it.

        ``scanner_statuses`` maps scanner name to ``(status, excluded,
        dependencies_satisfied)``. A finding is attributed to each scanner because
        ``ScannerStatisticsCalculator`` enumerates from both the SARIF and
        ``scanner_results``, and a scanner present in only one of them exercises a
        different branch than a real scan reaches. ``invocations`` replaces the
        run's ``invocations`` list when given, for the run-level notifications a
        rule that could not be evaluated leaves.
        """
        from automated_security_helper.config.ash_config import AshConfig
        from automated_security_helper.models.asharp_model import (
            AshAggregatedResults,
            ScannerTargetStatusInfo,
        )
        from automated_security_helper.schemas.sarif_schema_model import SarifReport

        entries = [
            _result(level="note", severity="INFO", scanner=name)
            for name in scanner_statuses
        ]
        config = AshConfig()
        config.global_settings.severity_threshold = "CRITICAL"
        model = AshAggregatedResults(ash_config=config)
        run = _run(*entries)
        if invocations is not None:
            run["invocations"] = invocations
        model.sarif = SarifReport.model_validate({"version": "2.1.0", "runs": [run]})
        for name, (status, excluded, satisfied) in scanner_statuses.items():
            model.scanner_results[name] = ScannerTargetStatusInfo(
                status=status,
                excluded=excluded,
                dependencies_satisfied=satisfied,
            )
        return model

    def _standalone_exit_code(self, tmp_path, scanner_statuses):
        """``_compute_exit_code`` with the completeness gate explicitly ON.

        Explicit rather than defaulted, and that is what makes the parity assertions
        below mean anything. ``incomplete_scanners_for_project`` reports the
        incomplete set unconditionally, while ``_compute_exit_code`` only acts on it
        when ``fail_on_incomplete_scanners`` resolves true -- which is off by
        default, since this repository cannot yet pass its own gate. Leaving it
        defaulted compares a gated verdict against an ungated list, so the two
        derivations disagree on the flag rather than on the scanners, and the
        invariant this class exists for goes untested in the direction that matters.
        """
        from automated_security_helper.interactions.run_ash_scan import (
            ScanOptions,
            _compute_exit_code,
        )

        model = self._model(scanner_statuses)
        opts = ScanOptions(
            source_dir=tmp_path,
            output_dir=tmp_path,
            fail_on_incomplete_scanners=True,
        )
        return _compute_exit_code(model, opts, None)

    @pytest.mark.parametrize("status", ["MISSING", "ERROR"])
    def test_an_incomplete_scanner_is_seen_by_both_derivations(self, tmp_path, status):
        statuses = {
            "bandit": ("PASSED", False, True),
            "cfn-nag": (status, False, status != "MISSING"),
        }
        standalone = self._standalone_exit_code(tmp_path, statuses)
        mine = incomplete_scanners_for_project(self._model(statuses))

        assert (standalone == 1) == bool(mine)
        # And the same scanner, not merely the same yes-or-no answer.
        assert mine == ["cfn-nag"]

    def test_a_complete_run_is_clean_to_both_derivations(self, tmp_path):
        """The control. Without it the agreement above could hold at always-fail."""
        statuses = {"bandit": ("PASSED", False, True)}
        standalone = self._standalone_exit_code(tmp_path, statuses)
        mine = incomplete_scanners_for_project(self._model(statuses))

        assert standalone == 0
        assert mine == []

    def test_an_excluded_scanner_is_clean_to_both_derivations(self, tmp_path):
        """The case that separates reading the metrics from reading raw statuses.

        Excluded AND its tool absent, which is ``--exclude-scanners cfn-nag`` on a
        host without cfn-nag, and also every shard of a sharded scan. Both
        derivations must read SKIPPED, which they do only because both go through
        ``scan_incompleteness`` -- a read of ``scanner_results[*].status``
        directly would see MISSING.
        """
        statuses = {
            "bandit": ("PASSED", False, True),
            "cfn-nag": ("MISSING", True, False),
        }
        standalone = self._standalone_exit_code(tmp_path, statuses)
        mine = incomplete_scanners_for_project(self._model(statuses))

        assert standalone == 0
        assert mine == []

    def test_a_none_model_is_read_as_no_coverage_facts(self):
        """``scan_incompleteness(None)`` answers an empty ``ScanIncompleteness``.

        ``_coverage_fields`` has no guard of its own for ``None``; it relies on this.
        Pinned so that the day ``scan_incompleteness`` raises on ``None``, this fails.
        ``_scan_one_project`` does not reach the coverage fields with a ``None``
        model (a crashed scan is FAILED before that point), so the answer matters
        only as the contract ``_coverage_fields`` is written against.
        """
        from automated_security_helper.interactions.run_ash_scan import (
            scan_incompleteness,
        )

        facts = scan_incompleteness(None, gate=True)

        assert not facts
        assert facts.no_scanner_ran is False
        assert facts.scanners == ()
        assert _coverage_fields(None) == {
            "incomplete_scanners": [],
            "incomplete_scanner_details": {},
            "partial_coverage_scanners": [],
            "no_scanner_ran": False,
            "unevaluated_rules": [],
            "unstoppable_tools": {},
        }

    @pytest.mark.parametrize(
        ("statuses", "roster", "exit_code"),
        [
            # Per-scanner arm only: a MISSING scanner beside one that ran.
            (
                {
                    "bandit": ("PASSED", False, True),
                    "cfn-nag": ("MISSING", False, False),
                },
                [],
                1,
            ),
            # Set-level arm only: every entry SKIPPED.
            ({"bandit": ("SKIPPED", True, True)}, [], 1),
            # Set-level arm through the roster: nothing recorded, a roster says
            # the scan phase ran.
            ({}, ["bandit"], 1),
            # Controls: a narrowed run that measured something, and a clean one.
            (
                {"bandit": ("PASSED", False, True), "cfn-nag": ("SKIPPED", True, True)},
                [],
                0,
            ),
            ({"bandit": ("PASSED", False, True)}, [], 0),
        ],
    )
    def test_the_fields_the_scan_writes_agree_with_the_exit_code(
        self, tmp_path, statuses, roster, exit_code
    ):
        """``_coverage_fields`` is what ``_scan_one_project`` writes into the outcome.

        Called from here and from production with only the results, so the helper
        owns the ``gate=`` it reads under and a change to it (a field dropped, a
        different ``gate=``, a filter on the details) moves this test. The expected
        side is ``_compute_exit_code`` on a second model built the same way, run with
        the completeness gate ON: the verdict a workspace project has to match. With
        the helper reading under ``gate=False`` the per-scanner and roster cells come
        back empty while the exit code is still 1, which is what fails here.
        """
        from automated_security_helper.models.workspace import WorkspaceProjectResult

        model = self._model(statuses)
        model.metadata.expected_scanners = list(roster)
        standalone_model = self._model(statuses)
        standalone_model.metadata.expected_scanners = list(roster)
        from automated_security_helper.interactions.run_ash_scan import (
            ScanOptions,
            _compute_exit_code,
        )

        standalone = _compute_exit_code(
            standalone_model,
            ScanOptions(
                source_dir=tmp_path,
                output_dir=tmp_path,
                fail_on_incomplete_scanners=True,
            ),
            None,
        )
        fields = _coverage_fields(model)

        assert standalone == exit_code
        assert set(fields) <= set(WorkspaceProjectResult.model_fields)
        assert set(fields) == {
            "incomplete_scanners",
            "incomplete_scanner_details",
            "partial_coverage_scanners",
            "no_scanner_ran",
            "unevaluated_rules",
            "unstoppable_tools",
        }
        # The two exit-1 arms the gate does not govern ride in the same read and
        # are empty in every case here, so the gated arms alone decide the verdict.
        assert fields["unevaluated_rules"] == []
        assert fields["unstoppable_tools"] == {}
        assert (standalone == 1) == bool(
            fields["incomplete_scanners"] or fields["no_scanner_ran"]
        )
        # The per-scanner half against the test module's own reader, which asks
        # scan_incompleteness under gate=True itself.
        assert fields["incomplete_scanners"] == incomplete_scanners_for_project(model)
        assert (
            list(fields["incomplete_scanner_details"]) == fields["incomplete_scanners"]
        )

    def test_an_unevaluated_rule_is_seen_by_both_derivations_with_the_gate_off(
        self, tmp_path
    ):
        """The exit-1 arm no setting silences, on the field that carries it.

        A run-level error notification naming a rule is ``unevaluated_rules`` to
        ``_coverage_fields`` and exit 1 to ``_compute_exit_code`` with the
        completeness gate OFF; the control, the same scanners with no
        notification, is empty and 0. Pinned as an agreement, as the other cases
        of this class are, so neither side can stop answering alone.
        """
        from automated_security_helper.interactions.run_ash_scan import (
            ScanOptions,
            _compute_exit_code,
        )

        statuses = {"cdk-nag": ("PASSED", False, True)}
        raised = [
            {
                "executionSuccessful": True,
                "toolExecutionNotifications": [
                    {
                        "level": "error",
                        "message": {"text": "AwsSolutions-S1 could not be evaluated"},
                        "associatedRule": {"id": "AwsSolutions-S1"},
                    }
                ],
            }
        ]
        opts = ScanOptions(
            source_dir=tmp_path,
            output_dir=tmp_path,
            fail_on_incomplete_scanners=False,
        )

        with_rule = self._model(statuses, invocations=raised)
        clean = self._model(statuses)

        assert _compute_exit_code(with_rule, opts, None) == 1
        assert _coverage_fields(with_rule)["unevaluated_rules"] == ["AwsSolutions-S1"]
        assert _coverage_fields(with_rule)["incomplete_scanners"] == []
        assert _compute_exit_code(clean, opts, None) == 0
        assert _coverage_fields(clean)["unevaluated_rules"] == []

    def test_a_project_whose_every_scanner_was_skipped_is_seen_by_both(self, tmp_path):
        """The set-level half, which the per-entry helper structurally cannot see.

        ``incomplete_scanners`` tolerates SKIPPED one entry at a time, because that
        is how an exclusion and another shard's ownership are recorded. So a project
        in which *every* entry is SKIPPED clears that pass having measured nothing,
        and before ``_coverage_fields`` carried ``no_scanner_ran`` the workspace layer
        had no second question to ask: the project reported zero findings and COMPLETED
        while ``ash --source-dir P`` on the same project exited 1.

        Asserted through the same agreement the rest of this class uses, so a
        workspace-side derivation that stopped answering cannot keep this passing.
        """
        statuses = {"bandit": ("SKIPPED", True, True)}
        standalone = self._standalone_exit_code(tmp_path, statuses)
        model = self._model(statuses)

        assert standalone == 1
        assert incomplete_scanners_for_project(model) == []
        assert _coverage_fields(model)["no_scanner_ran"] is True

    def test_a_project_with_one_scanner_that_ran_is_clean_to_both(self, tmp_path):
        """The control for the case above, at the boundary that decides it.

        One PASSED entry beside the SKIPPED ones is the difference between a scan
        that measured nothing and a scan that measured something and was narrowed.
        Without this the set-level gate could be stuck at always-fail and the test
        above would still pass.
        """
        statuses = {
            "bandit": ("PASSED", False, True),
            "cfn-nag": ("SKIPPED", True, True),
        }
        standalone = self._standalone_exit_code(tmp_path, statuses)
        model = self._model(statuses)

        assert standalone == 0
        assert incomplete_scanners_for_project(model) == []
        assert _coverage_fields(model)["no_scanner_ran"] is False

    def test_an_empty_scanner_set_with_no_roster_is_not_read_as_nothing_having_run(
        self, tmp_path
    ):
        """A results file recording no scanners *and no roster* is a different claim.

        ``--phases convert`` legitimately produces one, and ``no_scanner_ran``
        returns False for it so that a phase-limited run does not become an error.
        Pinned here because the workspace helper delegates, and a mirrored copy that
        tested emptiness instead would fail every convert-only project in a
        workspace.

        The absent roster is what makes this benign, and it is why the assertion
        cannot stop at emptiness -- see the test below.
        """
        model = self._model({})
        assert not getattr(model.metadata, "expected_scanners", None), (
            "premise: this model records no roster, which is what the benign "
            "reading depends on"
        )

        assert _coverage_fields(model)["no_scanner_ran"] is False

    def test_an_empty_scanner_set_with_a_roster_is_seen_by_both(self, tmp_path):
        """The state an empty set alone cannot distinguish.

        ``no_scanner_ran`` gained a second condition and a second parameter for
        this: an empty scanner set covers both "the scan phase was not requested",
        which is benign, and "the scan phase ran and had nothing to run", which is
        the silent zero. ``metadata.expected_scanners`` separates them, because
        ``ScanPhase`` is what records it -- a roster means the phase ran.

        The workspace helper once called ``no_scanner_ran`` with one argument, so it
        answered the benign reading for both states while ``ash --source-dir P`` on
        the same project answered 1. It now reads ``ScanIncompleteness``, which
        passes the roster.
        """
        statuses: dict = {}
        model = self._model(statuses)
        model.metadata.expected_scanners = ["bandit", "cfn-nag"]

        standalone_model = self._model(statuses)
        standalone_model.metadata.expected_scanners = ["bandit", "cfn-nag"]
        from automated_security_helper.interactions.run_ash_scan import (
            ScanOptions,
            _compute_exit_code,
        )

        standalone = _compute_exit_code(
            standalone_model,
            ScanOptions(
                source_dir=tmp_path,
                output_dir=tmp_path,
                fail_on_incomplete_scanners=True,
            ),
            None,
        )

        assert standalone == 1
        assert _coverage_fields(model)["no_scanner_ran"] is True


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

    @pytest.mark.skipif(
        sys.platform == "win32", reason="creating symlinks needs privileges on Windows"
    )
    def test_the_unified_file_is_not_written_through_a_link(self, tmp_path):
        plan = _plan(tmp_path, "api")
        output = tmp_path / "out"
        output.mkdir()
        victim = tmp_path / "victim.json"
        (output / "ash_aggregated_results.json").symlink_to(victim)
        aggregator = WorkspaceAggregator(plan=plan, output_dir=output)
        aggregator.add(self._outcome("api"), _run(_result()), plan.projects[0])

        with pytest.raises(OutputDirLinkRefused):
            aggregator.write(exit_code=0, wall_clock_seconds=1.0)

        assert not victim.exists()

    @pytest.mark.skipif(
        sys.platform == "win32", reason="creating symlinks needs privileges on Windows"
    )
    def test_a_spool_file_is_not_written_through_a_link(self, tmp_path):
        plan = _plan(tmp_path, "api")
        spool = tmp_path / "out" / ".workspace-spool"
        spool.mkdir(parents=True)
        victim = tmp_path / "victim.json"
        # The first spool written carries ordinal 0000; the name is the one add()
        # will write, so the link sits exactly where the write would land.
        (spool / "0000-api.run.json").symlink_to(victim)
        aggregator = WorkspaceAggregator(plan=plan, output_dir=tmp_path / "out")

        with pytest.raises(OutputDirLinkRefused):
            aggregator.add(self._outcome("api"), _run(_result()), plan.projects[0])

        assert not victim.exists()

    @pytest.mark.skipif(
        sys.platform == "win32", reason="creating symlinks needs privileges on Windows"
    )
    def test_a_spool_directory_that_is_a_link_is_not_written_through(self, tmp_path):
        """No PluginContext registered the workspace output; the spool is guarded."""
        plan = _plan(tmp_path, "api")
        output = tmp_path / "out"
        output.mkdir()
        elsewhere = tmp_path / "elsewhere"
        elsewhere.mkdir()
        (output / ".workspace-spool").symlink_to(elsewhere, target_is_directory=True)
        aggregator = WorkspaceAggregator(plan=plan, output_dir=output)

        with pytest.raises(OutputDirLinkRefused):
            aggregator.add(self._outcome("api"), _run(_result()), plan.projects[0])

        assert list(elsewhere.iterdir()) == []

    def test_a_reader_sees_the_previous_unified_file_while_it_is_written(
        self, tmp_path, monkeypatch
    ):
        """The MCP progress reader parses the file while a workspace scan rewrites it."""
        import shutil

        from automated_security_helper.workspace import aggregation

        plan = _plan(tmp_path, "api", "web")
        output = tmp_path / "out"
        output.mkdir()
        target = output / "ash_aggregated_results.json"
        previous = '{"previous": "complete"}\n'
        target.write_text(previous, encoding="utf-8")
        aggregator = WorkspaceAggregator(plan=plan, output_dir=output)
        for index, key in enumerate(("api", "web")):
            aggregator.add(self._outcome(key), _run(_result()), plan.projects[index])
        seen = []
        copy = shutil.copyfileobj

        def read_then_copy(source, destination, *args, **kwargs):
            destination.flush()
            seen.append(target.read_text(encoding="utf-8"))
            return copy(source, destination, *args, **kwargs)

        monkeypatch.setattr(aggregation.shutil, "copyfileobj", read_then_copy)

        path = aggregator.write(exit_code=0, wall_clock_seconds=1.0)

        assert seen == [previous, previous]
        assert len(json.loads(path.read_text(encoding="utf-8"))["sarif"]["runs"]) == 2
        assert sorted(p.name for p in output.iterdir() if p.is_file()) == [
            target.name
        ], "a staging file was left behind"

    def test_a_spool_file_appears_only_once_it_is_complete(self, tmp_path, monkeypatch):
        """Written to a staging file and renamed: no reader finds a partial spool."""
        from automated_security_helper.workspace import aggregation

        plan = _plan(tmp_path, "api")
        aggregator = WorkspaceAggregator(plan=plan, output_dir=tmp_path / "out")
        # Spool names carry an ordinal prefix so two keys that differ only in case
        # stay two files on a case-insensitive volume; the first add() writes 0000.
        spool = aggregator.spool_dir / "0000-api.run.json"
        present_while_written = []
        dump = json.dump

        def dump_then_look(obj, handle, *args, **kwargs):
            dump(obj, handle, *args, **kwargs)
            handle.flush()
            present_while_written.append(spool.exists())

        monkeypatch.setattr(aggregation.json, "dump", dump_then_look)

        aggregator.add(self._outcome("api"), _run(_result()), plan.projects[0])

        assert present_while_written == [False]
        assert json.loads(spool.read_text(encoding="utf-8"))["results"]
        assert sorted(p.name for p in aggregator.spool_dir.iterdir()) == [spool.name]

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

    def test_the_fallback_rollup_grades_each_scanner_by_its_own_threshold(
        self, tmp_path
    ):
        """Red at the base: without a carried split, every scanner was graded by the
        project gate, so a bandit MEDIUM counted under bandit's own CRITICAL and the
        rollup exceeded the project's actionable_finding_count it claims to sum."""
        plan = _plan(tmp_path, "api")
        plan.projects[0].severity_threshold = "MEDIUM"
        aggregator = WorkspaceAggregator(plan=plan, output_dir=tmp_path / "out")
        results = [
            _result(level="warning", scanner="bandit"),
            _result("iac/main.tf", level="error", scanner="checkov"),
        ]
        aggregator.add(
            self._outcome(
                "api",
                scanners={"bandit": "FAILED", "checkov": "FAILED"},
                actionable_finding_count=1,
                scanner_thresholds={"bandit": "CRITICAL"},
            ),
            _run(*results),
            plan.projects[0],
        )
        parsed = json.loads(
            aggregator.write(exit_code=2, wall_clock_seconds=1.0).read_text(
                encoding="utf-8"
            )
        )
        assert parsed["scanner_results"]["bandit"]["actionable_finding_count"] == 0
        assert parsed["scanner_results"]["checkov"]["actionable_finding_count"] == 1

    def test_the_fallback_rollup_leaves_policy_findings_out_when_the_gate_is_off(
        self, tmp_path
    ):
        """Red at the base: a policy-origin finding counted though the verdict excluded it."""
        plan = _plan(tmp_path, "api")
        aggregator = WorkspaceAggregator(plan=plan, output_dir=tmp_path / "out")
        policy = _result(level="error", scanner="bandit")
        policy["properties"]["origin"] = "workspace-policy"
        results = [policy, _result("src/two.py", level="error", scanner="semgrep")]
        aggregator.add(
            self._outcome(
                "api",
                scanners={"bandit": "FAILED", "semgrep": "FAILED"},
                actionable_finding_count=1,
                policy_scanners_gate=False,
            ),
            _run(*results),
            plan.projects[0],
        )
        parsed = json.loads(
            aggregator.write(exit_code=2, wall_clock_seconds=1.0).read_text(
                encoding="utf-8"
            )
        )
        assert parsed["scanner_results"]["bandit"]["actionable_finding_count"] == 0
        assert parsed["scanner_results"]["semgrep"]["actionable_finding_count"] == 1
        # Reported, as the project's own finding_count reports it.
        assert parsed["scanner_results"]["bandit"]["finding_count"] == 1

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


class TestStampingARunRecord:
    """A record goes into the written file without loading it whole.

    The inner run of a container scan stamps its completion marker after the
    report step, and its refusal when the report step refuses; see
    utils/inner_run_outcome.py.
    """

    RECORD = {"type": "run_completed", "metadata": {"run_id": "1" * 32}}

    def _written(self, tmp_path):
        from automated_security_helper.workspace.aggregation import (
            WorkspaceAggregator,
        )

        return WorkspaceAggregator(
            plan=_plan(tmp_path), output_dir=tmp_path / "out"
        ).write(exit_code=0, wall_clock_seconds=0.1)

    def test_the_record_is_stamped_and_the_rest_is_unchanged(self, tmp_path):
        from automated_security_helper.workspace.aggregation import stamp_run_record

        path = self._written(tmp_path)
        before = json.loads(path.read_text(encoding="utf-8"))

        assert stamp_run_record(path, self.RECORD)

        after = json.loads(path.read_text(encoding="utf-8"))
        assert after.pop("validation_checkpoints") == [self.RECORD]
        before.pop("validation_checkpoints")
        assert after == before

    @pytest.mark.skipif(
        sys.platform == "win32",
        reason="Windows refuses to replace a file another handle holds open, so the "
        "stamp returns False there by design and the inode swap has no counterpart",
    )
    def test_the_file_is_replaced_rather_than_rewritten_in_place(self, tmp_path):
        """A reader that opened the file before the stamp keeps reading it whole.

        POSIX only: the property is that the replace swaps the inode under a
        reader. Windows will not replace a file this process still holds open
        (``stamp_run_record`` closes its own source handle before the replace for
        that reason), so with the test's reader open the stamp returns False and
        leaves the file unchanged, which is the documented refusal, not the swap.
        """
        from automated_security_helper.workspace.aggregation import stamp_run_record

        path = self._written(tmp_path)
        before = path.read_bytes()
        inode = path.stat().st_ino

        with open(path, "rb") as reader:
            assert stamp_run_record(path, self.RECORD)
            assert reader.read() == before

        assert path.stat().st_ino != inode

    def test_a_header_line_longer_than_one_read_is_copied_whole(
        self, tmp_path, monkeypatch
    ):
        """The file is read in bounded pieces; a long line is copied in several."""
        from automated_security_helper.workspace import aggregation

        path = self._written(tmp_path)
        before = json.loads(path.read_text(encoding="utf-8"))
        # Only just long enough for the checkpoints line, which must be read whole;
        # the workspace and scanner_results lines take several reads.
        monkeypatch.setattr(
            aggregation,
            "_STAMP_READ_LIMIT",
            len(aggregation._EMPTY_CHECKPOINTS_LINE) + 1,
        )

        assert aggregation.stamp_run_record(path, self.RECORD)

        after = json.loads(path.read_text(encoding="utf-8"))
        assert after.pop("validation_checkpoints") == [self.RECORD]
        before.pop("validation_checkpoints")
        assert after == before

    def test_a_file_without_the_checkpoints_line_is_not_read_whole(
        self, tmp_path, monkeypatch
    ):
        """Given up on at the SARIF line, after one bounded read of it."""
        import builtins

        from automated_security_helper.workspace import aggregation

        path = tmp_path / "ash_aggregated_results.json"
        sarif_line = '"sarif": {"runs": ["' + "x" * 100_000 + '"]}\n'
        path.write_text('{\n"name": "n",\n' + sarif_line + "}\n", encoding="utf-8")
        reads = []

        class _Recording:
            def __init__(self, handle):
                self._handle = handle

            def readline(self, size=-1):
                line = self._handle.readline(size)
                reads.append((size, len(line)))
                return line

            def __getattr__(self, name):
                return getattr(self._handle, name)

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return self._handle.__exit__(*exc)

        def recording_open(file, mode="r", *args, **kwargs):
            handle = builtins.open(file, mode, *args, **kwargs)
            return _Recording(handle) if mode == "r" else handle

        monkeypatch.setattr(aggregation, "open", recording_open, raising=False)
        monkeypatch.setattr(aggregation, "_STAMP_READ_LIMIT", 4096)

        assert not aggregation.stamp_run_record(path, self.RECORD)

        assert reads, "the file was not read in bounded pieces"
        assert all(0 < size <= 4096 for size, _ in reads), reads
        assert sum(length for _, length in reads) < 4096 + 64, reads

    def test_a_link_at_the_results_file_is_not_written_through(self, tmp_path):
        """In the output directory a scan writes to, the stamp refuses a link at the
        file and leaves both the link and the file it names as they were."""
        from automated_security_helper.utils.sandbox.fs_guard import writable_root
        from automated_security_helper.workspace.aggregation import stamp_run_record

        path = self._written(tmp_path)
        elsewhere = tmp_path / "elsewhere.json"
        elsewhere.write_bytes(path.read_bytes())
        before = elsewhere.read_bytes()
        path.unlink()
        path.symlink_to(elsewhere)

        with writable_root(path.parent):
            assert not stamp_run_record(path, self.RECORD)

        assert path.is_symlink()
        assert elsewhere.read_bytes() == before

    def test_a_file_the_aggregator_did_not_write_is_left_unchanged(self, tmp_path):
        from automated_security_helper.workspace.aggregation import stamp_run_record

        path = tmp_path / "ash_aggregated_results.json"
        path.write_text(json.dumps({"validation_checkpoints": []}), encoding="utf-8")
        before = path.read_bytes()

        assert not stamp_run_record(path, self.RECORD)
        assert path.read_bytes() == before

    def test_a_failed_rewrite_leaves_the_file_and_no_staging_file(
        self, tmp_path, monkeypatch
    ):
        import os

        from automated_security_helper.workspace import aggregation

        path = self._written(tmp_path)
        before = path.read_bytes()

        def no_replace(*args, **kwargs):
            raise OSError("no space left on device")

        # The rename fs_guard.open_for_atomic_write makes when the copy ends.
        monkeypatch.setattr(os, "replace", no_replace)

        assert not aggregation.stamp_run_record(path, self.RECORD)
        assert path.read_bytes() == before
        assert sorted(p.name for p in path.parent.iterdir()) == [path.name]
