# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""What each merged reporter actually carries about the project.

Why existence is not enough
---------------------------
``test_workspace_reporting.py`` proves the driver writes a file for a MERGED
reporter. This file proves the file is *worth having*: that the project appears
in it, in the place the RFC's table promised, and that a reader can tell one
project's findings from another's.

A merged artefact that contained every finding but named no project would pass
every test in the other file and still be useless -- an operator staring at 40
findings across a monorepo with no way to route any of them. That is the failure
mode this file exists against, and it is why each assertion below names a
specific project's own data rather than merely counting.

The single-directory companion assertion
----------------------------------------
Every reporter here is also asserted to leave single-directory output alone. Not
defensiveness: a project column added unconditionally to CSV would shift every
subsequent column, and a consumer indexing by position rather than by header
would silently read the wrong field from then on. So each "adds the project"
assertion is paired with a "changes nothing without a workspace" assertion.
"""

import json

import pytest

# defusedxml rather than xml.etree: ASH self-scans this repository, and the
# stdlib parsers accept external entities by default. Already a dependency --
# junitxml_reporter calls defuse_stdlib() for the same reason.
from defusedxml import ElementTree

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.models.workspace import (
    ProjectRunStatus,
    SkippedProjectReason,
    WorkspaceProjectResult,
    WorkspaceResults,
)
from automated_security_helper.schemas.sarif_schema_model import SarifReport

PROJECTS = ("api", "web")

#: The skipped project used by the skip fixtures below. Named distinctly from
#: every scanned project so an assertion that finds it cannot be satisfied by a
#: project that was actually scanned.
SKIPPED_PROJECT = "docs"
SKIP_DETAIL = "nothing changed under docs/ since the base ref"


def _result(project: str | None, *, rule: str, uri: str) -> dict:
    entry = {
        "ruleId": rule,
        "level": "error",
        "message": {"text": f"finding for {project or 'single'}"},
        "locations": [{"physicalLocation": {"artifactLocation": {"uri": uri}}}],
        "properties": {"scanner_name": "bandit"},
    }
    if project is not None:
        entry["properties"]["workspace_project"] = project
    return entry


def _project_result(
    key: str, *, findings: int, actionable: int
) -> WorkspaceProjectResult:
    return WorkspaceProjectResult(
        project=key,
        relative_path=key,
        display_label=key,
        status=ProjectRunStatus.COMPLETED,
        severity_threshold="MEDIUM",
        finding_count=findings,
        actionable_finding_count=actionable,
        exceeds_threshold=bool(actionable),
        output_path=f"projects/{key}",
        scanners={"bandit": "FAILED" if actionable else "PASSED"},
    )


@pytest.fixture
def workspace_model(tmp_path) -> AshAggregatedResults:
    """A two-project workspace model, with one run per project.

    Rule ids and file paths differ per project so that a reporter which dropped
    or duplicated a project is caught by asserting on that project's own data
    rather than by a count -- which a duplicated first project would satisfy.
    """
    model = AshAggregatedResults()
    model.sarif = SarifReport.model_validate(
        {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "ASH"}},
                    "results": [
                        _result(key, rule=f"RULE-{key.upper()}", uri=f"src/{key}.py")
                    ],
                    "originalUriBaseIds": {
                        "PROJECTROOT": {"uri": f"file:///ws/{key}/"}
                    },
                    "invocations": [],
                }
                for key in PROJECTS
            ],
        }
    )
    model.workspace = WorkspaceResults(
        workspace_file=(tmp_path / "fixture.code-workspace").as_posix(),
        workspace_root=tmp_path.as_posix(),
        exit_code=2,
        projects=[
            _project_result("api", findings=1, actionable=1),
            _project_result("web", findings=1, actionable=0),
        ],
        wall_clock_seconds=3.25,
    )
    return model


def _skipped_project_result(
    key: str, *, reason: SkippedProjectReason, detail: str
) -> WorkspaceProjectResult:
    """A project that never ran, as execution records one.

    No threshold and no counts, because nothing was scanned. That absence is the
    whole reason a row-per-finding reporter loses the project: there is no finding
    to hang a row off.
    """
    return WorkspaceProjectResult(
        project=key,
        relative_path=key,
        display_label=key,
        status=ProjectRunStatus.SKIPPED,
        skip_reason=reason,
        skip_detail=detail,
        output_path=f"projects/{key}",
    )


@pytest.fixture
def skipped_workspace_model(tmp_path) -> AshAggregatedResults:
    """A workspace where one project was scanned and one was skipped.

    Deliberately not "every project skipped": resolution refuses that case
    outright, and a model with no SARIF at all would let a reporter pass by
    emitting nothing. One scanned project means every reporter here produces its
    ordinary output, and the skipped project has to appear *alongside* it.

    The skip reason is NO_CHANGES rather than ERROR because it is the reason most
    likely to be read as "nothing to report". A reporter that drops the row is
    then indistinguishable from a workspace that had nothing to say, which is the
    silent-omission failure this criterion exists against.
    """
    model = AshAggregatedResults()
    model.sarif = SarifReport.model_validate(
        {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "ASH"}},
                    "results": [
                        _result("api", rule="RULE-API", uri="src/api.py"),
                    ],
                    "invocations": [],
                }
            ],
        }
    )
    model.workspace = WorkspaceResults(
        workspace_file=(tmp_path / "fixture.code-workspace").as_posix(),
        workspace_root=tmp_path.as_posix(),
        exit_code=2,
        projects=[
            _project_result("api", findings=1, actionable=1),
            _skipped_project_result(
                SKIPPED_PROJECT,
                reason=SkippedProjectReason.NO_CHANGES,
                detail=SKIP_DETAIL,
            ),
        ],
        wall_clock_seconds=1.5,
    )
    return model


@pytest.fixture
def single_model() -> AshAggregatedResults:
    """The single-directory shape: one run, no ``workspace`` block."""
    model = AshAggregatedResults()
    model.sarif = SarifReport.model_validate(
        {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "ASH"}},
                    "results": [_result(None, rule="RULE-ONE", uri="src/app.py")],
                    "invocations": [],
                }
            ],
        }
    )
    return model


@pytest.fixture
def context(tmp_path) -> PluginContext:
    return PluginContext(
        source_dir=tmp_path,
        output_dir=tmp_path / "out",
        config=AshConfig(),
    )


def _report(reporter_class, model, context) -> str:
    return reporter_class(context=context).report(model)


# --------------------------------------------------------------------------- #
# Column-and-field reporters: csv, flat-json, yaml
# --------------------------------------------------------------------------- #


class TestCsvCarriesAProjectColumn:
    @staticmethod
    def _rows(text: str):
        import csv
        from io import StringIO

        return list(csv.reader(StringIO(text)))

    def test_the_project_column_is_present_and_leads_the_header(
        self, workspace_model, context
    ):
        from automated_security_helper.plugin_modules.ash_builtin.reporters.csv_reporter import (
            PROJECT_COLUMN,
            CsvReporter,
        )

        rows = self._rows(_report(CsvReporter, workspace_model, context))
        assert rows[0][0] == PROJECT_COLUMN

    def test_every_project_has_its_own_row(self, workspace_model, context):
        from automated_security_helper.plugin_modules.ash_builtin.reporters.csv_reporter import (
            CsvReporter,
        )

        rows = self._rows(_report(CsvReporter, workspace_model, context))
        header, *data = rows
        project_index = header.index("workspace_project")
        rule_index = header.index("rule_id")
        by_project = {row[project_index]: row[rule_index] for row in data if row}
        assert by_project == {"api": "RULE-API", "web": "RULE-WEB"}

    def test_a_single_directory_scan_gains_no_column(self, single_model, context):
        """The paired assertion: adding it unconditionally shifts every column.

        A consumer that reads by position rather than by header would then read
        the wrong field with no error, for every single-directory scan.
        """
        from automated_security_helper.plugin_modules.ash_builtin.reporters.csv_reporter import (
            PROJECT_COLUMN,
            CsvReporter,
        )

        rows = self._rows(_report(CsvReporter, single_model, context))
        assert PROJECT_COLUMN not in rows[0]

    def test_the_header_only_form_matches_the_populated_header(
        self, workspace_model, context
    ):
        """A workspace with no findings must still declare the project column.

        The empty case has its own hardcoded header list in this reporter, which
        is exactly the kind of duplicate that drifts. Asserted by comparing the
        two headers to each other rather than to a literal, so they cannot drift
        apart in either direction.
        """
        from automated_security_helper.plugin_modules.ash_builtin.reporters.csv_reporter import (
            CsvReporter,
        )

        populated = self._rows(_report(CsvReporter, workspace_model, context))[0]

        empty = AshAggregatedResults()
        empty.sarif = SarifReport.model_validate({"version": "2.1.0", "runs": []})
        empty.workspace = workspace_model.workspace
        assert self._rows(_report(CsvReporter, empty, context))[0] == populated


class TestFlatJsonCarriesAProjectField:
    def test_every_finding_names_its_project(self, workspace_model, context):
        from automated_security_helper.plugin_modules.ash_builtin.reporters.flatjson_reporter import (
            FlatJSONReporter,
        )

        payload = json.loads(_report(FlatJSONReporter, workspace_model, context))
        assert {finding["workspace_project"] for finding in payload["findings"]} == set(
            PROJECTS
        )

    def test_the_workspace_block_carries_the_per_project_verdicts(
        self, workspace_model, context
    ):
        """Grouping must not require re-deriving a verdict from the findings.

        A consumer that recomputed "did api fail" from the finding list would be
        applying its own threshold, not the one api's own config set -- and would
        get a different answer than the exit code for the same run.
        """
        from automated_security_helper.plugin_modules.ash_builtin.reporters.flatjson_reporter import (
            FlatJSONReporter,
        )

        payload = json.loads(_report(FlatJSONReporter, workspace_model, context))
        verdicts = {
            entry["project"]: entry["exceeds_threshold"]
            for entry in payload["workspace"]["projects"]
        }
        assert verdicts == {"api": True, "web": False}

    def test_a_single_directory_scan_has_no_project_field_and_no_block(
        self, single_model, context
    ):
        from automated_security_helper.plugin_modules.ash_builtin.reporters.flatjson_reporter import (
            FlatJSONReporter,
        )

        payload = json.loads(_report(FlatJSONReporter, single_model, context))
        assert "workspace" not in payload
        for finding in payload["findings"]:
            assert "workspace_project" not in finding


class TestYamlCarriesTheWholeWorkspaceShape:
    """No code change was needed here, so the test is the whole guarantee.

    ``yaml`` dumps the entire model, which already carries the ``workspace``
    block, all N runs, and per-finding attribution. Asserting it is what turns a
    coincidence into a contract: a future change that narrowed the dump would
    otherwise silently drop workspace attribution from this format alone.
    """

    @staticmethod
    def _load(text: str):
        import yaml

        return yaml.safe_load(text)

    def test_the_workspace_block_survives_the_dump(self, workspace_model, context):
        from automated_security_helper.plugin_modules.ash_builtin.reporters.yaml_reporter import (
            YamlReporter,
        )

        payload = self._load(_report(YamlReporter, workspace_model, context))
        assert [entry["project"] for entry in payload["workspace"]["projects"]] == list(
            PROJECTS
        )

    def test_every_run_survives_the_dump(self, workspace_model, context):
        from automated_security_helper.plugin_modules.ash_builtin.reporters.yaml_reporter import (
            YamlReporter,
        )

        payload = self._load(_report(YamlReporter, workspace_model, context))
        assert len(payload["sarif"]["runs"]) == len(PROJECTS)

    def test_each_finding_keeps_its_project_attribution(self, workspace_model, context):
        from automated_security_helper.plugin_modules.ash_builtin.reporters.yaml_reporter import (
            YamlReporter,
        )

        payload = self._load(_report(YamlReporter, workspace_model, context))
        attributed = {
            result["properties"]["workspace_project"]
            for run in payload["sarif"]["runs"]
            for result in run["results"]
        }
        assert attributed == set(PROJECTS)


# --------------------------------------------------------------------------- #
# Human-readable reporters: html, markdown, text
# --------------------------------------------------------------------------- #


class TestMarkdownHasAPerProjectSection:
    @staticmethod
    def _row(report: str, key: str) -> list[str]:
        """The cells of one project's markdown table row."""
        for line in report.splitlines():
            if line.startswith(f"| {key} |"):
                return [cell.strip() for cell in line.strip("|").split("|")]
        raise AssertionError(f"no table row for project {key!r} in:\n{report}")

    def test_every_project_appears_with_its_verdict(self, workspace_model, context):
        """The verdict, not just the name.

        The fixture is deliberately asymmetric: ``web`` has a finding but zero
        *actionable* findings, so it passes. A renderer that decided PASSED/FAILED
        from ``finding_count`` instead of from the project's recorded
        ``exceeds_threshold`` would call it FAILED -- and would be applying one
        threshold to projects that are independently configured, disagreeing with
        the exit code for the same run. Asserting only that "web" appears somewhere
        misses that entirely, which a mutation run showed it did.
        """
        from automated_security_helper.plugin_modules.ash_builtin.reporters.markdown_reporter import (
            MarkdownReporter,
        )

        report = _report(MarkdownReporter, workspace_model, context)
        assert "## Projects" in report
        assert self._row(report, "api")[-1] == "FAILED"
        assert self._row(report, "web")[-1] == "PASSED"

    def test_the_row_carries_the_counts_and_the_threshold(
        self, workspace_model, context
    ):
        """So a reader can see *why* a project failed, not only that it did."""
        from automated_security_helper.plugin_modules.ash_builtin.reporters.markdown_reporter import (
            MarkdownReporter,
        )

        report = _report(MarkdownReporter, workspace_model, context)
        api = self._row(report, "api")
        assert api[2] == "1"  # findings
        assert api[3] == "1"  # actionable
        assert api[4] == "MEDIUM"  # threshold

    def test_the_section_survives_compact_mode(self, workspace_model, context):
        """Compact exists for PR comments, which is where this matters most.

        In a monorepo PR the single most useful line is which project the
        findings are in, so this is the one section compact must not drop.
        """
        from automated_security_helper.plugin_modules.ash_builtin.reporters.markdown_reporter import (
            MarkdownReporter,
            MarkdownReporterConfig,
            MarkdownReporterConfigOptions,
        )

        reporter = MarkdownReporter(
            context=context,
            config=MarkdownReporterConfig(
                options=MarkdownReporterConfigOptions(compact=True)
            ),
        )
        report = reporter.report(workspace_model)
        assert "## Projects" in report
        for key in PROJECTS:
            assert f"| {key} |" in report

    def test_a_single_directory_scan_has_no_such_section(self, single_model, context):
        from automated_security_helper.plugin_modules.ash_builtin.reporters.markdown_reporter import (
            MarkdownReporter,
        )

        assert "## Projects" not in _report(MarkdownReporter, single_model, context)


class TestTextHasAPerProjectSection:
    def test_every_project_appears(self, workspace_model, context):
        from automated_security_helper.plugin_modules.ash_builtin.reporters.text_reporter import (
            TextReporter,
        )

        report = _report(TextReporter, workspace_model, context)
        assert "PROJECTS" in report
        for key in PROJECTS:
            assert key in report

    def test_the_project_table_columns_line_up_with_its_header(
        self, workspace_model, context
    ):
        """This lands in a CI log, where a misaligned table is unreadable.

        The same defect was fixed once already for the scanner table -- see
        ``TestTextReporterColumnAlignment`` in
        ``tests/unit/plugin_modules/test_reporter_regression.py`` -- so it is
        asserted here rather than assumed for the new table.
        """
        from automated_security_helper.plugin_modules.ash_builtin.reporters.text_reporter import (
            TextReporter,
        )

        lines = _report(TextReporter, workspace_model, context).splitlines()
        start = next(index for index, line in enumerate(lines) if "PROJECTS" in line)
        header = next(
            line for line in lines[start:] if line.strip().startswith("Project")
        )
        rows = [line for line in lines[start:] if line.strip().startswith(PROJECTS)]
        assert rows, "no project rows found under the PROJECTS heading"
        for row in rows:
            assert len(row.rstrip()) <= len(header.rstrip()) + 2

    def test_a_single_directory_scan_has_no_such_section(self, single_model, context):
        from automated_security_helper.plugin_modules.ash_builtin.reporters.text_reporter import (
            TextReporter,
        )

        assert "PROJECTS" not in _report(TextReporter, single_model, context)


class TestHtmlHasAPerProjectSection:
    def test_every_project_appears_in_a_table(self, workspace_model, context):
        from automated_security_helper.plugin_modules.ash_builtin.reporters.html_reporter import (
            HtmlReporter,
        )

        report = _report(HtmlReporter, workspace_model, context)
        assert "Projects" in report
        for key in PROJECTS:
            assert f"<td>{key}</td>" in report

    def test_a_project_label_is_escaped(self, context, workspace_model):
        """A project label reaches HTML from a config file, so it is untrusted.

        ASH self-scans this repository at MEDIUM and an unescaped interpolation
        into HTML is a finding, but the substantive reason is the same one it
        always is: a label containing markup would otherwise rewrite the report.
        """
        from automated_security_helper.plugin_modules.ash_builtin.reporters.html_reporter import (
            HtmlReporter,
        )

        workspace_model.workspace.projects[0].display_label = "<script>x</script>"
        report = _report(HtmlReporter, workspace_model, context)
        assert "<script>x</script>" not in report
        assert "&lt;script&gt;" in report

    def test_a_single_directory_scan_has_no_such_section(self, single_model, context):
        from automated_security_helper.plugin_modules.ash_builtin.reporters.html_reporter import (
            HtmlReporter,
        )

        report = _report(HtmlReporter, single_model, context)
        assert "workspace-projects" not in report


# --------------------------------------------------------------------------- #
# Structured reporters: junitxml, ocsf
# --------------------------------------------------------------------------- #


class TestJunitXmlNamesTheProjectInTheSuite:
    def test_the_suite_name_carries_both_project_and_scanner(
        self, workspace_model, context
    ):
        """The deviation from the RFC, asserted rather than described.

        The RFC said the project *becomes* the suite name. Taken literally that
        discards the scanner grouping every JUnit front end renders. The compound
        keeps both, with the project leading so one project's suites sort
        together.
        """
        from automated_security_helper.plugin_modules.ash_builtin.reporters.junitxml_reporter import (
            JunitXmlReporter,
        )

        tree = ElementTree.fromstring(
            _report(JunitXmlReporter, workspace_model, context)
        )
        names = {suite.get("name") for suite in tree.iter("testsuite")}
        assert {"api/bandit", "web/bandit"} <= names

    def test_a_single_directory_scan_keeps_the_bare_scanner_name(
        self, single_model, context
    ):
        from automated_security_helper.plugin_modules.ash_builtin.reporters.junitxml_reporter import (
            JunitXmlReporter,
        )

        tree = ElementTree.fromstring(_report(JunitXmlReporter, single_model, context))
        names = {suite.get("name") for suite in tree.iter("testsuite")}
        assert "bandit" in names
        assert not any(name and "/" in name for name in names)


class TestOcsfCarriesTheProjectInMetadata:
    """Carried in ``metadata.labels``, not as a ``metadata`` field.

    The RFC asked for "the project in metadata", and OCSF's ``Metadata`` sets
    ``extra="forbid"``. The trap is that pydantic's ``model_copy(update=...)``
    *silently drops* an undeclared key rather than raising, so the obvious
    implementation would have shipped findings with no attribution and nothing to
    show it had failed. ``labels`` is the schema's own slot for free-form
    annotation and is indexed by SIEMs, so the intent is met without extending
    the schema.
    """

    def test_every_finding_names_its_project(self, workspace_model, context):
        from automated_security_helper.plugin_modules.ash_builtin.reporters.ocsf_reporter import (
            WORKSPACE_PROJECT_LABEL_PREFIX,
            OcsfReporter,
        )

        findings = json.loads(_report(OcsfReporter, workspace_model, context))
        attributed = {
            label[len(WORKSPACE_PROJECT_LABEL_PREFIX) :]
            for finding in findings
            for label in finding["metadata"].get("labels", [])
            if label.startswith(WORKSPACE_PROJECT_LABEL_PREFIX)
        }
        assert attributed == set(PROJECTS)

    def test_no_finding_carries_more_than_one_project_label(
        self, workspace_model, context
    ):
        """One ``Metadata`` instance is shared across every finding in the report.

        Appending to its ``labels`` in place would give every finding every
        project's label -- each one individually plausible, and the whole report
        useless for routing. This is the assertion that catches a mutation where a
        copy should have been made.
        """
        from automated_security_helper.plugin_modules.ash_builtin.reporters.ocsf_reporter import (
            WORKSPACE_PROJECT_LABEL_PREFIX,
            OcsfReporter,
        )

        findings = json.loads(_report(OcsfReporter, workspace_model, context))
        assert findings
        for finding in findings:
            labels = [
                label
                for label in finding["metadata"].get("labels", [])
                if label.startswith(WORKSPACE_PROJECT_LABEL_PREFIX)
            ]
            assert len(labels) == 1

    def test_a_single_directory_scan_carries_no_project_label(
        self, single_model, context
    ):
        from automated_security_helper.plugin_modules.ash_builtin.reporters.ocsf_reporter import (
            WORKSPACE_PROJECT_LABEL_PREFIX,
            OcsfReporter,
        )

        findings = json.loads(_report(OcsfReporter, single_model, context))
        assert findings
        for finding in findings:
            for label in finding["metadata"].get("labels") or []:
                assert not label.startswith(WORKSPACE_PROJECT_LABEL_PREFIX)


# --------------------------------------------------------------------------- #
# Workspace-scoped: unused-suppressions
# --------------------------------------------------------------------------- #


class TestUnusedSuppressionsStatesItsScope:
    def test_the_workspace_report_says_it_covers_workspace_scope_only(
        self, workspace_model, context
    ):
        """The whole point of the WORKSPACE_SCOPED ruling, made explicit in output.

        Read as a merge, this reporter's zero counts mean "no unused suppressions
        anywhere in the workspace". What they actually mean is "no workspace-level
        suppressions". An operator who conflated the two would conclude their
        per-project suppressions were all in use without any evidence for it.
        """
        from automated_security_helper.plugin_modules.ash_builtin.reporters.unused_suppressions_reporter import (
            UnusedSuppressionsReporter,
        )

        payload = json.loads(
            _report(UnusedSuppressionsReporter, workspace_model, context)
        )
        assert payload["scope"] == "workspace"
        assert payload["summary"]["total_suppressions"] == 0

    def test_it_points_at_the_per_project_reports(self, workspace_model, context):
        from automated_security_helper.plugin_modules.ash_builtin.reporters.unused_suppressions_reporter import (
            UnusedSuppressionsReporter,
        )

        payload = json.loads(
            _report(UnusedSuppressionsReporter, workspace_model, context)
        )
        assert [entry["project"] for entry in payload["per_project_reports"]] == list(
            PROJECTS
        )

    def test_a_single_directory_scan_declares_no_scope_key(self, single_model, context):
        """The existing shape is unchanged, so existing consumers keep working."""
        from automated_security_helper.plugin_modules.ash_builtin.reporters.unused_suppressions_reporter import (
            UnusedSuppressionsReporter,
        )

        payload = json.loads(_report(UnusedSuppressionsReporter, single_model, context))
        assert "scope" not in payload
        assert "per_project_reports" not in payload


# --------------------------------------------------------------------------- #
# The skipped-project set, in every reporter's output
# --------------------------------------------------------------------------- #


class TestEveryReporterNamesASkippedProject:
    """The criterion, asserted once per format against rendered output.

    A skipped project is the one project most at risk of vanishing. It produced
    no findings, so in a row-per-finding format -- csv, junitxml, ocsf -- there is
    nothing to hang a row off and the project simply is not there. That is
    indistinguishable, to a reader, from a project that came back clean, and it is
    worse than useless: the operator asked for the project and is shown nothing.

    Every assertion below reads the reporter's own serialised output rather than
    the payload it was handed. Asserting on ``model.workspace.skipped_projects``
    would pass for a reporter that never looked at it.
    """

    def test_csv_emits_a_row_for_the_skipped_project(
        self, skipped_workspace_model, context
    ):
        from automated_security_helper.plugin_modules.ash_builtin.reporters.csv_reporter import (
            PROJECT_COLUMN,
            ROW_TYPE_COLUMN,
            SKIPPED_PROJECT_ROW_TYPE,
            CsvReporter,
        )

        rows = TestCsvCarriesAProjectColumn._rows(
            _report(CsvReporter, skipped_workspace_model, context)
        )
        header, *data = rows
        project_index = header.index(PROJECT_COLUMN)
        type_index = header.index(ROW_TYPE_COLUMN)
        skipped = [
            row for row in data if row and row[type_index] == SKIPPED_PROJECT_ROW_TYPE
        ]
        assert [row[project_index] for row in skipped] == [SKIPPED_PROJECT]

    def test_junitxml_emits_a_skipped_test_case_for_the_project(
        self, skipped_workspace_model, context
    ):
        from automated_security_helper.plugin_modules.ash_builtin.reporters.junitxml_reporter import (
            SKIPPED_PROJECT_SKIP_TYPE,
            JunitXmlReporter,
        )

        tree = ElementTree.fromstring(
            _report(JunitXmlReporter, skipped_workspace_model, context)
        )
        suites = {suite.get("name"): suite for suite in tree.iter("testsuite")}
        assert SKIPPED_PROJECT in suites, sorted(suites)
        skips = list(suites[SKIPPED_PROJECT].iter("skipped"))
        assert [skip.get("type") for skip in skips] == [SKIPPED_PROJECT_SKIP_TYPE]

    def test_ocsf_emits_a_finding_for_the_skipped_project(
        self, skipped_workspace_model, context
    ):
        from automated_security_helper.plugin_modules.ash_builtin.reporters.ocsf_reporter import (
            SKIPPED_PROJECT_LABEL,
            WORKSPACE_PROJECT_LABEL_PREFIX,
            OcsfReporter,
        )

        findings = json.loads(_report(OcsfReporter, skipped_workspace_model, context))
        skipped = [
            finding
            for finding in findings
            if SKIPPED_PROJECT_LABEL in (finding["metadata"].get("labels") or [])
        ]
        assert len(skipped) == 1
        labels = skipped[0]["metadata"]["labels"]
        assert f"{WORKSPACE_PROJECT_LABEL_PREFIX}{SKIPPED_PROJECT}" in labels

    def test_flat_json_carries_the_skipped_set_in_the_workspace_block(
        self, skipped_workspace_model, context
    ):
        """Already true on main, via the whole-workspace dump. Pinned, not added.

        ``skipped_projects`` is a ``computed_field``, so it survives
        ``model_dump`` and reaches this reporter's ``workspace`` block without any
        code here. Asserting it is what stops a future narrowing of that dump from
        dropping the set silently -- the same argument the yaml class below makes.
        """
        from automated_security_helper.plugin_modules.ash_builtin.reporters.flatjson_reporter import (
            FlatJSONReporter,
        )

        payload = json.loads(
            _report(FlatJSONReporter, skipped_workspace_model, context)
        )
        entries = payload["workspace"]["skipped_projects"]
        assert [entry["project"] for entry in entries] == [SKIPPED_PROJECT]
        assert entries[0]["reason"] == "no-changes"

    def test_yaml_carries_the_skipped_set_in_the_workspace_block(
        self, skipped_workspace_model, context
    ):
        from automated_security_helper.plugin_modules.ash_builtin.reporters.yaml_reporter import (
            YamlReporter,
        )

        payload = TestYamlCarriesTheWholeWorkspaceShape._load(
            _report(YamlReporter, skipped_workspace_model, context)
        )
        entries = payload["workspace"]["skipped_projects"]
        assert [entry["project"] for entry in entries] == [SKIPPED_PROJECT]

    def test_markdown_names_the_skip_reason_not_just_the_word_skipped(
        self, skipped_workspace_model, context
    ):
        """The reason, because the two reasons must not read the same.

        A NO_CHANGES skip is a successful optimisation; an ERROR skip is a project
        that was not looked at. A row saying only "SKIPPED" collapses them, and
        the operator cannot tell a fast clean run from a run that quietly examined
        nothing.
        """
        from automated_security_helper.plugin_modules.ash_builtin.reporters.markdown_reporter import (
            MarkdownReporter,
        )

        report = _report(MarkdownReporter, skipped_workspace_model, context)
        row = TestMarkdownHasAPerProjectSection._row(report, SKIPPED_PROJECT)
        assert row[-1] == "SKIPPED (no-changes)"

    def test_text_names_the_skip_reason(self, skipped_workspace_model, context):
        from automated_security_helper.plugin_modules.ash_builtin.reporters.text_reporter import (
            TextReporter,
        )

        report = _report(TextReporter, skipped_workspace_model, context)
        rows = [
            line
            for line in report.splitlines()
            if line.strip().startswith(SKIPPED_PROJECT)
        ]
        assert rows, f"no PROJECTS row for {SKIPPED_PROJECT!r} in:\n{report}"
        assert any("SKIPPED (no-changes)" in row for row in rows)

    def test_html_names_the_skip_reason_in_its_own_cell(
        self, skipped_workspace_model, context
    ):
        from automated_security_helper.plugin_modules.ash_builtin.reporters.html_reporter import (
            HtmlReporter,
        )

        report = _report(HtmlReporter, skipped_workspace_model, context)
        assert f"<td>{SKIPPED_PROJECT}</td>" in report
        assert "<td>SKIPPED (no-changes)</td>" in report


class TestASyntheticRowIsMarkedAndFilterable:
    """The two constraints the ruling was accepted with.

    A row that stands for a project rather than a finding is a lie to any consumer
    that counts rows and calls the answer a finding count. So each format's row
    carries a marker in that format's own vocabulary, and each marker is a field a
    query can exclude on -- not a convention in a string somebody has to parse.

    Filtering is demonstrated rather than asserted to exist: each test below
    computes the finding count a consumer would compute, and checks it equals the
    number of real findings.
    """

    def test_a_csv_consumer_can_count_findings_and_exclude_the_project_rows(
        self, skipped_workspace_model, context
    ):
        from automated_security_helper.plugin_modules.ash_builtin.reporters.csv_reporter import (
            FINDING_ROW_TYPE,
            ROW_TYPE_COLUMN,
            CsvReporter,
        )

        rows = TestCsvCarriesAProjectColumn._rows(
            _report(CsvReporter, skipped_workspace_model, context)
        )
        header, *data = rows
        data = [row for row in data if row]
        type_index = header.index(ROW_TYPE_COLUMN)
        # What a naive consumer computes, and what it should have computed.
        assert len(data) == 2
        assert sum(1 for row in data if row[type_index] == FINDING_ROW_TYPE) == 1

    def test_a_csv_project_row_carries_no_severity_a_rollup_could_act_on(
        self, skipped_workspace_model, context
    ):
        """A second, independent exclusion: nothing to aggregate.

        ``workspace_row_type`` is the explicit filter, but a consumer that groups
        by severity and never looks at the row type must also not see a phantom
        bucket. The cell is blank, so it lands nowhere rather than in INFO.
        """
        from automated_security_helper.plugin_modules.ash_builtin.reporters.csv_reporter import (
            ROW_TYPE_COLUMN,
            SKIPPED_PROJECT_ROW_TYPE,
            CsvReporter,
        )

        rows = TestCsvCarriesAProjectColumn._rows(
            _report(CsvReporter, skipped_workspace_model, context)
        )
        header, *data = rows
        type_index = header.index(ROW_TYPE_COLUMN)
        severity_index = header.index("severity")
        skipped = [
            row for row in data if row and row[type_index] == SKIPPED_PROJECT_ROW_TYPE
        ]
        assert skipped
        assert all(row[severity_index] == "" for row in skipped)

    def test_a_junit_consumer_counting_failures_sees_only_real_findings(
        self, skipped_workspace_model, context
    ):
        """JUnit's own idiom does the filtering for free.

        ``<skipped>`` means the test did not run, and every CI front end already
        counts it apart from ``<failure>`` and ``<error>``. So a project row cannot
        turn a CI job red, and no consumer has to be taught a new field.
        """
        from automated_security_helper.plugin_modules.ash_builtin.reporters.junitxml_reporter import (
            JunitXmlReporter,
        )

        tree = ElementTree.fromstring(
            _report(JunitXmlReporter, skipped_workspace_model, context)
        )
        failures = list(tree.iter("failure")) + list(tree.iter("error"))
        assert len(failures) == 1
        assert len(list(tree.iter("skipped"))) == 1

    def test_the_ocsf_project_finding_uses_the_schema_s_unmapped_status(
        self, skipped_workspace_model, context
    ):
        """status_id 99 is OCSF 1.1.0's "not mapped -- see ``status``".

        3 (Suppressed) was rejected: a suppressed finding is a finding somebody
        judged benign, so claiming one would assert ASH looked at the project. 0
        (Unknown) says only that the status is unknown, which is weaker than the
        value the schema reserves for a producer status it does not model.
        """
        from automated_security_helper.plugin_modules.ash_builtin.reporters.ocsf_reporter import (
            SKIPPED_PROJECT_LABEL,
            SKIPPED_PROJECT_STATUS,
            OcsfReporter,
        )

        findings = json.loads(_report(OcsfReporter, skipped_workspace_model, context))
        skipped = [
            finding
            for finding in findings
            if SKIPPED_PROJECT_LABEL in (finding["metadata"].get("labels") or [])
        ]
        assert len(skipped) == 1
        assert skipped[0]["status_id"] == 99
        assert skipped[0]["status"] == SKIPPED_PROJECT_STATUS
        assert SKIP_DETAIL in skipped[0]["status_detail"]

    def test_an_ocsf_consumer_counting_vulnerabilities_sees_only_real_findings(
        self, skipped_workspace_model, context
    ):
        """The array is empty, so a count over it excludes the project row.

        ``vulnerabilities`` is required by the class, so the row cannot omit it --
        but an empty array is the honest value and is also the filter: a consumer
        summing vulnerability counts never sees the synthetic row.
        """
        from automated_security_helper.plugin_modules.ash_builtin.reporters.ocsf_reporter import (
            SKIPPED_PROJECT_LABEL,
            OcsfReporter,
        )

        findings = json.loads(_report(OcsfReporter, skipped_workspace_model, context))
        assert len(findings) == 2
        total = sum(len(finding["vulnerabilities"]) for finding in findings)
        assert total == 1
        skipped = [
            finding
            for finding in findings
            if SKIPPED_PROJECT_LABEL in (finding["metadata"].get("labels") or [])
        ]
        assert skipped[0]["vulnerabilities"] == []


class TestNothingSyntheticAppearsWithoutASkippedProject:
    """The negative control: the marker must not be always-on.

    Every assertion above would also pass for an implementation that emitted a
    project row unconditionally, or that marked every row as synthetic. These use
    the two-project workspace where nothing was skipped, so the only correct
    answer is zero synthetic rows.
    """

    def test_csv_emits_no_project_rows(self, workspace_model, context):
        from automated_security_helper.plugin_modules.ash_builtin.reporters.csv_reporter import (
            FINDING_ROW_TYPE,
            ROW_TYPE_COLUMN,
            SKIPPED_PROJECT_ROW_TYPE,
            CsvReporter,
        )

        rows = TestCsvCarriesAProjectColumn._rows(
            _report(CsvReporter, workspace_model, context)
        )
        header, *data = rows
        type_index = header.index(ROW_TYPE_COLUMN)
        values = {row[type_index] for row in data if row}
        assert values == {FINDING_ROW_TYPE}
        assert SKIPPED_PROJECT_ROW_TYPE not in values

    def test_junitxml_emits_no_skipped_test_cases(self, workspace_model, context):
        from automated_security_helper.plugin_modules.ash_builtin.reporters.junitxml_reporter import (
            JunitXmlReporter,
        )

        tree = ElementTree.fromstring(
            _report(JunitXmlReporter, workspace_model, context)
        )
        assert list(tree.iter("skipped")) == []
        # Every suite is still "<project>/<scanner>"; none is a bare project.
        assert all("/" in (suite.get("name") or "") for suite in tree.iter("testsuite"))

    def test_ocsf_emits_no_unmapped_status_findings(self, workspace_model, context):
        from automated_security_helper.plugin_modules.ash_builtin.reporters.ocsf_reporter import (
            SKIPPED_PROJECT_LABEL,
            OcsfReporter,
        )

        findings = json.loads(_report(OcsfReporter, workspace_model, context))
        assert findings
        for finding in findings:
            assert SKIPPED_PROJECT_LABEL not in (
                finding["metadata"].get("labels") or []
            )
            assert finding["status_id"] != 99

    def test_flat_json_reports_an_empty_skipped_set(self, workspace_model, context):
        from automated_security_helper.plugin_modules.ash_builtin.reporters.flatjson_reporter import (
            FlatJSONReporter,
        )

        payload = json.loads(_report(FlatJSONReporter, workspace_model, context))
        assert payload["workspace"]["skipped_projects"] == []

    def test_no_project_row_reports_a_skip(self, workspace_model, context):
        """Scoped to the project rows, because "SKIPPED" is a scanner status too.

        The scanner table legitimately says SKIPPED for a scanner the operator
        excluded, so a document-wide search for the word passes on main for the
        wrong reason. The project rows' own verdict column is the thing under test.
        """
        from automated_security_helper.plugin_modules.ash_builtin.reporters.markdown_reporter import (
            MarkdownReporter,
        )

        report = _report(MarkdownReporter, workspace_model, context)
        verdicts = {
            TestMarkdownHasAPerProjectSection._row(report, key)[-1] for key in PROJECTS
        }
        assert verdicts == {"FAILED", "PASSED"}
        assert f"| {SKIPPED_PROJECT} |" not in report


class TestSingleDirectoryOutputKeepsItsShape:
    """The paired assertion this file opens with, for the new marker.

    ``workspace_row_type`` is added only in workspace mode, for the same reason
    ``workspace_project`` is: an unconditional column shifts every field after it,
    and a consumer reading a single-directory CSV by position would silently read
    the wrong one from then on.
    """

    def test_csv_gains_no_row_type_column(self, single_model, context):
        from automated_security_helper.plugin_modules.ash_builtin.reporters.csv_reporter import (
            ROW_TYPE_COLUMN,
            CsvReporter,
        )

        rows = TestCsvCarriesAProjectColumn._rows(
            _report(CsvReporter, single_model, context)
        )
        assert ROW_TYPE_COLUMN not in rows[0]

    def test_an_empty_single_directory_csv_gains_no_row_type_column(self, context):
        """The header-only path has its own column list, so it is asserted too."""
        from automated_security_helper.plugin_modules.ash_builtin.reporters.csv_reporter import (
            ROW_TYPE_COLUMN,
            CsvReporter,
        )

        empty = AshAggregatedResults()
        empty.sarif = SarifReport.model_validate({"version": "2.1.0", "runs": []})
        rows = TestCsvCarriesAProjectColumn._rows(_report(CsvReporter, empty, context))
        assert ROW_TYPE_COLUMN not in rows[0]

    def test_junitxml_and_ocsf_are_untouched_by_a_single_directory_scan(
        self, single_model, context
    ):
        from automated_security_helper.plugin_modules.ash_builtin.reporters.junitxml_reporter import (
            JunitXmlReporter,
        )
        from automated_security_helper.plugin_modules.ash_builtin.reporters.ocsf_reporter import (
            OcsfReporter,
        )

        tree = ElementTree.fromstring(_report(JunitXmlReporter, single_model, context))
        assert list(tree.iter("skipped")) == []

        findings = json.loads(_report(OcsfReporter, single_model, context))
        assert all(finding["status_id"] != 99 for finding in findings)


class TestASkippedProjectSurvivesAFindingLessWorkspace:
    """The case that breaks the row-per-finding formats hardest.

    Each of the three has an early return for "no findings": csv writes a header
    and stops, junitxml builds no suite, ocsf returns ``[]``. A workspace whose
    scanned projects all came back clean and whose other project was skipped hits
    every one of those. If the project row is appended after the early return, it
    is never reached -- and this is the shape where losing it matters most,
    because the artefact then says nothing at all.
    """

    @pytest.fixture
    def clean_model(self, skipped_workspace_model) -> AshAggregatedResults:
        skipped_workspace_model.sarif = SarifReport.model_validate(
            {"version": "2.1.0", "runs": []}
        )
        return skipped_workspace_model

    def test_csv_still_emits_the_project_row(self, clean_model, context):
        from automated_security_helper.plugin_modules.ash_builtin.reporters.csv_reporter import (
            PROJECT_COLUMN,
            ROW_TYPE_COLUMN,
            SKIPPED_PROJECT_ROW_TYPE,
            CsvReporter,
        )

        rows = TestCsvCarriesAProjectColumn._rows(
            _report(CsvReporter, clean_model, context)
        )
        header, *data = rows
        data = [row for row in data if row]
        assert len(data) == 1
        assert data[0][header.index(ROW_TYPE_COLUMN)] == SKIPPED_PROJECT_ROW_TYPE
        assert data[0][header.index(PROJECT_COLUMN)] == SKIPPED_PROJECT

    def test_junitxml_still_emits_the_skipped_suite(self, clean_model, context):
        from automated_security_helper.plugin_modules.ash_builtin.reporters.junitxml_reporter import (
            JunitXmlReporter,
        )

        tree = ElementTree.fromstring(_report(JunitXmlReporter, clean_model, context))
        assert [suite.get("name") for suite in tree.iter("testsuite")] == [
            SKIPPED_PROJECT
        ]

    def test_ocsf_still_emits_the_project_finding(self, clean_model, context):
        from automated_security_helper.plugin_modules.ash_builtin.reporters.ocsf_reporter import (
            SKIPPED_PROJECT_LABEL,
            OcsfReporter,
        )

        findings = json.loads(_report(OcsfReporter, clean_model, context))
        assert len(findings) == 1
        assert SKIPPED_PROJECT_LABEL in findings[0]["metadata"]["labels"]

    def test_ocsf_returns_a_bare_empty_array_when_nothing_was_skipped_either(
        self, context
    ):
        """The unchanged case, pinned byte-for-byte.

        ``[]`` is what a no-findings scan has always produced, and a consumer may
        well be comparing against exactly that string. The skipped-row path must
        not turn it into ``[\\n]`` or anything else.
        """
        from automated_security_helper.plugin_modules.ash_builtin.reporters.ocsf_reporter import (
            OcsfReporter,
        )

        empty = AshAggregatedResults()
        empty.sarif = SarifReport.model_validate({"version": "2.1.0", "runs": []})
        assert _report(OcsfReporter, empty, context) == "[]"
