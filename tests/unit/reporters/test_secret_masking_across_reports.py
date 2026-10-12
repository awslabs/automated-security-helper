# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""No secret value reaches a report, the aggregated results file or an MCP response.

Masking used to cover one field: the message of a bandit B105, B106 or B107
finding (``BanditScanner._post_process_sarif`` and
``FlatVulnerability.from_sarif_result``). The same values travel in the SARIF
snippets -- ``region.snippet`` and ``contextRegion.snippet`` -- and every output
that serializes a result carries them: the SARIF report, the flat JSON and CSV
(``code_snippet`` and ``raw_data``), GitLab SAST (``details.raw_data``), YAML, the
markdown summary's detailed findings, and ``ash_aggregated_results.json``.

Keying the mask on rule ID cannot cover two cases this file pins down:

* a finding that is not a secret finding but whose contextRegion encloses a
  secret on a neighboring line (B404 on line 1, secret on line 3), and
* a value one secret finding exposed, reused on a line no secret finding reports.

So masking works by location (the file and lines secret findings report) and by
value (values a secret finding exposes, such as B105's), across every result,
once, before ``ash_aggregated_results.json`` is saved and any reporter runs.
Non-secret snippet text survives it unchanged.

The scan here runs through ``run_ash_scan`` with bandit's SARIF canned and
detect-secrets run for real; ``tests/utils/secret_bearing_scan.py`` describes the
fixture tree and why each value sits where it does.
"""

import json

import pytest
from typer.testing import CliRunner

from tests.utils.secret_bearing_scan import (
    DEPLOY_PREFIX,
    IMPORT_LINE,
    KEY_ID_USE_LINE,
    RUN_LINE,
    SECRETS,
    SHARED_VALUE,
    SYNC_PREFIX,
    find_result,
    isolate_from_aws,
    results_without_masking,
    run_secret_bearing_scan,
    run_secret_bearing_workspace_scan,
    run_two_project_workspace_scan,
    sarif_results,
    snippet,
)


@pytest.fixture(autouse=True)
def _no_aws(monkeypatch, tmp_path):
    """No test here may reach AWS; see ``isolate_from_aws``."""
    isolate_from_aws(monkeypatch, tmp_path)


@pytest.fixture(scope="module")
def scan_output(tmp_path_factory):
    """The output directory of one scan of the fixture tree, shared by this module."""
    return run_secret_bearing_scan(tmp_path_factory.mktemp("secret-bearing-scan"))


#: The bandit findings that put a value in their message: (rule, file, line, value).
HARDCODED_VALUE_FINDINGS = [
    ("B105", "app.py", 3, "keyword_value"),
    ("B105", "creds.py", 1, "long_key"),
    ("B107", "client.py", 4, "default_arg_value"),
    ("B106", "client.py", 8, "call_arg_value"),
]


def _read(scan_output, relative):
    return (scan_output / relative).read_text(encoding="utf-8")


def _report_results(scan_output):
    return sarif_results(json.loads(_read(scan_output, "reports/ash.sarif")))


def _without_whitespace(text):
    """``text`` with all whitespace removed.

    Rich wraps console output at the terminal width and folds a long word across
    lines, which can split a value; the values themselves hold no whitespace.
    """
    return "".join(text.split())


class TestScanFixture:
    """The findings the masking tests below depend on are in the scan's results."""

    def test_the_scan_reports_every_finding_the_masking_tests_rely_on(
        self, scan_output
    ):
        results = sarif_results(
            json.loads(_read(scan_output, "ash_aggregated_results.json"))["sarif"]
        )
        for rule_id, uri, line in [
            ("B404", "app.py", 1),
            ("B105", "app.py", 3),
            ("B602", "app.py", 7),
            ("B602", "app.py", 11),
            ("B607", "app.py", 11),
            ("B107", "client.py", 4),
            ("B106", "client.py", 8),
            ("B602", "client.py", 9),
            ("B607", "client.py", 9),
            ("B105", "creds.py", 1),
            ("B602", "settings.py", 4),
        ]:
            find_result(results, rule_id, uri, line)

        detect_secrets_lines = set()
        for result in results:
            if (result.get("properties") or {}).get("scanner_name") != "detect-secrets":
                continue
            physical = result["locations"][0]["physicalLocation"]
            detect_secrets_lines.add(
                (
                    physical["artifactLocation"]["uri"].rsplit("/", 1)[-1],
                    physical["region"]["startLine"],
                )
            )
        assert {
            ("app.py", 3),
            ("client.py", 4),
            ("client.py", 8),
            ("settings.py", 3),
            ("creds.py", 1),
        } <= detect_secrets_lines
        # The reuses on app.py line 11 and client.py line 9 are reported by no
        # secret finding, which is what makes them tests of masking by value
        # rather than by location.
        assert ("app.py", 11) not in detect_secrets_lines
        assert ("client.py", 9) not in detect_secrets_lines


class TestOutputFiles:
    """Every output file a scan writes holds none of the secret values."""

    @pytest.mark.parametrize(
        "relative",
        [
            "ash_aggregated_results.json",
            "reports/ash.sarif",
            "reports/ash.flat.json",
            "reports/ash.csv",
            "reports/ash.gl-sast-report.json",
            "reports/ash.yaml",
            "reports/ash.summary.md",
        ],
    )
    def test_output_that_serializes_snippets_holds_no_secret_value(
        self, scan_output, relative
    ):
        text = _read(scan_output, relative)

        assert "B105" in text, f"{relative} lists no B105 finding; this checks nothing"
        assert SECRETS.found_in(text) == [], f"{relative} holds a secret value"

    @pytest.mark.parametrize(
        "relative",
        [
            "reports/ash.html",
            "reports/ash.ocsf.json",
            "reports/ash.junit.xml",
            "reports/ash.ghas.sarif",
        ],
    )
    def test_output_built_from_messages_and_lines_holds_no_secret_value(
        self, scan_output, relative
    ):
        """Control: these outputs carry messages and line numbers, not snippets."""
        text = _read(scan_output, relative)

        assert "B105" in text, f"{relative} lists no B105 finding; this checks nothing"
        assert SECRETS.found_in(text) == [], f"{relative} holds a secret value"


class TestSnippetMasking:
    """The SARIF report's snippets, result by result."""

    def test_neighboring_secret_is_masked_in_a_non_secret_findings_context(
        self, scan_output
    ):
        b404 = find_result(_report_results(scan_output), "B404", "app.py", 1)
        context = snippet(b404, "contextRegion")

        assert SECRETS.keyword_value not in context
        assert IMPORT_LINE in context
        assert snippet(b404, "region") == IMPORT_LINE

    @pytest.mark.parametrize("rule_id", ["B602", "B607"])
    @pytest.mark.parametrize(
        "uri, line, value_name, line_prefix",
        [
            ("app.py", 11, "keyword_value", DEPLOY_PREFIX),
            ("client.py", 9, "call_arg_value", SYNC_PREFIX),
        ],
        ids=["value-from-B105", "value-from-B106"],
    )
    def test_value_a_secret_finding_exposed_is_masked_where_it_is_reused(
        self, scan_output, rule_id, uri, line, value_name, line_prefix
    ):
        reuse = find_result(_report_results(scan_output), rule_id, uri, line)
        value = getattr(SECRETS, value_name)

        for region in ("region", "contextRegion"):
            assert value not in snippet(reuse, region), region
        assert snippet(reuse, "region").startswith(line_prefix)

    def test_secret_only_detect_secrets_reports_is_masked_by_its_location(
        self, scan_output
    ):
        b602 = find_result(_report_results(scan_output), "B602", "settings.py", 4)
        context = snippet(b602, "contextRegion")

        assert SECRETS.key_id not in context
        assert KEY_ID_USE_LINE in context
        assert snippet(b602, "region") == KEY_ID_USE_LINE

    @pytest.mark.parametrize(
        "rule_id, uri, line, value_name",
        HARDCODED_VALUE_FINDINGS,
    )
    def test_secret_findings_own_snippets_hold_no_secret_value(
        self, scan_output, rule_id, uri, line, value_name
    ):
        result = find_result(_report_results(scan_output), rule_id, uri, line)
        value = getattr(SECRETS, value_name)

        for region in ("region", "contextRegion"):
            assert value not in snippet(result, region), region

    def test_non_secret_snippet_survives_unmasked(self, scan_output):
        """Control: a finding with no secret in its lines keeps its snippets."""
        b602 = find_result(_report_results(scan_output), "B602", "app.py", 7)

        assert snippet(b602, "region") == RUN_LINE
        assert snippet(b602, "contextRegion") == "def run(cmd):\n" + RUN_LINE + "\n"

    @pytest.mark.parametrize(
        "rule_id, uri, line, value_name",
        HARDCODED_VALUE_FINDINGS,
    )
    def test_secret_finding_message_is_masked(
        self, scan_output, rule_id, uri, line, value_name
    ):
        """Control: the message masking that existed before keeps working."""
        result = find_result(_report_results(scan_output), rule_id, uri, line)
        message = result["message"]["text"]

        assert message.startswith("Possible hardcoded password: '")
        assert getattr(SECRETS, value_name) not in message


class TestFlatOutputs:
    """The flat JSON report, whose ``code_snippet`` prefers the contextRegion."""

    def test_flat_findings_hold_no_secret_value_in_any_field(self, scan_output):
        findings = json.loads(_read(scan_output, "reports/ash.flat.json"))["findings"]

        leaks = {
            (finding["rule_id"], finding.get("file_path"), field): SECRETS.found_in(
                str(value)
            )
            for finding in findings
            for field, value in finding.items()
            if SECRETS.found_in(str(value))
        }
        assert leaks == {}

    def test_non_secret_snippet_survives_in_the_flat_report(self, scan_output):
        """Control: masking leaves the B602 on app.py line 7 readable."""
        findings = json.loads(_read(scan_output, "reports/ash.flat.json"))["findings"]
        b602 = [
            finding
            for finding in findings
            if finding["rule_id"] == "B602"
            and finding.get("file_path", "").endswith("app.py")
            and finding.get("line_start") == 7
        ]

        assert len(b602) == 1
        # The flat model strips the snippet, so compare without the line ends.
        assert b602[0]["code_snippet"] == ("def run(cmd):\n" + RUN_LINE).strip()


class TestMcpResponses:
    """An MCP client asking about a finding gets no secret value back."""

    @pytest.mark.parametrize("uri_suffix", ["app.py", "creds.py"])
    def test_explain_finding_returns_no_secret_value(
        self, scan_output, monkeypatch, uri_suffix
    ):
        from automated_security_helper.cli.mcp.scan_target import (
            ASH_MCP_ALLOWED_ROOTS_ENV,
        )
        from automated_security_helper.cli.mcp_tools import mcp_explain_finding

        monkeypatch.setenv(ASH_MCP_ALLOWED_ROOTS_ENV, str(scan_output.parent))
        findings = json.loads(_read(scan_output, "reports/ash.flat.json"))["findings"]
        finding_id = next(
            finding["id"]
            for finding in findings
            if finding["rule_id"] == "B105"
            and finding.get("file_path", "").endswith(uri_suffix)
        )

        response = mcp_explain_finding(finding_id, results_path=str(scan_output))

        assert response["success"] is True, response
        assert SECRETS.found_in(json.dumps(response)) == []


@pytest.fixture(scope="module")
def workspace_output(tmp_path_factory):
    """The output directory of one workspace scan with the fixture tree as its project."""
    return run_secret_bearing_workspace_scan(
        tmp_path_factory.mktemp("secret-bearing-workspace")
    )


class TestWorkspaceScan:
    """A workspace scan's per-project and unified outputs hold no secret value."""

    @pytest.mark.parametrize(
        "relative",
        [
            "projects/api/ash_aggregated_results.json",
            "projects/api/reports/ash.sarif",
            "ash_aggregated_results.json",
            "reports/ash.sarif",
            "reports/ash.flat.json",
            "reports/ash.csv",
        ],
    )
    def test_workspace_output_holds_no_secret_value(self, workspace_output, relative):
        text = _read(workspace_output, relative)

        assert "B105" in text, f"{relative} lists no B105 finding; this checks nothing"
        assert SECRETS.found_in(text) == [], f"{relative} holds a secret value"


class TestScanIsolation:
    def test_the_scan_helpers_keep_tools_out_of_the_real_home(self, tmp_path):
        """The in-process scans run whatever semgrep and checkov are on PATH.

        Their version checks write under HOME (``~/.cache/semgrep_version``,
        ``~/.config/.semgrep/settings.yml``, ``~/.cache/checkov``), so the helper
        that isolates a scan from AWS points HOME and the XDG directories under
        the test's own directory too.
        """
        import os
        from pathlib import Path

        with pytest.MonkeyPatch.context() as monkeypatch:
            isolate_from_aws(monkeypatch, tmp_path)

            for name in (
                "HOME",
                "XDG_CONFIG_HOME",
                "XDG_CACHE_HOME",
                "XDG_DATA_HOME",
                "XDG_STATE_HOME",
            ):
                assert Path(os.environ[name]).is_relative_to(tmp_path), name
            assert Path.home().is_relative_to(tmp_path)


class TestScanWithoutAReportPhase:
    """``--phases convert --phases scan`` writes the results file with no report phase.

    That run builds its model empty and fills it in afterwards, so the masking
    when the model is built finds nothing; the masking when it is saved is what
    keeps the file clean.
    """

    def test_the_results_file_holds_no_secret_value(self, tmp_path):
        from automated_security_helper.core.enums import ExecutionPhase

        output_dir = run_secret_bearing_scan(
            tmp_path, phases=[ExecutionPhase.CONVERT, ExecutionPhase.SCAN]
        )

        assert not (output_dir / "reports" / "ash.sarif").exists(), (
            "a report phase ran, so this checks the usual path"
        )
        text = _read(output_dir, "ash_aggregated_results.json")
        assert "B105" in text
        assert SECRETS.found_in(text) == []


@pytest.fixture(scope="module")
def two_project_output(tmp_path_factory):
    """One workspace scan of two projects that share one value; see TWO_PROJECT_FILES."""
    return run_two_project_workspace_scan(
        tmp_path_factory.mktemp("two-project-workspace")
    )


def _written_outside_tool_output(output_dir):
    """Every file a scan wrote, except the tools' own output.

    ``scanners/<name>/`` and ``converted/`` hold what the tools wrote, which
    output-formats.md says is not masked.
    """
    for path in sorted(output_dir.rglob("*")):
        parts = set(path.relative_to(output_dir).parts)
        if path.is_file() and not parts & {"scanners", "converted"}:
            yield path


class TestWorkspaceAcrossProjects:
    """A value one project's finding exposes is masked in every project's output.

    ``api``'s B105 quotes the value; ``web`` has it on a command line that only a
    B602 reports. Each project's scan is masked against its own findings, so the
    workspace masks all of them again with the values every project exposed.
    """

    def test_the_projects_report_what_this_relies_on(self, two_project_output):
        api = _read(two_project_output, "projects/api/ash_aggregated_results.json")
        web = _read(two_project_output, "projects/web/ash_aggregated_results.json")
        unified = _read(two_project_output, "ash_aggregated_results.json")
        assert "B105" in api
        assert "B602" in web
        assert "B105" in unified and "B602" in unified
        # web's findings really carry the value: its scanner wrote it in clear.
        raw = [
            path
            for path in (two_project_output / "projects" / "web").rglob("*")
            if path.is_file()
            and "scanners" in path.parts
            and SHARED_VALUE in path.read_text(encoding="utf-8", errors="replace")
        ]
        assert raw, "web's scanner output does not hold the shared value"

    def test_no_output_holds_the_value_another_project_exposed(
        self, two_project_output
    ):
        written = list(_written_outside_tool_output(two_project_output))
        assert any(path.name == "ash.sarif" for path in written)

        leaks = [
            str(path.relative_to(two_project_output))
            for path in written
            if SHARED_VALUE in path.read_text(encoding="utf-8", errors="replace")
        ]

        assert leaks == []

    def test_the_masked_line_keeps_its_other_text(self, two_project_output):
        """Control: the value is masked, not the command line around it."""
        results = sarif_results(
            json.loads(_read(two_project_output, "ash_aggregated_results.json"))[
                "sarif"
            ]
        )
        b602 = next(result for result in results if result["ruleId"] == "B602")

        assert snippet(b602, "region").startswith('subprocess.call("deploy --pw ')


class TestStoredResultsRerendered:
    """Reports rendered from an ``ash_aggregated_results.json`` written without masking.

    Such a file comes from an ASH that predates masking, or from any producer that
    skipped it. The reporters still run on what it holds, so the masking has to
    happen on that path too.
    """

    @pytest.fixture
    def stored_output_dir(self, tmp_path):
        model = results_without_masking(tmp_path / "src", tmp_path / "scanner-output")
        output_dir = tmp_path / "out"
        output_dir.mkdir()
        results_file = output_dir / "ash_aggregated_results.json"
        results_file.write_text(model.model_dump_json(by_alias=True), encoding="utf-8")
        # Precondition: the stored file really holds the values.
        assert SECRETS.found_in(results_file.read_text(encoding="utf-8")) == (
            SECRETS.names()
        )
        return output_dir

    @pytest.mark.parametrize("report_format", ["sarif", "csv"])
    def test_report_command_output_holds_no_secret_value(
        self, stored_output_dir, report_format
    ):
        from automated_security_helper.cli.main import app

        result = CliRunner().invoke(
            app,
            [
                "report",
                "--format",
                report_format,
                "--output-dir",
                str(stored_output_dir),
                "--log-level",
                "ERROR",
                "--no-color",
            ],
        )

        assert result.exit_code == 0, result.output
        assert "B105" in result.output
        assert SECRETS.found_in(_without_whitespace(result.output)) == []

    def test_use_existing_rerender_writes_no_secret_value(self, stored_output_dir):
        from automated_security_helper.interactions.run_ash_scan import run_ash_scan

        run_ash_scan(
            source_dir=str(stored_output_dir.parent / "src"),
            output_dir=str(stored_output_dir),
            existing_results=str(stored_output_dir / "ash_aggregated_results.json"),
            output_formats=["sarif", "flat-json"],
            offline=True,
            progress=False,
            quiet=True,
            show_summary=False,
            fail_on_findings=False,
            # The stored file has no scanner statuses, which the completeness gate
            # would read as scanners that did not finish.
            fail_on_incomplete_scanners=False,
            color=False,
        )

        for relative in ("reports/ash.sarif", "reports/ash.flat.json"):
            text = _read(stored_output_dir, relative)
            assert "B105" in text, relative
            assert SECRETS.found_in(text) == [], relative

    def test_mcp_explain_finding_on_stored_results_returns_no_secret_value(
        self, stored_output_dir, monkeypatch
    ):
        from automated_security_helper.cli.mcp.scan_target import (
            ASH_MCP_ALLOWED_ROOTS_ENV,
        )
        from automated_security_helper.cli.mcp_tools import (
            _load_flat_vulns_for_explain,
            mcp_explain_finding,
        )

        monkeypatch.setenv(ASH_MCP_ALLOWED_ROOTS_ENV, str(stored_output_dir.parent))
        # The ids as the tool itself derives them from the stored file, so the
        # lookup does not depend on how masking rewrites a description.
        finding_ids = [
            vuln.id
            for vuln in _load_flat_vulns_for_explain(str(stored_output_dir))
            if vuln.rule_id in ("B105", "B106", "B107")
        ]
        assert len(finding_ids) == 4

        for finding_id in finding_ids:
            response = mcp_explain_finding(
                finding_id, results_path=str(stored_output_dir)
            )
            assert response["success"] is True, response
            assert SECRETS.found_in(json.dumps(response)) == [], finding_id

    def test_merge_of_stored_shard_results_writes_no_secret_value(
        self, stored_output_dir, tmp_path
    ):
        from automated_security_helper.cli.merge import (
            merge_command,
            stamp_shard_assignment,
        )
        from automated_security_helper.core.enums import ScannerStatus
        from automated_security_helper.core.sharding import ShardAssignment
        from automated_security_helper.models.asharp_model import (
            ScannerTargetStatusInfo,
        )

        # The stored file, stamped as the one shard of a one-shard run, as
        # `ash scan --shard-index 0 --shard-count 1` would have written it.
        results_file = stored_output_dir / "ash_aggregated_results.json"
        # Rebuilt the way the fixture built it, not read back: reading the file
        # into a model masks it, and the stored shard must hold the values.
        model = results_without_masking(tmp_path / "src", tmp_path / "scanner-output")
        scanners = ["bandit", "detect-secrets"]
        for name in scanners:
            model.scanner_results[name] = ScannerTargetStatusInfo(
                status=ScannerStatus.FAILED, excluded=False, dependencies_satisfied=True
            )
            model.additional_reports[name] = {
                "source": {"scanner_name": name, "status": "FAILED", "duration": 1.0}
            }
        stamp_shard_assignment(
            model,
            ShardAssignment(
                shard_index=0,
                shard_count=1,
                assigned_scanners=scanners,
                candidate_scanners=scanners,
            ),
        )
        results_file.write_text(model.model_dump_json(by_alias=True), encoding="utf-8")
        assert SECRETS.found_in(results_file.read_text(encoding="utf-8")) == (
            SECRETS.names()
        )
        merged_dir = tmp_path / "merged"

        # Called as the `ash merge` command function rather than through
        # CliRunner: after other in-process CLI runs, CliRunner's captured stream
        # is closed under it here, which would fail the test for a reason unrelated
        # to masking. Exit 0 returns; any other exit raises typer.Exit.
        merge_command(
            results=[str(stored_output_dir)],
            output_dir=str(merged_dir),
            output_formats=["sarif,flat-json"],
            fail_on_findings=False,
            fail_on_incomplete_scanners=False,
        )

        for relative in (
            "ash_aggregated_results.json",
            "reports/ash.sarif",
            "reports/ash.flat.json",
        ):
            text = _read(merged_dir, relative)
            assert "B105" in text, relative
            assert SECRETS.found_in(text) == [], relative
