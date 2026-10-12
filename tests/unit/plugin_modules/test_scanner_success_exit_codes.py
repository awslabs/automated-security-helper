"""Each scanner accepts exactly the exit codes its tool uses for a completed run.

The table records, per tool, which codes mean the tool finished.
A code that means findings were found is a success; any code the tool uses for an
error is not. A set that is too narrow turns ordinary scans into errors, and one that
is too wide records a failed tool as a clean scan, so every entry names its source:

- bandit 1.9.4, ``bandit/cli/main.py``: ``sys.exit(2)`` on every error path, 1 when
  results remain after filtering, 0 otherwise.
- checkov 3.3.26, ``checkov/main.py``: ``print_results`` returns 0 or 1 (failed
  checks), and ``exit_run`` exits 2 when the run crashes.
- grype, ``cmd/grype/cli/cli.go`` (``WithMapExitCode``): 2 when a match is at or above
  the configured fail-on severity, 100 for ``grype db check`` only, 1 for any other
  error.
- semgrep 1.180.0, ``semgrep/error.py``: 0 OK, 1 findings, 2 fatal, 3 and up for
  specific failures (7: the rule configuration could not be read).
- opengrep, ``src/osemgrep/core/Exit_code.ml``: the same values as semgrep.
- trivy, ``cmd/trivy/main.go``: a run exits with the ``--exit-code`` value when
  findings are reported and that flag is set (default 0,
  ``pkg/flag/report_flags.go``; the plugin never sets it), and with 1 from
  ``log.Fatal`` on an error.
- syft, ``cmd/syft/main.go`` runs ``clio``, whose ``Run`` exits 1 on any error; syft
  installs no exit-code mapping, so 0 is its only success.
- ferret-scan: 0 for a completed scan with or without findings, 3 for an incomplete
  scan under ``--fail-on-incomplete``, 1 for errors (the plugin's own notes in
  ``ash_ferret_plugins/ferret_scanner.py``).
- snyk, ``src/cli/exit-codes.ts``: 1 issues found, 2 error, 3 no supported
  project detected.

Not in the table, because their exit status is not a fixed set: cfn-nag exits with
its count of failing violations and is judged per template; npm audit exits 1 both
for advisories at the audit level and for errors, and is judged by whether it wrote
a report; detect-secrets and cdk-nag run ASH's own worker processes.

The second half runs each scanner's real class through ``ScannerExecutor`` with only
the tool replaced, at ``_run_subprocess``: the stand-in writes a well-formed, empty
results file where the scanner reads it and returns a chosen exit code. A rejected
code is an ERROR row; an accepted code with the same file is PASSED (the controls).

The last part runs two targets, source then converted, through one plugin instance,
as a scan does. ``_process_command_response`` keeps the largest code any run of the
instance returned, so each target's row is checked against the code of its own run.
"""

from __future__ import annotations

import importlib
import json
import re
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.constants import ASH_WORK_DIR_NAME
from automated_security_helper.core.enums import ScannerStatus
from automated_security_helper.core.phases.scanner_executor import ScannerExecutor
from automated_security_helper.models.asharp_model import AshAggregatedResults

AshConfig.model_rebuild()
AshAggregatedResults.model_rebuild()

_MODULES = "automated_security_helper.plugin_modules"

#: name -> (class path, accepted codes, rejected codes the tool uses for errors)
EXIT_CODE_TABLE = {
    "bandit": (
        f"{_MODULES}.ash_builtin.scanners.bandit_scanner.BanditScanner",
        {0, 1},
        {2},
    ),
    "checkov": (
        f"{_MODULES}.ash_builtin.scanners.checkov_scanner.CheckovScanner",
        {0, 1},
        {2},
    ),
    "grype": (
        f"{_MODULES}.ash_builtin.scanners.grype_scanner.GrypeScanner",
        {0, 2},
        {1},
    ),
    "semgrep": (
        f"{_MODULES}.ash_builtin.scanners.semgrep_scanner.SemgrepScanner",
        {0, 1},
        {2, 7},
    ),
    "opengrep": (
        f"{_MODULES}.ash_builtin.scanners.opengrep_scanner.OpengrepScanner",
        {0, 1},
        {2, 7},
    ),
    "trivy-repo": (
        f"{_MODULES}.ash_trivy_plugins.trivy_repo_scanner.TrivyRepoScanner",
        {0},
        {1},
    ),
    "syft": (f"{_MODULES}.ash_builtin.scanners.syft_scanner.SyftScanner", {0}, {1}),
    "ferret-scan": (
        f"{_MODULES}.ash_ferret_plugins.ferret_scanner.FerretScanScanner",
        {0, 3},
        {1},
    ),
    "snyk-code": (
        f"{_MODULES}.ash_snyk_plugins.snyk_code_scanner.SnykCodeScanner",
        {0, 1},
        {2, 3},
    ),
}

#: Scanners whose real class is run through the executor below.
EXECUTED = [
    "bandit",
    "checkov",
    "grype",
    "semgrep",
    "opengrep",
    "trivy-repo",
    "syft",
    "ferret-scan",
    "snyk-code",
]

#: Rejected codes left out of the one-target error cases. snyk exits 3 when it finds
#: no project it supports; what that means for a row is the scanner's own decision,
#: and the two-target snyk case below holds whichever way it is graded.
GRADED_BY_THE_SCANNER = {"snyk-code": {3}}


def _rejected(name: str) -> list[int]:
    return sorted(EXIT_CODE_TABLE[name][2] - GRADED_BY_THE_SCANNER.get(name, set()))


#: Accepted codes that say the run completed but lost coverage: ferret-scan exits 3
#: under fail_on_incomplete when a file could not be fully scanned. Its SARIF is
#: graded, and the target counts as failed, so the row is ERROR with its findings.
LOST_COVERAGE = {"ferret-scan": {3}}


def _accepted_and_complete(name: str) -> list[int]:
    return sorted(EXIT_CODE_TABLE[name][1] - LOST_COVERAGE.get(name, set()))


EMPTY_SARIF = json.dumps(
    {
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "tool", "rules": []}}, "results": []}],
    }
)
EMPTY_CYCLONEDX = json.dumps(
    {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1}
)


def _scanner_class(name: str):
    path, _accepted, _rejected = EXIT_CODE_TABLE[name]
    module, _, attribute = path.rpartition(".")
    return getattr(importlib.import_module(module), attribute)


@pytest.mark.parametrize("name", sorted(EXIT_CODE_TABLE))
def test_the_success_set_is_the_tools_documented_one(name):
    _path, accepted, rejected = EXIT_CODE_TABLE[name]
    declared = set(_scanner_class(name).success_exit_codes)

    assert declared == accepted, (
        f"{name} accepts {sorted(declared)}; its tool completes with "
        f"{sorted(accepted)} and uses {sorted(rejected)} for errors"
    )


@pytest.fixture
def plugin_context(tmp_path):
    source_dir = tmp_path / "source"
    source_dir.mkdir()
    (source_dir / "app.py").write_text("total = 1 + 1\n")
    output_dir = tmp_path / "output"
    output_dir.mkdir()
    work_dir = output_dir / ASH_WORK_DIR_NAME
    work_dir.mkdir()
    return PluginContext(
        source_dir=source_dir,
        output_dir=output_dir,
        work_dir=work_dir,
        config=AshConfig(project_name="test"),
    )


_OUTPUT_FLAGS = (
    "--output",
    "--sarif-output",
    "--output-file",
    "-o",
    "--sarif-file-output",
)


def _results_paths(command, results_dir: Path):
    """Paths in ``command`` that name a file under ``results_dir``.

    Covers ``--output PATH``, ``--output=PATH``, snyk's ``--sarif-file-output=PATH``
    and syft's ``--output FORMAT=PATH``.
    """
    root = str(results_dir)
    paths = []
    for index, part in enumerate(str(p) for p in command):
        values = []
        flag, _, inline = part.partition("=")
        if part in _OUTPUT_FLAGS and index + 1 < len(command):
            values.append(str(command[index + 1]))
        elif inline and flag in _OUTPUT_FLAGS:
            values.append(inline)
        for value in values:
            if not value.startswith(root) and "=" in value:
                value = value.split("=", 1)[1]
            if value.startswith(root):
                paths.append(Path(value))
    return paths


def _rows(plugin_context, monkeypatch, name: str, runs, earlier_run_code=None):
    """The scanner's rows after one executor call over source, then converted.

    ``runs`` holds one ``(exit code, results file content)`` pair per target, in
    that order, on one plugin instance. A ``None`` in place of a pair leaves the
    converted tree empty, so the scanner has nothing to run there.

    With ``earlier_run_code``, the dependency check of each target records a run of
    the plugin's that exited with it before the tool runs, as a version probe that
    goes through ``_run_subprocess`` does.
    """
    scanner = _scanner_class(name)(context=plugin_context)
    captured = {}
    targets = [{"path": plugin_context.source_dir, "type": "source"}]
    by_type = {"source": runs[0]}
    if len(runs) > 1:
        targets.append({"path": plugin_context.work_dir, "type": "converted"})
        by_type["converted"] = runs[1]
        if runs[1] is not None:
            (plugin_context.work_dir / "converted.py").write_text("total = 2 + 2\n")

    original_pre_scan = scanner._pre_scan

    def pre_scan(*args, **kwargs):
        captured["target_type"] = kwargs["target_type"]
        return original_pre_scan(*args, **kwargs)

    monkeypatch.setattr(scanner, "_pre_scan", pre_scan)

    if hasattr(scanner, "_execute_scan"):
        original = scanner._execute_scan

        def capture(*args, **kwargs):
            outcome = original(*args, **kwargs)
            captured["results_file"] = Path(outcome[1])
            return outcome

        monkeypatch.setattr(scanner, "_execute_scan", capture)

    def tool(command, results_dir=None, *args, **kwargs):
        run = by_type[captured["target_type"]]
        assert run is not None, "the tool ran on a target left empty"
        exit_code, content = run
        if "results_file" in captured:
            paths = [captured.pop("results_file")]
        else:
            paths = _results_paths(command, Path(scanner.results_dir))
        for path in paths:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")
        response = {
            "returncode": exit_code,
            "stdout": "",
            "stderr": f"exit {exit_code}",
        }
        scanner._process_command_response(response)
        return response

    def dependencies():
        if earlier_run_code is not None:
            scanner._process_command_response(
                {"returncode": earlier_run_code, "stdout": "", "stderr": ""}
            )
        return True

    monkeypatch.setattr(scanner, "_run_subprocess", tool)
    monkeypatch.setattr(scanner, "validate_plugin_dependencies", dependencies)
    executor = ScannerExecutor(
        plugin_context=plugin_context, progress_display=MagicMock(), scanner_tasks=[]
    )
    # The content-database age check runs the scanner's real binary; it is not
    # what is under test here.
    monkeypatch.setattr(executor, "_assess_content_databases", lambda *a, **k: None)
    rows = executor._execute_scanner(str(scanner.config.name), scanner, targets)
    return {row.target_type: row for row in rows}


def _empty_results(name: str) -> str:
    return EMPTY_CYCLONEDX if name == "syft" else EMPTY_SARIF


def _row(plugin_context, monkeypatch, name: str, exit_code: int):
    """The scanner's row after one run whose tool exits ``exit_code``."""
    rows = _rows(plugin_context, monkeypatch, name, [(exit_code, _empty_results(name))])
    return rows["source"]


@pytest.mark.parametrize(
    "name, exit_code",
    [(name, code) for name in EXECUTED for code in _rejected(name)],
)
def test_a_rejected_exit_code_is_an_error_row(
    plugin_context, monkeypatch, name, exit_code
):
    row = _row(plugin_context, monkeypatch, name, exit_code)

    assert row.status == ScannerStatus.ERROR, (
        f"{name}'s tool exited {exit_code}, an error code for it, and left a "
        f"well-formed empty results file; the row was graded {row.status.value}"
    )
    assert row.exit_code == exit_code
    assert any(re.search(rf"\b{exit_code}\b", str(e)) for e in row.errors), (
        f"the ERROR row names the exit code; errors: {row.errors!r}"
    )


@pytest.mark.parametrize(
    "name, exit_code",
    [(name, code) for name in EXECUTED for code in _accepted_and_complete(name)],
)
def test_an_accepted_exit_code_with_no_findings_is_passed(
    plugin_context, monkeypatch, name, exit_code
):
    """Control: the same scanner, stand-in and results file, with a success code."""
    row = _row(plugin_context, monkeypatch, name, exit_code)

    assert row.status == ScannerStatus.PASSED, (
        f"{name} exiting {exit_code} with no findings was graded {row.status.value}; "
        f"errors: {row.errors!r}"
    )


#: SARIF documents that validate and hold no run: nothing was scanned.
RUNLESS_SARIF = {
    "empty-object": json.dumps({}),
    "no-runs": json.dumps({"version": "2.1.0", "runs": []}),
}


@pytest.mark.parametrize("content", sorted(RUNLESS_SARIF))
@pytest.mark.parametrize("name", [name for name in EXECUTED if name != "syft"])
def test_sarif_with_no_run_is_an_error_row(plugin_context, monkeypatch, name, content):
    """The template refuses it before grading; a scan() override returns it as is."""
    row = _row_with(plugin_context, monkeypatch, name, 0, RUNLESS_SARIF[content])

    assert row.status == ScannerStatus.ERROR, (
        f"{name} exited 0 with a results file holding no SARIF run ({content}); "
        f"the row was graded {row.status.value}"
    )
    assert any("no SARIF run" in str(error) for error in row.errors), row.errors


def _sarif_with_notifications(*notifications) -> str:
    return json.dumps(
        {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "tool", "rules": []}},
                    "invocations": [
                        {
                            "executionSuccessful": False,
                            "toolExecutionNotifications": [
                                {"level": level, "message": {"text": text}}
                                for level, text in notifications
                            ],
                        }
                    ],
                    "results": [],
                }
            ],
        }
    )


@pytest.mark.parametrize(
    "name, exit_code", [("semgrep", 7), ("opengrep", 7), ("ferret-scan", 1)]
)
def test_a_rejected_run_quotes_the_errors_its_results_file_reports(
    plugin_context, monkeypatch, name, exit_code
):
    """semgrep reports a rule file it cannot read in its SARIF, not on stderr."""
    content = _sarif_with_notifications(
        ("error", "Invalid YAML file rules/example.yml: mapping values not allowed"),
        ("warning", "a warning that is not the cause"),
    )

    row = _row_with(plugin_context, monkeypatch, name, exit_code, content)

    assert row.status == ScannerStatus.ERROR
    text = " ".join(str(error) for error in row.errors)
    assert "Invalid YAML file rules/example.yml" in text, row.errors
    assert "a warning that is not the cause" not in text
    assert "results_sarif.sarif" in text or "ferret-scan.sarif" in text, (
        "the error names the results file the notifications came from"
    )


def test_ferret_scans_lost_coverage_fails_its_target_and_keeps_its_findings(
    plugin_context, monkeypatch
):
    """Exit 3: a file could not be fully scanned, so findings may be missing."""
    row = _row_with(
        plugin_context, monkeypatch, "ferret-scan", 3, _one_finding_sarif("app.py")
    )

    assert (row.targets_attempted, row.targets_failed) == (1, 1)
    assert row.status == ScannerStatus.ERROR
    assert row.finding_count == 1, "the partial results are still reported"
    assert row.exit_code == 3


def test_ferret_scan_counts_a_lost_target_only_for_the_run_that_lost_it(
    plugin_context, monkeypatch
):
    """Source exits 3, converted 0: the converted row has no failed target."""
    rows = _rows(
        plugin_context,
        monkeypatch,
        "ferret-scan",
        [(3, EMPTY_SARIF), (0, EMPTY_SARIF)],
    )

    assert rows["source"].targets_failed == 1
    assert rows["converted"].targets_failed == 0
    assert rows["converted"].status == ScannerStatus.PASSED


def test_ferret_scan_makes_no_target_claim_for_a_complete_run(
    plugin_context, monkeypatch
):
    """Control: exit 0, so nothing is said about targets, as before."""
    row = _row_with(plugin_context, monkeypatch, "ferret-scan", 0, EMPTY_SARIF)

    assert row.targets_attempted is None
    assert row.status == ScannerStatus.PASSED


def _row_with(plugin_context, monkeypatch, name: str, exit_code: int, content: str):
    return _rows(plugin_context, monkeypatch, name, [(exit_code, content)])["source"]


@pytest.mark.parametrize("name", EXECUTED)
def test_the_tools_own_exit_code_decides_over_an_earlier_run_in_the_target(
    plugin_context, monkeypatch, name
):
    """An earlier run of the plugin's in this target exits 2; the tool exits 0.

    The plugin keeps the largest code of all its runs, so the row is graded on the
    tool's run only because the scanner records that run's code.
    """
    row = _rows(
        plugin_context,
        monkeypatch,
        name,
        [(0, _empty_results(name))],
        earlier_run_code=2,
    )["source"]

    assert row.status == ScannerStatus.PASSED, (
        f"{name}'s tool exited 0 after an earlier run that exited 2; the row was "
        f"graded {row.status.value}, errors: {row.errors!r}"
    )
    assert row.exit_code == 0


# Two targets, source then converted, through one plugin instance.


def _one_finding_sarif(uri: str) -> str:
    return json.dumps(
        {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {"name": "tool", "rules": [{"id": "example-rule"}]}
                    },
                    "results": [
                        {
                            "ruleId": "example-rule",
                            "level": "error",
                            "message": {"text": "example finding"},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": uri},
                                        "region": {"startLine": 1},
                                    }
                                }
                            ],
                        }
                    ],
                }
            ],
        }
    )


@pytest.mark.parametrize(
    "name, exit_code",
    [(name, code) for name in EXECUTED for code in _rejected(name)],
)
def test_a_rejected_exit_code_after_an_accepted_one_is_an_error_row(
    plugin_context, monkeypatch, name, exit_code
):
    """Source exits the largest code the scanner accepts, converted a code it rejects.

    For grype that is 2 and then 1, and the largest code across both runs, 2, is one
    grype accepts.
    """
    accepted = max(EXIT_CODE_TABLE[name][1])
    content = _empty_results(name)

    rows = _rows(
        plugin_context, monkeypatch, name, [(accepted, content), (exit_code, content)]
    )

    expected_source = (
        ScannerStatus.ERROR
        if accepted in LOST_COVERAGE.get(name, set())
        else ScannerStatus.PASSED
    )
    assert rows["source"].status == expected_source, rows["source"].errors
    assert rows["converted"].status == ScannerStatus.ERROR, (
        f"{name}'s converted run exited {exit_code}, which it rejects, after a "
        f"source run that exited {accepted}; the row was graded "
        f"{rows['converted'].status.value}"
    )
    assert rows["converted"].exit_code == exit_code


@pytest.mark.parametrize(
    "name, exit_code",
    [(name, code) for name in EXECUTED for code in _rejected(name)],
)
def test_an_accepted_exit_code_after_a_rejected_one_is_graded_on_its_own(
    plugin_context, monkeypatch, name, exit_code
):
    content = _empty_results(name)

    rows = _rows(
        plugin_context, monkeypatch, name, [(exit_code, content), (0, content)]
    )

    assert rows["source"].status == ScannerStatus.ERROR
    assert rows["converted"].status == ScannerStatus.PASSED, (
        f"{name}'s converted run exited 0 after a source run that exited "
        f"{exit_code}; the row was graded {rows['converted'].status.value}, "
        f"errors: {rows['converted'].errors!r}"
    )
    assert rows["converted"].exit_code == 0


#: Scanners that start each target at exit code 0: every executed one, snyk-code
#: included (its scan() resets the code at its start, and its tool's run then
#: records that target's own code).
RESET_PER_TARGET = list(EXECUTED)


@pytest.mark.parametrize("name", RESET_PER_TARGET)
def test_a_target_with_nothing_to_scan_does_not_report_the_previous_exit_code(
    plugin_context, monkeypatch, name
):
    """The converted tree is empty, so the scanner returns before running its tool."""
    rejected = min(_rejected(name))

    rows = _rows(
        plugin_context,
        monkeypatch,
        name,
        [(rejected, _empty_results(name)), None],
    )

    assert rows["source"].exit_code == rejected
    assert rows["converted"].exit_code == 0, (
        f"{name} ran nothing on the empty converted tree, and its row reports "
        f"exit code {rows['converted'].exit_code}, the source run's"
    )
    assert rows["converted"].status == ScannerStatus.PASSED


def test_snyk_code_grades_the_converted_run_on_its_own_after_a_source_exit_3(
    plugin_context, monkeypatch
):
    """Source exits 3 (no supported project), converted exits 0 with one finding.

    Whatever exit 3 makes of the source row, the converted row is graded on its own
    run: its finding is counted and its exit code is 0.
    """
    rows = _rows(
        plugin_context,
        monkeypatch,
        "snyk-code",
        [(3, EMPTY_SARIF), (0, _one_finding_sarif("converted.py"))],
    )

    converted = rows["converted"]
    assert converted.finding_count == 1, (converted.status, converted.errors)
    assert converted.exit_code == 0
    assert converted.status not in (ScannerStatus.ERROR, ScannerStatus.SKIPPED)


def test_snyk_code_exit_1_with_a_finding_is_a_finding_not_an_error(
    plugin_context, monkeypatch
):
    """snyk exits 1 when it found issues; the row counts them and keeps the code.

    PASSED or FAILED is then the severity gate's call on the finding.
    """
    row = _rows(
        plugin_context,
        monkeypatch,
        "snyk-code",
        [(1, _one_finding_sarif("app.py"))],
    )["source"]

    assert row.status not in (ScannerStatus.ERROR, ScannerStatus.SKIPPED), row.errors
    assert row.finding_count == 1
    assert row.exit_code == 1


def test_a_target_the_sandbox_refused_does_not_report_the_previous_exit_code(
    plugin_context, monkeypatch
):
    """The sandbox refuses the converted target, so nothing runs on it."""
    from automated_security_helper.core.phases import scanner_executor
    from automated_security_helper.utils.sandbox import SandboxUnavailable

    original_scope = scanner_executor.scanner_sandbox_scope

    def scope(plugin, context, target):
        if Path(target) == plugin_context.work_dir:
            raise SandboxUnavailable("no backend for this target")
        return original_scope(plugin, context, target)

    monkeypatch.setattr(scanner_executor, "scanner_sandbox_scope", scope)

    rows = _rows(
        plugin_context,
        monkeypatch,
        "bandit",
        [(2, EMPTY_SARIF), (0, EMPTY_SARIF)],
    )

    assert rows["source"].exit_code == 2
    assert rows["converted"].status == ScannerStatus.MISSING
    assert rows["converted"].exit_code == 0, (
        "nothing ran on the refused target, and its row reports exit code "
        f"{rows['converted'].exit_code}, the source run's"
    )


# The scanners that are not in the table: they run their tool once per template or
# lockfile, or run ASH's own worker.

_SCANNERS = f"{_MODULES}.ash_builtin.scanners"
OTHER_SCANNERS = {
    "cfn-nag": f"{_SCANNERS}.cfn_nag_scanner.CfnNagScanner",
    "npm-audit": f"{_SCANNERS}.npm_audit_scanner.NpmAuditScanner",
    "cdk-nag": f"{_SCANNERS}.cdk_nag_scanner.CdkNagScanner",
    "detect-secrets": f"{_SCANNERS}.detect_secrets_scanner.DetectSecretsScanner",
}


def _other_scanner(name: str, plugin_context):
    module, _, attribute = OTHER_SCANNERS[name].rpartition(".")
    return getattr(importlib.import_module(module), attribute)(context=plugin_context)


def _execute(plugin_context, monkeypatch, scanner, targets):
    monkeypatch.setattr(scanner, "validate_plugin_dependencies", lambda: True)
    executor = ScannerExecutor(
        plugin_context=plugin_context, progress_display=MagicMock(), scanner_tasks=[]
    )
    monkeypatch.setattr(executor, "_assess_content_databases", lambda *a, **k: None)
    rows = executor._execute_scanner(str(scanner.config.name), scanner, targets)
    return {row.target_type: row for row in rows}


def _two_targets(plugin_context):
    return [
        {"path": plugin_context.source_dir, "type": "source"},
        {"path": plugin_context.work_dir, "type": "converted"},
    ]


def _respond_by_target(scanner, responses):
    """A ``_run_subprocess`` stand-in that answers by the target being scanned.

    Every run of these scanners writes below ``results_dir/<target type>``. The code
    is recorded as the real method records it.
    """

    def run(command, results_dir=None, *args, **kwargs):
        target_type = Path(results_dir).relative_to(scanner.results_dir).parts[0]
        response = dict(responses[target_type])
        scanner._process_command_response(response)
        return response

    return run


CFN_TEMPLATE = """Resources:
  ExampleQueue:
    Type: AWS::SQS::Queue
    Properties:
      QueueName: example-queue
"""


def _cfn_nag_sarif(results) -> str:
    return json.dumps(
        {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "cfn_nag", "rules": [{"id": "W48"}]}},
                    "results": results,
                }
            ],
        }
    )


def test_cfn_nag_grades_the_converted_target_on_its_own_runs(
    plugin_context, monkeypatch
):
    """cfn_nag exits with its count of failing violations: 1 on source, 0 converted."""
    (plugin_context.source_dir / "queue.yaml").write_text(CFN_TEMPLATE)
    (plugin_context.work_dir / "queue.yaml").write_text(CFN_TEMPLATE)
    scanner = _other_scanner("cfn-nag", plugin_context)
    finding = {
        "ruleId": "W48",
        "level": "warning",
        "message": {"text": "example finding"},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": "queue.yaml"},
                    "region": {"startLine": 3},
                }
            }
        ],
    }
    responses = {
        "source": {"stdout": _cfn_nag_sarif([finding]), "stderr": "", "returncode": 1},
        "converted": {"stdout": _cfn_nag_sarif([]), "stderr": "", "returncode": 0},
    }
    monkeypatch.setattr(
        scanner, "_run_subprocess", _respond_by_target(scanner, responses)
    )

    rows = _execute(plugin_context, monkeypatch, scanner, _two_targets(plugin_context))

    assert rows["source"].exit_code == 1
    converted = rows["converted"]
    assert converted.exit_code == 0, (
        f"cfn_nag exited 0 on the converted template, and the row reports "
        f"{converted.exit_code}, the source run's"
    )
    (invocation,) = converted.raw_results.runs[0].invocations
    assert invocation.exitCode == 0
    assert invocation.executionSuccessful is True


def _npm_project(root: Path) -> None:
    (root / "package.json").write_text(
        json.dumps({"name": "example-app", "version": "1.0.0"})
    )
    (root / "package-lock.json").write_text(
        json.dumps({"name": "example-app", "lockfileVersion": 3})
    )


NPM_AUDIT_WITH_ONE_ADVISORY = {
    "auditReportVersion": 2,
    "vulnerabilities": {
        "unlisted_pkg": {
            "name": "unlisted_pkg",
            "severity": "moderate",
            "isDirect": True,
            "via": [
                {
                    "source": 1,
                    "name": "unlisted_pkg",
                    "dependency": "unlisted_pkg",
                    "title": "Example advisory",
                    "url": "https://allowed.example/advisories/1",
                    "severity": "moderate",
                    "range": "<1.0.1",
                }
            ],
            "effects": [],
            "range": "<1.0.1",
            "nodes": ["node_modules/unlisted_pkg"],
            "fixAvailable": True,
        }
    },
}
NPM_AUDIT_WITH_NONE = {"auditReportVersion": 2, "vulnerabilities": {}}


def test_npm_audit_grades_the_converted_target_on_its_own_runs(
    plugin_context, monkeypatch
):
    """npm audit exits 1 with an advisory on source and 0 with none on converted."""
    _npm_project(plugin_context.source_dir)
    _npm_project(plugin_context.work_dir)
    scanner = _other_scanner("npm-audit", plugin_context)
    responses = {
        "source": {
            "stdout": json.dumps(NPM_AUDIT_WITH_ONE_ADVISORY),
            "stderr": "",
            "returncode": 1,
        },
        "converted": {
            "stdout": json.dumps(NPM_AUDIT_WITH_NONE),
            "stderr": "",
            "returncode": 0,
        },
    }
    monkeypatch.setattr(
        scanner, "_run_subprocess", _respond_by_target(scanner, responses)
    )

    rows = _execute(plugin_context, monkeypatch, scanner, _two_targets(plugin_context))

    assert rows["source"].exit_code == 1
    assert rows["source"].finding_count == 1
    converted = rows["converted"]
    assert converted.exit_code == 0, (
        f"npm audit exited 0 on the converted lockfile, and the row reports "
        f"{converted.exit_code}, the source run's"
    )
    (invocation,) = converted.raw_results.runs[0].invocations
    assert invocation.exitCode == 0


@pytest.mark.parametrize("name", sorted(OTHER_SCANNERS))
def test_an_exit_code_held_from_an_earlier_target_is_not_reported_for_an_empty_one(
    plugin_context, monkeypatch, name
):
    """The instance holds 2 from an earlier target; this target's tree is empty.

    cdk-nag and detect-secrets run ASH's own worker and never record a tool's code,
    so the code is set on the instance here, as an earlier target's runs leave it.
    """
    scanner = _other_scanner(name, plugin_context)
    scanner.exit_code = 2

    rows = _execute(
        plugin_context,
        monkeypatch,
        scanner,
        [{"path": plugin_context.work_dir, "type": "converted"}],
    )

    row = rows["converted"]
    assert row.exit_code == 0, (
        f"{name} ran nothing on the empty tree, and its row reports exit code "
        f"{row.exit_code}"
    )
    assert row.status != ScannerStatus.ERROR, row.errors
