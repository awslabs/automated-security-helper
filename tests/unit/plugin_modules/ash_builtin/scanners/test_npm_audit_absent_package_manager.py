"""A lockfile whose package manager is absent costs that lockfile, not the others.

npm-audit audits every package.json that has a lockfile beside it, each with its own
tool: npm for package-lock.json and npm-shrinkwrap.json, yarn for yarn.lock, pnpm
for pnpm-lock.yaml. When yarn or pnpm is not installed that lockfile cannot be
audited, and it is a failed target.

The findings of the audited lockfiles are kept and graded (with
``api/package-lock.json`` carrying one HIGH and ``web/yarn.lock`` with no yarn, the
row keeps the HIGH), the partial-coverage arm of the completeness gate lists the
scanner ("1 of 2 targets unevaluated") and the scan exits 1, and a scanner whose
every lockfile went unaudited is ERROR.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.enums import ScannerStatus
from automated_security_helper.core.phases.scan_result_processor import (
    ScanResultProcessor,
)
from automated_security_helper.core.phases.scanner_executor import ScannerExecutor
from automated_security_helper.core.unified_metrics import (
    populate_metrics_from_unified_source,
)
from automated_security_helper.interactions.run_ash_scan import incomplete_scanners
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.plugin_modules.ash_builtin.scanners import (
    npm_audit_scanner,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.npm_audit_scanner import (
    NpmAuditScanner,
)

pytestmark = pytest.mark.unit

AshConfig.model_rebuild()
AshAggregatedResults.model_rebuild()

HIGH_AUDIT = {
    "vulnerabilities": {
        "left-pad": {
            "name": "left-pad",
            "severity": "high",
            "range": "<1.3.0",
            "nodes": ["node_modules/left-pad"],
            "fixAvailable": True,
            "via": [
                {
                    "source": 1234,
                    "name": "left-pad",
                    "title": "Prototype pollution",
                    "url": "https://github.com/advisories/GHSA-aaaa-bbbb-cccc",
                    "severity": "high",
                    "cwe": ["CWE-1321"],
                    "range": "<1.3.0",
                }
            ],
        }
    },
    "metadata": {"vulnerabilities": {"high": 1, "total": 1}},
}


@pytest.fixture
def context(tmp_path, monkeypatch):
    monkeypatch.delenv("ASH_OFFLINE", raising=False)
    source = tmp_path / "source"
    source.mkdir()
    output = tmp_path / "output"
    output.mkdir()
    return PluginContext(
        source_dir=source,
        output_dir=output,
        work_dir=output / "converted",
        config=get_default_config(),
    )


def _package(root: Path, lock_name: str) -> None:
    root.mkdir(parents=True, exist_ok=True)
    (root / "package.json").write_text('{"name": "app"}\n', encoding="utf-8")
    (root / lock_name).write_text(
        json.dumps({"name": "app", "lockfileVersion": 3}), encoding="utf-8"
    )


def _without(binary: str):
    return lambda name: None if name == binary else f"/usr/bin/{name}"


def _respond(self, command, **kwargs):
    """The tool's answer, recorded the way the real ``_run_subprocess`` records it."""
    if "--version" in command:
        response = {"stdout": "10.9.4", "stderr": "", "returncode": 0}
    else:
        response = {"stdout": json.dumps(HIGH_AUDIT), "stderr": "", "returncode": 1}
    self._process_command_response(response)
    return response


def _run(context):
    """The executor and the result processor over the scanner, then the rebuild."""
    scanner = NpmAuditScanner(context=context)
    aggregated = AshAggregatedResults()
    aggregated.ash_config = context.config
    executor = ScannerExecutor(
        plugin_context=context,
        progress_display=MagicMock(),
        scanner_tasks=[
            (
                "npm-audit",
                scanner,
                [{"path": Path(context.source_dir), "type": "source"}],
            )
        ],
        process_results_fn=ScanResultProcessor(
            plugin_context=context
        ).process_container,
    )
    with patch.object(
        NpmAuditScanner, "_run_subprocess", autospec=True, side_effect=_respond
    ) as spawn:
        aggregated = executor.run_sequential(aggregated)
    results = populate_metrics_from_unified_source(aggregated_results=aggregated)
    started = [
        call.kwargs.get("command", [None])[0]
        for call in spawn.call_args_list
        if "audit" in call.kwargs.get("command", [])
    ]
    return results, started


def test_the_audited_lockfiles_findings_survive(context, monkeypatch):
    _package(context.source_dir / "api", "package-lock.json")
    _package(context.source_dir / "web", "yarn.lock")
    monkeypatch.setattr(npm_audit_scanner, "find_executable", _without("yarn"))

    results, started = _run(context)

    assert started == ["npm"], f"yarn must not be started: {started}"
    row = results.scanner_results["npm-audit"]
    assert row.exit_code == 1, f"npm audit exits 1 when it finds something: {row!r}"
    assert row.finding_count == 1, (
        "the HIGH from api/package-lock.json was dropped because web/yarn.lock "
        f"could not be audited: {row!r}"
    )
    # On a partial loss the severity gate runs first: the audited lockfile's
    # HIGH fails it, so the run grades FAILED, the status consumers gate on
    # (earlier revisions pinned FAILED via fall-through, then the fail-closed
    # ERROR). The unaudited lockfile still reaches the incomplete-scan gate
    # through the counts, whatever the status.
    assert row.status == ScannerStatus.FAILED, row
    report = results.additional_reports["npm-audit"]["source"]
    assert (report["targets_attempted"], report["targets_failed"]) == (2, 1), report
    assert ("npm-audit", "FAILED (1 of 2 targets unevaluated)") in (
        incomplete_scanners(results)
    ), incomplete_scanners(results)


@pytest.mark.parametrize(
    "lock_name,binary", [("yarn.lock", "yarn"), ("pnpm-lock.yaml", "pnpm")]
)
def test_every_lockfile_unaudited_is_an_error(context, monkeypatch, lock_name, binary):
    _package(context.source_dir, lock_name)
    monkeypatch.setattr(npm_audit_scanner, "find_executable", _without(binary))

    results, started = _run(context)

    assert started == []
    row = results.scanner_results["npm-audit"]
    assert row.status == ScannerStatus.ERROR
    assert ("npm-audit", "ERROR") in incomplete_scanners(results)
    assert row.exit_code is None, f"{binary} never started, so no exit code: {row!r}"
    for target, report in results.additional_reports["npm-audit"].items():
        assert report.get("exit_code") is None, (target, report)


def test_the_unaudited_lockfile_is_named(context, monkeypatch):
    _package(context.source_dir / "web", "yarn.lock")
    monkeypatch.setattr(npm_audit_scanner, "find_executable", _without("yarn"))
    scanner = NpmAuditScanner(context=context)

    with patch.object(NpmAuditScanner, "_run_subprocess", autospec=True) as spawn:
        spawn.side_effect = _respond
        report = scanner.scan(target=context.source_dir, target_type="source")

    assert any(
        "yarn is not installed" in error and "yarn.lock" in error
        for error in scanner.errors
    ), scanner.errors
    # No audit ran, so the SARIF invocation has no exit code. The one
    # discovered lockfile went unaudited and the row grades ERROR over its
    # recorded name, so the invocation does not claim success either.
    (invocation,) = report.runs[0].invocations
    assert invocation.exitCode is None, invocation
    assert invocation.executionSuccessful is False, invocation


def test_an_audit_that_failed_raises_naming_the_lockfile(context, monkeypatch):
    """scan() raises once every lockfile is tried; the executor records ERROR.

    npm writes an error document and exits 1 when the audit endpoint fails, the
    same exit code as "vulnerabilities found".
    """
    from automated_security_helper.core.exceptions import ScannerError

    _package(context.source_dir, "package-lock.json")
    monkeypatch.setattr(npm_audit_scanner, "find_executable", _without("none"))
    scanner = NpmAuditScanner(context=context)

    def endpoint_error(self, command, **kwargs):
        if "--version" in command:
            return {"stdout": "10.9.4", "stderr": "", "returncode": 0}
        body = {"message": "request failed", "error": {"code": "E500"}}
        response = {"stdout": json.dumps(body), "stderr": "", "returncode": 1}
        self._process_command_response(response)
        return response

    with (
        patch.object(
            NpmAuditScanner,
            "_run_subprocess",
            autospec=True,
            side_effect=endpoint_error,
        ),
        pytest.raises(ScannerError, match=r"could not audit 1 lockfile") as raised,
    ):
        scanner.scan(target=context.source_dir, target_type="source")

    assert "package-lock.json" in str(raised.value)
    assert "E500" in str(raised.value)


def test_offline_past_the_dependency_check_yarn_2_is_not_run(context, monkeypatch):
    """The offline skip in scan() serves a caller that skips the dependency check.

    A scan never reaches it: validate_plugin_dependencies refuses offline first.
    A caller that bypasses the check gets the same outcome: the offline branch skips
    before any yarn runs, records the lockfile as not audited and returns False,
    rather than a clean report.
    """
    monkeypatch.setenv("ASH_OFFLINE", "true")
    _package(context.source_dir, "yarn.lock")
    monkeypatch.setattr(npm_audit_scanner, "find_executable", _without("none"))
    scanner = NpmAuditScanner(context=context)
    scanner.dependencies_satisfied = True

    def yarn_four(self, command, **kwargs):
        if "--version" in command:
            return {"stdout": "4.1.0", "stderr": "", "returncode": 0}
        raise AssertionError(f"no audit may run offline: {command}")

    with (
        patch.object(scanner, "_pre_scan", return_value=True),
        patch.object(
            NpmAuditScanner, "_run_subprocess", autospec=True, side_effect=yarn_four
        ),
    ):
        result = scanner.scan(target=context.source_dir, target_type="source")

    # Offline no audit runs: the lockfile is recorded as not audited and scan()
    # returns False, which the executor records MISSING (npm_audit_scanner.py,
    # scan() before the lockfile loop; _skip_offline), not a clean report.
    assert result is False
    assert [entry["path"] for entry in scanner.inputs_not_scanned] == ["yarn.lock"]


@pytest.mark.parametrize("tree", ["empty", "no-lockfile"])
def test_a_scan_that_audits_nothing_reports_no_exit_code(context, monkeypatch, tree):
    """The report scan() builds before any audit runs, returned when none does."""
    if tree == "no-lockfile":
        (context.source_dir / "package.json").write_text('{"name": "app"}\n')
    monkeypatch.setattr(npm_audit_scanner, "find_executable", _without("none"))
    scanner = NpmAuditScanner(context=context)

    with patch.object(
        NpmAuditScanner, "_run_subprocess", autospec=True, side_effect=_respond
    ) as spawn:
        report = scanner.scan(target=context.source_dir, target_type="source")

    assert not [
        c for c in spawn.call_args_list if "audit" in c.kwargs.get("command", [])
    ]
    (invocation,) = report.runs[0].invocations
    assert invocation.exitCode is None, invocation
    assert invocation.executionSuccessful is True, invocation


@pytest.fixture
def markup_console():
    """ASH_LOGGER through a markup-enabled RichHandler, as setup_logging builds it.

    That handler is on in CI, under --no-progress and under --verbose. Rich reads
    a bracketed span starting with "/" as a closing tag and raises MarkupError out
    of the logging call.
    """
    import io
    import logging

    from rich.console import Console
    from rich.logging import RichHandler

    from automated_security_helper.utils.log import ASH_LOGGER

    buffer = io.StringIO()
    handler = RichHandler(
        console=Console(file=buffer, width=250, color_system=None),
        markup=True,
        show_time=False,
        show_path=False,
    )
    saved_handlers, saved_level = list(ASH_LOGGER.handlers), ASH_LOGGER.level
    ASH_LOGGER.handlers = [handler]
    ASH_LOGGER.setLevel(logging.DEBUG)
    try:
        yield buffer
    finally:
        ASH_LOGGER.handlers = saved_handlers
        ASH_LOGGER.setLevel(saved_level)


def test_a_bracketed_directory_name_does_not_crash_the_scan(
    context, monkeypatch, markup_console
):
    _package(context.source_dir / "api", "package-lock.json")
    _package(context.source_dir / "pkgs" / "[/x]", "yarn.lock")
    monkeypatch.setattr(npm_audit_scanner, "find_executable", _without("yarn"))

    results, started = _run(context)

    row = results.scanner_results["npm-audit"]
    # FAILED: the audited lockfile's finding fails the severity gate, which
    # runs first on a partial loss. The cell's point is above either status:
    # the scan did not crash, and the finding survived.
    assert row.status == ScannerStatus.FAILED, row
    assert row.finding_count == 1, row
    # The refusal line names the lockfile with the platform's separator, so the
    # expected text is built from the path's parts: "[/x]/yarn.lock" where the
    # separator is a slash (the Rich closing-tag shape this test is named for),
    # a backslash-joined path on Windows, where no such tag can arise.
    assert str(Path("[") / "x]" / "yarn.lock") in markup_console.getvalue()


def test_an_audit_naming_a_bracketed_path_keeps_its_findings(
    context, monkeypatch, markup_console
):
    """npm-audit used to log each audit's result dict, stdout included, at INFO.

    A successful audit whose JSON names "pkgs/[/x]/node_modules/left-pad" raised
    MarkupError out of that log call; the scanner caught it as "the audit raised",
    and that lockfile's findings were discarded (scan() raised ScannerError). The
    raw response is no longer logged (a one-line redacted summary is, at DEBUG),
    so the bracketed path reaches the console only through the lockfile list,
    and the finding keeps the path in its properties.

    scan() is called directly. Through the executor the result processor's
    suppression matcher logs the finding's path with markup on too, which is the
    sink-level fix's to handle, not npm-audit's.
    """
    _package(context.source_dir / "pkgs" / "[/x]", "package-lock.json")
    monkeypatch.setattr(npm_audit_scanner, "find_executable", _without("none"))
    audit = json.loads(json.dumps(HIGH_AUDIT))
    audit["vulnerabilities"]["left-pad"]["nodes"] = ["pkgs/[/x]/node_modules/left-pad"]
    scanner = NpmAuditScanner(context=context)

    def respond(self, command, **kwargs):
        if "--version" in command:
            return {"stdout": "10.9.4", "stderr": "", "returncode": 0}
        response = {"stdout": json.dumps(audit), "stderr": "", "returncode": 1}
        self._process_command_response(response)
        return response

    import logging

    from automated_security_helper.utils.log import ASH_LOGGER

    class _Messages(logging.Handler):
        """What a file handler writes: the message, not Rich's rendering of it."""

        def __init__(self):
            super().__init__(level=logging.DEBUG)
            self.messages: list[str] = []

        def emit(self, record):
            self.messages.append(record.getMessage())

    file_log = _Messages()
    ASH_LOGGER.addHandler(file_log)
    try:
        with patch.object(
            NpmAuditScanner, "_run_subprocess", autospec=True, side_effect=respond
        ):
            report = scanner.scan(target=context.source_dir, target_type="source")
    finally:
        ASH_LOGGER.removeHandler(file_log)

    (result,) = report.runs[0].results
    assert (scanner.targets_attempted, scanner.targets_failed) == (1, 0)
    assert "pkgs/[/x]/node_modules/left-pad" in result.model_dump_json()
    # The console shows the package's path with its brackets intact.
    console = markup_console.getvalue()
    assert "pkgs/[/x]/package.json" in console
    # The lockfile list reaches ash.log as the paths are, not escaped for Rich.
    (listed,) = [m for m in file_log.messages if "package locks" in m]
    assert "pkgs/[/x]/package.json" in listed and "\\[" not in listed, listed
    # The raw response stays out of both sinks: neither its node path nor a key
    # of the audit document is on the console or in ash.log. A stdout dump put
    # back with markup off would not crash, so the absences are asserted.
    assert "node_modules/left-pad" not in console, console
    assert '"fixAvailable"' not in console, console
    assert not any("node_modules/left-pad" in m for m in file_log.messages)
    assert not any('"fixAvailable"' in m for m in file_log.messages)


@pytest.mark.parametrize(
    "failure,logged",
    [
        pytest.param(
            "not json", "Failed to parse npm audit output for", id="unparseable"
        ),
        pytest.param(
            OSError("spawn failed"), "Failed to run npm audit in", id="raised"
        ),
    ],
)
def test_an_audit_that_fails_in_a_bracketed_directory_is_logged_as_data(
    context, monkeypatch, markup_console, failure, logged
):
    """The two warnings for an audit that produced no report name the directory.

    scan() is called directly: it raises ScannerError naming the lockfile, and the
    executor's own handling of that error is outside npm-audit.
    """
    from automated_security_helper.core.exceptions import ScannerError

    _package(context.source_dir / "pkgs" / "[/x]", "package-lock.json")
    monkeypatch.setattr(npm_audit_scanner, "find_executable", _without("none"))
    scanner = NpmAuditScanner(context=context)

    def respond(self, command, **kwargs):
        if "--version" in command:
            return {"stdout": "10.9.4", "stderr": "", "returncode": 0}
        if isinstance(failure, Exception):
            raise failure
        response = {"stdout": failure, "stderr": "", "returncode": 1}
        self._process_command_response(response)
        return response

    with (
        patch.object(
            NpmAuditScanner, "_run_subprocess", autospec=True, side_effect=respond
        ),
        pytest.raises(ScannerError, match=r"could not audit 1 lockfile"),
    ):
        scanner.scan(target=context.source_dir, target_type="source")

    console = markup_console.getvalue()
    assert logged in console, console
    assert "pkgs/[/x]" in console, console


def test_partial_audit_marks_the_sarif_invocation_unsuccessful(context, monkeypatch):
    """One lockfile audited, one with no runnable package manager: the row
    grades FAILED (the audited lockfile's finding fails the gate, which runs
    first on a partial loss), and every npm-audit invocation in the
    aggregated SARIF still says the execution did not succeed. The two answer
    different questions -- the status grades the findings, the flag records
    that a lockfile was never audited -- so FAILED beside False is the
    coherent pair, not a disagreement."""
    _package(context.source_dir / "api", "package-lock.json")
    _package(context.source_dir / "web", "yarn.lock")
    monkeypatch.setattr(npm_audit_scanner, "find_executable", _without("yarn"))

    results, _ = _run(context)

    row = results.scanner_results["npm-audit"]
    assert row.status == ScannerStatus.FAILED, row
    invocations = [
        inv
        for run in results.sarif.runs or []
        for inv in run.invocations or []
        if getattr(inv, "commandLine", None) == "npm audit --json"
    ]
    assert invocations, "no npm-audit invocation reached the aggregated SARIF"
    assert all(inv.executionSuccessful is False for inv in invocations), [
        inv.executionSuccessful for inv in invocations
    ]
