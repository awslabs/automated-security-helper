# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""npm-audit must read yarn's audit output and report yarn audit failures.

Before this, a yarn.lock project always came out clean. yarn 1 writes NDJSON,
which ``json.loads`` rejects, so a real report became "no output" and passed.
yarn 2 and later have no ``yarn audit`` at all, so the scanner ran a command
that printed a usage error and exited 1, and that passed too. A failed request
was never reported, because yarn had no report key for ``_audit_failure`` to
look for.

The payloads in tests/test_data/scanners/npmaudit/yarn are real output, with
the command, exit code, stdout and stderr each produced:

- yarn 1.22.22 (``yarn audit --json``) and yarn 4.18.1, the ``yarn@stable``
  the image prepares (``yarn npm audit --json --recursive``), plus yarn 3.8.7,
  whose ``yarn npm audit --json`` prints one npm v1 document instead.
- A project depending on lodash 4.17.20 and mkdirp 0.5.1 (which pulls in
  minimist 0.0.8) for the findings, and on is-number 7.0.0 for the clean case.
- Endpoint failures: yarn 1 sends its audit to a hardcoded registry, so it was
  pointed through ``HTTPS_PROXY`` at a closed port, and at a proxy that
  terminated TLS and answered 500 (the Node warning about the disabled
  certificate check that setup caused is removed from stderr). yarn 4 was
  pointed at a closed port and at a server answering 500 through
  ``YARN_NPM_AUDIT_REGISTRY``.
- No lockfile, and yarn 1 with ``--offline``.

Corepack's cache path in the stack traces is rewritten to the image's.
"""

import json
import logging
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.enums import ScannerStatus
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.core.phases.scanner_executor import ScannerExecutor
from automated_security_helper.plugin_modules.ash_builtin.scanners import (
    npm_audit_scanner,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.npm_audit_scanner import (
    NpmAuditScanner,
    NpmAuditScannerConfig,
    NpmAuditScannerConfigOptions,
)

CAPTURES = (
    Path(__file__).resolve().parents[4] / "test_data" / "scanners" / "npmaudit" / "yarn"
)


def _capture(name):
    return json.loads((CAPTURES / f"{name}.json").read_text(encoding="utf-8"))


def _response(capture):
    return {
        "stdout": capture["stdout"],
        "stderr": capture["stderr"],
        "returncode": capture["returncode"],
    }


# The advisories each capture of the vulnerable project holds, as
# (rule id, package, installed version, SARIF level).
LODASH = [
    ("GHSA-35jh-r3h4-6jhm", "lodash", "4.17.20", "error"),
    ("GHSA-29mw-wpgm-hmr9", "lodash", "4.17.20", "warning"),
    ("GHSA-r5fr-rjxr-66jc", "lodash", "4.17.20", "error"),
    ("GHSA-f23m-r3pf-42rh", "lodash", "4.17.20", "warning"),
    ("GHSA-xxjr-mmjv-4gpg", "lodash", "4.17.20", "warning"),
]
MINIMIST = [
    ("GHSA-vh95-rmgr-6w4m", "minimist", "0.0.8", "warning"),
    ("GHSA-xvch-5gv4-984h", "minimist", "0.0.8", "error"),
]
ALL_FINDINGS = sorted(LODASH + MINIMIST)

# (capture, findings the scan must report)
REPORTS = [
    ("classic-vuln", ALL_FINDINGS),
    ("classic-clean", []),
    ("berry-vuln-recursive", ALL_FINDINGS),
    ("berry-clean", []),
    ("berry3-vuln", ALL_FINDINGS),
    ("berry3-clean", []),
]

# (capture, text the failure must carry)
FAILURES = [
    ("classic-closedport", "ECONNREFUSED"),
    ("classic-500", 'Request failed "500 Internal Server Error"'),
    ("berry-closedport", "ECONNREFUSED"),
    ("berry-500", "Response code 500"),
    ("berry-nolock", "doesn't seem to be present in your lockfile"),
]

EXPECTED_COMMAND = {
    1: ["yarn", "audit", "--json"],
    3: ["yarn", "npm", "audit", "--json", "--recursive"],
    4: ["yarn", "npm", "audit", "--json", "--recursive"],
}


@pytest.fixture
def plugin_context(tmp_path):
    context = PluginContext(
        source_dir=tmp_path / "src",
        output_dir=tmp_path / "out",
        work_dir=tmp_path / "work",
        config=get_default_config(),
    )
    for d in (context.source_dir, context.output_dir, context.work_dir):
        d.mkdir(parents=True)
    return context


@pytest.fixture(autouse=True)
def tools_on_path(monkeypatch, tmp_path):
    monkeypatch.setattr(
        npm_audit_scanner, "find_executable", lambda name: str(tmp_path / name)
    )


def _scanner(context, offline=False):
    return NpmAuditScanner(
        context=context,
        config=NpmAuditScannerConfig(
            options=NpmAuditScannerConfigOptions(offline=offline)
        ),
    )


def _project(root, lock_name="yarn.lock"):
    root.mkdir(parents=True, exist_ok=True)
    (root / "package.json").write_text(
        json.dumps({"name": "placeholder-app", "version": "1.0.0"}), encoding="utf-8"
    )
    if lock_name:
        (root / lock_name).write_text("# yarn lockfile v1\n", encoding="utf-8")
    return root


def _respond(yarn_version, *responses):
    """_run_subprocess side effect: `--version` answers with ``yarn_version``,
    every other command takes the next response. Commands are recorded."""
    queue = list(responses)
    commands = []

    def _side_effect(self, command, **kwargs):
        commands.append(list(command))
        if "--version" in command:
            return {"stdout": f"{yarn_version}\n", "stderr": "", "returncode": 0}
        response = queue.pop(0)
        if "returncode" in response:
            self._process_command_response(response)
        return response

    return _side_effect, commands


def _scan(context, capture, offline=False):
    scanner = _scanner(context, offline=offline)
    _project(context.work_dir)
    side_effect, commands = _respond(capture["yarn_version"], _response(capture))
    with patch.object(
        NpmAuditScanner, "_run_subprocess", autospec=True, side_effect=side_effect
    ):
        report = scanner.scan(target=context.work_dir, target_type="converted")
    return report, commands


def _findings(report):
    return sorted(
        (
            r.ruleId,
            r.properties.model_extra["package_name"],
            r.properties.model_extra["installed_version"],
            r.level,
        )
        for r in report.runs[0].results
    )


@pytest.mark.parametrize("name, expected", REPORTS, ids=[n for n, _ in REPORTS])
def test_yarn_reports_become_findings(plugin_context, name, expected):
    capture = _capture(name)

    report, commands = _scan(plugin_context, capture)

    assert _findings(report) == expected
    # The capture was produced by the command the scanner now runs.
    audit = [c for c in commands if "--version" not in c]
    major = int(capture["yarn_version"].split(".")[0])
    assert audit == [EXPECTED_COMMAND[major]] == [capture["command"]]


@pytest.mark.parametrize("name, reason", FAILURES, ids=[n for n, _ in FAILURES])
def test_a_failed_yarn_audit_raises_instead_of_reporting_clean(
    plugin_context, name, reason
):
    with pytest.raises(ScannerError) as excinfo:
        _scan(plugin_context, _capture(name))

    message = str(excinfo.value)
    assert "could not audit 1 lockfile(s)" in message, message
    assert "yarn.lock" in message, message
    assert reason in message, message
    assert "\x1b[" not in message, "terminal colour codes leaked into the reason"
    assert "    at " not in message, "a stack frame leaked into the reason"


def test_yarn_audit_on_yarn_4_is_a_usage_error_not_a_report():
    """What the scanner used to run on yarn 2+: `yarn audit` is not a command
    there, and its usage error must not read as a clean report."""
    capture = _capture("berry-legacycmd-vuln")
    assert capture["returncode"] == 1

    report, reason = NpmAuditScanner._parse_yarn_audit(4, _response(capture))

    assert report is None
    assert "Couldn't find a script named" in reason, reason


def test_yarn_1_without_a_lockfile_still_reports():
    """yarn 1 audits from package.json when there is no lockfile, and says so in
    an info event. That is a report, not a failure."""
    report, reason = NpmAuditScanner._parse_yarn_audit(
        1, _response(_capture("classic-nolock"))
    )

    assert reason is None
    assert {r["package"] for r in report["yarn_advisories"]} == {"lodash"}


def test_no_lockfile_runs_no_yarn(plugin_context):
    """Without a lockfile there is nothing to audit and no command is run, as for
    npm and pnpm."""
    scanner = _scanner(plugin_context)
    _project(plugin_context.work_dir, lock_name=None)
    side_effect, commands = _respond("1.22.22")
    with patch.object(
        NpmAuditScanner, "_run_subprocess", autospec=True, side_effect=side_effect
    ):
        report = scanner.scan(target=plugin_context.work_dir, target_type="converted")

    assert [c for c in commands if "audit" in c] == []
    assert report.runs[0].results == []


def test_yarn_findings_carry_the_npm_result_shape(plugin_context):
    report, _ = _scan(plugin_context, _capture("classic-vuln"))
    run = report.runs[0]

    (critical,) = [r for r in run.results if r.ruleId == "GHSA-xvch-5gv4-984h"]
    props = critical.properties.model_extra
    assert critical.level == "error"
    location = critical.locations[0].model_dump(by_alias=True, exclude_none=True)
    assert (
        location["physicalLocation"]["artifactLocation"]["uri"]
        == "node_modules/minimist/package.json"
    )
    assert props["package_name"] == "minimist"
    assert props["package_version"] == "0.0.8"
    assert props["severity"] == "critical"
    assert props["vulnerable_versions"] == "<0.2.4"
    assert props["patched_versions"] == ">=0.2.4"
    assert props["fix_available"] is True
    assert props["cwe"] == ["CWE-1321"]
    assert props["cvss"]["score"] == 9.8
    assert props["dependency_paths"] == ["mkdirp>minimist"]
    assert "package_path" not in props, "yarn does not say where a copy is installed"
    assert "Prototype Pollution in minimist" in critical.message.root.text

    rule = {r.id: r for r in run.tool.driver.rules}["GHSA-xvch-5gv4-984h"]
    assert rule.properties.model_extra["security_severity"] == 9.8
    assert "npm-audit" in rule.properties.tags
    assert run.properties.model_extra["metrics"]["critical"] == 1


def test_yarn_4_deprecations_are_not_findings(plugin_context):
    """yarn 4 lists deprecated packages in the advisory stream; mkdirp 0.5.1 is
    one. npm audit does not report deprecations and neither does this."""
    capture = _capture("berry-vuln-recursive")
    assert "mkdirp (deprecation)" in capture["stdout"]

    report, _ = _scan(plugin_context, capture)

    assert "mkdirp" not in {
        r.properties.model_extra["package_name"] for r in report.runs[0].results
    }
    rule = {r.id: r for r in report.runs[0].tool.driver.rules}["GHSA-xvch-5gv4-984h"]
    assert "security_severity" not in (rule.properties.model_extra or {}), (
        "yarn 4 gives no CVSS score, and a made-up one would move the severity"
    )


def test_a_version_yarn_cannot_report_is_a_failure(plugin_context):
    scanner = _scanner(plugin_context)
    _project(plugin_context.work_dir)

    def _side_effect(self, command, **kwargs):
        return {
            "stdout": "",
            "stderr": "Internal Error: Usage Error: corepack could not fetch yarn",
            "returncode": 1,
        }

    with patch.object(
        NpmAuditScanner, "_run_subprocess", autospec=True, side_effect=_side_effect
    ):
        with pytest.raises(ScannerError) as excinfo:
            scanner.scan(target=plugin_context.work_dir, target_type="converted")

    assert "could not tell which yarn version runs here" in str(excinfo.value)
    assert "corepack could not fetch yarn" in str(excinfo.value)


class TestOffline:
    """Offline keeps npm's behavior: an audit that cannot reach its advisory
    source is a warning naming the lockfile, not an error."""

    def test_yarn_1_offline_failure_is_a_warning(self, plugin_context, caplog):
        capture = _capture("classic-offline")
        with caplog.at_level(logging.WARNING):
            report, commands = _scan(plugin_context, capture, offline=True)

        assert [c for c in commands if "--version" not in c] == [capture["command"]]
        assert report.runs[0].results == []
        warnings = [r.message for r in caplog.records]
        assert any(
            "npm-audit (offline) could not audit 1 lockfile(s)" in m
            and "Can't make a request in offline mode" in m
            for m in warnings
        ), warnings

    def test_yarn_4_offline_is_not_run_and_is_a_warning(self, plugin_context, caplog):
        """`yarn npm audit` rejects --offline and always asks the registry."""
        with caplog.at_level(logging.WARNING):
            report, commands = _scan(
                plugin_context, _capture("berry-clean"), offline=True
            )

        assert [c for c in commands if "--version" not in c] == []
        assert report.runs[0].results == []
        assert any("no offline mode" in r.message for r in caplog.records)


class TestExecutorStatus:
    """What the operator sees for a yarn project."""

    def _execute(self, context, capture):
        executor = ScannerExecutor(
            plugin_context=context, progress_display=MagicMock(), scanner_tasks=[]
        )
        _project(context.source_dir)
        side_effect, _ = _respond(capture["yarn_version"], _response(capture))
        with patch.object(
            NpmAuditScanner, "_run_subprocess", autospec=True, side_effect=side_effect
        ):
            (container,) = executor._execute_scanner(
                "npm-audit",
                _scanner(context),
                [{"path": context.source_dir, "type": "source"}],
            )
        return container

    def test_a_failed_yarn_audit_is_reported_as_error(self, plugin_context):
        container = self._execute(plugin_context, _capture("berry-500"))

        assert container.status == ScannerStatus.ERROR
        assert "Response code 500" in container.raw_results["errors"][0]

    def test_a_clean_yarn_audit_is_reported_as_passed(self, plugin_context):
        container = self._execute(plugin_context, _capture("classic-clean"))

        assert container.status == ScannerStatus.PASSED

    def test_yarn_findings_reach_the_executor(self, plugin_context):
        container = self._execute(plugin_context, _capture("classic-vuln"))

        assert container.status != ScannerStatus.ERROR
        assert container.finding_count == len(ALL_FINDINGS)


@pytest.mark.parametrize(
    "output, major",
    [
        ("1.22.22\n", 1),
        ("4.18.1", 4),
        ("\x1b[33mwarning\x1b[0m something\n3.8.7\n", 3),
        ("", None),
        ("Usage Error: nope", None),
    ],
)
def test_yarn_major(output, major):
    assert NpmAuditScanner._yarn_major(output) == major
