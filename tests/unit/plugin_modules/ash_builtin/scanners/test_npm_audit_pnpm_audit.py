# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""npm-audit must turn pnpm's audit advisories into findings.

`pnpm audit --json` writes npm's v1 report: ``advisories`` keyed by id, plus
``metadata``. The SARIF conversion read only ``vulnerabilities``, the npm 7+
key, so a pnpm-lock.yaml project with real advisories converted to zero
findings and reported PASSED.

The payloads in tests/test_data/scanners/npmaudit/pnpm are real output, with
the command, exit code, stdout and stderr each produced, from pnpm 12.10.1:
the ``pnpm@latest`` that ``corepack prepare`` caches in the image, run on
Node 22.23.3 and corepack 0.36.0, the versions the image's NodeSource
``node_22.x`` channel installs.

- vuln: a project depending on lodash 4.17.20, lodash 4.17.11 (as the alias
  ``lodash-legacy``), minimist 1.2.5 and mkdirp 0.5.1, which pulls in
  minimist 0.0.8. Several lodash advisories match both installed versions,
  and minimist's GHSA-xvch-5gv4-984h comes back as two ids, one per range.
- clean: a project depending on is-number 7.0.0.
- closedport and 500: the vuln project with a project ``.npmrc`` pointing the
  registry at a closed port, and at a local server answering 500.

Lockfiles were made with ``pnpm install --lockfile-only --ignore-scripts``.
"""

import json
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
)

CAPTURES = (
    Path(__file__).resolve().parents[4] / "test_data" / "scanners" / "npmaudit" / "pnpm"
)

# The results the vuln capture must give, as
# (rule id, package, installed version, vulnerable range, SARIF level):
# one per advisory entry and installed version it lists under findings.
LODASH_BOTH = [
    ("GHSA-35jh-r3h4-6jhm", "<4.17.21", "error"),
    ("GHSA-29mw-wpgm-hmr9", ">=4.0.0 <4.17.21", "warning"),
    ("GHSA-r5fr-rjxr-66jc", ">=4.0.0 <=4.17.23", "error"),
    ("GHSA-f23m-r3pf-42rh", "<=4.17.23", "warning"),
    ("GHSA-xxjr-mmjv-4gpg", ">=4.0.0 <=4.17.22", "warning"),
]
VULN_FINDINGS = sorted(
    [
        (rule, "lodash", version, rng, level)
        for rule, rng, level in LODASH_BOTH
        for version in ("4.17.11", "4.17.20")
    ]
    + [
        ("GHSA-jf85-cpcp-j695", "lodash", "4.17.11", "<4.17.12", "error"),
        ("GHSA-p6mc-m468-83gw", "lodash", "4.17.11", ">=3.7.0 <4.17.19", "error"),
        ("GHSA-vh95-rmgr-6w4m", "minimist", "0.0.8", "<0.2.1", "warning"),
        ("GHSA-xvch-5gv4-984h", "minimist", "0.0.8", "<0.2.4", "error"),
        ("GHSA-xvch-5gv4-984h", "minimist", "1.2.5", ">=1.0.0 <1.2.6", "error"),
    ]
)

# (capture, text the failure must carry)
FAILURES = [
    ("closedport", "Failed to request the audit endpoint"),
    ("500", "responded with 500"),
]


def _capture(name):
    return json.loads((CAPTURES / f"{name}.json").read_text(encoding="utf-8"))


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


def _project(root):
    root.mkdir(parents=True, exist_ok=True)
    (root / "package.json").write_text(
        json.dumps({"name": "placeholder-app", "version": "1.0.0"}), encoding="utf-8"
    )
    (root / "pnpm-lock.yaml").write_text("lockfileVersion: '9.0'\n", encoding="utf-8")
    return root


def _replay(capture, commands):
    """_run_subprocess side effect that answers every audit with ``capture``."""

    def _side_effect(self, command, **kwargs):
        commands.append(list(command))
        if "--version" in command:
            return {"stdout": capture["pnpm_version"], "stderr": "", "returncode": 0}
        response = {
            "stdout": capture["stdout"],
            "stderr": capture["stderr"],
            "returncode": capture["returncode"],
        }
        self._process_command_response(response)
        return response

    return _side_effect


def _scan(context, capture):
    scanner = NpmAuditScanner(context=context, config=NpmAuditScannerConfig())
    _project(context.work_dir)
    commands = []
    with patch.object(
        NpmAuditScanner,
        "_run_subprocess",
        autospec=True,
        side_effect=_replay(capture, commands),
    ):
        report = scanner.scan(target=context.work_dir, target_type="converted")
    return report, commands


def _findings(report):
    return sorted(
        (
            r.ruleId,
            r.properties.model_extra["package_name"],
            r.properties.model_extra["installed_version"],
            r.properties.model_extra["vulnerable_versions"],
            r.level,
        )
        for r in report.runs[0].results
    )


def test_the_capture_is_the_command_the_scanner_runs(plugin_context):
    capture = _capture("vuln")

    _, commands = _scan(plugin_context, capture)

    assert [c for c in commands if "audit" in c] == [capture["command"]]


def test_pnpm_advisories_become_findings(plugin_context):
    report, _ = _scan(plugin_context, _capture("vuln"))

    assert _findings(report) == VULN_FINDINGS


def test_a_clean_pnpm_audit_has_no_findings(plugin_context):
    capture = _capture("clean")
    assert capture["returncode"] == 0

    report, _ = _scan(plugin_context, capture)

    assert report.runs[0].results == []
    assert report.runs[0].properties.model_extra["metrics"]["critical"] == 0


def test_pnpm_findings_carry_the_npm_result_shape(plugin_context):
    report, _ = _scan(plugin_context, _capture("vuln"))
    run = report.runs[0]

    (critical,) = [
        r
        for r in run.results
        if r.ruleId == "GHSA-xvch-5gv4-984h"
        and r.properties.model_extra["installed_version"] == "1.2.5"
    ]
    props = critical.properties.model_extra
    location = critical.locations[0].model_dump(by_alias=True, exclude_none=True)
    assert (
        location["physicalLocation"]["artifactLocation"]["uri"]
        == "node_modules/minimist/package.json"
    )
    assert props["package_name"] == "minimist"
    assert props["package_version"] == "1.2.5"
    assert props["severity"] == "critical"
    assert props["vulnerable_versions"] == ">=1.0.0 <1.2.6"
    assert props["patched_versions"] == ">=1.2.6"
    assert props["fix_available"] is True
    assert props["cwe"] == ["CWE-1321"]
    assert props["dependency_paths"] == [".>minimist"]
    assert "package_path" not in props, "pnpm does not say where a copy is installed"
    assert "Prototype Pollution in minimist" in critical.message.root.text

    rules = {r.id: r for r in run.tool.driver.rules}
    assert len(rules) == len({f[0] for f in VULN_FINDINGS})
    rule = rules["GHSA-xvch-5gv4-984h"]
    assert "npm-audit" in rule.properties.tags
    assert str(rule.helpUri) == "https://github.com/advisories/GHSA-xvch-5gv4-984h"
    assert "security_severity" not in (rule.properties.model_extra or {}), (
        "pnpm gives no CVSS score, and a made-up one would move the severity"
    )
    assert run.properties.model_extra["metrics"] == {
        "info": 0,
        "low": 0,
        "moderate": 4,
        "high": 3,
        "critical": 3,
    }


def test_a_range_split_advisory_keeps_each_range_through_the_yarn_merge():
    """yarn 2 and 3 print the same npm v1 document. Their per-package merge
    used to key on the advisory URL, so minimist 1.2.5 was reported under
    GHSA-xvch-5gv4-984h's other range, <0.2.4."""
    capture = _capture("vuln")

    report, reason = NpmAuditScanner._parse_yarn_audit(
        3, {"stdout": capture["stdout"], "stderr": "", "returncode": 1}
    )

    assert reason is None
    ranges = sorted(
        (version, r["vulnerable_versions"])
        for r in report["yarn_advisories"]
        if r["url"].endswith("GHSA-xvch-5gv4-984h")
        for version in r["versions"]
    )
    assert ranges == [("0.0.8", "<0.2.4"), ("1.2.5", ">=1.0.0 <1.2.6")]


@pytest.mark.parametrize("name, reason", FAILURES, ids=[n for n, _ in FAILURES])
def test_a_failed_pnpm_audit_raises_instead_of_reporting_clean(
    plugin_context, name, reason
):
    capture = _capture(name)
    assert capture["stdout"] == "", "pnpm writes nothing to stdout when it fails"

    with pytest.raises(ScannerError) as excinfo:
        _scan(plugin_context, capture)

    message = str(excinfo.value)
    assert "could not audit 1 lockfile(s)" in message, message
    assert "pnpm-lock.yaml" in message, message
    assert "ERR_PNPM_AUDIT_BAD_RESPONSE" in message, message
    assert reason in message, message
    assert "\x1b[" not in message, "terminal color codes leaked into the reason"


def test_two_pnpm_lockfiles_keep_both_reports(plugin_context):
    """Each lockfile converts on its own, and results.json keeps every
    lockfile's advisories, not only the first one's."""
    scanner = NpmAuditScanner(context=plugin_context, config=NpmAuditScannerConfig())
    _project(plugin_context.work_dir / "a")
    _project(plugin_context.work_dir / "b")
    commands = []
    with patch.object(
        NpmAuditScanner,
        "_run_subprocess",
        autospec=True,
        side_effect=_replay(_capture("vuln"), commands),
    ):
        report = scanner.scan(target=plugin_context.work_dir, target_type="converted")

    assert len([c for c in commands if "audit" in c]) == 2
    assert len(report.runs[0].results) == 2 * len(VULN_FINDINGS)
    saved = json.loads(
        scanner.results_dir.joinpath("converted", "results.json").read_text()
    )
    assert len(saved["advisories"]) == 10


class TestExecutorStatus:
    """What the operator sees for a pnpm project."""

    def _execute(self, context, capture):
        executor = ScannerExecutor(
            plugin_context=context, progress_display=MagicMock(), scanner_tasks=[]
        )
        _project(context.source_dir)
        commands = []
        with patch.object(
            NpmAuditScanner,
            "_run_subprocess",
            autospec=True,
            side_effect=_replay(capture, commands),
        ):
            (container,) = executor._execute_scanner(
                "npm-audit",
                NpmAuditScanner(context=context, config=NpmAuditScannerConfig()),
                [{"path": context.source_dir, "type": "source"}],
            )
        return container

    def test_pnpm_findings_reach_the_executor(self, plugin_context):
        container = self._execute(plugin_context, _capture("vuln"))

        # PASSED or FAILED against the severity threshold is decided later,
        # in unified_metrics; here the scan ran and carried its findings.
        assert container.status != ScannerStatus.ERROR
        assert container.finding_count == len(VULN_FINDINGS)

    def test_a_clean_pnpm_audit_is_reported_as_passed(self, plugin_context):
        container = self._execute(plugin_context, _capture("clean"))

        assert container.status == ScannerStatus.PASSED

    def test_a_failed_pnpm_audit_is_reported_as_error(self, plugin_context):
        container = self._execute(plugin_context, _capture("500"))

        assert container.status == ScannerStatus.ERROR
        assert "responded with 500" in container.raw_results["errors"][0]
