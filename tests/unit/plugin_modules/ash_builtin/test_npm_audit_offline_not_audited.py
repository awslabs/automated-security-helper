"""Offline, npm-audit audits nothing, so it says so instead of passing.

``npm audit`` has to ask the registry's advisory service which dependencies are
vulnerable; nothing is cached for it. Offline, ``npm audit --json --offline`` on a
lockfile pinning lodash 4.17.20 (known advisories) exited 0 with no advisories,
``pnpm audit --offline`` sent the dependency list to the registry anyway, and
``yarn npm audit`` has no offline mode. npm-audit was graded PASSED with zero
findings, and the only trace was a log line.

Offline, npm-audit now runs no audit. Every lockfile it would have audited is recorded
as not scanned, with the reason, in the scanner's results and in the summary. When there
is a lockfile the scanner is MISSING, as snyk-code is offline, so the scan fails under the
default completeness gate; ``--exclude-scanners npm-audit`` is the opt-out. A project
with no lockfile has nothing the network would have audited, and is not MISSING.
"""

import json
from pathlib import Path
from typing import List

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.enums import ExecutionStrategy
from automated_security_helper.plugin_modules.ash_builtin.scanners import (
    npm_audit_scanner as npm_audit_module,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.npm_audit_scanner import (
    NpmAuditScanner,
    NpmAuditScannerConfig,
)
from tests.utils.refusing_proxy import scrub_cloud_credentials

#: What `npm audit --json --offline` printed for a lockfile with known advisories.
OFFLINE_NPM_AUDIT_OUTPUT = json.dumps(
    {
        "auditReportVersion": 2,
        "vulnerabilities": {},
        "metadata": {
            "vulnerabilities": {
                "info": 0,
                "low": 0,
                "moderate": 0,
                "high": 0,
                "critical": 0,
                "total": 0,
            }
        },
    }
)

LOCKFILES = {
    "web": "package-lock.json",
    "app": "pnpm-lock.yaml",
    "tools": "yarn.lock",
}


def _projects(source: Path, only: str | None = None) -> List[str]:
    chosen = {only: LOCKFILES[only]} if only else LOCKFILES
    for project, lock in chosen.items():
        directory = source / project
        directory.mkdir(parents=True)
        (directory / "package.json").write_text(
            json.dumps({"name": project, "version": "1.0.0"})
        )
        (directory / lock).write_text("{}" if lock.endswith(".json") else "")
    return sorted(f"{project}/{lock}" for project, lock in chosen.items())


@pytest.fixture
def offline(monkeypatch):
    scrub_cloud_credentials(monkeypatch)
    monkeypatch.setenv("ASH_OFFLINE", "YES")
    return monkeypatch


@pytest.fixture
def online(monkeypatch):
    scrub_cloud_credentials(monkeypatch)
    monkeypatch.delenv("ASH_OFFLINE", raising=False)
    return monkeypatch


@pytest.fixture
def spawns(monkeypatch):
    """Every command npm-audit starts; each answers as offline npm audit does."""
    started = []

    def fake_run(self, command, **kwargs):
        started.append([str(part) for part in command])
        if "--version" in command:
            return {"stdout": "1.22.22\n", "returncode": 0}
        return {"stdout": OFFLINE_NPM_AUDIT_OUTPUT, "returncode": 0}

    monkeypatch.setattr(NpmAuditScanner, "_run_subprocess", fake_run)
    monkeypatch.setattr(
        NpmAuditScanner, "validate_plugin_dependencies", lambda self: True
    )
    monkeypatch.setattr(
        npm_audit_module, "find_executable", lambda name: f"/usr/local/bin/{name}"
    )
    return started


def _scanner(tmp_path: Path) -> NpmAuditScanner:
    context = PluginContext(
        source_dir=tmp_path / "repo",
        output_dir=tmp_path / "out",
        work_dir=tmp_path / "out" / "converted",
        config=get_default_config(),
    )
    for directory in (context.source_dir, context.output_dir, context.work_dir):
        directory.mkdir(parents=True, exist_ok=True)
    scanner = NpmAuditScanner(context=context, config=NpmAuditScannerConfig())
    scanner.dependencies_satisfied = True
    return scanner


def test_offline_npm_audit_starts_no_audit_and_records_every_lockfile(
    offline, spawns, tmp_path
):
    scanner = _scanner(tmp_path)
    expected = _projects(scanner.context.source_dir)

    result = scanner.scan(target=scanner.context.source_dir, target_type="source")

    audits = [command for command in spawns if "audit" in command]
    assert audits == [], f"offline npm-audit ran an audit that audits nothing: {audits}"
    recorded = getattr(scanner, "inputs_not_scanned", None) or []
    assert sorted(entry["path"] for entry in recorded) == expected, recorded
    assert all(entry["reason"] for entry in recorded), recorded
    # False is what the executor records MISSING (scanner_executor, "plugin is
    # missing dependencies"): the dependency is the registry's advisory service.
    assert result is False, f"offline npm-audit with lockfiles returned {result!r}"


def test_offline_npm_audit_without_a_lockfile_is_not_missing(offline, spawns, tmp_path):
    """No lockfile, nothing the network would have audited: online audits nothing
    here too. MISSING for it would fail every offline scan of such a repository."""
    scanner = _scanner(tmp_path)
    project = scanner.context.source_dir / "web"
    project.mkdir()
    (project / "package.json").write_text(json.dumps({"name": "web"}))

    result = scanner.scan(target=scanner.context.source_dir, target_type="source")

    assert result is not False
    assert not getattr(scanner, "inputs_not_scanned", None)
    assert [c for c in spawns if "audit" in c] == []
    assert scanner.targets_attempted == 0  # evaluated nothing: SKIPPED


def test_control_online_npm_audit_audits_the_lockfile(online, spawns, tmp_path):
    scanner = _scanner(tmp_path)
    _projects(scanner.context.source_dir, only="web")

    scanner.scan(target=scanner.context.source_dir, target_type="source")

    assert [c for c in spawns if "audit" in c], spawns
    assert not getattr(scanner, "inputs_not_scanned", None)


def test_a_second_target_reports_only_its_own_inputs(offline, spawns, tmp_path):
    """One scanner instance scans the source, then the converted tree.

    The executor reads inputs_not_scanned and targets_attempted after each target,
    so scan() resets both first. Without that, the converted target, which has no
    package.json, carried the source's lockfile: the summaries listed it twice and
    the converted container claimed an input it never had.
    """
    scanner = _scanner(tmp_path)
    _projects(scanner.context.source_dir, only="web")
    (scanner.context.work_dir / "nb.py").write_text("print(1)\n")

    assert (
        scanner.scan(target=scanner.context.source_dir, target_type="source") is False
    )
    assert [e["path"] for e in scanner.inputs_not_scanned] == ["web/package-lock.json"]

    scanner.scan(target=scanner.context.work_dir, target_type="converted")

    assert scanner.inputs_not_scanned == []
    assert scanner.targets_attempted is None


def test_the_executor_gives_each_target_container_its_own_inputs(
    offline, spawns, tmp_path
):
    from unittest.mock import MagicMock

    from automated_security_helper.core.phases.scanner_executor import ScannerExecutor

    scanner = _scanner(tmp_path)
    _projects(scanner.context.source_dir, only="web")
    (scanner.context.work_dir / "nb.py").write_text("print(1)\n")
    executor = ScannerExecutor(
        plugin_context=scanner.context, progress_display=MagicMock(), scanner_tasks=[]
    )

    containers = executor._execute_scanner(
        "npm-audit",
        scanner,
        [
            {"path": scanner.context.source_dir, "type": "source"},
            {"path": scanner.context.work_dir, "type": "converted"},
        ],
    )

    by_target = {c.target_type: c for c in containers}
    assert [i.path for i in by_target["source"].inputs_not_scanned] == [
        "web/package-lock.json"
    ]
    assert by_target["converted"].inputs_not_scanned == []


def _offline_scan(tmp_path, monkeypatch, **options) -> int:
    """Run the whole offline scan with the default gates; return its exit code."""
    from automated_security_helper.interactions.run_ash_scan import run_ash_scan

    cwd = tmp_path / "cwd"
    cwd.mkdir()
    monkeypatch.chdir(cwd)
    try:
        run_ash_scan(
            source_dir=str(tmp_path / "repo"),
            output_dir=str(tmp_path / "out"),
            offline=True,
            strategy=ExecutionStrategy.SEQUENTIAL,
            progress=False,
            fail_on_findings=False,
            show_summary=False,
            quiet=True,
            color=False,
            **options,
        )
    except SystemExit as exit_:
        return int(exit_.code or 0)
    return 0


def test_an_offline_scan_grades_npm_audit_missing_and_reports_the_lockfiles(
    offline, spawns, tmp_path, monkeypatch
):
    """The whole scan, default completeness gate: exit code, results, summaries."""
    expected = _projects(tmp_path / "repo")
    output = tmp_path / "out"

    code = _offline_scan(tmp_path, monkeypatch, scanners=["npm-audit"])

    results = json.loads(
        (output / "ash_aggregated_results.json").read_text(encoding="utf-8")
    )
    row = results["scanner_results"]["npm-audit"]
    assert row["status"] == "MISSING", row
    assert code == 1, f"offline scan with an unaudited lockfile exited {code}"
    reports = results["additional_reports"]["npm-audit"]
    recorded = [
        entry["path"]
        for report in reports.values()
        for entry in report.get("inputs_not_scanned", [])
    ]
    assert sorted(recorded) == expected, reports
    for summary in ("ash.summary.md", "ash.summary.txt"):
        text = (output / "reports" / summary).read_text(encoding="utf-8")
        for lockfile in expected:
            assert lockfile in text, f"{summary} does not name {lockfile}"


def test_excluding_npm_audit_is_the_offline_opt_out(
    offline, spawns, tmp_path, monkeypatch
):
    """The documented opt-out: ``--exclude-scanners npm-audit`` passes the gate."""
    _projects(tmp_path / "repo")
    output = tmp_path / "out"

    code = _offline_scan(
        tmp_path,
        monkeypatch,
        scanners=["npm-audit", "detect-secrets"],
        exclude_scanners=["npm-audit"],
    )

    results = json.loads(
        (output / "ash_aggregated_results.json").read_text(encoding="utf-8")
    )
    statuses = {name: row["status"] for name, row in results["scanner_results"].items()}
    assert statuses["npm-audit"] == "SKIPPED", statuses
    assert statuses["detect-secrets"] == "PASSED", statuses  # pragma: allowlist secret
    assert code == 0, f"offline scan excluding npm-audit exited {code}: {statuses}"
