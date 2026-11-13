"""Offline, npm-audit does not run, and a lockfile it could audit makes it MISSING.

npm, yarn and pnpm audit a lockfile by asking the registry for the advisories that
match it. Offline there is nothing to ask, and npm does not say so: measured with npm
10.9.4, ``npm audit --json --offline`` on a lockfile pinning lodash 4.17.15, which has
published advisories, printed ``"vulnerabilities": {}`` and exited 0, and yarn and
pnpm fail offline.

So offline is a dependency npm-audit lacks, decided before anything starts: with a
lockfile to audit the scanner is MISSING with the reason, and with none it is SKIPPED
like any scanner with nothing to scan. Online it runs. A lockfile whose package
manager is not installed is an audit that did not happen, so it is a failed target
named in the errors.
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.constants import ASH_WORK_DIR_NAME
from automated_security_helper.core.enums import ScannerStatus
from automated_security_helper.core.phases.scan_phase import ScanPhase
from automated_security_helper.core.unified_metrics import (
    populate_metrics_from_unified_source,
)
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


@pytest.fixture
def context(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    output = tmp_path / "output"
    (output / ASH_WORK_DIR_NAME).mkdir(parents=True)
    return PluginContext(
        source_dir=source,
        output_dir=output,
        work_dir=output / ASH_WORK_DIR_NAME,
        config=get_default_config(),
    )


@pytest.fixture
def npm_installed(monkeypatch, tmp_path):
    monkeypatch.setattr(
        npm_audit_scanner, "find_executable", lambda name: str(tmp_path / name)
    )


@pytest.fixture
def offline(monkeypatch):
    monkeypatch.setenv("ASH_OFFLINE", "true")


def _lockfile_project(root, lock_name="package-lock.json"):
    (root / "package.json").write_text('{"name": "app"}\n', encoding="utf-8")
    (root / lock_name).write_text(
        json.dumps({"name": "app", "lockfileVersion": 3}), encoding="utf-8"
    )


def _scan(context):
    aggregated = AshAggregatedResults()
    phase = ScanPhase(
        plugin_context=context,
        plugins=[NpmAuditScanner],
        progress_display=MagicMock(),
        asharp_model=aggregated,
    )
    with patch.object(NpmAuditScanner, "_run_subprocess") as spawn:
        spawn.return_value = {"stdout": "10.9.4", "returncode": 0}
        results = phase._execute_phase(aggregated_results=aggregated, parallel=False)
    commands = []
    for call in spawn.call_args_list:
        command = call.kwargs.get("command")
        if command is None and call.args:
            command = call.args[0]
        commands.append(list(command or []))
    audits = [command for command in commands if "audit" in command]
    return populate_metrics_from_unified_source(aggregated_results=results), audits


def test_offline_with_a_lockfile_it_is_missing_and_says_why(
    context, npm_installed, offline
):
    _lockfile_project(context.source_dir)

    results, audits = _scan(context)

    row = results.scanner_results["npm-audit"]
    assert row.status == ScannerStatus.MISSING, (
        f"offline npm audit reports every lockfile clean; it must not run: {row!r}"
    )
    assert "offline" in (row.missing_reason or ""), row.missing_reason
    assert audits == [], "no audit may be started offline"


def test_offline_with_no_lockfile_it_is_skipped(context, npm_installed, offline):
    results, _ = _scan(context)

    row = results.scanner_results["npm-audit"]
    assert row.status == ScannerStatus.SKIPPED, row
    assert "lockfile" in (row.skipped_reason or ""), row.skipped_reason


def test_the_scanners_own_option_counts_as_offline(context, npm_installed):
    """options.offline: true forces this scanner offline while ASH is online."""
    from automated_security_helper.plugin_modules.ash_builtin.scanners.npm_audit_scanner import (
        NpmAuditScannerConfig,
        NpmAuditScannerConfigOptions,
    )

    scanner = NpmAuditScanner(
        context=context,
        config=NpmAuditScannerConfig(
            options=NpmAuditScannerConfigOptions(offline=True)
        ),
    )

    assert scanner.validate_plugin_dependencies() is False
    assert "offline" in scanner.missing_dependency_reason()


def test_online_it_runs(context, npm_installed, monkeypatch):
    """Control: online, the audit runs."""
    monkeypatch.delenv("ASH_OFFLINE", raising=False)
    _lockfile_project(context.source_dir)
    scanner = NpmAuditScanner(context=context)

    with patch.object(
        NpmAuditScanner,
        "_run_subprocess",
        return_value={"stdout": "10.9.4", "returncode": 0},
    ):
        assert scanner.validate_plugin_dependencies() is True


@pytest.mark.parametrize(
    "lock_name,binary", [("yarn.lock", "yarn"), ("pnpm-lock.yaml", "pnpm")]
)
def test_a_lockfile_whose_package_manager_is_absent_is_a_failed_target(
    context, monkeypatch, lock_name, binary
):
    monkeypatch.delenv("ASH_OFFLINE", raising=False)
    monkeypatch.setattr(
        npm_audit_scanner,
        "find_executable",
        lambda name: None if name == binary else f"/usr/bin/{name}",
    )
    _lockfile_project(context.source_dir, lock_name=lock_name)
    scanner = NpmAuditScanner(context=context)

    with patch.object(
        NpmAuditScanner,
        "_run_subprocess",
        return_value={"stdout": "10.9.4", "returncode": 0},
    ):
        scanner.scan(target=context.source_dir, target_type="source")

    assert (scanner.targets_attempted, scanner.targets_failed) == (1, 1)
    message = " ".join(scanner.errors)
    assert f"{binary} is not installed" in message, message
    assert lock_name in message, message


def test_the_offline_option_says_what_offline_does_to_npm_audit():
    """It does not say "this scanner runs offline", which npm-audit does not do."""
    from automated_security_helper.plugin_modules.ash_builtin.scanners.npm_audit_scanner import (
        NpmAuditScannerConfigOptions,
    )

    description = NpmAuditScannerConfigOptions.model_fields["offline"].description

    assert "runs offline" not in description, description
    assert "MISSING" in description and "SKIPPED" in description, description


def _console_after_exit_one(results, monkeypatch) -> str:
    import rich
    from rich.console import Console

    from automated_security_helper.interactions.run_ash_scan import (
        print_incompleteness_message,
        scan_incompleteness,
    )

    console = Console(record=True, width=200, color_system=None)
    monkeypatch.setattr(rich, "_console", console)
    facts = scan_incompleteness(results, gate=True)
    print_incompleteness_message(
        list(facts.scanners),
        list(facts.converters),
        list(facts.stale_content_databases),
        no_scanner_ran=facts.no_scanner_ran,
        observed=list(facts.observed),
        unevaluated_rules=list(facts.unevaluated_rules),
        missing_reasons=dict(facts.missing_reasons),
    )
    return console.export_text()


def test_the_exit_one_message_gives_the_offline_reason(
    context, npm_installed, offline, monkeypatch
):
    """Not "Install the missing tools": npm is installed, and offline is the cause."""
    _lockfile_project(context.source_dir)
    results, _ = _scan(context)

    out = _console_after_exit_one(results, monkeypatch)

    assert "npm-audit: MISSING" in out, out
    assert "offline: npm, yarn and pnpm audit" in out, out
    assert "Install the missing tools" not in out, out


def test_a_missing_scanner_with_no_reason_keeps_the_install_advice(monkeypatch):
    """Control: without a recorded reason the generic advice is all there is."""
    import rich
    from rich.console import Console

    from automated_security_helper.interactions.run_ash_scan import (
        print_incompleteness_message,
    )

    console = Console(record=True, width=200, color_system=None)
    monkeypatch.setattr(rich, "_console", console)
    print_incompleteness_message(
        [("tool-a", "MISSING"), ("npm-audit", "MISSING")],
        [],
        missing_reasons={"npm-audit": "offline: npm audits by asking the registry"},
    )
    out = console.export_text()

    assert "offline: npm audits by asking the registry" in out, out
    assert "Install the missing tools" in out, out


def test_the_placeholder_reason_is_not_a_reason():
    """A row whose scanner recorded nothing reads the placeholder; the advice stays."""
    from automated_security_helper.core.unified_metrics import (
        NO_MISSING_REASON_RECORDED,
        populate_metrics_from_unified_source,
    )
    from automated_security_helper.interactions.run_ash_scan import (
        scan_incompleteness,
    )

    model = AshAggregatedResults()
    model.additional_reports["tool-a"] = {
        "source": {
            "scanner_name": "tool-a",
            "status": "MISSING",
            "dependencies_satisfied": False,
        }
    }
    results = populate_metrics_from_unified_source(aggregated_results=model)
    assert results.scanner_results["tool-a"].missing_reason == (
        NO_MISSING_REASON_RECORDED
    )

    assert scan_incompleteness(results, gate=True).missing_reasons == ()
