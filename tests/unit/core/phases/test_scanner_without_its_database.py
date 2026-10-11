"""A scanner that ran without its content database is ERROR, never PASSED.

grype matches packages against its database. Measured with an empty cache
and the update endpoint refused: grype exited 1 and wrote a zero-byte report, and the
scanner was graded PASSED with 0 findings, the scan exiting 0 under
``--allow-stale-content-db``. The rejected exit code alone now makes that ERROR
(``test_scanner_executor_rejected_exit_codes.py``). This holds the second signal ASH
has: after the scan ASH asks the tool for the database's build time
(``utils/content_db_staleness.py``), and when the tool says the database does not
exist, the scan had nothing to match against, whatever the tool's exit code and
whichever staleness policy is in force. ``content_db_staleness: warn`` relaxes the age
bound for a database that exists; it does not make a missing one acceptable.

The real GrypeScanner runs with only its tool replaced (it writes a well-formed empty
SARIF report and exits 0), and ``grype`` on PATH is a stand-in that answers
``grype db status -o json`` the way grype does for an empty cache. The control is the
same stand-in reporting a database built an hour ago.
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.constants import ASH_WORK_DIR_NAME
from automated_security_helper.core.enums import ScannerStatus
from automated_security_helper.core.phases.scanner_executor import ScannerExecutor
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.plugin_modules.ash_builtin.scanners.grype_scanner import (
    GrypeScanner,
)
from automated_security_helper.utils import subprocess_utils

AshConfig.model_rebuild()
AshAggregatedResults.model_rebuild()

EMPTY_SARIF = json.dumps(
    {
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "grype", "rules": []}}, "results": []}],
    }
)

STATUS_TOOL = """\
import json, sys
print(json.dumps({status}))
sys.exit({code})
"""


def _status_tool(bin_dir: Path, status: dict, code: int) -> None:
    script = bin_dir / "grype"
    script.write_text(
        f"#!{sys.executable}\n" + STATUS_TOOL.format(status=repr(status), code=code),
        encoding="utf-8",
    )
    script.chmod(0o755)


@pytest.fixture
def layout(tmp_path, monkeypatch):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    cache = tmp_path / "grype-cache"
    cache.mkdir()
    monkeypatch.setenv("PATH", f"{bin_dir}:/usr/bin:/bin")
    monkeypatch.setenv("ASH_BIN_PATH", str(bin_dir))
    monkeypatch.setenv("GRYPE_DB_CACHE_DIR", str(cache))
    monkeypatch.setenv("ASH_OFFLINE", "YES")
    subprocess_utils.clear_find_executable_cache()
    yield tmp_path, bin_dir, cache
    subprocess_utils.clear_find_executable_cache()


def _context(tmp_path, policy: str) -> PluginContext:
    source = tmp_path / "source"
    source.mkdir()
    (source / "package.json").write_text("{}\n")
    output = tmp_path / "output"
    (output / ASH_WORK_DIR_NAME).mkdir(parents=True)
    return PluginContext(
        source_dir=source,
        output_dir=output,
        work_dir=output / ASH_WORK_DIR_NAME,
        config=AshConfig(project_name="nodb", content_db_staleness=policy),
    )


def _row(context, monkeypatch):
    scanner = GrypeScanner(context=context)
    captured = {}
    original = scanner._execute_scan

    def capture(*args, **kwargs):
        outcome = original(*args, **kwargs)
        captured["results_file"] = Path(outcome[1])
        return outcome

    def tool(*args, **kwargs):
        captured["results_file"].parent.mkdir(parents=True, exist_ok=True)
        captured["results_file"].write_text(EMPTY_SARIF, encoding="utf-8")
        response = {"returncode": 0, "stdout": "", "stderr": ""}
        scanner._process_command_response(response)
        return response

    monkeypatch.setattr(scanner, "_execute_scan", capture)
    monkeypatch.setattr(scanner, "_run_subprocess", tool)
    monkeypatch.setattr(scanner, "validate_plugin_dependencies", lambda: True)
    executor = ScannerExecutor(
        plugin_context=context, progress_display=MagicMock(), scanner_tasks=[]
    )
    (row,) = executor._execute_scanner(
        "grype", scanner, [{"path": context.source_dir, "type": "source"}]
    )
    return row


@pytest.mark.parametrize("policy", ["warn", "fail"])
def test_a_database_the_tool_reports_missing_makes_the_scanner_an_error(
    layout, monkeypatch, policy
):
    tmp_path, bin_dir, cache = layout
    _status_tool(
        bin_dir,
        {
            "schemaVersion": "",
            "path": str(cache / "6" / "vulnerability.db"),
            "valid": False,
            "error": "database does not exist",
        },
        code=1,
    )

    row = _row(_context(tmp_path, policy), monkeypatch)

    assert row.status == ScannerStatus.ERROR, (
        f"grype ran with no database at all (content_db_staleness={policy}) and was "
        f"graded {row.status.value} with {row.finding_count} findings"
    )
    assert any("database" in str(error) for error in row.errors), (
        f"the ERROR row names the missing database; errors: {row.errors!r}"
    )


def test_a_current_database_is_graded_on_findings(layout, monkeypatch):
    """Control: the same stand-in, reporting a database built an hour ago."""
    tmp_path, bin_dir, cache = layout
    built = (datetime.now(timezone.utc) - timedelta(hours=1)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    _status_tool(
        bin_dir,
        {
            "schemaVersion": "v6.0.2",
            "built": built,
            "path": str(cache / "6" / "vulnerability.db"),
            "valid": True,
        },
        code=0,
    )

    row = _row(_context(tmp_path, "fail"), monkeypatch)

    assert row.status == ScannerStatus.PASSED, f"errors: {row.errors!r}"


@pytest.mark.parametrize(
    "scanners, expected",
    [
        (None, ["trivy-db"]),
        (["vuln", "secret"], ["trivy-db"]),
        (["secret", "misconfig", "license"], []),
        # No --scanners is passed for an empty list, so trivy runs its own default,
        # vuln and secret (pkg/flag/scan_flags.go ScannersFlag), or what a trivy.yaml
        # says.
        ([], ["trivy-db"]),
    ],
    ids=["default", "with-vuln", "without-vuln", "empty-list"],
)
def test_trivy_repo_holds_its_database_unless_its_scanners_leave_out_vuln(
    layout, scanners, expected
):
    """A trivy-repo scan whose scanners leave out `vuln` reads no trivy-db.

    Without this, the absent database of a secrets-only scan would make it ERROR,
    and a stale one would fail it, for a database the scan never opened.
    """
    from automated_security_helper.plugin_modules.ash_trivy_plugins.trivy_repo_scanner import (
        TrivyRepoScanner,
    )

    tmp_path, _bin_dir, _cache = layout
    scanner = TrivyRepoScanner(context=_context(tmp_path, "fail"))
    if scanners is not None:
        scanner.config.options.scanners = scanners

    assert [entry.name for entry in scanner.content_databases_in_use()] == expected
