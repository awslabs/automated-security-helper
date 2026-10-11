"""Each scanner accepts exactly the exit codes its tool uses for a completed run.

The table is the reviewed answer, per tool, to "which codes mean the tool finished".
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

#: Scanners whose real class is run through the executor below. snyk-code is left
#: out: it needs a token and checks its exit code itself.
EXECUTED = [
    "bandit",
    "checkov",
    "grype",
    "semgrep",
    "opengrep",
    "trivy-repo",
    "syft",
    "ferret-scan",
]

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


_OUTPUT_FLAGS = ("--output", "--sarif-output", "--output-file", "-o")


def _results_paths(command, results_dir: Path):
    """Paths in ``command`` that name a file under ``results_dir``.

    Covers ``--output PATH``, ``--output=PATH`` and syft's ``--output FORMAT=PATH``.
    """
    root = str(results_dir)
    paths = []
    for index, part in enumerate(str(p) for p in command):
        values = []
        if part in _OUTPUT_FLAGS and index + 1 < len(command):
            values.append(str(command[index + 1]))
        elif part.startswith("--output="):
            values.append(part.split("=", 1)[1])
        for value in values:
            if not value.startswith(root) and "=" in value:
                value = value.split("=", 1)[1]
            if value.startswith(root):
                paths.append(Path(value))
    return paths


def _row(plugin_context, monkeypatch, name: str, exit_code: int):
    """The scanner's row after one run whose tool exits ``exit_code``."""
    scanner = _scanner_class(name)(context=plugin_context)
    content = EMPTY_CYCLONEDX if name == "syft" else EMPTY_SARIF
    captured = {}

    if hasattr(scanner, "_execute_scan"):
        original = scanner._execute_scan

        def capture(*args, **kwargs):
            outcome = original(*args, **kwargs)
            captured["results_file"] = Path(outcome[1])
            return outcome

        monkeypatch.setattr(scanner, "_execute_scan", capture)

    def tool(command, results_dir=None, *args, **kwargs):
        if "results_file" in captured:
            targets = [captured["results_file"]]
        else:
            targets = _results_paths(command, Path(scanner.results_dir))
        for target in targets:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")
        response = {
            "returncode": exit_code,
            "stdout": "",
            "stderr": f"exit {exit_code}",
        }
        scanner._process_command_response(response)
        return response

    monkeypatch.setattr(scanner, "_run_subprocess", tool)
    monkeypatch.setattr(scanner, "validate_plugin_dependencies", lambda: True)
    executor = ScannerExecutor(
        plugin_context=plugin_context, progress_display=MagicMock(), scanner_tasks=[]
    )
    # The content-database age check runs the scanner's real binary; it is not
    # what is under test here.
    monkeypatch.setattr(executor, "_assess_content_databases", lambda *a, **k: None)
    (row,) = executor._execute_scanner(
        str(scanner.config.name),
        scanner,
        [{"path": plugin_context.source_dir, "type": "source"}],
    )
    return row


@pytest.mark.parametrize(
    "name, exit_code",
    [(name, code) for name in EXECUTED for code in sorted(EXIT_CODE_TABLE[name][2])],
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
    [(name, code) for name in EXECUTED for code in sorted(EXIT_CODE_TABLE[name][1])],
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
