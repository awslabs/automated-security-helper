"""A refused grep scanner's code reaches the scanner's row, through the executor.

``test_a_grep_scanner_refusal_names_what_it_refused`` reads the code on the error the
scan-time guard raises. The reports read it from the row the scan phase files, so
these cases drive the same refusals through the executor's failure path and read
``error_reason_code`` and ``error_reason`` on the row: the configured-rules refusal
(a missing file, a file inside the scanned tree), the copy of opengrep found only
inside the scanned tree, and, as the control, the offline rule cache.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.enums import ScannerStatus
from automated_security_helper.core.exceptions import DEFAULT_SENTENCES, ReasonCode
from automated_security_helper.core.phases.scanner_executor import ScannerExecutor
from automated_security_helper.plugin_modules.ash_builtin.scanners.opengrep_scanner import (
    OpengrepScanner,
    OpengrepScannerConfig,
    OpengrepScannerConfigOptions,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.semgrep_scanner import (
    SemgrepScanner,
    SemgrepScannerConfig,
    SemgrepScannerConfigOptions,
)
from automated_security_helper.utils.short_reason import is_short_reason

pytestmark = pytest.mark.unit

AshConfig.model_rebuild()

SCANNERS = {
    "semgrep": (SemgrepScanner, SemgrepScannerConfig, SemgrepScannerConfigOptions),
    "opengrep": (
        OpengrepScanner,
        OpengrepScannerConfig,
        OpengrepScannerConfigOptions,
    ),
}
CACHE_ENV = ("SEMGREP_RULES_CACHE_DIR", "OPENGREP_RULES_CACHE_DIR", "ASH_OFFLINE")


def _context(base: Path) -> PluginContext:
    output = base / "ash-output"
    output.mkdir(exist_ok=True)
    source = base / "source"
    source.mkdir(exist_ok=True)
    (source / "a.py").write_text("x = 1\n", encoding="utf-8")
    return PluginContext(
        source_dir=source,
        output_dir=output,
        work_dir=output / "converted",
        config=AshConfig(),
    )


def _scanner(name, tmp_path, monkeypatch, **options):
    for variable in CACHE_ENV:
        monkeypatch.delenv(variable, raising=False)
    scanner_class, config_class, options_class = SCANNERS[name]
    context = _context(tmp_path)
    scanner = scanner_class(
        context=context, config=config_class(options=options_class(**options))
    )
    scanner.results_dir = tmp_path / "ash-output" / "scanners" / name
    # The refusal was recorded by construction; the scan phase dispatches the
    # scanner anyway, which is the guard's case.
    scanner.dependencies_satisfied = True
    return scanner


def _row(name, scanner):
    context = scanner.context
    executor = ScannerExecutor(
        plugin_context=context, progress_display=MagicMock(), scanner_tasks=[]
    )
    with (
        patch.object(scanner, "_pre_scan", return_value=True),
        patch.object(scanner, "_post_scan"),
    ):
        (row,) = executor._execute_scanner(
            name, scanner, [{"path": context.source_dir, "type": "source"}]
        )
    return row


def _assert_row(row, code):
    assert row.status == ScannerStatus.ERROR, (row.status, row.errors)
    assert row.error_reason_code == code, (row.error_reason_code, row.error_reason)
    assert is_short_reason(row.error_reason), row.error_reason
    assert code in DEFAULT_SENTENCES, code


@pytest.mark.parametrize("name", ["semgrep", "opengrep"])
class TestTheRowOfARefusedGrepScanner:
    @pytest.mark.parametrize("offline", [False, True])
    def test_configured_rules_that_do_not_exist_give_a_missing_file_row(
        self, name, offline, tmp_path, monkeypatch
    ):
        gone = tmp_path / "elsewhere" / "rules.yml"
        scanner = _scanner(
            name, tmp_path, monkeypatch, config=str(gone), offline=offline
        )
        assert scanner.dependency_unavailable_reason

        row = _row(name, scanner)

        _assert_row(row, ReasonCode.CONFIG_FILE_MISSING)
        assert "elsewhere" not in row.error_reason

    @pytest.mark.parametrize("offline", [False, True])
    def test_configured_rules_inside_the_scanned_tree_give_a_refused_option_row(
        self, name, offline, tmp_path, monkeypatch
    ):
        (tmp_path / "source").mkdir(exist_ok=True)
        inside = tmp_path / "source" / "rules.yml"
        inside.write_text("rules: []\n", encoding="utf-8")
        scanner = _scanner(
            name, tmp_path, monkeypatch, config=str(inside), offline=offline
        )
        assert scanner.dependency_unavailable_reason

        _assert_row(_row(name, scanner), ReasonCode.OPTION_REFUSED)

    def test_control_an_offline_scan_with_no_rule_cache_keeps_the_cache_code(
        self, name, tmp_path, monkeypatch
    ):
        scanner = _scanner(name, tmp_path, monkeypatch, offline=True)
        assert scanner.dependency_unavailable_reason

        _assert_row(_row(name, scanner), ReasonCode.OFFLINE_RULE_CACHE_UNUSABLE)


class TestTheCopyOfOpengrepInsideTheScannedTree:
    def test_the_row_says_the_tool_cannot_be_used(self, tmp_path, monkeypatch):
        scanner = _scanner("opengrep", tmp_path, monkeypatch)
        scanner._record_unavailable(
            "opengrep was found only inside the scanned tree",
            ReasonCode.TOOL_NOT_USABLE,
        )

        row = _row("opengrep", scanner)

        _assert_row(row, ReasonCode.TOOL_NOT_USABLE)
        assert row.error_reason == DEFAULT_SENTENCES[ReasonCode.TOOL_NOT_USABLE]

    def test_control_the_same_reason_filed_under_the_cache_code_is_another_row(
        self, tmp_path, monkeypatch
    ):
        """The row follows the code recorded with the reason, not the reason's text."""
        scanner = _scanner("opengrep", tmp_path, monkeypatch)
        scanner._record_unavailable(
            "opengrep was found only inside the scanned tree",
            ReasonCode.OFFLINE_RULE_CACHE_UNUSABLE,
        )

        row = _row("opengrep", scanner)

        _assert_row(row, ReasonCode.OFFLINE_RULE_CACHE_UNUSABLE)
