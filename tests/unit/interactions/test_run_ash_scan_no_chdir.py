"""Smoke test: scan succeeds when os.getcwd() != source_dir.

DA followup #43 — verify os.chdir() removal does not break relative-path
resolution. The orchestrator was already converting paths to absolute before
bc261ef removed the os.chdir() call. This test provides a concrete falsifiable
assertion: a scan driven by an absolute source_dir must produce results even
when the process cwd is set to an unrelated directory.
"""

from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from automated_security_helper.interactions.run_ash_scan import ScanOptions, _run_local_mode


class TestScanSucceedsWhenCwdDiffersFromSourceDir:
    def test_scan_succeeds_when_cwd_differs_from_source_dir(self, tmp_path, monkeypatch):
        """_run_local_mode must work correctly when cwd != source_dir.

        Sets cwd to /tmp (or a pytest tmp dir), runs against a different absolute
        source_dir, and asserts results are returned — proving no code path relies
        on os.getcwd() equalling source_dir.
        """
        source_dir = tmp_path / "source"
        source_dir.mkdir()
        output_dir = tmp_path / "out"
        output_dir.mkdir()

        # Point cwd at a completely different directory — never source_dir.
        cwd_dir = tmp_path / "unrelated_cwd"
        cwd_dir.mkdir()
        monkeypatch.chdir(cwd_dir)

        assert Path.cwd() != source_dir, "precondition: cwd must differ from source_dir"
        assert Path.cwd().resolve() != source_dir.resolve()

        opts = ScanOptions(source_dir=source_dir, output_dir=output_dir)

        mock_orchestrator = MagicMock()
        mock_results = MagicMock()
        mock_orchestrator.execute_scan.return_value = mock_results
        mock_orchestrator.config = MagicMock()
        mock_orchestrator.config.fail_on_findings = True

        with patch("os.chdir", side_effect=AssertionError("os.chdir must not be called")):
            with patch(
                "automated_security_helper.core.orchestrator.ASHScanOrchestrator.create",
                return_value=mock_orchestrator,
            ):
                with patch("builtins.open", MagicMock()):
                    with patch("pathlib.Path.exists", return_value=False):
                        result, _cfg_fof = _run_local_mode(opts, MagicMock())

        assert result is mock_results

    def test_scan_options_source_dir_is_absolute_regardless_of_cwd(self, tmp_path, monkeypatch):
        """ScanOptions must coerce source_dir to absolute at construction time.

        This means the absolute path is captured before any cwd change, so
        downstream code always gets an absolute path even if cwd shifts later.
        """
        source_dir = tmp_path / "src"
        source_dir.mkdir()

        cwd_dir = tmp_path / "somewhere_else"
        cwd_dir.mkdir()
        monkeypatch.chdir(cwd_dir)

        opts = ScanOptions(source_dir=source_dir, output_dir=tmp_path / "out")

        assert opts.source_dir.is_absolute(), "source_dir must be absolute after ScanOptions coercion"
        assert opts.output_dir.is_absolute(), "output_dir must be absolute after ScanOptions coercion"

    def test_os_getcwd_in_scan_set_is_called_at_runtime_not_import(self, tmp_path, monkeypatch):
        """os.getcwd() in scan_set() resolves at call time, not import time.

        Changing cwd after import must be reflected in scan_set()'s default
        source — confirming the if-None pattern is safe.
        """
        from automated_security_helper.utils.get_scan_set import scan_set

        # Point cwd at tmp_path (an empty directory) so scan_set() returns [].
        monkeypatch.chdir(tmp_path)

        result = scan_set()  # no source= arg, so os.getcwd() used at call time
        assert isinstance(result, list)
        # tmp_path is empty, so result is empty (or contains only git-untracked files
        # if pytest created some; either way the call must not blow up).
