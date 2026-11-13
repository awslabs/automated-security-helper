# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The CLI's --staged fast paths, before any engine starts.

The hook's hot path: a commit with nothing staged must cost one git call and
exit 0, an unreadable staged list must refuse rather than silently scanning the
whole tree, and any mode but precommit must refuse the flag. The staged reader
is replaced here, so these run no git and no scan.
"""

from __future__ import annotations

import pytest
from typer.testing import CliRunner

import automated_security_helper.utils.staged_files as staged_files_module
from automated_security_helper.core.constants import ASH_EXIT_USAGE_ERROR

pytestmark = pytest.mark.unit


def _invoke(tmp_path, monkeypatch, reader, argv):
    from automated_security_helper.cli.main import app

    monkeypatch.setattr(staged_files_module, "staged_files_for_source", reader)
    return CliRunner().invoke(app, [*argv, "--source-dir", str(tmp_path)])


def test_nothing_staged_exits_clean_before_any_scan(tmp_path, monkeypatch):
    result = _invoke(
        tmp_path, monkeypatch, lambda source: [], ["--mode", "precommit", "--staged"]
    )
    assert result.exit_code == 0, result.output
    assert "nothing is staged" in result.output


def test_an_unreadable_staged_list_is_a_usage_error(tmp_path, monkeypatch):
    result = _invoke(
        tmp_path, monkeypatch, lambda source: None, ["--mode", "precommit", "--staged"]
    )
    assert result.exit_code == ASH_EXIT_USAGE_ERROR
    assert "could not read the staged file list" in result.output


def test_staged_outside_precommit_mode_is_a_usage_error(tmp_path, monkeypatch):
    def never_called(source):  # pragma: no cover - the refusal comes first
        raise AssertionError("the mode refusal must come before any git read")

    result = _invoke(
        tmp_path, monkeypatch, never_called, ["--mode", "local", "--staged"]
    )
    assert result.exit_code == ASH_EXIT_USAGE_ERROR
    assert "only with --mode precommit" in result.output
