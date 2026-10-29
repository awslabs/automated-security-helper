# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A relative TRIVY_CONFIG is taken from the working directory ASH runs in.

``TRIVY_CONFIG`` is the operator's, set where ASH runs, so a relative value is
taken from the working directory, as ``TRIVY_IGNOREFILE`` and
``TRIVY_SECRET_CONFIG`` are (``config/operator_paths.py``). It was joined to the
source directory, so ``../trivy.yaml`` named the file beside the scanned
directory, not the one beside the operator's working directory. The file is then
judged as every path the operator names is: refused inside the scanned tree, the
scan root or the outermost git checkout holding it (``path_trust.operator_reason``).
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.path_trust import reset_path_refusal_warnings
from automated_security_helper.plugin_modules.ash_trivy_plugins.trivy_repo_scanner import (
    TrivyRepoScanner,
)
from automated_security_helper.utils.content_db_refresh import EMPTY_TOOL_CONFIG


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    reset_path_refusal_warnings()
    monkeypatch.delenv("TRIVY_CONFIG", raising=False)
    yield
    reset_path_refusal_warnings()


def _config_file(source: Path, tmp_path: Path) -> str:
    context = PluginContext(
        source_dir=source,
        output_dir=tmp_path / "out",
        work_dir=tmp_path / "out" / "converted",
    )
    return TrivyRepoScanner(context=context)._trivy_config_file()


def _posix(path: Path) -> str:
    """The resolved file as ASH names it: with forward slashes on every platform."""
    return Path(os.path.realpath(path)).as_posix()


def _write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def test_a_relative_trivy_config_is_taken_from_the_working_directory(
    tmp_path, monkeypatch
):
    source = tmp_path / "scan-root"
    source.mkdir()
    cwd = tmp_path / "work" / "run"
    cwd.mkdir(parents=True)
    meant = _write(tmp_path / "work" / "trivy.yaml", "severity: [HIGH]\n")
    # Where the value lands when joined to the source directory instead.
    _write(tmp_path / "trivy.yaml", "severity: [LOW]\n")
    monkeypatch.chdir(cwd)
    monkeypatch.setenv("TRIVY_CONFIG", "../trivy.yaml")

    assert _config_file(source, tmp_path) == _posix(meant)


def test_a_relative_trivy_config_inside_the_scanned_checkout_is_refused(
    tmp_path, monkeypatch, caplog
):
    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)
    cwd = repo / "sub" / "dir"
    cwd.mkdir(parents=True)
    _write(repo / "sub" / "trivy.yaml", "server:\n  addr: http://x.invalid\n")
    # Where the value lands when joined to the source directory: outside the checkout.
    _write(tmp_path / "trivy.yaml", "severity: [LOW]\n")
    monkeypatch.chdir(cwd)
    monkeypatch.setenv("TRIVY_CONFIG", "../trivy.yaml")
    caplog.set_level(logging.WARNING)

    assert _config_file(repo, tmp_path) == EMPTY_TOOL_CONFIG.as_posix()
    (message,) = [
        r.getMessage() for r in caplog.records if "TRIVY_CONFIG" in r.getMessage()
    ]
    # Named as the variable gives it, joined to the working directory.
    assert (cwd / ".." / "trivy.yaml").as_posix() in message, message
    assert "inside the scanned tree" in message, message


def test_a_relative_trivy_config_outside_every_checkout_is_used(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)
    cwd = tmp_path / "operator" / "run"
    cwd.mkdir(parents=True)
    meant = _write(tmp_path / "operator" / "trivy.yaml", "severity: [HIGH]\n")
    monkeypatch.chdir(cwd)
    monkeypatch.setenv("TRIVY_CONFIG", "../trivy.yaml")

    assert _config_file(repo, tmp_path) == _posix(meant)


def test_control_an_absolute_trivy_config_does_not_depend_on_the_working_directory(
    tmp_path, monkeypatch
):
    source = tmp_path / "scan-root"
    source.mkdir()
    operator = _write(tmp_path / "operator" / "trivy.yaml", "severity: [HIGH]\n")
    monkeypatch.chdir(source)
    monkeypatch.setenv("TRIVY_CONFIG", str(operator))

    assert _config_file(source, tmp_path) == _posix(operator)
