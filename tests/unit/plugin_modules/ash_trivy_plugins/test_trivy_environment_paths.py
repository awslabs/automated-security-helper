# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The trivy files the operator names in TRIVY_CONFIG, TRIVY_IGNOREFILE and TRIVY_SECRET_CONFIG.

Each variable is the operator's, set where ASH runs (``config/operator_paths.py``):

* A relative value is taken from the working directory as written, whatever it
  holds. A ``$`` or ``://`` in it is part of a file name: nothing expands these
  variables, so such a value was joined to the source directory instead.
* ``..`` after a symbolic link goes up from where the link points, as the kernel
  and the shell read it. Folding ``link/..`` away by name named a file the
  operator did not name.
* A value starting with ``~`` is expanded, and an absolute one is used as written.
* The file is judged as every path the operator names is: refused only inside the
  scanned tree, the scan root or the outermost git checkout holding it
  (``path_trust.operator_reason``), so a file in an unrelated checkout, such as an
  operator's ops repository, is used. The refusal gives the operator's advice.
* A warning or error that shows the value writes its control characters as escapes.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Callable, Dict

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.confinement_remedy import KEEP_A_SETTING
from automated_security_helper.config.path_trust import reset_path_refusal_warnings
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.plugin_modules.ash_trivy_plugins.trivy_repo_scanner import (
    TrivyRepoScanner,
)
from automated_security_helper.utils.content_db_refresh import EMPTY_TOOL_CONFIG

pytestmark = pytest.mark.unit

VARIABLES = ("TRIVY_CONFIG", "TRIVY_IGNOREFILE", "TRIVY_SECRET_CONFIG")

#: What each variable chooses, read from the scanner.
CHOSEN: Dict[str, Callable[[TrivyRepoScanner], str]] = {
    "TRIVY_CONFIG": lambda scanner: scanner._trivy_config_file(),
    "TRIVY_IGNOREFILE": lambda scanner: scanner._ignore_file(),
    "TRIVY_SECRET_CONFIG": lambda scanner: scanner._secret_config_file(),
}

OPERATOR_ADVICE = (
    "A file inside the scanned tree, or one an MCP client delivered, is not passed "
    "to the tool; name one outside it."
)


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    reset_path_refusal_warnings()
    for name in VARIABLES:
        monkeypatch.delenv(name, raising=False)
    yield
    reset_path_refusal_warnings()


def _scanner(source: Path, tmp_path: Path) -> TrivyRepoScanner:
    return TrivyRepoScanner(
        context=PluginContext(
            source_dir=source,
            output_dir=tmp_path / "out",
            work_dir=tmp_path / "out" / "converted",
        )
    )


def _write(path: Path, text: str = "{}\n") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def _checkout(path: Path) -> Path:
    (path / ".git").mkdir(parents=True)
    return path


@pytest.mark.parametrize("variable", VARIABLES)
@pytest.mark.parametrize("name", ["d$x", "d${HOME}", "u://v"])
def test_a_relative_value_is_taken_from_the_working_directory_as_written(
    tmp_path, monkeypatch, variable, name
):
    source = tmp_path / "scan-root"
    source.mkdir()
    cwd = tmp_path / "work" / "run"
    cwd.mkdir(parents=True)
    meant = _write(tmp_path / "work" / name / "trivy.yaml")
    # Where the value lands when joined to the source directory instead.
    _write(tmp_path / name / "trivy.yaml")
    monkeypatch.chdir(cwd)
    monkeypatch.setenv(variable, f"../{name}/trivy.yaml")

    assert CHOSEN[variable](_scanner(source, tmp_path)) == os.path.realpath(meant)


@pytest.mark.parametrize("variable", VARIABLES)
def test_dot_dot_after_a_link_goes_up_from_where_the_link_points(
    tmp_path, monkeypatch, variable
):
    source = tmp_path / "scan-root"
    source.mkdir()
    cwd = tmp_path / "work"
    (tmp_path / "elsewhere" / "sub").mkdir(parents=True)
    cwd.mkdir()
    (cwd / "link").symlink_to(tmp_path / "elsewhere" / "sub")
    meant = _write(tmp_path / "elsewhere" / "trivy.yaml")
    # The file `link/..` names when the link is folded away by name.
    _write(cwd / "trivy.yaml")
    monkeypatch.chdir(cwd)
    monkeypatch.setenv(variable, "link/../trivy.yaml")

    assert CHOSEN[variable](_scanner(source, tmp_path)) == os.path.realpath(meant)


@pytest.mark.parametrize("variable", VARIABLES)
def test_an_absolute_value_in_an_unrelated_checkout_is_used(
    tmp_path, monkeypatch, variable
):
    """An operator's ops repository is not the scanned tree."""
    repo = _checkout(tmp_path / "repo")
    ops = _checkout(tmp_path / "ops")
    named = _write(ops / "trivy" / "file.yaml")
    monkeypatch.chdir(repo)
    monkeypatch.setenv(variable, str(named))

    assert CHOSEN[variable](_scanner(repo, tmp_path)) == os.path.realpath(named)


@pytest.mark.parametrize("variable", VARIABLES)
def test_a_link_outside_the_tree_to_a_file_inside_it_is_refused(
    tmp_path, monkeypatch, variable, caplog
):
    repo = _checkout(tmp_path / "repo")
    inside = _write(repo / "trivy.yaml")
    link = tmp_path / "operator" / "trivy.yaml"
    link.parent.mkdir()
    link.symlink_to(inside)
    monkeypatch.setenv(variable, str(link))
    caplog.set_level(logging.WARNING)

    chosen = CHOSEN[variable](_scanner(repo, tmp_path))

    assert os.path.realpath(chosen) != os.path.realpath(inside)
    assert any(variable in r.getMessage() for r in caplog.records)


@pytest.mark.parametrize("variable", VARIABLES)
def test_a_link_outside_the_tree_to_a_file_outside_it_is_used(
    tmp_path, monkeypatch, variable
):
    repo = _checkout(tmp_path / "repo")
    target = _write(tmp_path / "operator-files" / "trivy.yaml")
    link = tmp_path / "operator" / "trivy.yaml"
    link.parent.mkdir()
    link.symlink_to(target)
    monkeypatch.setenv(variable, str(link))

    assert CHOSEN[variable](_scanner(repo, tmp_path)) == os.path.realpath(target)


def test_the_refusal_gives_the_operators_advice(tmp_path, monkeypatch, caplog):
    repo = _checkout(tmp_path / "repo")
    monkeypatch.setenv("TRIVY_CONFIG", str(_write(repo / "sub" / "trivy.yaml")))
    caplog.set_level(logging.WARNING)

    assert _scanner(repo, tmp_path)._trivy_config_file() == EMPTY_TOOL_CONFIG.as_posix()
    (message,) = [
        r.getMessage() for r in caplog.records if "TRIVY_CONFIG" in r.getMessage()
    ]
    assert message.endswith(OPERATOR_ADVICE), message
    assert KEEP_A_SETTING not in message, message


def test_a_newline_in_a_refused_value_is_escaped_in_the_warning(
    tmp_path, monkeypatch, caplog
):
    repo = _checkout(tmp_path / "repo")
    monkeypatch.setenv("TRIVY_CONFIG", f"{repo / 'trivy.yaml'}\n")
    caplog.set_level(logging.WARNING)

    _scanner(repo, tmp_path)._trivy_config_file()

    (message,) = [
        r.getMessage() for r in caplog.records if "TRIVY_CONFIG" in r.getMessage()
    ]
    assert "\n" not in message, message
    assert "trivy.yaml\\n" in message, message


def test_a_newline_in_a_value_that_is_not_a_file_is_escaped_in_the_error(
    tmp_path, monkeypatch
):
    source = tmp_path / "scan-root"
    source.mkdir()
    missing = tmp_path / "operator" / "trivy.yaml"
    monkeypatch.setenv("TRIVY_CONFIG", f"{missing}\n")

    with pytest.raises(ScannerError) as excinfo:
        _scanner(source, tmp_path)._trivy_config_file()

    assert "\n" not in str(excinfo.value), str(excinfo.value)
    assert "trivy.yaml\\n" in str(excinfo.value), str(excinfo.value)
