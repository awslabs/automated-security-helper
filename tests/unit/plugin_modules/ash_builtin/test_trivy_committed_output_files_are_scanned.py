# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""trivy skips ASH's own directories in the output directory, not the directory whole.

The builtin trivy scanner passed ``ScannerPluginBase._output_dir_inside(target)``,
the output directory as one path, to ``--skip-dirs``. The default output directory,
``.ash/ash_output``, is a fixed path inside the scanned tree, and a repository can
commit files to it. A ``requirements.txt`` committed under
``.ash/ash_output/hidden/`` was inside that one skipped path, so trivy never read
it, while the scanners that take ``_ash_output_dirs_inside`` (checkov, grype,
syft, bandit, ferret-scan, semgrep, opengrep) scan it, and so does detect-secrets.
trivy now takes the same helper: it is told to skip ASH's own directories, each
whole when git lists no committed file under the output directory, and the
working directories ASH creates in it otherwise.

These tests read the command line ``_execute_scan`` builds, so no trivy binary
runs. A value is read the way trivy applies ``--skip-dirs``: it names a directory
below the scanned root, and trivy does not enter a directory it matches, so a path
is left out when a value names it or a directory above it.

Red on the parent of the fix:

- ``test_a_file_committed_under_the_output_dir_is_not_skipped``, both outputs;
  the parent skips ``.ash/ash_output`` whole when the output directory is this
  run's, and skips none of ASH's earlier reports when it is elsewhere
- ``test_a_glob_character_in_the_directory_name_is_escaped``
- ``test_when_the_directories_cannot_be_named_...`` (three errors); the parent
  skips ``.ash/ash_output`` whole, which the first assertion wants, and logs no
  warning, which the second wants

The rest pass on the parent too. They pin what must not weaken: every directory
ASH creates in its output directory is still skipped, the output directory is
still skipped whole when it holds nothing the repository committed, and the
converted target is still not excluded.

``_ash_output_dirs_inside`` returns no directory when naming them raises an
OSError, TypeError or ValueError, and the drop after the scan then names nothing
either. ``test_when_the_directories_cannot_be_named_...`` pins the fallback: the
output directory skipped whole, with a warning. It is red on the first commit of
this fix as well, which skipped nothing then. Its two neighbors, that the fallback
adds nothing where there is nothing of ASH's inside the target, pass on the parent,
on the first commit and on the fix.
"""

from __future__ import annotations

import logging
from pathlib import Path

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.plugin_modules.ash_builtin.scanners.trivy_scanner import (
    TrivyScanner,
    TrivyScannerConfig,
    TrivyScannerConfigOptions,
)
from automated_security_helper.utils.config_trust import record_provenance
from automated_security_helper.utils.scan_output_dirs import ash_own_dir_names
from tests.unit.workspace.test_execution import _git

PluginContext.model_rebuild()

#: A tree built without ``git init`` is outside git wherever tmp_path is
#: (tests/unit/conftest.py).
pytestmark = [
    pytest.mark.integration,
    pytest.mark.usefixtures("no_checkout_above_tmp_path"),
]

DEFAULT_OUTPUT = ".ash/ash_output"

#: Committed to git under ASH's default output directory, in a directory ASH never
#: creates there.
COMMITTED = (
    ".ash/ash_output/hidden/requirements.txt",
    ".ash/ash_output/hidden/settings.txt",
)
#: What ASH wrote there: in no index.
ASH_WROTE = (
    ".ash/ash_output/reports/ash.sarif",
    ".ash/ash_output/scanners/detect-secrets/source/results_sarif.sarif",
)


@pytest.fixture(autouse=True)
def _isolated(monkeypatch, tmp_path):
    """No test here inherits ASH_OFFLINE or a TRIVY_CONFIG from the shell running it,
    and a ``.ash/ash_output`` in the working directory is never a candidate."""
    monkeypatch.delenv("ASH_OFFLINE", raising=False)
    monkeypatch.delenv("TRIVY_CONFIG", raising=False)
    monkeypatch.chdir(tmp_path)


def _tree(root: Path, *, in_git: bool, commit_output: bool = True) -> Path:
    """``repo/``: ``app.py``, the committed files and the files ASH wrote.

    With *in_git*, ``app.py`` and, unless *commit_output* is False, the committed
    files are staged. Nothing ASH wrote is.
    """
    source = root / "repo"
    for relative in ("app.py", *COMMITTED, *ASH_WROTE):
        path = source / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("urllib3==1.24.1\n", encoding="utf-8")
    if in_git:
        assert _git(source, "init", "-q").returncode == 0
        staged = ("app.py", *COMMITTED) if commit_output else ("app.py",)
        added = _git(source, "add", "--", *staged)
        assert added.returncode == 0, added.stderr
    return source


def _scanner(source: Path, output: Path) -> TrivyScanner:
    context = PluginContext(
        source_dir=source,
        output_dir=output,
        work_dir=output / "converted",
        config=AshConfig(),
    )
    # Built from no file in the scanned tree, as the operator's own settings are.
    record_provenance(
        context.config, in_tree=[], trusted=AshConfig(), config_overrides=[]
    )
    return TrivyScanner(
        context=context,
        config=TrivyScannerConfig(
            enabled=True, options=TrivyScannerConfigOptions(offline=False)
        ),
    )


def _skip_dirs(scanner: TrivyScanner, target: Path) -> list[str]:
    """The ``--skip-dirs`` values of the command line for *target*, as written."""
    argv, _, _ = scanner._execute_scan(target, "source", [])
    return [arg.split("=", 1)[1] for arg in argv if arg.startswith("--skip-dirs=")]


def _skipped(values: list[str], relative: str) -> bool:
    """Whether trivy leaves out *relative*, a path below the scanned root.

    Compared literally: no value in these tests holds a glob character.
    """
    return any(
        relative == value or relative.startswith(f"{value}/") for value in values
    )


@pytest.mark.parametrize("output", ["this-run", "elsewhere"])
def test_a_file_committed_under_the_output_dir_is_not_skipped(tmp_path, output):
    """``--output-dir`` outside the tree, as container mode runs, and the default
    ``.ash/ash_output``, which holds the committed files, as this run's output."""
    source = _tree(tmp_path, in_git=True)
    directory = source / DEFAULT_OUTPUT if output == "this-run" else tmp_path / "out"

    values = _skip_dirs(_scanner(source, directory), source)

    for relative in COMMITTED:
        assert not _skipped(values, relative), values
    # The control: ASH's own files beside them are still left out.
    for relative in ASH_WROTE:
        assert _skipped(values, relative), values


@pytest.mark.parametrize("name", ash_own_dir_names())
def test_each_directory_ash_creates_in_its_output_dir_is_still_skipped(tmp_path, name):
    """Nothing ASH generates is read by trivy because the repository also committed
    a file in the same output directory."""
    source = _tree(tmp_path, in_git=True)

    values = _skip_dirs(_scanner(source, source / DEFAULT_OUTPUT), source)

    assert _skipped(values, f"{DEFAULT_OUTPUT}/{name}/anything"), values


def test_without_a_committed_file_the_output_dir_is_skipped_whole(tmp_path):
    source = _tree(tmp_path, in_git=True, commit_output=False)

    values = _skip_dirs(_scanner(source, source / DEFAULT_OUTPUT), source)

    assert values == [DEFAULT_OUTPUT], values


def test_outside_git_this_runs_output_dir_is_skipped_whole(tmp_path):
    """Nothing tells ASH's files from the repository's there, so none is scanned."""
    source = _tree(tmp_path, in_git=False)

    values = _skip_dirs(_scanner(source, source / DEFAULT_OUTPUT), source)

    assert values == [DEFAULT_OUTPUT], values


def test_the_converted_target_is_not_excluded(tmp_path):
    """work_dir lives under the output directory, so skipping the output directory
    there would skip every file the converters produced."""
    source = _tree(tmp_path, in_git=True)
    output = source / DEFAULT_OUTPUT
    work = output / "converted"
    work.mkdir(parents=True, exist_ok=True)

    values = _skip_dirs(_scanner(source, output), work)

    assert values == [], values


def _naming_fails(monkeypatch, error: Exception) -> None:
    """``_ash_output_dirs_inside`` hits *error* while naming ASH's directories.

    It returns no directory then, which it cannot tell from "none inside". Raised
    from ``output_dirs_to_exclude``, the call it makes inside its ``try``.
    """
    from automated_security_helper.utils import scan_output_dirs

    def fail(*args, **kwargs):
        raise error

    monkeypatch.setattr(scan_output_dirs, "output_dirs_to_exclude", fail)


@pytest.mark.parametrize(
    "error",
    [OSError("working directory deleted"), TypeError("odd path"), ValueError("nul")],
    ids=["OSError", "TypeError", "ValueError"],
)
def test_when_the_directories_cannot_be_named_the_output_dir_is_skipped_whole(
    tmp_path, monkeypatch, error
):
    """The drop after the scan names the same directories and drops nothing when
    that raises, so the scan must not read ASH's output then: it is skipped whole,
    as it was before the directories were named one by one, and the scan says so."""
    source = _tree(tmp_path, in_git=True)
    scanner = _scanner(source, source / DEFAULT_OUTPUT)
    logged: list = []

    def record(self, *msg, **kwargs):
        logged.append((" ".join(msg), kwargs))

    monkeypatch.setattr(TrivyScanner, "_plugin_log", record)
    _naming_fails(monkeypatch, error)

    values = _skip_dirs(scanner, source)

    assert values == [DEFAULT_OUTPUT], values
    assert any(
        kwargs.get("level") == logging.WARNING and DEFAULT_OUTPUT in text
        for text, kwargs in logged
    ), logged


def test_a_failure_to_name_the_directories_adds_nothing_for_an_output_dir_elsewhere(
    tmp_path, monkeypatch
):
    """Nothing of ASH's is inside the target to skip, helper failure or not."""
    source = _tree(tmp_path, in_git=True)
    _naming_fails(monkeypatch, OSError("working directory deleted"))

    values = _skip_dirs(_scanner(source, tmp_path / "out"), source)

    assert values == [], values


def test_a_failure_to_name_the_directories_does_not_exclude_the_converted_target(
    tmp_path, monkeypatch
):
    source = _tree(tmp_path, in_git=True)
    output = source / DEFAULT_OUTPUT
    work = output / "converted"
    work.mkdir(parents=True, exist_ok=True)
    _naming_fails(monkeypatch, OSError("working directory deleted"))

    values = _skip_dirs(_scanner(source, output), work)

    assert values == [], values


def test_a_glob_character_in_the_directory_name_is_escaped(tmp_path):
    """Each directory is written as trivy reads it, a ``[`` or ``]`` backslash-escaped,
    here for a visible output directory that holds one committed file."""
    source = tmp_path / "repo"
    output = source / "out[1]"
    for relative in ("app.py", "out[1]/keep.txt", "out[1]/reports/ash.sarif"):
        path = source / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("urllib3==1.24.1\n", encoding="utf-8")
    assert _git(source, "init", "-q").returncode == 0
    added = _git(source, "add", "--", "app.py", ":(literal)out[1]/keep.txt")
    assert added.returncode == 0, added.stderr

    values = _skip_dirs(_scanner(source, output), source)

    assert sorted(values) == sorted(
        f"out\\[1\\]/{name}" for name in ash_own_dir_names()
    ), values
