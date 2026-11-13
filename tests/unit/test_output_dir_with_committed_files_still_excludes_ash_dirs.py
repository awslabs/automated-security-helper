# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""An output directory holding committed files still has ASH's own directories skipped.

A scanner's tool is told to skip each of ASH's named output directories, except
one holding files git tracks: those are scanned, and a tool cannot be told to
skip a directory but for some of its files. Were one committed file anywhere in
it, a README say, to turn off every exclusion for the whole directory, semgrep,
opengrep, grype, syft and ferret-scan would read ASH's reports, scanner results
and converted files there. ASH drops the SARIF findings located in them
afterwards, but syft writes an SBOM, not SARIF, and nothing would remove the
components it found in ASH's own files.

Such a directory has its working directories, ``analysis``, ``reports``,
``scanners`` and ``converted``, skipped one by one, each that holds no committed
file. The files at its root, ``ash_aggregated_results.json`` and the logs among
them, are still left to the drop: most tools' exclusions name directories.

Also here: a scan-set entry is matched with an output directory as its
filesystem matches names, without regard to case on macOS and Windows.

Every path here is under ``tmp_path``.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from automated_security_helper.utils.get_scan_set import scan_set
from automated_security_helper.utils.scan_output_dirs import (
    WORKING_DIR_NAMES,
    ash_own_dir_names,
    output_dirs_to_exclude,
    scanned_files_in,
)
from tests.unit.workspace.test_execution import _git

pytestmark = pytest.mark.usefixtures("no_checkout_above_tmp_path", "no_tool_probes")


@pytest.mark.unit
def test_ashs_own_directories_include_where_previous_results_are_held():
    """An MCP scan sets the previous results aside in the output directory, whole
    or part way, and a restore stages them on the way back: those are ASH's files
    as much as the working directories."""
    assert set(ash_own_dir_names()) == {
        *WORKING_DIR_NAMES,
        ".ash_previous_results",
        ".ash_previous_results.partial",
        ".ash_previous_results.restoring",
    }


def _repo(tmp_path: Path, committed: list[str]) -> tuple[Path, Path]:
    source = tmp_path / "repo"
    output = source / ".ash" / "ash_output"
    (source / "app.py").parent.mkdir(parents=True, exist_ok=True)
    (source / "app.py").write_text("x = 1\n", encoding="utf-8")
    for relative in committed:
        path = output / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"committed {relative}\n", encoding="utf-8")
    for name in WORKING_DIR_NAMES:
        (output / name).mkdir(parents=True, exist_ok=True)
    (output / "reports" / "ash.html").write_text("<html/>\n", encoding="utf-8")
    assert _git(source, "init", "-q").returncode == 0
    added = _git(
        source, "add", "app.py", *(f".ash/ash_output/{name}" for name in committed)
    )
    assert added.returncode == 0, added.stderr
    return source, output


@pytest.mark.integration
def test_a_committed_readme_leaves_ashs_own_directories_excluded(tmp_path):
    """Only .ash/ash_output/README committed, and the scan
    writing to .ash/ash_output."""
    source, output = _repo(tmp_path, ["README"])
    files = scan_set(source=str(source), output=str(output))
    assert str(output / "README") in files, files

    excluded = output_dirs_to_exclude(source, output, scanned_files=files)

    assert sorted(excluded) == sorted(output / name for name in ash_own_dir_names())


@pytest.mark.integration
def test_a_working_directory_holding_a_committed_file_is_not_excluded(
    tmp_path, monkeypatch
):
    """An earlier run's .ash/ash_output, with a file committed under reports/:
    every other working directory is still skipped, and reports/ is scanned for
    that file."""
    source, output = _repo(tmp_path, ["reports/kept.md", "hidden/notes.py"])
    elsewhere = tmp_path / "out"
    monkeypatch.chdir(tmp_path)
    files = scan_set(source=str(source), output=str(elsewhere))

    excluded = output_dirs_to_exclude(source, elsewhere, scanned_files=files)

    assert sorted(excluded) == sorted(
        output / name for name in ash_own_dir_names() if name != "reports"
    )


@pytest.mark.integration
def test_syft_is_told_to_skip_ashs_own_reports_beside_a_committed_file(tmp_path):
    """syft's SBOM has no fallback: what it is not told to skip, it catalogs."""
    from automated_security_helper.base.plugin_context import PluginContext
    from automated_security_helper.config.ash_config import AshConfig
    from automated_security_helper.plugin_modules.ash_builtin.scanners.syft_scanner import (
        SyftScanner,
        SyftScannerConfig,
    )
    from automated_security_helper.utils.scan_output_dirs import (
        output_dir_exclude_globs,
    )

    source, output = _repo(tmp_path, ["README"])
    context = PluginContext(
        source_dir=source,
        output_dir=output,
        work_dir=output / "converted",
        config=AshConfig(),
    )
    scanner = SyftScanner(context=context, config=SyftScannerConfig())

    globs = output_dir_exclude_globs(scanner._ash_output_dirs_inside(source))

    assert "./.ash/ash_output/reports/**" in globs, globs
    assert "./.ash/ash_output/**" not in globs, globs


@pytest.mark.unit
@pytest.mark.parametrize(
    "platform, matched", [("win32", True), ("darwin", True), ("linux", False)]
)
def test_a_scan_set_entry_is_matched_with_its_directory_as_the_filesystem_matches(
    tmp_path, monkeypatch, platform, matched
):
    """On macOS and Windows ``.ASH/Ash_Output`` is ``.ash/ash_output``; on Linux it
    is another directory. Compared as text, the entry spelled with other case
    was in no named directory on any platform."""
    import sys

    directory = tmp_path / "repo" / ".ash" / "ash_output"
    (directory / "hidden").mkdir(parents=True)
    (directory / "hidden" / "notes.py").write_text("x = 1\n", encoding="utf-8")
    entry = tmp_path / "repo" / ".ASH" / "Ash_Output" / "hidden" / "notes.py"
    monkeypatch.setattr(sys, "platform", platform)

    found = scanned_files_in([directory], [str(entry)])

    expected = [directory / "hidden" / "notes.py"] if matched else []
    assert found == {directory: expected}, found
