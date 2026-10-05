# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""`ash inspect sarif-fields`: the console tables and every file it writes.

The input is tests/test_data/snapshot/sarif_fields: one aggregated report and one
scanner report. Two orderings in the command are not deterministic, and the fixture
is shaped around both rather than masking them:

- Input files come from ``glob.glob``, in directory-listing order, and that order
  decides the key order of the JSON it writes. One file per directory keeps it the
  same on every filesystem.
- The HTML report lists scanners in the iteration order of a ``set`` of scanner
  names, which follows Python's per-process string hash. With two scanners (the
  aggregate counts as one) the sections swap between runs, so the HTML is
  snapshotted from a single-scanner run, where there is only one order.
"""

from __future__ import annotations

import shutil
from pathlib import Path, PurePosixPath, PureWindowsPath

import pytest

from tests.snapshot.support.cli import run_cli
from tests.snapshot.support.normalize import REPO_ROOT

# No measured time in the report; the one duration-shaped text is a CSS transition.
pytestmark = pytest.mark.snapshot_masking(
    mask_durations=False, mask_duration_keys=False
)

FIXTURE = REPO_ROOT / "tests" / "test_data" / "snapshot" / "sarif_fields"
SARIF_DIR = "sarif-input"
OUTPUT_DIR = "inspect-out"
WRITTEN_DATA = {
    "sarif_fields.json": "json",
    "sarif_excluded_fields.json": "json",
    "sarif_fields.csv": "csv",
    "sarif_excluded_fields.csv": "csv",
}
HTML_REPORT = "sarif_validation_report.html"


@pytest.fixture
def project_dir(tmp_path: Path, monkeypatch, snapshot_normalizer) -> Path:
    project = tmp_path / "demo-project"
    shutil.copytree(FIXTURE, project / SARIF_DIR)
    monkeypatch.chdir(project)
    # The command prints the relative paths it was given, joined with os.sep.
    for name in (SARIF_DIR, OUTPUT_DIR):
        for spelling in (PurePosixPath(name), PureWindowsPath(name)):
            snapshot_normalizer.add_root(spelling, name.upper().replace("-", "_"))
    return project


def _run():
    return run_cli(
        [
            "inspect",
            "sarif-fields",
            "--sarif-dir",
            SARIF_DIR,
            "--output-dir",
            OUTPUT_DIR,
        ]
    )


def _written(project_dir: Path, filename: str) -> str:
    return (project_dir / OUTPUT_DIR / filename).read_text(encoding="utf-8")


def test_sarif_fields_reports_missing_field(project_dir, text_snapshot):
    run = _run()

    # The scanner report carries `fingerprints`, which the aggregate dropped.
    assert run.exit_code == 1, run.output
    assert "unexpectedly missing" in run.output
    assert (project_dir / OUTPUT_DIR / HTML_REPORT).is_file()
    assert text_snapshot("txt")(name="console") == run.document
    for filename, ext in WRITTEN_DATA.items():
        assert text_snapshot(ext)(name=filename) == _written(project_dir, filename)


def test_sarif_fields_single_scanner(project_dir, text_snapshot):
    shutil.rmtree(project_dir / SARIF_DIR / "reports")

    run = _run()

    # With no aggregate every scanner field counts as missing from it.
    assert run.exit_code == 1, run.output
    assert text_snapshot("txt")(name="console") == run.document
    for filename, ext in {**WRITTEN_DATA, HTML_REPORT: "html"}.items():
        assert text_snapshot(ext)(name=filename) == _written(project_dir, filename)


def test_sarif_fields_all_preserved(project_dir, text_snapshot):
    scanner_report = project_dir / SARIF_DIR / "scanners" / "bandit" / "source"
    shutil.copyfile(
        scanner_report / "bandit.sarif",
        project_dir / SARIF_DIR / "reports" / "ash.sarif",
    )

    run = _run()

    assert run.exit_code == 0, run.output
    assert text_snapshot("txt") == run.document


def test_sarif_fields_no_input(project_dir, text_snapshot):
    shutil.rmtree(project_dir / SARIF_DIR)
    (project_dir / SARIF_DIR).mkdir()

    run = _run()

    assert run.exit_code == 1, run.output
    assert text_snapshot("txt") == run.document
