# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for get_changed_files() and _filter_results_to_changed_files()."""

import subprocess
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from automated_security_helper.utils.get_scan_set import get_changed_files
from automated_security_helper.interactions.run_ash_scan import _filter_results_to_changed_files
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.schemas.sarif_schema_model import (
    ArtifactLocation,
    Location,
    Message1,
    PhysicalLocation,
    PhysicalLocation2,
    Region,
    Result,
    Run,
    SarifReport,
    Tool,
    ToolComponent,
)


class TestGetChangedFiles:
    """Unit tests for the get_changed_files helper."""

    def test_returns_paths_on_success(self):
        fake_output = "src/app.py\nREADME.md\nlib/utils.js\n"
        mock_result = MagicMock(returncode=0, stdout=fake_output)
        with patch("automated_security_helper.utils.get_scan_set.subprocess.run", return_value=mock_result) as mock_run:
            result = get_changed_files("origin/main")

        mock_run.assert_called_once_with(
            ["git", "diff", "--name-only", "origin/main...HEAD"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert result == [Path("src/app.py"), Path("README.md"), Path("lib/utils.js")]

    def test_returns_empty_list_when_no_changes(self):
        mock_result = MagicMock(returncode=0, stdout="\n")
        with patch("automated_security_helper.utils.get_scan_set.subprocess.run", return_value=mock_result):
            result = get_changed_files()

        assert result == []

    def test_returns_none_when_git_not_found(self):
        with patch(
            "automated_security_helper.utils.get_scan_set.subprocess.run",
            side_effect=FileNotFoundError("git not found"),
        ):
            result = get_changed_files()

        assert result is None

    def test_returns_none_on_timeout(self):
        with patch(
            "automated_security_helper.utils.get_scan_set.subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd="git", timeout=30),
        ):
            result = get_changed_files()

        assert result is None

    def test_returns_none_on_nonzero_exit(self):
        mock_result = MagicMock(returncode=128, stdout="", stderr="fatal: bad ref")
        with patch("automated_security_helper.utils.get_scan_set.subprocess.run", return_value=mock_result):
            result = get_changed_files("nonexistent-branch")

        assert result is None

    def test_custom_base_ref(self):
        mock_result = MagicMock(returncode=0, stdout="file.txt\n")
        with patch("automated_security_helper.utils.get_scan_set.subprocess.run", return_value=mock_result) as mock_run:
            result = get_changed_files("origin/develop")

        mock_run.assert_called_once_with(
            ["git", "diff", "--name-only", "origin/develop...HEAD"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert result == [Path("file.txt")]

    def test_strips_blank_lines(self):
        fake_output = "\n  a.py  \n\nb.py\n\n"
        mock_result = MagicMock(returncode=0, stdout=fake_output)
        with patch("automated_security_helper.utils.get_scan_set.subprocess.run", return_value=mock_result):
            result = get_changed_files()

        assert result == [Path("a.py"), Path("b.py")]


def _make_result(uri: str) -> Result:
    """Helper: build a minimal SARIF Result pointing at *uri*."""
    return Result(
        message=Message1(text="test finding"),
        locations=[
            Location(
                physicalLocation=PhysicalLocation(
                    root=PhysicalLocation2(
                        artifactLocation=ArtifactLocation(uri=uri),
                        region=Region(startLine=1),
                    )
                )
            )
        ],
    )


def _make_results_with_sarif(result_list: list[Result]) -> AshAggregatedResults:
    """Helper: build an AshAggregatedResults with one run containing *result_list*."""
    sarif = SarifReport(
        version="2.1.0",
        runs=[
            Run(
                tool=Tool(driver=ToolComponent(name="test-tool")),
                results=result_list,
            )
        ],
    )
    results = AshAggregatedResults()
    results.sarif = sarif
    return results


class TestFilterResultsToChangedFiles:
    """Unit tests for _filter_results_to_changed_files."""

    def test_keeps_results_matching_changed_files(self, tmp_path):
        source_dir = tmp_path / "repo"
        source_dir.mkdir()
        changed = {(source_dir / "src" / "app.py").resolve()}

        results = _make_results_with_sarif([
            _make_result("src/app.py"),
            _make_result("src/other.py"),
        ])

        filtered = _filter_results_to_changed_files(results, changed, source_dir)
        run_results = filtered.sarif.runs[0].results
        assert len(run_results) == 1
        uri = run_results[0].locations[0].physicalLocation.root.artifactLocation.uri
        assert uri == "src/app.py"

    def test_strips_file_uri_prefix(self, tmp_path):
        source_dir = tmp_path / "repo"
        source_dir.mkdir()
        changed = {(source_dir / "lib" / "helper.js").resolve()}

        # Scanners sometimes emit file://relative/path (non-standard but real)
        results = _make_results_with_sarif([
            _make_result("file://lib/helper.js"),
        ])

        filtered = _filter_results_to_changed_files(results, changed, source_dir)
        assert len(filtered.sarif.runs[0].results) == 1

    def test_strips_file_triple_slash_prefix(self, tmp_path):
        source_dir = tmp_path / "repo"
        source_dir.mkdir()
        # file:///absolute/path -> after strip file:// we get /absolute/path
        # For this to match, the changed set must use the same absolute path.
        abs_path = (source_dir / "src" / "main.py").resolve()
        changed = {abs_path}

        # file:// + absolute path on disk: file:///Users/.../src/main.py
        uri = "file://" + str(abs_path)
        results = _make_results_with_sarif([_make_result(uri)])

        filtered = _filter_results_to_changed_files(results, changed, source_dir)
        assert len(filtered.sarif.runs[0].results) == 1

    def test_empty_changed_set_removes_all(self, tmp_path):
        source_dir = tmp_path / "repo"
        source_dir.mkdir()

        results = _make_results_with_sarif([
            _make_result("src/app.py"),
            _make_result("src/other.py"),
        ])

        filtered = _filter_results_to_changed_files(results, set(), source_dir)
        assert filtered.sarif.runs[0].results == []

    def test_result_without_locations_is_kept(self, tmp_path):
        source_dir = tmp_path / "repo"
        source_dir.mkdir()
        changed = {(source_dir / "x.py").resolve()}

        no_loc_result = Result(message=Message1(text="no location"), locations=[])
        results = _make_results_with_sarif([no_loc_result])

        filtered = _filter_results_to_changed_files(results, changed, source_dir)
        assert len(filtered.sarif.runs[0].results) == 1

    def test_returns_results_unchanged_when_sarif_is_none(self):
        results = AshAggregatedResults()
        results.sarif = None
        out = _filter_results_to_changed_files(results, set(), Path("/tmp"))
        assert out is results

    def test_none_results_returns_none(self):
        out = _filter_results_to_changed_files(None, set(), Path("/tmp"))
        assert out is None
