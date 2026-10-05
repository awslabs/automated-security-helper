# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for get_changed_files() and _filter_results_to_changed_files()."""

import logging
import subprocess  # nosec B404
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest


from automated_security_helper.utils.get_scan_set import get_changed_files
from automated_security_helper.interactions.run_ash_scan import (
    _filter_results_to_changed_files,
)
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
        with patch(
            "automated_security_helper.utils.get_scan_set.subprocess.run",
            return_value=mock_result,
        ) as mock_run:
            result = get_changed_files("origin/main")

        mock_run.assert_called_once_with(
            ["git", "diff", "--name-only", "origin/main...HEAD"],
            capture_output=True,
            text=True,
            timeout=30,
            cwd=None,
        )
        assert result == [Path("src/app.py"), Path("README.md"), Path("lib/utils.js")]

    def test_returns_empty_list_when_no_changes(self):
        mock_result = MagicMock(returncode=0, stdout="\n")
        with patch(
            "automated_security_helper.utils.get_scan_set.subprocess.run",
            return_value=mock_result,
        ):
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
        with patch(
            "automated_security_helper.utils.get_scan_set.subprocess.run",
            return_value=mock_result,
        ):
            result = get_changed_files("nonexistent-branch")

        assert result is None

    def test_custom_base_ref(self):
        mock_result = MagicMock(returncode=0, stdout="file.txt\n")
        with patch(
            "automated_security_helper.utils.get_scan_set.subprocess.run",
            return_value=mock_result,
        ) as mock_run:
            result = get_changed_files("origin/develop")

        mock_run.assert_called_once_with(
            ["git", "diff", "--name-only", "origin/develop...HEAD"],
            capture_output=True,
            text=True,
            timeout=30,
            cwd=None,
        )
        assert result == [Path("file.txt")]

    def test_strips_blank_lines(self):
        fake_output = "\n  a.py  \n\nb.py\n\n"
        mock_result = MagicMock(returncode=0, stdout=fake_output)
        with patch(
            "automated_security_helper.utils.get_scan_set.subprocess.run",
            return_value=mock_result,
        ):
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


@pytest.fixture
def ash_warnings(caplog):
    """Read back ASH's own WARNING records, which plain ``caplog`` cannot see.

    Two independent reasons, both documented in ``tests/conftest.py``:

    * ``utils.log`` sets ``ASH_LOGGER.propagate = False``, so a record on it never
      reaches the root handler ``caplog`` installs. Its handlers have to be swapped
      for the duration.
    * Any ``logging.config.dictConfig`` whose payload leaves
      ``disable_existing_loggers`` at its default -- some libraries do this at
      import time -- sets ``disabled`` on every logger not named in the payload.
      The autouse fixture in ``tests/conftest.py`` snapshots and restores that for
      the ``ash`` logger, so re-enabling here is belt and braces rather than the
      load-bearing part; a disabled logger drops records inside ``Logger.handle``
      and the assertion then reads as the code under test never having logged.

    Returns a callable rather than the records, so the list is read after the call
    under test instead of being captured before it.
    """
    from automated_security_helper.utils.log import ASH_LOGGER

    saved_handlers = ASH_LOGGER.handlers
    saved_propagate = ASH_LOGGER.propagate
    saved_disabled = ASH_LOGGER.disabled
    handlers = [
        handler
        for handler in saved_handlers
        if isinstance(handler, type(caplog.handler))
    ]
    if caplog.handler not in handlers:
        handlers.append(caplog.handler)
    ASH_LOGGER.handlers = handlers
    ASH_LOGGER.propagate = False
    ASH_LOGGER.disabled = False
    caplog.set_level(logging.WARNING, logger=ASH_LOGGER.name)
    try:
        yield lambda: [
            record.getMessage()
            for record in caplog.records
            if record.levelno >= logging.WARNING
        ]
    finally:
        ASH_LOGGER.handlers = saved_handlers
        ASH_LOGGER.propagate = saved_propagate
        ASH_LOGGER.disabled = saved_disabled


class TestFilterResultsToChangedFiles:
    """Unit tests for _filter_results_to_changed_files."""

    def test_keeps_results_matching_changed_files(self, tmp_path):
        source_dir = tmp_path / "repo"
        source_dir.mkdir()
        changed = {(source_dir / "src" / "app.py").resolve()}

        results = _make_results_with_sarif(
            [
                _make_result("src/app.py"),
                _make_result("src/other.py"),
            ]
        )

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
        results = _make_results_with_sarif(
            [
                _make_result("file://lib/helper.js"),
            ]
        )

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

        results = _make_results_with_sarif(
            [
                _make_result("src/app.py"),
                _make_result("src/other.py"),
            ]
        )

        filtered = _filter_results_to_changed_files(results, set(), source_dir)
        assert filtered.sarif.runs[0].results == []

    def test_empty_changed_set_says_so_and_counts_what_it_discarded(
        self, tmp_path, ash_warnings
    ):
        """Emptying a result set silently is indistinguishable from a clean scan.

        An empty changed-file set matches nothing, so every result goes and the run
        reports zero findings at exit 0. It is reachable without operator error:
        ``--changed-files-only`` against a base ref that resolves to an empty diff,
        or a diff falling entirely outside ``--source-dir`` once the caller
        intersects the two scopings. The count is part of the assertion because a
        warning that does not say how much was lost does not tell an operator
        whether to believe the report.
        """
        source_dir = tmp_path / "repo"
        source_dir.mkdir()

        results = _make_results_with_sarif(
            [
                _make_result("src/app.py"),
                _make_result("src/other.py"),
            ]
        )

        _filter_results_to_changed_files(results, set(), source_dir)

        warnings = ash_warnings()
        assert warnings, "an empty changed-file set discarded every result in silence"
        assert any("2 finding(s)" in message for message in warnings), (
            f"no warning named the number discarded: {warnings}"
        )

    def test_a_matching_changed_set_warns_about_nothing(self, tmp_path, ash_warnings):
        """The warning is for the empty-set case, not for the flag working.

        A non-empty set that discards results is the operator's filter doing what
        they asked. Warning there would make the line noise, and noise gets
        filtered -- which would cost the empty-set case its only signal.
        """
        source_dir = tmp_path / "repo"
        source_dir.mkdir()
        changed = {(source_dir / "src" / "app.py").resolve()}

        results = _make_results_with_sarif(
            [
                _make_result("src/app.py"),
                _make_result("src/other.py"),
            ]
        )

        _filter_results_to_changed_files(results, changed, source_dir)

        assert ash_warnings() == []

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
        out = _filter_results_to_changed_files(results, set(), Path("/tmp"))  # nosec B108
        assert out is results

    def test_none_results_returns_none(self):
        out = _filter_results_to_changed_files(None, set(), Path("/tmp"))  # nosec B108
        assert out is None
