# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for get_changed_files() and filter_results_to_changed_files()."""

import logging
import os
import subprocess  # nosec B404
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest


from automated_security_helper.utils.get_scan_set import get_changed_files
from automated_security_helper.utils.subprocess_utils import find_executable
from automated_security_helper.utils.changed_files import (
    filter_results_to_changed_files,
)
from automated_security_helper.utils.finding_identity import CONVERTED_PATH_PROPERTY
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.schemas.sarif_schema_model import (
    ArtifactLocation,
    Location,
    Message1,
    PhysicalLocation,
    PhysicalLocation2,
    PropertyBag,
    Region,
    Result,
    Run,
    SarifReport,
    Tool,
    ToolComponent,
)
from tests.utils.env_assertions import differing_names
from tests.utils.git_fixture import run_git


@pytest.fixture(autouse=True)
def _resolved_git(monkeypatch):
    """Pin the resolved git to the bare name, so the argv assertions below do not
    depend on where this machine installs git. The resolution itself is
    _git_executable's, checked in its own tests."""
    from automated_security_helper.utils import get_scan_set

    monkeypatch.setattr(get_scan_set, "_git_executable", lambda: "git")


def _diff_argv(base_ref: str) -> list[str]:
    """The diff get_changed_files runs: NUL-separated names, none quoted, named
    from the repository root whatever diff.relative says, with git_argv's options
    ahead of it and a trailing "--" so git reads the range only as revisions (a
    working-tree file named like the range is not taken in its place when the
    base ref is missing)."""
    return [
        "git",
        "-c",
        "core.fsmonitor=false",
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "core.quotepath=false",
        "-c",
        "diff.relative=false",
        "diff",
        "--name-only",
        "-z",
        f"{base_ref}...HEAD",
        "--",
    ]


def _assert_ran_the_diff(mock_run: MagicMock, base_ref: str) -> None:
    """get_changed_files ran the diff once: its argv, cwd and stdin, and an explicit
    copy of the environment, never the live environ (utils/process_env.py).

    Compared part by part, the environment by names: assert_called_once_with
    prints the call's whole environment when it fails (tests/utils/env_assertions.py).
    """
    assert mock_run.call_count == 1
    args, kwargs = mock_run.call_args
    assert args == (_diff_argv(base_ref),)
    others = {name: value for name, value in kwargs.items() if name != "env"}
    assert others == {
        "capture_output": True,
        "stdin": subprocess.DEVNULL,
        "timeout": 30,
        "cwd": None,
    }
    env = kwargs.get("env")
    copied = env is not None and env is not os.environ
    assert copied, "the diff was not given an explicit copy of the environment"
    assert differing_names(env, os.environ) == []


@pytest.mark.unit
class TestGetChangedFiles:
    """Unit tests for the get_changed_files helper."""

    def test_returns_paths_on_success(self):
        fake_output = b"src/app.py\0README.md\0lib/utils.js\0"
        mock_result = MagicMock(returncode=0, stdout=fake_output)
        with patch(
            "automated_security_helper.utils.get_scan_set.subprocess.run",
            return_value=mock_result,
        ) as mock_run:
            result = get_changed_files("origin/main")

        _assert_ran_the_diff(mock_run, "origin/main")
        assert result == [Path("src/app.py"), Path("README.md"), Path("lib/utils.js")]

    def test_returns_empty_list_when_no_changes(self):
        mock_result = MagicMock(returncode=0, stdout=b"")
        with patch(
            "automated_security_helper.utils.get_scan_set.subprocess.run",
            return_value=mock_result,
        ):
            result = get_changed_files()

        assert result == []

    def test_returns_none_without_running_anything_when_git_is_not_found(
        self, monkeypatch
    ):
        monkeypatch.setattr(
            "automated_security_helper.utils.get_scan_set._git_executable",
            lambda: None,
        )
        with patch(
            "automated_security_helper.utils.get_scan_set.subprocess.run"
        ) as mock_run:
            assert get_changed_files("origin/main") is None
        mock_run.assert_not_called()

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
        mock_result = MagicMock(returncode=0, stdout=b"file.txt\0")
        with patch(
            "automated_security_helper.utils.get_scan_set.subprocess.run",
            return_value=mock_result,
        ) as mock_run:
            result = get_changed_files("origin/develop")

        _assert_ran_the_diff(mock_run, "origin/develop")
        assert result == [Path("file.txt")]

    def test_splits_on_nul_and_keeps_each_name_whole(self):
        """Only NUL separates names: spaces, newlines and tabs are part of one."""
        fake_output = b"  a.py  \0b\nc.py\0tab\tname.py\0"
        mock_result = MagicMock(returncode=0, stdout=fake_output)
        with patch(
            "automated_security_helper.utils.get_scan_set.subprocess.run",
            return_value=mock_result,
        ):
            result = get_changed_files()

        assert result == [Path("  a.py  "), Path("b\nc.py"), Path("tab\tname.py")]


def _git(cwd: Path, *args: str) -> None:
    run_git(*args, cwd=cwd, check=True, timeout=30)


@pytest.mark.integration
class TestNamesFromARealRepository:
    """What a real ``git diff`` prints for names it would quote."""

    NAMES = ["\u00fcn\u00efcode.py", "dir with space/a b.py", " leading.py", "plain.py"]

    def test_quoted_names_come_back_as_the_files(self, tmp_path, monkeypatch):
        probe = run_git("--version")
        if probe.returncode != 0:
            pytest.skip("git is not available on PATH")
        # The real git, by ASH's own lookup.
        monkeypatch.setattr(
            "automated_security_helper.utils.get_scan_set._git_executable",
            lambda: find_executable("git"),
        )
        # The host's git configuration must not decide the outcome; a global
        # core.quotepath=false would hide the quoting this test is about.
        monkeypatch.setenv("GIT_CONFIG_GLOBAL", os.devnull)
        monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / "base.txt").write_text("base\n", encoding="utf-8")
        _git(repo, "init", "-q", "-b", "main")
        _git(repo, "config", "user.email", "fixture@example.invalid")
        _git(repo, "config", "user.name", "Fixture")
        _git(repo, "add", ".")
        _git(repo, "commit", "-q", "-m", "base")
        _git(repo, "checkout", "-q", "-b", "change")
        for name in self.NAMES:
            path = repo / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("x = 1\n", encoding="utf-8")
        _git(repo, "add", ".")
        _git(repo, "commit", "-q", "-m", "change")

        changed = get_changed_files(base_ref="main", cwd=repo)

        assert changed is not None
        assert sorted(changed) == sorted(Path(name) for name in self.NAMES)
        assert all((repo / path).is_file() for path in changed)


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


@pytest.mark.unit
class TestFilterResultsToChangedFiles:
    """Unit tests for filter_results_to_changed_files."""

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

        filtered = filter_results_to_changed_files(results, changed, source_dir)
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

        filtered = filter_results_to_changed_files(results, changed, source_dir)
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

        filtered = filter_results_to_changed_files(results, changed, source_dir)
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

        filtered = filter_results_to_changed_files(results, set(), source_dir)
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

        filter_results_to_changed_files(results, set(), source_dir)

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

        filter_results_to_changed_files(results, changed, source_dir)

        assert ash_warnings() == []

    def test_result_without_locations_is_kept(self, tmp_path):
        source_dir = tmp_path / "repo"
        source_dir.mkdir()
        changed = {(source_dir / "x.py").resolve()}

        no_loc_result = Result(message=Message1(text="no location"), locations=[])
        results = _make_results_with_sarif([no_loc_result])

        filtered = filter_results_to_changed_files(results, changed, source_dir)
        assert len(filtered.sarif.runs[0].results) == 1

    def test_returns_results_unchanged_when_sarif_is_none(self):
        results = AshAggregatedResults()
        results.sarif = None
        out = filter_results_to_changed_files(results, set(), Path("/tmp"))  # nosec B108
        assert out is results

    def test_none_results_returns_none(self):
        out = filter_results_to_changed_files(None, set(), Path("/tmp"))  # nosec B108
        assert out is None


def _converted_result(uri: str, converted_path: str) -> Result:
    """A result a scanner reported in a converted file, marked as the scanner
    executor marks it (``mark_converted_results``): the ``converted_path`` property
    holds the file's path relative to the converted root."""
    result = _make_result(uri)
    result.properties = PropertyBag()
    setattr(result.properties, CONVERTED_PATH_PROPERTY, converted_path)
    return result


@pytest.mark.unit
class TestFindingsInConvertedFiles:
    """A finding in a converted file is placed by the source the converter read.

    The converted file sits in the output directory, so its own path is never in
    the changed set; before this every such finding was dropped, including those
    from a notebook or archive that was in the diff, and nothing said so.
    """

    def test_a_converted_finding_whose_source_changed_is_kept(self, tmp_path):
        source_dir = tmp_path / "repo"
        source_dir.mkdir()
        changed = {(source_dir / "nb" / "analysis.ipynb").resolve()}
        converted = tmp_path / "out" / "work" / "jupyter" / "analysis-converted.py"
        results = _make_results_with_sarif(
            [_converted_result(str(converted), "jupyter/analysis-converted.py")]
        )

        filtered = filter_results_to_changed_files(
            results,
            changed,
            source_dir,
            converted_sources={"jupyter/analysis-converted.py": "nb/analysis.ipynb"},
        )

        assert len(filtered.sarif.runs[0].results) == 1

    def test_a_converted_finding_whose_source_did_not_change_is_dropped(self, tmp_path):
        source_dir = tmp_path / "repo"
        source_dir.mkdir()
        changed = {(source_dir / "other.py").resolve()}
        converted = tmp_path / "out" / "work" / "jupyter" / "analysis-converted.py"
        results = _make_results_with_sarif(
            [_converted_result(str(converted), "jupyter/analysis-converted.py")]
        )

        filtered = filter_results_to_changed_files(
            results,
            changed,
            source_dir,
            converted_sources={"jupyter/analysis-converted.py": "nb/analysis.ipynb"},
        )

        assert filtered.sarif.runs[0].results == []

    def test_a_converted_finding_with_no_known_source_is_kept_and_said(
        self, tmp_path, ash_warnings
    ):
        """Dropping it hid a finding whose notebook may have been in the diff."""
        source_dir = tmp_path / "repo"
        source_dir.mkdir()
        changed = {(source_dir / "other.py").resolve()}
        converted = tmp_path / "out" / "work" / "jupyter" / "analysis-converted.py"
        results = _make_results_with_sarif(
            [_converted_result(str(converted), "jupyter/analysis-converted.py")]
        )

        filtered = filter_results_to_changed_files(results, changed, source_dir)

        assert len(filtered.sarif.runs[0].results) == 1
        assert any(
            "1 finding(s) located in converted files" in message
            for message in ash_warnings()
        ), ash_warnings()

    def test_a_finding_in_an_extracted_member_is_placed_by_its_archive(self, tmp_path):
        """The archive converter records its extraction directory once, with a
        trailing slash, for every member below it; a member's finding is placed by
        the archive, which is what the diff can name."""
        source_dir = tmp_path / "repo"
        source_dir.mkdir()
        member = tmp_path / "out" / "work" / "archive" / "lib__bundle__zip" / "m.js"
        results = _make_results_with_sarif(
            [_converted_result(str(member), "archive/lib__bundle__zip/m.js")]
        )
        mapping = {"archive/lib__bundle__zip/": "lib/bundle.zip"}

        unchanged = filter_results_to_changed_files(
            results,
            {(source_dir / "other.py").resolve()},
            source_dir,
            converted_sources=mapping,
        )
        assert unchanged.sarif.runs[0].results == []

        results = _make_results_with_sarif(
            [_converted_result(str(member), "archive/lib__bundle__zip/m.js")]
        )
        changed = filter_results_to_changed_files(
            results,
            {(source_dir / "lib" / "bundle.zip").resolve()},
            source_dir,
            converted_sources=mapping,
        )
        assert len(changed.sarif.runs[0].results) == 1

    def test_a_files_own_entry_wins_over_its_directorys(self, tmp_path):
        source_dir = tmp_path / "repo"
        source_dir.mkdir()
        member = tmp_path / "out" / "work" / "archive" / "a__zip" / "m.js"
        results = _make_results_with_sarif(
            [_converted_result(str(member), "archive/a__zip/m.js")]
        )

        filtered = filter_results_to_changed_files(
            results,
            {(source_dir / "own.js").resolve()},
            source_dir,
            converted_sources={
                "archive/a__zip/": "a.zip",
                "archive/a__zip/m.js": "own.js",
            },
        )

        assert len(filtered.sarif.runs[0].results) == 1


@pytest.mark.unit
class TestLocationReadings:
    """A URI is read as written and percent-decoded, and one that names no file
    places the finding nowhere rather than failing the scan."""

    def test_a_percent_encoded_uri_matches_the_file_it_names(self, tmp_path):
        """checkov writes ``out(1)/x.tf`` as ``out%281%29/x.tf``."""
        source_dir = tmp_path / "repo"
        source_dir.mkdir()
        changed = {(source_dir / "out(1)" / "x.tf").resolve()}
        results = _make_results_with_sarif([_make_result("out%281%29/x.tf")])

        filtered = filter_results_to_changed_files(results, changed, source_dir)

        assert len(filtered.sarif.runs[0].results) == 1

    def test_a_uri_spelled_with_a_literal_percent_still_matches(self, tmp_path):
        source_dir = tmp_path / "repo"
        source_dir.mkdir()
        changed = {(source_dir / "100%25" / "x.tf").resolve()}
        results = _make_results_with_sarif([_make_result("100%25/x.tf")])

        filtered = filter_results_to_changed_files(results, changed, source_dir)

        assert len(filtered.sarif.runs[0].results) == 1

    @pytest.mark.skipif(
        sys.platform == "win32",
        reason="a Windows file name can hold a lone surrogate, so it resolves",
    )
    def test_a_uri_the_filesystem_cannot_name_keeps_the_finding(self, tmp_path):
        """A record-form ``\\ud800`` reads back as a surrogate no POSIX name holds:
        resolving it raised UnicodeEncodeError out of the filter and failed the
        scanner whose SARIF named it."""
        source_dir = tmp_path / "repo"
        source_dir.mkdir()
        changed = {(source_dir / "other.py").resolve()}
        results = _make_results_with_sarif([_make_result("odd\\ud800name.py")])

        filtered = filter_results_to_changed_files(results, changed, source_dir)

        assert len(filtered.sarif.runs[0].results) == 1

    def test_a_uri_holding_an_encoded_nul_keeps_the_finding(self, tmp_path):
        """``%00`` decodes to a NUL no path holds; the literal reading is a name."""
        source_dir = tmp_path / "repo"
        source_dir.mkdir()
        changed = {(source_dir / "a%00b.py").resolve()}
        results = _make_results_with_sarif([_make_result("a%00b.py")])

        filtered = filter_results_to_changed_files(results, changed, source_dir)

        assert len(filtered.sarif.runs[0].results) == 1

    @pytest.mark.skipif(
        sys.platform == "win32",
        reason="a Windows file name is UTF-16; the byte-wise percent form is POSIX's",
    )
    def test_a_percent_encoded_non_utf8_name_matches_the_file_it_names(self, tmp_path):
        """``Path.as_uri()`` spells a latin-1 ``secr\\xe9t.py`` as ``secr%E9t.py``;
        decoded with ``replace`` that became ``secr\\ufffdt.py``, a name no file has,
        so the finding was dropped though the file had changed."""
        source_dir = tmp_path / "repo"
        source_dir.mkdir()
        name = os.fsdecode(b"secr\xe9t.py")
        changed = {(source_dir / name).resolve()}
        results = _make_results_with_sarif(
            [_make_result("secr%E9t.py"), _make_result("other.py")]
        )

        filtered = filter_results_to_changed_files(results, changed, source_dir)

        uris = [
            result.locations[0].physicalLocation.root.artifactLocation.uri
            for result in filtered.sarif.runs[0].results
        ]
        assert uris == ["secr%E9t.py"]


@pytest.mark.unit
class TestTheKeptCountIsSaidOnce:
    """The scan execution engine narrows the one result model after the scan phase
    and again at the report phase; a kept converted finding survives both passes,
    so the "Kept N finding(s) located in converted files" count was said twice."""

    def test_the_kept_count_is_said_once_for_one_result_model(
        self, tmp_path, ash_warnings
    ):
        source_dir = tmp_path / "repo"
        source_dir.mkdir()
        changed = {(source_dir / "other.py").resolve()}
        converted = tmp_path / "out" / "work" / "jupyter" / "analysis-converted.py"
        results = _make_results_with_sarif(
            [_converted_result(str(converted), "jupyter/analysis-converted.py")]
        )

        filter_results_to_changed_files(results, changed, source_dir)
        filter_results_to_changed_files(results, changed, source_dir)

        said = [m for m in ash_warnings() if "located in converted files" in m]
        assert len(said) == 1, ash_warnings()

    def test_a_different_model_is_told_on_its_own(self, tmp_path, ash_warnings):
        source_dir = tmp_path / "repo"
        source_dir.mkdir()
        changed = {(source_dir / "other.py").resolve()}
        converted = tmp_path / "out" / "work" / "jupyter" / "analysis-converted.py"
        for _ in range(2):
            results = _make_results_with_sarif(
                [_converted_result(str(converted), "jupyter/analysis-converted.py")]
            )
            filter_results_to_changed_files(results, changed, source_dir)

        said = [m for m in ash_warnings() if "located in converted files" in m]
        assert len(said) == 2, ash_warnings()
