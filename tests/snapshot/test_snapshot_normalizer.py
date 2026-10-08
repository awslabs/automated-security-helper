# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The shared normalizer masks what varies between runs and nothing a user reads.

Both halves are asserted. A normalizer that masks too little makes snapshots flaky; one
that masks too much makes them pass over a real change, which is worse because nothing
reports it. So every masking rule below has a paired "this survives" case.
"""

from __future__ import annotations

import io
import json
import logging
import tempfile
import time
import warnings
from datetime import date
from pathlib import Path, PurePosixPath, PureWindowsPath

import pytest
from rich.console import Console
from rich.logging import RichHandler

from tests.snapshot.support.normalize import (
    REPO_ROOT,
    SnapshotNormalizer,
    _file_uri,
    _path_spellings,
    default_normalizer,
)


@pytest.fixture
def normalizer(tmp_path: Path) -> SnapshotNormalizer:
    return default_normalizer(tmp_paths=[tmp_path])


@pytest.fixture
def timed(normalizer: SnapshotNormalizer) -> SnapshotNormalizer:
    """The normalizer with every time switch on, as a test that opts in to all gets it."""
    normalizer.mask_instants = True
    normalizer.mask_durations = True
    normalizer.mask_duration_keys = True
    return normalizer


class TestMasked:
    def test_ansi_and_crlf(self, normalizer):
        assert normalizer.text("\x1b[1;31mERROR\x1b[0m\r\nnext\r\n") == "ERROR\nnext\n"

    def test_tmp_path_in_every_spelling(self, normalizer, tmp_path):
        native = str(tmp_path / "out" / "ash.sarif")
        text = "\n".join(
            [
                native,
                (tmp_path / "out" / "ash.sarif").as_posix(),
                json.dumps({"p": native}),
                (tmp_path / "out" / "ash.sarif").as_uri(),
            ]
        )
        out = normalizer.text(text)
        assert str(tmp_path) not in out
        assert tmp_path.as_posix() not in out
        assert out.count("<TMP>/out/ash.sarif") == 4, out

    def test_windows_separators_after_a_token(self):
        n = SnapshotNormalizer()
        n.add_root(
            PureWindowsPath(r"C:\Users\runner\AppData\Local\Temp\pytest-1"), "TMP"
        )
        out = n.text(r"wrote C:\Users\runner\AppData\Local\Temp\pytest-1\out\ash.html")
        assert out == "wrote <TMP>/out/ash.html"

    def test_json_escaped_windows_path(self):
        n = SnapshotNormalizer()
        n.add_root(PureWindowsPath(r"C:\work\repo"), "REPO")
        payload = json.dumps({"path": r"C:\work\repo\src\app.py"})
        assert json.loads(n.text(payload)) == {"path": "<REPO>/src/app.py"}

    def test_windows_spelling_of_the_default_config_path(self, normalizer):
        # What `ash config lint` printed on windows-latest, plain and JSON-escaped.
        out = normalizer.text(
            "Linting configuration file: .ash\\.ash.yaml\n"
            + json.dumps({"config": ".ash\\.ash.yaml"})
        )
        assert out == (
            'Linting configuration file: .ash/.ash.yaml\n{"config": ".ash/.ash.yaml"}'
        )

    def test_repo_root(self, normalizer):
        assert normalizer.text(str(REPO_ROOT / "ash")) == "<REPO>/ash"

    def test_timestamps_report_ids_and_today(self, timed):
        today = date.today().isoformat()
        out = timed.text(
            f"at 2026-10-05T12:34:56+00:00 and 2026-10-05 12:34:56Z id ASH-20261005123456 "
            f"day {today}"
        )
        assert out == "at <TIMESTAMP> and <TIMESTAMP> id ASH-<REPORT_ID> day <TODAY>"

    def test_rich_log_time_column(self, normalizer):
        out = normalizer.text(
            "[10/05/26 17:22:49] INFO     Applied modification: a=b\n"
            "                    INFO     Applied modification: c=d"
        )
        assert out == (
            "[<LOG_TIME>] INFO     Applied modification: a=b\n"
            "                    INFO     Applied modification: c=d"
        )

    def test_a_root_at_a_path_boundary(self):
        n = SnapshotNormalizer()
        n.add_root(PurePosixPath("/tmp"), "SYSTEM_TMP")
        out = n.text("wrote /tmp/x and file:///tmp/y, then '/tmp' ended at /tmp.")
        assert out == (
            "wrote <SYSTEM_TMP>/x and <SYSTEM_TMP>/y, then '<SYSTEM_TMP>' ended at "
            "<SYSTEM_TMP>."
        )

    def test_mcp_results_scan_id(self, timed):
        # Minted from the wall clock on every get_scan_results call.
        out = timed.text("'scan_id': 'scan-20261005181909'")
        assert out == "'scan_id': 'scan-<SCAN_TIMESTAMP>'"

    @pytest.mark.parametrize(
        "duration", ["1.25s", "350ms", "3 seconds", "0:00:01", "1m 2s", "12 sec"]
    )
    def test_durations(self, timed, duration):
        assert timed.text(f"took {duration}.") == "took <DURATION>."

    def test_uuid_version_and_hostname(self, normalizer):
        n = SnapshotNormalizer()
        n.add_literal("9.9.9-test", "ASH_VERSION")
        n.add_literal("build-host-01", "HOSTNAME")
        out = n.text(
            "ASH 9.9.9-test on build-host-01 run 123e4567-e89b-12d3-a456-426614174000"
        )
        assert out == "ASH <ASH_VERSION> on <HOSTNAME> run <UUID>"

    @pytest.mark.parametrize(
        ("text", "expected"),
        [
            ("ASH v4.0.0", "ASH v<ASH_VERSION>"),
            ("version: 4.0.0\n", "version: <ASH_VERSION>\n"),
            (
                "automated-security-helper==4.0.0",
                "automated-security-helper==<ASH_VERSION>",
            ),
            ("'4.0.0'", "'<ASH_VERSION>'"),
            # A dependency constraint that names the same number is not ASH's version.
            ("checkov>=3.2.0,<4.0.0", "checkov>=3.2.0,<4.0.0"),
            ("cdk-nag<4.0.0,>=3.0", "cdk-nag<4.0.0,>=3.0"),
            ("x>=4.0.0", "x>=4.0.0"),
            ("x~=4.0.0", "x~=4.0.0"),
            ("x!=4.0.0", "x!=4.0.0"),
            # Nor is a longer version that contains it.
            ("14.0.0", "14.0.0"),
            ("4.0.0.1", "4.0.0.1"),
            ("4.0.01", "4.0.01"),
        ],
    )
    def test_ash_version_is_masked_only_as_a_version(self, text, expected):
        n = SnapshotNormalizer()
        n.add_version("4.0.0", "ASH_VERSION")
        assert n.text(text) == expected

    def test_volatile_keys_in_data(self, timed):
        data = {"duration": 1.5, "start_time": "x", "count": 3, "nested": [{"time": 2}]}
        assert timed.data(data) == {
            "duration": "<DURATION>",
            "start_time": "<START_TIME>",
            "count": 3,
            "nested": [{"time": "<TIME>"}],
        }

    def test_volatile_keys_in_json_text(self, timed):
        text = json.dumps(
            {"time": 1791220796403, "metadata": {"logged_time": 1791220796403}},
            indent=2,
        )
        assert json.loads(timed.text(text)) == {
            "time": "<TIME>",
            "metadata": {"logged_time": "<LOGGED_TIME>"},
        }

    def test_trailing_whitespace(self, normalizer):
        assert normalizer.text("| a |   \n| b |\t\n") == "| a |\n| b |\n"

    def test_panel_padding_after_a_masked_home(self):
        # rich pads a help panel to the terminal width, so the space count before the
        # right border would otherwise still say how long the home directory was.
        def panel_line(home: str) -> str:
            line = f"│ --bin-path  [default: {home}/.ash/bin]"
            return line + " " * (60 - len(line) - 1) + "│"

        rendered = []
        for home in ("/home/me", "C:\\Users\\runneradmin"):
            normalizer = SnapshotNormalizer()
            normalizer.add_literal(home, "HOME")
            rendered.append(normalizer.text(panel_line(home) + "\nnext"))
        assert rendered[0] == rendered[1]
        first = rendered[0].split("\n")[0]
        assert len(first) == 60
        assert first.startswith("│ --bin-path  [default: <HOME>/.ash/bin]   ")
        assert first.endswith(" │")

    @staticmethod
    def _tmp_panel_line(tmp: str, width: int) -> str:
        line = f"│ --output-dir  [default: {tmp}/ash]"
        return line + " " * (width - len(line) - 1) + "│"

    def test_panel_padding_after_a_mask_that_lengthens_the_line(self):
        # "/tmp" -> "<SYSTEM_TMP>" grows the text by 8 characters. Temp dirs shorter
        # than the token, as long, and longer all render one line, border in place.
        rendered = set()
        for tmp in ("/tmp", "/var/tmpdir1", "/private/var/folders/xy/T"):
            normalizer = SnapshotNormalizer()
            normalizer.add_root(PurePosixPath(tmp), "SYSTEM_TMP")
            rendered.add(normalizer.text(self._tmp_panel_line(tmp, 60)))
        assert len(rendered) == 1, rendered
        (line,) = rendered
        assert len(line) == 60
        assert line.startswith("│ --output-dir  [default: <SYSTEM_TMP>/ash] ")
        assert line.endswith(" │")

    def test_panel_padding_when_a_lengthened_line_no_longer_fits(self):
        # A 39-column panel: "/tmp" left 3 spaces before the border and "/tmpab" left
        # 1, and "<SYSTEM_TMP>" fits in neither. Both hosts must still produce one
        # line, with one space before the border, rather than each keeping its own
        # padding.
        rendered = set()
        for tmp in ("/tmp", "/tmpab"):
            normalizer = SnapshotNormalizer()
            normalizer.add_root(PurePosixPath(tmp), "SYSTEM_TMP")
            rendered.add(normalizer.text(self._tmp_panel_line(tmp, 39)))
        assert rendered == {"│ --output-dir  [default: <SYSTEM_TMP>/ash] │"}

    def test_panel_line_the_mask_overflows_keeps_one_space(self):
        # The masked text is wider than the panel: no pad is negative, and two hosts
        # whose short values each left a different number of spaces agree.
        rendered = set()
        for tmp, pad in (("/t", 2), ("/tm", 1)):
            normalizer = SnapshotNormalizer()
            normalizer.add_literal(tmp, "A_VERY_LONG_TOKEN")
            rendered.add(normalizer.text(f"│ {tmp}/x" + " " * pad + "│"))
        assert rendered == {"│ <A_VERY_LONG_TOKEN>/x │"}


class TestSurvives:
    """What a user reads. A rule that ate any of these would hide a real change."""

    def test_counts_severities_rule_ids_and_relative_paths(self, normalizer):
        text = "CRITICAL 2  HIGH 10  B105 src/app.py:12  exit code 2"
        assert normalizer.text(text) == text

    def test_backslashes_outside_a_registered_relative_path(self, normalizer):
        # An unregistered relative path keeps its spelling, and so does text that
        # only contains the registered one: a longer name, or a regex escape.
        text = (
            "src\\app.py  x.ash\\.ash.yaml  .ash\\.ash.yaml.bak  .ash\\.ash.yamlx  "
            "pattern \\.ash\\.ash\\.yaml"
        )
        assert normalizer.text(text) == text

    def test_add_relative_path_refuses_what_it_cannot_rewrite(self):
        n = SnapshotNormalizer()
        for path in ("/etc/ash.yaml", "ash.yaml"):
            with pytest.raises(ValueError):
                n.add_relative_path(path)

    def test_a_date_that_is_not_today(self, timed):
        assert timed.text("expires 2031-01-31") == "expires 2031-01-31"

    def test_slash_dates_outside_the_log_time_column(self, normalizer):
        text = "released 10/05/26, ratio [10/05/26], level [INFO]"
        assert normalizer.text(text) == text

    def test_box_drawing_and_emoji(self, normalizer):
        text = "┏━━━┓ 📊 ✅ ❌"
        assert normalizer.text(text) == text

    def test_panel_width_on_a_masked_line(self):
        # Only the mask's own length change is undone: a panel drawn wider is still
        # wider after masking, so a layout change on that line shows in the diff.
        normalizer = SnapshotNormalizer()
        normalizer.add_literal("/home/me", "HOME")
        narrow = normalizer.text("│ [default: /home/me/.ash]  │")
        wide = normalizer.text("│ [default: /home/me/.ash]      │")
        assert narrow == "│ [default: <HOME>/.ash]    │"
        assert wide == "│ [default: <HOME>/.ash]        │"

    def test_markdown_table_padding_after_a_masked_value(self):
        normalizer = SnapshotNormalizer()
        normalizer.add_literal("/home/me", "HOME")
        assert normalizer.text("| /home/me/x | 3 |") == "| <HOME>/x | 3 |"

    def test_numbers_that_are_not_durations(self, normalizer):
        text = "B105 v2.1.0 3 findings 10 scanners sha256 1s2"
        assert normalizer.text(text) == text

    def test_bare_numbers_under_ordinary_keys_in_json_text(self, normalizer):
        """Only the exact volatile key names: ``severity_id`` and ``time_to_fix`` stay."""
        text = json.dumps(
            {"severity_id": 4, "end_line": 12, "time_to_fix": 3, "uptime": 99}
        )
        assert normalizer.text(text) == text

    def test_bare_numbers_under_ordinary_keys(self, normalizer):
        assert normalizer.data({"finding_count": 7, "line": 12}) == {
            "finding_count": 7,
            "line": 12,
        }


class TestMaskedForErrorOutput:
    """Rules added for CLI error output, each paired with what must survive it."""

    def test_rich_traceback_panel(self, normalizer):
        text = (
            "ERROR    boom\n"
            "         ╭──── Traceback (most recent call last) ────╮\n"
            "         │ /src/run_ash_scan.py:1792 in _run_local_mode │\n"
            "         │ ❱ 1792 │ orchestrator = create(            │\n"
            "         ╰───────────────────────────────────────────╯\n"
            "         RuntimeError: boom\n"
            "ERROR (1) Exiting due to exception during ASH scan: boom\n"
        )
        assert normalizer.text(text) == (
            "ERROR    boom\n"
            "         <TRACEBACK>\n"
            "         RuntimeError: boom\n"
            "ERROR (1) Exiting due to exception during ASH scan: boom\n"
        )

    def test_rich_traceback_panel_with_safe_box(self, normalizer):
        text = (
            "┌── Traceback (most recent call last) ──┐\n"
            "│ C:\\src\\app.py:3 in main              │\n"
            "└───────────────────────────────────────┘\n"
            "ValueError: bad\n"
        )
        assert normalizer.text(text) == "<TRACEBACK>\nValueError: bad\n"

    def test_plain_traceback(self, normalizer):
        text = (
            "ash: fatal error: RuntimeError: boom\n"
            "Traceback (most recent call last):\n"
            '  File "/src/automated_security_helper/cli/main.py", line 12, in run\n'
            "    app()\n"
            "    ~~~^^\n"
            "RuntimeError: boom\n"
        )
        assert normalizer.text(text) == (
            "ash: fatal error: RuntimeError: boom\n<TRACEBACK>\nRuntimeError: boom\n"
        )

    def test_pydantic_error_url_version(self, normalizer):
        text = (
            "For further information visit https://errors.pydantic.dev/2.13/v/bool_type"
        )
        assert normalizer.text(text) == (
            "For further information visit "
            "https://errors.pydantic.dev/<PYDANTIC_VERSION>/v/bool_type"
        )

    def test_root_followed_by_a_sentence_period(self):
        n = SnapshotNormalizer()
        n.add_root(Path("/work/run-1"), "TMP")
        assert n.text("No ignore files under /work/run-1.") == (
            "No ignore files under <TMP>."
        )


class TestSurvivesErrorOutputRules:
    def test_a_root_inside_a_longer_path(self):
        n = SnapshotNormalizer()
        n.add_root(Path("/tmp"), "SYSTEM_TMP")
        text = "under /home/u/jobs/tmp/run and /tmpfoo/x"
        assert n.text(text) == text

    def test_the_word_traceback_in_a_message(self, normalizer):
        text = "Traceback (most recent call last) is not printed for usage errors.\n"
        assert normalizer.text(text) == text

    def test_box_that_is_not_a_traceback(self, normalizer):
        text = (
            "╭─ Error ──────────────────────╮\n"
            "│ Invalid value: 'pdf'         │\n"
            "╰──────────────────────────────╯\n"
        )
        assert normalizer.text(text) == text

    def test_other_urls_keep_their_versions(self, normalizer):
        text = "see https://docs.pydantic.dev/2.13/concepts/ and v2.13"
        assert normalizer.text(text) == text

    def test_scan_ids_that_are_not_a_timestamp(self, normalizer):
        # A registry scan id, a shorter digit run, and a scan- prefix glued to
        # more digits than a date-time has, all stay as written.
        text = "scan-1 scan-2026100518 scan-202610051819091 rescan-20261005181909x"
        assert normalizer.text(text) == text

    def test_a_root_inside_a_longer_path_component(self):
        # "/tmp" is the system temp dir on Linux CI and not on macOS or Windows, so
        # masking it inside another name would make one snapshot differ by OS.
        n = SnapshotNormalizer()
        n.add_root(PurePosixPath("/tmp"), "SYSTEM_TMP")
        text = "/var/tmp/a /tmpfile dir/tmpk2x_.yaml /tmp-old /tmp.d"
        assert n.text(text) == text


class TestTimeSwitches:
    """``mask_instants``, ``mask_durations``, ``mask_duration_keys``: all off by default.

    A new test sees every instant and duration it renders; each switch masks only its
    own kind of value, and only for a test that opts in.
    """

    TEXT = (
        "at 2026-10-05T12:34:56Z id ASH-20261005123456 scan-20261005181909 "
        'took 3s {"time": 1768478442000, "duration": 1.25}'
    )

    def test_all_three_default_off(self):
        n = SnapshotNormalizer()
        assert (n.mask_instants, n.mask_durations, n.mask_duration_keys) == (
            False,
            False,
            False,
        )

    def test_nothing_time_shaped_is_masked_by_default(self, normalizer):
        today = date.today().isoformat()
        text = f"{self.TEXT} day {today} poll every 5 seconds <1ms 0:00:42"
        assert normalizer.text(text) == text
        data = {"time": 1768478442000, "start_time": "x", "duration_seconds": 0.0}
        assert normalizer.data(data) == data

    def test_default_keeps_every_other_rule(self, normalizer):
        out = normalizer.text(
            "at 2026-10-05T12:34:56Z run 123e4567-e89b-12d3-a456-426614174000 took 3s"
        )
        assert out == "at 2026-10-05T12:34:56Z run <UUID> took 3s"

    def test_mask_instants_alone(self, normalizer):
        normalizer.mask_instants = True
        assert normalizer.text(self.TEXT) == (
            "at <TIMESTAMP> id ASH-<REPORT_ID> scan-<SCAN_TIMESTAMP> "
            'took 3s {"time": "<TIME>", "duration": 1.25}'
        )
        data = {"time": 1768478442000, "start_time": "x", "report_id": "r"}
        assert normalizer.data(data) == {
            "time": "<TIME>",
            "start_time": "<START_TIME>",
            "report_id": "<REPORT_ID>",
        }
        assert normalizer.data({"duration": 42.0}) == {"duration": 42.0}

    def test_mask_durations_alone(self, normalizer):
        normalizer.mask_durations = True
        assert normalizer.text(self.TEXT) == (
            "at 2026-10-05T12:34:56Z id ASH-20261005123456 scan-20261005181909 "
            'took <DURATION> {"time": 1768478442000, "duration": 1.25}'
        )

    def test_mask_duration_keys_alone(self, normalizer):
        normalizer.mask_duration_keys = True
        assert normalizer.text(self.TEXT) == (
            "at 2026-10-05T12:34:56Z id ASH-20261005123456 scan-20261005181909 "
            'took 3s {"time": 1768478442000, "duration": "<DURATION>"}'
        )
        data = {"duration": 42.0, "duration_seconds": 0.0, "elapsed": "1.5s"}
        # A string under a duration key is masked by key, like a number.
        assert normalizer.data(data) == {
            "duration": "<DURATION>",
            "duration_seconds": "<DURATION_SECONDS>",
            "elapsed": "<ELAPSED>",
        }

    def test_a_duration_string_under_a_key_follows_the_prose_rule_when_keys_are_off(
        self, normalizer
    ):
        normalizer.mask_durations = True
        assert normalizer.data({"elapsed": "1.5s", "duration": 2.0}) == {
            "elapsed": "<DURATION>",
            "duration": 2.0,
        }

    @pytest.mark.snapshot_masking(mask_instants=True)
    def test_the_marker_turns_one_switch_on(self, snapshot_normalizer):
        assert snapshot_normalizer.mask_instants is True
        assert snapshot_normalizer.mask_durations is False
        assert snapshot_normalizer.mask_duration_keys is False

    @pytest.mark.snapshot_masking(
        mask_instants=True, mask_durations=True, mask_duration_keys=True
    )
    def test_the_marker_reaches_the_fixture(self, snapshot_normalizer):
        assert snapshot_normalizer.mask_instants is True
        assert snapshot_normalizer.mask_durations is True
        assert snapshot_normalizer.mask_duration_keys is True

    def test_the_fixture_defaults_without_the_marker(self, snapshot_normalizer):
        assert snapshot_normalizer.mask_instants is False
        assert snapshot_normalizer.mask_durations is False
        assert snapshot_normalizer.mask_duration_keys is False


class TestWorkingDirectoryRoot:
    """<CWD> is registered only when it cannot shadow <REPO> or be shadowed by it."""

    def test_a_subdirectory_of_the_repo_masks_as_repo(self, monkeypatch):
        monkeypatch.chdir(REPO_ROOT / "tests" / "snapshot")
        n = default_normalizer()
        path = REPO_ROOT / "tests" / "snapshot" / "conftest.py"
        assert n.text(str(path)) == "<REPO>/tests/snapshot/conftest.py"

    def test_the_repo_root_itself_masks_as_repo(self, monkeypatch):
        monkeypatch.chdir(REPO_ROOT)
        assert default_normalizer().text(str(REPO_ROOT / "ash")) == "<REPO>/ash"

    def test_a_parent_of_the_repo_is_not_registered(self, monkeypatch):
        monkeypatch.chdir(REPO_ROOT.parent)
        out = default_normalizer().text(str(REPO_ROOT.parent / "elsewhere" / "x"))
        assert "<CWD>" not in out

    def test_a_directory_outside_the_repo_masks_as_cwd(self, monkeypatch, tmp_path):
        # Not inside the repo checkout, and not a parent of it.
        # Neither inside the repo nor a temp dir: the shared normalizer takes a fake
        # cwd so the case is reachable on any host.
        # Built from the filesystem anchor so it is absolute on Windows (C:\...) too.
        outside = Path(Path.home().anchor) / "srv-elsewhere" / "work"
        monkeypatch.setattr(Path, "cwd", classmethod(lambda cls: outside))
        out = default_normalizer().text(str(outside / "a.txt"))
        assert out == "<CWD>/a.txt"

    def test_a_cwd_inside_tmp_path_masks_as_tmp(self, monkeypatch, tmp_path):
        # Tests chdir into tmp_path before asking for the normalizer; <CWD> and <TMP>
        # would then be the same length and which one won would depend on order.
        work = tmp_path / "work"
        work.mkdir()
        monkeypatch.chdir(work)
        out = default_normalizer(tmp_paths=[tmp_path]).text(str(work / "a.txt"))
        assert out == "<TMP>/work/a.txt"


class TestFileUriSpellings:
    """The ``file://`` spelling of a pure path, built without ``PurePath.as_uri()``."""

    @pytest.mark.parametrize(
        "path, uri",
        [
            (PureWindowsPath(r"C:\Users\a b\x"), "file:///C:/Users/a%20b/x"),
            (PureWindowsPath(r"\\server\share\x"), "file://server/share/x"),
            (PurePosixPath("/tmp/a b"), "file:///tmp/a%20b"),
        ],
    )
    def test_pure_path_uri(self, path, uri):
        with warnings.catch_warnings():
            # PurePath.as_uri() warns from Python 3.14; nothing here may call it.
            warnings.simplefilter("error")
            assert uri in _path_spellings(path)

    @pytest.mark.parametrize(
        "path",
        [
            PureWindowsPath(r"C:\Users\a b\x"),
            PureWindowsPath(r"\\server\share\x"),
            PurePosixPath("/tmp/a b/é"),
        ],
    )
    def test_matches_pathlib(self, path):
        # PurePath.as_uri() is deprecated from 3.14 but still works, so it remains the
        # reference on every version; only its warning is silenced, and only here.
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            expected = path.as_uri()
        assert _file_uri(path) == expected

    def test_a_concrete_path_asks_pathlib(self, tmp_path):
        assert _file_uri(tmp_path) == tmp_path.as_uri()


class TestLogTimeColumn:
    """The console log's time column is drawn as a constant (tests/snapshot/conftest.py).

    These run through rich's real handler, so they assert what the autouse fixture does,
    not what a text rule would make of it afterwards.
    """

    @staticmethod
    def _render(created: list[float]) -> str:
        console = Console(file=io.StringIO(), width=60, color_system=None)
        handler = RichHandler(console=console, show_path=False)
        logger = logging.getLogger("snapshot-normalizer-log-time")
        logger.handlers = [handler]
        logger.propagate = False
        try:
            for i, when in enumerate(created):
                record = logger.makeRecord(
                    logger.name, logging.INFO, __file__, 1, "row %d", (i,), None
                )
                record.created = when
                handler.handle(record)
        finally:
            logger.handlers = []
        # rich pads each row to the console width; the snapshots trim it the same way.
        return "\n".join(line.rstrip() for line in console.file.getvalue().splitlines())

    def test_a_repeated_second_and_a_new_second_render_identically(self):
        same_second = self._render([1_900_000_000.1, 1_900_000_000.9])
        next_second = self._render([1_900_000_000.9, 1_900_000_001.1])
        far_apart = self._render([0.0, 1_900_000_000.0])
        assert same_second == next_second == far_apart
        assert same_second.splitlines() == [
            "[<LOG_TIME>] INFO     row 0",
            "             INFO     row 1",
        ]

    def test_the_column_ignores_the_timezone(self, monkeypatch):
        rendered = []
        for tz in ("UTC", "Pacific/Kiritimati", "America/Adak"):
            monkeypatch.setenv("TZ", tz)
            if hasattr(time, "tzset"):
                time.tzset()
            rendered.append(self._render([1_900_000_000.0, 1_900_000_000.5]))
        monkeypatch.delenv("TZ")
        if hasattr(time, "tzset"):
            time.tzset()
        assert len(set(rendered)) == 1

    def test_a_date_in_the_message_survives(self):
        console = Console(file=io.StringIO(), width=80, color_system=None)
        handler = RichHandler(console=console, show_path=False, markup=False)
        logger = logging.getLogger("snapshot-normalizer-log-time-msg")
        logger.handlers = [handler]
        logger.propagate = False
        try:
            logger.info("expires [10/05/31 17:22:49]")
        finally:
            logger.handlers = []
        assert [line.rstrip() for line in console.file.getvalue().splitlines()] == [
            "[<LOG_TIME>] INFO     expires [10/05/31 17:22:49]"
        ]


class TestTempRootsDoNotDependOnTmpdir:
    """``/tmp`` and the real temp dir mask the same way whatever TMPDIR is.

    The system temp dir used to be registered only as ``tempfile.gettempdir()``. With
    TMPDIR=/tmp, a quoted ``/tmp/stage2`` masked as ``<SYSTEM_TMP>/stage2``; with any
    other TMPDIR (a RAM disk, macOS's /var/folders, Windows) it stayed literal, so one
    snapshot could not match both hosts.
    """

    @pytest.fixture
    def elsewhere(self, tmp_path, monkeypatch):
        temp = tmp_path / "not-tmp"
        temp.mkdir()
        monkeypatch.setenv("TMPDIR", str(temp))
        monkeypatch.setenv("TEMP", str(temp))
        monkeypatch.setenv("TMP", str(temp))
        # tempfile caches its answer; clear it so gettempdir() reads the new TMPDIR.
        monkeypatch.setattr(tempfile, "tempdir", None)
        assert Path(tempfile.gettempdir()) == temp
        return temp

    def test_a_literal_tmp_path_masks_with_tmpdir_elsewhere(self, elsewhere):
        out = default_normalizer().text('wget http://x/stage2 -O /tmp/stage2"')
        assert out == 'wget http://x/stage2 -O <SYSTEM_TMP>/stage2"'

    def test_the_real_temp_dir_masks_as_the_same_token(self, elsewhere):
        out = default_normalizer().text(str(elsewhere / "scratch" / "a.txt"))
        assert out == "<SYSTEM_TMP>/scratch/a.txt"

    def test_macos_private_tmp_masks_too(self, elsewhere):
        out = default_normalizer().text("/private/tmp/stage2")
        assert out == "<SYSTEM_TMP>/stage2"

    def test_tmp_inside_a_longer_path_still_survives(self, elsewhere):
        text = "/var/tmp/a /home/u/tmp/b /tmpfile"
        assert default_normalizer().text(text) == text

    def test_tmp_path_still_wins_over_the_temp_root(self, elsewhere, tmp_path):
        out = default_normalizer(tmp_paths=[tmp_path]).text(str(tmp_path / "x"))
        assert out == "<TMP>/x"
