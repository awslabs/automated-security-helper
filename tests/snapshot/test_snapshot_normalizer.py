# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The shared normalizer masks what varies between runs and nothing a user reads.

Both halves are asserted. A normalizer that masks too little makes snapshots flaky; one
that masks too much makes them pass over a real change, which is worse because nothing
reports it. So every masking rule below has a paired "this survives" case.
"""

from __future__ import annotations

import json
from datetime import date
from pathlib import Path, PureWindowsPath

import pytest

from tests.snapshot.support.normalize import (
    REPO_ROOT,
    SnapshotNormalizer,
    default_normalizer,
)


@pytest.fixture
def normalizer(tmp_path: Path) -> SnapshotNormalizer:
    return default_normalizer(tmp_paths=[tmp_path])


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

    def test_repo_root(self, normalizer):
        assert normalizer.text(str(REPO_ROOT / "ash")) == "<REPO>/ash"

    def test_timestamps_report_ids_and_today(self, normalizer):
        today = date.today().isoformat()
        out = normalizer.text(
            f"at 2026-10-05T12:34:56+00:00 and 2026-10-05 12:34:56Z id ASH-20261005123456 "
            f"day {today}"
        )
        assert out == "at <TIMESTAMP> and <TIMESTAMP> id ASH-<REPORT_ID> day <TODAY>"

    @pytest.mark.parametrize(
        "duration", ["1.25s", "350ms", "3 seconds", "0:00:01", "1m 2s", "12 sec"]
    )
    def test_durations(self, normalizer, duration):
        assert normalizer.text(f"took {duration}.") == "took <DURATION>."

    def test_uuid_version_and_hostname(self, normalizer):
        n = SnapshotNormalizer()
        n.add_literal("9.9.9-test", "ASH_VERSION")
        n.add_literal("build-host-01", "HOSTNAME")
        out = n.text(
            "ASH 9.9.9-test on build-host-01 run 123e4567-e89b-12d3-a456-426614174000"
        )
        assert out == "ASH <ASH_VERSION> on <HOSTNAME> run <UUID>"

    def test_volatile_keys_in_data(self, normalizer):
        data = {"duration": 1.5, "start_time": "x", "count": 3, "nested": [{"time": 2}]}
        assert normalizer.data(data) == {
            "duration": "<DURATION>",
            "start_time": "<START_TIME>",
            "count": 3,
            "nested": [{"time": "<TIME>"}],
        }

    def test_volatile_keys_in_json_text(self, normalizer):
        text = json.dumps(
            {"time": 1791220796403, "metadata": {"logged_time": 1791220796403}},
            indent=2,
        )
        assert json.loads(normalizer.text(text)) == {
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


class TestSurvives:
    """What a user reads. A rule that ate any of these would hide a real change."""

    def test_counts_severities_rule_ids_and_relative_paths(self, normalizer):
        text = "CRITICAL 2  HIGH 10  B105 src/app.py:12  exit code 2"
        assert normalizer.text(text) == text

    def test_a_date_that_is_not_today(self, normalizer):
        assert normalizer.text("expires 2031-01-31") == "expires 2031-01-31"

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
