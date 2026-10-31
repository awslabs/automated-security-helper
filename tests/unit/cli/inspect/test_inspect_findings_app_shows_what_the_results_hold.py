"""`ash inspect findings` shows what the results hold, as they hold it.

Each test here was red before its fix:

- a snippet's controls are written as escapes before it is cut, so the cap bounds
  what is drawn, and a CRLF line of exactly the cap is not marked truncated;
- a message is prose: its cap is on the whole text, written after its escapes,
  so a long paragraph is shown whole and a message of controls stays bounded;
- a read excerpt's line numbers are the view's own layout, right-aligned, and do
  not count toward the cap on the source; their width is measured before the
  excerpt is masked, since a masked line has no number;
- a file name recorded in its record form is read back before the file is opened,
  and the view names the file as the results record it;
- a missing rule id is shown as N/A, a message given by id alone as nothing, a null
  justification as "Not specified", never the word None;
- a scanner name that is not text names no scanner;
- a rejected or under-review SARIF suppression does not suppress;
- a saved suppression names its rule and no other, says what it covers, carries
  the reason typed, and marks every listed finding the scan's own matcher says it
  covers, a lineless entry's rule anywhere in its file included;
- a search for "none" does not match a finding without a line;
- a row key outside the list opens nothing;
- the suppression config is found from the scanned directory, and a discovery
  error there does not stop the explorer from opening;
- the command exits 1 when it has no results to show.
"""

from __future__ import annotations

import fnmatch
import os
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from textual.widgets import Static
from typer.testing import CliRunner

from automated_security_helper.cli.inspect import inspect_app
from automated_security_helper.cli.inspect import inspect_findings_app as tui
from automated_security_helper.cli.inspect.inspect_findings_app import (
    MESSAGE_CHARS,
    SNIPPET_LINE_CHARS,
    SNIPPET_LINE_CHARS_KEY,
    SNIPPET_READ_FROM,
    SNIPPET_TRUNCATED,
    FindingsExplorerApp,
    extract_findings,
)
from automated_security_helper.core.constants import ASH_DEFAULT_CONFIG_FILE_NAME
from automated_security_helper.schemas.sarif_schema_model import SarifReport

pytestmark = pytest.mark.unit


def _finding(**fields) -> dict:
    finding = {
        "rule_id": "R1",
        "severity": "low",
        "scanner": "probe",
        "message": "m",
        "suppressed": False,
    }
    finding.update(fields)
    return finding


def _findings_of(**result_fields) -> list:
    """extract_findings over one result built from the real SARIF schema."""
    result = {
        "message": {"text": "a finding"},
        "properties": {"scanner_details": {"tool_name": "bandit"}},
    }
    result.update(result_fields)
    report = SarifReport.model_validate(
        {
            "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "t"}}, "results": [result]}],
        }
    )
    return extract_findings(SimpleNamespace(sarif=report))


#: A file name holding one byte that is not UTF-8, as the bytes a POSIX file
#: system stores; its record form in a results file is "caf\\udce9.py".
_NON_UTF8_NAME = b"caf\xe9.py"


def _write_a_non_utf8_name(root) -> None:
    """One line of source in a file named _NON_UTF8_NAME under *root*, or a skip
    where the file system will not hold that name as given.

    Linux file systems store the bytes; APFS refuses a name that is not UTF-8
    (the open fails), and a file system that respelled the name would make the
    record form name no file. Either is the file system's shape, not the
    product's, so the test is skipped there with the reason.
    """
    try:
        with open(os.path.join(os.fsencode(root), _NON_UTF8_NAME), "wb") as handle:
            handle.write(b"x = 1\n")
    except OSError as exc:
        pytest.skip(f"this file system refuses a file name that is not UTF-8: {exc}")
    if _NON_UTF8_NAME not in os.listdir(os.fsencode(root)):
        pytest.skip("this file system stores a non-UTF-8 name under another spelling")


# --- the snippet cap -------------------------------------------------------------


def test_a_snippets_controls_are_escaped_before_it_is_cut():
    """A line of 500 control characters is drawn as 2,000 characters of escapes;
    cut first, the cap the view was sized against bounded nothing."""
    shown = tui._snippet("\x01" * SNIPPET_LINE_CHARS, None)

    lines = shown.plain.split("\n")
    assert lines[-1] == SNIPPET_TRUNCATED
    assert all(len(line) <= SNIPPET_LINE_CHARS for line in lines), [
        len(line) for line in lines
    ]


def test_a_crlf_line_of_exactly_the_cap_is_shown_whole():
    shown = tui._snippet("x" * SNIPPET_LINE_CHARS + "\r\n" + "y", None)

    assert shown.plain.split("\n") == ["x" * SNIPPET_LINE_CHARS, "y"]


def test_a_read_excerpts_line_numbers_do_not_count_toward_the_cap():
    excerpt = f"→ 10: {'a' * SNIPPET_LINE_CHARS}\n  11: short\n"
    cut = tui._cut_excerpt_lines(excerpt)

    shown = tui._snippet(cut, None, tui._excerpt_line_chars(cut))

    assert shown.plain.split("\n")[0] == f"→ 10: {'a' * SNIPPET_LINE_CHARS}"
    assert SNIPPET_TRUNCATED not in shown.plain


def test_a_read_excerpt_line_over_the_cap_keeps_the_cap_of_source():
    excerpt = f"→ 10: {'a' * (SNIPPET_LINE_CHARS + 40)}\n  11: short\n"
    cut = tui._cut_excerpt_lines(excerpt)

    shown = tui._snippet(cut, None, tui._excerpt_line_chars(cut))

    lines = shown.plain.split("\n")
    assert lines[0] == f"→ 10: {'a' * SNIPPET_LINE_CHARS}"
    assert lines[-1] == SNIPPET_TRUNCATED


def test_excerpt_line_numbers_are_right_aligned(tmp_path):
    (tmp_path / "a.py").write_text(
        "".join(f"v{n} = {n}\n" for n in range(1, 13)), encoding="utf-8"
    )

    excerpt = tui._source_excerpt({"file": "a.py", "line": 10}, tmp_path)

    assert excerpt is not None
    lines = [line for line in excerpt.split("\n") if line]
    assert lines[0] == "   5: v5 = 5"
    assert "→ 10: v10 = 10" in lines
    assert len({len(line.partition(": ")[0]) for line in lines}) == 1, lines


@pytest.mark.skipif(
    sys.platform == "win32", reason="a file name that is not UTF-8 is a POSIX name"
)
def test_a_record_form_name_is_read_back_before_the_file_is_opened(tmp_path):
    """A name with a byte that is not UTF-8 is recorded as text in its record form
    (utils/undecodable_text.py); opened as those six characters it was not found."""
    _write_a_non_utf8_name(tmp_path)

    excerpt = tui._source_excerpt({"file": "caf\\udce9.py", "line": 1}, tmp_path)

    assert excerpt == "→ 1: x = 1\n"


# --- values the results do not hold ----------------------------------------------


def test_a_missing_rule_id_or_message_is_never_drawn_as_the_word_none():
    finding = _finding(rule_id=None, message=None)

    assert tui._display_value(None) == "N/A"
    assert tui._named_finding(finding, status=False).plain.split("\n")[0] == "N/A"
    (title,) = tui._finding_cells(finding, ["finding"])
    assert title.plain.startswith("N/A")
    assert "None" not in title.plain


def test_a_message_given_by_id_alone_reads_as_no_text():
    assert _findings_of(message={"id": "msg1"})[0]["message"] == ""


def test_a_scanner_name_that_is_not_text_is_no_name():
    findings = _findings_of(
        properties={
            "scanner_name": ["bandit-sast"],
            "scanner_details": {"tool_name": "bandit"},
        }
    )

    assert [f["scanner"] for f in findings] == ["bandit"]


@pytest.mark.parametrize("state", ["rejected", "underReview"])
def test_a_suppression_that_is_rejected_or_under_review_does_not_suppress(state):
    findings = _findings_of(suppressions=[{"kind": "external", "state": state}])

    assert findings[0]["suppressed"] is False
    assert "suppression_reason" not in findings[0]


def test_the_justification_shown_is_an_applying_suppressions():
    findings = _findings_of(
        suppressions=[
            {"kind": "external", "state": "rejected", "justification": "no"},
            {"kind": "inSource", "state": "accepted", "justification": "ok"},
        ]
    )

    assert findings[0]["suppressed"] is True
    assert findings[0]["suppression_reason"] == "ok"


@pytest.mark.parametrize(
    "suppression",
    [
        pytest.param({"kind": "external"}, id="no-justification"),
        pytest.param({"kind": "external", "justification": None}, id="null"),
    ],
)
def test_a_missing_justification_reads_not_specified(suppression):
    findings = _findings_of(suppressions=[suppression])

    assert findings[0]["suppressed"] is True
    assert findings[0]["suppression_reason"] == "Not specified"


# --- the saved suppression ---------------------------------------------------------


def test_a_saved_rule_id_names_its_rule_and_no_other():
    pattern = tui._suppression_rule_id("CKV[1]*?")

    assert pattern == "CKV[[]1][*][?]"
    assert fnmatch.fnmatchcase("ckv[1]*?", pattern.lower())
    assert not fnmatch.fnmatchcase("ckv1xy", pattern.lower())
    assert tui._suppression_rule_id("B105") == "B105"


def test_the_dialog_says_a_lineless_suppression_covers_the_whole_file():
    assert "anywhere in this file" in tui._suppression_scope_note(_finding(line=None))
    assert "anywhere" not in tui._suppression_scope_note(_finding(line=3))


def test_the_scope_note_describes_the_entry_the_dialog_saves():
    """A line the dialog does not write (a missing key, or a line of 0, which it
    reads as none) is one the note calls the whole file; the two read one test."""
    for finding in (_finding(), _finding(line=0), _finding(line=None)):
        entry = tui._suppression_for(dict(finding, file="a.py"), "r")
        assert entry.line_start is None, finding
        assert "anywhere in this file" in tui._suppression_scope_note(finding)
    entry = tui._suppression_for(_finding(file="a.py", line=7), "r")
    assert (entry.line_start, entry.line_end) == (7, 7)
    assert "anywhere" not in tui._suppression_scope_note(_finding(line=7))


def test_the_saved_entry_is_the_one_the_dialog_describes():
    entry = tui._suppression_for(
        _finding(rule_id="CKV[1]", file="./x[1].py", line=3), "r"
    )

    assert entry.rule_id == "CKV[[]1]"
    assert entry.path == "x[[]1].py"
    assert entry.reason == "r"


def test_every_listed_finding_the_saved_entry_covers_is_marked():
    """Covered as the scan decides it: the entry's rule pattern read without regard
    to case, at the folded file, on the one line."""
    chosen = _finding(file="./src/a.py", line=3)
    twin = _finding(file="src/a.py", line=3)
    other_case = _finding(rule_id="r1", file="src/a.py", line=3)
    other_line = _finding(file="src/a.py", line=4)
    other_rule = _finding(rule_id="R2", file="src/a.py", line=3)
    other_file = _finding(file="src/b.py", line=3)
    no_file = _finding(line=3)
    listed = [chosen, twin, other_case, other_line, other_rule, other_file, no_file]

    covered = tui._findings_suppressed_by(listed, tui._suppression_for(chosen, "r"))

    assert covered == [chosen, twin, other_case]


def test_a_lineless_entry_marks_the_rule_anywhere_in_the_file():
    chosen = _finding(file="src/a.py")
    on_a_line = _finding(file="src/a.py", line=4)
    other_file = _finding(file="src/b.py", line=4)

    covered = tui._findings_suppressed_by(
        [chosen, on_a_line, other_file], tui._suppression_for(chosen, "r")
    )

    assert covered == [chosen, on_a_line]


def test_a_rule_id_with_glob_characters_marks_only_its_own_rule():
    chosen = _finding(rule_id="CKV[1]", file="src/a.py", line=3)
    glob_twin = _finding(rule_id="CKV1", file="src/a.py", line=3)

    covered = tui._findings_suppressed_by(
        [chosen, glob_twin], tui._suppression_for(chosen, "r")
    )

    assert covered == [chosen]


# --- the explorer's handlers -------------------------------------------------------


def test_a_search_for_none_does_not_match_a_finding_without_a_line(tmp_path):
    without_line = _finding()
    named_none = _finding(rule_id="none-rule", line=2)
    app = FindingsExplorerApp(
        [without_line, named_none], config_path=tmp_path / ASH_DEFAULT_CONFIG_FILE_NAME
    )
    app.filtered_findings = list(app.findings)
    app.search_query = "none"

    app._apply_search()

    assert app.filtered_findings == [named_none]


def test_a_row_key_outside_the_list_opens_nothing(tmp_path):
    app = FindingsExplorerApp(
        [_finding()], config_path=tmp_path / ASH_DEFAULT_CONFIG_FILE_NAME
    )
    app._show_detail = MagicMock()
    event = MagicMock()
    event.row_key.value = 5

    app.on_data_table_row_selected(event)

    app._show_detail.assert_not_called()


# --- the suppression config --------------------------------------------------------


def test_the_suppression_config_is_found_from_the_scanned_directory(
    tmp_path, monkeypatch
):
    scanned = tmp_path / "project"
    # A discovered name under .ash/ (ASH_CONFIG_FILE_NAMES are read at the root
    # and in .ash/; the ashrc names only at the root).
    config = scanned / ".ash" / ".ash.yaml"
    config.parent.mkdir(parents=True)
    config.write_text("project_name: p\n", encoding="utf-8")
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)

    assert tui._resolve_suppression_config_path(None, scanned) == config


def test_a_config_discovery_error_leaves_the_default_path(
    tmp_path, monkeypatch, capsys
):
    monkeypatch.setattr(
        tui, "find_config_file", MagicMock(side_effect=OSError("unreadable"))
    )

    resolved = tui._resolve_suppression_config_path(None, tmp_path)

    assert resolved == tmp_path / ASH_DEFAULT_CONFIG_FILE_NAME
    assert "Could not find a config file for suppressions" in capsys.readouterr().err


# --- the command's exit code -------------------------------------------------------


def test_the_command_exits_1_when_there_are_no_results(tmp_path):
    result = CliRunner().invoke(
        inspect_app, ["findings", "--output-dir", str(tmp_path)]
    )

    assert result.exit_code == 1, result.output
    assert "No model or report file available" in result.output


def test_the_command_exits_1_when_the_results_do_not_load(tmp_path):
    (tmp_path / "ash_aggregated_results.json").write_text("{}", encoding="utf-8")
    with patch.object(
        tui.AshAggregatedResults, "load_model", side_effect=FileNotFoundError("gone")
    ):
        result = CliRunner().invoke(
            inspect_app, ["findings", "--output-dir", str(tmp_path)]
        )

    assert result.exit_code == 1, result.output
    assert "Error loading model or report" in result.output


# --- the detail view ---------------------------------------------------------------


async def _settle(pilot, turns: int = 6) -> None:
    for _ in range(turns):
        await pilot.pause()


def _texts(widgets) -> list:
    return [getattr(widget.content, "plain", str(widget.content)) for widget in widgets]


def test_a_message_written_as_one_paragraph_is_shown_whole():
    """Prose wraps: a paragraph longer than a snippet line is no line to cut."""
    paragraph = "w" * (SNIPPET_LINE_CHARS * 3)

    assert tui._shown_prose(paragraph).plain == paragraph


def test_a_message_over_the_cap_ends_truncated_after_the_cap():
    shown = tui._shown_prose("m" * (MESSAGE_CHARS + 1)).plain

    assert shown == "m" * MESSAGE_CHARS + "\n" + SNIPPET_TRUNCATED


def test_a_messages_controls_are_escaped_before_it_is_cut():
    """A message of control characters is drawn as escapes, four characters each;
    cut first, the cap bounded a quarter of what was drawn."""
    shown = tui._shown_prose("\x01" * MESSAGE_CHARS).plain

    assert "\x01" not in shown
    assert len(shown) <= MESSAGE_CHARS + 1 + len(SNIPPET_TRUNCATED)
    assert shown.endswith(SNIPPET_TRUNCATED)


@pytest.mark.asyncio
async def test_the_detail_view_shows_the_message_through_the_prose_cap(tmp_path):
    message = "w" * (SNIPPET_LINE_CHARS + 100)
    app = FindingsExplorerApp(
        [_finding(message=message, file="a.py", line=1)],
        config_path=tmp_path / ASH_DEFAULT_CONFIG_FILE_NAME,
    )
    async with app.run_test(size=(160, 50)) as pilot:
        await _settle(pilot)
        await pilot.press("v")
        await _settle(pilot)
        texts = _texts(app.screen.query(Static))

    assert message in texts, [len(text) for text in texts]


@pytest.mark.asyncio
async def test_the_view_says_which_file_read_lines_came_from(tmp_path):
    root = tmp_path / "repo"
    (root / "src").mkdir(parents=True)
    (root / "src" / "a.py").write_text("x = 1\ny = 2\n", encoding="utf-8")
    app = FindingsExplorerApp(
        [_finding(file="src/a.py", line=2)],
        config_path=tmp_path / ASH_DEFAULT_CONFIG_FILE_NAME,
        scan_root=root,
    )
    async with app.run_test(size=(160, 50)) as pilot:
        await _settle(pilot)
        await pilot.press("v")
        await _settle(pilot)
        notices = _texts(app.screen.query(".notice"))

    read_from = str(Path(root) / "src" / "a.py")
    assert any(n.startswith("Read from ") and read_from in n for n in notices), notices


@pytest.mark.asyncio
async def test_the_shown_line_width_is_measured_before_the_lines_are_masked(tmp_path):
    """A masker replaces a line whole, its number and marker included; measured
    after it, the first line's missing prefix read as a prefix of its whole
    length and widened every line of the excerpt."""
    root = tmp_path / "repo"
    root.mkdir()
    (root / "a.py").write_text(
        "".join(f"v{n} = {n}\n" for n in range(1, 13)), encoding="utf-8"
    )
    finding = _finding(file="a.py", line=10)

    def mask_first_line(_file, _first, excerpt):
        return "\n".join(["(masked)"] + excerpt.split("\n")[1:])

    app = FindingsExplorerApp(
        [finding],
        config_path=tmp_path / ASH_DEFAULT_CONFIG_FILE_NAME,
        scan_root=root,
        mask_source=mask_first_line,
    )
    async with app.run_test(size=(160, 50)) as pilot:
        await _settle(pilot)
        await pilot.press("v")
        await _settle(pilot)

    # Lines 5 to 12 are shown, so every number is two wide: "   5: " is six.
    assert finding["code_snippet"].startswith("(masked)\n")
    assert finding[SNIPPET_LINE_CHARS_KEY] == SNIPPET_LINE_CHARS + len("   5: ")


@pytest.mark.skipif(
    sys.platform == "win32", reason="a file name that is not UTF-8 is a POSIX name"
)
@pytest.mark.asyncio
async def test_the_read_from_path_is_the_name_as_the_results_record_it(tmp_path):
    """The file is opened by the name read back from its record form; the view
    names it as the results spell it, the six characters of the record form, not
    the read-back name, whose lone surrogate drew as an escape of its own."""
    root = tmp_path / "repo"
    root.mkdir()
    _write_a_non_utf8_name(root)
    finding = _finding(file="caf\\udce9.py", line=1)
    app = FindingsExplorerApp(
        [finding], config_path=tmp_path / ASH_DEFAULT_CONFIG_FILE_NAME, scan_root=root
    )
    async with app.run_test(size=(160, 50)) as pilot:
        await _settle(pilot)
        await pilot.press("v")
        await _settle(pilot)

    assert finding["code_snippet"] == "→ 1: x = 1\n"
    assert finding[SNIPPET_READ_FROM] == str(root / "caf\\udce9.py")
