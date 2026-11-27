"""The terminal recording's core library: asciicast files, the storyboard, the
retimer, the scrub scan and the run record.

``scripts/_cast.py`` is the part of the recording work that has no terminal in it, so
every rule it holds is checked here on planted input:

* asciicast v2: the header fields the spec requires, the ``o`` and ``m`` event codes,
  three-decimal times that never go backwards, a reader that ignores codes it does not
  know, and a writer whose output reads back equal;
* the storyboard loader: schema 1, unknown keys refused, scene ids unique, scene starts
  as running sums, a 30 to 60 s total, a typing rate that is neither zero nor so slow
  that its arithmetic overflows, caption copy rules counted by the loader's own
  counter, and a read-only command allowlist limited to paths inside the project and
  to ls listings that print no owner or group;
* the retimer: the same input gives the same events, the scene totals are the
  storyboard's whatever the machine speed, output is shortened and never stretched, and
  a scene that does not fit its duration is refused;
* the scrub scan: a planted token is found, by its kind and never its value, including
  one that SGR runs, a line wrap or an escape sequence split;
* the run record: canonical JSON, byte for byte what ``json.dumps(sort_keys=True,
  indent=2)`` plus a newline writes;
* no ``pty``, ``termios`` or ``fcntl`` import, so the module runs, and is tested, on
  every platform.

Each refusal test plants one defect in an otherwise good input, and each detector has a
must-flag and a must-not-flag input.
"""

from __future__ import annotations

import ast
import copy
import dataclasses
import importlib
import json
import random
import sys
from pathlib import Path
from typing import Any

import pytest
import yaml

pytestmark = pytest.mark.unit

SCRIPTS = Path(__file__).resolve().parents[3] / "scripts"
MODULE = SCRIPTS / "_cast.py"


@pytest.fixture(scope="module")
def cast():
    """scripts/_cast.py, imported the way the other tests import a scripts module."""
    sys.path.insert(0, str(SCRIPTS))
    try:
        return importlib.import_module("_cast")
    finally:
        sys.path.remove(str(SCRIPTS))


# ---------------------------------------------------------------------------
# The import rule
# ---------------------------------------------------------------------------

FORBIDDEN_MODULES = frozenset({"pty", "termios", "fcntl"})


def _dynamic_import_name(call: ast.Call) -> str | None:
    """The module a ``__import__("x")`` or ``import_module("x")`` call names."""
    func = call.func
    if isinstance(func, ast.Name):
        called = func.id
    elif isinstance(func, ast.Attribute):
        called = func.attr
    else:
        return None
    if called not in {"__import__", "import_module"} or not call.args:
        return None
    first = call.args[0]
    if isinstance(first, ast.Constant) and isinstance(first.value, str):
        return first.value
    return None


def imported_roots(source: str) -> set[str]:
    """Top-level names of every module ``source`` imports, by any spelling the parser
    can see: ``import``, ``from ... import``, ``__import__("x")`` and
    ``import_module("x")``, at module level or inside any block or function."""
    roots: set[str] = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            roots.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.level == 0 and node.module:
                roots.add(node.module.split(".")[0])
        elif isinstance(node, ast.Call):
            named = _dynamic_import_name(node)
            if named:
                roots.add(named.split(".")[0])
    return roots


PLANTED_IMPORTS = {
    "import pty": {"pty"},
    "import termios as t": {"termios"},
    "import os, fcntl": {"fcntl"},
    "from pty import openpty": {"pty"},
    "from fcntl import ioctl": {"fcntl"},
    "def f():\n    import fcntl\n": {"fcntl"},
    "try:\n    import termios\nexcept ImportError:\n    termios = None\n": {"termios"},
    "__import__('pty')": {"pty"},
    "import importlib\nimportlib.import_module('termios')": {"termios"},
}

CLEAN_SOURCES = [
    "import json, re",
    "text = 'import pty'",
    "# import fcntl",
    "ptyx = 1\nempty = 2",
    "from . import pty_helpers",
    "import ptyprocess",
    "print('termios')",
]


@pytest.mark.parametrize("source", sorted(PLANTED_IMPORTS))
def test_the_import_check_flags_every_spelling(source):
    """Must-flag: each planted import is found, and only the forbidden name."""
    found = imported_roots(source) & FORBIDDEN_MODULES
    assert found == PLANTED_IMPORTS[source]


@pytest.mark.parametrize("source", CLEAN_SOURCES)
def test_the_import_check_ignores_names_that_only_look_like_the_modules(source):
    """Must-not-flag: strings, comments, relative imports and longer module names."""
    assert imported_roots(source) & FORBIDDEN_MODULES == set()


def test_the_module_imports_no_pty_termios_or_fcntl():
    roots = imported_roots(MODULE.read_text(encoding="utf-8"))
    # A scan that saw no imports at all would pass for any file.
    assert {"json", "re", "dataclasses"} <= roots
    assert roots & FORBIDDEN_MODULES == set()


def test_every_refusal_is_one_error_family(cast):
    for name in (
        "CastFileError",
        "StoryboardError",
        "RetimeError",
        "RecordError",
        "ForbiddenTokenError",
    ):
        error = getattr(cast, name)
        assert issubclass(error, cast.CastError)
    assert issubclass(cast.CastError, ValueError)


# ---------------------------------------------------------------------------
# asciicast v2
# ---------------------------------------------------------------------------

HEADER_LINE = '{"version": 2, "width": 80, "height": 24}'
THEME_COLORS = (
    "#000000",
    "#cd3131",
    "#0dbc79",
    "#e5e510",
    "#2472c8",
    "#bc3fbc",
    "#11a8cd",
    "#e5e5e5",
)
BRIGHT_COLORS = (
    "#666666",
    "#f14c4c",
    "#23d18b",
    "#f5f543",
    "#3b8eea",
    "#d670d6",
    "#29b8db",
    "#ffffff",
)
RICH_DATA = (
    "\x1b[1;35m\N{BOX DRAWINGS LIGHT DOWN AND RIGHT}"
    "\N{BOX DRAWINGS LIGHT HORIZONTAL}\x1b[0m \N{BAR CHART} "
    "caf\N{LATIN SMALL LETTER E WITH ACUTE}\r\n"
)


def _theme(cast, colors=THEME_COLORS):
    return cast.CastTheme(fg="#d4d4d4", bg="#1e1e1e", palette=colors)


def _small_cast(cast, *events, **header):
    return cast.Cast(
        header=cast.CastHeader(width=80, height=24, **header), events=tuple(events)
    )


def test_a_header_needs_version_2_width_and_height(cast):
    header = cast.CastHeader(width=100, height=30)
    assert header.version == 2
    assert header.to_json_obj() == {"version": 2, "width": 100, "height": 30}


@pytest.mark.parametrize(
    ("changes", "needle"),
    [
        ({"width": 0}, "width"),
        ({"width": -1}, "width"),
        ({"width": 80.5}, "width"),
        ({"width": True}, "width"),
        ({"height": 0}, "height"),
        ({"version": 1}, "version"),
        ({"version": 3}, "version"),
        ({"timestamp": -1}, "timestamp"),
        ({"duration": -0.5}, "duration"),
        ({"duration": float("nan")}, "duration"),
        ({"idle_time_limit": 0}, "idle_time_limit"),
        ({"command": ""}, "command"),
        ({"title": 7}, "title"),
        ({"env": {"SHELL": 1}}, "env"),
    ],
)
def test_a_header_refuses_what_the_spec_does_not_allow(cast, changes, needle):
    fields = {"width": 100, "height": 30, **changes}
    with pytest.raises(cast.CastFileError, match=needle):
        cast.CastHeader(**fields)


def test_optional_header_fields_are_written_only_when_set_and_in_a_fixed_order(cast):
    header = cast.CastHeader(
        width=100,
        height=30,
        timestamp=1700000000,
        duration=48.0,
        idle_time_limit=2.5,
        command="ash",
        title="Quick start",
        env={"TERM": "xterm-256color", "SHELL": "/bin/sh"},
        theme=_theme(cast),
    )
    obj = header.to_json_obj()
    assert list(obj) == [
        "version",
        "width",
        "height",
        "timestamp",
        "duration",
        "idle_time_limit",
        "command",
        "title",
        "env",
        "theme",
    ]
    assert list(obj["env"]) == ["SHELL", "TERM"]
    assert obj["theme"] == {
        "fg": "#d4d4d4",
        "bg": "#1e1e1e",
        "palette": ":".join(THEME_COLORS),
    }


@pytest.mark.parametrize(
    ("changes", "needle"),
    [
        ({"fg": "d4d4d4"}, "fg"),
        ({"bg": "#12345"}, "bg"),
        ({"palette": THEME_COLORS[:7]}, "8 or 16"),
        ({"palette": THEME_COLORS + ("#000000",)}, "8 or 16"),
        ({"palette": THEME_COLORS[:7] + ("red",)}, "palette"),
    ],
)
def test_a_theme_needs_fg_bg_and_8_or_16_hex_colors(cast, changes, needle):
    fields = {"fg": "#d4d4d4", "bg": "#1e1e1e", "palette": THEME_COLORS, **changes}
    with pytest.raises(cast.CastFileError, match=needle):
        cast.CastTheme(**fields)


def test_a_16_color_palette_is_accepted_and_written_colon_joined(cast):
    colors = THEME_COLORS + BRIGHT_COLORS
    assert _theme(cast, colors).to_json_obj()["palette"] == ":".join(colors)


def test_events_are_time_code_data_with_the_o_and_m_codes(cast):
    recording = _small_cast(
        cast,
        cast.CastEvent(0.0, "m", "Install"),
        cast.CastEvent(0.3, "o", "$ "),
        cast.CastEvent(1.25, "o", "ash\r\n"),
    )
    assert cast.dumps_cast(recording) == (
        '{"version": 2, "width": 80, "height": 24}\n'
        '[0.000, "m", "Install"]\n'
        '[0.300, "o", "$ "]\n'
        '[1.250, "o", "ash\\r\\n"]\n'
    )


@pytest.mark.parametrize("code", ["o", "i", "m", "r"])
def test_the_spec_event_codes_are_accepted(cast, code):
    data = "100x30" if code == "r" else "x"
    assert cast.CastEvent(0.0, code, data).code == code


def test_an_event_code_the_module_does_not_write_is_refused(cast):
    with pytest.raises(cast.CastFileError, match="event code"):
        cast.CastEvent(0.0, "x", "data")


@pytest.mark.parametrize(
    "data", ["100", "100x", "x30", "0x30", "100x0", "100 x 30", "-1x5"]
)
def test_a_resize_event_carries_cols_x_rows(cast, data):
    with pytest.raises(cast.CastFileError, match="resize"):
        cast.CastEvent(1.0, "r", data)


@pytest.mark.parametrize(
    ("seconds", "text"),
    [
        (0, "0.000"),
        (0.3, "0.300"),
        (48, "48.000"),
        (12.3456, "12.346"),
        (0.0004, "0.000"),
        (0.9996, "1.000"),
        (3600.25, "3600.250"),
    ],
)
def test_times_are_written_with_three_decimals(cast, seconds, text):
    assert cast.format_time(seconds) == text


@pytest.mark.parametrize("bad", [-0.001, float("nan"), float("inf"), True, "1.0", None])
def test_a_time_must_be_a_non_negative_number(cast, bad):
    with pytest.raises(cast.CastError):
        cast.format_time(bad)


def test_times_may_repeat_but_never_go_backwards(cast):
    header = cast.CastHeader(width=80, height=24)
    same = (cast.CastEvent(1.0, "m", "a"), cast.CastEvent(1.0, "o", "b"))
    assert cast.Cast(header=header, events=same).events == same
    backwards = (cast.CastEvent(1.0, "o", "a"), cast.CastEvent(0.999, "o", "b"))
    with pytest.raises(cast.CastFileError, match="earlier than"):
        cast.Cast(header=header, events=backwards)


def test_a_cast_reads_back_equal_and_the_file_is_ascii(cast):
    recording = _small_cast(
        cast,
        cast.CastEvent(0.0, "m", "Install \N{BAR CHART}"),
        cast.CastEvent(0.3, "o", RICH_DATA),
        cast.CastEvent(1.25, "o", "tab\there\x1b[2J"),
        cast.CastEvent(2.0, "r", "100x30"),
        timestamp=1700000000,
        duration=2.5,
        idle_time_limit=1.5,
        command="ash --version",
        title="Quick start",
        env={"TERM": "xterm-256color"},
        theme=_theme(cast),
    )
    text = cast.dumps_cast(recording)
    assert text.isascii()
    assert text.endswith("]\n")
    assert "\r" not in text
    assert cast.loads_cast(text) == recording
    assert cast.dumps_cast(cast.loads_cast(text)) == text


def test_a_cast_file_is_written_with_unix_newlines_and_read_back(cast, tmp_path):
    recording = _small_cast(cast, cast.CastEvent(0.0, "o", "line\r\n"))
    path = tmp_path / "x.cast"
    cast.write_cast(path, recording)
    assert path.read_bytes() == cast.dumps_cast(recording).encode("ascii")
    assert b"\r" not in path.read_bytes()
    assert cast.read_cast(path) == recording


def test_a_reader_ignores_event_codes_it_does_not_know(cast):
    text = (
        HEADER_LINE
        + '\n[0.5, "o", "a"]\n[0.6, "x", "mystery"]\n[0.7, "m", "label"]'
        + '\n[0.8, "r", "100x30"]\n[0.9, "i", "k"]\n'
    )
    recording = cast.loads_cast(text)
    assert [(e.code, e.data) for e in recording.events] == [
        ("o", "a"),
        ("m", "label"),
        ("r", "100x30"),
        ("i", "k"),
    ]


def test_a_reader_ignores_header_keys_it_does_not_know(cast):
    text = '{"version": 2, "width": 80, "height": 24, "future": [1]}\n'
    assert cast.loads_cast(text).header == cast.CastHeader(width=80, height=24)


@pytest.mark.parametrize(
    ("text", "needle"),
    [
        ("", "empty"),
        ("\n", "empty"),
        ("not json\n", "line 1: not valid JSON"),
        ("[1, 2]\n", "header must be"),
        ('{"version": 3, "width": 80, "height": 24}\n', "version"),
        ('{"version": 2, "height": 24}\n', "lacks"),
        ('{"version": 2, "width": 80}\n', "lacks"),
        (HEADER_LINE + '\n[0.5, "o"]\n', "line 2"),
        (HEADER_LINE + '\n{"time": 1}\n', "line 2"),
        (HEADER_LINE + '\n[0.5, "o", 7]\n', "data"),
        (HEADER_LINE + '\n["0.5", "o", "x"]\n', "time"),
        (HEADER_LINE + '\n[-1, "o", "x"]\n', "time"),
        (HEADER_LINE + '\n[0.5, 7, "x"]\n', "code"),
        (HEADER_LINE + '\n[NaN, "o", "x"]\n', "NaN"),
        (HEADER_LINE + '\n\n[0.5, "o", "x"]\n', "line 2: not valid JSON"),
        (HEADER_LINE + '\n[1.0, "o", "a"]\n[0.5, "o", "b"]\n', "earlier than"),
    ],
)
def test_a_reader_refuses_a_file_that_is_not_asciicast_v2(cast, text, needle):
    with pytest.raises(cast.CastFileError, match=needle):
        cast.loads_cast(text)


# ---------------------------------------------------------------------------
# The storyboard
# ---------------------------------------------------------------------------

DESIGN_STORYBOARD = """\
schema: 1
journey: docs/journeys/getting-started-local.journey.yaml
terminal: {cols: 100, rows: 30, prompt: "$ "}
typing: {chars_per_second: 30, lead_in_s: 0.3}
output: {max_gap_s: 0.8}
poster_scene: scan
playback: once            # or loop
scenes:
  - {id: install, caption: "Install from a release tag", duration_s: 6.0,
     comment_from: README.md#quick-start-install, hold_s: 2.5}
  - {id: version, caption: "Check the install", duration_s: 4.0,
     block: version, hold_s: 2.0, expect_screen: ["awslabs/automated-security-helper v"]}
  - {id: project, caption: "A small Python project", duration_s: 5.0,
     hidden_blocks: [project], command: "cat app.py", clear: true, hold_s: 2.5}
  - {id: scan, caption: "Scan with bandit and detect-secrets", duration_s: 16.0,
     block: scan-two, clear: true, output_window_s: 9.0, hold_s: 5.0,
     expect_screen: ["ASH Scan Results Summary", "bandit", "detect-secrets", "Exiting due to"]}
  - {id: report, caption: "Read the findings", duration_s: 12.0,
     block: report, clear: true, output_window_s: 6.0, hold_s: 5.0, expect_screen: ["B324"]}
  - {id: reports, caption: "Where the reports live", duration_s: 5.0,
     command: "ls .ash/ash_output/reports", hold_s: 3.0}
"""
JOURNEY_IDS = frozenset({"version", "project", "scan-two", "report"})
GOOD_STORYBOARD = yaml.safe_load(DESIGN_STORYBOARD)


def _good() -> dict[str, Any]:
    return copy.deepcopy(GOOD_STORYBOARD)


def _scene(data: dict[str, Any], scene_id: str) -> dict[str, Any]:
    return next(scene for scene in data["scenes"] if scene["id"] == scene_id)


def _node(data: Any, path: tuple) -> Any:
    for step in path:
        data = data[step]
    return data


def _parse(cast, data, journey_ids=JOURNEY_IDS):
    return cast.parse_storyboard(data, journey_ids, source="storyboard.yaml")


def _two_scenes(first_s: float, second_s: float) -> dict[str, Any]:
    """The good storyboard with two one-word scenes of the given lengths."""
    data = _good()
    data["poster_scene"] = "a"
    data["scenes"] = [
        {
            "id": "a",
            "caption": "First",
            "duration_s": first_s,
            "comment_from": "README.md#a",
            "hold_s": 0.5,
        },
        {
            "id": "b",
            "caption": "Second",
            "duration_s": second_s,
            "comment_from": "README.md#b",
            "hold_s": 0.5,
        },
    ]
    return data


def test_the_design_storyboard_loads_with_running_sum_starts(cast, tmp_path):
    path = tmp_path / "getting-started-local.cast.yaml"
    path.write_text(DESIGN_STORYBOARD, encoding="utf-8")
    board = cast.load_storyboard(path, JOURNEY_IDS)
    assert board.journey == "docs/journeys/getting-started-local.journey.yaml"
    assert board.terminal.cols == 100
    assert board.terminal.rows == 30
    assert board.terminal.prompt == "$ "
    assert board.typing.chars_per_second == 30
    assert board.typing.lead_in_ms == 300
    assert board.output.max_gap_ms == 800
    assert board.poster_scene == "scan"
    assert board.playback == "once"
    assert [scene.scene_id for scene in board.scenes] == [
        "install",
        "version",
        "project",
        "scan",
        "report",
        "reports",
    ]
    assert [scene.start_ms for scene in board.scenes] == [
        0,
        6000,
        10000,
        15000,
        31000,
        43000,
    ]
    assert [scene.duration_ms for scene in board.scenes] == [
        6000,
        4000,
        5000,
        16000,
        12000,
        5000,
    ]
    assert [scene.end_ms for scene in board.scenes] == [
        6000,
        10000,
        15000,
        31000,
        43000,
        48000,
    ]
    assert board.total_ms == 48000
    assert board.total_s == 48.0


def test_scene_fields_are_read_as_written(cast):
    board = _parse(cast, _good())
    install, version, project, scan, _report, reports = board.scenes
    assert install.comment_from == "README.md#quick-start-install"
    assert install.block is None
    assert install.command is None
    assert install.hold_ms == 2500
    assert version.block == "version"
    assert version.clear is False
    assert version.output_window_ms is None
    assert version.expect_screen == ("awslabs/automated-security-helper v",)
    assert project.hidden_blocks == ("project",)
    assert project.command == "cat app.py"
    assert project.clear is True
    assert scan.block == "scan-two"
    assert scan.output_window_ms == 9000
    assert scan.hold_ms == 5000
    assert scan.expect_screen == (
        "ASH Scan Results Summary",
        "bandit",
        "detect-secrets",
        "Exiting due to",
    )
    assert reports.command == "ls .ash/ash_output/reports"
    assert board.scene("scan") is scan
    with pytest.raises(cast.StoryboardError, match="no scene"):
        board.scene("nope")


def test_the_loaders_counter_reads_the_design_captions(cast):
    board = _parse(cast, _good())
    assert [scene.words for scene in board.scenes] == [5, 3, 4, 5, 3, 4]
    assert cast.count_words("a  b\tc\n") == 3
    assert cast.count_words("") == 0


def test_parsing_leaves_its_input_untouched(cast):
    data = _good()
    before = copy.deepcopy(data)
    _parse(cast, data)
    assert data == before


def test_a_missing_or_malformed_storyboard_file_is_refused_by_name(cast, tmp_path):
    with pytest.raises(cast.StoryboardError, match="cannot be read"):
        cast.load_storyboard(tmp_path / "nope.cast.yaml", JOURNEY_IDS)
    broken = tmp_path / "broken.cast.yaml"
    broken.write_text("scenes: [unclosed\n", encoding="utf-8")
    with pytest.raises(cast.StoryboardError, match="not valid YAML") as caught:
        cast.load_storyboard(broken, JOURNEY_IDS)
    assert "broken.cast.yaml" in str(caught.value)
    listing = tmp_path / "list.cast.yaml"
    listing.write_text("- a\n- b\n", encoding="utf-8")
    with pytest.raises(cast.StoryboardError, match="must be a mapping"):
        cast.load_storyboard(listing, JOURNEY_IDS)


@pytest.mark.parametrize("bad", [None, [1], "text", 5])
def test_a_storyboard_must_be_a_mapping(cast, bad):
    with pytest.raises(cast.StoryboardError, match="must be a mapping"):
        _parse(cast, bad)


@pytest.mark.parametrize(
    "path", [(), ("terminal",), ("typing",), ("output",), ("scenes", 0)]
)
def test_unknown_keys_are_refused_at_every_level(cast, path):
    data = _good()
    _node(data, path)["extra"] = 1
    with pytest.raises(
        cast.StoryboardError, match=r"unknown key\(s\) \['extra'\]; schema 1 allows"
    ):
        _parse(cast, data)


def test_scene_starts_are_computed_and_cannot_be_written(cast):
    data = _good()
    _scene(data, "scan")["start_s"] = 15.0
    with pytest.raises(cast.StoryboardError, match=r"unknown key\(s\) \['start_s'\]"):
        _parse(cast, data)


@pytest.mark.parametrize(
    ("path", "key"),
    [
        ((), "schema"),
        ((), "journey"),
        ((), "terminal"),
        ((), "typing"),
        ((), "output"),
        ((), "poster_scene"),
        ((), "playback"),
        ((), "scenes"),
        (("terminal",), "rows"),
        (("terminal",), "prompt"),
        (("typing",), "lead_in_s"),
        (("typing",), "chars_per_second"),
        (("output",), "max_gap_s"),
        (("scenes", 0), "id"),
        (("scenes", 0), "caption"),
        (("scenes", 0), "duration_s"),
    ],
)
def test_a_missing_required_key_is_refused(cast, path, key):
    data = _good()
    del _node(data, path)[key]
    with pytest.raises(cast.StoryboardError, match=rf"missing key\(s\) \['{key}'\]"):
        _parse(cast, data)


@pytest.mark.parametrize("schema", [2, 0, True, "1", 1.0, None])
def test_only_schema_1_is_read(cast, schema):
    data = _good()
    data["schema"] = schema
    with pytest.raises(cast.StoryboardError, match="schema must be 1"):
        _parse(cast, data)


def test_a_duplicate_scene_id_is_refused(cast):
    data = _good()
    _scene(data, "report")["id"] = "scan"
    with pytest.raises(cast.StoryboardError, match="duplicate scene id 'scan'"):
        _parse(cast, data)


@pytest.mark.parametrize("bad", ["Scan", "scan two", "1scan", "", "scan_two", 7])
def test_a_scene_id_has_the_journey_id_shape(cast, bad):
    data = _good()
    _scene(data, "reports")["id"] = bad
    with pytest.raises(cast.StoryboardError, match="scene id"):
        _parse(cast, data)


@pytest.mark.parametrize(
    ("first", "second", "accepted"),
    [
        (10.0, 20.0, True),
        (30.0, 30.0, True),
        (15.5, 15.5, True),
        (10.0, 19.999, False),
        (30.0, 30.001, False),
        (1.0, 1.0, False),
        (40.0, 40.0, False),
    ],
)
def test_the_total_must_be_30_to_60_seconds(cast, first, second, accepted):
    data = _two_scenes(first, second)
    if accepted:
        assert _parse(cast, data).total_ms == round((first + second) * 1000)
    else:
        with pytest.raises(cast.StoryboardError, match="30 to 60 s"):
            _parse(cast, data)


# --- captions

EXCLUSIVE = ["only", "every", "all", "always", "never", "each"]


@pytest.mark.parametrize("word", EXCLUSIVE)
def test_an_exclusive_word_in_a_caption_is_refused(cast, word):
    for variant in (word, word.capitalize(), word.upper()):
        for caption in (
            f"Scan {variant} files",
            f"{variant} findings",
            f"See {variant}.",
        ):
            problems = cast.caption_problems(caption, 10000)
            assert any(
                "exclusive" in problem and word in problem.lower()
                for problem in problems
            ), caption


@pytest.mark.parametrize(
    "caption",
    [
        "Allow the scan",
        "Alliance report",
        "Nevertheless scanned",
        "Everyone reads",
        "Reach the findings",
        "Lonely project",
    ],
)
def test_words_that_only_contain_an_exclusive_word_pass(cast, caption):
    assert cast.caption_problems(caption, 10000) == []


@pytest.mark.parametrize(
    "caption", ["Done in seconds", "Done In Seconds", "Scan in  seconds"]
)
def test_the_phrase_in_seconds_is_refused(cast, caption):
    problems = cast.caption_problems(caption, 10000)
    assert any("in seconds" in problem for problem in problems)


@pytest.mark.parametrize(
    "caption",
    [
        "Scan 3 files",
        "Python3 project",
        "Step 1",
        "Scan \N{ARABIC-INDIC DIGIT THREE} files",
    ],
)
def test_a_digit_in_a_caption_is_refused(cast, caption):
    assert any("digit" in problem for problem in cast.caption_problems(caption, 10000))


def test_a_caption_is_at_most_7_words_and_3_and_a_half_words_a_second(cast):
    seven = "Run the quick scan on the project"
    assert cast.count_words(seven) == 7
    assert cast.caption_problems(seven, 2000) == []
    slow = cast.caption_problems(seven, 1999)
    assert any("3.5 words a second" in problem for problem in slow)
    eight = "Run the quick scan on the small project"
    assert cast.count_words(eight) == 8
    long_problems = cast.caption_problems(eight, 30000)
    assert any("more than 7 words" in problem for problem in long_problems)


@pytest.mark.parametrize(
    ("caption", "needle"),
    [
        ("", "is empty"),
        (" ", "is empty"),
        (" Scan", "separated by single spaces"),
        ("Scan ", "separated by single spaces"),
        ("Scan  files", "separated by single spaces"),
        ("Scan\nfiles", "separated by single spaces"),
        ("Scan\tfiles", "separated by single spaces"),
        # The next cases hold no digit and no space problem, so only the printable-text
        # rule can refuse them: a caption with a control or invisible character in it
        # would otherwise reach the cast as a marker that moves the cursor.
        ("A\x1b[m B", "printable words"),
        ("A\x07 B", "printable words"),
        ("A\x7f B", "printable words"),
        ("Scan\N{ZERO WIDTH SPACE}files", "printable words"),
        # This one also holds a digit, and the printable-text rule must name it too.
        ("A\x1b[0m B", "printable words"),
    ],
)
def test_a_caption_is_one_clean_line_of_single_spaced_words(cast, caption, needle):
    problems = cast.caption_problems(caption, 10000)
    assert any(needle in problem for problem in problems), problems


def test_a_good_caption_has_no_problem(cast):
    assert cast.caption_problems("Check the install", 4000) == []


@pytest.mark.parametrize(
    ("caption", "needle"),
    [
        ("Check 3 installs", "digit"),
        ("Check every install", "exclusive word"),
        ("Check the install quickly and then some more", "more than 7 words"),
    ],
)
def test_the_loader_refuses_a_bad_caption_and_names_the_scene(cast, caption, needle):
    data = _good()
    _scene(data, "version")["caption"] = caption
    with pytest.raises(cast.StoryboardError, match=needle) as caught:
        _parse(cast, data)
    assert "'version'" in str(caught.value)


# --- commands

# What the refusal of an ls flag that prints owners and groups says it is for. The
# scrub scan knows a user name only after a slash, so a name in such a column is not
# one it can recognize.
LISTS_OWNERS = "owner and group of each file"
# What the refusal of a long option says. ls takes short flags only, so the check
# refuses every long option in the same words and names the short flags it refuses.
NOT_A_SHORT_FLAG = "other than a short flag"

ADMITTED_COMMANDS = [
    "cat app.py",
    "ls",
    "ls .",
    "ls .ash/ash_output/reports",
    "ls -1 reports",
    "cat ./app.py",
    "cat src/app.py src/util.py",
    "ls -a .ash",
    "ls -1",
    "ls -AF .ash",
    # Only the lower-case l, g, o and n flags print owners and groups.
    "ls -LGN .",
    # The owner rule is about ls listings: cat takes -n to number lines.
    "cat -n app.py",
]
REFUSED_COMMANDS = [
    ("rm -rf app.py", "allowlist"),
    ("/bin/cat app.py", "allowlist"),
    ("echo hi", "allowlist"),
    ("cat /etc/passwd", "relative path"),
    ("cat ../secret", "leaves the project"),
    ("cat src/../../secret", "leaves the project"),
    ("cat app.py; rm app.py", "relative path"),
    ("cat app.py | head", "relative path"),
    ("cat app.py > out.txt", "relative path"),
    ("ls $(pwd)", "relative path"),
    ("cat $HOME/x", "relative path"),
    ("ls ~", "relative path"),
    ("ls 'a b'", "relative path"),
    ("cat a\\b", "relative path"),
    ("ls --all", "option"),
    ("cat -", "option"),
    ("cat", "needs a file"),
    ("", "empty"),
    ("ls  app", "single spaces"),
    (" ls", "single spaces"),
    ("ls\tapp", "single spaces"),
    # A listing that prints the owner and group of each file, alone or in a bundle,
    # before or after the paths.
    ("ls -l", LISTS_OWNERS),
    ("ls -la .ash", LISTS_OWNERS),
    ("ls -al .ash", LISTS_OWNERS),
    ("ls -lh reports", LISTS_OWNERS),
    ("ls -1l", LISTS_OWNERS),
    ("ls -g", LISTS_OWNERS),
    ("ls -o", LISTS_OWNERS),
    ("ls -n", LISTS_OWNERS),
    ("ls -a -l .ash", LISTS_OWNERS),
    ("ls .ash -l", LISTS_OWNERS),
    # Every ls long option is refused in the same words, whatever it prints: the owners
    # (--format=long), nothing (--author), or a spelling that GNU ls reads as ambiguous
    # (--f, --n, --format=v), which the check does not try to place.
    ("ls --format=long", NOT_A_SHORT_FLAG),
    ("ls --format=verbose", NOT_A_SHORT_FLAG),
    ("ls --form=long", NOT_A_SHORT_FLAG),
    ("ls --numeric-uid-gid", NOT_A_SHORT_FLAG),
    ("ls --numeric", NOT_A_SHORT_FLAG),
    ("ls --full-time", NOT_A_SHORT_FLAG),
    ("ls --f", NOT_A_SHORT_FLAG),
    ("ls --n", NOT_A_SHORT_FLAG),
    ("ls --format=v", NOT_A_SHORT_FLAG),
    ("ls --format=across", NOT_A_SHORT_FLAG),
    ("ls --author", NOT_A_SHORT_FLAG),
    ("ls --no-group", NOT_A_SHORT_FLAG),
    # Shell syntax of the kinds the path pattern has to keep out.
    ("cat .*/secret", "relative path"),
    ("cat {..,x}/secret", "relative path"),
    ("ls `pwd`", "relative path"),
    ("cat a&", "relative path"),
    ("cat <app.py", "relative path"),
]


@pytest.mark.parametrize("command", ADMITTED_COMMANDS)
def test_the_read_only_allowlist_admits_cat_and_ls_on_project_paths(cast, command):
    assert cast.command_problem(command) is None


@pytest.mark.parametrize(("command", "needle"), REFUSED_COMMANDS)
def test_the_read_only_allowlist_refuses_everything_else(cast, command, needle):
    problem = cast.command_problem(command)
    assert problem is not None
    assert needle in problem


def test_the_loader_refuses_a_disallowed_command(cast):
    data = _good()
    _scene(data, "reports")["command"] = "rm -rf ."
    with pytest.raises(cast.StoryboardError, match="allowlist") as caught:
        _parse(cast, data)
    assert "'reports'" in str(caught.value)


def test_the_loader_refuses_an_ls_listing_of_owners_and_names_the_scene(cast):
    data = _good()
    _scene(data, "reports")["command"] = "ls -la .ash/ash_output/reports"
    with pytest.raises(cast.StoryboardError, match=LISTS_OWNERS) as caught:
        _parse(cast, data)
    assert "'reports'" in str(caught.value)


def test_the_ls_refusal_names_the_argument_that_prints_owners(cast):
    problem = cast.command_problem("ls -a -lh reports")
    assert problem is not None
    assert LISTS_OWNERS in problem
    assert "'-lh'" in problem
    assert "'-a'" not in problem


@pytest.mark.parametrize(
    "command",
    ["ls --format=across", "ls --format", "ls --author", "ls --no-group", "ls --all"],
)
def test_a_long_option_that_prints_no_owners_does_not_claim_to(cast, command):
    problem = cast.command_problem(command)
    assert problem is not None
    assert LISTS_OWNERS not in problem


@pytest.mark.parametrize(
    "option",
    [
        "--f",
        "--n",
        "--format=v",
        "--format=long",
        "--format=verbose",
        "--full-time",
        "--numeric-uid-gid",
        "--author",
        "--all",
    ],
)
def test_every_ls_long_option_gets_the_one_generic_refusal(cast, option):
    # GNU ls reads --f, --n and --format=v as ambiguous, so the check does not guess
    # which option a spelling stands for: any long option is refused in the same words.
    generic = cast.command_problem("ls --no-such-option")
    assert generic is not None
    problem = cast.command_problem(f"ls {option}")
    assert problem == generic.replace("--no-such-option", option)


def test_the_generic_ls_refusal_names_the_short_flags_that_print_owners(cast):
    problem = cast.command_problem("ls --all")
    assert problem is not None
    assert "-l, -g, -o, -n" in problem
    # cat has no such flags, so its refusal of an option does not name them.
    assert "-l, -g, -o, -n" not in cast.command_problem("cat --all")


@pytest.mark.parametrize(
    "value", ["long", "verbose", "l", "lo", "lon", "verb", "verbos", "across"]
)
def test_ls_format_with_its_value_in_the_next_argument_gets_the_owner_reason(
    cast, value
):
    # GNU ls takes the value of --format from the next argument, so `ls --format long`
    # prints owners and groups as `ls --format=long` does. The option is refused before
    # its value is read, with the reason every ls option gets: the owner flags.
    problem = cast.command_problem(f"ls --format {value}")
    assert problem is not None
    assert problem == cast.command_problem("ls --format")
    assert "-l, -g, -o, -n" in problem
    assert "owners and groups" in problem


# --- ids, kinds and the other keys


def test_block_and_hidden_block_ids_must_be_journey_ids(cast):
    data = _good()
    _scene(data, "scan")["block"] = "no-such-block"
    with pytest.raises(
        cast.StoryboardError, match="'no-such-block' is not a journey block id"
    ):
        _parse(cast, data)
    data = _good()
    _scene(data, "project")["hidden_blocks"] = ["project", "ghost"]
    with pytest.raises(cast.StoryboardError, match="'ghost' is not a journey block id"):
        _parse(cast, data)
    # The ids are checked against the ids the caller gives; with none given, only
    # their shape is.
    assert _parse(cast, data, None).total_ms == 48000


@pytest.mark.parametrize("bad", ["Scan", "scan two", "-scan", "scan_two", "", 7])
def test_a_block_id_must_have_the_journey_id_shape(cast, bad):
    data = _good()
    _scene(data, "scan")["block"] = bad
    with pytest.raises(cast.StoryboardError, match="block"):
        _parse(cast, data, None)


def test_a_scene_names_exactly_one_of_block_command_or_comment_from(cast):
    both = _good()
    _scene(both, "version")["command"] = "ls"
    neither = _good()
    del _scene(neither, "version")["block"]
    for data in (both, neither):
        with pytest.raises(
            cast.StoryboardError,
            match="exactly one of block, command or comment_from",
        ):
            _parse(cast, data)


@pytest.mark.parametrize("hidden", [[], ["project", "project"], "project", [7]])
def test_hidden_blocks_are_a_non_empty_list_of_distinct_ids(cast, hidden):
    data = _good()
    _scene(data, "project")["hidden_blocks"] = hidden
    with pytest.raises(cast.StoryboardError, match="hidden_blocks"):
        _parse(cast, data)


def test_a_hidden_block_is_not_also_the_scenes_own_block(cast):
    data = _good()
    _scene(data, "version")["hidden_blocks"] = ["version"]
    with pytest.raises(cast.StoryboardError, match="hidden_blocks"):
        _parse(cast, data)


def test_hidden_blocks_cannot_go_with_a_scene_that_runs_nothing(cast):
    data = _good()
    _scene(data, "install")["hidden_blocks"] = ["project"]
    with pytest.raises(cast.StoryboardError, match="runs nothing"):
        _parse(cast, data)


@pytest.mark.parametrize(
    "value",
    [
        "README.md",
        "README.md#",
        "#anchor",
        "../x.md#a",
        "/abs/x.md#a",
        "a b.md#x",
        "README.md#a#b",
        "README.md#Upper",
        7,
    ],
)
def test_comment_from_is_a_relative_path_and_an_anchor(cast, value):
    data = _good()
    _scene(data, "install")["comment_from"] = value
    with pytest.raises(cast.StoryboardError, match="comment_from"):
        _parse(cast, data)


def test_a_scene_that_runs_nothing_has_no_output_window(cast):
    data = _good()
    _scene(data, "install")["output_window_s"] = 1.0
    with pytest.raises(cast.StoryboardError, match="output_window_s"):
        _parse(cast, data)


def test_the_poster_scene_names_a_scene(cast):
    data = _good()
    data["poster_scene"] = "nope"
    with pytest.raises(
        cast.StoryboardError, match="poster_scene 'nope' names no scene"
    ):
        _parse(cast, data)


@pytest.mark.parametrize("playback", ["forever", "Once", "", None, True])
def test_playback_is_once_or_loop(cast, playback):
    data = _good()
    data["playback"] = playback
    with pytest.raises(cast.StoryboardError, match="playback must be one of"):
        _parse(cast, data)


def test_loop_playback_is_accepted(cast):
    data = _good()
    data["playback"] = "loop"
    assert _parse(cast, data).playback == "loop"


@pytest.mark.parametrize(
    ("path", "key", "value", "needle"),
    [
        (("scenes", 0), "duration_s", 6.0004, "whole number of milliseconds"),
        (("scenes", 0), "duration_s", 0, "greater than 0"),
        (("scenes", 0), "duration_s", -1.0, "greater than 0"),
        (("scenes", 0), "duration_s", True, "number of seconds"),
        (("scenes", 0), "duration_s", "6", "number of seconds"),
        (("scenes", 0), "hold_s", -0.5, "0 or more"),
        (("scenes", 3), "output_window_s", 0, "greater than 0"),
        (("typing",), "lead_in_s", -0.1, "0 or more"),
        (("typing",), "chars_per_second", 0, "at least 0.1"),
        (("typing",), "chars_per_second", 5000, "at most 1000"),
        (("output",), "max_gap_s", 0, "greater than 0"),
    ],
)
def test_times_are_positive_whole_milliseconds(cast, path, key, value, needle):
    data = _good()
    _node(data, path)[key] = value
    with pytest.raises(cast.StoryboardError, match=needle):
        _parse(cast, data)


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("cols", 19),
        ("cols", 301),
        ("cols", 100.0),
        ("cols", True),
        ("rows", 4),
        ("rows", 101),
        ("prompt", ""),
        ("prompt", "\x1b[31m$ "),
        ("prompt", "$\n"),
        ("prompt", 5),
    ],
)
def test_the_terminal_is_a_sane_size_with_a_printable_prompt(cast, key, value):
    data = _good()
    data["terminal"][key] = value
    with pytest.raises(cast.StoryboardError, match=key):
        _parse(cast, data)


@pytest.mark.parametrize(
    "value",
    [
        "../x.journey.yaml",
        "/abs/x.journey.yaml",
        "docs/journeys/x.yaml",
        "docs/journeys/x y.journey.yaml",
        "",
        7,
    ],
)
def test_the_journey_is_a_relative_journey_file(cast, value):
    data = _good()
    data["journey"] = value
    with pytest.raises(cast.StoryboardError, match="journey"):
        _parse(cast, data)


@pytest.mark.parametrize("value", ["B324", [""], [7], ["a\nb"], [["x"]]])
def test_expect_screen_is_a_list_of_one_line_strings(cast, value):
    data = _good()
    _scene(data, "report")["expect_screen"] = value
    with pytest.raises(cast.StoryboardError, match="expect_screen"):
        _parse(cast, data)


def test_a_scene_that_cannot_fit_its_lead_in_command_and_hold_is_refused(cast):
    # The command `ls .ash/ash_output/reports` is 26 characters, 867 ms at 30 a second,
    # so 300 + 867 + 3833 fills the 5 s scene exactly and one more millisecond does not.
    data = _good()
    _scene(data, "reports")["hold_s"] = 3.833
    assert _parse(cast, data).total_ms == 48000
    _scene(data, "reports")["hold_s"] = 3.834
    with pytest.raises(cast.StoryboardError, match="over budget") as caught:
        _parse(cast, data)
    assert "'reports'" in str(caught.value)


@pytest.mark.parametrize(
    ("chars", "rate", "ms"),
    [
        (36, 30, 1200),
        (82, 30, 2733),
        (26, 30, 867),
        (7, 20, 350),
        (0, 30, 0),
        (1, 12.5, 80),
    ],
)
def test_typing_time_is_the_character_count_over_the_rate(cast, chars, rate, ms):
    assert cast.typing_ms(chars, rate) == ms


@pytest.mark.parametrize("rate", [1.0e-320, 5e-324, 1e-300])
def test_a_typing_rate_too_slow_to_compute_with_is_refused_not_overflowed(cast, rate):
    # At 1e-320 characters a second the time to type a command is infinite, and
    # rounding it raised OverflowError instead of refusing the storyboard.
    data = _good()
    data["typing"]["chars_per_second"] = rate
    with pytest.raises(cast.StoryboardError, match="at least") as caught:
        _parse(cast, data)
    assert "chars_per_second" in str(caught.value)


def test_the_slowest_admitted_typing_rate_is_the_floor(cast):
    floor = cast.MIN_CHARS_PER_SECOND
    # No scene of this storyboard types a command, so the rate is only a bound here.
    data = _two_scenes(15.0, 15.0)
    data["typing"]["chars_per_second"] = floor
    assert _parse(cast, data).typing.chars_per_second == floor
    data["typing"]["chars_per_second"] = floor * 0.99
    with pytest.raises(cast.StoryboardError, match="at least"):
        _parse(cast, data)


def test_the_fastest_admitted_typing_rate_is_the_ceiling(cast):
    ceiling = cast.MAX_CHARS_PER_SECOND
    data = _two_scenes(15.0, 15.0)
    data["typing"]["chars_per_second"] = ceiling
    assert _parse(cast, data).typing.chars_per_second == ceiling
    data["typing"]["chars_per_second"] = ceiling * 1.01
    with pytest.raises(cast.StoryboardError, match="at most"):
        _parse(cast, data)


def _refused_typing_rate(cast, rate):
    """The refusal of a storyboard with this typing rate, without the rate it quotes."""
    data = _good()
    data["typing"]["chars_per_second"] = rate
    with pytest.raises(cast.StoryboardError) as caught:
        _parse(cast, data)
    head, _, quoted = str(caught.value).rpartition(", not ")
    assert quoted == repr(rate)
    return head


@pytest.mark.parametrize(
    "rate",
    [0, -1, 0.05, 0.0999, 1000.5, 5000, "30", None, True, float("nan"), float("inf")],
)
def test_a_typing_rate_out_of_range_gets_one_message_naming_both_bounds(cast, rate):
    head = _refused_typing_rate(cast, rate)
    assert f"at least {cast.MIN_CHARS_PER_SECOND}" in head
    assert f"at most {cast.MAX_CHARS_PER_SECOND}" in head
    assert "greater than 0" not in head
    # One message for every rate: only the rate it quotes differs.
    assert head == _refused_typing_rate(cast, -1)


@pytest.mark.parametrize(
    "rate", [1.0e-320, 0, -1, float("nan"), float("inf"), True, "30", None]
)
def test_typing_time_refuses_a_rate_that_is_not_a_usable_speed(cast, rate):
    with pytest.raises(cast.CastError, match="typing rate"):
        cast.typing_ms(26, rate)


def test_typing_time_at_the_floor_is_finite(cast):
    floor = cast.MIN_CHARS_PER_SECOND
    assert cast.typing_ms(1, floor) == round(1000 / floor)


# ---------------------------------------------------------------------------
# The retimer
# ---------------------------------------------------------------------------

MINI_IDS = frozenset({"run"})
CLEAR_SCREEN = "\x1b[H\x1b[2J"
GOLDEN_CHUNKS = ((0.2, "<0>"), (0.5, "<1>"), (3.5, "<2>"), (3.6, "<3>"), (3.7, "<4>"))
DESIGN_TYPED = {
    "install": (
        "# pipx install git+https://github.com/awslabs/automated-security-helper.git"
        "@v3.8.0"
    ),
    "version": "ash --version",
    "project": "cat app.py",
    "scan": "ash --scanners bandit,detect-secrets",
    "report": "ash report",
    "reports": "ls .ash/ash_output/reports",
}


def _mini(second_s: float = 20.0, **scene_one: Any) -> dict[str, Any]:
    """Two scenes at 20 characters a second with a 0.5 s lead-in and 1 s gap cap.

    A keyword set to None removes that key from the first scene.
    """
    one: dict[str, Any] = {
        "id": "one",
        "caption": "Run the thing",
        "duration_s": 20.0,
        "block": "run",
        "clear": True,
        "output_window_s": 4.0,
        "hold_s": 2.0,
    }
    one.update(scene_one)
    one = {key: value for key, value in one.items() if value is not None}
    return {
        "schema": 1,
        "journey": "docs/journeys/mini.journey.yaml",
        "terminal": {"cols": 80, "rows": 24, "prompt": "$ "},
        "typing": {"chars_per_second": 20, "lead_in_s": 0.5},
        "output": {"max_gap_s": 1.0},
        "poster_scene": "one",
        "playback": "once",
        "scenes": [
            one,
            {
                "id": "two",
                "caption": "Install it",
                "duration_s": second_s,
                "comment_from": "README.md#install",
                "hold_s": 3.0,
            },
        ],
    }


def _chunks(cast, *pairs):
    return tuple(cast.RawChunk(offset, data) for offset, data in pairs)


def _runs(cast, chunks=(), typed="echo hi"):
    return {
        "one": cast.SceneRun(typed=typed, chunks=chunks),
        "two": cast.SceneRun(typed="# pipx install x"),
    }


def _ms(events):
    """(time in whole milliseconds, code, data) of each event."""
    return [(round(event.time * 1000), event.code, event.data) for event in events]


def _timed(cast, offsets, **scene_one):
    """Scene one retimed over chunks <0>, <1>, ... at the given raw offsets."""
    board = cast.parse_storyboard(_mini(**scene_one), MINI_IDS)
    chunks = tuple(
        cast.RawChunk(offset, f"<{index}>") for index, offset in enumerate(offsets)
    )
    return cast.retime(board, _runs(cast, chunks)).scenes[0]


def _outputs(scene):
    """(milliseconds after the typing ended, data) of each output chunk of a scene."""
    return [
        (round(event.time * 1000) - scene.output_start_ms, event.data)
        for event in scene.events
        if event.data.startswith("<")
    ]


def test_the_retimer_gives_these_events_for_this_run(cast):
    board = cast.parse_storyboard(_mini(), MINI_IDS)
    retimed = cast.retime(board, _runs(cast, _chunks(cast, *GOLDEN_CHUNKS)))
    expected = [(0, "m", "Run the thing"), (0, "o", CLEAR_SCREEN), (0, "o", "$ ")]
    expected += [(500 + 50 * k, "o", char) for k, char in enumerate("echo hi")]
    expected += [(850, "o", "\r\n")]
    # The 3.0 s gap before the third chunk is cut to the 1.0 s maximum, and the run
    # (1.7 s) fits the 4.0 s window, so nothing is scaled.
    expected += [
        (1050, "o", "<0>"),
        (1350, "o", "<1>"),
        (2350, "o", "<2>"),
        (2450, "o", "<3>"),
        (2550, "o", "<4>"),
    ]
    expected += [(20000, "m", "Install it"), (20000, "o", "$ ")]
    expected += [(20500 + 50 * k, "o", c) for k, c in enumerate("# pipx install x")]
    expected += [(21300, "o", "\r\n")]
    assert _ms(retimed.events) == expected


def test_each_scene_reports_its_spans_and_its_hold(cast):
    board = cast.parse_storyboard(_mini(), MINI_IDS)
    retimed = cast.retime(board, _runs(cast, _chunks(cast, *GOLDEN_CHUNKS)))
    one, two = retimed.scenes
    assert (one.scene_id, one.start_ms, one.end_ms) == ("one", 0, 20000)
    assert one.typing == cast.TypingSpan(500, 850, 7)
    assert (one.output_start_ms, one.output_end_ms, one.hold_ms) == (850, 2550, 17450)
    assert (two.scene_id, two.start_ms, two.end_ms) == ("two", 20000, 40000)
    assert two.typing == cast.TypingSpan(20500, 21300, 16)
    assert (two.output_start_ms, two.output_end_ms, two.hold_ms) == (
        21300,
        21300,
        18700,
    )
    assert retimed.total_ms == 40000
    assert retimed.final_hold_ms == 18700


def test_the_clear_and_the_marker_follow_the_storyboard(cast):
    board = cast.parse_storyboard(_mini(), MINI_IDS)
    one, two = cast.retime(board, _runs(cast)).scenes
    assert cast.CLEAR_SCREEN == CLEAR_SCREEN
    assert [event.code for event in one.events[:3]] == ["m", "o", "o"]
    assert [event.data for event in one.events[:3]] == [
        "Run the thing",
        CLEAR_SCREEN,
        "$ ",
    ]
    # Scene two does not clear: its marker is followed by the prompt.
    assert [event.code for event in two.events[:2]] == ["m", "o"]
    assert [event.data for event in two.events[:2]] == ["Install it", "$ "]


def test_a_fixed_input_gives_a_fixed_output(cast):
    board = cast.parse_storyboard(_mini(), MINI_IDS)
    runs = _runs(cast, _chunks(cast, *GOLDEN_CHUNKS))
    first = cast.retime(board, runs)
    again = cast.retime(
        cast.parse_storyboard(_mini(), MINI_IDS), dict(reversed(list(runs.items())))
    )
    assert first == again
    assert cast.dumps_cast(cast.build_cast(board, first)) == cast.dumps_cast(
        cast.build_cast(board, again)
    )


@pytest.mark.parametrize("speed", [0.01, 1.0, 50.0])
def test_totals_equal_the_storyboard_whatever_the_machine_speed(cast, speed):
    board = cast.parse_storyboard(_mini(), MINI_IDS)
    raw = tuple((offset * speed, data) for offset, data in GOLDEN_CHUNKS)
    retimed = cast.retime(board, _runs(cast, _chunks(cast, *raw)))
    assert retimed.total_ms == board.total_ms == 40000
    assert [(s.start_ms, s.end_ms) for s in retimed.scenes] == [
        (0, 20000),
        (20000, 40000),
    ]
    for scene in retimed.scenes:
        times = [round(event.time * 1000) for event in scene.events]
        assert all(scene.start_ms <= time <= scene.end_ms for time in times)


def test_output_is_shortened_never_stretched(cast):
    # A run that already fits its 4 s window keeps its own offsets.
    assert _outputs(_timed(cast, [0.1, 0.2])) == [(100, "<0>"), (200, "<1>")]
    # A long wait before the first chunk is cut to the 1 s gap cap, not kept.
    assert _outputs(_timed(cast, [10.0, 10.5])) == [(1000, "<0>"), (1500, "<1>")]
    # A run longer than its window is scaled down into it: 6 s into 3 s halves it.
    scaled = _outputs(_timed(cast, [1, 2, 3, 4, 5, 6], output_window_s=3.0))
    assert scaled == [
        (500, "<0>"),
        (1000, "<1>"),
        (1500, "<2>"),
        (2000, "<3>"),
        (2500, "<4>"),
        (3000, "<5>"),
    ]


def test_without_a_window_key_the_rest_of_the_scene_before_the_hold_is_the_window(cast):
    # 20 s - 0.5 s lead-in - 0.35 s typing - 2 s hold leaves a 17.15 s window.
    offsets = [float(second) for second in range(1, 21)]
    scene = _timed(cast, offsets, output_window_s=None)
    assert _outputs(scene)[-1] == (17150, "<19>")
    assert scene.output_end_ms == 18000
    assert scene.hold_ms == 2000


def test_random_runs_keep_the_retimers_invariants(cast):
    board = cast.parse_storyboard(_mini(), MINI_IDS)
    scene = board.scenes[0]
    rng = random.Random(20261126)
    for _trial in range(200):
        offset = 0.0
        raw = []
        for index in range(rng.randint(1, 25)):
            offset += rng.choice([0.0, rng.random() * 0.4, rng.random() * 3.0])
            raw.append(cast.RawChunk(round(offset, 6), f"<{index}>"))
        timed = cast.retime_scene(board, scene, cast.SceneRun("echo hi", tuple(raw)))
        times = [round(event.time * 1000) for event in timed.events]
        assert times == sorted(times)
        assert times[0] == scene.start_ms
        assert times[-1] <= scene.end_ms - scene.hold_ms
        outputs = _outputs(timed)
        assert [data for _offset, data in outputs] == [chunk.data for chunk in raw]
        new = [offset_ms for offset_ms, _data in outputs]
        assert new == sorted(new)
        assert new[-1] <= 4000
        previous_raw, previous_new, capped_total = 0.0, 0, 0.0
        for chunk, now in zip(raw, new, strict=True):
            raw_gap = chunk.offset_s - previous_raw
            # Nothing is stretched: a gap never grows, past a millisecond of rounding.
            assert now - previous_new <= min(raw_gap * 1000, 1000) + 1.001
            capped_total += min(raw_gap, 1.0)
            previous_raw, previous_new = chunk.offset_s, now
        if capped_total <= 4.0:
            assert abs(new[-1] - capped_total * 1000) <= 1.001


def test_a_scene_that_does_not_fit_its_duration_is_refused(cast):
    # A 0.5 s lead-in, a 17.5 s window and a 2 s hold fill the 20 s scene before a
    # character is typed, so the loader admits it (it does not know the command) and
    # the retimer, which does, cannot.
    board = cast.parse_storyboard(_mini(output_window_s=17.5), MINI_IDS)
    with pytest.raises(cast.RetimeError, match="over budget") as caught:
        cast.retime(board, _runs(cast, _chunks(cast, (0.1, "<0>"))))
    assert "'one'" in str(caught.value)
    # A 17 s window fits: 500 + 350 + 17000 + 2000 = 19850 ms.
    fits = cast.parse_storyboard(_mini(output_window_s=17.0), MINI_IDS)
    assert cast.retime(fits, _runs(cast)).total_ms == 40000


def test_a_command_too_long_to_type_in_its_scene_is_refused(cast):
    board = cast.parse_storyboard(_mini(output_window_s=None), MINI_IDS)
    with pytest.raises(cast.RetimeError, match="over budget"):
        cast.retime(board, _runs(cast, typed="x" * 400))


def test_the_retimer_refuses_a_typing_rate_too_slow_to_compute_with(cast):
    # A storyboard built by hand skips the loader's floor on the rate. The retimer
    # still refuses it by name, as a RetimeError, and does not overflow.
    board = cast.parse_storyboard(_mini(), MINI_IDS)
    slow = dataclasses.replace(
        board, typing=cast.TypingPolicy(chars_per_second=1.0e-320, lead_in_ms=500)
    )
    with pytest.raises(cast.RetimeError, match="typing rate") as caught:
        cast.retime(slow, _runs(cast))
    assert "'one'" in str(caught.value)


def test_output_with_no_time_left_to_show_it_is_refused(cast):
    # 6 s scene: a 0.5 s lead-in, 0.5 s typing (10 characters) and a 5 s hold leave no
    # window. A scene with nothing to show still fits.
    data = _mini(second_s=34.0, duration_s=6.0, hold_s=5.0, output_window_s=None)
    board = cast.parse_storyboard(data, MINI_IDS)
    typed = "0123456789"
    assert cast.retime(board, _runs(cast, typed=typed)).scenes[0].hold_ms == 5000
    with pytest.raises(cast.RetimeError, match="over budget"):
        cast.retime(board, _runs(cast, _chunks(cast, (0.1, "<0>")), typed=typed))


def test_the_runs_must_match_the_storyboards_scenes(cast):
    board = cast.parse_storyboard(_mini(), MINI_IDS)
    runs = _runs(cast)
    with pytest.raises(cast.RetimeError, match="no run for scene 'two'"):
        cast.retime(board, {"one": runs["one"]})
    with pytest.raises(cast.RetimeError, match="runs for unknown scene 'three'"):
        cast.retime(board, {**runs, "three": runs["one"]})


@pytest.mark.parametrize("offset", [-0.1, float("nan"), float("inf"), True, "1"])
def test_a_raw_chunk_offset_is_a_non_negative_number(cast, offset):
    with pytest.raises(cast.RetimeError, match="offset"):
        cast.RawChunk(offset, "x")


def test_a_raw_chunk_carries_text(cast):
    with pytest.raises(cast.RetimeError, match="data"):
        cast.RawChunk(0.1, b"bytes")


def test_raw_chunks_must_not_go_backwards(cast):
    board = cast.parse_storyboard(_mini(), MINI_IDS)
    runs = _runs(cast, _chunks(cast, (1.0, "<0>"), (0.5, "<1>")))
    with pytest.raises(cast.RetimeError, match="earlier than the chunk before it"):
        cast.retime(board, runs)


@pytest.mark.parametrize("typed", ["", "two\nlines", "tab\there", "esc\x1b[0m", 7])
def test_the_typed_text_is_one_printable_line(cast, typed):
    with pytest.raises(cast.RetimeError, match="typed"):
        cast.SceneRun(typed=typed)


def test_the_design_storyboard_retimes_to_its_48_seconds(cast):
    assert len(DESIGN_TYPED["install"]) == 82
    board = _parse(cast, _good())
    runs = {}
    for scene in board.scenes:
        if scene.scene_id == "install":
            chunks = ()
        else:
            chunks = _chunks(cast, (0.4, "<0>"), (2.0, "<1>"), (30.0, "<2>"))
        runs[scene.scene_id] = cast.SceneRun(DESIGN_TYPED[scene.scene_id], chunks)
    retimed = cast.retime(board, runs)
    assert retimed.total_ms == 48000
    assert [(s.start_ms, s.end_ms) for s in retimed.scenes] == [
        (0, 6000),
        (6000, 10000),
        (10000, 15000),
        (15000, 31000),
        (31000, 43000),
        (43000, 48000),
    ]
    assert retimed.scenes[0].typing == cast.TypingSpan(300, 3033, 82)
    assert retimed.scenes[3].typing == cast.TypingSpan(15300, 16500, 36)
    markers = [event for event in retimed.events if event.code == "m"]
    assert [event.data for event in markers] == [s.caption for s in board.scenes]


def test_the_retimed_events_make_a_cast_as_long_as_the_storyboard(cast):
    board = cast.parse_storyboard(_mini(), MINI_IDS)
    retimed = cast.retime(board, _runs(cast, _chunks(cast, *GOLDEN_CHUNKS)))
    recording = cast.build_cast(board, retimed)
    assert recording.header.width == 80
    assert recording.header.height == 24
    assert recording.header.duration == 40.0
    assert recording.header.theme is None
    assert recording.events == retimed.events
    last = recording.events[-1].time
    assert round((last + retimed.final_hold_ms / 1000) * 1000) == 40000
    assert cast.loads_cast(cast.dumps_cast(recording)) == recording
    themed = cast.build_cast(board, retimed, _theme(cast))
    assert themed.header.theme == _theme(cast)


# ---------------------------------------------------------------------------
# The scrub scan
# ---------------------------------------------------------------------------

SPLIT_BY_SGR = "\x1b[2m/home/\x1b[0m\x1b[1mbuilder\x1b[0m/app.py"


def _tokens(cast):
    return [
        cast.ForbiddenToken("home", "/home/builder"),
        cast.ForbiddenToken("user", "runner", "path-component"),
        cast.ForbiddenToken("host", "build-host-7", "word"),
    ]


@pytest.mark.parametrize(
    ("text", "kinds"),
    [
        ("wrote /home/builder/ash-tutorial/app.py", ["home"]),
        ("see /home/builder", ["home"]),
        ("nothing to see here", []),
        ("/home/runner/work/ash", ["user"]),
        ("in /home/runner.", ["user"]),
        ("the runner started", []),
        ("/home/runnerx/work", []),
        ("/home/runner.bak/work", []),
        ("/home/xrunner/work", []),
        ("on build-host-7 today", ["host"]),
        ("on build-host-7.", ["host"]),
        ("on build-host-70", []),
        ("on xbuild-host-7", []),
        ("/home/builder at build-host-7 as /home/runner", ["home", "host", "user"]),
    ],
)
def test_each_match_mode_reads_the_text_the_way_its_name_says(cast, text, kinds):
    hits = cast.scan_text(text, _tokens(cast), "sample")
    assert sorted(hit.kind for hit in hits) == kinds


def test_a_token_split_by_sgr_runs_is_found_in_the_plain_view(cast):
    tokens = [cast.ForbiddenToken("home", "/home/builder")]
    # The raw text does not hold the token, so only the plain view can find it.
    assert "/home/builder" not in SPLIT_BY_SGR
    hits = cast.scan_text(SPLIT_BY_SGR, tokens, "event 4")
    assert [(hit.kind, hit.where, hit.view) for hit in hits] == [
        ("home", "event 4", "plain")
    ]
    # Must-not-flag: the same colors around another name.
    other = SPLIT_BY_SGR.replace("builder", "somebody")
    assert cast.scan_text(other, tokens, "event 4") == []
    # A token the raw text holds is reported once, from the raw view.
    raw = cast.scan_text("\x1b[1m/home/builder\x1b[0m", tokens, "event 5")
    assert [(hit.kind, hit.view) for hit in raw] == [("home", "raw")]


def test_strip_sgr_removes_color_runs_and_nothing_else(cast):
    text = "\x1b[2Jone\x1b[1;38;2;1;2;3mtwo\x1b[0m\x1b[Hthree\x1b[m"
    assert cast.strip_sgr(text) == "\x1b[2Jonetwo\x1b[Hthree"


BAR = "\N{BOX DRAWINGS LIGHT VERTICAL}"

#: Text that holds /home/builder only in pieces: how a table cell wraps a long path, and
#: how a terminal moves the cursor around one. Neither the raw text nor the text without
#: color runs holds the token, so only the flat view can find it.
SPLIT_BY_A_WRAP_OR_AN_ESCAPE = {
    "a table wrap": f"{BAR} /home/bu {BAR}\r\n{BAR} ilder/app.py {BAR}",
    "an erase code and a wrap": f"/home/bui\x1b[K\r\n{BAR} lder/app.py",
    "a line feed": "wrote /home/bui\nlder/app.py",
    "a carriage return and a line feed": "wrote /home/bui\r\nlder/app.py",
    "an erase code": "/home/bui\x1b[Klder",
    "a cursor move": "/home/bui\x1b[1Clder",
    "a title ended by a bell": "/home/bui\x1b]0;ash\x07lder",
    "a link ended by a string terminator": "/home/bui\x1b]8;;u\x1b\\lder",
    "a charset designation": "/home/bui\x1b(Blder",
    "a saved cursor": "/home/bui\x1b7lder",
    "a device control string": "/home/bui\x1bPq\x1b\\lder",
    "an eight-bit control sequence": "/home/bui\x9b1Clder",
    "a bell": "/home/bui\x07lder",
    "an erase code in color runs": "\x1b[2m/home/bui\x1b[K\x1b[0m\x1b[1mlder\x1b[0m",
}


@pytest.mark.parametrize("how", sorted(SPLIT_BY_A_WRAP_OR_AN_ESCAPE))
def test_a_token_split_by_a_wrap_or_an_escape_is_found_in_the_flat_view(cast, how):
    text = SPLIT_BY_A_WRAP_OR_AN_ESCAPE[how]
    tokens = [cast.ForbiddenToken("home", "/home/builder")]
    assert "/home/builder" not in text
    assert "/home/builder" not in cast.strip_sgr(text)
    hits = cast.scan_text(text, tokens, "event 7")
    assert [(hit.kind, hit.where, hit.view) for hit in hits] == [
        ("home", "event 7", "flat")
    ]


@pytest.mark.parametrize(
    ("text", "kinds"),
    [
        ("/home/bu\r\nilder/app.py", ["home"]),
        ("/home/\r\nrunner/work", ["user"]),
        ("on build-\r\nhost-7 today", ["host"]),
        # Joined, the name runs on into more word characters, so it is not the token.
        ("on build-\r\nhost-70", []),
        ("the\r\nrunner started", []),
        ("see /home/\x1b[Kother\r\nbuilder", []),
    ],
)
def test_the_flat_view_keeps_each_match_modes_boundaries(cast, text, kinds):
    hits = cast.scan_text(text, _tokens(cast), "event 3")
    assert sorted(hit.kind for hit in hits) == kinds


@pytest.mark.parametrize(
    "text",
    [
        f"{BAR} ash {BAR} PASSED {BAR}\r\n",
        f"{BAR} /home/other {BAR}\r\n{BAR} builder/app.py {BAR}",
        "\x1b[2J\x1b[Hscan complete\x1b[K\r\n",
        "wrote /home/\r\nsomebody/app.py",
    ],
)
def test_text_with_wraps_and_escapes_but_no_token_stays_clean(cast, text):
    assert cast.scan_text(text, _tokens(cast), "event 2") == []


@pytest.mark.parametrize(
    ("text", "flat"),
    [
        ("plain text", "plain text"),
        ("two  spaces stay", "two  spaces stay"),
        ("\x1b[2Jone\x1b[1;38;2;1;2;3mtwo\x1b[0m\x1b[Hthree\x1b[m", "onetwothree"),
        (f"{BAR} ab {BAR}\r\n{BAR} cd {BAR}", "abcd"),
        ("ab \r\n cd", "abcd"),
        ("ab\x1b]0;title\x07cd", "abcd"),
        ("ab\x1b]8;;http://x\x1b\\cd", "abcd"),
        ("ab\x1bPdata\x1b\\cd", "abcd"),
        ("ab\x1b(Bcd", "abcd"),
        ("ab\x1b7cd", "abcd"),
        ("ab\x9b1Ccd", "abcd"),
        ("ab\x00\x07\x08\x0b\x7f\x85cd", "abcd"),
        ("\x1b", ""),
    ],
)
def test_the_flat_view_drops_escapes_controls_breaks_and_boxes(cast, text, flat):
    assert cast.flatten_text(text) == flat


def test_the_flat_view_drops_exactly_the_box_drawing_block(cast):
    assert cast.flatten_text(f"a{chr(0x2500)}b{chr(0x257F)}c") == "abc"
    kept = f"a{chr(0x24FF)}b{chr(0x2580)}c"
    assert cast.flatten_text(kept) == kept


#: A path that wraps inside a cell of a table of three columns, as a terminal prints
#: it: the first line holds the cells and the start of the path, the second the rest of
#: it. In ``last`` no cell follows the wrapped one on its row. In ``middle`` another
#: cell does, and that cell's text lies between the two halves of the path.
WRAPPED_IN_A_TABLE = {
    "bordered": {
        "last": (
            f"{BAR} B324 {BAR} HIGH {BAR} /home/bu {BAR}\r\n"
            f"{BAR}      {BAR}      {BAR} ilder/x  {BAR}\r\n"
        ),
        "middle": (
            f"{BAR} B324 {BAR} /home/bu {BAR} HIGH {BAR}\r\n"
            f"{BAR}      {BAR} ilder/x  {BAR}      {BAR}\r\n"
        ),
    },
    "spaced": {
        "last": " B324   HIGH   /home/bu\r\n               ilder/x\r\n",
        "middle": " B324   /home/bu   HIGH\r\n        ilder/x\r\n",
    },
}


@pytest.mark.parametrize("shape", sorted(WRAPPED_IN_A_TABLE))
def test_a_token_wrapped_in_the_last_cell_of_a_row_is_found_in_flat_view(cast, shape):
    text = WRAPPED_IN_A_TABLE[shape]["last"]
    tokens = [cast.ForbiddenToken("home", "/home/builder")]
    assert "/home/builder" not in text
    hits = cast.scan_text(text, tokens, "event 6")
    assert [(hit.kind, hit.where, hit.view) for hit in hits] == [
        ("home", "event 6", "flat")
    ]


@pytest.mark.parametrize("shape", sorted(WRAPPED_IN_A_TABLE))
def test_a_token_wrapped_inside_a_middle_column_is_not_rejoined_so_recordings_must_not_wrap(
    cast, shape
):
    """A limit of the flat view, pinned as it is, not a promise: it does not rejoin a
    path that wraps inside a cell with other cells after it on its row. The text of
    those cells lies between the halves of the path, and the view keeps it. So a
    recording must not wrap a table of several columns; the scan is not what keeps
    such a path out of one. If the view comes to rejoin these cells, this test turns
    red and becomes a must-flag case beside the last-cell one above.
    """
    tokens = [cast.ForbiddenToken("home", "/home/builder")]
    middle = WRAPPED_IN_A_TABLE[shape]["middle"]
    assert "/home/builder" not in cast.flatten_text(middle)
    assert cast.scan_text(middle, tokens, "event 6") == []
    # The same halves with no cell after the wrapped one are found, so the miss is the
    # cell's place in its row and not the text of the path.
    last = WRAPPED_IN_A_TABLE[shape]["last"]
    assert "/home/builder" in cast.flatten_text(last)


def test_a_token_wrapped_inside_a_table_drawn_with_ascii_bars_is_not_rejoined(cast):
    """Another limit of the flat view, pinned as it is: only box-drawing characters
    count as the borders of a table, so the bars of a table drawn with ``|`` stay
    between the halves of a path that wraps inside it, even in a table of one column.
    A recording must not wrap a table of this kind either.
    """
    tokens = [cast.ForbiddenToken("home", "/home/builder")]
    ascii_table = "| /home/bu |\r\n| ilder/x |"
    assert "/home/builder" not in cast.flatten_text(ascii_table)
    assert cast.scan_text(ascii_table, tokens, "event 6") == []
    # The same table drawn with box-drawing characters is found.
    drawn = f"{BAR} /home/bu {BAR}\r\n{BAR} ilder/x {BAR}"
    assert [hit.view for hit in cast.scan_text(drawn, tokens, "event 6")] == ["flat"]


ZERO_WIDTH_SPACE = "\N{ZERO WIDTH SPACE}"

#: More wrapped paths that the flat view does not rejoin, each with a twin that it does.
#: In the twin only characters the view removes lie between the halves. In the text,
#: something it keeps does: the text of a column to the right of the wrapped cell, the
#: right-hand column of a log line, the bar of an ASCII table, a zero-width space.
NOT_REJOINED = {
    "first column with a column to its right, bordered": (
        f"{BAR} /home/bu {BAR} FAILED {BAR}\r\n{BAR} ilder/x  {BAR}        {BAR}\r\n",
        f"{BAR} /home/bu {BAR}        {BAR}\r\n{BAR} ilder/x  {BAR}        {BAR}\r\n",
    ),
    "first column with a column to its right, spaced": (
        " /home/bu   FAILED\r\n ilder/x\r\n",
        " /home/bu\r\n ilder/x\r\n",
    ),
    "a log line with a right-hand column": (
        "wrote /home/bu        cli.py:42\r\n                    ilder/x",
        "wrote /home/bu\r\n                    ilder/x",
    ),
    "an ASCII border around two columns": (
        "| /home/bu | FAILED |\r\n| ilder/x  |        |",
        f"{BAR} /home/bu {BAR}        {BAR}\r\n{BAR} ilder/x  {BAR}        {BAR}",
    ),
    "a zero-width space inside the token": (
        f"wrote /home/bu{ZERO_WIDTH_SPACE}ilder/x",
        "wrote /home/bu\x07ilder/x",
    ),
}


@pytest.mark.parametrize("shape", sorted(NOT_REJOINED))
def test_a_token_with_something_kept_between_its_halves_is_not_rejoined(cast, shape):
    """Limits of the flat view, pinned as they are, not promises. The view removes
    escape sequences, control characters, box-drawing characters and the spaces beside
    the last two, and nothing else. A token with anything else between its halves is
    not found, so a recording must not wrap a path beside other text: the scan is not
    what keeps such a path out of one. If the view comes to rejoin one of these, its
    case here turns red and becomes a must-flag case.
    """
    text, twin = NOT_REJOINED[shape]
    tokens = [cast.ForbiddenToken("home", "/home/builder")]
    assert "/home/builder" not in cast.flatten_text(text)
    assert cast.scan_text(text, tokens, "event 6") == []
    # The twin has only removed characters between the halves, and is found.
    assert "/home/builder" in cast.flatten_text(twin)
    assert [hit.view for hit in cast.scan_text(twin, tokens, "event 6")] == ["flat"]


def test_a_hit_names_its_kind_and_never_the_value(cast):
    hits = cast.scan_text("at /home/builder/x", _tokens(cast), "event 3")
    assert len(hits) == 1
    shown = f"{hits[0]} {hits[0]!r}"
    assert "home" in shown
    assert "builder" not in shown
    with pytest.raises(cast.ForbiddenTokenError) as caught:
        cast.require_clean(hits)
    assert caught.value.hits == tuple(hits)
    message = str(caught.value)
    assert "home" in message
    assert "event 3" in message
    assert "builder" not in message
    cast.require_clean([])


@pytest.mark.parametrize(
    "args",
    [
        ("", "x"),
        ("home", ""),
        ("home", "x", "regex"),
        ("user", "a/b", "word"),
        ("user", "a/b", "path-component"),
        (7, "x"),
    ],
)
def test_a_token_needs_a_kind_a_value_and_a_known_mode(cast, args):
    with pytest.raises(cast.CastError):
        cast.ForbiddenToken(*args)


def test_scan_cast_reads_the_header_and_every_event(cast):
    tokens = _tokens(cast)
    clean = _small_cast(
        cast,
        cast.CastEvent(0.0, "m", "Install"),
        cast.CastEvent(0.1, "o", "$ "),
        title="Quick start",
        command="ash --version",
        env={"TERM": "xterm-256color"},
    )
    assert cast.scan_cast(clean, tokens) == []

    def found(recording):
        return [(hit.kind, hit.where) for hit in cast.scan_cast(recording, tokens)]

    assert found(_small_cast(cast, title="from /home/builder")) == [
        ("home", "header title")
    ]
    assert found(_small_cast(cast, command="cat /home/builder/x")) == [
        ("home", "header command")
    ]
    assert found(_small_cast(cast, env={"PWD": "/home/builder"})) == [
        ("home", "header env")
    ]
    leaked = _small_cast(
        cast,
        cast.CastEvent(0.0, "o", "ok"),
        cast.CastEvent(0.1, "m", "from /home/builder"),
    )
    assert found(leaked) == [("home", "event 1")]


def test_a_token_found_in_one_event_is_not_reported_again_from_the_stream(cast):
    recording = _small_cast(cast, cast.CastEvent(0.0, "o", "at /home/builder"))
    hits = cast.scan_cast(recording, _tokens(cast))
    assert [(hit.kind, hit.where) for hit in hits] == [("home", "event 0")]


def test_a_token_split_across_two_events_is_found_in_the_output_stream(cast):
    recording = _small_cast(
        cast,
        cast.CastEvent(0.0, "o", "see /home/bui"),
        cast.CastEvent(0.1, "o", "lder/app.py"),
    )
    hits = cast.scan_cast(recording, _tokens(cast))
    assert [(hit.kind, hit.where) for hit in hits] == [("home", "output stream")]


def test_a_token_wrapped_across_two_events_is_found_in_the_flat_output_stream(cast):
    recording = _small_cast(
        cast,
        cast.CastEvent(0.0, "o", "wrote /home/bui\x1b[K\r\n"),
        cast.CastEvent(0.1, "o", f"{BAR} lder/app.py\r\n"),
    )
    hits = cast.scan_cast(recording, _tokens(cast))
    assert [(hit.kind, hit.where, hit.view) for hit in hits] == [
        ("home", "output stream", "flat")
    ]


def test_a_token_wrapped_inside_one_event_is_found_in_that_event(cast):
    wrapped = f"{BAR} /home/bu {BAR}\r\n{BAR} ilder/x {BAR}"
    recording = _small_cast(cast, cast.CastEvent(0.0, "o", wrapped))
    hits = cast.scan_cast(recording, _tokens(cast))
    assert [(hit.kind, hit.where, hit.view) for hit in hits] == [
        ("home", "event 0", "flat")
    ]


def test_a_table_drawn_over_several_events_without_a_token_stays_clean(cast):
    rows = [f"{BAR} bandit {BAR} FAILED {BAR}\r\n", f"{BAR} ash {BAR} PASSED {BAR}\r\n"]
    events = [cast.CastEvent(index / 10, "o", row) for index, row in enumerate(rows)]
    assert cast.scan_cast(_small_cast(cast, *events), _tokens(cast)) == []


def test_a_planted_token_turns_a_clean_cast_dirty(cast):
    """The control for the scan: the same cast, clean and then with one event
    carrying a token, reads zero hits and then one."""
    events = [cast.CastEvent(0.0, "o", "$ "), cast.CastEvent(0.2, "o", "ash\r\n")]
    assert cast.scan_cast(_small_cast(cast, *events), _tokens(cast)) == []
    events.append(cast.CastEvent(0.4, "o", "\x1b[1m/home/builder\x1b[0m\r\n"))
    hits = cast.scan_cast(_small_cast(cast, *events), _tokens(cast))
    assert [(hit.kind, hit.where) for hit in hits] == [("home", "event 2")]


# ---------------------------------------------------------------------------
# The run record
# ---------------------------------------------------------------------------


def _scanner(cast, name, status, **counts):
    fields = {
        "suppressed": 0,
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
        "actionable": 0,
    }
    fields.update(counts)
    return cast.ScannerRecord(name=name, status=status, **fields)


def _record(cast):
    """A record built with its lists out of canonical order, on purpose."""
    install = cast.SceneRecord(
        scene_id="install",
        command=DESIGN_TYPED["install"],
        exit_code=None,
        end_screen=(),
        typing=cast.TypingSpan(300, 3033, 82),
    )
    scan = cast.SceneRecord(
        scene_id="scan",
        command=DESIGN_TYPED["scan"],
        exit_code=2,
        end_screen=(
            "ASH Scan Results Summary",
            "Scanner \N{BOX DRAWINGS LIGHT VERTICAL} Status",
            "ERROR (2) Exiting due to 2 actionable findings found in ASH scan",
        ),
        typing=cast.TypingSpan(15300, 16500, 36),
    )
    return cast.RunRecord(
        ash_version="awslabs/automated-security-helper v3.8.0",
        scanners=(
            _scanner(cast, "detect-secrets", "PASSED"),
            _scanner(cast, "bandit", "FAILED", high=2, low=1, actionable=2),
        ),
        findings=(
            cast.FindingRecord(
                rule_id="B602", severity="LOW", scanner="bandit", location="app.py:11"
            ),
            cast.FindingRecord(
                rule_id="B324", severity="HIGH", scanner="bandit", location="app.py:7"
            ),
        ),
        reports=("ash_aggregated_results.json", "ash.sarif", "ash.html"),
        scenes=(install, scan),
    )


def _obj(cast):
    return json.loads(cast.record_to_json(_record(cast)))


def test_canonical_json_is_json_dumps_sorted_indent_2_plus_a_newline(cast):
    value = {
        "b": [1, 2, {"z": None, "a": "caf\N{LATIN SMALL LETTER E WITH ACUTE}"}],
        "a": True,
        "c": 1.5,
    }
    text = cast.canonical_json(value)
    assert text == json.dumps(value, sort_keys=True, indent=2) + "\n"
    assert text.isascii()
    assert text.endswith("}\n")
    assert not text.endswith("\n\n")
    assert text.index('"a"') < text.index('"b"') < text.index('"c"')


def test_the_record_json_is_the_canonical_form_of_its_fields(cast):
    record = _record(cast)
    text = cast.record_to_json(record)
    expected = json.dumps(dataclasses.asdict(record), sort_keys=True, indent=2) + "\n"
    assert text == expected
    assert text.isascii()
    bar = "\N{BOX DRAWINGS LIGHT VERTICAL}"
    assert bar not in text
    assert bar in json.loads(text)["scenes"][1]["end_screen"][1]


def test_the_record_json_is_a_fixed_point_of_the_pretty_format_json_hook(cast):
    text = cast.record_to_json(_record(cast))
    assert json.dumps(json.loads(text), indent=2, sort_keys=True) + "\n" == text


def test_the_record_is_canonical_whatever_the_order_it_was_built_in(cast):
    record = _record(cast)
    assert [scanner.name for scanner in record.scanners] == ["bandit", "detect-secrets"]
    assert [finding.rule_id for finding in record.findings] == ["B324", "B602"]
    assert record.reports == ("ash.html", "ash.sarif", "ash_aggregated_results.json")
    reordered = dataclasses.replace(
        record,
        scanners=tuple(reversed(record.scanners)),
        findings=tuple(reversed(record.findings)),
        reports=tuple(reversed(record.reports)),
    )
    assert cast.record_to_json(reordered) == cast.record_to_json(record)


@pytest.mark.parametrize(
    ("field", "first", "second"),
    [
        ("rule_id", "B324", "B602"),
        ("scanner", "bandit", "detect-secrets"),
        # Written as text, so "app.py:11" sorts before "app.py:7".
        ("location", "app.py:11", "app.py:7"),
        ("severity", "HIGH", "LOW"),
    ],
)
def test_findings_that_differ_in_one_field_have_one_order(cast, field, first, second):
    """A sort on any other field leaves a pair like this in the order it came in."""
    same = {
        "rule_id": "B324",
        "severity": "HIGH",
        "scanner": "bandit",
        "location": "app.py:7",
    }
    one = cast.FindingRecord(**{**same, field: first})
    other = cast.FindingRecord(**{**same, field: second})
    record = _record(cast)
    forward = dataclasses.replace(record, findings=(one, other))
    backward = dataclasses.replace(record, findings=(other, one))
    assert [getattr(finding, field) for finding in forward.findings] == [first, second]
    assert cast.record_to_json(forward) == cast.record_to_json(backward)


def test_a_record_reads_back_equal(cast, tmp_path):
    record = _record(cast)
    text = cast.record_to_json(record)
    assert cast.record_from_json(text) == record
    assert cast.record_from_obj(cast.record_to_obj(record)) == record
    path = tmp_path / "quick-start.record.json"
    cast.write_record(path, record)
    assert path.read_bytes() == text.encode("ascii")
    assert cast.read_record(path) == record


@pytest.mark.parametrize(
    ("path", "key", "value", "needle"),
    [
        ((), "extra", 1, "unknown key"),
        ((), "schema", 2, "schema must be 1"),
        ((), "schema", True, "schema must be 1"),
        ((), "ash_version", "", "ash_version"),
        ((), "ash_version", "two\nlines", "ash_version"),
        ((), "reports", "ash.sarif", "reports"),
        (("scanners", 0), "high", -1, "high"),
        (("scanners", 0), "high", True, "high"),
        (("scanners", 0), "high", 1.5, "high"),
        (("scanners", 0), "status", "", "status"),
        (("scanners", 0), "extra", 1, "unknown key"),
        (("findings", 0), "rule_id", "", "rule_id"),
        (("findings", 0), "location", 7, "location"),
        (("scenes", 0), "exit_code", True, "exit_code"),
        (("scenes", 0), "exit_code", "2", "exit_code"),
        (("scenes", 1), "end_screen", "text", "end_screen"),
        (("scenes", 1), "end_screen", [7], "end_screen"),
        (("scenes", 0, "typing"), "end_ms", 100, "end_ms"),
        (("scenes", 0, "typing"), "chars", 0, "chars"),
        (("scenes", 0, "typing"), "start_ms", -1, "start_ms"),
    ],
)
def test_a_record_refuses_what_it_does_not_hold(cast, path, key, value, needle):
    obj = _obj(cast)
    _node(obj, path)[key] = value
    with pytest.raises(cast.RecordError, match=needle):
        cast.record_from_obj(obj)


@pytest.mark.parametrize(
    ("path", "key"),
    [
        ((), "scenes"),
        ((), "ash_version"),
        (("scanners", 0), "actionable"),
        (("findings", 0), "scanner"),
        (("scenes", 0), "typing"),
        (("scenes", 0, "typing"), "chars"),
    ],
)
def test_a_record_needs_every_field(cast, path, key):
    obj = _obj(cast)
    del _node(obj, path)[key]
    with pytest.raises(cast.RecordError, match=rf"missing key\(s\) \['{key}'\]"):
        cast.record_from_obj(obj)


def test_scene_ids_and_scanner_names_are_unique(cast):
    obj = _obj(cast)
    obj["scenes"][1]["scene_id"] = "install"
    with pytest.raises(cast.RecordError, match="duplicate scene id 'install'"):
        cast.record_from_obj(obj)
    obj = _obj(cast)
    obj["scanners"][1]["name"] = "bandit"
    with pytest.raises(cast.RecordError, match="duplicate scanner 'bandit'"):
        cast.record_from_obj(obj)


def test_a_record_must_be_a_json_object(cast):
    with pytest.raises(cast.RecordError, match="must be a mapping"):
        cast.record_from_obj([1])
    with pytest.raises(cast.RecordError, match="not valid JSON"):
        cast.record_from_json("{")
