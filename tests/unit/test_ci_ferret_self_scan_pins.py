# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Line-pinned suppressions for the ferret plugin's files name the lines they excuse.

Why this exists
---------------
``.ash/.ash_alpha_plugins.yaml`` excuses hits in the ferret plugin's files by line.
Each entry was written for a line of its file when the plugin was added. The files
changed after that, the entries did not move, and a pin that points at a blank line, a
comment or an unrelated statement excuses nothing. It happened to the two
``SECRET-SECRET-KEYWORD`` entries (one for the plugin's development notes, one for its
test fixtures), which both pinned a blank line, and then to four more: the
``subprocess`` import and the call that runs ferret-scan in ``ferret_scanner.py``, and
the card narrative lines in ``scripts/generate_test_docx.py``. Nothing noticed:
``scripts/validate_ferret_plugin.py`` judges the hits its own pattern finds and never
compares an entry's range with the file, and a pin that excuses nothing reads the same
in the config as one that works.

``SECRET-SECRET-KEYWORD`` and ``SECRET-HEX-HIGH-ENTROPY-STRING`` are detect-secrets rule
ids, and detect-secrets is off in that config (``scanners.detect-secrets.enabled:
false``), so no scan of that config could read an entry for them. The entries were
removed, and ``_PIN_MARKERS`` is empty until one returns with detect-secrets. This
test reads only the alpha-plugins config; ``.ash/.ash.yaml`` has no pin of this kind.

What this checks
----------------
Every ``SECRET-SECRET-KEYWORD`` entry with a line in the alpha-plugins config, and
every entry with a line for a rule that has a row in ``_RANGED_PIN_MARKERS``, needs both
``line_start`` and ``line_end`` as integers. ASH reads a ``line_start`` with no
``line_end`` as running to the end of the file (``utils/suppression_matcher.py``), so a
pin that lost its end would silently excuse every later hit in the file.

A row is a list of markers, one for each entry the file has. A marker is the line the
entry was written for, as a pattern that matches exactly one line; a block of lines has
one pattern per line, and a rule that fires on many lines of one file has a pattern that
may match all of them. Each entry must hold exactly one marker, in full, and each marker
must be held by exactly one entry, so a second pin in the same file needs a second
marker. A pin that moved fails with the line number to use.

A ``SECRET-SECRET-KEYWORD`` entry with no row in ``_PIN_MARKERS`` fails until it gets
one. An entry for another rule is looked at only if ``_RANGED_PIN_MARKERS`` has a row
for its rule and path. The GuardDog entries (``test_ci_guarddog_self_scan_pins.py``)
and the digest tables in ``tool_downloads.py`` (``test_pinned_tool_downloads.py`` and
``test_third_party_licenses.py``) have tests of their own, and a new ranged entry for
some other rule is not checked until it gets a row.

The patterns are chosen so that this file does not trigger the rules it guards: none of
them has a keyword name beside an assignment, and none spells out a card number or a
passport line.
"""

import re
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest
import yaml

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[2]
ALPHA_CONFIG = REPO_ROOT / ".ash" / ".ash_alpha_plugins.yaml"
RULE = "SECRET-SECRET-KEYWORD"

PLUGIN_DIR = "automated_security_helper/plugin_modules/ash_ferret_plugins"
TEST_DIR = "tests/unit/plugin_modules/ash_ferret_plugins"
FERRET_SCANNER = f"{PLUGIN_DIR}/ferret_scanner.py"
DOCX_SCRIPT = "scripts/generate_test_docx.py"
TOOL_CONFIG_TRUST = "automated_security_helper/config/tool_config_trust.py"
OPERATIONAL_FACETS = "automated_security_helper/base/scanner_operational_facets.py"
FINDING_TREND_TEST = "tests/unit/utils/test_finding_trend.py"
HADOLINT_BEHAVIOR_TEST = (
    "tests/unit/plugin_modules/ash_hadolint_plugins/test_hadolint_scanner_behavior.py"
)
BETTERLEAKS_SCANNER_TEST = (
    "tests/unit/plugin_modules/ash_betterleaks_plugins/test_betterleaks_scanner.py"
)
MCP_CONFIG_SCANNER = "automated_security_helper/plugin_modules/ash_builtin/scanners/mcp_config_scanner.py"
IMAGE_DELIVERY_SNAPSHOT = "tests/snapshot/mcp/test_snapshot_mcp_image_delivery.py"
IMAGE_DELIVERY_TEST = "tests/unit/cli/mcp/test_image_delivery_names_one_subject.py"
IMAGE_ANCHOR_TEST = (
    "tests/unit/cli/mcp/test_run_ash_scan_anchors_an_image_scan_in_its_own_directory.py"
)
DEPENDABOT_WORKFLOW = ".github/workflows/ash-dependabot-auto-merge.yml"


@dataclass(frozen=True)
class _Marker:
    """The line, or the block of lines, one pinned entry was written for.

    Each pattern is a regular expression searched in every line, and must match exactly
    one line, so the marker names that line and not a kind of line. A marker with
    several patterns names a block. With ``every_line`` a pattern may match several
    lines, and the marker names all of them.
    """

    patterns: tuple[str, ...]
    every_line: bool = False


#: The line each pinned entry was written for, by the path the entry names, as a list
#: of markers: a path with two pinned entries has two. When a file changes above its
#: pin, this row is what says which line the pin has to move to. An entry whose path has
#: no row fails below, and so does a row whose entry is gone.
#: Empty while the alpha-plugins config carries no SECRET-SECRET-KEYWORD pin: that is
#: a detect-secrets rule id, detect-secrets is off in that config, and its two pins
#: (the plugin's development notes and its test conftest) were removed because they
#: could not match.
_PIN_MARKERS: dict[str, list[_Marker]] = {}

#: The calls to the random module that the docx generator makes.
_RANDOM_CALL = (
    r"\brandom\.(?:Random|choice|choices|getrandbits|randbytes|randint|randrange"
    r"|random|sample|triangular|uniform)\("
)

#: The same for the other rules, by rule id and path. A moved pin fails below with the
#: line to use, and so does a row whose entry is gone. An entry with no row here is not
#: looked at.
#: Entries scoped by ``symbol`` instead of a line range have no rows here: the
#: resolver finds the definition wherever it moves, and
#: tests/unit/config/test_symbol_migration_record.py holds each one to a symbol
#: that resolves.
_RANGED_PIN_MARKERS: dict[tuple[str, str], list[_Marker]] = {
    # The three ferret_scanner.py bandit pins are gone: the import and the call carry
    # nosec comments, bandit reports nothing for either, and the pins excused nothing
    # (test_product_bandit_subprocess_pins.py holds the comments in place).
    #
    # The one line the ferret-scan 2.6.1 self-scan reports in tool_config_trust.py: the
    # row of the scanner-option table that pairs the detect-secrets scanner with its
    # baseline option. The pattern names the row without spelling it out.
    ("API_KEY_OR_SECRET", TOOL_CONFIG_TRUST): [
        _Marker((r'detect-secrets"\W+\(\W*baseline_file',)),
    ],
    # The enum member whose name is a token word, one line of the facets module.
    ("API_KEY_OR_SECRET", OPERATIONAL_FACETS): [
        _Marker((r"^    AUTH_TOKEN = ",)),
    ],
    # The report-id helper's twelve-hex-digit default argument.
    ("API_KEY_OR_SECRET", FINDING_TREND_TEST): [
        _Marker((r"^def report_id\(second, token=",)),
    ],
    # The two lines of .ash.yaml whose reasons quote a placeholder fixture; they
    # are the findings the self-scan reports on that file, and each is the one line of
    # the file that has this shape.
    ("API_KEY_OR_SECRET", ".ash.yaml"): [
        _Marker((r'HEAD = "[0-9a-f]{40}" and TOKEN =',)),
        _Marker((r'`\w+ = "abcdefghijklmnop"` is a fixture',)),
    ],
    # Every line that draws a value from the random module, as the file was written.
    ("B311", DOCX_SCRIPT): [_Marker((_RANDOM_CALL,), every_line=True)],
    # The two MRZ-style passport lines of the MRZ_LINES tuple, each padded to the TD3
    # length with the "<" filler. The padding call is what no other line of the file
    # has, so the pattern names the two lines without spelling out a passport line.
    ("PASSPORT", DOCX_SCRIPT): [
        _Marker((r'\.ljust\(TD3_LINE_LENGTH, "<"\)',), every_line=True),
    ],
    # The block of three constants the hadolint behavior test compares the vendored
    # license files against: the commit its tag points at and two file digests. One
    # pin takes the three lines; the patterns name the constants, not their values.
    ("API_KEY_OR_SECRET", HADOLINT_BEHAVIOR_TEST): [
        _Marker(
            (
                r'^    COMMIT = "',
                r'^    LICENSE_SHA256 = "',
                r'^    NOTICES_SHA256 = "',
            )
        ),
    ],
    # The one constant the betterleaks pinned-release test compares the Dockerfile's
    # pin against: the commit the v1.10.1 tag points at.
    ("API_KEY_OR_SECRET", BETTERLEAKS_SCANNER_TEST): [
        _Marker((r'^    COMMIT = "',)),
    ],
    # The MCP config scanner's rule-id constant for an environment value, one line of
    # the module. The pattern names the constant by its prefix and its value's.
    ("API_KEY_OR_SECRET", MCP_CONFIG_SCANNER): [
        _Marker((r'^RULE_ENV_\w+ = "MCP-ENV-',)),
    ],
    # The two module constants holding the MCP request header the image-delivery
    # snapshot calls send, the refused id first. One pin takes both lines.
    ("API_KEY_OR_SECRET", IMAGE_DELIVERY_SNAPSHOT): [
        _Marker((r'^_BAD_\w+ = \{"mcp-', r'^_[A-Z]+ = \{"mcp-')),
    ],
    # The module constant naming the made-up MCP session each image test delivers to.
    ("API_KEY_OR_SECRET", IMAGE_DELIVERY_TEST): [
        _Marker((r'^_[A-Z]+ = "\w+-image-delivery"$',)),
    ],
    # The same kind of constant in the image-scan anchoring test.
    ("API_KEY_OR_SECRET", IMAGE_ANCHOR_TEST): [
        _Marker((r'^_[A-Z]+ = "\w+-image-anchor"$',)),
    ],
    # The trigger of the dependabot auto-merge workflow, the one line zizmor's
    # dangerous-triggers audit reports. The header comment and the expressions further
    # down also say workflow_run, so the pattern names the key at its indent in the
    # on: block. .ash.yaml carries the same pin, and
    # test_the_two_suppression_files_agree_on_shared_entries.py holds the two together.
    ("zizmor/dangerous-triggers", DEPENDABOT_WORKFLOW): [
        _Marker((r"^  workflow_run:",)),
    ],
}


def _ranged_keyword_pins(config_path: Path = ALPHA_CONFIG) -> list[dict[str, Any]]:
    config = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
    entries = (config.get("global_settings") or {}).get("suppressions") or []
    return [
        entry
        for entry in entries
        if entry.get("rule_id") == RULE
        and (entry.get("line_start") is not None or entry.get("line_end") is not None)
    ]


def _ranged_pins_with_rows(
    config_path: Path = ALPHA_CONFIG,
    rows: dict[tuple[str, str], list[_Marker]] = _RANGED_PIN_MARKERS,
) -> list[dict[str, Any]]:
    config = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
    entries = (config.get("global_settings") or {}).get("suppressions") or []
    return [
        entry
        for entry in entries
        if (entry.get("rule_id"), entry.get("path")) in rows
        and (entry.get("line_start") is not None or entry.get("line_end") is not None)
    ]


def _range_problem(entry: dict[str, Any]) -> str | None:
    """What is wrong with the range ``entry`` gives, or None when it gives both ends.

    ASH reads a ``line_start`` with no ``line_end`` as running to the end of the file,
    and a ``line_end`` with no ``line_start`` as running from the first line, so a pin
    that lacks either end excuses more than the one line it was written for.
    """
    for key in ("line_start", "line_end"):
        value = entry.get(key)
        if value is None:
            return (
                f"{key} is not set, and ASH reads a missing end as the edge of the "
                f"file; add {key}"
            )
        if isinstance(value, bool) or not isinstance(value, int):
            return f"{key} is {value!r}, not an integer; give the line number"
    return None


def _marker_lines(lines: list[str], marker: _Marker) -> tuple[list[int], str | None]:
    """The line numbers ``marker`` names, or what is wrong with it."""
    named: set[int] = set()
    for pattern in marker.patterns:
        holders = [n for n, line in enumerate(lines, 1) if re.search(pattern, line)]
        if marker.every_line and not holders:
            return [], f"{pattern!r} is on no line, expected at least one"
        if not marker.every_line and len(holders) != 1:
            return [], (
                f"{pattern!r} is on {len(holders)} lines {holders}, "
                "expected exactly one"
            )
        named.update(holders)
    return sorted(named), None


def _pin_problem(
    lines: list[str], start: int, end: int, markers: Sequence[_Marker]
) -> str | None:
    """What is wrong with a pin on lines ``start`` to ``end``, or None when it holds.

    The pin must hold exactly one of ``markers``, all of its lines.
    """
    named = []
    for marker in markers:
        found, problem = _marker_lines(lines, marker)
        if problem:
            return problem
        named.append(found)
    held = [found for found in named if any(start <= n <= end for n in found)]
    if not held:
        wanted = sorted(n for found in named for n in found)
        if len(wanted) == 1:
            return f"the line it was written for is {wanted[0]}, outside {start}-{end}"
        return f"it was written for lines {wanted}, none of them inside {start}-{end}"
    if len(held) > 1:
        return (
            f"{start}-{end} holds {len(held)} markers, on lines {held}; "
            "a pin is written for one"
        )
    outside = [n for n in held[0] if not start <= n <= end]
    if outside:
        return (
            f"the lines it was written for are {held[0]}, and {start}-{end} leaves "
            f"out {outside}"
        )
    return None


def _cover_problems(
    lines: list[str], ranges: Sequence[tuple[int, int]], markers: Sequence[_Marker]
) -> list[str]:
    """The markers that no pin covers, or that more than one pin covers."""
    problems = []
    for marker in markers:
        found, problem = _marker_lines(lines, marker)
        if problem:
            problems.append(problem)
            continue
        covering = [r for r in ranges if any(r[0] <= n <= r[1] for n in found)]
        if not covering:
            problems.append(f"the marker on lines {found} is covered by no pin")
        elif len(covering) > 1:
            problems.append(
                f"the marker on lines {found} is covered by {len(covering)} pins, "
                f"{covering}"
            )
    return problems


def _lines_of(path: str) -> list[str]:
    return (REPO_ROOT / path).read_text(encoding="utf-8").splitlines()


_PINS = _ranged_keyword_pins()
_ROW_PINS = _ranged_pins_with_rows()


def _pin_id(entry: dict[str, Any]) -> str:
    return Path(entry["path"]).name


def _row_pin_id(entry: dict[str, Any]) -> str:
    return f"{entry['rule_id']}-{Path(entry['path']).name}"


@pytest.mark.parametrize("entry", _PINS, ids=_pin_id)
def test_every_ranged_keyword_pin_names_the_line_it_was_written_for(entry):
    where = f"{ALPHA_CONFIG.name}: {RULE} {entry['path']}"
    range_problem = _range_problem(entry)
    assert range_problem is None, f"{where}: {range_problem}"

    start, end = entry["line_start"], entry["line_end"]
    markers = _PIN_MARKERS.get(entry["path"])
    assert markers, (
        f"{where}:{start}-{end}: no marker for this path; add a _PIN_MARKERS row"
    )

    problem = _pin_problem(_lines_of(entry["path"]), start, end, markers)

    assert problem is None, (
        f"{where}:{start}-{end}: {problem}. The file moved under the pin; set "
        "line_start and line_end to that line."
    )


def test_every_marker_row_still_has_a_pin():
    # Without this a deleted entry leaves its row behind, and an empty pin list
    # collects zero cases above and passes.
    pinned = {entry["path"] for entry in _PINS}
    assert sorted(set(_PIN_MARKERS) - pinned) == [], (
        f"{ALPHA_CONFIG.name} has no line-pinned {RULE} entry for these paths, "
        "so drop their rows from _PIN_MARKERS"
    )


def test_every_keyword_marker_is_covered_by_exactly_one_pin():
    problems = []
    for path, markers in _PIN_MARKERS.items():
        ranges = [
            (entry["line_start"], entry["line_end"])
            for entry in _PINS
            if entry["path"] == path and _range_problem(entry) is None
        ]
        problems += [
            f"{path}: {problem}"
            for problem in _cover_problems(_lines_of(path), ranges, markers)
        ]

    assert problems == [], f"{ALPHA_CONFIG.name}: {RULE}: {'; '.join(problems)}"


@pytest.mark.parametrize("entry", _ROW_PINS, ids=_row_pin_id)
def test_every_ranged_pin_with_a_marker_row_names_the_lines_it_was_written_for(entry):
    where = f"{ALPHA_CONFIG.name}: {entry['rule_id']} {entry['path']}"
    range_problem = _range_problem(entry)
    assert range_problem is None, f"{where}: {range_problem}"

    start, end = entry["line_start"], entry["line_end"]
    markers = _RANGED_PIN_MARKERS[(entry["rule_id"], entry["path"])]

    problem = _pin_problem(_lines_of(entry["path"]), start, end, markers)

    assert problem is None, (
        f"{where}:{start}-{end}: {problem}. The file moved under the pin; set "
        "line_start and line_end to cover the lines it was written for."
    )


def test_every_ranged_pin_row_still_has_an_entry():
    # Without this a deleted entry leaves its row behind, and an empty pin list
    # collects zero cases above and passes.
    pinned = {(entry["rule_id"], entry["path"]) for entry in _ROW_PINS}
    assert sorted(set(_RANGED_PIN_MARKERS) - pinned) == [], (
        f"{ALPHA_CONFIG.name} has no line-pinned entry for these (rule, path) "
        "pairs, so drop their rows from _RANGED_PIN_MARKERS"
    )


def test_every_ranged_pin_marker_is_covered_by_exactly_one_pin():
    problems = []
    for (rule_id, path), markers in _RANGED_PIN_MARKERS.items():
        ranges = [
            (entry["line_start"], entry["line_end"])
            for entry in _ROW_PINS
            if (entry["rule_id"], entry["path"]) == (rule_id, path)
            and _range_problem(entry) is None
        ]
        problems += [
            f"{rule_id} {path}: {problem}"
            for problem in _cover_problems(_lines_of(path), ranges, markers)
        ]

    assert problems == [], f"{ALPHA_CONFIG.name}: {'; '.join(problems)}"


# Controls: the predicates above, fed input whose verdict is known.

SAMPLE = ["first line", "", "the marked line", "last line"]
MARKER = "marked line"
MARKERS = [_Marker((MARKER,))]


@pytest.mark.parametrize(
    ("start", "end"),
    [(3, 3), (2, 4), (3, 4), (1, 3)],
    ids=["names the line", "spans it", "starts on it", "ends on it"],
)
def test_a_range_that_includes_the_marked_line_is_accepted(start, end):
    assert _pin_problem(SAMPLE, start, end, MARKERS) is None


@pytest.mark.parametrize(
    ("start", "end"),
    [(2, 2), (4, 4), (1, 2), (1, 1)],
    ids=[
        "a blank line",
        "the line after",
        "a range ending before it",
        "the first line",
    ],
)
def test_a_range_that_misses_the_marked_line_is_reported(start, end):
    problem = _pin_problem(SAMPLE, start, end, MARKERS)

    assert problem is not None
    assert f"is 3, outside {start}-{end}" in problem


@pytest.mark.parametrize(
    "lines",
    [["no marker here", "or here"], ["marked line", "between", "marked line again"]],
    ids=["a marker the file does not hold", "a marker on two lines"],
)
def test_a_marker_that_is_not_on_exactly_one_line_is_reported(lines):
    problem = _pin_problem(lines, 1, len(lines), MARKERS)

    assert problem is not None
    assert "expected exactly one" in problem


@pytest.mark.parametrize(
    "entry",
    [{"line_start": 3, "line_end": 3}, {"line_start": 2, "line_end": 4}],
    ids=["a one-line range", "a longer range"],
)
def test_a_range_with_both_ends_is_accepted(entry):
    assert _range_problem(entry) is None


@pytest.mark.parametrize(
    ("entry", "key"),
    [
        ({"line_start": 3}, "line_end"),
        ({"line_start": 3, "line_end": None}, "line_end"),
        ({"line_end": 3}, "line_start"),
        ({"line_start": "3", "line_end": 3}, "line_start"),
        ({"line_start": 3, "line_end": True}, "line_end"),
    ],
    ids=[
        "missing line_end",
        "null line_end",
        "missing line_start",
        "a quoted line number",
        "a boolean line_end",
    ],
)
def test_a_range_without_two_integer_ends_is_reported(entry, key):
    problem = _range_problem(entry)

    assert problem is not None
    assert problem.startswith(f"{key} is ")


def test_only_ranged_entries_for_the_keyword_rule_are_pins(tmp_path):
    config = tmp_path / "config.yaml"
    config.write_text(
        "global_settings:\n"
        "  suppressions:\n"
        "    - path: pinned.md\n"
        f"      rule_id: {RULE}\n"
        "      line_start: 4\n"
        "      line_end: 4\n"
        "    - path: open-ended.md\n"
        f"      rule_id: {RULE}\n"
        "      line_start: 4\n"
        "    - path: whole-file.md\n"
        f"      rule_id: {RULE}\n"
        "    - path: other-rule.md\n"
        "      rule_id: B404\n"
        "      line_start: 9\n"
        "      line_end: 9\n",
        encoding="utf-8",
    )

    assert [entry["path"] for entry in _ranged_keyword_pins(config)] == [
        "pinned.md",
        "open-ended.md",
    ]


# Controls for the rows: one marker per entry, one entry per marker, blocks of lines,
# and the selection of the entries that have a row.

TWO = ["first", "marker one", "between", "marker two", "last"]
TWO_MARKERS = [_Marker(("marker one",)), _Marker(("marker two",))]
BLOCK = ["first", "head of block", "between", "tail of block", "last"]
BLOCK_MARKERS = [_Marker(("head of block", "tail of block"))]
EVERY = ["first", "the marked line", "between", "the marked line again", "last"]
EVERY_MARKERS = [_Marker((MARKER,), every_line=True)]


@pytest.mark.parametrize(
    ("start", "end"),
    [(2, 4), (1, 5)],
    ids=["from one marker to the other", "the whole file"],
)
def test_a_pin_that_holds_two_markers_is_reported(start, end):
    problem = _pin_problem(TWO, start, end, TWO_MARKERS)

    assert problem is not None
    assert "holds 2 markers" in problem


@pytest.mark.parametrize(
    ("start", "end"),
    [(2, 2), (4, 4), (1, 3), (3, 5)],
    ids=["the first marker", "the second marker", "a wider first", "a wider second"],
)
def test_a_pin_that_holds_one_of_two_markers_is_accepted(start, end):
    assert _pin_problem(TWO, start, end, TWO_MARKERS) is None


def test_a_pin_that_holds_none_of_two_markers_is_reported():
    problem = _pin_problem(TWO, 3, 3, TWO_MARKERS)

    assert problem is not None
    assert "none of them inside 3-3" in problem


def test_two_pins_that_hold_one_marker_each_are_accepted():
    assert _cover_problems(TWO, [(2, 2), (4, 4)], TWO_MARKERS) == []


@pytest.mark.parametrize(
    "ranges",
    [[(2, 2), (1, 3)], [(2, 4), (4, 4)]],
    ids=["a pin inside a wider one", "two pins that overlap"],
)
def test_a_marker_that_two_pins_cover_is_reported(ranges):
    problems = _cover_problems(TWO, ranges, TWO_MARKERS)

    assert len(problems) >= 1
    assert any("is covered by 2 pins" in problem for problem in problems)


def test_a_marker_that_no_pin_covers_is_reported():
    problems = _cover_problems(TWO, [(2, 2)], TWO_MARKERS)

    assert problems == ["the marker on lines [4] is covered by no pin"]


@pytest.mark.parametrize(
    ("start", "end"),
    [(2, 4), (1, 5)],
    ids=["exactly its lines", "wider"],
)
def test_a_block_marker_held_in_full_is_accepted(start, end):
    assert _pin_problem(BLOCK, start, end, BLOCK_MARKERS) is None


@pytest.mark.parametrize(
    ("start", "end", "outside"),
    [(2, 3, "[4]"), (3, 4, "[2]"), (2, 2, "[4]")],
    ids=["the tail left out", "the head left out", "the head only"],
)
def test_a_pin_that_leaves_part_of_a_block_out_is_reported(start, end, outside):
    problem = _pin_problem(BLOCK, start, end, BLOCK_MARKERS)

    assert problem is not None
    assert f"leaves out {outside}" in problem


def test_a_pin_that_misses_a_block_is_reported():
    problem = _pin_problem(BLOCK, 5, 5, BLOCK_MARKERS)

    assert problem is not None
    assert "it was written for lines [2, 4], none of them inside 5-5" in problem


@pytest.mark.parametrize(
    ("start", "end"),
    [(2, 4), (1, 5)],
    ids=["from the first match to the last", "wider"],
)
def test_an_every_line_range_that_includes_every_match_is_accepted(start, end):
    assert _pin_problem(EVERY, start, end, EVERY_MARKERS) is None


@pytest.mark.parametrize(
    ("start", "end", "outside"),
    [(1, 3, "[4]"), (3, 5, "[2]"), (2, 2, "[4]")],
    ids=["the last match left out", "the first match left out", "one match only"],
)
def test_an_every_line_range_that_leaves_a_match_out_is_reported(start, end, outside):
    problem = _pin_problem(EVERY, start, end, EVERY_MARKERS)

    assert problem is not None
    assert f"leaves out {outside}" in problem


def test_an_every_line_pattern_that_matches_nothing_is_reported():
    problem = _pin_problem(["first"], 1, 1, EVERY_MARKERS)

    assert problem is not None
    assert "is on no line" in problem


@pytest.mark.parametrize(
    ("key", "hit", "miss"),
    [
        (
            ("API_KEY_OR_SECRET", TOOL_CONFIG_TRUST),
            # Built from two halves so that this file does not hold the flagged row.
            '    "detect-' + 'secrets": ("baseline_file",),',
            '    "ferret-scan": ("config_file",),',
        ),
        (
            ("API_KEY_OR_SECRET", OPERATIONAL_FACETS),
            "    AUTH_" + "TOK" + 'EN = "auth_' + "tok" + 'en"',
            '    AUTH_HEADER = "auth_header"',
        ),
        (
            ("API_KEY_OR_SECRET", FINDING_TREND_TEST),
            "def report_id(second, tok" + "en=" + '"012345678901"):',
            "def other_id(second, count=3):",
        ),
        (
            ("API_KEY_OR_SECRET", ".ash.yaml"),
            'HEAD = "' + "0123456789abcdef0123456789abcdef01234567" + '" and TOKEN =',
            'HEAD = "unset" and nothing else',
        ),
        (
            ("API_KEY_OR_SECRET", ".ash.yaml"),
            "`sec" + 'ret = "abcdefghijklmnop"` is a fixture fed into',
            "`value` is a fixture fed into",
        ),
        (
            ("B311", DOCX_SCRIPT),
            "    area = random.randint(900, 999)  # nosec B311",
            "random.seed(42)",
        ),
        (
            ("PASSPORT", DOCX_SCRIPT),
            '    "P<USA".ljust(TD3_LINE_LENGTH, "<"),',
            "    for mrz_line in MRZ_LINES:",
        ),
        (
            ("zizmor/dangerous-triggers", DEPENDABOT_WORKFLOW),
            "  workflow_run: # zizmor: ignore[dangerous-triggers]",
            "  group: ${{ github.workflow }}-${{ github.event.workflow_run.head_sha }}",
        ),
    ],
    ids=[
        "tool_config_trust",
        "operational_facets",
        "finding_trend_test",
        "ash_yaml_head",
        "ash_yaml_secret",
        "B311",
        "PASSPORT",
        "zizmor_trigger",
    ],
)
def test_a_row_pattern_matches_its_line_and_not_a_near_miss(key, hit, miss):
    patterns = [p for marker in _RANGED_PIN_MARKERS[key] for p in marker.patterns]

    assert any(re.search(pattern, hit) for pattern in patterns)
    assert not any(re.search(pattern, miss) for pattern in patterns)


def test_only_ranged_entries_that_have_a_row_are_selected(tmp_path):
    config = tmp_path / "config.yaml"
    config.write_text(
        "global_settings:\n"
        "  suppressions:\n"
        "    - path: pinned.py\n"
        "      rule_id: B404\n"
        "      line_start: 4\n"
        "      line_end: 4\n"
        "    - path: open-ended.py\n"
        "      rule_id: B404\n"
        "      line_start: 4\n"
        "    - path: pinned.py\n"
        "      rule_id: B311\n"
        "      line_start: 4\n"
        "      line_end: 4\n"
        "    - path: whole-file.py\n"
        "      rule_id: B404\n",
        encoding="utf-8",
    )
    rows = {
        ("B404", "pinned.py"): [_Marker(("x",))],
        ("B404", "open-ended.py"): [_Marker(("x",))],
        ("B404", "whole-file.py"): [_Marker(("x",))],
    }

    selected = _ranged_pins_with_rows(config, rows)

    assert [(entry["rule_id"], entry["path"]) for entry in selected] == [
        ("B404", "pinned.py"),
        ("B404", "open-ended.py"),
    ]


# This file is scanned too, and no entry covers it. The docstring promises that none of
# its patterns has a keyword name beside an assignment, so the test strings that stand
# for the flagged lines are built from halves, and this reads the file's own text to
# keep them that way. The keywords are built from halves for the same reason.
_KEYWORD_NAMES = ("sec" + "ret", "tok" + "en", "pass" + "word", "api" + "_key")
_KEYWORD_ASSIGNMENT = re.compile(
    r"(?i)(?:" + "|".join(_KEYWORD_NAMES) + r")\w*\s*=\s*"
    r"(?:\"[^\"\n]{3,}\"|'[^'\n]{3,}')"
)


def _keyword_assignment_lines(text: str) -> list[str]:
    return [
        f"{number}: {line.strip()}"
        for number, line in enumerate(text.splitlines(), start=1)
        if _KEYWORD_ASSIGNMENT.search(line)
    ]


def test_this_file_spells_no_keyword_name_beside_an_assignment_with_a_value():
    own_text = Path(__file__).read_text(encoding="utf-8")

    assert _keyword_assignment_lines(own_text) == []


@pytest.mark.parametrize(
    ("text", "flagged"),
    [
        ("sec" + "ret" + ' = "abcdefghijklmnop"', True),
        ("    AUTH_" + "TOKEN" + ' = "auth_' + "' + 'token\"", True),
        ("def report_id(second, tok" + "en=" + '" + \'"012345678901"):', True),
        ("sec" + "ret", False),
        ("AUTH_" + "TOKEN" + ' = ",', False),
        ('HEAD = "unset" and nothing else', False),
    ],
    ids=[
        "a quoted value",
        "a value cut by a concatenation",
        "an argument default cut by a concatenation",
        "the bare keyword",
        "an assignment that ends the string",
        "no keyword",
    ],
)
def test_the_keyword_assignment_reader_flags_a_flagged_line_and_not_a_near_miss(
    text, flagged
):
    assert bool(_keyword_assignment_lines(text)) is flagged
