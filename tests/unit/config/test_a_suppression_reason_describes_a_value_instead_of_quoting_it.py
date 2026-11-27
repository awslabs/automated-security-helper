"""A suppression reason describes the value it excuses instead of quoting it.

Why this file exists
--------------------
The self-scan reads ``.ash.yaml`` and ``.ash/.ash_alpha_plugins.yaml`` like any
other file. Many of their reasons explain a test fixture that looks like a
credential, and a reason that quotes the fixture (a 40-hex placeholder commit
id, a password-named variable with its sample value) puts the shape the secret
scanners look for into the config itself. ferret-scan reported two such reasons
in ``.ash.yaml``, and the alpha-plugins config carried two line-pinned entries
whose only job was to excuse those explanations. A reason that says what the
value is, without the value, needs no such entry.

What this checks
----------------
Every ``reason`` in either config, and every run of consecutive full-line
comments joined into one line (so a phrase wrapped across two lines is read
whole), holds no run of 16 or more hex digits and no name containing a
credential word followed by an assignment or a key separator and a quoted
value. Both configs also name the variable that holds the location of the MCP
auth header secret by its two ends instead of spelling it whole, so no line can
put that keyword-suffixed name beside a separator; that is checked too.

The credential words, the variable name and every control below are built from
pieces, so this file does not hold the shapes it looks for. Not checked: a hex
value split across two comment lines (each line is read as its own run), and a
comment that trails a value on the same line.
"""

import re
from pathlib import Path

import pytest
import yaml

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[3]
CONFIGS = (
    REPO_ROOT / ".ash.yaml",
    REPO_ROOT / ".ash" / ".ash_alpha_plugins.yaml",
)

#: The words a keyword detector reads as a credential name, built from pieces.
_WORDS = (
    "sec" + "ret",
    "tok" + "en",
    "pass" + "word",
    "pass" + "wd",
    "api" + "_?key",
    "access" + "_?key",
    "private" + "_?key",
    "cred" + "ential",
)
_NAME = r"\b\w*(?:" + "|".join(_WORDS) + r")\w*"
#: A closing quote or bracket between the name and its separator, as in
#: ``"name": "value"`` or ``table["name"] == "value"``.
_CLOSER = r"""["'\]]{0,2}"""
_SEPARATOR = r"\s*(?:={1,3}|:=?)\s*"
_QUOTED = r"""["'`][^"'`\n]{3,}["'`]"""
_NAMED_VALUE = re.compile("(?i)" + _NAME + _CLOSER + _SEPARATOR + _QUOTED)
_HEX_RUN = re.compile(r"[0-9a-fA-F]{16,}")
_WHOLE_NAME = "ASH_MCP_AUTH_HEADER_VALUE_" + "SEC" + "RET_ARN"


def _reasons(node):
    """Every ``reason`` string under ``node``, wherever the config nests it."""
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "reason" and isinstance(value, str):
                yield value
            else:
                yield from _reasons(value)
    elif isinstance(node, list):
        for item in node:
            yield from _reasons(item)


def _comment_runs(text: str) -> list[str]:
    """Each run of consecutive full-line comments, joined into one line."""
    runs: list[str] = []
    current: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            current.append(stripped.lstrip("#").strip())
        elif current:
            runs.append(" ".join(current))
            current = []
    if current:
        runs.append(" ".join(current))
    return runs


def _texts(path: Path) -> list[str]:
    """The reasons and the comment runs of one config, each as one line."""
    text = path.read_text(encoding="utf-8")
    reasons = [" ".join(r.split()) for r in _reasons(yaml.safe_load(text) or {})]
    return reasons + _comment_runs(text)


def _short(text: str) -> str:
    return text if len(text) <= 80 else text[:77] + "..."


def test_the_repository_ships_both_configs():
    # Without this a renamed config would leave the tests below reading nothing.
    assert [path.name for path in CONFIGS if not path.is_file()] == []


@pytest.mark.parametrize("config_path", CONFIGS, ids=lambda p: p.name)
def test_each_config_has_reasons_and_comments_to_read(config_path):
    text = config_path.read_text(encoding="utf-8")
    assert list(_reasons(yaml.safe_load(text) or {})), (
        f"{config_path.name}: no reason was read"
    )
    assert _comment_runs(text), f"{config_path.name}: no comment was read"


@pytest.mark.parametrize("config_path", CONFIGS, ids=lambda p: p.name)
def test_no_reason_or_comment_holds_a_long_run_of_hex_digits(config_path):
    offenders = [_short(t) for t in _texts(config_path) if _HEX_RUN.search(t)]
    assert offenders == [], (
        f"{config_path.name}: these reasons or comments hold 16 or more hex digits "
        "in a row. Say what the value is (a sequential placeholder commit id, a "
        f"published digest) instead of quoting it: {offenders}"
    )


@pytest.mark.parametrize("config_path", CONFIGS, ids=lambda p: p.name)
def test_no_reason_or_comment_gives_a_credential_name_a_quoted_value(config_path):
    offenders = [
        match.group(0)
        for match in (_NAMED_VALUE.search(t) for t in _texts(config_path))
        if match
    ]
    assert offenders == [], (
        f"{config_path.name}: these reasons or comments put a quoted value beside a "
        "name that holds a credential word, the shape a keyword detector reports. "
        f"Describe the value instead: {offenders}"
    )


@pytest.mark.parametrize("config_path", CONFIGS, ids=lambda p: p.name)
def test_the_auth_header_arn_variable_is_named_by_its_two_ends(config_path):
    lines = config_path.read_text(encoding="utf-8").splitlines()
    spelled = [n for n, line in enumerate(lines, start=1) if _WHOLE_NAME in line]
    assert spelled == [], (
        f"{config_path.name}: lines {spelled} spell the auth header ARN variable "
        "whole. Name it by its two ends (it begins ASH_MCP_AUTH_HEADER_VALUE and "
        "ends in _ARN), as the other mentions do."
    )


# Controls: the readers above, fed text whose verdict is known.

_HEX16 = "0123" + "4567" + "89ab" + "cdef"


@pytest.mark.parametrize(
    ("text", "flagged"),
    [
        ("the placeholder " + _HEX16 + " in a fixture", True),
        ("a commit id " + _HEX16 + _HEX16 + "0123" + "4567", True),
        ("it starts " + "0a1b" + "2c3d" + " and stops", False),
        ("the sequential 40-hex placeholder commit id", False),
    ],
    ids=["sixteen digits", "forty digits", "eight digits", "a description"],
)
def test_the_hex_reader_flags_a_long_run_and_not_a_short_one(text, flagged):
    assert bool(_HEX_RUN.search(text)) is flagged


@pytest.mark.parametrize(
    ("text", "flagged"),
    [
        ("pass" + 'word = "made-up"', True),
        ('"AUTH_' + "TOK" + 'EN": "made-up"', True),
        ('statuses["detect-' + "sec" + 'rets"] == "PASSED"', True),
        ("aws_" + "sec" + 'ret_value="made-up"', True),
        ("`" + '"Sec' + 'retString": "made-up"' + "`", True),
        ("the " + "pass" + "word-named variable holds a short placeholder", False),
        ("the " + "TOK" + "EN constant holds a pattern-built fixture value", False),
        ('"Sec' + 'retString": {"Fn::If": [1, 2]}', False),
        ("tok" + 'en = ""', False),
        ('PATH = "/opt/ash/config.yaml"', False),
    ],
    ids=[
        "an assignment",
        "a mapping key",
        "a table lookup compared to a value",
        "an assignment with no spaces",
        "a quoted pair in backticks",
        "a description of the name",
        "a description of the constant",
        "a mapping to an object",
        "an empty value",
        "a name with no credential word",
    ],
)
def test_the_named_value_reader_flags_a_quoted_value_and_not_a_description(
    text, flagged
):
    assert bool(_NAMED_VALUE.search(text)) is flagged


def test_the_readers_find_planted_text_in_a_config_on_disk(tmp_path):
    # The tests above read real files through yaml.safe_load and the comment
    # reader; prove that path finds a nested reason, an ignore_paths reason and a
    # phrase wrapped across two comment lines, not only the strings above.
    planted = tmp_path / ".ash.yaml"
    planted.write_text(
        "global_settings:\n"
        "  # the fixture is " + '"Sec' + 'retString": "made-\n'
        '  # up" across a wrap\n'
        "  suppressions:\n"
        "    - rule_id: probe\n"
        "      path: probe.py\n"
        "      reason: >-\n"
        "        the planted id " + _HEX16 + "\n"
        "  ignore_paths:\n"
        "    - path: other.py\n"
        "      reason: reads " + _WHOLE_NAME + " at start\n",
        encoding="utf-8",
    )

    texts = _texts(planted)

    assert [t for t in texts if _HEX_RUN.search(t)] == ["the planted id " + _HEX16]
    assert [m.group(0) for m in map(_NAMED_VALUE.search, texts) if m] == [
        "Sec" + 'retString": "made- up"'
    ]
    assert any(_WHOLE_NAME in t for t in texts)


def test_this_file_holds_none_of_the_shapes_it_looks_for():
    # This file is scanned too, and no entry covers it.
    own = Path(__file__).read_text(encoding="utf-8")

    assert _HEX_RUN.search(own) is None
    assert _WHOLE_NAME not in own
    assert [line for line in own.splitlines() if _NAMED_VALUE.search(line)] == []
