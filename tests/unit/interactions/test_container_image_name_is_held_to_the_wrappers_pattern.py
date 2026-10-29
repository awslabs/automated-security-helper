# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``ash scan --mode container`` takes the image names the wrappers take.

./ash and Invoke-ASH hold ASH_IMAGE_NAME to A-Z, a-z, 0-9 and . _ : / @ -, not
starting with '-', and refuse anything else with 3 before anything is built or run.
Container mode applies the same check to the variable before the build and the
run, with the same message and code, so the three entrypoints
split the wrappers' own corpus of names the same way. An empty ASH_IMAGE_NAME names
no image there either, so the default is used.
"""

from __future__ import annotations

import itertools
import re
from typing import Any, Dict

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli.main import app
from automated_security_helper.interactions import run_ash_container as rac
from automated_security_helper.utils import subprocess_utils
from automated_security_helper.utils.subprocess_utils import create_completed_process
from tests.unit.test_powershell_wrapper_matches_ash import REFUSAL_EXIT, _IMAGE_NAMES

pytestmark = pytest.mark.unit

SCAN = [
    "scan",
    "--mode",
    "container",
    "--no-progress",
    "--source-dir",
    "src",
    "--output-dir",
    "out",
]

#: The refusal both wrappers give, up to the value.
REFUSAL_TEXT = "The image name '"


@pytest.fixture
def runtime(monkeypatch, tmp_path) -> Dict[str, Any]:
    """Every collaborator that would reach an OCI runtime, replaced by a recorder."""
    monkeypatch.chdir(tmp_path)
    (tmp_path / "src").mkdir()
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text("FROM scratch\n", encoding="utf-8")

    seen: Dict[str, Any] = {"built": [], "run": []}

    monkeypatch.setattr(subprocess_utils, "get_host_uid", lambda: 1000)
    monkeypatch.setattr(subprocess_utils, "get_host_gid", lambda: 1000)
    monkeypatch.setattr(rac, "_find_runner", lambda _name: "/usr/bin/docker")
    monkeypatch.setattr(rac, "get_ash_revision", lambda quiet=False: "LOCAL")
    monkeypatch.setattr(rac, "_find_dockerfile", lambda _rev: dockerfile)

    def fake_build(**kwargs):
        seen["built"].append(kwargs["image_name"])

    def fake_execute(cmd, debug=False, env=None):
        seen["run"].append(list(cmd))
        return create_completed_process(args=list(cmd), returncode=0)

    monkeypatch.setattr(rac, "_build_image", fake_build)
    monkeypatch.setattr(rac, "_execute_container", fake_execute)
    for name in ("CI", "IsCI", "ISCI", "CODEBUILD_BUILD_ID", "ASH_IMAGE_NAME"):
        monkeypatch.delenv(name, raising=False)
    return seen


@pytest.mark.parametrize("cell", sorted(_IMAGE_NAMES))
def test_container_mode_splits_the_image_names_as_the_wrappers_do(
    runtime, monkeypatch, cell
):
    name, code = _IMAGE_NAMES[cell]
    monkeypatch.setenv("ASH_IMAGE_NAME", name)

    result = CliRunner().invoke(app, SCAN)

    if code == REFUSAL_EXIT:
        assert result.exit_code == REFUSAL_EXIT, result.output
        assert REFUSAL_TEXT in result.output, result.output
        assert runtime["built"] == [] and runtime["run"] == [], runtime
    else:
        assert result.exit_code != REFUSAL_EXIT, result.output
        assert REFUSAL_TEXT not in result.output, result.output
        assert runtime["built"] == [name], runtime
        assert any(name in command for command in runtime["run"]), runtime


def _read_back(shown: str) -> str:
    """A refused value read back from the refusal that shows it.

    utils/terminal_text.py's rule: an odd run of backslashes before xNN, uNNNN or
    UNNNNNNNN ends in an escape, and an even run is text; any other backslash is as
    typed. A backslash before t, n or r is text too.
    """

    def read(match: re.Match[str]) -> str:
        run, escape = match.group(1), match.group(2)
        half = "\\" * (len(run) // 2)
        if len(run) % 2 == 0:
            return half + escape
        return half + chr(int(escape[1:], 16))

    return re.sub(
        r"(\\+)(x[0-9A-Fa-f]{2}|u[0-9A-Fa-f]{4}|U[0-9A-Fa-f]{8})", read, shown
    )


def _shown_in_refusal(output: str, before: str, after: str) -> str:
    """The value the one line of the refusal shows between *before* and *after*."""
    lines = [line for line in output.splitlines() if before in line]
    assert len(lines) == 1, output
    line = lines[0]
    assert after in line, output
    assert not set("\t\n\r") & set(line), repr(line)
    return line[line.index(before) + len(before) : line.index(after)]


@pytest.mark.parametrize(
    "name",
    ["ash\tname:ci", "ash:ci\n", "ash:ci\r\n", "a\\tb\tc", "ash name:ci"],
    ids=["tab", "newline", "carriage-return", "backslash-t-and-tab", "space"],
)
def test_a_refused_image_name_is_shown_on_one_line(runtime, monkeypatch, name):
    """A tab, newline or carriage return in the name is written out, as the wrappers
    write it, so the refusal stays one line and reads back to the name."""
    monkeypatch.setenv("ASH_IMAGE_NAME", name)

    result = CliRunner().invoke(app, SCAN)

    assert result.exit_code == REFUSAL_EXIT, result.output
    shown = _shown_in_refusal(result.output, REFUSAL_TEXT, "' starts with '-'")
    assert _read_back(shown) == name, shown


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("ash\tname:ci", "ash\\x09name:ci"),
        ("ash:ci\n", "ash:ci\\x0a"),
        ("ash:ci\r\n", "ash:ci\\x0d\\x0a"),
        ("a\\x09\tc", "a\\\\x09\\x09c"),
    ],
    ids=["tab", "newline", "carriage-return", "escape-text-and-tab"],
)
def test_a_refused_image_name_is_shown_as_terminal_text_shows_one_line(
    runtime, monkeypatch, name, expected
):
    """The refusal writes the value as utils/terminal_text.py's shown_on_one_line
    does, the form every other one-line message of ASH's takes: a tab, newline or
    carriage return as \\x09, \\x0a or \\x0d, and the run of backslashes before
    text that reads as an escape doubled."""
    monkeypatch.setenv("ASH_IMAGE_NAME", name)

    result = CliRunner().invoke(app, SCAN)

    assert result.exit_code == REFUSAL_EXIT, result.output
    assert _shown_in_refusal(result.output, REFUSAL_TEXT, "' starts with '-'") == (
        expected
    )


def test_the_shown_form_reads_back_one_to_one():
    """Every string up to four characters long over a set chosen to collide.

    Each is put in the refusal and the whole message shown as the refusal shows it,
    with the shown_on_one_line run_ash_container calls; the result is one line and
    reads back to the value, so no two values look alike.
    """
    alphabet = ["\\", "t", "x", "0", "9", "\t", "\n", "\r", "\x1b", " "]
    values = [
        "".join(chars)
        for length in range(5)
        for chars in itertools.product(alphabet, repeat=length)
    ]
    after = "' starts with '-'"
    shown = set()
    for value in values:
        text = rac.shown_on_one_line(f"{REFUSAL_TEXT}{value}{after}")
        assert not set("\t\n\r\x1b") & set(text), repr(text)
        assert text.startswith(REFUSAL_TEXT) and text.endswith(after), repr(text)
        text = text[len(REFUSAL_TEXT) : -len(after)]
        assert _read_back(text) == value, (value, text)
        shown.add(text)
    assert len(shown) == len(values) == 11111


def test_an_empty_ash_image_name_names_the_default(runtime, monkeypatch):
    monkeypatch.setenv("ASH_IMAGE_NAME", "")

    result = CliRunner().invoke(app, SCAN)

    assert REFUSAL_TEXT not in result.output, result.output
    assert runtime["built"] == ["automated-security-helper:non-root"], runtime
