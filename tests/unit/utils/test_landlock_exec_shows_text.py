# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The sandbox's exec wrapper shows the text its errors quote, as ASH does.

utils/sandbox/landlock_exec.py runs as its own interpreter and imports nothing
from ASH, so it cannot call terminal_text. Its errors quote policy paths, which
name the scanned tree's directories, the scanner's path, and the error of a
failed exec; bare writes would put each on stderr as given. It has an inline copy of
shown_on_one_line; this checks the copy writes what the original writes, and
that the wrapper's own failure line is shown.
"""

from __future__ import annotations

import importlib.util
import random
import subprocess  # nosec B404 - the wrapper runs as its own interpreter
import sys
from pathlib import Path

import pytest

from automated_security_helper.utils.terminal_text import shown_on_one_line

_WRAPPER = (
    Path(__file__).resolve().parents[3]
    / "automated_security_helper"
    / "utils"
    / "sandbox"
    / "landlock_exec.py"
)


def _wrapper_module():
    spec = importlib.util.spec_from_file_location("landlock_exec_under_test", _WRAPPER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_BS = "\\"

#: The characters that interact: backslashes, escape-like text (whole, as one
#: choice, so each kind comes up), the layout characters, controls of each
#: category, DEL, Unicode spaces, the separators, and the command prefixes and
#: brackets. Built with chr(), so this file holds none of them raw.
_ALPHABET = [_BS, "x", "u", "U", "0", "a", "9", "F", ":", "#", "[", "]", "v", " "]
_ALPHABET += ["\n", "\r", "\t", "\x1b", "\x7f", "\x85", "\x9b"]
_ALPHABET += [chr(c) for c in (0xA0, 0x200B, 0xAD, 0xFFFE, 0xDC80, 0xE0041, 0x3000)]
_ALPHABET += [chr(c) for c in (0x202E, 0x2028, 0x2029, 0xE000, 0x0378)]
_ALPHABET += [_BS + "x1b", _BS + "u202e", _BS + "U000e0041", "##vso["]


def _targeted() -> list[str]:
    """Each class the copy has to treat as the original does, alone and where it
    interacts: after one and two backslashes, at a line's start, between command
    prefixes, and at the end of a 2,500-character line."""
    singles = [chr(c) for c in range(0x20)] + [chr(0x7F)]
    singles += [chr(c) for c in range(0x80, 0xA0)]
    singles += [
        chr(c)
        for c in (0x2028, 0x2029, 0x200E, 0x200F, 0x061C, 0xAD, 0xFEFF)
        + tuple(range(0x202A, 0x202F))
        + tuple(range(0x2066, 0x206A))
    ]
    # Unassigned, a noncharacter, lone surrogates, private use, tag characters.
    singles += [
        chr(c)
        for c in (0x0378, 0x10FFFE, 0xD800, 0xDFFF, 0xE000, 0xF8FF, 0xF0000, 0x10FFFD)
        + (0xE0001, 0xE0041, 0xE007F)
    ]
    tokens = [_BS + "x1b", _BS + "x9b", _BS + "u202e", _BS + "U000e0041"]
    tokens += [_BS + "U0010fffd", "::", "##[", "##vso[", "##teamcity[", "[", "]"]
    texts = []
    for item in singles + tokens:
        texts += [item, _BS + item, _BS * 2 + item, item + _BS, "a\n" + item]
        texts += ["\n::" + item, "::" + item + "::", "##" + item + "[x]"]
    texts.append("a" * 2500 + chr(0x1B) + "::" + _BS + "x1b" + chr(0x2029))
    texts.append(("ab" + chr(0x2029) + _BS + "U000e0041 ##[x]") * 200)
    return texts


@pytest.mark.unit
@pytest.mark.skipif(sys.platform != "linux", reason="the wrapper loads Linux's libc")
def test_the_wrapper_shows_text_as_shown_on_one_line_does():
    shown = _wrapper_module()._shown
    chooser = random.Random(20261012)
    for _ in range(20000):
        text = "".join(chooser.choice(_ALPHABET) for _ in range(chooser.randint(0, 40)))
        assert shown(text) == shown_on_one_line(text), ascii(text)


@pytest.mark.unit
@pytest.mark.skipif(sys.platform != "linux", reason="the wrapper loads Linux's libc")
def test_the_wrapper_shows_each_class_as_shown_on_one_line_does():
    """The random strings alone left whole classes untried: no \\u or \\U text, no
    DEL, no U+2029, no "]", and nothing longer than 16 characters."""
    shown = _wrapper_module()._shown
    for text in _targeted():
        assert shown(text) == shown_on_one_line(text), ascii(text)


@pytest.mark.integration
@pytest.mark.skipif(sys.platform != "linux", reason="the wrapper loads Linux's libc")
def test_a_scanner_the_wrapper_cannot_exec_is_refused_shown(tmp_path):
    """fail() quotes the scanner's path and the exec error, which quotes it again."""
    scanner = str(tmp_path / "x\x1b]52;c;ZXZpbA==\x07\n::add-mask::hidden")
    child = subprocess.run(  # nosec B603 - this interpreter, the wrapper by path
        [sys.executable, "-I", str(_WRAPPER), "--socket-filter", "all", "--", scanner],
        capture_output=True,
        timeout=60,
    )
    stderr = child.stderr.decode("utf-8", "replace")

    assert child.returncode == 126, stderr
    assert "ash-landlock: exec" in stderr, ascii(stderr)
    assert "\\x1b]52;c;ZXZpbA==\\x07\\x0a::add-mask::hidden" in stderr, ascii(stderr)
    assert "\x1b" not in stderr and "\n::" not in stderr, ascii(stderr)
    assert stderr.count("\n") == 1, ascii(stderr)
