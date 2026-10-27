# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The could-not-stop wording is spelled in subprocess_utils and nowhere else.

The ending strings and the default reasons for a stop that failed live beside
COULD_NOT_STOP_MARKER. A module that spells them again drifts from the rest,
so this scan goes red when any module outside subprocess_utils holds the text.
The scan has a planted-positive control: it must flag a file that spells it.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import List

import automated_security_helper
from automated_security_helper.utils import subprocess_utils

#: The spellings: the "may still be running" tail of every reason, and a string
#: literal that opens with the was-killed ending.
_PATTERNS = (
    re.compile(r"which may still be running"),
    re.compile(r"[\"'] ?and was killed"),
    # The same ending composed in an f-string, after a replacement field.
    re.compile(r"\} ?and was killed"),
)


def _spellers(root: Path, home: Path) -> List[str]:
    found = []
    for path in sorted(root.rglob("*.py")):
        if path == home:
            continue
        text = path.read_text(encoding="utf-8")
        if any(pattern.search(text) for pattern in _PATTERNS):
            found.append(path.name)
    return found


def test_the_scan_flags_a_file_that_spells_the_wording(tmp_path):
    """The planted-positive control, with a clean file as the negative."""
    (tmp_path / "speller.py").write_text(
        'REASON = "ASH could not stop the tool, which may still be running"\n'
    )
    (tmp_path / "killer.py").write_text('ENDING = " and was killed"\n')
    (tmp_path / "composer.py").write_text(
        'LINE = f"timed out after {limit} and was killed"\n'
    )
    (tmp_path / "clean.py").write_text("REASON = 'nothing here'\n")

    assert _spellers(tmp_path, tmp_path / "none.py") == [
        "composer.py",
        "killer.py",
        "speller.py",
    ]


def test_no_module_outside_subprocess_utils_spells_the_wording():
    root = Path(automated_security_helper.__file__).parent
    home = Path(subprocess_utils.__file__)

    assert _spellers(root, home) == []
