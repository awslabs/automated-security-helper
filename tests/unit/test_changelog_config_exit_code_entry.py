# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The CHANGELOG says what exit code ``config lint`` and ``config validate`` give.

For a file that loads and that a scan would accept, both commands exit 0 and print
what they find as warnings. For a file that loads and that a scan would refuse,
both exit 3. The exit-code entry used to end "1 still means a file that loads has
problems", which holds for neither command: ``validate`` returns for a file a scan
accepts, and ``lint`` falls through to exit 0 after the issues it reports. This
reads the entry and the code that decides the exit, so a clause that gives a loaded
file exit 1 is caught.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[2]
CHANGELOG = REPO_ROOT / "CHANGELOG.md"
CONFIG_CLI = REPO_ROOT / "automated_security_helper" / "cli" / "config.py"
ENTRY_OPENER = "`ash config validate` and `ash config lint` also exit 3, not 1"


def _entry() -> str:
    """The CHANGELOG paragraph that opens with the exit-3 sentence, whitespace folded."""
    text = CHANGELOG.read_text(encoding="utf-8")
    for paragraph in re.split(r"\n\s*\n", text):
        folded = " ".join(paragraph.split())
        if ENTRY_OPENER in folded:
            return folded
    raise AssertionError(f"no CHANGELOG paragraph holds: {ENTRY_OPENER}")


def _function_source(name: str) -> str:
    """The source of the module-level function ``name``, up to the next one."""
    source = CONFIG_CLI.read_text(encoding="utf-8")
    start = source.index(f"def {name}(")
    following = re.search(r"^def \w+\(", source[start + 1 :], re.MULTILINE)
    end = start + 1 + following.start() if following else len(source)
    return source[start:end]


def test_validate_has_no_exit_one_for_a_file_a_scan_accepts():
    """The code the entry is checked against: ``validate`` returns for an accepted file."""
    body = _function_source("validate")
    accepted = body.index("if check.scan_accepts:")
    arm = body[accepted : body.index("return", accepted) + len("return")]
    assert "Exit(" not in arm, "validate no longer returns for a file a scan accepts"


def test_lint_has_no_exit_one_for_a_file_a_scan_accepts():
    """After the refusals and a declined fix, ``lint`` ends without an exit."""
    body = _function_source("lint")
    declined = body.index("if declined:")
    after_declined = body[declined + len("if declined:") :]
    ends = after_declined.index("raise typer.Exit(0)") + len("raise typer.Exit(0)")
    assert "Exit(" not in after_declined[ends:], (
        "lint exits again after a declined fix: the entry would need another look"
    )
    assert "has_errors" not in body[body.index("if remaining.scan_refuses:") :]


def test_the_exit_code_entry_gives_a_loaded_file_no_exit_one_clause():
    entry = _entry()
    for stale in (
        "1 still means a file that loads has problems",
        "1 is left for problems in a file that a scan would accept",
        "`ash config lint` still exits 1 when it reports an error",
    ):
        assert stale not in entry, (
            f"the entry says {stale!r}, which holds for neither `ash config lint` "
            "nor `ash config validate`: a file that loads exits 3 when a scan "
            "would refuse it and 0 when a scan would accept it"
        )


def test_the_exit_code_entry_says_what_a_loaded_file_exits_with():
    entry = _entry()
    assert "A file that loads but that a scan would refuse exits 3 as well." in entry
    assert (
        "For a file that a scan would accept, both commands exit 0 and print what "
        "they find as warnings; `ash config lint` exits 1 only when `--fix` or "
        "`--fix-unused` could not rewrite the file." in entry
    )


def test_lint_exits_1_after_the_refusals_only_for_a_rewrite_it_could_not_make():
    """The one exit 1 the entry names: a refused ``--fix`` or ``--fix-unused``."""
    body = _function_source("lint")
    tail = body[body.index("if remaining.scan_refuses:") :]
    assert tail.count("Exit(1)") == 1
    refused = tail.index("if fix_refused:")
    assert "raise typer.Exit(1)" in tail[refused : tail.index("if declined:")]
