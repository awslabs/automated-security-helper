# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""CI steps run ASH as `ashx`, never as the deprecated `ash` alias.

Why this exists
---------------
v4 made `ashx` the command and kept `ash` as a deprecated alias that prints a
warning on stderr. Steps merged from main keep arriving with `ash ...` in them
(#757's sandbox-scanner-parity job ran `ash dependencies install` and passed
`--ash ash` to the parity script). They work on Linux, so nothing fails, but they
test the alias instead of the command, and on a Windows leg with MSYS2 or Git for
Windows ahead on PATH `ash` is the Almquist shell. This reads every `run:` body of
every workflow and composite action and refuses `ash` in command position or as the
value of an `--ash` option.

The deliberate alias checks spell the name through a variable or a quoted string
(`for name in "$ASH_CLI_NAME" ash`), which is not command position, so they pass.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Iterator

import pytest
import yaml

from tests.utils.helpers import github_yaml_files

REPO = Path(__file__).resolve().parents[2]

# `ash` (or ash.exe) where a shell would run it: the start of a command line, or
# after a separator, a subshell opener or a keyword that takes a command.
BARE_ASH = re.compile(
    r"(?:^|[;&|(`]\s*|\$\(\s*|(?:\b(?:then|do|else|if)|!)\s+)ash(?:\.exe)?(?=\s|$|;|\))"
)
ASH_OPTION = re.compile(r"--ash(?:=|\s+)ash(?:\.exe)?(?=\s|$|\\)")


def _files() -> list[Path]:
    # The listed .github roots only. A `**` glob from the repository root descends
    # into tests/pytest-temp, which other xdist workers create and delete under it.
    return github_yaml_files(REPO)


def _run_lines() -> Iterator[tuple[str, str, str]]:
    for path in _files():
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            continue
        rel = path.relative_to(REPO).as_posix()
        lists = [
            (name, (job or {}).get("steps") or [])
            for name, job in (data.get("jobs") or {}).items()
        ]
        lists.append(("", (data.get("runs") or {}).get("steps") or []))
        for job, steps in lists:
            for step in steps:
                label = f"{rel} {job} {step.get('name') or step.get('uses') or '?'}"
                for line in str(step.get("run", "")).splitlines():
                    text = line.strip()
                    if text and not text.startswith("#"):
                        yield label, text, rel


def offenders(lines) -> list[str]:
    return [
        f"{label}: {text}"
        for label, text, _ in lines
        if BARE_ASH.search(text) or ASH_OPTION.search(text)
    ]


def test_no_ci_step_runs_the_deprecated_alias() -> None:
    found = offenders(_run_lines())
    assert found == [], "run these as `ashx`:\n  " + "\n  ".join(found)


def test_the_walk_reads_the_steps_that_run_ashx() -> None:
    # Non-vacuity: the walk reaches the run bodies that invoke ASH at all.
    ashx_lines = [t for _, t, _ in _run_lines() if re.search(r"\bashx\b", t)]
    assert len(ashx_lines) >= 20, ashx_lines


@pytest.mark.parametrize(
    ("line", "flagged"),
    [
        ("ash dependencies install", True),
        ("ash.exe --version", True),
        ("pip install . && ash scan --mode local", True),
        ("if ! ash --help; then exit 1; fi", True),
        ("--sandbox bwrap --online --ash ash \\", True),
        ("ashx dependencies install", False),
        ('for name in "$ASH_CLI_NAME" ash; do', False),
        ("--ash ashx", False),
        ("bash scripts/run.sh", False),
        ("uses: ./.github/actions/setup-ash", False),
        ('echo "the deprecated ash alias warns"', False),
    ],
)
def test_the_patterns(line: str, flagged: bool) -> None:
    assert bool(offenders([("x", line, "x")])) is flagged
