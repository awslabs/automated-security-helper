# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The 3.9 contract for every command spelling that moved.

ASH 3.9 moves the directory scan under ``ash scan fs``, the commands that read saved
results under ``ash results`` and the image build under ``ash container build``. Each
old spelling keeps working through 3.x:

* it prints exactly one deprecation line, on stderr and never on stdout, that names
  the spelling replacing it and the 4.0 removal;
* its stdout and its exit code are those of the new spelling;
* the new spelling prints no deprecation line.

ASH 4.0 removes the old spellings. This file is the record that removal starts from:
each row here becomes a refusal row in 4.0. The rows were green when written, since
they pin behavior the scan group, results group and container group already deliver.

Every scan row passes ``--shard-index 3`` without ``--shard-count``, which the engine
refuses with the usage-error code right after the deprecation line would print, so no
row scans anything; the image build's scan is replaced by a stand-in that records its
arguments, so no image is built.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Callable, List

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli.main import app

pytestmark = pytest.mark.unit

#: Fails at once in the engine: a shard index needs a shard count.
FAILS_FAST = ["--shard-index", "3"]

#: The two prefixes a deprecation line starts with: the scan spellings print
#: ``Deprecated: ...``, the moved top-level commands ``DeprecationWarning: ...``.
DEPRECATION_PREFIXES = ("Deprecated:", "DeprecationWarning:")


def _invoke(args: List[str]):
    return CliRunner().invoke(app, args, prog_name="ash")


def _deprecation_lines(text: str) -> List[str]:
    return [line for line in text.splitlines() if line.startswith(DEPRECATION_PREFIXES)]


@dataclass(frozen=True)
class Spelling:
    """An old spelling, the spelling that replaces it, and what the line must name."""

    legacy: Callable[[Path], List[str]]
    noun: Callable[[Path], List[str]]
    names: str


def _results_argv(verb: str) -> Callable[[Path], List[str]]:
    """A cheap invocation of *verb* that needs no saved results.

    Each one fails the same way under either spelling (a missing input, or a bare
    group), so the exit code and the command's own output can be compared.
    """

    def build(tmp_path: Path) -> List[str]:
        missing = str(tmp_path / "absent.json")
        return {
            "report": [verb, "--output-dir", str(tmp_path / "no-such-output")],
            "diff": [verb, missing, missing],
            "trend": [verb, missing, missing],
            "merge": [verb, "--results", str(tmp_path / "no-such-shard")],
            "inspect": [verb],
        }[verb]

    return build


SPELLINGS = {
    "bare-ash": Spelling(
        legacy=lambda _: [*FAILS_FAST],
        noun=lambda _: ["scan", "fs", *FAILS_FAST],
        names="ash scan fs",
    ),
    "scan-without-subject": Spelling(
        legacy=lambda _: ["scan", *FAILS_FAST],
        noun=lambda _: ["scan", "fs", *FAILS_FAST],
        names="ash scan fs",
    ),
    "source-dir-on-fs": Spelling(
        legacy=lambda _: ["scan", "fs", "--source-dir", "src", *FAILS_FAST],
        noun=lambda _: ["scan", "fs", "src", *FAILS_FAST],
        names="ash scan fs",
    ),
    **{
        verb: Spelling(
            legacy=_results_argv(verb),
            noun=lambda tmp_path, verb=verb: [
                "results",
                *_results_argv(verb)(tmp_path),
            ],
            names=f"ash results {verb}",
        )
        for verb in ("report", "diff", "trend", "merge", "inspect")
    },
    "build-image": Spelling(
        legacy=lambda _: ["build-image", "--no-run"],
        noun=lambda _: ["container", "build", "--no-run"],
        names="ash container build",
    ),
}


@pytest.fixture
def isolated(tmp_path, monkeypatch):
    """A working directory with no config of its own, and an image build that builds
    nothing: the build command's scan is recorded, not run."""
    (tmp_path / "src").mkdir()
    monkeypatch.chdir(tmp_path)
    builds: List[dict] = []
    monkeypatch.setattr(
        "automated_security_helper.cli.image.run_ash_scan",
        lambda **kwargs: builds.append(kwargs),
    )
    return builds


@pytest.mark.parametrize("name", list(SPELLINGS))
def test_a_legacy_spelling_prints_one_line_on_stderr(name, tmp_path, isolated):
    spelling = SPELLINGS[name]

    result = _invoke(spelling.legacy(tmp_path))

    lines = _deprecation_lines(result.stderr)
    assert len(lines) == 1, result.stderr
    assert spelling.names in lines[0], lines[0]
    assert "4.0" in lines[0], lines[0]
    assert _deprecation_lines(result.stdout) == [], (
        "a script's stdout is never handed the line"
    )


@pytest.mark.parametrize("name", list(SPELLINGS))
def test_a_legacy_spelling_keeps_the_nouns_stdout_and_exit_code(
    name, tmp_path, isolated
):
    spelling = SPELLINGS[name]

    legacy = _invoke(spelling.legacy(tmp_path))
    noun = _invoke(spelling.noun(tmp_path))

    assert legacy.exit_code == noun.exit_code, (legacy.output, noun.output)
    assert legacy.stdout == noun.stdout


@pytest.mark.parametrize("name", list(SPELLINGS))
def test_the_noun_spelling_prints_no_deprecation_line(name, tmp_path, isolated):
    result = _invoke(SPELLINGS[name].noun(tmp_path))

    assert _deprecation_lines(result.stderr) == [], result.stderr
    assert _deprecation_lines(result.stdout) == [], result.stdout
    assert "deprecat" not in result.output.lower(), result.output


def test_both_build_spellings_start_the_same_build(tmp_path, isolated):
    """The rows above compare what the two spellings print; this one, that the
    recorded build is the same, so the stand-in is not hiding a difference."""
    _invoke(SPELLINGS["build-image"].legacy(tmp_path))
    _invoke(SPELLINGS["build-image"].noun(tmp_path))

    assert len(isolated) == 2
    assert isolated[0] == isolated[1]
