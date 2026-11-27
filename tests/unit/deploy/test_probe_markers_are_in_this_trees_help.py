"""The names the deploy probes look for are in this tree's own CLI help.

Why this file exists
--------------------
The gate handlers, the sharded pipelines' buildspecs, the generated CDK buildspecs, the
reusable scan workflow, the example buildspec, the Homebrew formula and the gate's
regression script each decide whether the installed ASH has ``ash scan fs``, ``ash
results merge`` or ``ash results report`` by looking for the command's own name in the
help it prints. Every test of those probes answers them with help text it wrote itself,
so none of them says that the real help carries the name. If it stopped doing so (a
typer or rich release that restyles the usage line, a renamed subject, a root callback
that prints to stdout or exits non-zero on ``--help``), every deployment would move to
the older spelling with every one of those tests green. It would show only when v4.0
removes that spelling.

What is asserted
----------------
This tree's CLI, started as the ``ash`` console script in a subprocess, exits 0 and
prints each name in the help of its command, in the two environments the probes run in:

* the gate handlers' own, colour off and 200 columns (``NO_COLOR=1``, ``COLUMNS=200``);
* a buildspec's, the workflow's and the formula's: a pipe with no colour or width
  setting, so the help is laid out at the default width.

The gates also read an option's name out of the same help (``--fail-on-incomplete-scanners``
in ``ash scan fs --help``, which they refuse to scan without), so that name is asserted
in the environment they use.

What it does not cover
----------------------
No older ASH is installed, so the answers an older ASH gives (the subject-less help, the
usage error for the word ``fs``) are the stand-ins of each probe's own test.
"""

from __future__ import annotations

import os
import shutil
import subprocess  # nosec B404 - runs this repository's own console script
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.integration

posix_only = pytest.mark.skipif(
    os.name == "nt",
    reason="the probes are shell and Python run on Linux; the console script differs",
)

#: Each command a probe asks about, with the name its probes look for in the help.
PROBED = [
    (("scan", "fs"), "scan fs"),
    (("results", "merge"), "results merge"),
    (("results", "report"), "results report"),
]

#: The environments the probes run in, by what they set. `plain` sets nothing: the
#: help goes to a pipe, as a buildspec's command substitution reads it.
ENVIRONMENTS = {
    "gates": {"NO_COLOR": "1", "COLUMNS": "200"},
    "plain": {},
}

COMPLETENESS_OPTION = "--fail-on-incomplete-scanners"


def _ash() -> str:
    beside = Path(sys.executable).with_name("ash")
    found = str(beside) if beside.exists() else shutil.which("ash")
    # Not a skip: a probe test that skips where the console script is missing would
    # read as green while checking nothing.
    assert found, "no `ash` console script beside this interpreter or on PATH"
    return found


def _help(
    command: tuple[str, ...], environment: dict[str, str], tmp_path: Path
) -> subprocess.CompletedProcess:
    """``ash <command> --help`` as a probe runs it: no terminal, nothing on stdin, and
    none of this process's environment, so no ``ASH_*`` setting or CI variable of the
    runner decides how the help is laid out."""
    return subprocess.run(  # nosec B603 - the console script, a list of fixed words
        [_ash(), *command, "--help"],
        cwd=tmp_path,
        env={"PATH": os.environ.get("PATH", ""), "HOME": str(tmp_path), **environment},
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )


def _shown(ran: subprocess.CompletedProcess) -> str:
    out = "\n".join(ran.stdout.splitlines()[:15])
    err = "\n".join(ran.stderr.splitlines()[:15])
    return (
        f"exit {ran.returncode}\n"
        f"stdout (first lines):\n{out}\n"
        f"stderr (first lines):\n{err}"
    )


@posix_only
@pytest.mark.parametrize("environment", ENVIRONMENTS.values(), ids=list(ENVIRONMENTS))
@pytest.mark.parametrize(
    "command, name", PROBED, ids=[name.replace(" ", "-") for _, name in PROBED]
)
def test_the_help_names_the_command_the_probes_look_for(
    tmp_path, command, name, environment
):
    ran = _help(command, environment, tmp_path)

    assert ran.returncode == 0, _shown(ran)
    assert name in ran.stdout, f"{name!r} is not in the help:\n{_shown(ran)}"


@posix_only
def test_the_scan_help_the_gates_read_names_the_completeness_option(tmp_path):
    ran = _help(("scan", "fs"), ENVIRONMENTS["gates"], tmp_path)

    assert ran.returncode == 0, _shown(ran)
    assert COMPLETENESS_OPTION in ran.stdout, _shown(ran)
