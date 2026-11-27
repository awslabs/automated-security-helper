"""The reusable scan workflow runs ASH 3.9's spellings when its ASH has them.

Why this file exists
--------------------
ASH 3.9 scans a directory with ``ash scan fs PATH`` and renders saved results with
``ash results report``. Bare ``ash [options]``, ``--source-dir`` and the top-level
``ash report`` still work there, but each prints a deprecation line on stderr, and
they go in ASH v4.0. run-ash-security-scan.yml installs the ASH that ``ash-version``
names: the pull-request scan of this repository installs the head commit, the
required scan the base commit, and an outside caller may pin any tag, 3.8 and older
included. So the Run ASH and Show ASH Summary Report steps ask the installed ASH for
the new command's help, as the deploy targets do, and only an answer picks the older
spelling: a help that does not name the command, or the usage error that refuses the
word the command adds (``fs``, or ``results``). A probe that fails any other way (uvx
cannot fetch the source, ASH crashes) says nothing about the ASH's commands, so the
step fails with status 70, which ASH never gives, and the end of what the probe
printed, and runs neither spelling.

The scan step used to pass ``--source-dir .`` ahead of ``ash-args``, so a
``--source-dir`` in ``ash-args`` came later and named the directory scanned (click
keeps the last value). ``ash scan fs`` refuses a ``--source-dir`` beside a PATH that
names another directory, so the step takes the caller's ``--source-dir`` out of
``ash-args`` and names that directory the way the installed ASH does.

What is asserted
----------------
Each step's own script runs in bash as the runner runs it (``-e -o pipefail``), with
a stand-in uvx first on PATH. The stand-in answers the two help probes as a release
would and records every other call:

* ``3.9`` prints this tree's own help for ``ash scan fs --help`` and
  ``ash results report --help``, padded to thousands of lines;
* ``3.8`` prints the subject-less scan's help for ``ash scan fs --help``, as click
  shows a command's help before it refuses the extra word, and has no ``results``;
* ``refusing`` is an older ASH that refuses the word with click's usage error
  instead (exit 2), and has no ``results`` either;
* ``refusing-otherwise`` refuses with the other two phrases the steps read as a
  refusal: "No such command 'fs'" for the scan and "Got unexpected extra argument
  (results)" for the report, which ``refusing`` has the other way round;
* ``no-name`` exits 0 with a help that names neither command;
* ``broken`` exits non-zero with only an error on stderr, as uvx does when it cannot
  install the source;
* ``names-it-and-fails`` prints the usage line, which names the command, and exits 1;
* ``numbered-failure`` prints 25 numbered lines and exits 1;
* ``hostile`` exits non-zero and prints lines that would be workflow commands.

It answers ``ash scan <subject> --help`` for the subjects ash-args can name
(``workspace``, ``image`` and ``git``) from files each test writes, so a row says what
the ASH it plays has. With nothing said it answers as this tree does: the real help of
the ``workspace`` subject, and the usage error this tree gives for a subject it does
not have. The rows that need another ASH give it: one that also has ``image`` and
``git``, one that refuses a subject in each of the three ways the step reads as a
refusal, or one whose probe fails.

1. The scan runs ``ash scan fs .`` on 3.9 and ``ash --source-dir .`` on the releases
   that answer without the subject, with the same options after the directory on
   both, for each value the step's env selects a flag from; its exit status is the
   step's. On ``broken``, ``names-it-and-fails``, ``numbered-failure`` and ``hostile``
   the step fails with status 70 and the probe's last 20 lines, and runs no scan.
2. A ``--source-dir`` in ``ash-args``, written either way, is the directory on both;
   one that is another option's value is left as that value; one with no word after
   it is refused by the step, with or without use-betterleaks, by position and before
   any probe, since passed on it would take the next option the step adds as its
   directory; a directory whose name starts with a dash is given as ``./`` plus the
   name, the same directory.
3. The 3.9 command line, run through this tree's CLI with the scan engine stubbed,
   scans that directory and prints no deprecation line.
4. The report runs ``ash results report`` on 3.9 and ``ash --output-dir ... report``
   on the releases that answer without ``results``, and its exit status is the step's.
   On ``broken``, ``names-it-and-fails``, ``numbered-failure`` and ``hostile`` the
   step fails with status 70 and runs no report.
5. The probes run with colour off, name the config their step's command names, run
   without ``--reinstall``, do not print the help they read, and do not run at all
   for an ``ash-args`` the step refuses. They start in RUNNER_TEMP with
   ``--no-config``, so the scanned repository's uv settings do not reach the install
   they make, while the scan and the report start in the checkout.
6. Each step says on stderr which spelling it chose and why, and what a failed probe
   printed goes through ``one_line`` a line at a time, so no line of it is read as a
   workflow command.
7. An option of ash-args that names what to scan goes to the subject that scans it
   when, and only when, the installed ASH's own answer to ``ash scan <subject> --help``
   names the subject: ``--workspace FILE`` and ``--workspace-config`` to ``ash scan
   workspace FILE``; ``--image``, ``--image-archive`` and ``--image-layout`` to ``ash
   scan image``, as REF, ``--archive`` and ``--layout``; ``--source-git``,
   ``--git-ref`` and ``--git-depth`` to ``ash scan git``, as URL and the two options.
   The subject's operand comes first, then the step's own options, then the rest of
   ash-args in the order it was written. The same options stay on ``ash scan fs`` as
   they were written, for it to refuse by name, when the ASH answers with a usage error
   or with a help that does not name the subject, when ash-args names things of two
   subjects or a directory as well, when a value is empty or, for an image reference
   or a clone, starts with a dash, and in the older spelling, which asks nothing more.
   An answer of any other kind ends the step with status 70 and what the probe printed,
   as the first probe does. The probe is asked as the first one is: colour off, no
   ``--reinstall``, the scan's config named, from RUNNER_TEMP with ``--no-config``.
8. The routed command line is accepted by this tree's own CLI: the ``workspace`` forms
   are run through it with the scan engine stubbed, and the options left on ``fs`` are
   refused by name or handed on as they were typed, never dropped.

What it does not cover
----------------------
No real ASH 3.8 is installed: its answers are the stand-in's, in the shape the deploy
targets' tests use for the same probe (deploy/cdk-constructs/test/subject-probe.test.ts).

This tree has the ``workspace`` subject and no ``image`` or ``git`` subject. The rows
that send an image or a clone option to its subject run against a stand-in ASH that has
them, whose help is a usage line in this tree's style, so they measure the step's
routing and not the options of a subject that does not exist yet. The rows that parse
that command line with this tree's CLI are skipped until the subject exists. Once it
does, they measure the spellings the routing assumes for it: REF and URL as the
operand, ``--archive`` and ``--layout`` for the image subject, and ``--git-ref`` and
``--git-depth`` unchanged. The rows that keep those options on ``fs`` for this tree's
own answer run only while the tree lacks the subject.
"""

from __future__ import annotations

import functools
import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

import pytest
import typer
import yaml
from typer.testing import CliRunner

from automated_security_helper.cli import scan_group
from automated_security_helper.cli.main import app
from automated_security_helper.core.constants import ASH_EXIT_USAGE_ERROR
from tests.utils.workflow_one_line import command_lines, write_helper

REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "run-ash-security-scan.yml"
RUN_ASH = "Run ASH"
REPORT = "Show ASH Summary Report"

posix_only = pytest.mark.skipif(
    os.name == "nt" or shutil.which("bash") is None,
    reason="runs the step's bash script, which the workflow runs on Linux",
)

#: A stand-in for uvx. A call that ends in --help is a probe: it is logged to
#: $PROBE_LOG, with the directory it started in logged to $PROBE_CWD_LOG, and answered
#: as $UVX_RELEASE would answer `ash scan fs --help` and `ash results report --help`.
#: A leading --no-config is logged with the rest of the call and then set aside, so the
#: answers below read the same words whether or not a probe passes it. Every other call
#: is recorded to $CALLS_LOG, one argument per line with an END line after each call,
#: and the directory it started in to $CALL_CWD_LOG. A probe that reinstalled would not
#: start `--from ash-source ash`, so it gets the broken answer. A probe of `ash scan
#: <subject>` is answered from $SUBJECT_ANSWERS when that directory has the subject:
#: the file named for it holds what it prints and `<subject>.status` the status it
#: exits with, so each test says what the ASH it plays has.
STAND_IN_UVX = r"""#!/bin/sh
pad() {
  i=0
  while [ "$i" -lt 4000 ]; do
    echo "  --option-$i TEXT  A line of help."
    i=$((i + 1))
  done
}
for last in "$@"; do :; done
if [ "${last:-}" = "--help" ]; then
  printf '%s NO_COLOR=%s\n' "$*" "${NO_COLOR:-}" >> "$PROBE_LOG"
  pwd >> "$PROBE_CWD_LOG"
  if [ "${1:-}" = "--no-config" ]; then shift; fi
  case "$UVX_RELEASE:$1 $2 $3 $4 $5" in
    "3.9:--from ash-source ash scan fs") cat "$FS_HELP"; pad; exit 0 ;;
    "3.9:--from ash-source ash results report") cat "$REPORT_HELP"; pad; exit 0 ;;
    "3.8:--from ash-source ash scan fs") echo " Usage: ash scan [OPTIONS]"; pad; exit 0 ;;
    "3.8:--from ash-source ash results report")
      echo "Error: No such command 'results'." >&2; exit 2 ;;
    "refusing:--from ash-source ash scan fs")
      printf '%s\n' "Usage: ash scan [OPTIONS]" "Error: Got unexpected extra argument (fs)" >&2
      exit 2 ;;
    "refusing:--from ash-source ash results report")
      echo "Error: No such command 'results'." >&2; exit 2 ;;
    "refusing-otherwise:--from ash-source ash scan fs")
      echo "Error: No such command 'fs'." >&2; exit 2 ;;
    "refusing-otherwise:--from ash-source ash results report")
      printf '%s\n' "Usage: ash [OPTIONS]" "Error: Got unexpected extra argument (results)" >&2
      exit 2 ;;
    "numbered-failure:--from ash-source ash scan fs"|"numbered-failure:--from ash-source ash results report")
      i=1
      while [ "$i" -le 25 ]; do
        printf 'probe line %02d\n' "$i" >&2
        i=$((i + 1))
      done
      exit 1 ;;
    "no-name:--from ash-source ash scan fs"|"no-name:--from ash-source ash results report")
      echo " Usage: ash [OPTIONS]"; pad; exit 0 ;;
    "names-it-and-fails:--from ash-source ash scan fs"|"names-it-and-fails:--from ash-source ash results report")
      echo " Usage: ash $4 $5 [OPTIONS]"
      echo "Error: it broke after printing its usage" >&2
      exit 1 ;;
    "hostile:--from ash-source ash scan fs"|"hostile:--from ash-source ash results report")
      printf '%s\n' "::warning::planted by the probe" "##[warning]planted too" >&2
      exit 1 ;;
  esac
  if [ "${4:-}" = "scan" ] && [ -f "$SUBJECT_ANSWERS/${5:-}.status" ]; then
    cat "$SUBJECT_ANSWERS/$5"
    exit "$(cat "$SUBJECT_ANSWERS/$5.status")"
  fi
  echo "error: Failed to fetch the source" >&2
  exit 1
fi
printf '%s\n' "$@" END >> "$CALLS_LOG"
pwd >> "$CALL_CWD_LOG"
exit "${UVX_EXIT:-0}"
"""

#: The values the Run ASH step's env gives it when every input is at its default.
SCAN_ENV = {
    "ASH_MODE": "local",
    "ASH_ARGS": "",
    "FAIL_ON_FINDINGS_PARAM": "--fail-on-findings",
    "VERBOSE": "",
    "CHANGED_FILES_ONLY": "",
    "BASE_REF": "",
}

#: uvx's own words before the scan's.
UVX_SCAN = ["--reinstall", "--from", "ash-source", "ash"]
#: What the step passes after the directory, with SCAN_ENV.
OWN_OPTIONS = [
    "--output-dir",
    "out",
    "--no-progress",
    "--fail-on-findings",
    "--build-target",
    "ci",
    "--mode",
    "local",
]


#: The first probe the Run ASH step makes, which asks for `fs`, as the stand-in logs it.
FS_PROBE = "--no-config --from ash-source ash scan fs --help NO_COLOR=1"
#: The subjects of `ash scan` this tree has.
SCAN_SUBJECTS = frozenset(typer.main.get_command(app).commands["scan"].commands)
#: Thousands of lines to follow a help, so the step has to read the whole of one.
HELP_PADDING = "".join(f"  --option-{i} TEXT  A line of help.\n" for i in range(4000))


def _steps() -> list[dict]:
    return yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))["jobs"]["ash"]["steps"]


def _script(name: str) -> str:
    matches = [step for step in _steps() if step.get("name") == name]
    assert len(matches) == 1, f"expected one {name!r} step, found {len(matches)}"
    return matches[0]["run"]


def _help(*command: str) -> str:
    """This tree's help for ``ash <command> --help``, as the probe reads it."""
    result = CliRunner().invoke(
        app,
        [*command, "--help"],
        prog_name="ash",
        env={"NO_COLOR": "1", "COLUMNS": "140"},
    )
    assert result.exit_code == 0, result.output
    return result.output


@functools.cache
def _this_trees_subject_answers() -> dict[str, tuple[int, str]]:
    """What this tree answers to ``ash scan <subject> --help``, for each subject
    ash-args can name: the status it exits with, and what it prints.

    A subject it has prints its help, which names it. One it does not have is refused
    with a usage error, which is what the step reads as a refusal.
    """
    answers = {}
    for subject in ("workspace", "image", "git"):
        result = CliRunner().invoke(
            app,
            ["scan", subject, "--help"],
            prog_name="ash",
            env={"NO_COLOR": "1", "COLUMNS": "140"},
        )
        answers[subject] = (result.exit_code, result.output)
    return answers


def _wave_2_subjects() -> dict[str, tuple[int, str]]:
    """An ASH that has the ``image`` and ``git`` subjects as well as ``workspace``.

    This tree has neither yet, so the two helps are a usage line and a sentence in the
    style of this tree's own, which is all the step reads: that the help names the
    subject.
    """
    return {
        "workspace": _this_trees_subject_answers()["workspace"],
        "image": (
            0,
            "\n Usage: ash scan image [OPTIONS] REF\n\n Scan a container image.\n",
        ),
        "git": (
            0,
            "\n Usage: ash scan git [OPTIONS] URL\n\n Scan a remote git repository.\n",
        ),
    }


#: The three ways an ASH that lacks a subject refuses `ash scan <subject> --help` so
#: that the step reads it as a refusal: this tree's own usage error, a group that reads
#: the word as an extra argument, and one that has no such command.
REFUSALS = ["not-a-subject", "extra-argument", "no-such-command"]


def _refusal(shape: str, subject: str) -> tuple[int, str]:
    if shape == "not-a-subject":
        return ASH_EXIT_USAGE_ERROR, (
            "Usage: ash scan [OPTIONS] COMMAND [ARGS]...\n"
            "Try 'ash scan --help' for help.\n\n"
            f"Error: '{subject}' is not a scan subject (subjects: fs). "
            f"To scan a directory, run 'ash scan fs {subject}'.\n"
        )
    if shape == "extra-argument":
        return 2, (
            "Usage: ash scan [OPTIONS]\n"
            f"Error: Got unexpected extra argument ({subject})\n"
        )
    return 2, f"Error: No such command '{subject}'.\n"


def _refusing(shape: str) -> dict[str, tuple[int, str]]:
    """An ASH that has `fs` and none of the subjects ash-args can name."""
    return {
        subject: _refusal(shape, subject) for subject in ("workspace", "image", "git")
    }


def _args(ash_args: str, **inputs: str) -> dict[str, str]:
    """The Run ASH step's env, with *ash_args* and any other inputs given on top."""
    return {**SCAN_ENV, "ASH_ARGS": ash_args, **inputs}


def _probe(subject: str, config: str = "") -> str:
    """The line the stand-in logs for ``ash scan <subject> --help``."""
    named = f" --config {config}" if config else ""
    return f"--no-config --from ash-source ash scan {subject}{named} --help NO_COLOR=1"


@pytest.fixture(scope="module")
def helps(tmp_path_factory) -> dict[str, Path]:
    directory = tmp_path_factory.mktemp("help")
    files = {}
    for key, command in (("fs", ("scan", "fs")), ("report", ("results", "report"))):
        files[key] = directory / f"{key}.txt"
        files[key].write_text(_help(*command), encoding="utf-8")
    return files


@dataclass(frozen=True)
class Ran:
    result: subprocess.CompletedProcess
    #: The calls the stand-in recorded, each its argument list.
    calls: list[list[str]]
    #: The probes it answered, each `<argv> NO_COLOR=<value>`.
    probes: list[str]
    #: The directory each probe started in, and each of the other calls.
    probe_dirs: list[str]
    call_dirs: list[str]


def _run(
    where: Path,
    helps: dict[str, Path],
    step: str,
    release: str,
    env: dict[str, str],
    subjects: dict[str, tuple[int, str]] | None = None,
) -> Ran:
    """Run the script of *step* in *where* with the stand-in uvx.

    *release* is how the stand-in answers the probes for ``fs`` and ``results``.
    *subjects* is what it answers to ``ash scan <subject> --help``, subject by subject,
    as the status it exits with and what it prints; left out, it answers as this tree
    does.
    """
    where.mkdir(parents=True, exist_ok=True)
    bin_dir = where / "bin"
    bin_dir.mkdir()
    uvx = bin_dir / "uvx"
    uvx.write_text(STAND_IN_UVX, encoding="utf-8")
    uvx.chmod(0o755)
    answers = where / "subject-answers"
    answers.mkdir()
    answered = _this_trees_subject_answers() if subjects is None else subjects
    for subject, (status, text) in answered.items():
        # A help is followed by thousands of lines, as a real one is long: the step
        # has to read the whole of it, not the first lines.
        padding = HELP_PADDING if status == 0 else ""
        (answers / subject).write_text(text + padding, encoding="utf-8")
        (answers / f"{subject}.status").write_text(str(status), encoding="utf-8")
    # The job's definer runs before either step does, into the same RUNNER_TEMP.
    runner_temp = where / "runner_temp"
    write_helper(_steps(), runner_temp)
    calls_log, probe_log = where / "calls", where / "probes"
    call_cwd_log, probe_cwd_log = where / "call-dirs", where / "probe-dirs"
    result = subprocess.run(
        [shutil.which("bash") or "bash", "-e", "-o", "pipefail", "-c", _script(step)],
        cwd=where,
        env={
            "PATH": os.pathsep.join([str(bin_dir), "/usr/bin", "/bin"]),
            "HOME": str(where),
            "RUNNER_TEMP": str(runner_temp),
            "ASH_UVX_SOURCE": "ash-source",
            "ASH_OUTPUT_DIR": "out",
            "UVX_RELEASE": release,
            "FS_HELP": str(helps["fs"]),
            "REPORT_HELP": str(helps["report"]),
            "CALLS_LOG": str(calls_log),
            "PROBE_LOG": str(probe_log),
            "CALL_CWD_LOG": str(call_cwd_log),
            "PROBE_CWD_LOG": str(probe_cwd_log),
            "SUBJECT_ANSWERS": str(answers),
            **env,
        },
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )
    calls: list[list[str]] = []
    current: list[str] = []
    lines = (
        calls_log.read_text(encoding="utf-8").splitlines() if calls_log.exists() else []
    )
    for line in lines:
        if line == "END":
            calls.append(current)
            current = []
        else:
            current.append(line)
    assert not current, f"a call with no END line: {current}"
    probes = (
        probe_log.read_text(encoding="utf-8").splitlines() if probe_log.exists() else []
    )
    probe_dirs = (
        probe_cwd_log.read_text(encoding="utf-8").splitlines()
        if probe_cwd_log.exists()
        else []
    )
    call_dirs = (
        call_cwd_log.read_text(encoding="utf-8").splitlines()
        if call_cwd_log.exists()
        else []
    )
    return Ran(result, calls, probes, probe_dirs, call_dirs)


def _output(ran: Ran) -> str:
    return ran.result.stdout + ran.result.stderr


@pytest.mark.unit
def test_this_trees_help_names_both_commands():
    """Control: the words the steps look for are in this tree's own help."""
    assert "scan fs" in _help("scan", "fs")
    assert "results report" in _help("results", "report")


@pytest.mark.integration
@posix_only
@pytest.mark.parametrize(
    "release, head",
    [
        ("3.9", ["scan", "fs", "."]),
        ("3.8", ["--source-dir", "."]),
        ("refusing", ["--source-dir", "."]),
        # The scan's other refusal: an unknown command, not an extra argument.
        ("refusing-otherwise", ["--source-dir", "."]),
        ("no-name", ["--source-dir", "."]),
    ],
)
def test_the_scan_names_the_directory_the_way_its_ash_does(
    tmp_path, helps, release, head
):
    ran = _run(tmp_path, helps, RUN_ASH, release, SCAN_ENV)

    assert ran.result.returncode == 0, _output(ran)
    assert ran.calls == [[*UVX_SCAN, *head, *OWN_OPTIONS]], _output(ran)
    # The help the probe read is not printed into the step's log.
    assert "Usage:" not in _output(ran)


#: The failed probes: uvx that cannot fetch the source, an ASH that prints the usage
#: line, which names the command, and then dies, and one that prints 25 lines and dies.
#: The exit status is not 0 in any, so none of the help is an answer: the status is read
#: before the words are.
FAILED_PROBES = [
    pytest.param("broken", "error: Failed to fetch the source", id="cannot-fetch"),
    pytest.param(
        "names-it-and-fails",
        "it broke after printing its usage",
        id="names-it-and-fails",
    ),
    pytest.param("numbered-failure", "probe line 25", id="twenty-five-lines"),
]


@pytest.mark.integration
@posix_only
@pytest.mark.parametrize("release, printed", FAILED_PROBES)
def test_the_scan_does_not_read_a_failed_probe_as_an_older_ash(
    tmp_path, helps, release, printed
):
    """A failed probe says nothing about the ASH's commands. Read as an older ASH, it
    would scan with the older spelling on an ASH that has the new one, with no word of
    why, and the older spelling is the one that goes in v4.0."""
    ran = _run(tmp_path, helps, RUN_ASH, release, SCAN_ENV)

    # 70, which ASH never gives: its 1 is "incomplete result", so a step that ended
    # with 1 could be a scan that reported that or a probe that failed.
    assert ran.result.returncode == 70, _output(ran)
    assert ran.calls == [], ran.calls
    output = _output(ran)
    could_not_tell = "Could not tell whether the ASH this workflow installs has"
    assert f"{could_not_tell} 'ash scan fs'" in output
    assert "'ash scan fs --help' exited 1" in output
    # What the probe printed is the diagnosis.
    assert printed in output


@pytest.mark.integration
@posix_only
@pytest.mark.parametrize(
    "env",
    [
        pytest.param({}, id="defaults"),
        pytest.param({"VERBOSE": "--verbose"}, id="verbose"),
        pytest.param(
            {"CHANGED_FILES_ONLY": "--changed-files-only", "BASE_REF": "0123abc"},
            id="changed-files-only",
        ),
        pytest.param({"ASH_CONFIG": "ops/ash.yaml"}, id="config"),
        pytest.param({"FAIL_ON_FINDINGS_PARAM": "--no-fail-on-findings"}, id="no-fail"),
        pytest.param({"USE_BETTERLEAKS": "true"}, id="betterleaks"),
        pytest.param({"ASH_ARGS": "--exclude-scanners grype -c config"}, id="ash-args"),
    ],
)
def test_both_spellings_pass_the_same_options(tmp_path, helps, env):
    (new,) = _run(tmp_path / "new", helps, RUN_ASH, "3.9", {**SCAN_ENV, **env}).calls
    (old,) = _run(tmp_path / "old", helps, RUN_ASH, "3.8", {**SCAN_ENV, **env}).calls

    assert new[: len(UVX_SCAN) + 3] == [*UVX_SCAN, "scan", "fs", "."], new
    assert old[: len(UVX_SCAN) + 2] == [*UVX_SCAN, "--source-dir", "."], old
    assert new[len(UVX_SCAN) + 3 :] == old[len(UVX_SCAN) + 2 :]


@pytest.mark.integration
@posix_only
@pytest.mark.parametrize("release", ["3.9", "3.8"])
def test_the_scans_exit_status_is_the_steps(tmp_path, helps, release):
    # Findings exit 2: the probe in front of the scan must not change the verdict.
    ran = _run(tmp_path, helps, RUN_ASH, release, {**SCAN_ENV, "UVX_EXIT": "2"})
    assert ran.result.returncode == 2, _output(ran)
    assert len(ran.calls) == 1


@pytest.mark.integration
@posix_only
@pytest.mark.parametrize(
    "ash_args, directory, path, rest",
    [
        ("--source-dir services/api", "services/api", "services/api", []),
        ("--source-dir=services/api", "services/api", "services/api", []),
        # The last one wins, as click resolves a repeated option.
        (
            "--verbose --source-dir a --source-dir=b --offline",
            "b",
            "b",
            ["--verbose", "--offline"],
        ),
        # The value of another option, which click reads as that value.
        ("--config --source-dir", ".", ".", ["--config", "--source-dir"]),
        # A name that starts with a dash: the same directory, never read as an option.
        ("--source-dir -x", "-x", "./-x", []),
    ],
)
def test_a_source_dir_in_ash_args_names_the_directory(
    tmp_path, helps, ash_args, directory, path, rest
):
    env = {**SCAN_ENV, "ASH_ARGS": ash_args}

    (new,) = _run(tmp_path / "new", helps, RUN_ASH, "3.9", env).calls
    (old,) = _run(tmp_path / "old", helps, RUN_ASH, "3.8", env).calls

    assert new == [*UVX_SCAN, "scan", "fs", path, *OWN_OPTIONS, *rest]
    assert old == [*UVX_SCAN, "--source-dir", directory, *OWN_OPTIONS, *rest]


class _Engine:
    """Stands in for the engine behind ``ash scan fs`` and ``ash scan workspace``:
    records what it is handed."""

    def __init__(self) -> None:
        self.calls: list[dict] = []

    def __call__(self, *args, **kwargs):
        self.calls.append(kwargs)


@pytest.fixture
def engine(monkeypatch) -> _Engine:
    stub = _Engine()
    monkeypatch.setattr(scan_group, "run_ash_scan_cli_command", stub)
    return stub


def _cli(argv: list[str]):
    """This tree's CLI run with *argv*, where the engine of ``fs`` and ``workspace`` is
    stubbed.

    Only an ``ash scan fs`` or ``ash scan workspace`` command line is run. Any other
    reaches the scan engine through the root command, which the ``engine`` fixture does
    not stub, and would scan for real; a step that has chosen another command fails the
    test here instead.
    """
    assert argv[:2] in (["scan", "fs"], ["scan", "workspace"]), (
        f"not a command line the stub covers: {argv}"
    )
    return CliRunner().invoke(app, argv, prog_name="ash")


@pytest.mark.integration
@posix_only
@pytest.mark.parametrize(
    "ash_args, directory",
    [
        ("", "."),
        ("--source-dir services/api", "services/api"),
        ("--source-dir=services/api", "services/api"),
        ("--source-dir -x", "./-x"),
        ("--phases scan -c config --exclude-scanners grype", "."),
    ],
)
def test_the_new_spelling_scans_that_directory_with_no_deprecation_line(
    tmp_path, helps, engine, monkeypatch, ash_args, directory
):
    (call,) = _run(
        tmp_path, helps, RUN_ASH, "3.9", {**SCAN_ENV, "ASH_ARGS": ash_args}
    ).calls
    monkeypatch.chdir(tmp_path)

    result = _cli(call[len(UVX_SCAN) :])

    assert result.exit_code == 0, result.output
    assert [kwargs["source_dir"] for kwargs in engine.calls] == [directory]
    assert engine.calls[0]["fail_on_findings"] is True
    assert "Deprecated" not in result.output, result.output


@pytest.mark.integration
@posix_only
@pytest.mark.parametrize("use_betterleaks", ["true", ""], ids=["betterleaks", "none"])
@pytest.mark.parametrize(
    "ash_args, position",
    [("--source-dir", 1), ("--verbose --source-dir", 2)],
)
def test_a_source_dir_with_no_directory_is_refused_before_anything_runs(
    tmp_path, helps, ash_args, position, use_betterleaks
):
    """Passed on, it would take the next option the step adds as its directory.

    With use-betterleaks on that is `--config-overrides`, and ASH would refuse the word
    after it, a config override, for the wrong reason. The step refuses it first, by
    position as it refuses `--` and a bare word, and asks the ASH nothing.
    """
    env = {**SCAN_ENV, "ASH_ARGS": ash_args, "USE_BETTERLEAKS": use_betterleaks}

    ran = _run(tmp_path, helps, RUN_ASH, "3.9", env)

    assert ran.result.returncode == 1, _output(ran)
    assert ran.probes == [] and ran.calls == [], (ran.probes, ran.calls)
    (command,) = command_lines(_output(ran))
    assert command.startswith(
        f"::error::ash-args word {position} is --source-dir with no directory after it"
    ), command


@pytest.mark.integration
@posix_only
@pytest.mark.parametrize(
    "release, words",
    [
        ("3.9", ["results", "report", "--output-dir", "out"]),
        ("3.8", ["--output-dir", "out", "report"]),
        ("refusing", ["--output-dir", "out", "report"]),
        # The report's other refusal: an extra argument, not an unknown command.
        ("refusing-otherwise", ["--output-dir", "out", "report"]),
        ("no-name", ["--output-dir", "out", "report"]),
    ],
)
@pytest.mark.parametrize(
    "config, config_words",
    [("", []), ("ops/ash.yaml", ["--config", "ops/ash.yaml"])],
    ids=["no-config", "config"],
)
def test_the_report_uses_the_results_group_when_its_ash_has_it(
    tmp_path, helps, release, words, config, config_words
):
    ran = _run(tmp_path, helps, REPORT, release, {"ASH_CONFIG": config})

    assert ran.result.returncode == 0, _output(ran)
    assert ran.calls == [["--from", "ash-source", "ash", *words, *config_words]]
    assert "Usage:" not in _output(ran)


@pytest.mark.integration
@posix_only
@pytest.mark.parametrize("release, printed", FAILED_PROBES)
def test_the_report_does_not_read_a_failed_probe_as_an_older_ash(
    tmp_path, helps, release, printed
):
    ran = _run(tmp_path, helps, REPORT, release, {"ASH_CONFIG": ""})

    assert ran.result.returncode == 70, _output(ran)
    assert ran.calls == [], ran.calls
    output = _output(ran)
    could_not_tell = "Could not tell whether the ASH this workflow installs has"
    assert f"{could_not_tell} 'ash results report'" in output
    assert "'ash results report --help' exited 1" in output
    assert printed in output


@pytest.mark.integration
@posix_only
@pytest.mark.parametrize(
    "step, env, asked",
    [
        (RUN_ASH, SCAN_ENV, "ash scan fs"),
        (REPORT, {"ASH_CONFIG": ""}, "ash results report"),
    ],
    ids=["scan", "report"],
)
def test_a_failed_probe_shows_its_last_twenty_lines_and_no_others(
    tmp_path, helps, step, env, asked
):
    """The probe printed 25 lines and failed: the step shows lines 6 to 25.

    Fewer would cut the line that says why, and more would put a whole traceback in a
    log the reader scrolls through for the one line that matters.
    """
    ran = _run(tmp_path, helps, step, "numbered-failure", env)

    assert ran.result.returncode == 70, _output(ran)
    assert ran.calls == [], ran.calls
    output = _output(ran)
    could_not_tell = "Could not tell whether the ASH this workflow installs has"
    assert f"{could_not_tell} '{asked}'" in output
    for number in range(6, 26):
        assert f"probe line {number:02d}" in output, (number, output)
    for number in range(1, 6):
        assert f"probe line {number:02d}" not in output, (number, output)


@pytest.mark.integration
@posix_only
@pytest.mark.parametrize(
    "step, env",
    [(RUN_ASH, SCAN_ENV), (REPORT, {"ASH_CONFIG": ""})],
    ids=["scan", "report"],
)
def test_what_a_failed_probe_printed_is_not_read_as_a_workflow_command(
    tmp_path, helps, step, env
):
    """The tail of a failed probe is shown a line at a time through one_line: a line the
    probe printed that starts with `::`, or holds `##[`, would otherwise be the
    runner's to act on, and it comes from the installed ASH, which loads the scanned
    repository's config before it reads --help."""
    ran = _run(tmp_path, helps, step, "hostile", env)

    assert ran.result.returncode == 70, _output(ran)
    assert ran.calls == [], ran.calls
    output = _output(ran)
    # Shown, not dropped.
    assert "planted by the probe" in output and "planted too" in output
    # The one workflow command is the step's own error.
    (own,) = command_lines(output)
    assert own.startswith("::error::Could not tell whether the ASH"), own


@pytest.mark.integration
@posix_only
@pytest.mark.parametrize("release", ["3.9", "3.8"])
def test_the_reports_exit_status_is_the_steps(tmp_path, helps, release):
    ran = _run(tmp_path, helps, REPORT, release, {"ASH_CONFIG": "", "UVX_EXIT": "1"})
    assert ran.result.returncode == 1, _output(ran)
    assert len(ran.calls) == 1


@pytest.mark.integration
@posix_only
@pytest.mark.parametrize(
    "config, config_words",
    [("", ""), ("ops/ash.yaml", " --config ops/ash.yaml")],
    ids=["no-config", "config"],
)
def test_the_probes_run_with_colour_off_and_never_reinstall(
    tmp_path, helps, config, config_words
):
    # Each names the config its step's command does, so no ASH this job runs is
    # left to find the checkout's config, though --help reads none, and each skips
    # uv's config discovery.
    env = {"ASH_CONFIG": config}
    scan = _run(tmp_path / "scan", helps, RUN_ASH, "3.9", {**SCAN_ENV, **env})
    report = _run(tmp_path / "report", helps, REPORT, "3.9", env)

    assert scan.probes == [
        f"--no-config --from ash-source ash scan fs{config_words} --help NO_COLOR=1"
    ]
    assert report.probes == [
        (
            "--no-config --from ash-source ash results report"
            f"{config_words} --help NO_COLOR=1"
        )
    ]


@pytest.mark.integration
@posix_only
@pytest.mark.parametrize("release", ["3.9", "3.8"])
@pytest.mark.parametrize(
    "step, env",
    [(RUN_ASH, SCAN_ENV), (REPORT, {"ASH_CONFIG": ""})],
    ids=["scan", "report"],
)
def test_the_help_is_asked_from_runner_temp_and_the_scan_runs_in_the_checkout(
    tmp_path, helps, step, env, release
):
    """`uvx --from X` installs X, so the scanned repository's uv settings must not reach
    it: each step asks its question from RUNNER_TEMP, with --no-config, as the job runs
    its other installs. The `cd` stays inside the probe: the scan and the report start
    in the checkout, where they have to run."""
    ran = _run(tmp_path, helps, step, release, env)

    assert ran.result.returncode == 0, _output(ran)
    assert ran.probe_dirs == [str(tmp_path / "runner_temp")], ran.probe_dirs
    assert [probe.split()[0] for probe in ran.probes] == ["--no-config"], ran.probes
    assert ran.call_dirs == [str(tmp_path)], ran.call_dirs


@pytest.mark.integration
@posix_only
def test_an_ash_args_the_step_refuses_starts_no_probe(tmp_path, helps):
    ran = _run(
        tmp_path, helps, RUN_ASH, "3.9", {**SCAN_ENV, "ASH_ARGS": "--verbose scan"}
    )

    assert ran.result.returncode != 0, _output(ran)
    assert ran.probes == [] and ran.calls == []


@pytest.mark.integration
@posix_only
@pytest.mark.parametrize(
    "step, env, release, said",
    [
        (
            RUN_ASH,
            SCAN_ENV,
            "3.9",
            "scanning with 'ash scan fs': its help names 'scan fs'",
        ),
        (
            RUN_ASH,
            SCAN_ENV,
            "3.8",
            (
                "scanning with the older spelling: the help of 'ash scan fs --help' "
                "does not name 'scan fs'"
            ),
        ),
        (
            RUN_ASH,
            SCAN_ENV,
            "refusing",
            "scanning with the older spelling: this ASH refused the word 'fs'",
        ),
        (
            REPORT,
            {"ASH_CONFIG": ""},
            "3.9",
            "reporting with 'ash results report': its help names 'results report'",
        ),
        (
            REPORT,
            {"ASH_CONFIG": ""},
            "no-name",
            (
                "reporting with the older spelling: the help of "
                "'ash results report --help' does not name 'results report'"
            ),
        ),
        (
            REPORT,
            {"ASH_CONFIG": ""},
            "3.8",
            "reporting with the older spelling: this ASH refused the word 'results'",
        ),
        (
            RUN_ASH,
            SCAN_ENV,
            "refusing-otherwise",
            "scanning with the older spelling: this ASH refused the word 'fs'",
        ),
        (
            REPORT,
            {"ASH_CONFIG": ""},
            "refusing-otherwise",
            "reporting with the older spelling: this ASH refused the word 'results'",
        ),
    ],
    ids=[
        "scan-3.9",
        "scan-3.8",
        "scan-refusing",
        "report-3.9",
        "report-no-name",
        "report-3.8",
        "scan-refusing-otherwise",
        "report-refusing-otherwise",
    ],
)
def test_the_steps_say_which_spelling_they_chose_and_why(
    tmp_path, helps, step, env, release, said
):
    ran = _run(tmp_path, helps, step, release, env)

    assert f"ash: {said}" in ran.result.stderr, _output(ran)


WORKSPACE_FILE = "services.code-workspace"
CLONE_URL = "https://example.invalid/repo.git"
#: What use-betterleaks adds, after the rest of ash-args.
BETTERLEAKS_OPTIONS = [
    "--config-overrides",
    "ash_plugin_modules+=[automated_security_helper.plugin_modules.ash_betterleaks_plugins]",
    "--config-overrides",
    "scanners.betterleaks.enabled=true",
    "--config-overrides",
    "scanners.gitleaks.enabled=false",
]


def _routed(subject: str) -> str:
    """What the step says when it scans with the subject its ash-args name."""
    return f"ash: scanning with 'ash scan {subject}': its help names 'scan {subject}'"


def _kept(subject: str) -> str:
    """What the step says when its ASH has no such subject: it scans with `fs`."""
    return (
        "ash: scanning with 'ash scan fs' and ash-args as written: "
        f"this ASH has no 'ash scan {subject}'"
    )


@pytest.mark.unit
@pytest.mark.parametrize("subject", ["workspace", "image", "git"])
def test_this_trees_answer_for_a_subject_is_one_the_step_reads(subject):
    """Control for the rows that play this tree. A subject it has prints a help that
    names it, which the step reads as the subject being there; one it lacks is refused
    with a usage error, which the step reads as a refusal. Which of the two holds is
    this tree's: once it has the image and git subjects, those read the first way."""
    status, text = _this_trees_subject_answers()[subject]

    if subject in SCAN_SUBJECTS:
        assert status == 0, text
        assert f"scan {subject}" in text, text
    else:
        assert status != 0, text
        assert "is not a scan subject" in text, text


#: The forms in which ash-args names a workspace, with the operands the workspace
#: subject is given right after its name and the words it is given after the step's own
#: options, which keep the order ash-args had them in.
WORKSPACE_FORMS = [
    pytest.param(
        f"--workspace {WORKSPACE_FILE}",
        [WORKSPACE_FILE],
        [],
        id="workspace",
    ),
    pytest.param(
        f"--workspace={WORKSPACE_FILE}",
        [WORKSPACE_FILE],
        [],
        id="workspace-equals",
    ),
    pytest.param(
        f"--workspace {WORKSPACE_FILE} --workspace-config policy.yaml",
        [WORKSPACE_FILE],
        ["--workspace-config", "policy.yaml"],
        id="with-policy",
    ),
    pytest.param(
        f"--workspace-config policy.yaml --workspace {WORKSPACE_FILE}",
        [WORKSPACE_FILE],
        ["--workspace-config", "policy.yaml"],
        id="policy-first",
    ),
    pytest.param(
        f"--workspace-config=policy.yaml --workspace={WORKSPACE_FILE}",
        [WORKSPACE_FILE],
        ["--workspace-config", "policy.yaml"],
        id="both-with-equals",
    ),
    pytest.param(
        f"--verbose --workspace {WORKSPACE_FILE} --exclude-scanners grype -c config",
        [WORKSPACE_FILE],
        ["--verbose", "--exclude-scanners", "grype", "-c", "config"],
        id="among-other-options",
    ),
    pytest.param(
        "--workspace auto",
        ["auto"],
        [],
        id="auto",
    ),
    # A name that starts with a dash: the same file, never read as an option.
    pytest.param(
        "--workspace -x.code-workspace",
        ["./-x.code-workspace"],
        [],
        id="a-name-that-starts-with-a-dash",
    ),
]


@pytest.mark.integration
@posix_only
@pytest.mark.parametrize("ash_args, operands, rest", WORKSPACE_FORMS)
def test_a_workspace_in_ash_args_goes_to_the_workspace_subject(
    tmp_path, helps, ash_args, operands, rest
):
    ran = _run(tmp_path, helps, RUN_ASH, "3.9", _args(ash_args))

    assert ran.result.returncode == 0, _output(ran)
    assert ran.calls == [
        [*UVX_SCAN, "scan", "workspace", *operands, *OWN_OPTIONS, *rest]
    ], _output(ran)
    # The ASH was asked about the subject as it was asked about `fs`, from RUNNER_TEMP,
    # and the scan starts in the checkout.
    assert ran.probes == [FS_PROBE, _probe("workspace")], ran.probes
    assert ran.probe_dirs == [str(tmp_path / "runner_temp")] * 2, ran.probe_dirs
    assert ran.call_dirs == [str(tmp_path)], ran.call_dirs
    assert _routed("workspace") in ran.result.stderr, _output(ran)
    # The help the probe read is not printed into the step's log.
    assert "Usage:" not in _output(ran)


@pytest.mark.integration
@posix_only
def test_the_options_the_step_adds_stay_ahead_of_the_rest_of_ash_args(tmp_path, helps):
    env = _args(
        f"--workspace {WORKSPACE_FILE} --exclude-scanners grype",
        ASH_CONFIG="ops/ash.yaml",
        VERBOSE="--verbose",
        CHANGED_FILES_ONLY="--changed-files-only",
        BASE_REF="0123abc",
        USE_BETTERLEAKS="true",
    )

    ran = _run(tmp_path, helps, RUN_ASH, "3.9", env)

    assert ran.result.returncode == 0, _output(ran)
    assert ran.calls == [
        [
            *UVX_SCAN,
            "scan",
            "workspace",
            WORKSPACE_FILE,
            *OWN_OPTIONS,
            "--config",
            "ops/ash.yaml",
            "--verbose",
            "--changed-files-only",
            "--base-ref",
            "0123abc",
            "--exclude-scanners",
            "grype",
            *BETTERLEAKS_OPTIONS,
        ]
    ], _output(ran)
    # Each probe names the config the scan names, as the first one always did.
    assert ran.probes == [
        _probe("fs", "ops/ash.yaml"),
        _probe("workspace", "ops/ash.yaml"),
    ], ran.probes


@pytest.mark.integration
@posix_only
@pytest.mark.parametrize(
    "ash_args, file, policy",
    [
        pytest.param(
            f"--workspace {WORKSPACE_FILE}",
            WORKSPACE_FILE,
            None,
            id="file",
        ),
        pytest.param(
            f"--workspace={WORKSPACE_FILE} --workspace-config policy.yaml",
            WORKSPACE_FILE,
            "policy.yaml",
            id="file-and-policy",
        ),
        pytest.param(
            "--workspace -x.code-workspace",
            "./-x.code-workspace",
            None,
            id="a-name-that-starts-with-a-dash",
        ),
    ],
)
def test_the_workspace_command_line_is_one_this_trees_cli_accepts(
    tmp_path, helps, engine, monkeypatch, ash_args, file, policy
):
    """The workspace scan the step runs is read by this tree's own ``ash scan
    workspace``, with the scan engine stubbed: the FILE is the workspace, the policy
    file is the workspace config, no option is refused, and no deprecation line is
    printed."""
    (call,) = _run(tmp_path, helps, RUN_ASH, "3.9", _args(ash_args)).calls
    monkeypatch.chdir(tmp_path)

    result = _cli(call[len(UVX_SCAN) :])

    assert result.exit_code == 0, result.output
    (kwargs,) = engine.calls
    assert kwargs["workspace"] == file, kwargs
    assert kwargs.get("workspace_config") == policy, kwargs
    assert kwargs["fail_on_findings"] is True, kwargs
    assert "Deprecated" not in result.output, result.output


@pytest.mark.integration
@posix_only
@pytest.mark.parametrize("shape", REFUSALS)
def test_a_workspace_stays_on_fs_when_its_ash_refuses_the_subject(
    tmp_path, helps, shape
):
    """The three answers the step reads as a refusal each leave ash-args as it was
    written, on `ash scan fs`, where the option is refused by name: it is not left out
    of the scan, and the step does not fail for it."""
    ash_args = f"--workspace {WORKSPACE_FILE} --workspace-config policy.yaml"

    ran = _run(
        tmp_path, helps, RUN_ASH, "3.9", _args(ash_args), subjects=_refusing(shape)
    )

    assert ran.result.returncode == 0, _output(ran)
    assert ran.calls == [
        [*UVX_SCAN, "scan", "fs", ".", *OWN_OPTIONS, *ash_args.split()]
    ], _output(ran)
    assert ran.probes == [FS_PROBE, _probe("workspace")], ran.probes
    assert _kept("workspace") in ran.result.stderr, _output(ran)


@pytest.mark.integration
@posix_only
@pytest.mark.parametrize(
    "release", ["3.8", "refusing", "refusing-otherwise", "no-name"]
)
def test_an_ash_without_fs_gets_ash_args_as_written_and_is_asked_no_more(
    tmp_path, helps, release
):
    """An ASH that has no `fs` has none of the subjects either: the older spelling
    takes every option of ash-args, and nothing but the first probe is asked."""
    ash_args = f"--workspace {WORKSPACE_FILE} --workspace-config policy.yaml"

    ran = _run(tmp_path, helps, RUN_ASH, release, _args(ash_args))

    assert ran.result.returncode == 0, _output(ran)
    assert ran.calls == [
        [*UVX_SCAN, "--source-dir", ".", *OWN_OPTIONS, *ash_args.split()]
    ], _output(ran)
    assert ran.probes == [FS_PROBE], ran.probes


@pytest.mark.integration
@posix_only
@pytest.mark.parametrize(
    "ash_args, path, words",
    [
        pytest.param(
            f"--workspace {WORKSPACE_FILE} --image alpine:3.20",
            ".",
            ["--workspace", WORKSPACE_FILE, "--image", "alpine:3.20"],
            id="a-workspace-and-an-image",
        ),
        pytest.param(
            f"--image alpine:3.20 --source-git {CLONE_URL}",
            ".",
            ["--image", "alpine:3.20", "--source-git", CLONE_URL],
            id="an-image-and-a-clone",
        ),
        pytest.param(
            f"--source-dir services/api --workspace {WORKSPACE_FILE}",
            "services/api",
            ["--workspace", WORKSPACE_FILE],
            id="a-directory-and-a-workspace",
        ),
        pytest.param(
            f"--source-dir=services/api --source-git {CLONE_URL}",
            "services/api",
            ["--source-git", CLONE_URL],
            id="a-directory-and-a-clone",
        ),
    ],
)
def test_what_names_two_subjects_or_a_directory_as_well_is_not_routed(
    tmp_path, helps, ash_args, path, words
):
    """No scan has two subjects, and a directory named with --source-dir is a scan of
    that directory: the options stay on `fs` as written, for it to refuse by name, and
    the ASH is not asked about a subject. The ASH here has all three, so only the
    step's own rule keeps them there."""
    ran = _run(
        tmp_path, helps, RUN_ASH, "3.9", _args(ash_args), subjects=_wave_2_subjects()
    )

    assert ran.result.returncode == 0, _output(ran)
    assert ran.calls == [[*UVX_SCAN, "scan", "fs", path, *OWN_OPTIONS, *words]], (
        _output(ran)
    )
    assert ran.probes == [FS_PROBE], ran.probes


@pytest.mark.integration
@posix_only
@pytest.mark.parametrize(
    "ash_args",
    ["--image -x", "--image=", "--source-git -x", "--source-git=", "--workspace="],
)
def test_a_value_the_subject_would_read_as_an_option_stays_where_it_is(
    tmp_path, helps, ash_args
):
    """As an operand of the subject, a value that starts with a dash would be an option
    and an empty one names nothing. As the value of the option on `fs` each is the word
    it is, which ASH refuses by name. So the step does not route it, and asks nothing."""
    ran = _run(
        tmp_path, helps, RUN_ASH, "3.9", _args(ash_args), subjects=_wave_2_subjects()
    )

    assert ran.result.returncode == 0, _output(ran)
    assert ran.calls == [
        [*UVX_SCAN, "scan", "fs", ".", *OWN_OPTIONS, *ash_args.split()]
    ], _output(ran)
    assert ran.probes == [FS_PROBE], ran.probes


@pytest.mark.integration
@posix_only
def test_a_subject_probe_that_gets_no_answer_stops_the_step(tmp_path, helps):
    """The probe failed in a way that is not a refusal of the subject: here uvx could
    not fetch the source, after two lines that would be workflow commands. Nothing says
    whether the ASH has the subject, so the step ends with status 70 and the end of what
    the probe printed, and scans with neither command."""
    printed = (
        "::warning::planted by the probe\n"
        "##[warning]planted too\n"
        "error: Failed to fetch the source\n"
    )

    ran = _run(
        tmp_path,
        helps,
        RUN_ASH,
        "3.9",
        _args(f"--workspace {WORKSPACE_FILE}"),
        subjects={"workspace": (1, printed)},
    )

    assert ran.result.returncode == 70, _output(ran)
    assert ran.calls == [], ran.calls
    output = _output(ran)
    could_not_tell = "Could not tell whether the ASH this workflow installs has"
    assert f"{could_not_tell} 'ash scan workspace'" in output
    assert "'ash scan workspace --help' exited 1" in output
    assert "error: Failed to fetch the source" in output
    # What the probe printed is shown, and is not read as a workflow command.
    assert "planted by the probe" in output and "planted too" in output
    (own,) = command_lines(output)
    assert own.startswith("::error::Could not tell whether the ASH"), own


@pytest.mark.integration
@posix_only
def test_a_failed_subject_probe_shows_its_last_twenty_lines_and_no_others(
    tmp_path, helps
):
    printed = "".join(f"probe line {number:02d}\n" for number in range(1, 26))

    ran = _run(
        tmp_path,
        helps,
        RUN_ASH,
        "3.9",
        _args(f"--workspace {WORKSPACE_FILE}"),
        subjects={"workspace": (1, printed)},
    )

    assert ran.result.returncode == 70, _output(ran)
    assert ran.calls == [], ran.calls
    output = _output(ran)
    for number in range(6, 26):
        assert f"probe line {number:02d}" in output, (number, output)
    for number in range(1, 6):
        assert f"probe line {number:02d}" not in output, (number, output)


#: The forms in which ash-args names an image or a clone, with the subject that scans
#: it, the operands that subject is given right after its name, and the words it is
#: given after the step's own options. `--oci` is the runner every subject takes, not an
#: option of the image: it stays where it was written.
IMAGE_AND_CLONE_FORMS = [
    pytest.param(
        "--image alpine:3.20",
        "image",
        ["alpine:3.20"],
        [],
        id="image",
    ),
    pytest.param(
        "--image=alpine:3.20",
        "image",
        ["alpine:3.20"],
        [],
        id="image-equals",
    ),
    pytest.param(
        "--image-archive images/app.tar",
        "image",
        [],
        ["--archive", "images/app.tar"],
        id="image-archive",
    ),
    pytest.param(
        "--image-layout=images/app-layout",
        "image",
        [],
        ["--layout", "images/app-layout"],
        id="image-layout-equals",
    ),
    pytest.param(
        "--image alpine:3.20 --image-layout images/app-layout",
        "image",
        ["alpine:3.20"],
        ["--layout", "images/app-layout"],
        id="image-and-layout",
    ),
    pytest.param(
        "--oci podman --image alpine:3.20",
        "image",
        ["alpine:3.20"],
        ["--oci", "podman"],
        id="the-runner-stays",
    ),
    pytest.param(
        f"--source-git {CLONE_URL}",
        "git",
        [CLONE_URL],
        [],
        id="clone",
    ),
    pytest.param(
        f"--source-git={CLONE_URL} --git-ref main --git-depth 1",
        "git",
        [CLONE_URL],
        ["--git-ref", "main", "--git-depth", "1"],
        id="clone-ref-and-depth",
    ),
    pytest.param(
        f"--git-depth 1 --source-git {CLONE_URL}",
        "git",
        [CLONE_URL],
        ["--git-depth", "1"],
        id="depth-first",
    ),
]


@pytest.mark.integration
@posix_only
@pytest.mark.parametrize("ash_args, subject, operands, rest", IMAGE_AND_CLONE_FORMS)
def test_an_image_or_a_clone_goes_to_the_subject_of_an_ash_that_has_it(
    tmp_path, helps, ash_args, subject, operands, rest
):
    """Measured against a stand-in ASH that has the subjects, since this tree does not
    yet: the step's routing is what these rows read, not the options of a subject that
    does not exist here."""
    ran = _run(
        tmp_path, helps, RUN_ASH, "3.9", _args(ash_args), subjects=_wave_2_subjects()
    )

    assert ran.result.returncode == 0, _output(ran)
    assert ran.calls == [
        [*UVX_SCAN, "scan", subject, *operands, *OWN_OPTIONS, *rest]
    ], _output(ran)
    assert ran.probes == [FS_PROBE, _probe(subject)], ran.probes
    assert _routed(subject) in ran.result.stderr, _output(ran)


@pytest.mark.integration
@posix_only
@pytest.mark.parametrize("ash_args, subject, operands, rest", IMAGE_AND_CLONE_FORMS)
def test_the_image_or_clone_command_line_is_one_the_subject_of_this_tree_accepts(
    tmp_path, helps, ash_args, subject, operands, rest
):
    """Measurable once this tree has the subject, and skipped until then: its own
    ``ash scan image`` or ``ash scan git`` reads every option the step routed to it.
    ``--help`` after them has the CLI parse the options and print the help without
    reaching the engine, so nothing is scanned, and an option the subject lacks is a
    usage error."""
    if subject not in SCAN_SUBJECTS:
        pytest.skip(f"this tree has no `ash scan {subject}` yet")
    (call,) = _run(
        tmp_path, helps, RUN_ASH, "3.9", _args(ash_args), subjects=_wave_2_subjects()
    ).calls
    argv = call[len(UVX_SCAN) :]

    result = CliRunner().invoke(app, [*argv, "--help"], prog_name="ash")

    assert argv[2 : 2 + len(operands)] == operands, argv
    assert result.exit_code == 0, result.output


#: What this tree's own answer, a usage error, keeps on `fs`: the subjects it lacks.
IMAGE_AND_CLONE_ON_FS = [
    pytest.param("--image alpine:3.20", "image", id="image"),
    pytest.param("--image-archive images/app.tar", "image", id="image-archive"),
    pytest.param("--image-layout images/app-layout", "image", id="image-layout"),
    pytest.param(
        f"--source-git {CLONE_URL} --git-ref main --git-depth 1",
        "git",
        id="clone",
    ),
    pytest.param("--git-ref main", "git", id="clone-ref-alone"),
    pytest.param("--git-depth 1", "git", id="clone-depth-alone"),
]


@pytest.mark.integration
@posix_only
@pytest.mark.parametrize("ash_args, subject", IMAGE_AND_CLONE_ON_FS)
def test_an_image_or_a_clone_stays_on_fs_when_this_tree_has_no_such_subject(
    tmp_path, helps, ash_args, subject
):
    """The ASH here answers as this tree does, with the usage error it gives for a
    subject it lacks, and the step reads that as a refusal. Skipped once this tree has
    the subject: the rows above then measure the routing."""
    if subject in SCAN_SUBJECTS:
        pytest.skip(f"this tree has `ash scan {subject}`")

    ran = _run(tmp_path, helps, RUN_ASH, "3.9", _args(ash_args))

    assert ran.result.returncode == 0, _output(ran)
    assert ran.calls == [
        [*UVX_SCAN, "scan", "fs", ".", *OWN_OPTIONS, *ash_args.split()]
    ], _output(ran)
    assert ran.probes == [FS_PROBE, _probe(subject)], ran.probes
    assert _kept(subject) in ran.result.stderr, _output(ran)


@pytest.mark.integration
@posix_only
@pytest.mark.parametrize(
    "ash_args, option",
    [
        pytest.param(f"--workspace {WORKSPACE_FILE}", "--workspace", id="workspace"),
        pytest.param(f"--source-git {CLONE_URL}", "--source-git", id="clone"),
    ],
)
def test_an_option_left_on_fs_is_refused_by_name_and_never_dropped(
    tmp_path, helps, engine, monkeypatch, ash_args, option
):
    """The command line the step makes when its ASH has no subject for the option, run
    through this tree's `ash scan fs`: it refuses the option, naming it, before the
    engine runs. A step that dropped the option would scan the checkout instead."""
    (call,) = _run(
        tmp_path,
        helps,
        RUN_ASH,
        "3.9",
        _args(ash_args),
        subjects=_refusing("not-a-subject"),
    ).calls
    monkeypatch.chdir(tmp_path)

    result = _cli(call[len(UVX_SCAN) :])

    assert result.exit_code != 0, result.output
    assert option in result.output, result.output
    assert engine.calls == [], engine.calls


@pytest.mark.integration
@posix_only
def test_an_image_left_on_fs_is_refused_or_handed_to_the_engine_as_typed(
    tmp_path, helps, engine, monkeypatch
):
    """`fs` of this tree takes `--image` and leaves it to the engine to refuse beside
    the directory; once the image subject has taken it from `fs`, `fs` refuses it by
    name. Either way it is not dropped."""
    (call,) = _run(
        tmp_path,
        helps,
        RUN_ASH,
        "3.9",
        _args("--image alpine:3.20"),
        subjects=_refusing("not-a-subject"),
    ).calls
    monkeypatch.chdir(tmp_path)

    result = _cli(call[len(UVX_SCAN) :])

    if result.exit_code != 0:
        assert "--image" in result.output, result.output
    else:
        (kwargs,) = engine.calls
        assert kwargs.get("image"), kwargs
