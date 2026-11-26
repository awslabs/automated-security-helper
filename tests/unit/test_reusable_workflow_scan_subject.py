# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

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
the new command's help, as the deploy targets do, and run the older spelling when
that help does not name the command.

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
* ``broken`` exits non-zero with nothing on stdout, as uvx does when it cannot
  install the source.

1. The scan runs ``ash scan fs .`` on 3.9 and ``ash --source-dir .`` otherwise, with
   the same options after the directory on both, for each value the step's env
   selects a flag from; its exit status is the step's.
2. A ``--source-dir`` in ``ash-args``, written either way, is the directory on both;
   one that is another option's value is left as that value; one with no word after
   it is passed on, for ASH to refuse; a directory whose name starts with a dash is
   given as ``./`` plus the name, the same directory.
3. The 3.9 command line, run through this tree's CLI with the scan engine stubbed,
   scans that directory and prints no deprecation line.
4. The report runs ``ash results report`` on 3.9 and ``ash --output-dir ... report``
   otherwise, and its exit status is the step's.
5. The probes run with colour off, name the config their step's command names, run
   without ``--reinstall``, print nothing, and do not run at all for an ``ash-args``
   the step refuses.

What it does not cover
----------------------
No real ASH 3.8 is installed: its answers are the stand-in's, in the shape the deploy
targets' tests use for the same probe (deploy/cdk-constructs/test/subject-probe.test.ts).
"""

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner

from automated_security_helper.cli import scan_group
from automated_security_helper.cli.main import app
from automated_security_helper.core.constants import ASH_EXIT_USAGE_ERROR
from tests.utils.workflow_one_line import write_helper

REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "run-ash-security-scan.yml"
RUN_ASH = "Run ASH"
REPORT = "Show ASH Summary Report"

posix_only = pytest.mark.skipif(
    os.name == "nt" or shutil.which("bash") is None,
    reason="runs the step's bash script, which the workflow runs on Linux",
)

#: A stand-in for uvx. A call that ends in --help is a probe: it is logged to
#: $PROBE_LOG and answered as $UVX_RELEASE would answer `ash scan fs --help` and
#: `ash results report --help`. Every other call is recorded to $CALLS_LOG, one
#: argument per line with an END line after each call. A probe that reinstalled
#: would not start `--from ash-source ash`, so it gets the broken answer.
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
  case "$UVX_RELEASE:$1 $2 $3 $4 $5" in
    "3.9:--from ash-source ash scan fs") cat "$FS_HELP"; pad; exit 0 ;;
    "3.9:--from ash-source ash results report") cat "$REPORT_HELP"; pad; exit 0 ;;
    "3.8:--from ash-source ash scan fs") echo " Usage: ash scan [OPTIONS]"; pad; exit 0 ;;
    "3.8:--from ash-source ash results report")
      echo "Error: No such command 'results'." >&2; exit 2 ;;
  esac
  echo "error: Failed to fetch the source" >&2
  exit 1
fi
printf '%s\n' "$@" END >> "$CALLS_LOG"
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


def _run(
    where: Path, helps: dict[str, Path], step: str, release: str, env: dict[str, str]
) -> Ran:
    where.mkdir(parents=True, exist_ok=True)
    bin_dir = where / "bin"
    bin_dir.mkdir()
    uvx = bin_dir / "uvx"
    uvx.write_text(STAND_IN_UVX, encoding="utf-8")
    uvx.chmod(0o755)
    # The job's definer runs before either step does, into the same RUNNER_TEMP.
    runner_temp = where / "runner_temp"
    write_helper(_steps(), runner_temp)
    calls_log, probe_log = where / "calls", where / "probes"
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
    return Ran(result, calls, probes)


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
        ("broken", ["--source-dir", "."]),
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
        # No word after it: passed on, and ASH refuses an option with no value.
        ("--verbose --source-dir", ".", ".", ["--verbose", "--source-dir"]),
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
    """Stands in for the engine behind ``ash scan fs``: records what it is handed."""

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
    """This tree's CLI run with *argv*, where only ``fs``'s engine is stubbed.

    Only an ``ash scan fs`` command line is run. Any other reaches the scan engine
    through the root command, which the ``engine`` fixture does not stub, and would
    scan for real; a step that has not chosen ``scan fs`` fails the test here instead.
    """
    assert argv[:2] == ["scan", "fs"], f"not an `ash scan fs` command line: {argv}"
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
def test_a_source_dir_with_no_directory_is_still_refused(
    tmp_path, helps, engine, monkeypatch
):
    (call,) = _run(
        tmp_path, helps, RUN_ASH, "3.9", {**SCAN_ENV, "ASH_ARGS": "--source-dir"}
    ).calls
    monkeypatch.chdir(tmp_path)

    result = _cli(call[len(UVX_SCAN) :])

    assert result.exit_code == ASH_EXIT_USAGE_ERROR, result.output
    assert engine.calls == []


@pytest.mark.integration
@posix_only
@pytest.mark.parametrize(
    "release, words",
    [
        ("3.9", ["results", "report", "--output-dir", "out"]),
        ("3.8", ["--output-dir", "out", "report"]),
        ("broken", ["--output-dir", "out", "report"]),
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
    # left to find the checkout's config, though --help reads none.
    env = {"ASH_CONFIG": config}
    scan = _run(tmp_path / "scan", helps, RUN_ASH, "3.9", {**SCAN_ENV, **env})
    report = _run(tmp_path / "report", helps, REPORT, "3.9", env)

    assert scan.probes == [
        f"--from ash-source ash scan fs{config_words} --help NO_COLOR=1"
    ]
    assert report.probes == [
        f"--from ash-source ash results report{config_words} --help NO_COLOR=1"
    ]


@pytest.mark.integration
@posix_only
def test_an_ash_args_the_step_refuses_starts_no_probe(tmp_path, helps):
    ran = _run(
        tmp_path, helps, RUN_ASH, "3.9", {**SCAN_ENV, "ASH_ARGS": "--verbose scan"}
    )

    assert ran.result.returncode != 0, _output(ran)
    assert ran.probes == [] and ran.calls == []
