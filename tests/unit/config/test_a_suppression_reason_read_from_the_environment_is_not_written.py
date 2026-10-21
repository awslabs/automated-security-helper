# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A suppression whose reason the configuration read from the environment
writes no value it read into the results, the reports or the console.

WHY THIS EXISTS
---------------
A configuration can read a suppression's reason from the environment
(``reason: ${ASH_X}``). Where the suppression applies, the scan writes a
justification into the suppressed finding's SARIF (utils/sarif_utils.py,
_apply_config_suppression) and logs it at VERBOSE, and neither holds a value
read from the environment. The results file's ``ash_config`` records the reason
as its reference, and no report made from the findings holds the value.

WHAT IT CHECKS
--------------
One tree's configuration reads one suppression's reason from a variable set to
a value made for this run. One scan runs detect-secrets with every report
format the tree ships, and a second runs with ``--verbose``.

- No report, no other file of the output directory (the results file and
  ash.log among them), no line of either scan's console and no answer of an
  MCP tool that reads results holds the value.
- Controls: the scan ran, suppressed as many findings as it kept, the results
  file's ``ash_config`` records the reason as its reference, and each report
  named here was written.

The value is counted after removing whitespace and U+2500-U+257F, and its
12-character prefix is counted too. Failures name the output, never the value.

LIMITS
------
- An inline ``ash-ignore`` comment's reason is the scanned file's own text and
  is not checked.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import secrets
import subprocess
import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from tests.utils.helpers import importing_this_checkout

VARIABLE = "ASH_OUTPUT_SUPPRESSED"

CONFIG = """global_settings:
  suppressions:
    - rule_id: "*"
      path: suppressed.py
      reason: ${ASH_OUTPUT_SUPPRESSED}
reporters:
  yaml:
    enabled: true
  spdx:
    enabled: true
"""

#: Report formats every line of ASH ships, and the file each writes.
REPORTS = {
    "text": "ash.summary.txt",
    "markdown": "ash.summary.md",
    "html": "ash.html",
    "flat-json": "ash.flat.json",
    "csv": "ash.csv",
    "sarif": "ash.sarif",
    "junitxml": "ash.junit.xml",
    "ocsf": "ash.ocsf.json",
    "cyclonedx": "ash.cdx.json",
    "yaml": "ash.yaml",
    "spdx": "ash.spdx.json",
}
#: Formats asked for too where this tree has them; their files are checked
#: with every other file of the output directory.
MORE_FORMATS = ("github-ghas", "gitlab-sast", "gitlab-cyclonedx", "unused-suppressions")

_SQUEEZE = re.compile(r"[\s─-╿]")

#: Written as a ``sitecustomize.py`` first on the children's PYTHONPATH, so it
#: loads at interpreter startup in the CLI child AND in every process it is
#: allowed to start (the detect-secrets worker inherits the environment):
#: every start is recorded at ``subprocess.Popen``, the one constructor
#: ``spawn_run``, ``run_command``, ``subprocess.run`` and every other helper
#: of the subprocess layer reaches, so no path to a start goes unseen in any
#: of the module's processes. Recorded starts are refused, with one exception:
#: ASH's own detect-secrets worker — this exact interpreter running exactly
#: that module, nothing looser — which does the scanning and is not a tool,
#: runs for real. detect-secrets asks for its CLI (``uv tool run
#: detect-secrets --version``) only to log where it is, so a refused probe
#: changes no result.
_RECORDER = (
    "import os as _os\n"
    "import sys as _sys\n"
    "if 'REFUSED_STARTS' in _os.environ:\n"
    "    import subprocess as _subprocess\n"
    "    _real_popen = _subprocess.Popen\n"
    # A subclass, not a plain function: mcp's win32 utilities annotate a
    # parameter as subprocess.Popen[bytes] without deferred annotations, so
    # Python 3.12 subscripts the stand-in at import time (3.14 defers under
    # PEP 649), and a function there is a TypeError that breaks every lazy
    # import of mcp.server. Recording and refusing happen in __new__, before
    # any construction; the allowed worker start returns the real class's
    # fully built instance, which is not an instance of the subclass, so its
    # __init__ is not run again -- and the metaclass answers isinstance by
    # asking the real class, so that instance still counts as a Popen
    # (tests/utils/process_guard.py answers the same way).
    "    class _RecordedType(type(_real_popen)):\n"
    "        def __instancecheck__(cls, instance):\n"
    "            return isinstance(instance, _real_popen)\n"
    "    class _Recorded(_real_popen, metaclass=_RecordedType):\n"
    "        def __new__(cls, args=None, *more, **kwargs):\n"
    "            if isinstance(args, (str, bytes, _os.PathLike)):\n"
    "                argv = [_os.fsdecode(args)]\n"
    "            else:\n"
    "                argv = [\n"
    "                    _os.fsdecode(arg)\n"
    "                    if isinstance(arg, (bytes, _os.PathLike))\n"
    "                    else str(arg)\n"
    "                    for arg in (args or [])\n"
    "                ]\n"
    "            with open(\n"
    "                _os.environ['REFUSED_STARTS'], 'a', encoding='utf-8'\n"
    "            ) as log:\n"
    "                log.write(' '.join(argv) + '\\n')\n"
    "            own_worker = argv[:3] == [\n"
    "                _sys.executable,\n"
    "                '-m',\n"
    "                'automated_security_helper.utils.detect_secrets_worker',\n"
    "            ]\n"
    "            if own_worker:\n"
    "                return _real_popen(args, *more, **kwargs)\n"
    "            raise OSError('refused: a unit test starts no tool')\n"
    "    _subprocess.Popen = _Recorded\n"
)


def _formats() -> str:
    from automated_security_helper.core.enums import ExportFormat

    shipped = {member.value for member in ExportFormat}
    return ",".join([*REPORTS, *(name for name in MORE_FORMATS if name in shipped)])


def _holds(run, text: str) -> bool:
    return run["value"][:12] in _SQUEEZE.sub("", text)


def _context() -> MagicMock:
    from mcp.server.mcpserver import Context

    context = MagicMock(spec=Context)
    context.headers = {}
    for level in ("info", "warning", "error", "debug"):
        setattr(context, level, AsyncMock())
    return context


async def _mcp_answers(output: Path) -> dict:
    from automated_security_helper.cli import mcp_server
    from automated_security_helper.models.asharp_model import AshAggregatedResults

    results = output / "ash_aggregated_results.json"
    model = AshAggregatedResults.from_json(results.read_text(encoding="utf-8"))
    suppressed = [
        item for item in model.to_flat_vulnerabilities() if item.is_suppressed
    ]
    assert suppressed, (
        "the scan suppressed nothing, so there is no finding to ask the MCP "
        "tools about; the named control cells say what the scan should have "
        "found"
    )
    finding = suppressed[0].id
    ctx = _context()
    return {
        "get_scan_results": await mcp_server.get_scan_results(
            ctx, output_dir=str(output)
        ),
        "get_scan_summary": await mcp_server.get_scan_summary(
            ctx, output_dir=str(output)
        ),
        "explain_finding": await mcp_server.explain_finding(
            ctx, finding_id=finding, results_path=str(results)
        ),
        "diff_scan_results": await mcp_server.diff_scan_results(
            ctx, before_path=str(results), after_path=str(results)
        ),
    }


@pytest.fixture(scope="module")
def work(tmp_path_factory) -> Path:
    """The run's own directory: its tree and both scans' output directories."""
    return tmp_path_factory.mktemp("environment-suppression")


@pytest.fixture(scope="module")
def run(work):
    # The value is made here, for this run only.
    value = "ashv" + secrets.token_hex(12)
    refused_starts = work / "refused-starts.log"
    recorder = work / "recorder"
    recorder.mkdir()
    (recorder / "sitecustomize.py").write_text(_RECORDER, encoding="utf-8")
    env = dict(os.environ)
    env.pop("ASH_CONFIG", None)
    env.update(
        {VARIABLE: value},
        COLUMNS="300",
        NO_COLOR="1",
        REFUSED_STARTS=str(refused_starts),
        # First on the path, so the recorder loads at startup in the CLI
        # child and in the worker it starts.
        PYTHONPATH=os.pathsep.join(
            [str(recorder), *filter(None, [os.environ.get("PYTHONPATH")])]
        ),
        # The zero-git-probes count below assumes the source tree sits outside
        # every repository. A --basetemp inside a checkout, or a transient
        # /tmp/.git above a tmp root on /tmp, breaks that assumption from the
        # outside, so the scan's repository walk (which honors the variable as
        # git does) is stopped at this run's own directory; any entries the
        # caller set are kept.
        GIT_CEILING_DIRECTORIES=os.pathsep.join(
            [str(work), *filter(None, [os.environ.get("GIT_CEILING_DIRECTORIES")])]
        ),
    )

    source = work / "src"
    (source / ".ash").mkdir(parents=True)
    # A keyword detect-secrets reports, made here too.
    finding = f'password = "{secrets.token_hex(10)}"\n'
    for name in ("app.py", "suppressed.py"):
        (source / name).write_text(finding, encoding="utf-8")
    config = source / ".ash" / ".ash.yaml"
    config.write_text(CONFIG, encoding="utf-8")

    def scan(output: Path, *more: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            [
                sys.executable,
                "-c",
                importing_this_checkout(
                    "from automated_security_helper.cli.main import app; app()"
                ),
                "scan",
                "--source-dir",
                str(source),
                "--output-dir",
                str(output),
                "--config",
                str(config),
                "--scanners",
                "detect-secrets",
                "--output-formats",
                _formats(),
                "--no-progress",
                "--no-fail-on-findings",
                "--no-fail-on-incomplete-scanners",
                *more,
            ],
            capture_output=True,
            text=True,
            timeout=900,
            cwd=work,
            env=env,
            check=False,
        )

    output = work / "out"
    steps = {
        "scan": scan(output),
        "scan --verbose": scan(work / "out-verbose", "--verbose"),
    }
    answers = {}
    if (output / "ash_aggregated_results.json").is_file():
        with pytest.MonkeyPatch.context() as patch:
            patch.setenv("ASH_MCP_ALLOWED_ROOTS", str(work))
            answers = asyncio.run(_mcp_answers(output))
    return {
        "value": value,
        "steps": steps,
        "output": output,
        "answers": answers,
        "refused_starts": refused_starts,
    }


def _the_scan_ran(run) -> dict:
    scan = run["steps"]["scan"]
    assert scan.returncode == 0, scan.returncode
    results = run["output"] / "ash_aggregated_results.json"
    assert results.is_file()
    data = json.loads(results.read_text(encoding="utf-8"))
    stats = data["metadata"]["summary_stats"]
    # app.py and suppressed.py hold the same line.
    assert stats["actionable"] >= 1, stats["severity_counts"]
    assert stats["severity_counts"]["suppressed"] == stats["actionable"], stats[
        "severity_counts"
    ]
    return data


def test_the_recorder_records_a_path_like_start(tmp_path):
    """``subprocess.Popen`` takes one str, bytes or path-like argument as well
    as an argv list; the recorder decodes it instead of iterating it, so a
    path-like start is recorded and refused rather than raising TypeError
    with no record."""
    log = tmp_path / "refused.log"
    env = dict(os.environ, REFUSED_STARTS=str(log))
    code = _RECORDER + (
        "import pathlib, subprocess\n"
        "try:\n"
        "    subprocess.Popen(pathlib.Path('/bin/true'))\n"
        "except OSError:\n"
        "    print('REFUSED')\n"
    )

    done = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        env=env,
        timeout=60,
        check=False,
    )

    assert "REFUSED" in done.stdout, (done.stdout, done.stderr)
    assert log.is_file(), done.stderr
    assert "/bin/true" in log.read_text(encoding="utf-8")


def test_an_allowed_worker_start_is_an_instance_of_the_stand_in(tmp_path):
    """The allowed worker start returns the real class's fully built instance,
    which is not an instance of the subclass. The stand-in answers
    ``isinstance`` for it anyway (a metaclass ``__instancecheck__`` that asks
    the real class, as tests/utils/process_guard.py answers), so code in the
    child asking ``isinstance(worker, subprocess.Popen)`` is not told False
    by the recorder."""
    from tests.utils.helpers import checkout_env

    log = tmp_path / "refused.log"
    env = checkout_env(dict(os.environ, REFUSED_STARTS=str(log)))
    code = _RECORDER + (
        "import subprocess, sys\n"
        "worker = subprocess.Popen(\n"
        "    [sys.executable, '-m',\n"
        "     'automated_security_helper.utils.detect_secrets_worker'],\n"
        "    stdin=subprocess.DEVNULL,\n"
        "    stdout=subprocess.DEVNULL,\n"
        "    stderr=subprocess.DEVNULL,\n"
        ")\n"
        "checked = isinstance(worker, subprocess.Popen)\n"
        # The negative case keeps the check a check: a __instancecheck__ that
        # answers True for anything would pass the worker too.
        "unrelated = isinstance(object(), subprocess.Popen)\n"
        "worker.wait()\n"
        "print(f'ISINSTANCE={checked} UNRELATED={unrelated}')\n"
    )

    done = subprocess.run(
        [sys.executable, "-c", importing_this_checkout(code)],
        capture_output=True,
        text=True,
        env=env,
        timeout=60,
        check=False,
    )

    assert "ISINSTANCE=True" in done.stdout, (done.stdout, done.stderr)
    assert "UNRELATED=False" in done.stdout, (done.stdout, done.stderr)


def test_the_scan_ran_and_records_the_reason_as_its_reference(run):
    data = _the_scan_ran(run)
    entry = data["ash_config"]["global_settings"]["suppressions"][0]
    # A boolean, so a failure never shows what the field holds.
    recorded = entry["reason"] == "${ASH_OUTPUT_SUPPRESSED}"
    assert recorded


def test_the_scan_starts_no_tool_but_the_version_probes(run):
    """Every process of the module records each start at ``subprocess.Popen``
    (_RECORDER, loaded through sitecustomize in the CLI child and the worker
    it starts), so the module's scans start no real tool. Each scan asks for
    exactly two: detect-secrets' CLI version probe, refused and scanned
    without, and ASH's own detect-secrets worker — this interpreter running
    exactly that module — which runs. The source tree here sits outside every
    repository, so the scan starts no git probe either: it looks for a .git
    entry first and records the absolute path without starting git (the
    contract test_a_scan_outside_a_git_repository_starts_no_program.py pins on
    its own; the zero count here keeps this module's accounting exact). A
    recorded line for anything else is a start this module never intended.
    The known starts are the positive control: a missing log, or one without
    them, means the recorder never saw the starts each scan is known to ask
    for, so an absent or bypassed recorder fails here instead of reading as a
    tool-free run."""
    _the_scan_ran(run)
    log = run["refused_starts"]
    lines = log.read_text(encoding="utf-8").splitlines() if log.is_file() else None
    assert lines is not None, "no start was recorded: the recorder did not run"
    scans = len(run["steps"])
    git_probes = [
        line
        for line in lines
        if line.startswith("git ") and line.endswith(" rev-parse --show-toplevel")
    ]
    version_probes = [
        line for line in lines if line.endswith(" tool run detect-secrets --version")
    ]
    worker_start = (
        f"{sys.executable} -m automated_security_helper.utils.detect_secrets_worker "
    )
    workers = [line for line in lines if line.startswith(worker_start)]
    expected = {*version_probes, *workers}
    unexpected = [line for line in lines if line not in expected]
    assert unexpected == [], unexpected
    assert git_probes == [], git_probes
    assert len(version_probes) == scans, lines
    assert len(workers) == scans, lines
    assert len(lines) == 2 * scans, lines


def test_the_results_file_holds_no_value(run):
    _the_scan_ran(run)
    text = (run["output"] / "ash_aggregated_results.json").read_text(encoding="utf-8")
    holds = _holds(run, text)
    assert not holds


@pytest.mark.parametrize("report", list(REPORTS))
def test_no_report_holds_the_value(run, report):
    _the_scan_ran(run)
    path = run["output"] / "reports" / REPORTS[report]
    assert path.is_file(), f"{report}: {path.name} was not written"
    holds = _holds(run, path.read_text(encoding="utf-8", errors="replace"))
    assert not holds, report


def test_no_other_output_file_holds_the_value(run, work):
    _the_scan_ran(run)
    # Walked by the path the fixture made it from, so the walk reads as one of
    # this run's own directory (tests/utils/walk_guard.py).
    output = work / "out"
    assert output == run["output"]
    named = {output / "reports" / name for name in REPORTS.values()}
    named.add(output / "ash_aggregated_results.json")
    holding = [
        path.relative_to(output).as_posix()
        for path in sorted(output.rglob("*"))
        if path.is_file()
        and path not in named
        and _holds(run, path.read_bytes().decode("utf-8", "replace"))
    ]
    assert holding == []


@pytest.mark.parametrize("step", ["scan", "scan --verbose"])
def test_the_scan_console_holds_no_value(run, step):
    scan = run["steps"][step]
    assert scan.returncode == 0, scan.returncode
    holds = _holds(run, scan.stdout + scan.stderr)
    assert not holds, step


def test_no_mcp_results_answer_holds_the_value(run):
    _the_scan_ran(run)
    answers = run["answers"]
    assert sorted(answers) == [
        "diff_scan_results",
        "explain_finding",
        "get_scan_results",
        "get_scan_summary",
    ]
    for tool, answer in answers.items():
        assert answer.get("success") is not False, (tool, answer.get("error_type"))
    holding = [
        tool
        for tool, answer in answers.items()
        if _holds(run, json.dumps(answer, default=str))
    ]
    assert holding == []
