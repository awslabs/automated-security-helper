# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A scan, a report over existing results and a merge into an output directory whose
path is not UTF-8 work as they do into one whose path is.

ASH writes its results, reports and logs below the output directory and names the
paths below it in what it logs and prints. A path that is not UTF-8 arrives as a str
with surrogate escapes, which a UTF-8 stream cannot encode. The console and ash.log
show such a character as an escape (utils/terminal_text.py's SHOWN_AS_ESCAPES holds
Cs), so each of these gives the same verdict, writes the same reports and logs the
same lines as it does into an output directory whose path is UTF-8.

Measured with Cs left out of SHOWN_AS_ESCAPES: on a stdout that cannot encode a
surrogate, the local scan, the report over existing results and the merge exited 1
instead of 2, and ash.log lost the lines that named the output directory: it kept
64 of the local scan's 79 and 20 of the report's 31. These tests pin the behavior,
so that a change to a sink that writes such a path as it is fails here.

Container mode is not covered here: it cannot mount such a directory and refuses it
(test_a_source_dir_that_is_not_utf8_is_refused.py).

Only some filesystems can hold such a name. Windows cannot decode one, and APFS
refuses it, so there the tests skip, with the reason.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess  # nosec B404 - the CLI under test runs as a child process
import sys
from pathlib import Path
from typing import List, Tuple

import pytest

import automated_security_helper
from tests.utils.helpers import checkout_env
from tests.utils.tool_guard import CHILD_TOOL_PROBE_STUBS

pytestmark = pytest.mark.integration

#: The checkout under test, which a child process is pointed at.
_CHECKOUT = Path(automated_security_helper.__file__).resolve().parents[1]

#: The scan every test runs: one scanner, Python only, and one secret to find.
_SCAN = ["--scanners", "detect-secrets", "--python-only", "--no-progress", "--no-color"]

#: What the child runs: ``ash`` as its console script does, after the tool probes are
#: answered. Without them the child found the uv installed with ASH beside its
#: interpreter and ran ``uv tool run detect-secrets --version``, which left uv's cache
#: and tool lock in the test's HOME.
_DRIVER = CHILD_TOOL_PROBE_STUBS + (
    "import sys\n"
    "from automated_security_helper.cli.entrypoint import main\n"
    "sys.argv = ['ash', *sys.argv[1:]]\n"
    "main()\n"
)

#: A duration in a log line, the one thing two runs of the same scan differ in.
_DURATION = re.compile(r"\d+(?:\.\d+)?(?: ?(?:seconds|second|ms|s))\b")


def _not_utf8(parent: Path, name: bytes = b"caf\xe9") -> Path:
    try:
        odd = parent / os.fsdecode(name)
        odd.mkdir()
    except (UnicodeDecodeError, OSError) as error:
        pytest.skip(f"this filesystem cannot hold a name that is not UTF-8: {error}")
    return odd


def _shown(path: Path) -> str:
    """*path* as the console and ash.log show it: its surrogates as ``\\udcNN``."""
    return "".join(
        f"\\u{ord(character):04x}" if 0xD800 <= ord(character) <= 0xDFFF else character
        for character in str(path)
    )


def _ash(tmp_path: Path, args: List[str]) -> subprocess.CompletedProcess:
    """`ash` in a child process whose stdout cannot encode a surrogate."""
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    env = {
        key: value for key, value in os.environ.items() if not key.startswith("ASH_")
    }
    env.update(
        HOME=str(home),
        USERPROFILE=str(home),
        XDG_CONFIG_HOME=str(home / ".config"),
        XDG_CACHE_HOME=str(home / ".cache"),
        XDG_DATA_HOME=str(home / ".local" / "share"),
        XDG_STATE_HOME=str(home / ".local" / "state"),
        PYTHONIOENCODING="utf-8:strict",
        # Wide, so that no path is folded and the two runs' lines compare.
        COLUMNS="1000",
        TERMINAL_WIDTH="1000",
    )
    return subprocess.run(  # nosec B603 - fixed interpreter and arguments
        [sys.executable, "-c", _DRIVER, *args],
        cwd=tmp_path,
        env=checkout_env(env),
        capture_output=True,
        timeout=600,
    )


def _source(tmp_path: Path) -> Path:
    source = tmp_path / "src"
    source.mkdir()
    (source / "app.py").write_text('password = "hunter2hunter2hunter2"\n')
    return source


def _lines(text: str, output: Path) -> List[str]:
    """*text*'s lines with the output directory and the durations taken out, and an
    ash.log line's timestamp column dropped."""
    shown = _shown(output)
    lines = []
    for line in text.splitlines():
        if "\t" in line:
            line = line.split("\t", 1)[1]
        lines.append(_DURATION.sub("T", line.replace(shown, "OUT")))
    return lines


def _log(output: Path) -> List[str]:
    with open(os.path.join(os.fsencode(output), b"ash.log"), "rb") as handle:
        return _lines(handle.read().decode("utf-8"), output)


def _reports(output: Path) -> List[bytes]:
    return sorted(os.listdir(os.path.join(os.fsencode(output), b"reports")))


def _app_py_findings(output: Path) -> List[Tuple[str, str]]:
    """The (rule, file) of each finding in *output*'s aggregated results."""
    path = os.path.join(os.fsencode(output), b"ash_aggregated_results.json")
    with open(path, "rb") as handle:
        results = json.loads(handle.read().decode("utf-8"))
    return sorted(
        (
            result.get("ruleId", ""),
            result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
        )
        for run in (results.get("sarif") or {}).get("runs") or []
        for result in run.get("results") or []
    )


def _outcome(child: subprocess.CompletedProcess) -> Tuple[int, str, str]:
    return (
        child.returncode,
        child.stdout.decode("utf-8"),
        child.stderr.decode("utf-8", "backslashreplace"),
    )


def _same_as_utf8(plain_child, plain: Path, odd_child, odd: Path) -> None:
    code, stdout, stderr = _outcome(odd_child)
    plain_code, plain_stdout, plain_stderr = _outcome(plain_child)

    assert plain_code == 2, (plain_stdout, plain_stderr)
    # The verdict: one actionable finding, as into the UTF-8 directory.
    assert code == plain_code, (stdout, stderr)
    assert "Logging error" not in stderr and "Traceback" not in stderr, stderr
    assert "caf\\udce9" in stdout, stdout
    assert _reports(odd) == _reports(plain)
    assert os.path.isfile(
        os.path.join(os.fsencode(odd), b"ash_aggregated_results.json")
    )
    # The control: with its tool probes answered the child still runs detect-secrets,
    # which finds app.py's one secret, into either directory.
    plain_findings = _app_py_findings(plain)
    assert len(plain_findings) == 1, plain_findings
    assert plain_findings[0][1].endswith("app.py"), plain_findings
    assert _app_py_findings(odd) == plain_findings


def test_the_child_imports_the_checkout_under_test(tmp_path):
    """Else the tests below would measure whatever ASH the interpreter finds."""
    child = subprocess.run(  # nosec B603 - fixed interpreter and arguments
        [
            sys.executable,
            "-c",
            "import automated_security_helper as a; print(a.__file__)",
        ],
        cwd=tmp_path,
        env=checkout_env({**os.environ, "HOME": str(tmp_path)}),
        capture_output=True,
        text=True,
        timeout=120,
        check=True,
    )

    assert Path(child.stdout.strip()).resolve().is_relative_to(_CHECKOUT), child.stdout


def test_a_local_scan_into_it_logs_and_reports_as_into_a_utf8_one(tmp_path):
    source = _source(tmp_path)
    plain = tmp_path / "plain-out"
    odd = _not_utf8(tmp_path) / "out"
    scan = ["scan", "--mode", "local", "--source-dir", str(source), *_SCAN]

    plain_child = _ash(tmp_path, [*scan, "--output-dir", str(plain)])
    odd_child = _ash(tmp_path, [*scan, "--output-dir", str(odd)])

    _same_as_utf8(plain_child, plain, odd_child, odd)
    assert _log(odd) == _log(plain)


def test_a_report_over_existing_results_there_works_too(tmp_path):
    source = _source(tmp_path)
    seeded = tmp_path / "seed-out"
    scan = ["scan", "--mode", "local", "--source-dir", str(source), *_SCAN]
    assert _ash(tmp_path, [*scan, "--output-dir", str(seeded)]).returncode == 2
    plain = tmp_path / "plain-out"
    odd = _not_utf8(tmp_path) / "out"
    for output in (plain, odd):
        output.mkdir()
        shutil.copy(
            seeded / "ash_aggregated_results.json",
            output / "ash_aggregated_results.json",
        )

    plain_child = _ash(tmp_path, [*scan, "--use-existing", "--output-dir", str(plain)])
    odd_child = _ash(tmp_path, [*scan, "--use-existing", "--output-dir", str(odd)])

    _same_as_utf8(plain_child, plain, odd_child, odd)
    assert _log(odd) == _log(plain)


def test_a_merge_into_it_reports_as_into_a_utf8_one(tmp_path):
    """ash merge writes no ash.log; its lines are on stdout, and compared there."""
    source = _source(tmp_path)
    shard = tmp_path / "shard-0"
    sharded = _ash(
        tmp_path,
        [
            "scan",
            "--mode",
            "local",
            "--source-dir",
            str(source),
            "--output-dir",
            str(shard),
            "--shard-index",
            "0",
            "--shard-count",
            "1",
            *_SCAN,
        ],
    )
    assert sharded.returncode == 2, _outcome(sharded)
    plain = tmp_path / "plain-out"
    odd = _not_utf8(tmp_path) / "out"
    merge = ["merge", "--results", str(shard), "--no-color"]

    plain_child = _ash(tmp_path, [*merge, "--output-dir", str(plain)])
    odd_child = _ash(tmp_path, [*merge, "--output-dir", str(odd)])

    _same_as_utf8(plain_child, plain, odd_child, odd)
    assert _console_text(odd_child, odd) == _console_text(plain_child, plain)


#: The console's time column.
_CLOCK = re.compile(r"\[\d\d/\d\d/\d\d \d\d:\d\d:\d\d\]")


def _console_text(child: subprocess.CompletedProcess, output: Path) -> str:
    """What *child* printed, with its time column, its whitespace (the console
    folds a log record at its own width, so a longer path folds elsewhere), the
    output directory and the durations taken out."""
    text = "".join(_CLOCK.sub("", child.stdout.decode("utf-8")).split())
    return _DURATION.sub("T", text.replace(_shown(output), "OUT"))
