# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Trees, scans and read-backs for tests of file names that are not UTF-8.

On POSIX a file name is bytes. Python lists a byte that is not UTF-8 as a lone
surrogate (os.fsdecode, surrogateescape), so a latin-1 ``secr\\xe9t.py`` is listed
as "secr\\udce9t.py". A result records such a name in the record form, the
surrogate written as the six characters ``\\udcNN`` (utils/undecodable_text.py).

Each decision ASH makes by a file's name has to give such a file the answer it
gives a file whose name is plain text. The tests built on this module put the two
side by side in one tree and compare what one ``ash scan`` decides for each.

A child ``ash`` runs the checkout under test (checkout_env), with the tool probes
answered (CHILD_TOOL_PROBE_STUBS), and one scanner that reads each file by its
path: detect-secrets, which ASH runs in its own worker.

Only some filesystems can hold such a name. Windows cannot decode one and APFS
refuses it, so there a test that needs one on disk skips, with the reason.
"""

from __future__ import annotations

import json
import os
import subprocess  # nosec B404 - the CLI under test runs as a child process
import sys
from pathlib import Path
from typing import Dict, List, Mapping, NamedTuple, Optional, Sequence, Union

import pytest

from tests.utils.git_fixture import run_git
from tests.utils.helpers import checkout_env
from tests.utils.tool_guard import CHILD_TOOL_PROBE_STUBS

#: A file name that is not UTF-8: latin-1 bytes.
ODD_BYTES = b"secr\xe9t.py"
#: That name as Python lists it, with a lone surrogate.
ODD = os.fsdecode(ODD_BYTES)
#: That name in the record form: the surrogate as the six characters \udce9.
RECORDED = "secr\\udce9t.py"
#: The control: a plain name, which every decision below is also made for.
CONTROL = "secret.py"
#: A file no decision names, so a scan that dropped everything shows.
KEEP = "keep.py"

#: A line detect-secrets reports, under more than one detector.
SECRET_LINE = 'aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"'  # pragma: allowlist secret

#: The scan the tests run: one scanner that reads each file by its path.
SCAN_ARGS = (
    "--scanners",
    "detect-secrets",
    "--python-only",
    "--no-progress",
    "--no-color",
)

#: What the child runs: ``ash`` as its console script does, after the tool probes
#: are answered.
DRIVER = CHILD_TOOL_PROBE_STUBS + (
    "import sys\n"
    "from automated_security_helper.cli.entrypoint import main\n"
    "sys.argv = ['ash', *sys.argv[1:]]\n"
    "main()\n"
)

Name = Union[str, bytes]


def secret_source(blank_lines: int = 0, trailer: str = "") -> bytes:
    """A Python file holding SECRET_LINE after *blank_lines* empty lines, with
    *trailer* after it on the same line (an inline suppression comment, say)."""
    lines = ['"""A secret-like line."""', *([""] * blank_lines), SECRET_LINE + trailer]
    return ("\n".join(lines) + "\n").encode("utf-8")


def secret_line_number(blank_lines: int = 0) -> int:
    """The line SECRET_LINE is on in ``secret_source(blank_lines)``."""
    return blank_lines + 2


def make_tree(root: Path, files: Mapping[Name, bytes]) -> Path:
    """*root* holding each of *files*, a name (bytes, or text) to its content.

    A name may hold ``/``; its directories are made. Skips the test where the
    filesystem cannot hold a name.
    """
    root.mkdir(parents=True, exist_ok=True)
    base = os.fsencode(root)
    for name, content in files.items():
        raw = name if isinstance(name, bytes) else os.fsencode(name)
        path = os.path.join(base, raw)
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "wb") as handle:
                handle.write(content)
        except (UnicodeError, OSError) as error:
            pytest.skip(f"this filesystem cannot hold the name {raw!r}: {error}")
    return root


def child_env(cwd: Path) -> Dict[str, str]:
    """The environment of a child ``ash``: this one without ASH_ settings, a HOME of
    its own under *cwd*, and a stdout that cannot encode a surrogate."""
    home = cwd / "home"
    home.mkdir(parents=True, exist_ok=True)
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
        COLUMNS="1000",
        TERMINAL_WIDTH="1000",
        GIT_CONFIG_GLOBAL=os.devnull,
        GIT_CONFIG_NOSYSTEM="1",
    )
    return checkout_env(env)


def ash(cwd: Path, args: Sequence[Name], timeout: float = 600) -> "Ran":
    """``ash <args>`` in a child process, from *cwd*. An argument given as bytes
    reaches the child's argv as those bytes."""
    child = subprocess.run(  # nosec B603 - fixed interpreter and arguments
        [sys.executable, "-c", DRIVER, *args],
        cwd=cwd,
        env=child_env(cwd),
        capture_output=True,
        timeout=timeout,
    )
    return Ran(
        child.returncode,
        child.stdout.decode("utf-8", "backslashreplace"),
        child.stderr.decode("utf-8", "backslashreplace"),
        child.stdout,
    )


class Ran(NamedTuple):
    """What a child ``ash`` exited with and printed, decoded for an assertion, and
    its stdout as written (``ash report`` writes the report there)."""

    code: int
    stdout: str
    stderr: str
    stdout_bytes: bytes = b""

    def __repr__(self) -> str:
        return (
            f"Ran(code={self.code!r}, stdout={self.stdout!r}, stderr={self.stderr!r})"
        )


def report_of(cwd: Path, output: Path, reporter: str) -> "Ran":
    """``ash report`` of *output*'s saved results with *reporter*, uncolored, so the
    report on stdout is the reporter's own text."""
    return ash(
        cwd,
        ["report", "--output-dir", str(output), "--format", reporter, "--no-color"],
    )


def scan(
    cwd: Path, source: Path, output: Path, *extra: Name, scanner_args=SCAN_ARGS
) -> Ran:
    """``ash scan`` of *source* into *output*, local mode, with *extra* arguments."""
    return ash(
        cwd,
        [
            "scan",
            "--mode",
            "local",
            "--source-dir",
            str(source),
            "--output-dir",
            str(output),
            *scanner_args,
            *extra,
        ],
    )


def results_file(output: Path) -> Path:
    return output / "ash_aggregated_results.json"


def results(output: Path) -> dict:
    """The aggregated results *output* holds, as JSON reads them: a name in the
    record form is the six-character escape text."""
    return json.loads(results_file(output).read_bytes().decode("utf-8"))


class Finding(NamedTuple):
    """One SARIF result as the results file holds it."""

    uri: str
    rule: str
    line: Optional[int]
    suppressed: bool


def findings(output: Path) -> List[Finding]:
    """Every SARIF result in *output*'s aggregated results, in a stable order."""
    found = []
    for run in (results(output).get("sarif") or {}).get("runs") or []:
        for result in run.get("results") or []:
            location = (result.get("locations") or [{}])[0].get(
                "physicalLocation"
            ) or {}
            region = location.get("region") or {}
            found.append(
                Finding(
                    uri=(location.get("artifactLocation") or {}).get("uri", ""),
                    rule=result.get("ruleId", ""),
                    line=region.get("startLine"),
                    suppressed=bool(result.get("suppressions")),
                )
            )
    return sorted(found)


def flat_findings(text: str) -> List[Finding]:
    """Every finding in the flat JSON report *text*, as JSON reads it."""
    document = json.loads(text)
    return sorted(
        Finding(
            uri=entry.get("file_path") or "",
            rule=entry.get("rule_id") or "",
            line=entry.get("line_start"),
            suppressed=bool(entry.get("is_suppressed")),
        )
        for entry in document.get("findings") or []
    )


def report_text(name: str, document: str) -> str:
    """The text the report file *name* holds, as its format decodes it: a name
    written as a JSON or YAML escape of a surrogate reads as the surrogate, not as
    the record form."""
    import yaml
    from defusedxml import ElementTree

    def strings(value):
        if isinstance(value, str):
            yield value
        elif isinstance(value, dict):
            for key, item in value.items():
                yield from strings(key)
                yield from strings(item)
        elif isinstance(value, list):
            for item in value:
                yield from strings(item)

    if name.endswith((".json", ".sarif")):
        return "\n".join(strings(json.loads(document)))
    if name.endswith(".yaml"):
        return "\n".join(strings(yaml.safe_load(document)))
    if name.endswith(".xml"):
        root = ElementTree.fromstring(document)
        return "\n".join(
            part
            for element in root.iter()
            for part in (element.text, element.tail, *element.attrib.values())
            if part
        )
    return document


def reports(output: Path) -> Dict[str, str]:
    """Each file under *output*/reports, read as UTF-8 text."""
    return {
        entry.name: entry.read_bytes().decode("utf-8")
        for entry in sorted((output / "reports").iterdir())
        if entry.is_file()
    }


#: A file the results hold no finding for.
ABSENT = "absent"
#: A file whose findings are all suppressed.
SUPPRESSED = "suppressed"
#: A file whose findings are all reported.
REPORTED = "reported"
#: A file with suppressed and reported findings both.
MIXED = "mixed"


def decision(found: Sequence[Finding], uri: str, rule: Optional[str] = None) -> str:
    """What the results say for the file the results name *uri*: for its findings
    of *rule*, or for all of them."""
    states = {f.suppressed for f in found if f.uri == uri and rule in (None, f.rule)}
    if not states:
        return ABSENT
    if states == {True}:
        return SUPPRESSED
    if states == {False}:
        return REPORTED
    return MIXED


def git(cwd: Path, *args: str) -> str:
    """Plain git in *cwd*, with no user or system configuration, failing the test
    on a non-zero exit."""
    env = {
        **os.environ,
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_AUTHOR_NAME": "test",
        "GIT_AUTHOR_EMAIL": "test@example.com",
        "GIT_COMMITTER_NAME": "test",
        "GIT_COMMITTER_EMAIL": "test@example.com",
    }
    for key in ("GIT_DIR", "GIT_WORK_TREE", "GIT_COMMON_DIR", "GIT_INDEX_FILE"):
        env.pop(key, None)
    done = run_git(*args, cwd=cwd, env=env)
    assert done.returncode == 0, (args, done.stdout, done.stderr)
    return done.stdout
