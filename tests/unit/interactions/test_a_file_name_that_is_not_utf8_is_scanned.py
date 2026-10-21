# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A file whose name is not UTF-8 is scanned, and its findings are reported, as any other file's are.

On POSIX a file name is bytes. Python lists a byte that is not UTF-8 as a lone
surrogate, so a latin-1 ``secr\\xe9t.py`` is listed as "secr\\udce9t.py". A record holds
such a name as the surrogate's escape, the six characters ``\\udcNN``
(utils/undecodable_text.py), which UTF-8 JSON can hold and pydantic reads back.

A scanner that reads the file by its path reports what it finds there under that name,
and a name it can't read costs none of the other files' findings.
"""

from __future__ import annotations

import json
import os
import subprocess  # nosec B404 - the CLI under test runs as a child process
import sys
from pathlib import Path
from typing import Dict, List, Tuple

import pytest

import automated_security_helper
from automated_security_helper.models.asharp_model import AshAggregatedResults
from tests.utils.helpers import checkout_env
from tests.utils.tool_guard import CHILD_TOOL_PROBE_STUBS

#: The checkout under test, which a child process is pointed at.
_CHECKOUT = Path(automated_security_helper.__file__).resolve().parents[1]

#: The scan every test runs: one scanner that reads each file by its path.
_SCAN = ["--scanners", "detect-secrets", "--python-only", "--no-progress", "--no-color"]

#: What the child runs: ``ash`` as its console script does, after the tool probes are
#: answered (tests/unit/interactions/test_an_output_dir_that_is_not_utf8_works.py).
_DRIVER = CHILD_TOOL_PROBE_STUBS + (
    "import sys\n"
    "from automated_security_helper.cli.entrypoint import main\n"
    "sys.argv = ['ash', *sys.argv[1:]]\n"
    "main()\n"
)

#: One secret-like line, which detect-secrets reports more than once (several detectors).
_SECRET = (
    (
        '"""One secret-like line."""\n'
        "\n"
        'aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"\n'  # pragma: allowlist secret
    ).encode("utf-8")
)

#: The file whose name is not UTF-8: latin-1 bytes.
_ODD = b"secr\xe9t.py"
#: How a record writes that name: its surrogate as the six characters \udce9.
_ODD_RECORDED = "secr\\udce9t.py"
#: A file whose UTF-8 name is those same characters, a backslash included. A record
#: writes it exactly as it writes _ODD, so its reports are the yardstick for _ODD's.
_SPELLED = _ODD_RECORDED.encode("utf-8")
#: A plain file holding the same line.
_PLAIN = b"secret.py"


def _tree(parent: Path, label: str, names: List[bytes]) -> Path:
    """A directory under *parent* holding _SECRET in a file of each name in *names*."""
    source = parent / label
    source.mkdir()
    for name in names:
        try:
            with open(os.path.join(os.fsencode(source), name), "wb") as handle:
                handle.write(_SECRET)
        except (UnicodeError, OSError) as error:
            pytest.skip(f"this filesystem cannot hold the name {name!r}: {error}")
    return source


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


def _scan(
    tmp_path: Path, source: Path, label: str
) -> Tuple[subprocess.CompletedProcess, Path]:
    output = tmp_path / f"{label}-out"
    child = _ash(
        tmp_path,
        [
            "scan",
            "--mode",
            "local",
            "--source-dir",
            str(source),
            "--output-dir",
            str(output),
            *_SCAN,
        ],
    )
    return child, output


def _said(child: subprocess.CompletedProcess) -> Tuple[int, str, str]:
    return (
        child.returncode,
        child.stdout.decode("utf-8", "backslashreplace"),
        child.stderr.decode("utf-8", "backslashreplace"),
    )


def _results_bytes(output: Path) -> bytes:
    with open(output / "ash_aggregated_results.json", "rb") as handle:
        return handle.read()


def _findings(output: Path) -> List[Tuple[str, str]]:
    """The (rule, file) of each finding in *output*'s aggregated results."""
    results = json.loads(_results_bytes(output).decode("utf-8"))
    return sorted(
        (
            result.get("ruleId", ""),
            result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
        )
        for run in (results.get("sarif") or {}).get("runs") or []
        for result in run.get("results") or []
    )


def _rules_for(findings: List[Tuple[str, str]], name: str) -> List[str]:
    return sorted(rule for rule, uri in findings if uri == name)


def _report_texts(output: Path) -> Dict[str, str]:
    """Each file under *output*/reports, read as UTF-8 text."""
    reports = output / "reports"
    return {
        entry.name: entry.read_bytes().decode("utf-8")
        for entry in sorted(reports.iterdir())
        if entry.is_file()
    }


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


def test_a_secret_in_a_file_whose_name_is_not_utf8_is_reported(tmp_path):
    """The file's findings are reported under the recorded name, as the same file's are
    under a UTF-8 name, and the run's verdict is the same: findings, not incomplete."""
    plain_child, plain_out = _scan(
        tmp_path, _tree(tmp_path, "plain", [_PLAIN]), "plain"
    )
    odd_child, odd_out = _scan(tmp_path, _tree(tmp_path, "odd", [_ODD]), "odd")

    plain_code, plain_stdout, plain_stderr = _said(plain_child)
    code, stdout, stderr = _said(odd_child)
    # The control: detect-secrets reports the line under the UTF-8 name.
    assert plain_code == 2, (plain_stdout, plain_stderr)
    plain_rules = _rules_for(_findings(plain_out), "secret.py")
    assert len(plain_rules) >= 1, _findings(plain_out)

    assert code == plain_code, (stdout, stderr)
    assert "Traceback" not in stderr and "Error serializing" not in stdout + stderr
    assert _findings(odd_out) == [(rule, _ODD_RECORDED) for rule in plain_rules]


def test_a_name_that_is_not_utf8_costs_no_other_file_its_findings(tmp_path):
    """One run over both files: secret.py's findings are reported whatever happens to
    the other name, and the other name's are reported too."""
    plain_child, plain_out = _scan(
        tmp_path, _tree(tmp_path, "plain", [_PLAIN]), "plain"
    )
    both_child, both_out = _scan(
        tmp_path, _tree(tmp_path, "both", [_PLAIN, _ODD]), "both"
    )

    assert plain_child.returncode == 2, _said(plain_child)
    plain_rules = _rules_for(_findings(plain_out), "secret.py")
    code, stdout, stderr = _said(both_child)
    findings = _findings(both_out)

    assert _rules_for(findings, "secret.py") == plain_rules, (findings, stdout, stderr)
    assert _rules_for(findings, _ODD_RECORDED) == plain_rules, (
        findings,
        stdout,
        stderr,
    )
    assert code == 2, (stdout, stderr)


def test_the_results_read_back_and_every_report_names_the_file(tmp_path):
    """The aggregated results read back through the model, a report over them works, and
    each report names the file as it names a file spelled with the recorded name."""
    spelled_child, spelled_out = _scan(
        tmp_path, _tree(tmp_path, "spelled", [_SPELLED]), "spelled"
    )
    odd_source = _tree(tmp_path, "odd", [_ODD])
    odd_child, odd_out = _scan(tmp_path, odd_source, "odd")

    # The yardstick: a file spelled with the escape's characters is scanned today.
    assert spelled_child.returncode == 2, _said(spelled_child)
    assert odd_child.returncode == 2, _said(odd_child)

    # The read-back the report commands use.
    model = AshAggregatedResults.model_validate_json(_results_bytes(odd_out))
    uris = {
        location.physicalLocation.root.artifactLocation.uri
        for result in model.sarif.get_all_results()
        for location in result.locations or []
    }
    assert uris == {_ODD_RECORDED}, uris

    # A report over the stored results, as `ash scan --use-existing` makes it.
    again = _ash(
        tmp_path,
        [
            "scan",
            "--mode",
            "local",
            "--source-dir",
            str(odd_source),
            "--output-dir",
            str(odd_out),
            "--use-existing",
            *_SCAN,
        ],
    )
    assert again.returncode == 2, _said(again)

    spelled = _report_texts(spelled_out)
    odd = _report_texts(odd_out)
    assert sorted(odd) == sorted(spelled)
    # Each report names the file as often as it names the spelled one. The needle
    # leaves out the backslash, which each format may escape its own way.
    needle = "udce9t.py"
    counts = {
        name: (odd[name].count(needle), spelled[name].count(needle)) for name in spelled
    }
    assert all(got == want for got, want in counts.values()), counts
    assert sum(want for _, want in counts.values()) > 0, counts
