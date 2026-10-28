# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A name that is not valid UTF-8 costs no run its results file.

On POSIX a file name is bytes, and Python lists a byte that is not UTF-8 as a lone
surrogate: a latin-1 ``secr\\xe9t.py`` is listed as "secr\\udce9t.py". A scanned
repository's own ``.ash`` config can spell one too, as a ``\\udcNN`` escape in a
double-quoted YAML string or a JSON string. The JSON writer cannot encode a lone
surrogate, so one such name held as is anywhere in the results (a finding's file, an
ignore path or a suppression's reason in the recorded config) would stop the results
file from being written, and with it every scanner's findings. Each one is written
as its record form, the six characters ``\\udcNN`` (utils/undecodable_text.py).

Each cell runs ``ash scan`` in a child process, as a user runs it, with every tool
probe answered as on a host without the tool, and every program start refused and
logged apart from ASH's own detect-secrets worker, so the child starts nothing else.
"""

from __future__ import annotations

import json
import os
import subprocess  # nosec B404 - the CLI under test runs as a child process
import sys
from pathlib import Path
from typing import Dict, List, Tuple

import pytest

from tests.utils.helpers import checkout_env
from tests.utils.isolated_tool_env import network_containment

#: For the tests that plant the file whose name is not UTF-8.
_NO_NON_UTF8_NAMES = pytest.mark.skipif(
    os.name == "nt",
    reason="NTFS names are UTF-16; a name that is not UTF-8 bytes cannot exist",
)

#: What the child runs first: the probes answered, uv's cache and installs answered
#: unavailable, and an audit hook that refuses and logs every program start apart
#: from ASH's own detect-secrets worker. Source, not a call: the child cannot
#: import the tests.
_DRIVER = """\
import os
import sys

_LOG = os.environ["ASH_TEST_START_LOG"]
#: A program a cell lets the child start, such as git: the name only, never a path.
_ALLOWED = os.environ.get("ASH_TEST_ALLOW_PROGRAM")
_EVENTS = {
    "subprocess.Popen",
    "os.posix_spawn",
    "os.exec",
    "os.system",
    "os.spawn",
    "_posixsubprocess.fork_exec",
}


def _named(value):
    if isinstance(value, bytes):
        value = os.fsdecode(value)
    return os.path.basename(value) if isinstance(value, str) else None


def _starts_allowed_program(args):
    # The program a start names: the executable or path, then the first argument.
    if not _ALLOWED or not args:
        return False
    if _named(args[0]) == _ALLOWED:
        return True
    argv = args[1] if len(args) > 1 else None
    return isinstance(argv, (list, tuple)) and bool(argv) and _named(argv[0]) == _ALLOWED


def _refuse_starts(event, args):
    if event not in _EVENTS:
        return
    if "automated_security_helper.utils.detect_secrets_worker" in repr(args):
        return
    if _starts_allowed_program(args):
        return
    with open(_LOG, "a", encoding="utf-8", errors="backslashreplace") as handle:
        handle.write(event + " " + repr(args) + "\\n")
    raise FileNotFoundError(2, "refused by the test", "a program")


sys.addaudithook(_refuse_starts)

from automated_security_helper.plugin_modules.ash_builtin.scanners.opengrep_scanner import (
    OpengrepScanner,
)
from automated_security_helper.utils import pre_installed_tool, uv_tool_runner

uv_tool_runner.UVToolRunner.is_uv_available = lambda self: False
uv_tool_runner.UVToolRunner.get_cache_info = lambda self: {
    "cache_available": False,
    "error": "uv is not asked here",
}
uv_tool_runner.UVToolRunner.install_tool_with_version = lambda self, *a, **k: False
uv_tool_runner.find_uv_or_none = lambda: None
pre_installed_tool._run = lambda command, timeout: None
OpengrepScanner._get_opengrep_version = lambda self: None

from automated_security_helper.cli.entrypoint import main

sys.argv = ["ash", *sys.argv[1:]]
main()
"""

#: One secret-like line, which detect-secrets reports under three rules.
_SECRET = (
    (
        '"""One secret-like line."""\n'
        "\n"
        'aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"\n'  # pragma: allowlist secret
    ).encode("utf-8")
)

#: The file whose name is not UTF-8: latin-1 bytes.
_ODD = b"secr\xe9t.py"
#: How the results file writes that name: its surrogate as the six characters \\udce9.
_ODD_RECORDED = "secr\\udce9t.py"
_PLAIN = b"secret.py"


def _tree(root: Path, files: Dict[bytes, bytes]) -> Path:
    root.mkdir(parents=True)
    for name, data in files.items():
        path = os.path.join(os.fsencode(root), name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        try:
            with open(path, "wb") as handle:
                handle.write(data)
        except (UnicodeError, OSError) as error:
            pytest.skip(f"this filesystem cannot hold the name {name!r}: {error}")
    return root


def _scan(
    tmp_path: Path, source: Path, *extra: str, allow_program: str | None = None
) -> Tuple[int, str, Path, List[str]]:
    """``ash scan`` of *source* in a child, which starts no program but ASH's
    detect-secrets worker and *allow_program*, by name."""
    output = tmp_path / f"{source.name}-out"
    starts = tmp_path / f"{source.name}-starts.log"
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    env = {k: v for k, v in os.environ.items() if not k.startswith("ASH_")}
    env.update(network_containment())
    env.update(
        HOME=str(home),
        XDG_CONFIG_HOME=str(home / ".config"),
        XDG_CACHE_HOME=str(home / ".cache"),
        XDG_DATA_HOME=str(home / ".local" / "share"),
        XDG_STATE_HOME=str(home / ".local" / "state"),
        PYTHONIOENCODING="utf-8:strict",
        ASH_TEST_START_LOG=str(starts),
        COLUMNS="1000",
    )
    if allow_program:
        env["ASH_TEST_ALLOW_PROGRAM"] = allow_program
    # The child imports ASH from this checkout: it runs without -I, which would
    # ignore PYTHONPATH, and checkout_env puts the checkout first on it.
    child = subprocess.run(  # nosec B603 - fixed interpreter and arguments
        [
            sys.executable,
            "-c",
            _DRIVER,
            "scan",
            "--mode",
            "local",
            "--source-dir",
            str(source),
            "--output-dir",
            str(output),
            "--scanners",
            "detect-secrets",
            "--python-only",
            "--no-progress",
            "--no-color",
            *extra,
        ],
        cwd=tmp_path,
        env=checkout_env(env),
        capture_output=True,
        timeout=600,
    )
    said = child.stdout.decode("utf-8", "backslashreplace") + child.stderr.decode(
        "utf-8", "backslashreplace"
    )
    started = starts.read_text(encoding="utf-8").splitlines() if starts.exists() else []
    return child.returncode, said, output, started


def _findings(output: Path) -> List[Tuple[str, str]]:
    """The (rule, file) of each finding in *output*'s results file, read as JSON."""
    with open(output / "ash_aggregated_results.json", "rb") as handle:
        results = json.loads(handle.read().decode("utf-8"))
    return sorted(
        (
            result.get("ruleId", ""),
            result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
        )
        for run in (results.get("sarif") or {}).get("runs") or []
        for result in run.get("results") or []
    )


def _rules_for(findings: List[Tuple[str, str]], name: str) -> List[str]:
    return sorted(rule for rule, uri in findings if os.path.basename(uri) == name)


def _plain_rules(tmp_path: Path) -> List[str]:
    """The control: what detect-secrets reports for secret.py alone."""
    code, said, output, started = _scan(
        tmp_path, _tree(tmp_path / "control", {_PLAIN: _SECRET})
    )
    assert code == 2, said
    assert started == []
    rules = _rules_for(_findings(output), "secret.py")
    assert rules, _findings(output)
    return rules


@_NO_NON_UTF8_NAMES
def test_a_file_named_so_keeps_the_results_file_and_both_files_findings(tmp_path):
    plain_rules = _plain_rules(tmp_path)
    source = _tree(tmp_path / "both", {_PLAIN: _SECRET, _ODD: _SECRET})

    code, said, output, started = _scan(tmp_path, source)

    assert code == 2, said
    assert "Error serializing" not in said and "Traceback" not in said, said
    assert started == []
    findings = _findings(output)
    assert _rules_for(findings, "secret.py") == plain_rules, findings
    assert _rules_for(findings, _ODD_RECORDED) == plain_rules, findings


_CONFIG_SHAPES = {
    "yaml-ignore-path": (
        b".ash/.ash.yaml",
        (
            b'global_settings:\n  ignore_paths:\n    - path: "secr\\udce9t.py"\n'
            b'      reason: "x"\n'
        ),
    ),
    "json-ignore-path": (
        b".ash/.ash.json",
        (
            b'{"global_settings": {"ignore_paths": '
            b'[{"path": "secr\\udce9t.py", "reason": "x"}]}}\n'
        ),
    ),
    "yaml-suppression-reason": (
        b".ash/.ash.yaml",
        (
            b'global_settings:\n  suppressions:\n    - path: "other.py"\n'
            b'      rule_id: "SECRET-SECRET-KEYWORD"\n      reason: "caf\\udce9"\n'
        ),
    ),
}


@pytest.mark.parametrize("shape", sorted(_CONFIG_SHAPES))
def test_a_repository_config_spelling_such_a_name_keeps_the_results_file(
    tmp_path, shape
):
    """The repository's own config, which its owner writes, not the operator."""
    plain_rules = _plain_rules(tmp_path)
    config_name, config = _CONFIG_SHAPES[shape]
    source = _tree(tmp_path / shape, {_PLAIN: _SECRET, config_name: config})

    code, said, output, started = _scan(tmp_path, source)

    assert code == 2, said
    assert "Error serializing" not in said, said
    assert started == []
    assert _rules_for(_findings(output), "secret.py") == plain_rules


@_NO_NON_UTF8_NAMES
def test_an_ignore_path_naming_such_a_file_ignores_it(tmp_path):
    """The live configuration keeps the name it read, so the file is not scanned."""
    plain_rules = _plain_rules(tmp_path)
    config_name, config = _CONFIG_SHAPES["yaml-ignore-path"]
    source = _tree(
        tmp_path / "ignored", {_PLAIN: _SECRET, _ODD: _SECRET, config_name: config}
    )

    code, said, output, started = _scan(tmp_path, source)

    assert code == 2, said
    assert started == []
    findings = _findings(output)
    assert _rules_for(findings, "secret.py") == plain_rules, findings
    assert _rules_for(findings, _ODD_RECORDED) == [], findings


@_NO_NON_UTF8_NAMES
def test_use_existing_applies_the_ignore_path_the_scan_applied(tmp_path):
    """The results record the ignore path in its record form, and a run that reads
    them back reads it as the name, so it ignores the same file."""
    plain_rules = _plain_rules(tmp_path)
    config_name, config = _CONFIG_SHAPES["yaml-ignore-path"]
    source = _tree(
        tmp_path / "again", {_PLAIN: _SECRET, _ODD: _SECRET, config_name: config}
    )
    first, said, output, started = _scan(tmp_path, source)
    assert first == 2, said

    code, said, output, started = _scan(tmp_path, source, "--use-existing")

    assert code == 2, said
    assert started == []
    findings = _findings(output)
    assert _rules_for(findings, "secret.py") == plain_rules, findings
    assert _rules_for(findings, _ODD_RECORDED) == [], findings


def test_a_project_name_spelling_such_a_name_is_refused(tmp_path):
    source = _tree(
        tmp_path / "named",
        {_PLAIN: _SECRET, b".ash/.ash.yaml": b'project_name: "caf\\udce9"\n'},
    )

    code, said, output, started = _scan(tmp_path, source)

    assert code == 3, said
    assert "Invalid configuration" in said, said
    assert started == []
    assert not (output / "ash_aggregated_results.json").exists()
