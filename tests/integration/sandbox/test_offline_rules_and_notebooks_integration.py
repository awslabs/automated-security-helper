"""Real scans: a failed semgrep run fails the scan, and the sandbox confines nbconvert.

Three behaviors, each through ``ash scan`` with the real tools:

1. semgrep exits 7 when it cannot use a rule configuration and still writes SARIF that
   holds only error notifications. The scanner's row must be ERROR and the scan must
   not exit 0, with or without a sandbox. Measured before the change: ``PASSED``, 0
   findings, exit 0 under ``--fail-on-findings``.
2. An offline scan under ``--sandbox bwrap`` reads the operator's
   ``$SEMGREP_RULES_CACHE_DIR``. Measured before the change: semgrep could not see the
   directory, exited 7, and the scan reported no findings and exited 0.
3. Under ``--sandbox bwrap`` nbconvert runs in the sandbox. The stand-in is a
   ``jupyter_nbconvert_config.py`` in ``$JUPYTER_CONFIG_DIR``, which nbconvert loads
   when it starts and which records the network namespace it ran in. Measured before
   the change: the host's namespace, with the home directory and a credential-shaped
   variable visible.

The ``--sandbox off`` runs are the controls. Skipped unless ``--run-integration`` is
given, and per test when semgrep, nbconvert or bubblewrap is not installed.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from automated_security_helper.utils.sandbox import clear_backend_cache, resolve_backend
from automated_security_helper.utils.sandbox.scope import SandboxUnavailable

pytestmark = pytest.mark.integration

RULE = """\
rules:
  - id: offline-print-call
    pattern: print(...)
    message: a print call
    languages: [python]
    severity: ERROR
"""

# A rule file semgrep rejects: no pattern.
BROKEN_RULE = """\
rules:
  - id: offline-broken
    message: no pattern
    languages: [python]
    severity: ERROR
"""

NOTEBOOK = json.dumps(
    {
        "cells": [
            {
                "cell_type": "code",
                "metadata": {},
                "execution_count": None,
                "outputs": [],
                "source": ["print('notebook')\n"],
            }
        ],
        "metadata": {"language_info": {"name": "python", "file_extension": ".py"}},
        "nbformat": 4,
        "nbformat_minor": 5,
    }
)

PROBE_CONFIG = """\
import os
from pathlib import Path

marker = Path({marker!r})
try:
    namespace = os.readlink("/proc/self/ns/net")
except OSError as error:
    namespace = "unreadable: " + type(error).__name__
with marker.open("a", encoding="utf-8") as fh:
    fh.write(namespace + "\\n")
"""


def _ash_executable() -> str:
    beside = Path(sys.executable).with_name("ash")
    found = str(beside) if beside.exists() else shutil.which("ash")
    if not found:
        pytest.fail("the ash entry point is not installed beside this interpreter")
    return found


def _require(tool: str) -> None:
    if shutil.which(tool) is None:
        pytest.skip(f"{tool} is not installed")


def _require_bwrap() -> None:
    clear_backend_cache()
    try:
        resolve_backend("bwrap")
    except SandboxUnavailable as e:
        pytest.skip(f"bwrap unavailable: {e}")


def _rules(tmp_path: Path, content: str) -> Path:
    rules = tmp_path / "rule-cache"
    rules.mkdir()
    (rules / "rules.yml").write_text(content)
    (rules / ".ash-rules-fetched-at").write_text("2026-10-10T00:00:00Z\n")
    return rules


def _scan(tmp_path: Path, sandbox: str, *, scanners: str, env_extra: dict, extra=()):
    source = tmp_path / "src"
    output = tmp_path / "out"
    env = {**os.environ, **env_extra}
    command = [
        _ash_executable(),
        "scan",
        "--mode",
        "local",
        "--source-dir",
        str(source),
        "--output-dir",
        str(output),
        "--scanners",
        scanners,
        "--sandbox",
        sandbox,
        "--offline",
        "--no-progress",
        *extra,
    ]
    result = subprocess.run(  # nosec B603 - fixed argv
        command,
        env=env,
        capture_output=True,
        text=True,
        timeout=600,
        check=False,
        cwd=tmp_path,
    )
    return result, output


def _semgrep_row(output: Path) -> dict:
    row = output / "scanners" / "semgrep" / "source" / "ASH.ScanResults.json"
    assert row.exists(), f"no semgrep result at {row}"
    return json.loads(row.read_text())


def _source(tmp_path: Path) -> Path:
    source = tmp_path / "src"
    source.mkdir()
    (source / "app.py").write_text("print('hello')\n")
    return source


def test_a_semgrep_run_with_a_rejected_rule_file_fails_the_scan(tmp_path):
    _require("semgrep")
    _source(tmp_path)
    rules = _rules(tmp_path, BROKEN_RULE)

    result, output = _scan(
        tmp_path,
        "off",
        scanners="semgrep",
        env_extra={"SEMGREP_RULES_CACHE_DIR": str(rules)},
        extra=["--fail-on-findings"],
    )

    row = _semgrep_row(output)
    assert row.get("exit_code") not in (0, 1), f"semgrep accepted the rules: {row}"
    assert row.get("status") == "ERROR", (
        f"semgrep exited {row.get('exit_code')} and was graded {row.get('status')} "
        f"with {row.get('finding_count')} findings"
    )
    assert result.returncode != 0, (
        "the scan exited 0 although semgrep failed:\n" + result.stdout[-2000:]
    )


def test_an_offline_sandboxed_scan_reads_the_operators_rule_cache(tmp_path):
    _require("semgrep")
    _require_bwrap()
    _source(tmp_path)
    rules = _rules(tmp_path, RULE)

    result, output = _scan(
        tmp_path,
        "bwrap",
        scanners="semgrep",
        env_extra={"SEMGREP_RULES_CACHE_DIR": str(rules)},
        extra=["--fail-on-findings"],
    )

    row = _semgrep_row(output)
    assert row.get("finding_count", 0) >= 1, (
        f"the sandboxed scan found nothing with the rule cache at {rules}: {row}"
    )
    assert result.returncode == 2, result.stdout[-2000:]


def test_an_offline_unsandboxed_scan_reads_the_rule_cache(tmp_path):
    """Control: the same rules and source without a sandbox report the finding."""
    _require("semgrep")
    _source(tmp_path)
    rules = _rules(tmp_path, RULE)

    result, output = _scan(
        tmp_path,
        "off",
        scanners="semgrep",
        env_extra={"SEMGREP_RULES_CACHE_DIR": str(rules)},
        extra=["--fail-on-findings"],
    )

    assert _semgrep_row(output).get("finding_count", 0) >= 1
    assert result.returncode == 2, result.stdout[-2000:]


def _notebook_scan(tmp_path: Path, sandbox: str):
    source = _source(tmp_path)
    (source / "analysis.ipynb").write_text(NOTEBOOK)
    config_dir = tmp_path / "jupyter-config"
    config_dir.mkdir()
    marker = tmp_path / "nbconvert-namespace.txt"
    (config_dir / "jupyter_nbconvert_config.py").write_text(
        PROBE_CONFIG.format(marker=str(marker))
    )
    rules = _rules(tmp_path, RULE)
    _result, output = _scan(
        tmp_path,
        sandbox,
        scanners="semgrep",
        env_extra={
            "SEMGREP_RULES_CACHE_DIR": str(rules),
            "JUPYTER_CONFIG_DIR": str(config_dir),
        },
        extra=[
            "--fail-on-findings",
            "false",
            "--config-overrides",
            f"sandbox.extra_read_paths=[{rules}]",
        ],
    )
    converted = sorted((output / "converted").rglob("*-converted.*"))
    namespaces = marker.read_text().split() if marker.exists() else []
    return converted, namespaces


def test_nbconvert_runs_inside_the_sandbox(tmp_path):
    _require("semgrep")
    _require("jupyter-nbconvert")
    _require_bwrap()
    host = os.readlink("/proc/self/ns/net")

    converted, namespaces = _notebook_scan(tmp_path, "bwrap")

    assert host not in namespaces, (
        f"nbconvert ran in the host's network namespace {host} under --sandbox bwrap"
    )
    assert converted, "the notebook was not converted under the sandbox"


def test_without_a_sandbox_nbconvert_runs_on_the_host(tmp_path):
    """Control: the probe works, and without a sandbox it reports the host."""
    _require("semgrep")
    _require("jupyter-nbconvert")
    host = os.readlink("/proc/self/ns/net")

    converted, namespaces = _notebook_scan(tmp_path, "off")

    assert host in namespaces, f"the probe did not record the host: {namespaces}"
    assert converted
