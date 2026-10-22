# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A run in which no selected scanner had a file to scan exits 1, and says why.

A scanner with no file of its kind to scan is SKIPPED rather than PASSED with no
findings. A run whose every scanner is SKIPPED has shown the target to be neither
clean nor dirty, so with fail_on_incomplete_scanners on (the default) it exits 1,
and 0 with --no-fail-on-incomplete-scanners. ``ash merge`` reaches the same verdict
through the same code.

The error used to be "Scan ran no scanners", which reads as a selection mistake.
When the scanners had nothing to scan it now says so, names them, names
global_settings.ignore_paths when the config sets it, and gives the remedy.

The tree is the one an operator meets: ``app.py`` and an in-tree
``.ash/.ash.yaml`` whose ignore_paths is ``**``, scanned with detect-secrets, which
ASH depends on. Each run is a child process with no cloud credentials, an endpoint
that refuses connections and a home of its own.
"""

from __future__ import annotations

import json
import os
import re
import subprocess  # nosec B404 -- runs this interpreter's ASH on a fixture tree
import sys
import textwrap
from pathlib import Path

import pytest

from automated_security_helper.interactions import run_ash_scan
from automated_security_helper.models.asharp_model import AshAggregatedResults
from tests.utils.helpers import importing_this_checkout

DRIVER = importing_this_checkout(
    textwrap.dedent(
        """
        from automated_security_helper.cli.main import app

        sys.argv = ["ash", *sys.argv[1:]]
        app()
        """
    )
)

IGNORE_EVERYTHING = (
    "project_name: nothing-to-scan\n"
    "global_settings:\n"
    "  ignore_paths:\n"
    '    - path: "**"\n'
    '      reason: "listed in the scanned tree"\n'
)

NOTHING_TO_SCAN = "No selected scanner had a file to scan"
REMEDY = "--no-fail-on-incomplete-scanners"
_ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def _tree(root: Path) -> Path:
    (root / ".ash").mkdir(parents=True)
    (root / ".ash" / ".ash.yaml").write_text(IGNORE_EVERYTHING, encoding="utf-8")
    (root / "app.py").write_text('print("hello")\n', encoding="utf-8")
    return root


def _env(home: Path) -> dict[str, str]:
    env = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith(("AWS_", "ASH_"))
    }
    for directory in (".cache", ".config", ".local/share"):
        (home / directory).mkdir(parents=True, exist_ok=True)
    env.update(
        {
            "AWS_CONFIG_FILE": os.devnull,
            "AWS_SHARED_CREDENTIALS_FILE": os.devnull,
            "AWS_EC2_METADATA_DISABLED": "true",
            "AWS_ENDPOINT_URL": "http://127.0.0.1:9",
            "AWS_REGION": "us-east-1",
            "ASH_OFFLINE": "YES",
            "NO_COLOR": "1",
            "COLUMNS": "400",
            "HOME": str(home),
            "XDG_CACHE_HOME": str(home / ".cache"),
            "XDG_CONFIG_HOME": str(home / ".config"),
            "XDG_DATA_HOME": str(home / ".local" / "share"),
        }
    )
    return env


def _ash(base: Path, cwd: Path, *args: str) -> subprocess.CompletedProcess:
    # A fixed argv: this interpreter and the driver above, no shell.
    return subprocess.run(  # nosec B603
        [sys.executable, "-I", "-c", DRIVER, *args],
        capture_output=True,
        text=True,
        timeout=600,
        env=_env(base / "home"),
        cwd=cwd,
    )


def _scan(base: Path, source: Path, output: Path, *extra: str):
    return _ash(
        base,
        source,
        "scan",
        "--source-dir",
        str(source),
        "--output-dir",
        str(output),
        "--scanners",
        "detect-secrets",
        "--offline",
        "--no-progress",
        "--no-fail-on-findings",
        *extra,
    )


def _said(result: subprocess.CompletedProcess) -> str:
    """What the run printed, on one line per message: rich wraps at the width."""
    return " ".join(_ANSI.sub("", result.stdout + result.stderr).split())


def _sentence(said: str) -> str:
    """The new message, from its first words to the remedy."""
    start = said.find(NOTHING_TO_SCAN)
    assert start >= 0, said[-3000:]
    end = said.find(REMEDY, start)
    assert end >= 0, said[start : start + 3000]
    return said[start : end + len(REMEDY)]


@pytest.fixture(scope="module")
def ignored_scan(tmp_path_factory):
    base = tmp_path_factory.mktemp("nothing-to-scan")
    source = _tree(base / "src")
    output = base / "out"
    result = _scan(base, source, output)
    return base, source, output, result


def test_a_scan_whose_config_ignores_every_file_exits_1_and_says_why(ignored_scan):
    _, _, output, result = ignored_scan
    said = _said(result)

    assert result.returncode == 1, said[-3000:]
    results = json.loads((output / "ash_aggregated_results.json").read_text())
    assert results["scanner_results"]["detect-secrets"]["status"] == "SKIPPED"
    sentence = _sentence(said)
    assert "detect-secrets" in sentence
    assert "ignore_paths" in sentence
    assert "'**'" in sentence
    assert "narrow it" in sentence
    assert "Scan ran no scanners" not in said


def test_the_gate_switched_off_exits_0(tmp_path):
    source = _tree(tmp_path / "src")

    result = _scan(tmp_path, source, tmp_path / "out", REMEDY)

    assert result.returncode == 0, _said(result)[-3000:]


def test_a_merge_of_shards_with_nothing_to_scan_says_the_same(tmp_path):
    source = _tree(tmp_path / "src")
    for index in range(2):
        shard = _scan(
            tmp_path,
            source,
            tmp_path / f"shard-{index}",
            "--shard-index",
            str(index),
            "--shard-count",
            "2",
        )
        assert shard.returncode == 0, _said(shard)[-3000:]

    merged = _ash(
        tmp_path,
        source,
        "merge",
        "--results",
        str(tmp_path / "shard-0"),
        "--results",
        str(tmp_path / "shard-1"),
        "--output-dir",
        str(tmp_path / "merged"),
    )
    said = _said(merged)

    assert merged.returncode == 1, said[-3000:]
    sentence = _sentence(said)
    assert "detect-secrets" in sentence
    assert "ignore_paths" in sentence
    assert "Scan ran no scanners" not in said


# ---------------------------------------------------------------------------
# The two functions the message is built from, on that scan's own results
# ---------------------------------------------------------------------------


def _results(output: Path) -> dict:
    return json.loads((output / "ash_aggregated_results.json").read_text())


def test_only_the_scanner_that_had_nothing_to_scan_is_named(ignored_scan):
    _, _, output, _ = ignored_scan
    results = AshAggregatedResults.model_validate(_results(output))

    # The nine scanners that were not selected are SKIPPED too, with no count.
    assert run_ash_scan.scanners_with_nothing_to_scan(results) == ["detect-secrets"]


def test_without_ignore_paths_the_message_does_not_name_them(ignored_scan):
    _, _, output, _ = ignored_scan
    data = _results(output)
    data["ash_config"]["global_settings"]["ignore_paths"] = []
    results = AshAggregatedResults.model_validate(data)

    message = run_ash_scan.nothing_to_scan_message(results, ["detect-secrets"])

    assert message.startswith(NOTHING_TO_SCAN)
    assert "ignore_paths" not in message
    assert REMEDY in message


def test_a_pattern_is_shown_inert(ignored_scan):
    """ignore_paths comes from a config that may be the scanned tree's own."""
    _, _, output, _ = ignored_scan
    data = _results(output)
    data["ash_config"]["global_settings"]["ignore_paths"] = [
        {"path": "a\x1b[31mb", "reason": "r"}
    ]
    results = AshAggregatedResults.model_validate(data)

    message = run_ash_scan.nothing_to_scan_message(results, ["detect-secrets"])

    assert "\x1b" not in message
    assert "\\x1b" in message


def test_a_skipped_scanner_with_no_count_is_not_called_empty(ignored_scan):
    """Not selected, or declined on this platform: it made no claim about files."""
    _, _, output, _ = ignored_scan
    data = _results(output)
    for report in (
        (data.get("additional_reports") or {}).get("detect-secrets", {}).values()
    ):
        if isinstance(report, dict):
            report.pop("targets_attempted", None)
    results = AshAggregatedResults.model_validate(data)

    assert run_ash_scan.scanners_with_nothing_to_scan(results) == []
