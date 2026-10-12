# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Through ``ash scan``: semgrep, opengrep and bandit report PASSED only after
scanning something.

- Every Python file excluded by the operator's ``exclude`` options: semgrep and
  opengrep scanned none, and are ERROR. bandit, given the same files in its
  ``excluded_paths``, scanned none and is not PASSED either: those files are
  excluded on purpose, so it is SKIPPED.
- A tree with no Python file: bandit is SKIPPED. (semgrep and opengrep scan its
  README with ASH's own rulesets; the unit tests cover their SKIPPED case.)
- A Python file they all scan: each is PASSED or FAILED (FAILED is findings over
  the threshold).

Needs the tools on ``PATH``; each scanner is skipped where it is not installed.
semgrep and opengrep read an offline rule cache the test writes.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess  # nosec B404 -- runs this interpreter's ASH on a fixture tree
import sys
import textwrap
from datetime import datetime, timezone
from pathlib import Path

import pytest

from tests.utils.helpers import importing_this_checkout

pytestmark = [pytest.mark.integration]

SCANNERS = ["semgrep", "opengrep", "bandit"]

RULE = """rules:
  - id: scanned-nothing-shell-true
    languages: [python]
    severity: WARNING
    message: subprocess with shell=True
    pattern: subprocess.call(..., shell=True)
"""

#: The child imports ASH from this checkout (see importing_this_checkout).
DRIVER = importing_this_checkout(
    textwrap.dedent(
        """
        import sys
        from automated_security_helper.cli.main import app

        sys.argv = ["ash", "scan", *sys.argv[1:]]
        app()
        """
    )
)

PY = "import subprocess\nsubprocess.call('x', shell=True)\n"


def _scan(base: Path, files: dict[str, str], config: str | None = None) -> dict:
    tree = base / "tree"
    for rel, text in files.items():
        (tree / rel).parent.mkdir(parents=True, exist_ok=True)
        (tree / rel).write_text(text, encoding="utf-8")
    rules = base / "rules"
    rules.mkdir()
    (rules / "rule.yaml").write_text(RULE, encoding="utf-8")
    (rules / ".ash-rules-fetched-at").write_text(
        datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ") + "\n",
        encoding="utf-8",
    )
    home = base / "home"
    for directory in (".cache", ".config", ".local/share"):
        (home / directory).mkdir(parents=True)
    env = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith("AWS_") and key not in ("ASH_CONFIG", "ASH_BIN_PATH")
    }
    env.update(
        {
            "ASH_OFFLINE": "YES",
            "NO_COLOR": "1",
            "AWS_CONFIG_FILE": os.devnull,
            "AWS_SHARED_CREDENTIALS_FILE": os.devnull,
            "AWS_EC2_METADATA_DISABLED": "true",
            "AWS_ENDPOINT_URL": "http://127.0.0.1:9",
            "HOME": str(home),
            "XDG_CACHE_HOME": str(home / ".cache"),
            "XDG_DATA_HOME": str(home / ".local" / "share"),
            "XDG_CONFIG_HOME": str(home / ".config"),
            "ASH_BIN_PATH": str(home / "ash-bin"),
            "UV_OFFLINE": "1",
            "SEMGREP_RULES_CACHE_DIR": str(rules),
            "OPENGREP_RULES_CACHE_DIR": str(rules),
        }
    )
    argv = [
        sys.executable,
        "-I",
        "-c",
        DRIVER,
        "--source-dir",
        str(tree),
        "--output-dir",
        str(base / "out"),
        "--mode",
        "local",
        "--no-progress",
        "--no-fail-on-findings",
        "--no-fail-on-incomplete-scanners",
        "--scanners",
        ",".join(SCANNERS),
    ]
    if config is not None:
        config_file = base / "cfg" / ".ash.yaml"
        config_file.parent.mkdir()
        config_file.write_text(config, encoding="utf-8")
        argv += ["--config", str(config_file)]
    completed = subprocess.run(  # nosec B603 -- fixed argv, the test's own interpreter
        argv,
        capture_output=True,
        text=True,
        timeout=1800,
        env=env,
        cwd=base,
    )
    assert completed.returncode == 0, (
        completed.stdout[-4000:] + completed.stderr[-4000:]
    )
    return json.loads((base / "out" / "ash_aggregated_results.json").read_text())


def _status(results: dict, scanner: str) -> str | None:
    info = (results.get("scanner_results") or {}).get(scanner) or {}
    targets = [v for v in info.values() if isinstance(v, dict)]
    status = info.get("status") or next(
        (t.get("status") for t in targets if t.get("status")), None
    )
    return None if status is None else str(status)


EXCLUDE_ALL = """project_name: scanned-nothing
scanners:
  semgrep:
    options:
      exclude: ["*.py"]
  opengrep:
    options:
      exclude: ["*.py"]
  bandit:
    options:
      excluded_paths:
        - path: "pkg"
          reason: "all the Python here"
"""


@pytest.fixture(scope="module")
def everything_excluded(tmp_path_factory):
    return _scan(
        tmp_path_factory.mktemp("excluded"),
        {"pkg/a.py": PY, "pkg/b.py": PY},
        EXCLUDE_ALL,
    )


@pytest.fixture(scope="module")
def nothing_covered(tmp_path_factory):
    return _scan(tmp_path_factory.mktemp("uncovered"), {"README.md": "# hello\n"})


@pytest.fixture(scope="module")
def something_scanned(tmp_path_factory):
    return _scan(tmp_path_factory.mktemp("scanned"), {"app.py": PY})


def _installed(scanner: str) -> None:
    if shutil.which(scanner) is None:
        pytest.skip(f"{scanner} is not installed here")


@pytest.mark.parametrize("scanner", ["semgrep", "opengrep"])
def test_excluding_every_file_is_an_error(everything_excluded, scanner):
    _installed(scanner)
    assert _status(everything_excluded, scanner) == "ERROR"


def test_bandit_with_every_file_excluded_is_not_passed(everything_excluded):
    _installed("bandit")
    assert _status(everything_excluded, "bandit") == "SKIPPED"


def test_bandit_with_no_python_file_is_skipped(nothing_covered):
    """semgrep and opengrep are left out here: ASH's own rulesets, which both are
    given, scan any text file, so they scan the README (measured)."""
    _installed("bandit")
    assert _status(nothing_covered, "bandit") == "SKIPPED"


@pytest.mark.parametrize("scanner", SCANNERS)
def test_a_scanned_file_is_passed_or_failed(something_scanned, scanner):
    _installed(scanner)
    assert _status(something_scanned, scanner) in ("PASSED", "FAILED")
