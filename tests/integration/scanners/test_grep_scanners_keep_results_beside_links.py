# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""semgrep and opengrep still scan a project that holds a link named like itself.

The project is a directory inside a git work tree (as a workspace project, or any
``--source-dir`` below a checkout's root, is) and holds ``sub/proj``, a link out of
the tree named like the project directory. ASH used to pass such a link's name in
``--exclude`` when nothing below the target had it. semgrep matches ``--exclude``
against paths below the git work tree's root, so ``proj`` left out the whole
project: 54 results became 0, with semgrep reporting PASSED.

Needs the tool on ``PATH``; each scanner is skipped where it is not installed. The
rules come from an offline rule cache the test writes.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess  # nosec B404 -- runs this interpreter's ASH on a fixture tree
import sys
import textwrap
from datetime import datetime, timezone

import pytest

from tests.utils.git_fixture import run_git

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        sys.platform == "win32", reason="creating symlinks needs privileges on Windows"
    ),
]

RULE = """rules:
  - id: grep-links-shell-true
    languages: [python]
    severity: WARNING
    message: subprocess with shell=True
    pattern: subprocess.call(..., shell=True)
"""

DRIVER = textwrap.dedent(
    """
    import sys
    from automated_security_helper.cli.main import app

    sys.argv = ["ash", "scan", *sys.argv[1:]]
    app()
    """
)


@pytest.fixture(scope="module")
def scan(tmp_path_factory):
    base = tmp_path_factory.mktemp("grep-links")
    repo = base / "repo"
    repo.mkdir()
    run_git("init", "-q", str(repo), check=True)
    project = repo / "proj"
    (project / "sub").mkdir(parents=True)
    (project / "real.py").write_text(
        "import subprocess\nsubprocess.call('in-tree', shell=True)\n", encoding="utf-8"
    )
    (project / "sub" / "proj").symlink_to(base / "elsewhere" / "proj")

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
    output = base / "out"
    completed = subprocess.run(  # nosec B603 -- fixed argv, the test's own interpreter
        [
            sys.executable,
            "-I",
            "-c",
            DRIVER,
            "--source-dir",
            str(project),
            "--output-dir",
            str(output),
            "--mode",
            "local",
            "--no-progress",
            "--no-fail-on-findings",
            "--no-fail-on-incomplete-scanners",
            "--scanners",
            "semgrep,opengrep",
        ],
        capture_output=True,
        text=True,
        timeout=1800,
        env=env,
        cwd=base,
    )
    assert completed.returncode == 0, (
        completed.stdout[-4000:] + completed.stderr[-4000:]
    )
    return output


@pytest.mark.parametrize("scanner", ["semgrep", "opengrep"])
def test_the_scanner_still_reports_the_projects_finding(scan, scanner):
    if shutil.which(scanner) is None:
        pytest.skip(f"{scanner} is not installed here")
    sarif = json.loads((scan / "reports" / "ash.sarif").read_text())
    uris = [
        location["physicalLocation"]["artifactLocation"].get("uri", "")
        for run in sarif.get("runs", [])
        for result in run.get("results") or []
        if (result.get("properties") or {}).get("scanner_name") == scanner
        for location in result.get("locations") or []
    ]
    assert any(uri.endswith("real.py") for uri in uris), uris
