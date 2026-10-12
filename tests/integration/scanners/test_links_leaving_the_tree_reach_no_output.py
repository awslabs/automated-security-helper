# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A whole offline ``ash scan``: nothing behind a link that leaves the tree is read.

The tree commits links to a ``.py``, a ``.tf`` and a ``Dockerfile`` outside it, each
holding a marker string (and the ``.py`` an AWS-key-shaped string). Measured before
the change, bandit's snippet of the outside ``.py`` reached ash.sarif,
ash_aggregated_results.json, the CSV, flat JSON and GitLab SAST reports and
ash.summary.md. Every scanner installed where the test runs takes part; this checks
every file the scan wrote.

In-tree controls show the scanners ran: ``real.py`` and ``real.tf`` hold what bandit
and checkov report, and ``in_tree_link.py`` is a link to ``real.py``, which is still
scanned.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess  # nosec B404 -- runs this interpreter's ASH on a fixture tree
import sys
import textwrap
from pathlib import Path

import pytest

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        sys.platform == "win32", reason="creating symlinks needs privileges on Windows"
    ),
]

MARKER = "OUTSIDE-CONTENT-7c41"
#: AWS-key-shaped, so detect-secrets reports it wherever it reads it.
OUTSIDE_KEY = "AKIAOUTSIDE7C4100001"

INSECURE_BUCKET = """
resource "aws_s3_bucket" "b" {{
  bucket = "{name}"
  acl    = "public-read"
}}
"""

DRIVER = textwrap.dedent(
    """
    import sys
    from automated_security_helper.cli.main import app

    sys.argv = ["ash", "scan", *sys.argv[1:]]
    app()
    """
)


def _build(base: Path) -> Path:
    outside = base / "outside"
    tree = base / "tree"
    outside.mkdir()
    tree.mkdir()
    (outside / "secret.py").write_text(
        "import subprocess\n"
        f"MARKER = '{MARKER}'\n"
        f"KEY = '{OUTSIDE_KEY}'\n"
        "subprocess.call(MARKER, shell=True)\n",
        encoding="utf-8",
    )
    (outside / "main.tf").write_text(
        INSECURE_BUCKET.format(name=MARKER.lower()), encoding="utf-8"
    )
    (outside / "Dockerfile").write_text(
        f"FROM alpine:3.20\n# {MARKER}\nUSER root\n", encoding="utf-8"
    )

    (tree / "app.py").write_text("print('hello')\n", encoding="utf-8")
    (tree / "real.py").write_text(
        "import subprocess\nsubprocess.call('in-tree', shell=True)\n",
        encoding="utf-8",
    )
    (tree / "real.tf").write_text(
        INSECURE_BUCKET.format(name="in-tree-bucket"), encoding="utf-8"
    )
    (tree / "link_out.py").symlink_to(outside / "secret.py")
    (tree / "infra").mkdir()
    (tree / "infra" / "main.tf").symlink_to(outside / "main.tf")
    (tree / "docker").mkdir()
    (tree / "docker" / "Dockerfile").symlink_to(outside / "Dockerfile")
    (tree / "in_tree_link.py").symlink_to("real.py")
    return tree


def _isolated_env(base: Path) -> dict[str, str]:
    """No cloud credentials, a refusing endpoint, and a home of the test's own."""
    env = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith("AWS_") and key not in ("ASH_CONFIG", "ASH_BIN_PATH")
    }
    home = base / "home"
    home.mkdir()
    env.update(
        {
            "ASH_OFFLINE": "YES",
            "NO_COLOR": "1",
            "COLUMNS": "200",
            "AWS_CONFIG_FILE": os.devnull,
            "AWS_SHARED_CREDENTIALS_FILE": os.devnull,
            "AWS_EC2_METADATA_DISABLED": "true",
            "AWS_ENDPOINT_URL": "http://127.0.0.1:9",
            "AWS_REGION": "us-east-1",
            "HOME": str(home),
            "XDG_CACHE_HOME": str(home / ".cache"),
            "XDG_DATA_HOME": str(home / ".local" / "share"),
            "XDG_CONFIG_HOME": str(home / ".config"),
            "ASH_BIN_PATH": str(home / "ash-bin"),
            "UV_OFFLINE": "1",
        }
    )
    return env


@pytest.fixture(scope="module")
def scan(tmp_path_factory):
    base = tmp_path_factory.mktemp("links-leaving-the-tree")
    tree = _build(base)
    output = base / "out"
    completed = subprocess.run(  # nosec B603 -- fixed argv, the test's own interpreter
        [
            sys.executable,
            "-I",
            "-c",
            DRIVER,
            "--source-dir",
            str(tree),
            "--output-dir",
            str(output),
            "--mode",
            "local",
            "--no-progress",
            "--no-fail-on-findings",
            "--no-fail-on-incomplete-scanners",
        ],
        capture_output=True,
        text=True,
        timeout=1800,
        env=_isolated_env(base),
        cwd=base,
    )
    assert completed.returncode == 0, (
        completed.stdout[-4000:] + completed.stderr[-4000:]
    )
    results = json.loads((output / "ash_aggregated_results.json").read_text())
    return output, results, completed.stdout


def _statuses(results) -> dict[str, str]:
    statuses = {}
    for name, info in (results.get("scanner_results") or {}).items():
        if isinstance(info, dict):
            targets = [v for v in info.values() if isinstance(v, dict)]
            status = info.get("status") or next(
                (t.get("status") for t in targets if t.get("status")), None
            )
            statuses[name] = str(status)
    return statuses


def _uris(output: Path) -> dict[str, set[str]]:
    sarif = json.loads((output / "reports" / "ash.sarif").read_text())
    found: dict[str, set[str]] = {}
    for run in sarif.get("runs", []):
        for result in run.get("results", []) or []:
            tool = (result.get("properties") or {}).get("scanner_name") or ""
            for location in result.get("locations", []) or []:
                uri = location["physicalLocation"]["artifactLocation"].get("uri", "")
                found.setdefault(tool, set()).add(uri)
    return found


def test_no_output_file_holds_anything_from_outside_the_tree(scan):
    output, results, console = scan
    needles = [MARKER, MARKER.lower(), OUTSIDE_KEY]
    holding = {
        str(path.relative_to(output)): [n for n in needles if n.encode() in data]
        for path in output.rglob("*")
        if path.is_file()
        and not path.is_symlink()
        and any(n.encode() in (data := path.read_bytes()) for n in needles)
    }
    assert holding == {}, (holding, _statuses(results))
    assert not any(n in console for n in needles)


@pytest.mark.parametrize(
    "scanner, command, in_tree_uri",
    [
        ("bandit", "bandit", "real.py"),
        ("checkov", "checkov", "real.tf"),
        ("detect-secrets", "detect-secrets", None),
    ],
)
def test_the_measured_readers_ran_and_still_scan_the_tree(
    scan, scanner, command, in_tree_uri
):
    """The control: each ran, and found what is in the tree."""
    if shutil.which(command) is None:
        pytest.skip(f"{command} is not installed here")
    output, results, _ = scan
    status = _statuses(results).get(scanner)
    # FAILED is a scanner that ran and reported findings over the threshold.
    assert status in ("PASSED", "FAILED"), status
    if in_tree_uri is not None:
        assert any(in_tree_uri in uri for uri in _uris(output).get(scanner, set())), (
            _uris(output)
        )


def test_an_in_tree_link_is_still_scanned_by_bandit(scan):
    if shutil.which("bandit") is None:
        pytest.skip("bandit is not installed here")
    output, _, _ = scan
    assert any("in_tree_link.py" in uri for uri in _uris(output).get("bandit", set()))
