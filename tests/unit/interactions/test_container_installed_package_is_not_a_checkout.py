# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""An installed ASH is not taken for a clone because of files beside it.

ASH runs from a clone of its repository (revision LOCAL, build the Dockerfile
beside the package) when ``.github``, ``docs``, ``tests``, a ``Dockerfile``,
``pyproject.toml`` and a few more sit next to the package. The same files can sit
beside an installed package too, for example when a project that has them in its
own ``.venv/lib/pythonX.Y/site-packages`` installs ASH into that venv.

A package that pip or uv installed has its distribution's dist-info directory
beside it, and sits in a directory named site-packages or dist-packages; a clone
has neither. Either one means installed, and the markers are not consulted: the
Dockerfile beside the package is not built.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess  # nosec B404 - one test runs a Python child against a copied package
import sys
from pathlib import Path

import pytest

from automated_security_helper.interactions import run_ash_container as rac

ASH_PACKAGE = Path(rac.__file__).resolve().parents[1]
MARKER_DIRS = (".github", "docs", "tests")
MARKER_FILES = (".gitignore", ".dockerignore", "NOTICE", "pyproject.toml")

_CHILD = r"""
import json, os, sys
from pathlib import Path
site, repo, report = sys.argv[1:4]
sys.path.insert(0, site)
os.chdir(repo)
from automated_security_helper.interactions import run_ash_container as rac
from automated_security_helper.utils import subprocess_utils
assert Path(rac.__file__).resolve().is_relative_to(Path(site).resolve())
seen = []
def record(cmd_list, check=True, debug=False, shell=False, env=None):
    seen.append([str(c) for c in cmd_list if c is not None])
    return subprocess_utils.create_completed_process(args=seen[-1], returncode=0)
rac.run_cmd_direct = record
rac._find_runner = lambda name: "/nonexistent/ash-test/docker"
rac._runner_supports_buildx = lambda runner: False
subprocess_utils.get_host_uid = lambda: 1000
subprocess_utils.get_host_gid = lambda: 1000
revision = rac.get_ash_revision()
result = rac.run_ash_container(build=True, run=False)
Path(report).write_text(json.dumps(
    {"revision": revision, "returncode": result.returncode, "commands": seen}))
"""


@pytest.mark.parametrize(
    ("site_name", "dist_info"),
    [
        pytest.param("site-packages", True, id="as-pip-installs-it"),
        pytest.param("site-packages", False, id="no-dist-info"),
        pytest.param("lib", True, id="dist-info-only"),
    ],
)
def test_markers_beside_an_installed_package_do_not_make_it_a_clone(
    site_name, dist_info, tmp_path
):
    repo = tmp_path / "scanned-repo"
    site = repo / ".venv" / "lib" / "python3.12" / site_name
    site.mkdir(parents=True)
    for name in MARKER_DIRS:
        (site / name).mkdir()
    for name in MARKER_FILES:
        (site / name).write_text("x\n")
    beside = site / "Dockerfile"
    beside.write_text("FROM scratch AS non-root\nRUN echo project-dockerfile\n")
    shutil.copytree(
        ASH_PACKAGE,
        site / "automated_security_helper",
        ignore=shutil.ignore_patterns("__pycache__"),
    )
    if dist_info:
        record = site / "automated_security_helper-9.9.9.dist-info"
        record.mkdir()
        (record / "METADATA").write_text(
            "Metadata-Version: 2.1\nName: automated-security-helper\nVersion: 9.9.9\n"
        )
    report = tmp_path / "report.json"
    env = {
        k: v
        for k, v in os.environ.items()
        if k not in ("CI", "OCI_RUNNER", "ASH_IMAGE_NAME", "ASH_CONFIG")
    }

    completed = subprocess.run(  # nosec B603 - fixed interpreter, script built above
        [sys.executable, "-c", _CHILD, str(site), str(repo), str(report)],
        capture_output=True,
        text=True,
        env=env,
        timeout=300,
        check=False,
    )

    assert report.is_file(), completed.stderr[-2000:]
    outcome = json.loads(report.read_text(encoding="utf-8"))
    assert outcome["revision"] != "LOCAL"
    for cmd in outcome["commands"]:
        if cmd[1] == "build":
            assert Path(cmd[cmd.index("--file") + 1]).resolve() != beside.resolve()
            assert Path(cmd[-1]).resolve() != site.resolve()


def test_the_clone_this_suite_runs_from_is_still_one():
    """Control: the developer flow keeps building the checkout."""
    assert rac._is_checkout(rac._checkout_root())
