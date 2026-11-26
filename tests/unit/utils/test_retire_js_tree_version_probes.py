# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The version probes of retire.js's package tree read the release the tree holds.

Each package the retire.js tree carries beside retire has a THIRD_PARTY_LICENSES entry
whose ``version_probe`` is node code: it finds ``retire`` on PATH, follows the link
into the installed tree, and prints the ``version`` of that package's own
``package.json``. These tests run that code with the real node on a fake tree laid out
as ``retire_js_install`` lays out the real one. They start a process, so they are the
integration tier, and the unit tests' tool guard is off for them: a stand-in node
cannot say what a package.json holds. The module is in tests/unit/conftest.py's
REAL_TOOL_MODULES for that reason.
"""

from __future__ import annotations

import importlib.util
import json
import os
import shutil
import subprocess  # nosec B404 - runs node on a fake tree, for the table's own probe
from pathlib import Path

import pytest

from automated_security_helper.plugin_modules.ash_retire_js_plugins.retire_js_install import (
    LOCKED_PACKAGES,
    TREE_DIRECTORY,
)
from automated_security_helper.utils.process_env import snapshot_environ
from automated_security_helper.utils.tool_downloads import THIRD_PARTY_LICENSES

pytestmark = [
    pytest.mark.integration,
    pytest.mark.runs_real_tools(
        reason="the version probe is node code, run by the real node on a fake tree"
    ),
    pytest.mark.skipif(
        shutil.which("node") is None or os.name == "nt",
        reason="the probe runs on node, through a link to the tree",
    ),
]

REPO_ROOT = Path(__file__).resolve().parents[3]

#: Every package of the tree, by the name its THIRD_PARTY_LICENSES entry is under.
TREE = {path.split("/", 1)[1]: entry for path, entry in LOCKED_PACKAGES.items()}
#: The packages the tree carries beside retire; each has a probe of its own.
CARRIED = sorted(name for name in TREE if name != "retire")


def _fake_tree(root: Path, versions: "dict[str, str]") -> Path:
    """``<root>/bin/retire`` linked into a tree laid out as the installer lays it."""
    modules = root / "bin" / TREE_DIRECTORY / "node_modules"
    for name, version in versions.items():
        (modules / name).mkdir(parents=True)
        (modules / name / "package.json").write_text(
            json.dumps({"name": name, "version": version})
        )
    cli = modules / "retire" / "lib" / "cli.js"
    cli.parent.mkdir(parents=True, exist_ok=True)
    cli.write_text("#!/usr/bin/env node\n")
    (root / "bin" / "retire").symlink_to(
        f"{TREE_DIRECTORY}/node_modules/retire/lib/cli.js"
    )
    return root / "bin"


def _run_probe(name: str, bin_dir: Path) -> "subprocess.CompletedProcess[str]":
    """The probe, run by node's absolute path with ``bin_dir`` as the whole PATH.

    PATH is only where the probe looks for ``retire``, so nothing else on this
    host's PATH (a ``retire`` installed globally, say) can answer for the fake tree.
    """
    program, flag, code = THIRD_PARTY_LICENSES[name].version_probe
    node = shutil.which(program)
    assert node is not None
    env = {**snapshot_environ(), "PATH": str(bin_dir)}
    return subprocess.run(  # nosec B603 - node, running the table's own probe
        [node, flag, code],
        capture_output=True,
        text=True,
        env=env,
        timeout=60,
        check=False,
    )


def _load_installer():
    spec = importlib.util.spec_from_file_location(
        "_install_pinned_tool_for_retire",
        REPO_ROOT / "automated_security_helper" / "assets" / "install-pinned-tool.py",
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize("name", CARRIED)
def test_the_probe_reads_the_version_the_tree_holds(name, tmp_path):
    installer = _load_installer()
    bin_dir = _fake_tree(tmp_path, {n: TREE[n]["version"] for n in TREE})
    proc = _run_probe(name, bin_dir)
    assert proc.returncode == 0, proc.stderr
    assert installer.reports_version(
        proc.stdout, THIRD_PARTY_LICENSES[name].version.lstrip("v")
    ), proc.stdout


@pytest.mark.parametrize("name", CARRIED)
def test_another_release_in_the_tree_is_not_reported_as_the_pinned_one(name, tmp_path):
    installer = _load_installer()
    versions = {n: TREE[n]["version"] for n in TREE}
    versions[name] = "99.0.0"
    proc = _run_probe(name, _fake_tree(tmp_path, versions))
    assert proc.returncode == 0, proc.stderr
    assert not installer.reports_version(
        proc.stdout, THIRD_PARTY_LICENSES[name].version.lstrip("v")
    ), proc.stdout


@pytest.mark.parametrize("name", CARRIED)
def test_a_package_missing_from_the_tree_fails_the_probe(name, tmp_path):
    versions = {n: TREE[n]["version"] for n in TREE if n != name}
    proc = _run_probe(name, _fake_tree(tmp_path, versions))
    assert proc.returncode != 0, proc.stdout


def test_no_retire_on_path_fails_the_probe(tmp_path):
    empty = tmp_path / "empty"
    empty.mkdir()
    proc = _run_probe("zod", empty)
    assert proc.returncode != 0, proc.stdout
