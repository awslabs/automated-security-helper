# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""A merge refused for a plugin module that fails to import writes no merged file.

The merge wrote ``ash_aggregated_results.json`` and then loaded the operator's
plugin modules, so the import refusal (exit 3) left a merged results file on
disk -- one whose ``metadata.plugin_load_errors`` is empty and that says
nothing about the refusal, which a later ``ash report`` would read as a
completed merge. The namespace refusal already fires before the write and its
cells assert no file; the import refusal must agree: refused means nothing was
written, and the refusal must not claim a results file was.

The merge runs in a child, so the broken module's import attempt happens there
and the parent registry is untouched.
"""

import json
import os
import subprocess
import sys
from pathlib import Path

import yaml

from tests.unit.cli.test_merge import build_shards, write_shards
from tests.utils.helpers import importing_this_checkout

BROKEN = "mergebroken_ash_plugins"
DEPENDENCY = "mergebrokendep_for_refusal"


def _refused_merge(tmp_path: Path) -> subprocess.CompletedProcess:
    plugins = tmp_path / "plugins"
    (plugins / BROKEN).mkdir(parents=True)
    (plugins / BROKEN / "__init__.py").write_text(
        f"import {DEPENDENCY}  # noqa: F401\nASH_REPORTERS = []\n", encoding="utf-8"
    )
    config = tmp_path / "operator" / "ash.yaml"
    config.parent.mkdir()
    config.write_text(
        yaml.safe_dump({"ash_plugin_modules": [BROKEN]}), encoding="utf-8"
    )
    argv = [
        sys.executable,
        "-c",
        importing_this_checkout(
            "from automated_security_helper.cli.main import app; app()"
        ),
        "merge",
    ]
    for path in write_shards(tmp_path / "artifacts", build_shards(2)):
        argv += ["--results", path]
    argv += [
        "--output-dir",
        str(tmp_path / "merged"),
        "--no-color",
        "--config",
        str(config),
    ]
    env = {
        key: value for key, value in os.environ.items() if not key.startswith("AWS_")
    }
    env["PYTHONPATH"] = os.pathsep.join(
        part for part in (env.get("PYTHONPATH"), str(plugins)) if part
    )
    collector = tmp_path / "collector"
    collector.mkdir()
    return subprocess.run(
        argv,
        capture_output=True,
        text=True,
        timeout=300,
        cwd=collector,
        env=env,
        check=False,
    )


def test_a_merge_refused_for_an_import_failure_writes_no_merged_file(tmp_path):
    result = _refused_merge(tmp_path)
    output = " ".join((result.stdout + result.stderr).split())

    assert result.returncode == 3, (result.returncode, output[-2000:])
    assert "which failed to import" in output, output[-2000:]
    # Refused means nothing was written: not the merged results file, and not
    # the output directory either, as the namespace refusal leaves neither.
    assert not (tmp_path / "merged").exists(), output[-2000:]
    assert "already written" not in output, output[-2000:]


def test_the_control_merge_writes_the_file(tmp_path):
    """The same shards with no broken module merge to a results file, so the
    absence above is the refusal's doing."""
    argv = [
        sys.executable,
        "-c",
        importing_this_checkout(
            "from automated_security_helper.cli.main import app; app()"
        ),
        "merge",
    ]
    for path in write_shards(tmp_path / "artifacts", build_shards(2)):
        argv += ["--results", path]
    argv += ["--output-dir", str(tmp_path / "merged"), "--no-color"]
    env = {
        key: value for key, value in os.environ.items() if not key.startswith("AWS_")
    }
    collector = tmp_path / "collector"
    collector.mkdir()
    result = subprocess.run(
        argv,
        capture_output=True,
        text=True,
        timeout=300,
        cwd=collector,
        env=env,
        check=False,
    )

    assert result.returncode in (0, 2), (result.returncode, result.stderr[-1500:])
    merged = tmp_path / "merged" / "ash_aggregated_results.json"
    assert merged.is_file()
    json.loads(merged.read_text(encoding="utf-8"))
