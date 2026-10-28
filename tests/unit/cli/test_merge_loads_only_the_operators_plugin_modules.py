# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""``ash merge`` imports the plugin modules the operator's ``--config`` names, never one only a shard recorded.

Each shard's results record the configuration its scan ran with, which may come
from a file in the scanned repository. Importing a module is running its code,
so which modules the merge imports is the operator's choice: the modules their
``--config`` names. A module only the shards recorded is not imported, and a
warning names it.

The merge runs in a child, so the only modules imported are the ones the merge
imports itself. The probe module, written into the test's own directory and put
on the child's path, leaves a marker file when it is imported.
"""

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import List, Optional

import yaml

from tests.unit.cli.test_merge import build_shards, write_shards
from tests.utils.helpers import importing_this_checkout

PROBE = "importprobe_ash_plugins"
PROBE_SOURCE = (
    "import os\n"
    "open(os.path.join(os.environ['PROBE_MARKER_DIR'], 'imported'), 'w').close()\n"
    "ASH_REPORTERS = []\n"
)


def _merge(
    tmp_path: Path,
    shard_modules: List[str],
    config_modules: Optional[List[str]] = None,
    extra_env: Optional[dict] = None,
    refused: bool = False,
):
    from automated_security_helper.config.ash_config import AshConfig

    plugins = tmp_path / "plugins"
    (plugins / PROBE).mkdir(parents=True)
    (plugins / PROBE / "__init__.py").write_text(PROBE_SOURCE, encoding="utf-8")
    markers = tmp_path / "markers"
    markers.mkdir()
    shards = build_shards(2)
    for shard in shards:
        shard.ash_config = AshConfig.model_validate(
            {"ash_plugin_modules": shard_modules}
        )
    argv = [
        sys.executable,
        "-c",
        importing_this_checkout(
            "from automated_security_helper.cli.main import app; app()"
        ),
        "merge",
    ]
    for path in write_shards(tmp_path / "artifacts", shards):
        argv += ["--results", path]
    argv += ["--output-dir", str(tmp_path / "merged"), "--no-color"]
    if config_modules is not None:
        config = tmp_path / "operator" / "ash.yaml"
        config.parent.mkdir()
        config.write_text(
            yaml.safe_dump({"ash_plugin_modules": config_modules}), encoding="utf-8"
        )
        argv += ["--config", str(config)]
    env = {
        key: value for key, value in os.environ.items() if not key.startswith("AWS_")
    }
    env["PYTHONPATH"] = os.pathsep.join(
        part for part in (env.get("PYTHONPATH"), str(plugins)) if part
    )
    env["PROBE_MARKER_DIR"] = str(markers)
    env.update(extra_env or {})
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
    assert "Traceback" not in result.stderr, result.stderr[-2000:]
    output = " ".join((result.stdout + result.stderr).split())
    if refused:
        assert result.returncode == 3, (result.returncode, result.stderr[-1500:])
        # Refused before anything was merged: no merged results file on disk.
        assert not (tmp_path / "merged" / "ash_aggregated_results.json").exists()
    else:
        assert result.returncode in (0, 2), (result.returncode, result.stderr[-1500:])
        assert (tmp_path / "merged" / "ash_aggregated_results.json").is_file()
    return (markers / "imported").exists(), output


def test_a_module_only_the_shards_recorded_is_not_imported(tmp_path):
    imported, output = _merge(tmp_path, [PROBE])

    assert not imported, output[-1500:]
    assert "Ignoring ash_plugin_modules" in output and PROBE in output, output[-1500:]


def test_a_module_only_the_shards_recorded_is_not_imported_beside_the_operators(
    tmp_path,
):
    """The operator's --config names a module of its own; the shards' is still left out."""
    imported, output = _merge(
        tmp_path,
        [PROBE],
        ["automated_security_helper.plugin_modules.ash_aws_plugins"],
    )

    assert not imported, output[-1500:]
    assert PROBE in output, output[-1500:]


def test_a_module_the_operators_config_names_is_imported(tmp_path):
    """The control: the same module, named by the operator, is imported."""
    imported, output = _merge(tmp_path, [], [PROBE])

    assert imported, output[-1500:]


def test_the_merged_results_record_the_operators_modules_as_written(tmp_path):
    """The operator's --config reads its module from the environment. The merge
    imports the module it names, and the merged results record the reference
    the file wrote, as a scan's results do, never the value."""
    imported, output = _merge(
        tmp_path,
        [],
        ["${ASH_MODULE_FROM_ENV}"],
        extra_env={"ASH_MODULE_FROM_ENV": PROBE},
    )

    # The control: the variable named the probe, and the merge imported it.
    assert imported, output[-1500:]
    record = json.loads(
        (tmp_path / "merged" / "ash_aggregated_results.json").read_text(
            encoding="utf-8"
        )
    )["ash_config"]
    assert record["ash_plugin_modules"] == ["${ASH_MODULE_FROM_ENV}"], record.get(
        "ash_plugin_modules"
    )


def test_a_module_outside_the_namespace_refuses_the_merge_before_it_writes(tmp_path):
    """The operator's --config names a module outside the plugin namespace: the
    merge refuses with exit 3 before writing the merged results file, so no
    artifact exists for a merge whose refusal says nothing was done."""
    imported, output = _merge(tmp_path, [], ["outside_module"], refused=True)

    assert not imported, output[-1500:]
    assert "is not a plugin module ASH imports" in output, output[-1500:]
    # The merge's own closing words, not the scan's: this command scanned
    # nothing either way, and has no --ash-plugin-modules to remove.
    assert "nothing was merged" in output, output[-1500:]
    assert "nothing was scanned" not in output, output[-1500:]
    assert "--ash-plugin-modules" not in output, output[-1500:]


def test_the_import_log_names_an_env_read_module_masked(tmp_path):
    """The merge's import log line names an env-read entry by its placeholder,
    never by the variable's value. The entry is the probe, importable and
    inside the namespace, so the import happens and its INFO line fires."""
    imported, output = _merge(
        tmp_path,
        [],
        ["${ASH_IMPORT_LOG_MODULE}"],
        extra_env={"ASH_IMPORT_LOG_MODULE": PROBE},
    )

    # The control: the merge did import the module the variable named.
    assert imported, output[-1500:]
    assert f"Importing additional plugin module: {PROBE}" not in output, output[-1500:]
    assert "Importing additional plugin module: <value>" in output, output[-1500:]


def test_the_merge_refusal_names_an_env_read_entry_masked(tmp_path):
    """The merge's refusal names an entry the config read from the environment
    by its placeholder, never by the variable's value: the merge passes its
    shown map into the refusal, and this cell is what notices if it stops."""
    imported, output = _merge(
        tmp_path,
        [],
        ["${ASH_M_PLUGIN}"],
        extra_env={"ASH_M_PLUGIN": "env_named_module"},
        refused=True,
    )

    assert not imported, output[-1500:]
    assert "env_named_module" not in output, output[-1500:]
    assert "<value>" in output, output[-1500:]


def test_a_refused_config_wins_over_unreadable_shards(tmp_path):
    """Both inputs are bad: the module refusal (exit 3) is the answer, not a
    shard error. The check runs on the resolved config before any shard is
    read, so the operator is not sent to fix shards for a merge that will then
    be refused anyway."""
    config = tmp_path / "operator" / "ash.yaml"
    config.parent.mkdir()
    config.write_text(
        yaml.safe_dump({"ash_plugin_modules": ["outside_module"]}), encoding="utf-8"
    )
    collector = tmp_path / "collector"
    collector.mkdir()
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            importing_this_checkout(
                "from automated_security_helper.cli.main import app; app()"
            ),
            "merge",
            "--results",
            str(tmp_path / "missing-results.json"),
            "--output-dir",
            str(tmp_path / "merged"),
            "--no-color",
            "--config",
            str(config),
        ],
        capture_output=True,
        text=True,
        timeout=300,
        cwd=collector,
        env={
            key: value
            for key, value in os.environ.items()
            if not key.startswith("AWS_")
        },
        check=False,
    )

    output = " ".join((result.stdout + result.stderr).split())
    assert result.returncode == 3, (result.returncode, output[-1500:])
    assert "is not a plugin module ASH imports" in output, output[-1500:]


def test_a_module_both_name_is_imported_without_a_warning(tmp_path):
    imported, output = _merge(tmp_path, [PROBE], [PROBE])

    assert imported, output[-1500:]
    assert "Ignoring ash_plugin_modules" not in output, output[-1500:]
