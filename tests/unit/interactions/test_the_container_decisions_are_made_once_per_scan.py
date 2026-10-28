# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A container scan decides which config files it hands over once.

The refusals that run ahead of the log and the build judge the operator's
config inputs, and the run command is assembled later from the same scan record
(``run_ash_container.OperatorConfigReads``). Two decisions used to be taken
again at assembly, from the filesystem and the environment as they were by
then: which file ``ASH_CONFIG`` names, and whether that file is the scan's
``--config`` (discovery in the source directory first, the environment's file
only when discovery finds nothing). A file created, deleted or re-pointed
between the judging and the assembly made the command mount and name something
the refusals never judged. The record now carries both answers from the first
ask, so the command follows what was judged.

The choreography is real filesystem and environment mutation between the two
steps, at the seam the test owns: it calls the refusal, changes the world, and
then assembles the command from the same record.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List

import pytest

from automated_security_helper.core.enums import ExecutionPhase, ExecutionStrategy
from automated_security_helper.interactions import run_ash_container as rac
from tests.utils.helpers import stand_in_host_ids


@pytest.fixture(autouse=True)
def _host_ids(monkeypatch):
    stand_in_host_ids(monkeypatch)


@pytest.fixture
def layout(tmp_path, monkeypatch) -> Dict[str, Path]:
    """A source directory, an output directory and an operator directory kept
    outside the source."""
    for name in ("ASH_CONFIG", "ASH_WORKSPACE", "OCI_RUNNER_WRAPPER", "CI"):
        monkeypatch.delenv(name, raising=False)
    source = tmp_path / "src"
    source.mkdir()
    (source / "a.py").write_text("x = 1\n", encoding="utf-8")
    out = tmp_path / "out"
    out.mkdir()
    operator = tmp_path / "operator"
    operator.mkdir()
    return {"source": source, "out": out, "operator": operator}


def _write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def _judge(layout, reads: rac.OperatorConfigReads, config: Path | None = None) -> None:
    refusal = rac.container_input_refusal(
        layout["source"],
        layout["out"],
        None if config is None else str(config),
        None,
        None,
        reads,
    )
    assert refusal is None, refusal


def _assemble(layout, reads: rac.OperatorConfigReads, **overrides: Any) -> List[str]:
    kwargs: Dict[str, Any] = {
        "oci_command_prefix": [],
        "resolved_oci_runner": "/usr/bin/docker",
        "image_name": "automated-security-helper:non-root",
        "source_dir": layout["source"],
        "output_dir": layout["out"],
        "offline": False,
        "debug": False,
        "color": False,
        "quiet": True,
        "progress": False,
        "verbose": False,
        "simple": True,
        "python_based_plugins_only": False,
        "cleanup": False,
        "inspect": False,
        "fail_on_findings": None,
        "phases": [ExecutionPhase.SCAN],
        "scanners": [],
        "exclude_scanners": [],
        "output_formats": [],
        "config": None,
        "config_overrides": [],
        "existing_results": None,
        "ash_plugin_modules": [],
        "strategy": ExecutionStrategy.PARALLEL,
        "ctx": None,
        "reads": reads,
    }
    kwargs.update(overrides)
    return rac._assemble_run_command(**kwargs)


def _mounted_sources(cmd: List[str]) -> List[str]:
    sources = []
    for i, arg in enumerate(cmd[:-1]):
        if arg == "--mount":
            fields = dict(part.partition("=")[::2] for part in cmd[i + 1].split(","))
            sources.append(fields.get("source", ""))
    return sources


def _config_flags(cmd: List[str]) -> List[str]:
    return [cmd[i + 1] for i, arg in enumerate(cmd[:-1]) if arg == "--config"]


def test_a_config_discovered_when_judged_stays_the_scans_config(layout, monkeypatch):
    env_config = _write(layout["operator"] / "env.yaml", "project_name: env\n")
    monkeypatch.setenv("ASH_CONFIG", str(env_config))
    discovered = _write(
        layout["source"] / ".ash" / ".ash.yaml", "project_name: found\n"
    )
    reads = rac.OperatorConfigReads()
    _judge(layout, reads)

    discovered.unlink()
    cmd = _assemble(layout, reads)

    assert _config_flags(cmd) == [], (
        "discovery found a config when the inputs were judged, so the "
        f"environment's file is the base only; command: {cmd}"
    )
    assert "--ash-config-from-host" in cmd, cmd


def test_a_config_not_discovered_when_judged_leaves_the_environments_file_the_scans(
    layout, monkeypatch
):
    env_config = _write(layout["operator"] / "env.yaml", "project_name: env\n")
    monkeypatch.setenv("ASH_CONFIG", str(env_config))
    reads = rac.OperatorConfigReads()
    _judge(layout, reads)

    _write(layout["source"] / ".ash" / ".ash.yaml", "project_name: later\n")
    cmd = _assemble(layout, reads)

    assert _config_flags(cmd) == [
        f"{rac.CONTAINER_ENV_CONFIG_ROOT}/{env_config.name}"
    ], (
        "nothing was discovered when the inputs were judged, so the "
        f"environment's file is the scan's config; command: {cmd}"
    )


def test_the_environment_file_mounted_is_the_one_judged(layout, monkeypatch):
    judged = _write(layout["operator"] / "judged.yaml", "project_name: judged\n")
    swapped_in = _write(layout["operator"] / "other.yaml", "project_name: other\n")
    monkeypatch.setenv("ASH_CONFIG", str(judged))
    reads = rac.OperatorConfigReads()
    _judge(layout, reads)

    monkeypatch.setenv("ASH_CONFIG", str(swapped_in))
    cmd = _assemble(layout, reads)

    sources = _mounted_sources(cmd)
    assert str(judged.resolve()) in sources, cmd
    assert str(swapped_in.resolve()) not in sources, cmd


def test_a_chain_file_repointed_after_judging_leaves_the_judged_files_mounted(
    layout,
):
    """Pins what the record already did: the mounts come from the chain the
    refusals judged, not from a second walk. Red if the assembly re-reads the
    chain from the filesystem instead of using the judged record."""
    base = _write(layout["operator"] / "base.yaml", "project_name: base\n")
    other = _write(layout["operator"] / "other.yaml", "project_name: other\n")
    config = _write(layout["operator"] / "ash.yaml", "extends: base.yaml\n")
    reads = rac.OperatorConfigReads()
    _judge(layout, reads, config)

    config.write_text("extends: other.yaml\n", encoding="utf-8")
    cmd = _assemble(layout, reads, config=str(config))

    sources = _mounted_sources(cmd)
    assert str(base.resolve()) in sources, cmd
    assert str(other.resolve()) not in sources, cmd
