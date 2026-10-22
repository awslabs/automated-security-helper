# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A container run keeps two records, and each is taken and dropped in its order.

The run records the container it starts, so a later start can remove it if this
process dies first, and it records the file that holds the operator's environment
values, so a die-now ending can remove that. The two share one run step, and each
has its own rule:

* the leftover record exists before the runtime starts, and is dropped when the
  run ends on its own, but stays when an exception ends the run;
* the env file's record is dropped only once the file is gone.

State only, no signal is raised and no runtime is started: the run step is a
stub, the runtime is never called, and the order is read from a log the spies
write.
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path
from typing import List

import pytest

from automated_security_helper.core import cancellation
from automated_security_helper.interactions import container_leftovers
from automated_security_helper.interactions import run_ash_container as rac
from automated_security_helper.interactions.run_ash_container import (
    run_ash_container,
)
from automated_security_helper.utils import subprocess_utils
from automated_security_helper.utils.subprocess_utils import create_completed_process

_CANARY = "ops-canary-qq41"


@pytest.fixture
def events(monkeypatch, tmp_path) -> List[str]:
    """A run that writes the env file, with every step logging when it happens."""
    log: List[str] = []
    dockerfile = tmp_path / "assets" / "Dockerfile"
    dockerfile.parent.mkdir(parents=True)
    dockerfile.write_text("FROM scratch\n", encoding="utf-8")
    state = tmp_path / "ash-state"
    monkeypatch.setenv(container_leftovers.STATE_DIR_ENV, str(state))
    monkeypatch.setattr(cancellation, "_CLEANUP_FILES", ())
    import tempfile

    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path))

    monkeypatch.setattr(subprocess_utils, "get_host_uid", lambda: 4242)
    monkeypatch.setattr(subprocess_utils, "get_host_gid", lambda: 4343)
    monkeypatch.setattr(rac, "_resolve_oci_runner", lambda oci_runner: "docker")
    monkeypatch.setattr(rac, "get_ash_revision", lambda quiet=False: "LOCAL")
    monkeypatch.setattr(rac, "_find_dockerfile", lambda revision: dockerfile)
    monkeypatch.setattr(rac, "_build_image", lambda **kwargs: None)
    monkeypatch.setattr(rac, "_get_oci_wrapper_prefix", lambda: ["env"])
    monkeypatch.setattr(rac, "_host_ash_config", lambda: None)
    monkeypatch.setattr(
        rac, "operator_environment_names", lambda *args: ["ZZ_OPERATOR_VALUE"]
    )
    monkeypatch.setenv("ZZ_OPERATOR_VALUE", _CANARY)
    monkeypatch.setattr(
        rac,
        "_assemble_run_command",
        lambda **kwargs: ["docker", "run", "--rm", kwargs["image_name"]],
    )

    real_write = rac._write_env_file
    real_record = rac.record_container
    real_discard = rac.discard_record
    real_rmtree = rac.shutil.rmtree
    real_discard_env = cancellation.discard_die_now_cleanup

    def write(*args, **kwargs):
        result = real_write(*args, **kwargs)
        log.append("env-file-written")
        return result

    def record(name, *args, **kwargs):
        log.append("leftover-recorded")
        return real_record(name, *args, **kwargs)

    def discard(path):
        log.append("leftover-discarded")
        return real_discard(path)

    def rmtree(path, *args, **kwargs):
        real_rmtree(path, *args, **kwargs)
        if "ash-container-env-" in str(path):
            log.append("env-file-removed")

    def discard_env(path):
        log.append(
            "env-record-discarded"
            + ("" if not os.path.exists(path) else "-WHILE-THE-FILE-EXISTS")
        )
        return real_discard_env(path)

    monkeypatch.setattr(rac, "_write_env_file", write)
    monkeypatch.setattr(rac, "record_container", record)
    monkeypatch.setattr(rac, "discard_record", discard)
    monkeypatch.setattr(rac.shutil, "rmtree", rmtree)
    monkeypatch.setattr(cancellation, "discard_die_now_cleanup", discard_env)
    for name in ("CI", "IsCI", "ISCI", "CODEBUILD_BUILD_ID", "ASH_IMAGE_NAME"):
        monkeypatch.delenv(name, raising=False)
    return log


def _records(tmp_path: Path) -> List[str]:
    state = tmp_path / "ash-state"
    return (
        sorted(p.name for p in state.glob("ash-scan-*.json")) if state.exists() else []
    )


def test_a_run_that_ends_on_its_own_takes_and_drops_both_records_in_order(
    events, tmp_path, monkeypatch
):
    seen: dict = {}

    def execute(cmd, debug=False):
        events.append("run")
        seen["leftover_records"] = _records(tmp_path)
        seen["env_records"] = tuple(cancellation._CLEANUP_FILES)
        return create_completed_process(args=list(cmd), returncode=0)

    monkeypatch.setattr(rac, "_execute_container", execute)
    source = tmp_path / "src"
    source.mkdir()

    result = run_ash_container(
        source_dir=source, output_dir=tmp_path / "out", build=False, run=True
    )

    assert result.returncode == 0, result
    assert events == [
        "env-file-written",
        "leftover-recorded",
        "run",
        "leftover-discarded",
        "env-file-removed",
        "env-record-discarded",
    ], events
    assert len(seen["leftover_records"]) == 1, seen
    assert len(seen["env_records"]) == 1, seen
    assert _records(tmp_path) == []
    assert cancellation._CLEANUP_FILES == ()


def test_a_run_ended_by_an_exception_keeps_the_leftover_record_and_drops_the_env_file(
    events, tmp_path, monkeypatch
):
    def execute(cmd, debug=False):
        events.append("run")
        raise KeyboardInterrupt

    monkeypatch.setattr(rac, "_execute_container", execute)
    source = tmp_path / "src"
    source.mkdir()

    with pytest.raises(KeyboardInterrupt):
        run_ash_container(
            source_dir=source, output_dir=tmp_path / "out", build=False, run=True
        )

    assert events == [
        "env-file-written",
        "leftover-recorded",
        "run",
        "env-file-removed",
        "env-record-discarded",
    ], events
    assert len(_records(tmp_path)) == 1, (
        "the interrupted run's container is not recorded"
    )
    assert cancellation._CLEANUP_FILES == ()
    leftovers = [
        entry
        for entry in tmp_path.glob("ash-container-env-*")
        if (entry / "container.env").exists()
    ]
    assert leftovers == [], "the env file outlived the run"


def test_the_env_files_record_is_kept_while_its_removal_fails(
    events, tmp_path, monkeypatch
):
    """The rule the combined run must not loosen: with the removal failing
    silently, the file is still there, so its record stays."""

    def execute(cmd, debug=False):
        return create_completed_process(args=list(cmd), returncode=0)

    monkeypatch.setattr(rac, "_execute_container", execute)
    real_rmtree = shutil.rmtree
    removals: list = []
    monkeypatch.setattr(
        rac.shutil, "rmtree", lambda *args, **kwargs: removals.append(args)
    )
    source = tmp_path / "src"
    source.mkdir()

    try:
        run_ash_container(
            source_dir=source, output_dir=tmp_path / "out", build=False, run=True
        )
        assert len(cancellation._CLEANUP_FILES) == 1
        assert "leftover-discarded" in events
    finally:
        for name in tuple(cancellation._CLEANUP_FILES):
            cancellation.discard_die_now_cleanup(name)
        for call in removals:
            if call:
                real_rmtree(call[0], ignore_errors=True)
