# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The container env file is on the die-now cleanup record while it exists.

The env file holds the operator's environment values (mode 0600, a private
temp directory), and the run's ``finally`` removes it however the run ends.
Both die-now endings re-raise under SIG_DFL, so that ``finally`` never
runs; for exactly this the cancellation layer keeps a cleanup-file record
the handlers walk before the default kill. The record only helps if
production writes it: the file must be recorded from before its bytes
exist until the ``finally`` removes it, and a write that fails discards
the record only once the file is really gone -- a removal that fails
silently keeps the record, since the record is all that is left to
remove the file.

State only, no signal is raised: the cells read the record where the die-now
walk would, ``cancellation._CLEANUP_FILES``, with the run step's execution
stubbed at the moment the file is live.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from automated_security_helper.core import cancellation
from automated_security_helper.interactions import run_ash_container as rac
from automated_security_helper.interactions.run_ash_container import (
    ContainerInputError,
    run_ash_container,
)
from automated_security_helper.utils import subprocess_utils
from automated_security_helper.utils.subprocess_utils import create_completed_process

pytestmark = pytest.mark.unit

#: The value the planted variable carries; a leak guard for the harness.
_CANARY = "ops-canary-xy77"


@pytest.fixture
def fresh_cleanup_record(monkeypatch):
    monkeypatch.setattr(cancellation, "_CLEANUP_FILES", ())


@pytest.fixture
def scoped_tempdir(tmp_path, monkeypatch):
    """The writer's temp directory, scoped to the cell.

    ``_write_env_file`` makes its directory with ``tempfile.mkdtemp`` and no
    ``dir`` argument, which lands in the process-wide temp directory: a cell
    whose cleanup regresses would strand its directory where a sibling's
    leftovers scan reads, so each cell writes under its own ``tmp_path`` and
    the scan reads exactly there."""
    import tempfile

    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path))
    return tmp_path


@pytest.fixture
def run_reaches_the_env_file(monkeypatch):
    """Every collaborator that would reach an OCI runtime, stubbed, with the
    wrapper prefix and one operator-read name present so the run step writes
    the env file. Returns the dict the execution stub fills."""
    seen = {}

    monkeypatch.setattr(subprocess_utils, "get_host_uid", lambda: 4242)
    monkeypatch.setattr(subprocess_utils, "get_host_gid", lambda: 4343)
    monkeypatch.setattr(rac, "_resolve_oci_runner", lambda oci_runner: "docker")
    monkeypatch.setattr(rac, "get_ash_revision", lambda quiet=False: "LOCAL")
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

    def fake_execute(cmd, debug=False, env=None):
        # The moment the die-now walk would run: the file is written and
        # the runtime is (as far as the launcher knows) live.
        seen["recorded"] = tuple(cancellation._CLEANUP_FILES)
        seen["existing"] = [path for path in seen["recorded"] if os.path.exists(path)]
        return create_completed_process(args=list(cmd), returncode=0)

    monkeypatch.setattr(rac, "_execute_container", fake_execute)
    for name in ("CI", "IsCI", "ISCI", "CODEBUILD_BUILD_ID", "ASH_IMAGE_NAME"):
        monkeypatch.delenv(name, raising=False)
    return seen


def test_the_env_file_is_recorded_while_the_run_is_live(
    fresh_cleanup_record, run_reaches_the_env_file, tmp_path
):
    source = tmp_path / "src"
    source.mkdir()
    output = tmp_path / "out"
    seen = run_reaches_the_env_file

    result = run_ash_container(
        source_dir=source, output_dir=output, build=False, run=True
    )

    assert result.returncode == 0, result
    assert seen, "the execution stub never ran"
    recorded = seen["recorded"]
    assert len(recorded) == 1 and recorded[0].endswith("container.env"), (
        ("the env file was not on the die-now cleanup record while the run was live"),
        recorded,
    )
    assert seen["existing"] == [recorded[0]], (
        "the recorded path was not the written file",
        seen,
    )
    assert cancellation._CLEANUP_FILES == (), (
        "the record outlived the finally that removed the file",
        cancellation._CLEANUP_FILES,
    )
    assert not os.path.exists(recorded[0]), "the finally did not remove the file"


def test_a_successful_write_records_before_its_caller_sees_the_path(
    fresh_cleanup_record, tmp_path
):
    """The writer itself records: there is no window between the file holding
    values and the record existing, whoever calls it."""
    source = tmp_path / "src"
    source.mkdir()
    output = tmp_path / "out"
    output.mkdir()

    directory, path = rac._write_env_file(
        ["ZZ_OPERATOR_VALUE"],
        {"ZZ_OPERATOR_VALUE": _CANARY},
        "docker",
        source,
        output,
    )
    try:
        assert str(path) in cancellation._CLEANUP_FILES, (
            "the written env file is not recorded for the die-now walk",
            cancellation._CLEANUP_FILES,
        )
    finally:
        cancellation.discard_die_now_cleanup(path)
        import shutil

        shutil.rmtree(directory, ignore_errors=True)


def test_a_failed_write_leaves_no_record(
    fresh_cleanup_record, scoped_tempdir, tmp_path
):
    """A value the file cannot carry fails the write after the record would
    be taken: the refusal must discard it with the directory."""
    source = tmp_path / "src"
    source.mkdir()
    output = tmp_path / "out"
    output.mkdir()

    with pytest.raises(ContainerInputError):
        rac._write_env_file(
            ["ZZ_OPERATOR_VALUE"],
            {"ZZ_OPERATOR_VALUE": _CANARY + "\udcff"},
            "docker",
            source,
            output,
        )
    assert cancellation._CLEANUP_FILES == (), (
        "a failed write left its record behind",
        cancellation._CLEANUP_FILES,
    )
    assert list(scoped_tempdir.glob("ash-container-env-*")) == []


def test_a_failed_write_whose_removal_fails_keeps_the_record(
    fresh_cleanup_record, scoped_tempdir, tmp_path, monkeypatch
):
    """The failure arm removes first and discards only once the file is
    gone: a removal that fails silently (its errors are ignored) must not
    strand the values file with nothing recorded to remove it. The first
    variable's line is already in the file when the second's refusal
    raises. State only, no signal is raised: the die-now window itself is
    out of this cell's scope."""
    source = tmp_path / "src"
    source.mkdir()
    output = tmp_path / "out"
    output.mkdir()
    real_rmtree = rac.shutil.rmtree
    removals = []
    monkeypatch.setattr(
        rac.shutil, "rmtree", lambda *args, **kwargs: removals.append(args)
    )

    try:
        with pytest.raises(ContainerInputError):
            rac._write_env_file(
                ["ZZ_FIRST_VALUE", "ZZ_OPERATOR_VALUE"],
                {
                    "ZZ_FIRST_VALUE": _CANARY,
                    "ZZ_OPERATOR_VALUE": _CANARY + "\udcff",
                },
                "docker",
                source,
                output,
            )

        assert removals, "the failure arm never attempted the removal"
        recorded = tuple(cancellation._CLEANUP_FILES)
        assert len(recorded) == 1 and recorded[0].endswith("container.env"), (
            "the stranded values file is no longer on the die-now record",
            recorded,
        )
        assert os.path.exists(recorded[0]), (
            "the recorded path is not the stranded file",
            recorded,
        )
        assert _CANARY in Path(recorded[0]).read_text(errors="replace"), (
            "the stranded file holds no written value, so the cell measured "
            "an empty window"
        )
    finally:
        # The record only resets the global; the removal walks the captured
        # calls, so a regression that empties the record cannot also strand
        # the directory past this cell.
        for name in tuple(cancellation._CLEANUP_FILES):
            cancellation.discard_die_now_cleanup(name)
        for call in removals:
            if call:
                real_rmtree(call[0], ignore_errors=True)


def test_a_run_whose_cleanup_fails_keeps_the_record(
    fresh_cleanup_record,
    scoped_tempdir,
    run_reaches_the_env_file,
    tmp_path,
    monkeypatch,
):
    """The run's finally removes first and discards only once the file is
    gone: a removal that fails silently on the success path must not strand
    the values file with nothing recorded to remove it. State only, no
    signal is raised."""
    source = tmp_path / "src"
    source.mkdir()
    output = tmp_path / "out"
    real_rmtree = rac.shutil.rmtree
    removals = []
    monkeypatch.setattr(
        rac.shutil, "rmtree", lambda *args, **kwargs: removals.append(args)
    )

    try:
        result = run_ash_container(
            source_dir=source, output_dir=output, build=False, run=True
        )
        assert result.returncode == 0, result
        recorded = tuple(cancellation._CLEANUP_FILES)
        assert len(recorded) == 1 and recorded[0].endswith("container.env"), (
            "the stranded values file is no longer on the die-now record",
            recorded,
        )
        assert os.path.exists(recorded[0]), (
            "the recorded path is not the stranded file",
            recorded,
        )
    finally:
        # As in the failure-arm cell: the record only resets the global, and
        # the removal walks the captured calls.
        for name in tuple(cancellation._CLEANUP_FILES):
            cancellation.discard_die_now_cleanup(name)
        for call in removals:
            if call:
                real_rmtree(call[0], ignore_errors=True)


def test_the_record_is_taken_before_the_file_is_created(
    fresh_cleanup_record, scoped_tempdir, tmp_path, monkeypatch
):
    """The record names the path before ``os.open`` can create it, so a die-now
    ending cannot find the file unrecorded, even empty."""
    source = tmp_path / "src"
    source.mkdir()
    output = tmp_path / "out"
    output.mkdir()
    seen = []
    real_open = os.open

    def spy(*args, **kwargs):
        # Replaces os.open for every caller while the cell runs, so it delegates
        # each call and acts only on the env file; monkeypatch undoes it with the cell.
        if str(args[0]).endswith("container.env"):
            seen.append((str(args[0]), tuple(cancellation._CLEANUP_FILES)))
        return real_open(*args, **kwargs)

    monkeypatch.setattr(os, "open", spy)

    with rac._env_file(
        ["ZZ_OPERATOR_VALUE"], {"ZZ_OPERATOR_VALUE": _CANARY}, "docker", source, output
    ) as (_directory, path):
        assert path.exists()

    assert len(seen) == 1, seen
    opened, recorded = seen[0]
    assert opened in recorded, (
        "the file was created before it was on the die-now record",
        seen,
    )


def test_an_exit_between_the_write_and_the_run_removes_the_file_and_the_record(
    fresh_cleanup_record,
    scoped_tempdir,
    run_reaches_the_env_file,
    tmp_path,
    monkeypatch,
):
    """The write is inside the try whose finally cleans up, so an interrupt on
    the next step still reaches it."""
    source = tmp_path / "src"
    source.mkdir()

    def interrupted(**kwargs):
        raise KeyboardInterrupt

    monkeypatch.setattr(rac, "_assemble_run_command", interrupted)

    with pytest.raises(KeyboardInterrupt):
        run_ash_container(
            source_dir=source, output_dir=tmp_path / "out", build=False, run=True
        )

    assert cancellation._CLEANUP_FILES == ()
    assert list(scoped_tempdir.glob("ash-container-env-*")) == []


def test_a_refused_value_leaves_no_file_and_no_record_and_is_not_started(
    fresh_cleanup_record,
    scoped_tempdir,
    run_reaches_the_env_file,
    tmp_path,
    monkeypatch,
):
    """The refusal arm returns from inside the try: the finally has nothing to
    close, and the writer has already cleaned up after itself."""
    source = tmp_path / "src"
    source.mkdir()
    monkeypatch.setenv("ZZ_OPERATOR_VALUE", "a\nb")

    result = run_ash_container(
        source_dir=source, output_dir=tmp_path / "out", build=False, run=True
    )

    assert result.returncode == 3, result
    assert not run_reaches_the_env_file, "the run started after the refusal"
    assert cancellation._CLEANUP_FILES == ()
    assert list(scoped_tempdir.glob("ash-container-env-*")) == []


def test_the_env_file_is_cleaned_up_inside_the_run_not_when_its_scope_is_collected(
    fresh_cleanup_record,
    scoped_tempdir,
    run_reaches_the_env_file,
    tmp_path,
    monkeypatch,
):
    """The scope is closed by the run's own finally. Left unclosed, CPython would
    still run the context manager's exit when the scope is collected, just after
    the run returns, and every after-the-fact check would pass; the stack at the
    discard says which happened."""
    import traceback

    source = tmp_path / "src"
    source.mkdir()
    stacks = []
    real_discard = cancellation.discard_die_now_cleanup

    def spy(path):
        stacks.append([frame.name for frame in traceback.extract_stack()])
        return real_discard(path)

    monkeypatch.setattr(cancellation, "discard_die_now_cleanup", spy)

    run_ash_container(
        source_dir=source, output_dir=tmp_path / "out", build=False, run=True
    )

    assert len(stacks) == 1, stacks
    assert "run_ash_container" in stacks[0], stacks[0]
