# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The derived roots a scan run records belong to that run.

A configuration can outlive one scan, and can serve two scans at once. Inside a
scan run (``path_trust.derived_roots_scope``) the output, work and workspace
output directories of every plugin context on the configuration are filed under
that run, and a path is judged against the whole record: every run's directories
that have not ended and those recorded outside every run. A path under another
run's output directory is refused like one under the run's own, and a run never
loses a directory it recorded. A run's directories leave the record only when
its scan ends (``forget_derived_roots``).
"""

import os
import sys
import threading
from pathlib import Path

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config import path_trust
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.path_trust import (
    honored_path,
    reset_path_refusal_warnings,
)
from automated_security_helper.core.constants import ASH_WORK_DIR_NAME

pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
def _fresh_warnings():
    reset_path_refusal_warnings()
    yield
    reset_path_refusal_warnings()


@pytest.fixture
def source(tmp_path):
    directory = tmp_path / "repo"
    directory.mkdir()
    return directory


def _output(tmp_path, name):
    """An output directory and a file under its work directory."""
    output = tmp_path / name
    product = output / ASH_WORK_DIR_NAME / "derived.yaml"
    product.parent.mkdir(parents=True)
    product.write_text("")
    return output, product


def _refused(path, source, config):
    return (
        honored_path(path, source_dir=source, key="config_file", config=config) is None
    )


def test_a_later_run_is_refused_under_an_earlier_runs_output_dir(tmp_path, source):
    config = AshConfig()
    first_output, first_product = _output(tmp_path, "first-out")
    second_output, second_product = _output(tmp_path, "second-out")
    with path_trust.derived_roots_scope("first-run"):
        PluginContext(source_dir=source, output_dir=first_output, config=config)
        assert _refused(first_product, source, config)
    with path_trust.derived_roots_scope("second-run"):
        PluginContext(source_dir=source, output_dir=second_output, config=config)
        assert _refused(first_product, source, config)
        assert _refused(second_product, source, config)
    path_trust.forget_derived_roots(config, "first-run")
    with path_trust.derived_roots_scope("second-run"):
        assert not _refused(first_product, source, config)
        assert _refused(second_product, source, config)


def test_inside_one_run_a_path_under_any_context_on_the_config_is_refused(
    tmp_path, source
):
    """The workspace shape: several contexts hold one config in one run, and a
    context's copy can move its output directory."""
    config = AshConfig()
    first_output, first_product = _output(tmp_path, "project-a-out")
    second_output, second_product = _output(tmp_path, "project-b-out")
    moved_output, moved_product = _output(tmp_path, "copied-out")
    workspace_output = tmp_path / "workspace-out"
    other_project = workspace_output / "other-project" / "derived.yaml"
    other_project.parent.mkdir(parents=True)
    other_project.write_text("")
    with path_trust.derived_roots_scope("workspace-run"):
        first = PluginContext(
            source_dir=source,
            output_dir=first_output,
            workspace_output_dir=workspace_output,
            config=config,
        )
        PluginContext(source_dir=source, output_dir=second_output, config=config)
        first.model_copy(update={"output_dir": moved_output})
        for product in (first_product, second_product, moved_product, other_project):
            assert _refused(product, source, config), product


def test_two_runs_at_once_on_one_config_each_refuse_both_runs_paths_throughout(
    tmp_path, source
):
    config = AshConfig()
    first_output, first_product = _output(tmp_path, "first-out")
    second_output, second_product = _output(tmp_path, "second-out")
    first_recorded = threading.Event()
    second_recorded = threading.Event()
    second_finished = threading.Event()
    failures = []

    def check(label, condition):
        if not condition:
            failures.append(label)

    def first_run():
        with path_trust.derived_roots_scope("first-run"):
            PluginContext(source_dir=source, output_dir=first_output, config=config)
            check(
                "first refuses its own before the second starts",
                _refused(first_product, source, config),
            )
            first_recorded.set()
            if not second_recorded.wait(30):
                failures.append("second run never recorded")
                return
            check(
                "first refuses its own while the second runs",
                _refused(first_product, source, config),
            )
            check(
                "first is refused under the second's output",
                _refused(second_product, source, config),
            )
            if not second_finished.wait(30):
                failures.append("second run never finished")
                return
            check(
                "first refuses its own after the second ends",
                _refused(first_product, source, config),
            )

    def second_run():
        if not first_recorded.wait(30):
            failures.append("first run never recorded")
            return
        try:
            with path_trust.derived_roots_scope("second-run"):
                PluginContext(
                    source_dir=source, output_dir=second_output, config=config
                )
                second_recorded.set()
                check(
                    "second refuses its own while the first runs",
                    _refused(second_product, source, config),
                )
                check(
                    "second is refused under the first's output",
                    _refused(first_product, source, config),
                )
        finally:
            second_recorded.set()
            second_finished.set()

    threads = [threading.Thread(target=first_run), threading.Thread(target=second_run)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(60)
    assert not any(thread.is_alive() for thread in threads)
    assert failures == []


def test_with_no_run_in_effect_the_accumulated_union_refuses(tmp_path, source):
    config = AshConfig()
    first_output, first_product = _output(tmp_path, "first-out")
    second_output, second_product = _output(tmp_path, "second-out")
    PluginContext(source_dir=source, output_dir=first_output, config=config)
    PluginContext(source_dir=source, output_dir=second_output, config=config)
    assert _refused(first_product, source, config)
    assert _refused(second_product, source, config)


def test_a_reader_outside_every_run_is_judged_against_every_runs_roots(
    tmp_path, source
):
    """A thread that did not copy its run's context reads with no run in effect;
    it is judged against the whole record, which fails closed."""
    config = AshConfig()
    first_output, first_product = _output(tmp_path, "first-out")
    second_output, second_product = _output(tmp_path, "second-out")
    with path_trust.derived_roots_scope("first-run"):
        PluginContext(source_dir=source, output_dir=first_output, config=config)
    with path_trust.derived_roots_scope("second-run"):
        PluginContext(source_dir=source, output_dir=second_output, config=config)
    assert _refused(first_product, source, config)
    assert _refused(second_product, source, config)


def test_a_context_built_outside_every_run_refuses_inside_a_run(tmp_path, source):
    config = AshConfig()
    output, product = _output(tmp_path, "library-out")
    PluginContext(source_dir=source, output_dir=output, config=config)
    with path_trust.derived_roots_scope("later-run"):
        assert _refused(product, source, config)


def test_a_config_copys_run_roots_stay_its_own(tmp_path, source):
    """``model_copy`` copies the private state shallowly, so the run record is
    replaced on every change, never changed in place."""
    config = AshConfig()
    first_output, _ = _output(tmp_path, "first-out")
    copy_output, copy_product = _output(tmp_path, "copy-out")
    with path_trust.derived_roots_scope("one-run"):
        PluginContext(source_dir=source, output_dir=first_output, config=config)
        copied = config.model_copy()
        PluginContext(source_dir=source, output_dir=copy_output, config=copied)
        assert _refused(copy_product, source, copied)
        assert not _refused(copy_product, source, config)


STORM_THREADS = 8
STORM_CONTEXTS_PER_THREAD = 100


def _storm(tmp_path, source, config, scoped):
    """Build contexts on one config from many threads started together.

    Every thread builds ``STORM_CONTEXTS_PER_THREAD`` contexts, each with its
    own output directory, so each build files new directories on the shared
    record. The thread switch interval is shortened for the storm, so the
    threads interleave inside a read-then-replace if nothing holds them out.
    Returns the (output, work) directories each thread's contexts used.
    """
    directories = {}
    for index in range(STORM_THREADS):
        directories[index] = []
        for count in range(STORM_CONTEXTS_PER_THREAD):
            output = tmp_path / f"thread-{index}" / f"out-{count}"
            work = output / ASH_WORK_DIR_NAME
            work.mkdir(parents=True)
            directories[index].append((output, work))
    start_together = threading.Barrier(STORM_THREADS)
    failures = []

    def build(index):
        try:
            start_together.wait(30)
            for output, work in directories[index]:
                if scoped:
                    with path_trust.derived_roots_scope(f"run-{index}"):
                        PluginContext(
                            source_dir=source,
                            output_dir=output,
                            work_dir=work,
                            config=config,
                        )
                else:
                    PluginContext(
                        source_dir=source,
                        output_dir=output,
                        work_dir=work,
                        config=config,
                    )
        except BaseException as error:  # reported by the test thread
            failures.append(repr(error))

    threads = [
        threading.Thread(target=build, args=(index,)) for index in range(STORM_THREADS)
    ]
    previous_interval = sys.getswitchinterval()
    sys.setswitchinterval(1e-6)
    try:
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(120)
    finally:
        sys.setswitchinterval(previous_interval)
    assert not any(thread.is_alive() for thread in threads)
    assert failures == []
    return directories


def _resolved(path):
    return Path(os.path.realpath(path))


def test_runs_recording_at_once_on_one_config_each_keep_every_root(tmp_path, source):
    """Recording is a read-then-replace of the config's record, held under one
    lock: a run's roots survive other runs recording at the same moment."""
    config = AshConfig()
    directories = _storm(tmp_path, source, config, scoped=True)

    by_run = config._run_derived_roots
    assert sorted(by_run) == sorted(f"run-{index}" for index in range(STORM_THREADS))
    for index, pairs in directories.items():
        recorded = set(by_run[f"run-{index}"])
        for output, work in pairs:
            assert _resolved(output) in recorded, (index, output)
            assert _resolved(work) in recorded, (index, work)


def test_writers_outside_every_run_at_once_keep_every_root(tmp_path, source):
    config = AshConfig()
    directories = _storm(tmp_path, source, config, scoped=False)

    recorded = set(config._derived_roots)
    for index, pairs in directories.items():
        for output, work in pairs:
            assert _resolved(output) in recorded, (index, output)
            assert _resolved(work) in recorded, (index, work)
    assert config._run_derived_roots == {}


class _Warnings:
    """A logger that keeps the warnings and drops every other record."""

    def __init__(self):
        self.messages = []

    def warning(self, message, *args, **kwargs):
        self.messages.append(message)

    def __getattr__(self, name):
        return lambda *args, **kwargs: None


def test_a_later_run_logs_a_refusal_an_earlier_run_already_logged(
    tmp_path, source, monkeypatch
):
    """The warning is once per run: the same option and path refused in a
    second run of one long-lived process (the MCP server) is logged again,
    and refused twice inside one run it is logged once."""
    config = AshConfig()
    output, product = _output(tmp_path, "out")
    logger = _Warnings()
    monkeypatch.setattr(path_trust, "ASH_LOGGER", logger)
    run = ["first-run"]
    monkeypatch.setattr(path_trust, "current_run_log_scope", lambda: run[0])

    def refuse():
        return path_trust.refused_derived_product(
            product,
            source_dir=source,
            key="config_file",
            config=config,
            derived_dirs=[output],
        )

    assert refuse() is True
    assert refuse() is True
    assert len(logger.messages) == 1, logger.messages

    run[0] = "second-run"
    assert refuse() is True
    assert len(logger.messages) == 2, logger.messages
