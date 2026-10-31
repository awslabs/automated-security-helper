# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The sandbox scope's records, refusals, counts and cleanup, read in-process.

A remembered probe refusal keeps no traceback; SandboxBackendUnavailable survives
pickle; a scanner whose config is of another class is refused for that, and one
whose config has no name is named by its declaration; a class scope says its
values are unread and that it is a class scope; an explicit network list that
omits a scanner is said once; a cache-only scanner gets no read_path_scanners
advice and a warning is written once per scanned tree, scanner and setting (a
second tree in the same process gets its own); a converter's offline option is
read from the converters section; the probe directory is removed when the scope
build raises anything; any planning failure is counted on the scope as a failure,
apart from the refusals; a registration that raises runs the plan's cleanup; the sweep is the cleanup's first
step and passes over the plan's private directories; a record that raises releases
each root once; and a DEBUG record names no argv when the plugin's values could not
be read, saying for a class scope that none exist. Nothing runs a backend.
"""

from __future__ import annotations

import copy
import pickle
import tempfile
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from pydantic import BaseModel, Field

from automated_security_helper.base.converter_plugin import ConverterPluginBase
from automated_security_helper.config.ash_config import AshConfig, SandboxConfig
from automated_security_helper.utils import subprocess_utils
from automated_security_helper.utils.sandbox import scope
from automated_security_helper.utils.sandbox.backends import SpawnPlan
from automated_security_helper.utils.sandbox.policy import (
    SandboxRequirements,
    SandboxUnavailable,
)

pytestmark = pytest.mark.unit


class _Cfg(BaseModel):
    name: str = "tool"


class _OtherCfg(BaseModel):
    name: str = "tool"


class _Plugin(BaseModel):
    """A scanner that declares _Cfg as its config class and 'tool' as its name."""

    config: _Cfg = Field(default_factory=_Cfg)
    sandbox_requirements: Any = None
    results_dir: Any = None


class _Recorder:
    name = "recorder"

    def __init__(self):
        self.cleanups: list = []
        self.private_dirs: list = []

    def plan(self, argv, env, policy):
        return SpawnPlan(
            argv=list(argv),
            env=dict(env),
            cleanup=list(self.cleanups),
            private_dirs=list(self.private_dirs),
        )


class _Logger:
    def __init__(self):
        self.lines: list = []

    def isEnabledFor(self, level):
        return True

    def _record(self, level):
        return lambda message, *args, **kwargs: self.lines.append((level, message))

    def __getattr__(self, name):
        if name in ("debug", "info", "warning", "error"):
            return self._record(name)
        raise AttributeError(name)


@pytest.fixture
def fresh(monkeypatch):
    scope.clear_backend_cache()
    monkeypatch.setattr(scope, "resolve_backend", lambda mode: _Recorder())
    monkeypatch.setattr(
        "automated_security_helper.core.constants.is_offline_mode", lambda: False
    )
    yield
    scope.clear_backend_cache()


def _context(tmp_path, **settings):
    config = AshConfig(sandbox=SandboxConfig(mode="bwrap", **settings))
    source = tmp_path / "src"
    source.mkdir(exist_ok=True)
    return SimpleNamespace(
        config=config, source_dir=source, output_dir=tmp_path / "out"
    )


def _scope(tmp_path, backend=None, **fields) -> scope.SandboxScope:
    return scope.SandboxScope(
        backend=backend or _Recorder(),
        scanner_name="scanner",
        requirements=SandboxRequirements(),
        source_dir=tmp_path / "src",
        output_dir=tmp_path / "out",
        results_dir=tmp_path / "out" / "scanner",
        scan_target=None,
        offline=True,
        **fields,
    )


def test_a_remembered_refusal_keeps_no_traceback(monkeypatch):
    """The refusal is kept for the process's life, so its frames must not be: not
    its own traceback, and not the chain behind it. A real probe raises from
    inside an ``except`` (the OSError of a missing binary), so the refusal
    carries a ``__context__`` whose traceback holds the probe's frames; both are
    dropped."""
    scope.clear_backend_cache()

    def probe(name):
        try:
            raise OSError("bwrap: command not found")
        except OSError:
            raise SandboxUnavailable("bwrap is not installed")

    monkeypatch.setattr(scope, "_probe_backend", probe)
    try:
        with pytest.raises(scope.SandboxBackendUnavailable):
            scope.resolve_backend("bwrap")
        (kept,) = list(scope._resolved.values())
        assert isinstance(kept, SandboxUnavailable)
        assert kept.__traceback__ is None
        assert kept.__context__ is None
        assert kept.__cause__ is None
    finally:
        scope.clear_backend_cache()


def test_backend_unavailable_survives_pickle_and_copy():
    error = scope.SandboxBackendUnavailable("no backend works", "auto")
    for rebuilt in (pickle.loads(pickle.dumps(error)), copy.copy(error)):
        assert isinstance(rebuilt, scope.SandboxBackendUnavailable)
        assert rebuilt.mode == "auto"
        assert str(rebuilt) == "no backend works"


def test_a_config_of_another_class_is_refused_for_its_class(fresh, tmp_path):
    plugin = _Plugin.model_construct(config=_OtherCfg())
    with pytest.raises(SandboxUnavailable) as raised:
        scope.scanner_sandbox_scope(plugin, _context(tmp_path), None)
    assert "_OtherCfg" in str(raised.value) and "_Cfg" in str(raised.value)
    assert "but its own name is" not in str(raised.value)


def test_a_nameless_config_reads_as_the_declared_name_not_a_rename(fresh, tmp_path):
    plugin = _Plugin.model_construct(config=_Cfg(name=""))
    built = scope.scanner_sandbox_scope(plugin, _context(tmp_path), None)
    assert built is not None
    assert built.scanner_name == "tool"
    assert built.class_scope is False


def test_a_class_scope_marks_its_values_unread(fresh, tmp_path):
    built = scope.scanner_sandbox_scope(_Plugin, _context(tmp_path), None)
    assert built is not None
    assert built.environment_values_unread is True
    assert built.environment_values == ()
    assert built.class_scope is True


def test_an_explicit_network_list_omitting_the_scanner_is_said_once(
    fresh, tmp_path, monkeypatch
):
    logger = _Logger()
    monkeypatch.setattr(scope, "ASH_LOGGER", logger)
    plugin = _Plugin(sandbox_requirements=SandboxRequirements(network=True))
    context = _context(tmp_path, network_scanners=["other"])
    for _ in range(2):
        scope.scanner_sandbox_scope(plugin, context, None)
    said = [m for level, m in logger.lines if "network" in m and "tool" in m]
    assert len(said) == 1, logger.lines
    assert "withholds" in said[0]


def test_a_withheld_note_is_said_once_per_scanned_tree(fresh, tmp_path, monkeypatch):
    """One process can scan several trees in turn (an MCP server), each under
    its own configuration: a note already written for one tree is written again
    for the next, once, at both sites (the operator's network list at INFO, a
    withheld grant at WARNING); the same tree twice stays one note."""
    logger = _Logger()
    monkeypatch.setattr(scope, "ASH_LOGGER", logger)
    plugin = _Plugin(sandbox_requirements=SandboxRequirements(network=True))
    context = _context(tmp_path, network_scanners=["other"])
    first, second = tmp_path / "first", tmp_path / "second"
    first.mkdir()
    second.mkdir()

    with subprocess_utils.scanning_tree(first):
        for _ in range(2):
            scope.scanner_sandbox_scope(plugin, context, None)
        scope._warn_withheld_once("tool", "network", "withheld for the first tree")
        scope._warn_withheld_once("tool", "network", "withheld for the first tree")
    with subprocess_utils.scanning_tree(second):
        scope.scanner_sandbox_scope(plugin, context, None)
        scope._warn_withheld_once("tool", "network", "withheld for the second tree")

    network_list = [
        (level, m) for level, m in logger.lines if "sandbox.network_scanners" in m
    ]
    assert [level for level, _ in network_list] == ["info", "info"], logger.lines
    withheld = [(level, m) for level, m in logger.lines if m.startswith("withheld")]
    assert withheld == [
        ("warning", "withheld for the first tree"),
        ("warning", "withheld for the second tree"),
    ], logger.lines


def test_a_second_scan_of_the_same_tree_writes_the_withheld_note_again(
    fresh, tmp_path, monkeypatch
):
    """A long-lived MCP server scans one tree again and again: each scan's log
    carries the note its settings earn, and the process keeps none of them."""
    logger = _Logger()
    monkeypatch.setattr(scope, "ASH_LOGGER", logger)
    tree = tmp_path / "tree"
    tree.mkdir()

    for _ in range(2):
        with subprocess_utils.scanning_tree(tree):
            for _ in range(2):
                scope._warn_withheld_once("tool", "network", "withheld for the tree")

    withheld = [m for level, m in logger.lines if m.startswith("withheld")]
    # Red at the base: one note for the process, so the second scan's log had none.
    assert withheld == ["withheld for the tree", "withheld for the tree"]
    assert scope._WARNED_WITHHELD == set()


def test_a_cache_only_scanner_gets_no_read_path_advice_and_advice_comes_once(
    fresh, tmp_path, monkeypatch
):
    logger = _Logger()
    monkeypatch.setattr(scope, "ASH_LOGGER", logger)
    cache_only = _Plugin(
        sandbox_requirements=SandboxRequirements(
            cache_paths=("~/.cache/tool",), read_paths_require_grant=True
        )
    )
    scope.scanner_sandbox_scope(cache_only, _context(tmp_path), None)
    assert not [m for _, m in logger.lines if "read_path_scanners" in m], logger.lines

    reads = _Plugin(
        sandbox_requirements=SandboxRequirements(
            read_paths=("~/rules",), read_paths_require_grant=True
        )
    )
    for _ in range(3):
        scope.scanner_sandbox_scope(reads, _context(tmp_path), None)
    assert len([m for _, m in logger.lines if "read_path_scanners" in m]) == 1


def test_a_converters_offline_option_is_read_from_its_own_section():
    class _Converter(ConverterPluginBase):
        pass

    class _Scanner:
        pass

    asked = []

    def get_plugin_config(plugin_type, plugin_name):
        asked.append(plugin_type)
        return {"options": {"offline": True}}

    context = SimpleNamespace(
        config=SimpleNamespace(get_plugin_config=get_plugin_config)
    )
    assert scope._probe_offline(_Converter, context) is True
    assert scope._probe_offline(_Scanner, context) is True
    assert asked == ["converter", "scanner"]


def test_the_probe_directory_is_removed_when_the_scope_build_raises(
    tmp_path, monkeypatch
):
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(scratch))

    made: list = []

    def exploding(plugin, context, scan_target):
        # The positive control: the probe directory exists when the build fails,
        # so an empty scratch afterwards means it was removed, not never made.
        made.extend(scratch.iterdir())
        raise RuntimeError("not a refusal")

    monkeypatch.setattr(scope, "scanner_sandbox_scope", exploding)
    with pytest.raises(RuntimeError, match="not a refusal"):
        with scope._sandboxed_probe_scope(_Plugin, _context(tmp_path)):
            pass
    assert len(made) == 1 and made[0].name.startswith("ash-sandbox-probe-"), made
    assert list(scratch.iterdir()) == []


def test_any_planning_failure_is_counted_as_a_failure(tmp_path, monkeypatch):
    def failing(sandbox_scope, argv, env, cwd):
        raise RuntimeError("plan exploded")

    monkeypatch.setattr(scope, "_plan_spawn", failing)
    sandbox_scope = _scope(tmp_path)
    with scope.sandbox_scope(sandbox_scope):
        with pytest.raises(RuntimeError):
            scope.prepare_spawn(["tool"], {}, None)
    # Red at the parent: the failure was counted as a refusal (refused_spawns 1,
    # "RuntimeError" in last_refusal), and the converter's row then said the
    # sandbox refused a process it had not.
    assert sandbox_scope.failed_spawns == 1
    assert "RuntimeError" in (sandbox_scope.last_failure or "")
    assert sandbox_scope.refused_spawns == 0
    assert sandbox_scope.last_refusal is None


@pytest.fixture
def planning(monkeypatch):
    monkeypatch.setattr(
        scope,
        "build_scanner_policy",
        lambda *args, **kwargs: SimpleNamespace(network=False, writable=[Path("/w")]),
    )


def test_a_registration_that_raises_runs_the_plans_cleanup(
    tmp_path, planning, monkeypatch
):
    ran = []
    recorder = _Recorder()
    recorder.cleanups = [lambda: ran.append("backend")]

    def refusing(path):
        raise OSError("cannot register")

    monkeypatch.setattr(scope, "register_writable_root", refusing)
    with pytest.raises(OSError, match="cannot register"):
        scope._plan_spawn(_scope(tmp_path, backend=recorder), ["tool"], {}, None)
    assert ran == ["backend"]


def test_the_sweep_runs_first_and_passes_over_the_plans_private_dirs(
    tmp_path, planning, monkeypatch
):
    """The stream-log write relies on the sweep being the cleanup's first step
    (subprocess_utils._write_stream_logs), and the backend's own private cache
    under the results directory, which uv fills with links, is not the scanner's
    to be counted: the plan names it and the sweep is told to pass it over."""
    recorder = _Recorder()
    order: list = []
    recorder.cleanups = [lambda: order.append("backend")]
    recorder.private_dirs = [tmp_path / "out" / "scanner" / ".sandbox-cache-abc"]
    swept: list = []
    monkeypatch.setattr(scope, "register_writable_root", lambda path: Path(path))
    monkeypatch.setattr(
        scope, "release_writable_root", lambda path: order.append("release")
    )

    def recording_sweep(roots, values=(), **kwargs):
        order.append("sweep")
        swept.append((list(roots), kwargs))
        return 0

    monkeypatch.setattr(scope, "sweep_writable", recording_sweep)

    plan = scope._plan_spawn(_scope(tmp_path, backend=recorder), ["tool"], {}, None)
    for step in plan.cleanup:
        step()

    # Each step identified by what it did, in the order it ran: the sweep first,
    # the release of this spawn's roots, the backend's own steps last.
    assert order == ["sweep", "release", "backend"]
    assert swept == [
        ([Path("/w")], {"values_unread": False, "skip": recorder.private_dirs})
    ]


def test_a_record_that_raises_releases_each_root_once(tmp_path, planning, monkeypatch):
    """The release step is already in the plan when the record runs, so the
    failure path lets run_cleanup release the roots and does not release them
    itself as well: a second release would take a registration the scope or the
    output directory still holds on the same root (fs_guard._decrement counts)."""
    ran: list = []
    released: list = []
    recorder = _Recorder()
    recorder.cleanups = [lambda: ran.append("backend")]
    monkeypatch.setattr(scope, "register_writable_root", lambda path: Path(path))
    monkeypatch.setattr(scope, "release_writable_root", released.append)
    monkeypatch.setattr(scope, "sweep_writable", lambda roots, values=(), **kw: 0)

    def exploding(sandbox_scope, policy, plan):
        raise RuntimeError("record exploded")

    monkeypatch.setattr(scope, "_record_plan", exploding)
    with pytest.raises(RuntimeError, match="record exploded"):
        scope._plan_spawn(_scope(tmp_path, backend=recorder), ["tool"], {}, None)

    assert released == [Path("/w")], "each root is released exactly once"
    assert ran == ["backend"]


def test_the_record_names_no_argv_when_the_values_are_unread(
    tmp_path, planning, monkeypatch
):
    logger = _Logger()
    monkeypatch.setattr(scope, "ASH_LOGGER", logger)
    monkeypatch.setattr(scope, "delivers", lambda *args: True)
    monkeypatch.setattr(scope, "register_writable_root", lambda path: Path(path))
    monkeypatch.setattr(scope, "release_writable_root", lambda path: None)
    sandbox_scope = _scope(tmp_path, environment_values_unread=True)

    with scope.sandbox_scope(sandbox_scope):
        scope._plan_spawn(sandbox_scope, ["tool", "--token=the-secret"], {}, None)

    (record,) = [m for level, m in logger.lines if level == "debug"]
    assert "the-secret" not in record
    assert "could not be read" in record
    assert record.startswith("Scanner sandbox (recorder, network=no) for scanner")


def test_the_record_of_a_class_scope_says_it_carries_no_values(
    tmp_path, planning, monkeypatch
):
    """A class scope has no values hook to read, so nothing failed: its record
    says so instead of reporting a read that never happened."""
    logger = _Logger()
    monkeypatch.setattr(scope, "ASH_LOGGER", logger)
    monkeypatch.setattr(scope, "delivers", lambda *args: True)
    monkeypatch.setattr(scope, "register_writable_root", lambda path: Path(path))
    monkeypatch.setattr(scope, "release_writable_root", lambda path: None)
    sandbox_scope = _scope(tmp_path, environment_values_unread=True, class_scope=True)

    with scope.sandbox_scope(sandbox_scope):
        scope._plan_spawn(sandbox_scope, ["tool", "--token=the-secret"], {}, None)

    (record,) = [m for level, m in logger.lines if level == "debug"]
    assert "the-secret" not in record
    assert "carries no redaction values" in record
    assert "could not be read" not in record
