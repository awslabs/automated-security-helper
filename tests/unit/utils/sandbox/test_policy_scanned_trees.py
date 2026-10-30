# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The policy takes every root of the active scan as the repository's data.

A scan opens a tree scope for the directory it scans
(``subprocess_utils.scanning_tree``), and every tool lookup in it refuses a copy
found inside that tree. The sandbox policy knew only ``source_dir`` and
``output_dir`` as the repository's: an import entry of ASH's interpreter inside
another root of the scan stayed executable, a tool given a staged copy could still
read that root, and a backend that limits where programs run from (sandbox-exec)
was not told to deny it. ``build_scanner_policy`` now takes the scan's roots, and
the scope passes the ones it was built under.

These tests read the built policy and the plan a recording backend was handed;
nothing is run.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from automated_security_helper.utils import subprocess_utils
from automated_security_helper.utils.sandbox import policy as policy_module
from automated_security_helper.utils.sandbox import scope as scope_module
from automated_security_helper.utils.sandbox.backends import SpawnPlan
from automated_security_helper.utils.sandbox.policy import (
    SandboxRequirements,
    build_scanner_policy,
)

pytestmark = pytest.mark.unit


def _real(paths) -> set:
    return {Path(os.path.realpath(p)) for p in paths}


@pytest.fixture
def trees(tmp_path: Path):
    """A scanned source tree, its output directory, and a second scanned root."""
    source = tmp_path / "src"
    source.mkdir()
    output = tmp_path / "out"
    output.mkdir()
    other = tmp_path / "other-root"
    other.mkdir()
    return source, output, other


def _policy(source: Path, output: Path, requirements=None, **kwargs):
    return build_scanner_policy(
        "probe",
        requirements or SandboxRequirements(),
        argv0="/bin/true",
        source_dir=source,
        output_dir=output,
        results_dir=output / "results",
        scan_target=None,
        cwd=None,
        offline=True,
        network_scanners=None,
        **kwargs,
    )


def test_a_scanned_root_is_data_and_not_a_read_grant(trees):
    """The root joins scan_data; nothing is granted for it."""
    source, output, other = trees

    built = _policy(source, output, scanned_trees=(other,))

    assert Path(os.path.realpath(other)) in _real(built.scan_data)
    assert Path(os.path.realpath(other)) not in _real(built.read_only)
    assert Path(os.path.realpath(other)) not in _real(built.executable)


def test_an_import_entry_in_a_scanned_root_is_read_as_source(trees, monkeypatch):
    """An import entry of ASH's interpreter inside a scanned root is not executable.

    ``executable`` is read by sandbox-exec, the one backend that restricts exec.
    """
    source, output, other = trees
    entry = other / "lib"
    entry.mkdir()
    monkeypatch.setattr(policy_module, "_ash_paths", lambda: ([entry], [entry]))

    built = _policy(source, output, scanned_trees=(other,))

    assert Path(os.path.realpath(entry)) in _real(built.read_only)
    assert Path(os.path.realpath(entry)) not in _real(built.executable)


def test_an_import_entry_outside_every_tree_stays_executable(trees, monkeypatch):
    """The control: the same entry elsewhere is ASH's own and stays runnable."""
    source, output, other = trees
    elsewhere = other.parent / "ash-lib"
    elsewhere.mkdir()
    monkeypatch.setattr(policy_module, "_ash_paths", lambda: ([elsewhere], [elsewhere]))

    built = _policy(source, output, scanned_trees=(other,))

    assert Path(os.path.realpath(elsewhere)) in _real(built.executable)


def test_a_staged_tool_does_not_read_a_scanned_root(trees):
    """With a staged copy, every scanned root is unread, like the source tree."""
    source, output, other = trees

    built = _policy(
        source,
        output,
        SandboxRequirements(staged_input_only=True),
        scanned_trees=(other,),
    )

    unread = _real(built.unread)
    assert Path(os.path.realpath(source)) in unread
    assert Path(os.path.realpath(other)) in unread


def test_a_missing_root_is_left_out(trees):
    """A root that no longer exists adds nothing to the policy."""
    source, output, other = trees
    gone = other / "gone"

    built = _policy(source, output, scanned_trees=(gone,))

    assert Path(os.path.realpath(gone)) not in _real(built.scan_data)


class _Recorder:
    name = "recorder"

    def __init__(self):
        self.policies = []

    def probe(self):
        return None

    def plan(self, argv, env, policy):
        self.policies.append(policy)
        return SpawnPlan(argv=list(argv), env=dict(env))


def _scope(recorder, source: Path, output: Path) -> scope_module.SandboxScope:
    return scope_module.SandboxScope(
        backend=recorder,
        scanner_name="probe",
        requirements=SandboxRequirements(),
        source_dir=source,
        output_dir=output,
        results_dir=output / "scanners" / "probe",
        scan_target=source,
        offline=True,
    )


def test_a_scope_built_in_a_scan_carries_its_roots(trees):
    """SandboxScope reads the active scan's roots when it is built."""
    source, output, other = trees

    with subprocess_utils.scanning_tree(other):
        scope = _scope(_Recorder(), source, output)

    assert _real(scope.scanned_trees) == {Path(os.path.realpath(other))}
    assert _scope(_Recorder(), source, output).scanned_trees == ()


def test_the_scope_factory_carries_the_scans_roots(trees, monkeypatch):
    """scanner_sandbox_scope, the production constructor, reads the active roots.

    A nested tree scope adds its root to the enclosing one's, so a scope built
    under both carries both. The backend is a recorder; nothing is probed.
    """
    from types import SimpleNamespace

    from automated_security_helper.config.ash_config import AshConfig, SandboxConfig

    source, output, other = trees
    monkeypatch.setattr(scope_module, "resolve_backend", lambda mode: _Recorder())
    context = SimpleNamespace(
        config=AshConfig(sandbox=SandboxConfig(mode="bwrap")),
        source_dir=source,
        output_dir=output,
    )
    plugin = SimpleNamespace(
        config=SimpleNamespace(name="probe"),
        sandbox_requirements=SandboxRequirements(),
        results_dir=None,
    )

    with subprocess_utils.scanning_tree(source), subprocess_utils.scanning_tree(other):
        scope = scope_module.scanner_sandbox_scope(plugin, context, source)

    assert scope is not None
    assert _real(scope.scanned_trees) == {
        Path(os.path.realpath(source)),
        Path(os.path.realpath(other)),
    }


def test_the_plan_is_built_with_the_scopes_roots(trees):
    """_plan_spawn passes the scope's roots, so the backend's policy has them."""
    source, output, other = trees
    recorder = _Recorder()
    with subprocess_utils.scanning_tree(other):
        scope = _scope(recorder, source, output)

    with scope_module.sandbox_scope(scope):
        plan = scope_module.prepare_spawn(["/bin/true"], None, None)
    for cleanup in plan.cleanup if plan is not None else []:
        cleanup()

    assert Path(os.path.realpath(other)) in _real(recorder.policies[-1].scan_data)
    assert Path(os.path.realpath(other)) not in _real(recorder.policies[-1].read_only)
