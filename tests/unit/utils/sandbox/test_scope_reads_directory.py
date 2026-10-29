# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``scope.reads_directory`` grants one existing directory, as data, for one block.

A sandbox policy grants paths for argv0 and for the programs ``also_runs`` names;
a directory ASH makes for a check (the staged Nix metadata the pre-installed tool
check hands uv as ``--target``) is reached by neither. ``reads_directory`` is the
one way ASH's own code adds a directory to a spawn's reads: the directory as
named, read-only, never executable, for the spawns of the block alone. It takes
one directory per call, with no pattern or expansion, and refuses a path that is
not an existing directory and a filesystem root.

These tests plan spawns under a recording backend and read the policy it was
handed; nothing is run.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from automated_security_helper.utils.sandbox import scope as scope_module
from automated_security_helper.utils.sandbox.backends import SpawnPlan
from automated_security_helper.utils.sandbox.policy import SandboxRequirements

pytestmark = pytest.mark.unit


class _Recorder:
    name = "recorder"

    def __init__(self):
        self.policies = []

    def probe(self):
        return None

    def plan(self, argv, env, policy):
        self.policies.append(policy)
        return SpawnPlan(argv=list(argv), env=dict(env))


@pytest.fixture
def recorded(tmp_path):
    """Plan every spawn under a recording sandbox scope instead of running it."""
    source = tmp_path / "src"
    source.mkdir()
    output = tmp_path / "out"
    output.mkdir()
    recorder = _Recorder()
    scope = scope_module.SandboxScope(
        backend=recorder,
        scanner_name="probe",
        requirements=SandboxRequirements(),
        source_dir=source,
        output_dir=output,
        results_dir=output / "scanners" / "probe",
        scan_target=source,
        offline=True,
    )
    with scope_module.sandbox_scope(scope):
        yield recorder


def _plan(argv):
    """Plan one spawn under the active scope, then release what planning held."""
    plan = scope_module.prepare_spawn(argv, None, None)
    for cleanup in plan.cleanup if plan is not None else []:
        cleanup()


def _real(paths) -> set:
    return {Path(os.path.realpath(p)) for p in paths}


def test_the_directory_is_readable_and_never_executable(recorded, tmp_path):
    staging = tmp_path / "staging"
    staging.mkdir()

    with scope_module.reads_directory(staging):
        _plan(["/bin/true"])

    policy = recorded.policies[-1]
    assert Path(os.path.realpath(staging)) in _real(policy.read_only)
    assert Path(os.path.realpath(staging)) in _real(policy.scan_data)
    assert Path(os.path.realpath(staging)) not in _real(policy.executable)


def test_the_grant_ends_with_the_block(recorded, tmp_path):
    staging = tmp_path / "staging"
    staging.mkdir()

    with scope_module.reads_directory(staging):
        _plan(["/bin/true"])
    _plan(["/bin/true"])

    assert Path(os.path.realpath(staging)) not in _real(recorded.policies[-1].read_only)


def test_a_relative_path_is_taken_from_the_working_directory(
    recorded, tmp_path, monkeypatch
):
    staging = tmp_path / "staging"
    staging.mkdir()
    monkeypatch.chdir(tmp_path)

    with scope_module.reads_directory("staging"):
        _plan(["/bin/true"])

    assert Path(os.path.realpath(staging)) in _real(recorded.policies[-1].read_only)


def test_a_missing_directory_is_refused(tmp_path):
    with pytest.raises(NotADirectoryError):
        with scope_module.reads_directory(tmp_path / "gone"):
            pass  # pragma: no cover - the grant is refused before the block


def test_a_file_is_refused(tmp_path):
    file = tmp_path / "METADATA"
    file.write_text("Name: faketool\n")

    with pytest.raises(NotADirectoryError):
        with scope_module.reads_directory(file):
            pass  # pragma: no cover - the grant is refused before the block


def test_a_pattern_is_a_name_not_a_glob(tmp_path):
    """``*`` names a directory called ``*``; nothing is expanded or matched."""
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()

    with pytest.raises(NotADirectoryError):
        with scope_module.reads_directory(tmp_path / "*"):
            pass  # pragma: no cover - the grant is refused before the block


def test_a_filesystem_root_is_refused():
    with pytest.raises(ValueError):
        with scope_module.reads_directory(Path(Path.cwd().anchor)):
            pass  # pragma: no cover - the grant is refused before the block


def test_a_refused_grant_leaves_nothing_granted(recorded, tmp_path):
    with pytest.raises(NotADirectoryError):
        with scope_module.reads_directory(tmp_path / "gone"):
            pass  # pragma: no cover - the grant is refused before the block
    _plan(["/bin/true"])

    assert Path(os.path.realpath(tmp_path / "gone")) not in _real(
        recorded.policies[-1].read_only
    )
