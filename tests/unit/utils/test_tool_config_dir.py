# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Where utils/tool_config_dir puts a scanner run's config files and empty
directories, and how it writes them.

tests/unit/config/test_generated_tool_configs_are_outside_the_tree.py runs the
scanners that use it through the scanner executor; these cover the directory's
placement when the temporary directory is inside the scanned tree or is one
another account could change, and the writes.
"""

from __future__ import annotations

import logging
import os
import stat
import subprocess  # nosec B404 - runs this module's own code in a child
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace

import pytest

from automated_security_helper.config.path_trust import in_scanned_tree
from automated_security_helper.utils.tool_config_dir import (
    active_tool_config_dir,
    make_tool_config_directory,
    tool_config_scope,
    write_tool_config,
)


@pytest.fixture(autouse=True)
def _private_umask():
    """The directories the tests make are 0755 whatever the host's umask.

    A umask of 002 would make them group-writable, which the placement rule
    treats as a directory another account could change.
    """
    previous = os.umask(0o022)
    try:
        yield
    finally:
        os.umask(previous)


@pytest.fixture
def tree(tmp_path: Path) -> SimpleNamespace:
    source = tmp_path / "repo"
    (source / ".git").mkdir(parents=True)
    inside = source / ".ash" / "ash_output"
    inside.mkdir(parents=True)
    outside = tmp_path / "out"
    outside.mkdir()
    return SimpleNamespace(source=source, inside=inside, outside=outside)


def _context(source: Path, output: Path) -> SimpleNamespace:
    return SimpleNamespace(source_dir=source, output_dir=output, config=None)


@pytest.fixture
def temp_inside_the_tree(tree, monkeypatch: pytest.MonkeyPatch) -> Path:
    temp = tree.source / "tmp"
    temp.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(temp))
    return temp


@pytest.mark.unit
def test_a_scope_writes_nothing_until_asked(tree) -> None:
    with tool_config_scope(_context(tree.source, tree.inside)):
        assert active_tool_config_dir() is None
    assert active_tool_config_dir() is None


@pytest.mark.unit
def test_files_of_one_run_share_its_directory(tree) -> None:
    with tool_config_scope(_context(tree.source, tree.inside)):
        first = write_tool_config("a.yaml", "{}\n")
        second = write_tool_config("b.ini", "[bandit]\n")
        assert first.parent == second.parent == active_tool_config_dir()
        assert not in_scanned_tree(first, tree.source)
        if os.name != "nt":
            assert [stat.S_IMODE(p.stat().st_mode) for p in (first, second)] == [
                0o600,
                0o600,
            ]
    assert not first.parent.exists()


@pytest.mark.unit
def test_the_same_name_twice_keeps_both_contents(tree) -> None:
    with tool_config_scope(_context(tree.source, tree.inside)):
        first = write_tool_config("x.yaml", "first\n")
        second = write_tool_config("x.yaml", "second\n")
        assert first != second and first.name == second.name == "x.yaml"
        assert first.read_text() == "first\n"
        assert second.read_text() == "second\n"


@pytest.mark.parametrize("name", ["", ".", "..", "a/b.yaml", "../x.yaml"])
@pytest.mark.unit
def test_a_name_that_is_not_a_file_name_is_refused(tree, name: str) -> None:
    with tool_config_scope(_context(tree.source, tree.inside)):
        with pytest.raises(ValueError):
            write_tool_config(name, "{}\n")


@pytest.mark.unit
def test_a_temporary_directory_inside_the_tree_moves_it_to_the_output_directory(
    tree, temp_inside_the_tree: Path
) -> None:
    with tool_config_scope(_context(tree.source, tree.outside)):
        written = write_tool_config("x.yaml", "{}\n")
        assert written.parent.parent == tree.outside
        assert not in_scanned_tree(written, tree.source)
    assert not written.parent.exists()
    assert list(temp_inside_the_tree.iterdir()) == []


@pytest.mark.unit
def test_with_nowhere_outside_the_tree_it_says_so(
    tree, temp_inside_the_tree: Path, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.WARNING):
        with tool_config_scope(_context(tree.source, tree.inside)):
            written = write_tool_config("x.yaml", "{}\n")
            assert written.parent.parent == temp_inside_the_tree
            if os.name != "nt":
                assert (written.parent.stat().st_mode & 0o777) == 0o700
    assert "inside the scanned tree" in caplog.text
    assert not written.parent.exists()
    # Nothing was left behind under the output directory while looking.
    assert list(tree.inside.iterdir()) == []


@pytest.mark.unit
def test_outside_a_scope_each_file_gets_its_own_directory(tree) -> None:
    context = _context(tree.source, tree.inside)
    first = write_tool_config("x.yaml", "{}\n", context=context)
    second = write_tool_config("x.yaml", "{}\n", context=context)
    assert first.parent != second.parent
    assert not in_scanned_tree(first, tree.source)


@pytest.mark.integration
def test_outside_a_scope_the_directory_is_removed_when_the_process_exits(
    tmp_path: Path,
) -> None:
    """A child process writes one with no scope, exits, and leaves nothing behind."""
    import automated_security_helper

    temp = tmp_path / "temp"
    temp.mkdir(mode=0o700)
    source = tmp_path / "repo"
    source.mkdir()
    output = tmp_path / "out"
    output.mkdir()
    script = (
        "import sys\n"
        "from pathlib import Path\n"
        "from types import SimpleNamespace\n"
        "from automated_security_helper.utils.tool_config_dir import write_tool_config\n"
        "context = SimpleNamespace(\n"
        "    source_dir=Path(sys.argv[1]), output_dir=Path(sys.argv[2]), config=None\n"
        ")\n"
        "path = write_tool_config('x.yaml', '{}\\n', context=context)\n"
        "assert path.is_file(), path\n"
        "print(path)\n"
    )
    # The child imports this checkout, whatever the interpreter has installed.
    checkout = Path(automated_security_helper.__file__).resolve().parents[1]
    env = {
        **os.environ,
        "TMPDIR": temp.as_posix(),
        "PYTHONPATH": os.pathsep.join(
            [checkout.as_posix(), *filter(None, [os.environ.get("PYTHONPATH")])]
        ),
    }
    done = subprocess.run(  # nosec B603 - this interpreter, a fixed script
        [sys.executable, "-c", script, source.as_posix(), output.as_posix()],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert done.returncode == 0, done.stderr
    written = Path(done.stdout.strip().splitlines()[-1])
    assert written.parent.parent == temp
    assert not written.parent.exists()
    assert list(temp.iterdir()) == []


@pytest.mark.unit
def test_a_wider_scanned_root_keeps_the_directory_out_of_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """In workspace mode the scanned tree is the workspace, not the project in it."""
    workspace = tmp_path / "workspace"
    source = workspace / "project"
    (source / ".git").mkdir(parents=True)
    temp = workspace / "tmp"
    temp.mkdir(mode=0o700)
    monkeypatch.setattr(tempfile, "tempdir", str(temp))
    output = tmp_path / "out"
    output.mkdir()
    context = SimpleNamespace(
        source_dir=source,
        output_dir=output,
        config=SimpleNamespace(_scanned_root=workspace),
    )
    with tool_config_scope(context):
        written = write_tool_config("x.yaml", "{}\n")
        assert written.parent.parent == output
    assert list(temp.iterdir()) == []


@pytest.mark.unit
def test_without_a_usable_temporary_directory_the_output_directory_is_used(
    tree, monkeypatch: pytest.MonkeyPatch
) -> None:
    def no_temporary_directory() -> str:
        raise FileNotFoundError(2, "No usable temporary directory found")

    monkeypatch.setattr(tempfile, "gettempdir", no_temporary_directory)
    with tool_config_scope(_context(tree.source, tree.outside)):
        written = write_tool_config("x.yaml", "{}\n")
        assert written.parent.parent == tree.outside
    assert not written.parent.exists()


# A directory another local account can change: it could rename the directory ASH
# made there and put its own in its place before the file is written or read.

posix_only = pytest.mark.skipif(os.name == "nt", reason="POSIX modes and owners")

#: Root passes every mode and ownership check the kernel makes by user id, so a
#: refusal that depends on one cannot be provoked when the runner is root.
not_root = pytest.mark.skipif(
    os.name != "nt" and os.geteuid() == 0,
    reason="root ignores file modes and ownership gates",
)


def _temp_dir(monkeypatch: pytest.MonkeyPatch, path: Path, mode: int) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    os.chmod(path, mode)
    monkeypatch.setattr(tempfile, "tempdir", str(path))
    return path


@posix_only
@pytest.mark.unit
def test_a_temporary_directory_others_can_write_is_not_used(
    tree, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    shared = _temp_dir(monkeypatch, tmp_path / "shared", 0o777)
    with tool_config_scope(_context(tree.source, tree.outside)):
        written = write_tool_config("x.yaml", "{}\n")
        assert written.parent.parent == tree.outside
    assert list(shared.iterdir()) == []


@posix_only
@pytest.mark.unit
def test_a_directory_above_it_that_others_can_write_is_not_used_either(
    tree, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _temp_dir(monkeypatch, tmp_path / "shared", 0o777)
    mine = _temp_dir(monkeypatch, tmp_path / "shared" / "mine", 0o700)
    with tool_config_scope(_context(tree.source, tree.outside)):
        written = write_tool_config("x.yaml", "{}\n")
        assert written.parent.parent == tree.outside
    assert list(mine.iterdir()) == []


@posix_only
@pytest.mark.unit
def test_a_sticky_temporary_directory_like_tmp_is_used(
    tree, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sticky = _temp_dir(monkeypatch, tmp_path / "sticky", 0o1777)
    with tool_config_scope(_context(tree.source, tree.outside)):
        written = write_tool_config("x.yaml", "{}\n")
        assert written.parent.parent == sticky
        assert (written.parent.stat().st_mode & 0o777) == 0o700
    assert list(sticky.iterdir()) == []


@posix_only
@pytest.mark.unit
def test_with_only_a_shared_temporary_directory_the_output_directory_is_used(
    tree,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The output directory inside the tree beats a directory another account controls."""
    shared = _temp_dir(monkeypatch, tmp_path / "shared", 0o777)
    with caplog.at_level(logging.WARNING):
        with tool_config_scope(_context(tree.source, tree.inside)):
            written = write_tool_config("x.yaml", "{}\n")
            assert written.parent.parent == tree.inside
    assert "inside the scanned tree" in caplog.text
    assert shared.as_posix() in caplog.text
    assert not written.parent.exists()
    assert list(shared.iterdir()) == []


@posix_only
@pytest.mark.unit
def test_with_no_private_directory_nothing_is_written(
    tree, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    shared = _temp_dir(monkeypatch, tmp_path / "shared", 0o777)
    # A world-writable directory is the input tool_config_scope must refuse.
    os.chmod(tree.outside, 0o777)  # nosec B103
    with tool_config_scope(_context(tree.source, tree.outside)):
        with pytest.raises(OSError, match="TMPDIR") as refused:
            write_tool_config("x.yaml", "{}\n")
        assert active_tool_config_dir() is None
    assert shared.as_posix() in str(refused.value)
    assert tree.outside.as_posix() in str(refused.value)
    assert list(shared.iterdir()) == []
    assert list(tree.outside.iterdir()) == []


@posix_only
@not_root
@pytest.mark.unit
def test_a_directory_another_account_owns_is_not_used(
    tree, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Its owner can rename what is in it whatever its mode says.

    The test account cannot give a directory away, so it is the one that looks
    foreign: with geteuid answering another id, every directory it owns is
    another account's, and neither candidate is used.
    """
    owned = _temp_dir(monkeypatch, tmp_path / "owned", 0o700)
    me = os.geteuid()
    monkeypatch.setattr(os, "geteuid", lambda: me + 1)
    with tool_config_scope(_context(tree.source, tree.outside)):
        with pytest.raises(OSError, match="another account"):
            write_tool_config("x.yaml", "{}\n")
    assert list(owned.iterdir()) == []
    assert list(tree.outside.iterdir()) == []


# What a sandboxed scanner is granted.


def _real(path) -> Path:
    return Path(os.path.realpath(path))


def _policy(tree, results: Path, grant):
    from automated_security_helper.utils.sandbox.policy import (
        SandboxRequirements,
        build_scanner_policy,
    )

    return build_scanner_policy(
        "probe",
        SandboxRequirements(),
        argv0="/bin/sh",
        source_dir=tree.source,
        output_dir=tree.inside,
        results_dir=results,
        scan_target=tree.source,
        cwd=None,
        offline=True,
        network_scanners=None,
        tool_config_dir=grant,
    )


@posix_only
@pytest.mark.unit
def test_the_grant_adds_the_directory_read_only_and_nothing_else(
    tree, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _temp_dir(monkeypatch, tmp_path / "temp", 0o700)
    results = tree.inside / "scanners" / "probe"
    results.mkdir(parents=True)
    with tool_config_scope(_context(tree.source, tree.inside)):
        write_tool_config("x.yaml", "{}\n")
        directory = _real(active_tool_config_dir())
        without = _policy(tree, results, None)
        granted = _policy(tree, results, directory)

    def reals(paths):
        return {_real(p) for p in paths}

    assert reals(granted.read_only) - reals(without.read_only) == {directory}
    assert reals(without.read_only) - reals(granted.read_only) == set()
    # Nothing that holds the directory is readable either: not its parent, not
    # the temporary directory, not anything above them.
    assert not [
        p for p in reals(granted.read_only) if p != directory and p in directory.parents
    ]
    assert reals(granted.writable) == reals(without.writable)
    assert reals(granted.cache) == reals(without.cache)
    assert directory not in reals(granted.executable)
    assert directory in reals(granted.scan_data)


class _RecordingBackend:
    """A sandbox backend that records each spawn's policy and changes nothing."""

    name = "recording"

    def __init__(self) -> None:
        self.policies: list = []

    def plan(self, argv, env, policy):
        from automated_security_helper.utils.sandbox.backends import SpawnPlan

        self.policies.append(policy)
        return SpawnPlan(argv=list(argv), env=dict(env))


@posix_only
@pytest.mark.unit
def test_runs_in_two_threads_each_see_and_are_granted_only_their_own_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Scanner runs share the process. Each run's directory is its thread's alone.

    Both runs write before either looks, and neither ends before both have
    looked, so a lookup that answered with another run's directory, such as the
    one made last, is seen.
    """
    import threading

    from automated_security_helper.utils.sandbox.policy import SandboxRequirements
    from automated_security_helper.utils.sandbox.scope import (
        SandboxScope,
        prepare_spawn,
        sandbox_scope,
    )

    _temp_dir(monkeypatch, tmp_path / "temp", 0o700)
    barrier = threading.Barrier(2, timeout=60)
    seen: dict = {}
    failures: list = []

    def run(name: str) -> None:
        try:
            source = tmp_path / name / "repo"
            (source / ".git").mkdir(parents=True)
            output = tmp_path / name / "out"
            results = output / "scanners" / "probe"
            results.mkdir(parents=True)
            backend = _RecordingBackend()
            scope = SandboxScope(
                backend=backend,  # type: ignore[arg-type]
                scanner_name="probe",
                requirements=SandboxRequirements(),
                source_dir=source,
                output_dir=output,
                results_dir=results,
                scan_target=source,
                offline=True,
            )
            with sandbox_scope(scope), tool_config_scope(_context(source, output)):
                written = write_tool_config("x.yaml", "{}\n")
                barrier.wait()
                active = active_tool_config_dir()
                prepare_spawn(["/bin/true"], {"PATH": "/usr/bin:/bin"}, None)
                barrier.wait()
            seen[name] = (written.parent, active, backend.policies[-1])
        except BaseException as e:  # reported below, in the test's own thread
            failures.append(e)
            barrier.abort()

    threads = [threading.Thread(target=run, args=(name,)) for name in ("a", "b")]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=120)
    assert not failures, failures
    (a_dir, a_active, a_policy), (b_dir, b_active, b_policy) = seen["a"], seen["b"]
    assert a_dir != b_dir
    assert (a_active, b_active) == (a_dir, b_dir)
    a_granted = {_real(p) for p in a_policy.read_only}
    b_granted = {_real(p) for p in b_policy.read_only}
    assert _real(a_dir) in a_granted and _real(b_dir) not in a_granted
    assert _real(b_dir) in b_granted and _real(a_dir) not in b_granted


@posix_only
@pytest.mark.unit
def test_each_run_gets_a_new_directory_whose_name_is_not_known_in_advance(
    tree, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A directory made at a name an earlier run used is not taken for a new run's."""
    _temp_dir(monkeypatch, tmp_path / "temp", 0o700)
    context = _context(tree.source, tree.outside)
    made = []
    for _ in range(2):
        with tool_config_scope(context):
            made.append(write_tool_config("x.yaml", "{}\n").parent)
        assert not made[-1].exists()
    assert made[0] != made[1]

    # Something else makes a directory at the second run's name, with a file in it.
    planted = made[1]
    planted.mkdir()
    (planted / "x.yaml").write_text("planted\n", encoding="utf-8")
    with tool_config_scope(context):
        third = write_tool_config("x.yaml", "{}\n")
        assert planted not in third.parents
        assert third.read_text(encoding="utf-8") == "{}\n"
    assert (planted / "x.yaml").read_text(encoding="utf-8") == "planted\n"
    assert sorted(path.name for path in planted.iterdir()) == ["x.yaml"]


@pytest.mark.unit
def test_an_empty_directory_shares_the_runs_directory_and_goes_with_it(tree) -> None:
    with tool_config_scope(_context(tree.source, tree.inside)):
        config = write_tool_config("trivy-config.yaml", "")
        modules = make_tool_config_directory("trivy-modules")
        assert modules.is_dir() and list(modules.iterdir()) == []
        assert modules.parent == config.parent == active_tool_config_dir()
        assert not in_scanned_tree(modules, tree.source)
        if os.name != "nt":
            assert (modules.stat().st_mode & 0o777) == 0o700
    assert not modules.exists()
    assert not modules.parent.exists()


@pytest.mark.unit
def test_the_same_directory_name_twice_gives_two_empty_directories(tree) -> None:
    with tool_config_scope(_context(tree.source, tree.inside)):
        first = make_tool_config_directory("trivy-modules")
        (first / "left.wasm").write_bytes(b"\0asm")
        second = make_tool_config_directory("trivy-modules")
        assert first != second and first.name == second.name == "trivy-modules"
        assert list(second.iterdir()) == []


@pytest.mark.parametrize("name", ["", ".", "..", "a/b", "../x"])
@pytest.mark.unit
def test_a_directory_name_that_is_not_a_name_is_refused(tree, name: str) -> None:
    with tool_config_scope(_context(tree.source, tree.inside)):
        with pytest.raises(ValueError):
            make_tool_config_directory(name)
