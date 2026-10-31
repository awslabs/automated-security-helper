# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A timed-out scanner under Landlock leaves no process behind.

Landlock does not end a process's descendants with it, so its wrapper is a child
subreaper that kills what its scanner leaves. On a timeout ASH sends the wrapper
SIGTERM first, and the wrapper ends the whole tree; a SIGKILL would leave it no way
to. Measured here by a detached process that would write a file after the
timeout: the file must never appear.
"""

import os
import time

import pytest

from automated_security_helper.utils.sandbox.backends import LandlockBackend
from automated_security_helper.utils.sandbox.policy import (
    SandboxRequirements,
)
from automated_security_helper.utils.sandbox.scope import SandboxScope, sandbox_scope
from automated_security_helper.utils.subprocess_utils import (
    run_command_with_output_handling,
)

pytestmark = pytest.mark.integration


def _landlock() -> LandlockBackend:
    backend = LandlockBackend()
    reason = backend.probe()
    if reason:
        required = os.environ.get("ASH_REQUIRE_SANDBOX_BACKENDS", "").split(",")
        if "landlock" in [name.strip() for name in required]:
            pytest.fail(f"landlock is required but: {reason}")
        pytest.skip(f"landlock unavailable: {reason}")
    return backend


def test_a_timed_out_scanner_leaves_no_process_behind(tmp_path):
    backend = _landlock()
    source = tmp_path / "src"
    source.mkdir()
    output = tmp_path / "out"
    results = output / "scanners" / "probe"
    results.mkdir(parents=True)
    late = results / "late.txt"
    scope = SandboxScope(
        backend=backend,
        scanner_name="probe",
        requirements=SandboxRequirements(),
        source_dir=source,
        output_dir=output,
        results_dir=results,
        scan_target=source,
        offline=True,
    )
    script = f"(setsid sh -c 'sleep 4; echo late > {late}' &) ; sleep 60"
    started = time.monotonic()
    with sandbox_scope(scope):
        response = run_command_with_output_handling(
            ["/bin/sh", "-c", script],
            results_dir=results,
            stdout_preference="return",
            stderr_preference="return",
            timeout=2,
        )
    assert response.get("timed_out") is True, response
    assert time.monotonic() - started < 30
    # Longer than the detached process's own delay.
    time.sleep(6)
    assert not late.exists(), "a process the scanner detached outlived the timeout"


def _plan(backend, tmp_path, argv):
    from automated_security_helper.utils.sandbox.policy import build_scanner_policy

    source = tmp_path / "src"
    source.mkdir(exist_ok=True)
    output = tmp_path / "out"
    policy = build_scanner_policy(
        "probe",
        SandboxRequirements(),
        argv0=argv[0],
        source_dir=source,
        output_dir=output,
        results_dir=output / "scanners" / "probe",
        scan_target=source,
        cwd=None,
        offline=True,
        network_scanners=None,
    )
    return backend.plan(argv, {"PATH": "/usr/bin:/bin"}, policy)


def _no_core_dump() -> None:
    """Run in each child before it execs: a SIGSEGV here must not write a core file.

    With an unlimited core size and a bare ``core`` core_pattern, both the Landlock
    wrapper, which re-raises its scanner's signal on itself, and the unwrapped
    shell dump core into their working directory, which was the checkout pytest
    ran from. The limit is inherited across the wrapper's exec of the scanner.
    """
    import resource

    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


def test_a_scanner_killed_by_a_signal_reports_it_as_unwrapped(tmp_path):
    import subprocess  # nosec B404 - runs the sandboxed command under test

    backend = _landlock()
    argv = ["/bin/sh", "-c", "kill -SEGV $$"]
    plan = _plan(backend, tmp_path, argv)
    cwd = tmp_path / "cwd"
    cwd.mkdir()
    wrapped = subprocess.run(  # nosec B603 - backend-built argv
        plan.argv, env=plan.env, cwd=cwd, preexec_fn=_no_core_dump, check=False
    )
    plan.run_cleanup()
    unwrapped = subprocess.run(  # nosec B603 - fixed argv
        argv, cwd=cwd, preexec_fn=_no_core_dump, check=False
    )
    assert wrapped.returncode == unwrapped.returncode < 0
    assert not [path.name for path in cwd.iterdir() if path.name.startswith("core")]


def test_a_process_left_after_a_normal_exit_is_reaped(tmp_path):
    import subprocess  # nosec B404 - runs the sandboxed command under test

    backend = _landlock()
    results = tmp_path / "out" / "scanners" / "probe"
    late = results / "late.txt"
    argv = ["/bin/sh", "-c", f"(setsid sh -c 'sleep 2; echo late > {late}' &) ; exit 3"]
    plan = _plan(backend, tmp_path, argv)
    started = time.monotonic()
    result = subprocess.run(plan.argv, env=plan.env, check=False)  # nosec B603 - backend-built argv
    elapsed = time.monotonic() - started
    plan.run_cleanup()
    assert result.returncode == 3
    # The reap loop must not cost a full /proc scan per spawn.
    assert elapsed < 2, elapsed
    time.sleep(3)
    assert not late.exists()


def test_a_stopped_scanner_and_what_it_detached_end_inside_half_a_second(tmp_path):
    """SIGTERM to the wrapper, as ASH stops a sandboxed spawn, then the grace.

    Half a second is the shortest grace ASH gives a stopping process before it
    SIGKILLs it. The wrapper must have ended the scanner and the process it
    detached by then; the detached process would write a file two seconds later.
    """
    import signal
    import subprocess  # nosec B404 - runs the sandboxed command under test

    backend = _landlock()
    results = tmp_path / "out" / "scanners" / "probe"
    results.mkdir(parents=True)
    ready = results / "ready.txt"
    late = results / "late.txt"
    script = (
        f"(setsid sh -c 'sleep 2; echo late > {late}' &) ; "
        f"echo ready > {ready} && echo ready ; sleep 60"
    )
    argv = ["/bin/sh", "-c", script]
    plan = _plan(backend, tmp_path, argv)
    process = subprocess.Popen(plan.argv, env=plan.env, stdout=subprocess.PIPE)  # nosec B603 - backend-built argv
    try:
        assert process.stdout.readline() == b"ready\n"
        started = time.monotonic()
        process.send_signal(signal.SIGTERM)
        process.wait(timeout=30)
        elapsed = time.monotonic() - started
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()
        process.stdout.close()
        plan.run_cleanup()

    assert elapsed < 0.5, elapsed
    # The scanner could write there, so the missing file below is the reap's doing.
    assert ready.exists()
    time.sleep(3)
    assert not late.exists(), "a process the stopped scanner detached outlived it"


def test_a_scanner_cannot_kill_its_wrapper_to_escape_reaping(tmp_path):
    """The wrapper sits outside the scanner's Landlock domain.

    A scanner that detaches a process and then SIGKILLs the wrapper would leave
    that process running after ASH's sweep. On ABI 6+ the scanner cannot signal
    a process outside its domain, so the kill fails and the wrapper reaps the
    detached process. Below ABI 6 Landlock has no signal scoping: that is a
    documented gap, asserted to still exist rather than skipped.
    """
    backend = _landlock()
    output = tmp_path / "out"
    results = output / "scanners" / "probe"
    results.mkdir(parents=True)
    source = tmp_path / "src"
    source.mkdir()
    late = results / "late.txt"
    scope = SandboxScope(
        backend=backend,
        scanner_name="probe",
        requirements=SandboxRequirements(),
        source_dir=source,
        output_dir=output,
        results_dir=results,
        scan_target=source,
        offline=True,
    )
    script = (
        f"(setsid sh -c 'sleep 3; echo late > {late}' &) ; "
        "kill -9 $PPID 2>/dev/null; sleep 30"
    )
    started = time.monotonic()
    with sandbox_scope(scope):
        response = run_command_with_output_handling(
            ["/bin/sh", "-c", script],
            results_dir=results,
            stdout_preference="return",
            stderr_preference="return",
            timeout=2,
        )
    elapsed = time.monotonic() - started
    time.sleep(5)
    if backend._abi < 6:
        pytest.xfail(
            f"Landlock ABI {backend._abi} has no signal scoping (documented gap)"
        )
    # The wrapper survived the kill, so ASH's timeout reached it and it ended the
    # tree; the timeout also stayed a timeout.
    assert response.get("timed_out") is True, response
    assert elapsed < 20, elapsed
    assert not late.exists()


def test_the_reaper_sees_the_whole_tree_not_only_direct_children():
    """One reap pass must reach every level, so a deep tree dies in one pass."""
    _landlock()  # the reaper walks /proc, which exists only where landlock runs
    import subprocess  # nosec B404 - starts a short-lived process tree to inspect

    from automated_security_helper.utils.sandbox import landlock_exec

    tree = subprocess.Popen(  # nosec B603 - fixed argv
        ["/bin/sh", "-c", "sh -c 'sh -c \"sleep 30\" & wait' & wait"]
    )
    try:
        time.sleep(1)
        everything = landlock_exec._descendants()
        # This process's own children: the descendants whose parent it is, read
        # from each one's stat, not by repeating the walk's first level.
        direct = [
            pid for pid in everything if landlock_exec._parent_pid(pid) == os.getpid()
        ]
        assert tree.pid in direct
        assert len(everything) >= 3, everything
        assert set(direct) < set(everything)
    finally:
        for pid in reversed(landlock_exec._descendants()):
            try:
                os.kill(pid, 9)
            except OSError:
                pass
        tree.wait()
