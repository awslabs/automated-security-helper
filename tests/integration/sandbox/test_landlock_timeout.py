# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A timed-out scanner under Landlock leaves no process behind.

Landlock does not end a process's descendants with it, so its wrapper is a child
subreaper that kills what its scanner leaves. A timeout used to SIGKILL the wrapper,
which can do nothing after that; ASH now sends SIGTERM first and the wrapper ends the
whole tree. Measured here by a detached process that would write a file after the
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


def test_a_scanner_killed_by_a_signal_reports_it_as_unwrapped(tmp_path):
    import subprocess  # nosec B404 - runs the sandboxed command under test

    backend = _landlock()
    argv = ["/bin/sh", "-c", "kill -SEGV $$"]
    plan = _plan(backend, tmp_path, argv)
    wrapped = subprocess.run(plan.argv, env=plan.env, check=False)  # nosec B603 - backend-built argv
    plan.run_cleanup()
    unwrapped = subprocess.run(argv, check=False)  # nosec B603 - fixed argv
    assert wrapped.returncode == unwrapped.returncode < 0


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
