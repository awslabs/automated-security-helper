# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A working directory inside the writable results directory stays writable.

bwrap applies mounts in order, so a read-only bind of a cwd under the results
directory, emitted after the writable bind, made that subtree read-only. The cdk-nag
worker hit it by running from its work directory. The command-line half of this is
in tests/unit/utils/test_sandbox_policy.py; this runs real bwrap.

Skipped when bwrap cannot start a sandbox, unless ASH_REQUIRE_SANDBOX_BACKENDS names
it, which the sandbox CI job does.
"""

import os
import subprocess  # nosec B404 - runs the sandboxed command under test

import pytest

from automated_security_helper.utils.sandbox.backends import BwrapBackend
from automated_security_helper.utils.sandbox.policy import (
    SandboxRequirements,
    build_scanner_policy,
)

pytestmark = pytest.mark.integration


def _require_bwrap() -> BwrapBackend:
    backend = BwrapBackend()
    reason = backend.probe()
    if reason:
        required = os.environ.get("ASH_REQUIRE_SANDBOX_BACKENDS", "").split(",")
        if "bwrap" in [name.strip() for name in required]:
            pytest.fail(
                f"bwrap is required (ASH_REQUIRE_SANDBOX_BACKENDS) but: {reason}"
            )
        pytest.skip(f"bwrap unavailable: {reason}")
    return backend


def test_a_writable_cwd_under_the_results_directory_can_be_written(tmp_path):
    backend = _require_bwrap()
    source = tmp_path / "src"
    source.mkdir()
    output = source / ".ash" / "ash_output"
    results = output / "scanners" / "probe"
    work = results / "work"
    work.mkdir(parents=True)
    policy = build_scanner_policy(
        "probe",
        SandboxRequirements(),
        argv0="/bin/sh",
        source_dir=source,
        output_dir=output,
        results_dir=results,
        scan_target=source,
        cwd=work,
        offline=True,
        network_scanners=None,
    )
    plan = backend.plan(
        ["/bin/sh", "-c", "echo ok > written && cat written"],
        {"PATH": "/usr/bin:/bin"},
        policy,
    )
    result = subprocess.run(  # nosec B603 - argv built by the backend under test
        plan.argv, env=plan.env, capture_output=True, text=True, check=False
    )
    plan.run_cleanup()
    assert result.returncode == 0, result.stderr
    assert (work / "written").read_text() == "ok\n"
