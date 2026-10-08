# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""ASH's stream-log write stays inside the results directory even if a directory
on its path is replaced by a link after the scanner has run.

The harness performs the replacement itself, at the boundary between the spawn
returning and ASH writing the scanner's stream logs, by wrapping
``subprocess_utils._write_stream_log``. That is the window a process left behind by
a scanner would have. The assertion is that nothing is written into the directory
the link points to. Run on each backend that is available; ASH_REQUIRE_SANDBOX_BACKENDS
makes a missing one a failure.
"""

import os
import shutil

import pytest

from automated_security_helper.utils import subprocess_utils
from automated_security_helper.utils.sandbox import clear_backend_cache, resolve_backend
from automated_security_helper.utils.sandbox.policy import SandboxRequirements
from automated_security_helper.utils.sandbox.scope import (
    SandboxScope,
    SandboxUnavailable,
    sandbox_scope,
)

pytestmark = pytest.mark.integration


def _backend(name):
    clear_backend_cache()
    try:
        return resolve_backend(name)
    except SandboxUnavailable as e:
        required = os.environ.get("ASH_REQUIRE_SANDBOX_BACKENDS", "").split(",")
        if name in [n.strip() for n in required]:
            pytest.fail(f"{name} is required but: {e}")
        pytest.skip(f"{name} unavailable: {e}")


@pytest.mark.parametrize("backend_name", ["bwrap", "landlock"])
def test_a_results_subdirectory_replaced_after_the_spawn_is_not_followed(
    tmp_path, monkeypatch, backend_name
):
    backend = _backend(backend_name)
    source = tmp_path / "src"
    source.mkdir()
    output = tmp_path / "out"
    scanner_dir = output / "scanners" / "probe"
    target_dir = scanner_dir / "source"
    target_dir.mkdir(parents=True)
    victim = tmp_path / "victim"
    victim.mkdir()

    original = subprocess_utils._write_stream_log
    swapped = []

    def swap_then_write(results_dir, *args, **kwargs):
        if not swapped:
            shutil.rmtree(target_dir)
            os.symlink(victim, target_dir, target_is_directory=True)
            swapped.append(True)
        return original(results_dir, *args, **kwargs)

    monkeypatch.setattr(subprocess_utils, "_write_stream_log", swap_then_write)
    scope = SandboxScope(
        backend=backend,
        scanner_name="probe",
        requirements=SandboxRequirements(),
        source_dir=source,
        output_dir=output,
        results_dir=scanner_dir,
        scan_target=source,
        offline=True,
    )
    with sandbox_scope(scope):
        subprocess_utils.run_command_with_output_handling(
            ["/bin/sh", "-c", "echo scanner-output"],
            results_dir=target_dir,
            stdout_preference="write",
            stderr_preference="write",
            class_name="Probe",
        )
    assert swapped, "the harness never reached the stream-log write"
    assert list(victim.iterdir()) == [], "ASH wrote through the replaced directory"
