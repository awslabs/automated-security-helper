# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The policy document the Landlock backend writes is the one its wrapper accepts.

utils/sandbox/landlock_exec.py's ``_parse_policy`` fails closed (exit 126) on an
unknown key, a wrong type, a relative path or a missing required key. The document
is written by utils/sandbox/backends.py's ``LandlockBackend._plan`` from a
``SandboxPolicy``; a mismatch between the two would refuse every Landlock spawn.
This test builds a real policy the way the scan does, with and without a working
directory, plans the spawn and hands the ``--policy`` argument to the wrapper's
check. No sandbox runs: the plan is built and parsed in-process.
"""

import json
import os
import sys
from pathlib import Path
from typing import Tuple

import pytest

if sys.platform != "linux":
    pytest.skip("the wrapper uses prctl and /proc, Linux only", allow_module_level=True)

from automated_security_helper.utils.sandbox import landlock_exec  # noqa: E402
from automated_security_helper.utils.sandbox.backends import (  # noqa: E402
    LandlockBackend,
)
from automated_security_helper.utils.sandbox.policy import (  # noqa: E402
    SandboxRequirements,
    build_scanner_policy,
)

pytestmark = pytest.mark.unit


def _policy_argument(tmp_path: Path, cwd) -> Tuple[str, Path, Path]:
    """The ``--policy`` argument of a planned spawn, with the source tree and the
    results directory it was planned for. The output directory exists, as in a scan
    (a path that does not exist is left out of the policy)."""
    source = tmp_path / "src"
    source.mkdir(exist_ok=True)
    output = tmp_path / "out"
    output.mkdir(exist_ok=True)
    results = output / "scanners" / "probe"
    policy = build_scanner_policy(
        "probe",
        SandboxRequirements(),
        argv0="/bin/sh",
        source_dir=source,
        output_dir=output,
        results_dir=results,
        scan_target=source,
        cwd=cwd,
        offline=True,
        network_scanners=None,
    )
    plan = LandlockBackend().plan(
        ["/bin/sh", "-c", "true"], {"PATH": "/usr/bin"}, policy
    )
    try:
        flag = plan.argv.index("--policy")
        return plan.argv[flag + 1], source, results
    finally:
        plan.run_cleanup()


@pytest.mark.parametrize("with_cwd", [False, True])
def test_the_backends_policy_document_passes_the_wrappers_check(tmp_path, with_cwd):
    """With no working directory (a version probe: the backend names its private
    TMPDIR as the cwd) and with one (ASH gives the spawn its cwd, so the document
    carries none): every key is one the wrapper knows, every path is absolute,
    nothing is null, and the check returns the document instead of exiting 126."""
    cwd = tmp_path / "work" if with_cwd else None
    if cwd is not None:
        cwd.mkdir()

    text, source, results = _policy_argument(tmp_path, cwd)
    document = json.loads(text)
    parsed = landlock_exec._parse_policy(text)

    assert set(document) <= set(landlock_exec._POLICY_KEYS)
    assert set(landlock_exec._REQUIRED_POLICY_KEYS) <= set(document)
    for key in ("read_only", "read_data", "writable"):
        assert all(Path(p).is_absolute() for p in document.get(key, []))
    # The lists are not empty: the scanned tree is read, the results directory is
    # written, and both are named as the wrapper will resolve them.
    assert os.path.realpath(source) in document["read_only"] + document["read_data"]
    assert os.path.realpath(results) in document["writable"]
    if with_cwd:
        assert "cwd" not in document
    else:
        assert Path(document["cwd"]).is_absolute()
    assert None not in document.values()
    assert parsed == document
