# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A standard descriptor the entry point holds is inherited by ASH's children.

``ensure_std_streams`` holds a descriptor found closed at startup with
``os.devnull``. When the null device is opened while that very number is the
lowest free one, ``os.open`` hands it back directly, and ``os.open`` gives a
descriptor children do not inherit (PEP 446). A child started with
``stderr=None`` then began with descriptor 2 closed again, and its first
``open()`` landed on 2, so its stderr writes went into that file: the hazard
the hold exists for, re-created one process down. The hold is now made
inheritable on both of its paths.

Measured with real descriptors: a child Python starts with 2 closed (the
``preexec_fn`` closes it between fork and exec), calls ``ensure_std_streams``,
and starts a grandchild that reports whether its descriptor 2 is open. The
stand-in tests in tests/unit/cli/test_entrypoint_reserves_closed_descriptors.py
cannot see this: they replace ``os.open`` and ``os.dup2``.
"""

from __future__ import annotations

import os
import subprocess
import sys

import pytest

pytestmark = pytest.mark.integration

#: Run in the child: hold the closed descriptor, then ask a grandchild whether
#: it inherited an open descriptor 2. The grandchild's exit code is printed on
#: stdout, which stays the child's pipe to this test.
CHILD = """
import subprocess, sys
from automated_security_helper.cli.entrypoint import ensure_std_streams
ensure_std_streams()
grandchild = subprocess.run(
    [sys.executable, "-c",
     "import os\\n"
     "try:\\n"
     "    os.fstat(2)\\n"
     "except OSError:\\n"
     "    raise SystemExit(3)\\n"
     "raise SystemExit(0)\\n"],
    stdin=subprocess.DEVNULL,
)
print(grandchild.returncode)
"""


@pytest.mark.skipif(sys.platform == "win32", reason="preexec_fn is POSIX-only")
def test_a_child_inherits_the_held_stderr(tmp_path):
    def close_stderr() -> None:
        os.close(2)

    result = subprocess.run(
        [sys.executable, "-I", "-c", CHILD],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        preexec_fn=close_stderr,
        cwd=tmp_path,
        text=True,
        check=False,
        timeout=120,
    )

    assert result.returncode == 0, result
    assert result.stdout.strip() == "0", (
        "the grandchild started with descriptor 2 closed: the hold was not inherited"
    )
