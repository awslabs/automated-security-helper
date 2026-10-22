# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""An output directory that is there but cannot be written is refused, exit 5.

``utils/directory_refusals.output_dir_refusal`` makes a file in the directory
with ``O_CREAT | O_EXCL`` and removes it, and refuses the directory with
``Output directory cannot be written: <path> (<reason>)`` when that fails, the
reason being the error's strerror. ``os.access(W_OK)`` is not asked: it answers
for the real user, not the effective one, and does not know about ACLs or a
read-only mount. A directory that is not there yet is not checked; whoever makes
it finds out.
"""

from __future__ import annotations

import os
import shutil
import subprocess  # nosec B404 - a read-only mount is made in a namespace of its own
import sys

import pytest

from automated_security_helper.utils.directory_refusals import output_dir_refusal

_NON_ROOT_ONLY = pytest.mark.skipif(
    os.name == "nt" or os.geteuid() == 0,
    reason="root writes into a directory without write permission",
)


def test_control_a_writable_directory_is_not_refused_and_keeps_nothing(tmp_path):
    out = tmp_path / "out"
    out.mkdir()
    (out / "kept.txt").write_text("x\n", encoding="utf-8")

    assert output_dir_refusal(out) is None
    assert sorted(path.name for path in out.iterdir()) == ["kept.txt"]


@_NON_ROOT_ONLY
def test_a_directory_without_write_permission_is_refused(tmp_path):
    out = tmp_path / "out"
    out.mkdir()
    out.chmod(0o555)
    try:
        refusal = output_dir_refusal(out)
        left = list(out.iterdir())
    finally:
        out.chmod(0o755)

    assert refusal == f"Output directory cannot be written: {out} (Permission denied)"
    assert left == []


def test_a_directory_that_is_not_there_is_not_checked(tmp_path):
    assert output_dir_refusal(tmp_path / "not-yet") is None
    assert list(tmp_path.iterdir()) == []


#: Run in a user and mount namespace of the child's own, where it may mount: a
#: read-only tmpfs on the directory, then the check on it. MS_RDONLY is 1.
_READ_ONLY_PROBE = """
import ctypes, os, sys
target = sys.argv[1]
libc = ctypes.CDLL(None, use_errno=True)
if libc.mount(b"tmpfs", target.encode(), b"tmpfs", 1, None) != 0:
    sys.exit("mount failed: " + os.strerror(ctypes.get_errno()))
from automated_security_helper.utils.directory_refusals import output_dir_refusal
print(output_dir_refusal(target))
"""


def test_a_read_only_mount_is_refused(tmp_path):
    """A read-only file system refuses a write whatever the permissions say, root
    included: the child is root in its own namespace, and is still refused."""
    unshare = shutil.which("unshare")
    if sys.platform != "linux" or unshare is None:
        pytest.skip("needs Linux and unshare to mount without privileges")
    allowed = subprocess.run(  # nosec B603 - fixed arguments
        [unshare, "--user", "--map-root-user", "--mount", "true"],
        capture_output=True,
        check=False,
    )
    if allowed.returncode != 0:
        pytest.skip("unprivileged user namespaces are not available here")
    out = tmp_path / "out"
    out.mkdir()
    home = tmp_path / "home"
    home.mkdir()

    result = subprocess.run(  # nosec B603 - fixed interpreter, script and arguments
        [
            unshare,
            "--user",
            "--map-root-user",
            "--mount",
            sys.executable,
            "-I",
            "-c",
            _READ_ONLY_PROBE,
            str(out),
        ],
        capture_output=True,
        text=True,
        env={**os.environ, "HOME": str(home), "USERPROFILE": str(home)},
        timeout=120,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == (
        f"Output directory cannot be written: {out} (Read-only file system)"
    ), result.stdout + result.stderr
    assert list(out.iterdir()) == []
