# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Who can write ASH's directories in a built image, read from inside the image.

tests/unit/test_dockerfile_directory_permissions.py holds the Dockerfile text to the
rule; this checks the image a CI leg actually built, because a base image, an
installer or a later edit can leave a mode the text does not show. Deselected by
default (tests/conftest.py); the scan-validation legs that build the ``ci`` image
run it with ``--run-container-snapshots``, and the ``non-root-image-permissions`` job
in ash-unified-ci.yml runs it against the default stage, ``non-root``. Locally, with
an image already built:

    ASH_IMAGE_NAME=<tag> OCI_RUNNER=docker \\
        pytest tests/snapshot/container/runtime/test_container_image_permissions.py \\
        --run-container-snapshots --no-cov -n 0

The rule:

- Nothing on the image's filesystem is writable by every user, except a directory
  with the sticky bit. The find starts at ``/`` and stays on that filesystem
  (``-xdev``), skipping /proc, /sys and /dev, and the sticky scratch directories
  /tmp, /var/tmp and /run/lock with what is in them, whose files belong to whoever
  wrote them. tests/unit/test_container_permissions_probe_covers_the_image.py runs
  the same find against a small tree.
- /deps, the semgrep and opengrep rule caches, /ash, /.ash and ASH_BIN_PATH
  (/.ash/bin): owned by root, not writable by group or others, and nothing in them
  writable by others either.
- The grype database cache (and trivy's, where the image has one): written by the
  database update at scan time, so owned by the user the image runs as -- root in
  the ``ci`` stage, the unprivileged user in ``non-root`` -- and not writable by
  others. An offline image never updates it, so there it stays root's.
- /src and /out may be writable by every user only with the sticky bit.
"""

from __future__ import annotations

import os
import shlex
import subprocess  # nosec B404 - running the real OCI runner is the point of this module
from typing import Dict, List

import pytest

pytestmark = [pytest.mark.container_runtime]

# The ``ci`` stage's tag, which every leg running this module builds with an explicit
# ``--build-target ci``; see test_snapshot_container_runtime.py.
IMAGE = os.environ.get("ASH_IMAGE_NAME") or "automated-security-helper:ci"
RUNNER_PREFIX = [
    *shlex.split(os.environ.get("OCI_RUNNER_WRAPPER", "")),
    os.environ.get("OCI_RUNNER") or "docker",
]

ROOT_OWNED = (
    "/deps",
    "/deps/.semgrep",
    "/deps/.opengrep",
    "/ash",
    "/.ash",
    "/.ash/bin",
)

#: Left out of the search for files every user may write: the kernel's and the
#: runner's filesystems, and the sticky scratch directories with what is in them.
PRUNED = ("/proc", "/sys", "/dev", "/tmp", "/var/tmp", "/run/lock")  # nosec B108


def open_files_find(root: str = "/") -> str:
    """The find that prints ``open <path>`` for each file every user may write.

    Symbolic links are left out (their mode is always 777 and means nothing), and
    so are directories with the sticky bit. ``root`` is ``/`` in the image; the
    unit test passes a temporary tree.
    """
    base = root.rstrip("/")
    prune = " -o ".join(f"-path {shlex.quote(base + path)}" for path in PRUNED)
    return (
        f"find {shlex.quote(root)} -xdev \\( {prune} \\) -prune -o "
        "! -type l -perm -0002 ! -perm -1000 -printf 'open %p\\n'"
    )


_PROBE = r"""
set -eu
echo "uid $(id -u)"
echo "offline ${OFFLINE:-NO}"
for d in /deps /deps/.grype /deps/.semgrep /deps/.opengrep /ash /.ash /.ash/bin \
         ${TRIVY_CACHE_DIR:-}; do
  if [ -e "$d" ]; then stat -c 'dir %n %u %a' "$d"; fi
done
find /ash /.ash /deps/.semgrep /deps/.opengrep -xdev ! -type l ! -uid 0 \
  -printf 'owner %p\n'
"""


def _run_in_image(script: str, *, as_root: bool = False) -> subprocess.CompletedProcess:
    user = ["--user", "0:0"] if as_root else []
    return subprocess.run(  # nosec B603 - runner and image come from the CI leg
        [*RUNNER_PREFIX, "run", "--rm", *user, IMAGE, "sh", "-c", script],
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=300,
        check=False,
    )


def list_open_files() -> List[str]:
    """Each file in the image every user may write, outside the pruned paths.

    Run as root: the image's own user cannot list directories such as /root, and
    find would fail on them rather than look inside.
    """
    result = _run_in_image(open_files_find(), as_root=True)
    assert result.returncode == 0, result.stderr
    return [
        line.partition(" ")[2]
        for line in result.stdout.splitlines()
        if line.startswith("open ")
    ]


@pytest.fixture(scope="module")
def probe() -> Dict[str, List[str]]:
    result = _run_in_image(_PROBE)
    assert result.returncode == 0, result.stderr
    lines: Dict[str, List[str]] = {
        "uid": [],
        "offline": [],
        "dir": [],
        "owner": [],
    }
    for line in result.stdout.splitlines():
        kind, _, rest = line.partition(" ")
        if kind in lines:
            lines[kind].append(rest)
    assert lines["uid"], result.stdout
    return lines


def _dirs(probe) -> Dict[str, tuple]:
    found = {}
    for entry in probe["dir"]:
        path, uid, mode = entry.split(" ")
        found[path] = (int(uid), int(mode, 8))
    return found


def test_nothing_is_writable_by_every_user_without_the_sticky_bit():
    assert list_open_files() == []


def test_the_root_owned_directories_are_roots_and_closed(probe):
    dirs = _dirs(probe)

    assert set(ROOT_OWNED) <= set(dirs), dirs
    for path in ROOT_OWNED:
        uid, mode = dirs[path]
        assert uid == 0, f"{path} is owned by uid {uid}"
        assert mode & 0o022 == 0, f"{path} is writable by group or others: {oct(mode)}"
    assert probe["owner"] == []


def test_the_database_caches_belong_to_the_user_the_image_runs_as(probe):
    """Or to root in an offline image, whose database is never updated at scan time."""
    run_as = 0 if probe["offline"] == ["YES"] else int(probe["uid"][0])
    caches = {
        path: owner_mode
        for path, owner_mode in _dirs(probe).items()
        if path == "/deps/.grype" or path.endswith(".trivy")
    }

    assert "/deps/.grype" in caches
    for path, (uid, mode) in caches.items():
        assert uid == run_as, (
            f"{path} is owned by uid {uid}, the image runs as {run_as}"
        )
        assert mode & 0o002 == 0, f"{path} is writable by others: {oct(mode)}"
