# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The image permissions probe looks at the whole image, not a list of directories.

tests/snapshot/container/runtime/test_container_image_permissions.py runs a find
inside a built image and fails on any file every user may write outside a sticky
directory: the files some gems ship mode 777 under /var/lib/gems and the lock files
uv creates mode 666 in home directories are such files. The find starts at ``/`` and
stays on the image's own filesystem (``-xdev``), skipping /proc, /sys and /dev and
the sticky scratch directories /tmp, /var/tmp and /run/lock, whose files belong to
whoever wrote them.

The probe needs a built image and an OCI runner, which the unit suite does not
have, so this runs the probe's own find against a small tree laid out like one.
"""

from __future__ import annotations

import importlib.util
import os
import shutil
import subprocess  # nosec B404 - runs the probe's find against a temporary tree
from pathlib import Path

import pytest

PROBE_MODULE = (
    Path(__file__).resolve().parents[1]
    / "snapshot"
    / "container"
    / "runtime"
    / "test_container_image_permissions.py"
)
# Paths inside the image under test; nothing is created or opened under them.
PRUNED = {"/proc", "/sys", "/dev", "/tmp", "/var/tmp", "/run/lock"}  # nosec B108


@pytest.fixture(scope="module")
def probe():
    spec = importlib.util.spec_from_file_location(
        "ash_image_permissions_probe", PROBE_MODULE
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_the_probe_starts_at_the_root_of_the_image(probe, monkeypatch):
    seen = []

    def record(cmd, **_kwargs):
        seen.append(cmd)
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr(probe.subprocess, "run", record)

    assert probe.list_open_files() == []
    find = probe.open_files_find()
    assert find.startswith("find / -xdev ")
    assert set(probe.PRUNED) == PRUNED
    # As root, which can list every directory; the image's user cannot.
    [cmd] = seen
    assert cmd[cmd.index("--user") + 1] == "0:0"
    assert cmd[-3:] == ["sh", "-c", find]


def _write(path: Path, mode: int) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("x\n", encoding="utf-8")
    path.chmod(mode)
    return path


def _find_supports_printf() -> bool:
    """Whether the host's find has GNU -printf.

    The probe's find runs inside the Linux image, where find is GNU. This
    test runs it against a local tree, and BSD find (the macOS runners)
    refuses -printf with "unknown primary or operator".
    """
    find = shutil.which("find")
    if find is None:
        return False
    completed = subprocess.run(  # nosec B603 - fixed argv, reads one directory
        [find, "/", "-maxdepth", "0", "-printf", ""],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    return completed.returncode == 0


@pytest.mark.skipif(
    os.name == "nt" or not _find_supports_printf(),
    reason="POSIX file modes and GNU find -printf, as inside the image",
)
def test_the_probe_lists_what_every_user_may_write_and_nothing_else(probe, tmp_path):
    image = tmp_path / "image"
    expected = {
        _write(image / "var/lib/gems/3.1.0/gems/lightly-0.3.3/lib/lightly.rb", 0o777),
        _write(image / "root/.cache/uv/.lock", 0o666),
        _write(image / "home/ash-user/.local/share/uv/tools/.lock", 0o666),
    }
    open_dir = image / "opt/shared"
    open_dir.mkdir(parents=True)
    open_dir.chmod(0o777)
    expected.add(open_dir)
    # Skipped: the kernel's and the runner's filesystems, and the sticky scratch
    # directories with what is in them.
    for pruned in sorted(PRUNED):
        _write(image / pruned.lstrip("/") / "uv-0123.lock", 0o666)
        (image / pruned.lstrip("/")).chmod(0o1777)
    # Not listed: sticky, closed, group-writable only, or a symbolic link.
    sticky = image / "src"
    sticky.mkdir()
    sticky.chmod(0o1777)
    _write(image / "usr/bin/tool", 0o755)
    shared_group = image / "var/local"
    shared_group.mkdir(parents=True)
    shared_group.chmod(0o2775)
    (image / "usr/bin/link").symlink_to(next(iter(expected)))

    completed = subprocess.run(  # nosec B603 B607 - the probe's own find, fixed tree
        ["sh", "-c", probe.open_files_find(str(image))],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr
    listed = {
        line.partition(" ")[2]
        for line in completed.stdout.splitlines()
        if line.startswith("open ")
    }
    assert listed == {str(path) for path in expected}
