# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The private-directory ownership walk inside a user namespace.

In a rootless container or an agent sandbox, ``stat`` reports ``/`` and
``/tmp`` as owned by the kernel's overflow uid (``nobody``, 65534 by default),
because their real owners are not mapped into the process's user namespace.
Before the user-namespace clause in ``_changeable_by_others``, the walk from
any candidate up to ``/`` met such an ancestor, called it another account's,
rejected every candidate, and the scanner run failed with "No private
directory ..." that no ``TMPDIR`` could fix, since every ``TMPDIR`` still sits
under ``/``.

These cover: a normal walk still passes; a world-writable directory is still
rejected, inside a user namespace too (only the ownership inference is
loosened, never the mode check); an overflow-uid-owned ``/`` passes inside a
user namespace and is still rejected outside one; the refusals name the
failing ancestor, its owning uid and its mode bits; and the uid_map parser
reads literal ``/proc/self/uid_map`` texts right. Every ``stat`` is mocked and
the namespace detection is a mocked seam, so no real namespace is needed.
"""

from __future__ import annotations

import os
import stat as stat_module
from pathlib import Path
from typing import Dict, Optional, Tuple

import pytest

from automated_security_helper.utils import tool_config_dir
from automated_security_helper.utils.tool_config_dir import (
    _changeable_by_others,
    _uid_map_is_identity,
)

pytestmark = pytest.mark.unit

#: The euid every walk here runs as.
ME = 1000

#: The kernel's default overflow uid, what an unmapped owner stats as.
NOBODY = 65534

#: The real sandbox shape these tests reproduce is about /tmp itself, so its
#: spelling is part of the fixture. It is only ever a key in the mocked stat
#: tables and a prefix of the expected refusal text: every ``os.stat`` here is
#: a fake, and nothing in these tests reads or writes the real filesystem.
TMP = "/tmp"  # nosec B108 - a mocked stat key and message prefix, never written to


def _walk(
    monkeypatch: pytest.MonkeyPatch,
    path: str,
    table: Dict[str, Tuple[int, int]],
    overflow_uid: Optional[int],
) -> Optional[str]:
    """``_changeable_by_others(path)`` with every stat and the detection mocked.

    ``table`` maps each directory's posix path to ``(owner uid, mode bits)``; a
    stat of anything else fails the test. ``overflow_uid`` is what the mocked
    :func:`_user_namespace_overflow_uid` returns: an int means the walk runs
    inside a user namespace whose overflow uid that is, None means it does not.
    """

    def fake_stat(target, *args, **kwargs):
        key = Path(target).as_posix()
        if key not in table:
            raise AssertionError(f"unexpected stat of {key}")
        uid, mode = table[key]
        return os.stat_result(
            (stat_module.S_IFDIR | mode, 1, 1, 1, uid, uid, 0, 0, 0, 0)
        )

    with monkeypatch.context() as patched:
        patched.setattr(tool_config_dir.os, "geteuid", lambda: ME)
        patched.setattr(tool_config_dir.os, "stat", fake_stat)
        patched.setattr(
            tool_config_dir, "_user_namespace_overflow_uid", lambda: overflow_uid
        )
        return _changeable_by_others(Path(path))


def test_a_walk_over_own_and_root_owned_directories_passes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The normal case is unchanged, and never reads the namespace detection."""

    def never() -> Optional[int]:
        raise AssertionError("the detection ran although every owner was known")

    def fake_stat(target, *args, **kwargs):
        table = {"/": (0, 0o755), "/work": (0, 0o755), "/work/tmp": (ME, 0o700)}
        uid, mode = table[Path(target).as_posix()]
        return os.stat_result(
            (stat_module.S_IFDIR | mode, 1, 1, 1, uid, uid, 0, 0, 0, 0)
        )

    with monkeypatch.context() as patched:
        patched.setattr(tool_config_dir.os, "geteuid", lambda: ME)
        patched.setattr(tool_config_dir.os, "stat", fake_stat)
        patched.setattr(tool_config_dir, "_user_namespace_overflow_uid", never)
        assert _changeable_by_others(Path("/work/tmp")) is None


def test_a_nobody_owned_root_passes_inside_a_user_namespace(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The sandbox shape: / and /tmp stat as nobody's, and the walk passes.

    ``/tmp`` here is world-writable WITH the sticky bit, as a real /tmp is,
    which the walk has always accepted.
    """
    reason = _walk(
        monkeypatch,
        TMP + "/ash-x",
        {
            "/": (NOBODY, 0o755),
            TMP: (NOBODY, 0o1777),
            TMP + "/ash-x": (ME, 0o700),
        },
        overflow_uid=NOBODY,
    )
    assert reason is None


def test_a_nobody_owned_root_is_rejected_outside_a_user_namespace(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Outside a user namespace, uid 65534 is another account, as before."""
    reason = _walk(
        monkeypatch,
        TMP + "/ash-x",
        {
            "/": (NOBODY, 0o755),
            TMP: (NOBODY, 0o1777),
            TMP + "/ash-x": (ME, 0o700),
        },
        overflow_uid=None,
    )
    # The walk goes candidate-first, so /tmp is the first nobody-owned
    # ancestor it meets and the one the refusal names.
    assert reason is not None
    assert reason.startswith(TMP + " belongs to another account")
    assert "uid 65534" in reason
    assert f"uid {ME}" in reason
    assert "0o1777" in reason


def test_an_owner_other_than_the_overflow_uid_is_rejected_in_a_namespace(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Only the overflow uid is treated like root, not any foreign owner."""
    reason = _walk(
        monkeypatch,
        "/work",
        {"/": (0, 0o755), "/work": (4242, 0o755)},
        overflow_uid=NOBODY,
    )
    assert reason is not None
    assert "/work belongs to another account" in reason
    assert "uid 4242" in reason
    assert "0o755" in reason


def test_a_world_writable_directory_is_still_rejected_in_a_user_namespace(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Only the ownership inference is loosened: mode bits still reject.

    An overflow-uid-owned directory that group or everyone can write without
    the sticky bit is one anybody in the sandbox's mapped accounts could
    change, and stays rejected, with the mode named.
    """
    reason = _walk(
        monkeypatch,
        "/shared",
        {"/": (NOBODY, 0o755), "/shared": (NOBODY, 0o777)},
        overflow_uid=NOBODY,
    )
    assert reason is not None
    assert "/shared can be written by other accounts" in reason
    assert "sticky bit" in reason
    assert "uid 65534" in reason
    assert "0o777" in reason


def test_a_world_writable_directory_is_still_rejected_outside_one(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The pre-existing mode rejection, with the owner and mode now named."""
    reason = _walk(
        monkeypatch,
        "/work/shared",
        {"/": (0, 0o755), "/work": (0, 0o755), "/work/shared": (ME, 0o770)},
        overflow_uid=None,
    )
    assert reason is not None
    assert "/work/shared can be written by other accounts" in reason
    assert f"uid {ME}" in reason
    assert "0o770" in reason


@pytest.mark.parametrize(
    "uid_map,identity",
    [
        # The initial namespace's map, as /proc/self/uid_map prints it.
        ("         0          0 4294967295\n", True),
        # A rootless container: root inside is 100000 outside.
        ("         0     100000      65536\n", False),
        # An agent sandbox mapping one uid to itself: still a user namespace,
        # every other uid on disk stats as the overflow uid.
        ("      1000       1000          1\n", False),
        # Several rows are never the identity map.
        ("0 0 1000\n1000 1000 4294966295\n", False),
        ("", False),
    ],
)
def test_the_uid_map_parser_reads_literal_uid_map_texts(
    uid_map: str, identity: bool
) -> None:
    assert _uid_map_is_identity(uid_map) is identity
