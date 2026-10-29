# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""An install location the OS refuses to check or read reads as never built.

``_installed_revision`` runs at import time, so what it does with an
uncheckable path decides whether ``import ash`` survives. ``Path.exists()``
can propagate the refused stat's OSError (measured: 3.10 through 3.13 raise
PermissionError, 3.14 answers False), and ``read_text()`` raises it on every
interpreter. The cells use a real refused directory and a real unreadable
file, no mocks, so they measure each interpreter's own pathlib — and each
asserts its refusal precondition first, so an environment where mode 0 does
not refuse (Windows read-only attribute, CAP_DAC_OVERRIDE, a mode-ignoring
filesystem) fails or skips instead of passing vacuously.
"""

from __future__ import annotations

import os

import pytest

from automated_security_helper.core.constants import _installed_revision

pytestmark = pytest.mark.unit


def test_an_uncheckable_path_reads_as_unknown_commit(tmp_path):
    if os.name != "posix":
        pytest.skip("chmod(0) does not refuse lookups off POSIX")
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        pytest.skip("root sees through a mode-0 directory")
    parent = tmp_path / "refused"
    parent.mkdir()
    target = parent / "ASH_INSTALLED_REVISION"
    parent.chmod(0)
    try:
        # The precondition: this environment really refuses the stat.
        with pytest.raises(PermissionError):
            target.stat()
        assert _installed_revision(target) == "unknown-commit"
    finally:
        parent.chmod(0o700)


def test_an_unreadable_recorded_revision_reads_as_unknown_commit(tmp_path):
    """A mode-0 file in a readable directory: ``exists()`` answers True on
    every interpreter and the read is what the OS refuses, so this cell
    guards the ``read_text()`` branch of the handler everywhere, not only
    where ``exists()`` itself raises."""
    if os.name != "posix":
        pytest.skip("chmod(0) does not refuse reads off POSIX")
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        pytest.skip("root reads through a mode-0 file")
    recorded = tmp_path / "ASH_INSTALLED_REVISION"
    recorded.write_text("0123abcd\n", encoding="utf-8")
    recorded.chmod(0)
    try:
        # The precondition: this environment really refuses the read.
        with pytest.raises(PermissionError):
            recorded.read_text()
        assert _installed_revision(recorded) == "unknown-commit"
    finally:
        recorded.chmod(0o600)


def test_a_recorded_revision_is_still_read(tmp_path):
    """The control: the handler changes nothing for a readable asset."""
    recorded = tmp_path / "ASH_INSTALLED_REVISION"
    recorded.write_text("0123abcd\n", encoding="utf-8")
    assert _installed_revision(recorded) == "0123abcd"
