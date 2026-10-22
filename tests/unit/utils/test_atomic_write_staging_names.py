# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""An atomic write's staging file is named without ``uuid.uuid4``.

``write_text_atomically``, ``open_atomically`` and ``write_bytes_atomically``
stage each write in a file beside the target and rename it over the target. The
snapshot tests pin ``uuid.uuid4`` to a counter, because report ids are built from
it, so a staging name drawing its random part from ``uuid.uuid4`` would have
every atomic write ASH adds before a report is made shift that report's id: the
workspace spool's writes would move the unified report's id from ...07 to ...09
and fail the workspace snapshots. A staging name only has to be unique, so it
comes from :mod:`secrets`, which nothing pins.

Every path here is under ``tmp_path``.
"""

from __future__ import annotations

import uuid

import pytest

from automated_security_helper.utils.atomic_write import (
    open_atomically,
    write_bytes_atomically,
    write_text_atomically,
)


@pytest.fixture
def uuid4_refused(monkeypatch):
    def _refuse():
        raise AssertionError("an atomic write drew from uuid.uuid4")

    monkeypatch.setattr(uuid, "uuid4", _refuse)


@pytest.mark.usefixtures("uuid4_refused")
def test_no_atomic_write_draws_from_uuid4(tmp_path):
    write_text_atomically(tmp_path / "text.txt", "text\n")
    write_bytes_atomically(tmp_path / "bytes.bin", b"bytes\n")
    with open_atomically(tmp_path / "stream.txt") as handle:
        handle.write("stream\n")

    assert (tmp_path / "text.txt").read_text(encoding="utf-8") == "text\n"
    assert (tmp_path / "bytes.bin").read_bytes() == b"bytes\n"
    assert (tmp_path / "stream.txt").read_text(encoding="utf-8") == "stream\n"
    assert sorted(p.name for p in tmp_path.iterdir()) == [
        "bytes.bin",
        "stream.txt",
        "text.txt",
    ]


def test_two_staging_files_for_one_target_get_different_names(tmp_path):
    """Two writers to one target at once each stage in a file of their own."""
    target = tmp_path / "shared.txt"
    with open_atomically(target) as first, open_atomically(target) as second:
        first.write("first\n")
        second.write("second\n")
        staged = sorted(p.name for p in tmp_path.iterdir())

    assert len(staged) == 2 and staged[0] != staged[1], staged
    assert target.read_text(encoding="utf-8") in ("first\n", "second\n")
