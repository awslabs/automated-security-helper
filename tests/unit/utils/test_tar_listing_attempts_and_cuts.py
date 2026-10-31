# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Three readings of utils/tar_listing.py.

tarfile.open under "r:*" tries each compression in turn and reads the first
header under each, so the recording class open_tar_listing hands it can be run
more than once over the same bytes; what an abandoned attempt recorded (its
skipped count, its budget charge, the first unreadable offset) used to carry
into the attempt tarfile kept. A header error is charged the bytes tarfile read
for it, not a fixed block. And tar_names reports a tar cut right after a member
with no end-of-archive block, which used to list as complete.
"""

from __future__ import annotations

import io
import tarfile
from types import SimpleNamespace
from typing import Any, List

import pytest

from automated_security_helper.utils import tar_listing

pytestmark = pytest.mark.unit


def _tar_of(name: str, content: bytes) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        info = tarfile.TarInfo(name)
        info.size = len(content)
        archive.addfile(info, io.BytesIO(content))
    return buffer.getvalue()


def _member_only(tarred: bytes) -> bytes:
    """A member's header and its one data block, no end-of-archive blocks."""
    return tarred[:1024]


def _fake_tarfile(data: bytes) -> Any:
    """What TarInfo.fromtarfile reads from a TarFile: its stream and its codec."""
    return SimpleNamespace(
        fileobj=io.BytesIO(data), encoding="utf-8", errors="surrogateescape"
    )


def _read_damaged_blocks(recorder: Any, blocks: int) -> None:
    """Have ``recorder`` classify ``blocks`` headers that cannot be read."""
    attempt = _fake_tarfile(b"\x01" * 512 * blocks)
    for _ in range(blocks):
        with pytest.raises(tarfile.HeaderError):
            recorder.fromtarfile(attempt)


def _recorder_under(monkeypatch, attempts) -> Any:
    """The recording TarInfo class open_tar_listing builds, captured from a fake
    tarfile.open that runs ``attempts`` with it, as the "r:*" retries would."""
    captured: List[Any] = []

    def fake_open(fileobj, mode, ignore_zeros, tarinfo, **options):
        captured.append(tarinfo)
        attempts(tarinfo)
        return None

    monkeypatch.setattr(tar_listing, "open_tar", fake_open)
    return captured


def test_an_abandoned_attempt_leaves_nothing_in_the_kept_one(monkeypatch):
    unreadable: List[int] = []
    stopped: List[int] = []
    budget = tar_listing.SkippedBlocksBudget(100 * 512)
    ordinary_blocks = tar_listing.ORDINARY_END_BYTES // 512

    def attempts(recorder):
        # The first attempt skips past the ordinary end: four blocks charged.
        _read_damaged_blocks(recorder, ordinary_blocks + 4)
        assert budget.used == 4 * 512, "the control: the first attempt was charged"
        assert unreadable == [0]
        # tarfile abandons it and starts the next one at byte 0.
        _read_damaged_blocks(recorder, 1)

    _recorder_under(monkeypatch, attempts)
    tar_listing.open_tar_listing(
        io.BytesIO(b""), unreadable, stopped=stopped, budget=budget
    )

    assert budget.used == 0, "the first attempt's charge was given back"
    assert unreadable == [0]
    assert stopped == []


def test_a_header_error_is_charged_the_bytes_tarfile_read_for_it(monkeypatch):
    unreadable: List[int] = []
    stopped: List[int] = []

    class _ReadsTwoBlocks(io.BytesIO):
        """A stream that moves two blocks for each block handed out, as tarfile
        does when it reads a long-name header's extension before it raises."""

        def read(self, size=-1):
            data = super().read(size)
            super().read(size)
            return data

    def attempts(recorder):
        attempt = SimpleNamespace(
            fileobj=_ReadsTwoBlocks(b"\x01" * 512 * 2 * 2),
            encoding="utf-8",
            errors="surrogateescape",
        )
        with pytest.raises(tarfile.HeaderError):
            recorder.fromtarfile(attempt)
        # The second read starts where the stream is, two blocks in.
        assert attempt.fileobj.tell() == 1024
        with pytest.raises(tarfile.HeaderError):
            recorder.fromtarfile(attempt)

    captured = _recorder_under(monkeypatch, attempts)
    budget = tar_listing.SkippedBlocksBudget(10 * 512)
    # Make every skipped byte count: an ordinary end of zero bytes.
    monkeypatch.setattr(tar_listing, "ORDINARY_END_BYTES", 0)
    tar_listing.open_tar_listing(
        io.BytesIO(b""), unreadable, stopped=stopped, budget=budget
    )

    assert captured, "the control: the fake open ran"
    assert budget.used == 2048, budget.used


def test_tar_names_reports_a_tar_cut_right_after_a_member():
    cut = _member_only(_tar_of("ok.js", b"ok = 1\n"))

    with pytest.raises(tar_listing.TarCutShort) as raised:
        tar_listing.tar_names(io.BytesIO(cut))

    assert raised.value.offset == 1024


def test_tar_names_lists_a_whole_tar_as_before():
    whole = _tar_of("ok.js", b"ok = 1\n")

    assert tar_listing.tar_names(io.BytesIO(whole)) == ["ok.js"]
