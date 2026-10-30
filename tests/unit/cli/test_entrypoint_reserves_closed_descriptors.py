# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A standard descriptor closed at startup is held, and the raw floor skips it.

``ensure_std_streams`` reattaches a stream only where a descriptor is open. A
descriptor that is closed outright (``EBADF``) got no stream and was left free,
so the next file ASH opened anywhere could be handed descriptor 1 or 2, and from
then on everything writing to that number -- the last-resort ``os.write`` floor,
a child's inherited stderr -- wrote into that file. The entry point now holds
such a descriptor with ``os.devnull`` and records it, and ``_write_raw`` never
writes to a recorded one: nothing is reading it.

The descriptors here are never really closed; the probes the entry point reads
them through are stood in for, and the ``os`` calls that would hold one record
what they were asked.
"""

from __future__ import annotations

import os
import sys

import pytest

from automated_security_helper.cli import entrypoint

pytestmark = pytest.mark.unit

NULL_FD = 977


def _recording_write(written: list[int]):
    """An ``os.write`` stand-in that records the descriptor and answers as the
    real call does: the count of bytes written, the whole payload.

    The raw floor repeats ``os.write`` until its counts cover the text
    (``payload = payload[os.write(fd, payload):]``). A stand-in that answered
    None left the payload whole on every turn, so the floor never returned, and
    the record grew one entry per turn until the test process was killed for its
    memory.
    """

    def write(fd: int, payload: bytes) -> int:
        written.append(fd)
        return len(payload)

    return write


@pytest.fixture
def no_reservations(monkeypatch):
    monkeypatch.setattr(entrypoint, "_RESERVED_DESCRIPTORS", set())
    # ensure_std_streams records a descriptor it could not reattach in
    # _CLOSED_AT_START as well; patched too, so the tests that call it with
    # sys.stderr None leave no 2 behind for the raw floor's other tests to read
    # (test_startup_failure_diagnosability's raw write to descriptor 2).
    monkeypatch.setattr(entrypoint, "_CLOSED_AT_START", set())
    return entrypoint._RESERVED_DESCRIPTORS


@pytest.fixture
def recorded_os(monkeypatch):
    """The entry point's os calls on the null device as records, not actions.

    Only those: pytest's own capture moves descriptors 1 and 2 with ``os.dup2``
    around the test body, and those calls must still happen and are not the
    entry point's. A call that names NULL_FD, the descriptor the stand-in null
    device "opens", is the entry point's; every other call is passed through.
    """
    calls: list[tuple] = []
    real_open, real_dup2, real_close = os.open, os.dup2, os.close
    real_set_inheritable = os.set_inheritable

    def fake_set_inheritable(fd, inheritable):
        # The entry point's own hold on 0, 1 or 2 is recorded and NOT applied
        # (the real descriptor is pytest's); any other call passes through.
        if fd in (0, 1, 2):
            calls.append(("inheritable", fd, inheritable))
            return None
        return real_set_inheritable(fd, inheritable)

    def fake_open(path, flags, *args, **kwargs):
        if path == os.devnull:
            calls.append(("open", path, flags))
            return NULL_FD
        return real_open(path, flags, *args, **kwargs)

    def fake_dup2(src, dst, *args, **kwargs):
        if src == NULL_FD:
            calls.append(("dup2", src, dst))
            return dst
        return real_dup2(src, dst, *args, **kwargs)

    def fake_close(fd):
        if fd == NULL_FD:
            calls.append(("close", fd))
            return None
        return real_close(fd)

    monkeypatch.setattr(os, "open", fake_open)
    monkeypatch.setattr(os, "dup2", fake_dup2)
    monkeypatch.setattr(os, "close", fake_close)
    monkeypatch.setattr(os, "set_inheritable", fake_set_inheritable)
    return calls


def test_a_closed_stderr_is_held_with_the_null_device(
    monkeypatch, no_reservations, recorded_os
):
    monkeypatch.setattr(sys, "stderr", None)
    monkeypatch.setattr(entrypoint, "_reattach", lambda fd: None)
    monkeypatch.setattr(entrypoint, "_descriptor_is_closed", lambda fd: fd == 2)

    repaired = entrypoint.ensure_std_streams()

    assert repaired == (), repaired
    assert recorded_os == [
        ("open", os.devnull, os.O_WRONLY),
        ("dup2", NULL_FD, 2),
        ("close", NULL_FD),
        ("inheritable", 2, True),
    ], recorded_os
    assert no_reservations == {2}


def test_a_closed_stdin_is_held_for_reading(monkeypatch, no_reservations, recorded_os):
    """`ash 0<&-`: left free, the next file ASH opened would become descriptor 0
    and every child that inherits stdin would read from it."""
    monkeypatch.setattr(sys, "stdin", None)
    monkeypatch.setattr(entrypoint, "_descriptor_is_closed", lambda fd: fd == 0)

    repaired = entrypoint.ensure_std_streams()

    assert repaired == (), repaired
    assert recorded_os == [
        ("open", os.devnull, os.O_RDONLY),
        ("dup2", NULL_FD, 0),
        ("close", NULL_FD),
        ("inheritable", 0, True),
    ], recorded_os
    assert no_reservations == {0}
    # No stream is attached for a held stdin.
    assert sys.stdin is None


def test_an_unattached_but_open_descriptor_is_not_held(
    monkeypatch, no_reservations, recorded_os
):
    """The control: a descriptor that is open but has no stream is left as it was."""
    monkeypatch.setattr(sys, "stderr", None)
    monkeypatch.setattr(entrypoint, "_reattach", lambda fd: None)
    monkeypatch.setattr(entrypoint, "_descriptor_is_closed", lambda fd: False)

    entrypoint.ensure_std_streams()

    assert recorded_os == [], recorded_os
    assert no_reservations == set()


def test_the_null_device_handed_the_descriptor_itself_stays_open(
    monkeypatch, no_reservations, recorded_os
):
    """When the closed number is the lowest free one, os.open returns it."""
    real_open = os.open
    monkeypatch.setattr(
        os,
        "open",
        lambda path, flags, *a, **k: (
            2 if path == os.devnull else real_open(path, flags, *a, **k)
        ),
    )

    assert entrypoint._reserve_descriptor(2) is True
    # No dup2, no close; the descriptor the null device took is made inheritable,
    # as os.open hands out a non-inheritable one (PEP 446).
    assert recorded_os == [("inheritable", 2, True)], recorded_os


def test_a_held_descriptor_is_reported_held_though_inheritance_fails(
    monkeypatch, no_reservations, recorded_os
):
    """The descriptor is open on the null device once dup2 returned; a failure
    to make it inheritable does not unhold it, and False said it was not held."""

    def refusing_set_inheritable(fd, inheritable):
        raise OSError("not permitted")

    monkeypatch.setattr(os, "set_inheritable", refusing_set_inheritable)

    assert entrypoint._reserve_descriptor(2) is True
    assert recorded_os == [
        ("open", os.devnull, os.O_WRONLY),
        ("dup2", NULL_FD, 2),
        ("close", NULL_FD),
    ], recorded_os


def test_a_descriptor_closed_at_startup_is_recorded_though_the_hold_fails(
    monkeypatch, no_reservations
):
    """With no null device to open (a bare container, a sandbox policy) the
    number stays free, so the raw floor must still never write to it."""
    monkeypatch.setattr(sys, "stderr", None)
    monkeypatch.setattr(entrypoint, "_reattach", lambda fd: None)
    monkeypatch.setattr(entrypoint, "_descriptor_is_closed", lambda fd: fd == 2)
    monkeypatch.setattr(entrypoint, "_reserve_descriptor", lambda fd: False)
    written: list[int] = []
    monkeypatch.setattr(os, "write", _recording_write(written))

    entrypoint.ensure_std_streams()

    assert no_reservations == {2}
    assert entrypoint._write_raw("report") is True
    assert written == [1], written


def test_the_raw_floor_skips_a_held_descriptor(monkeypatch, no_reservations):
    written: list[int] = []
    monkeypatch.setattr(os, "write", _recording_write(written))
    no_reservations.add(2)

    assert entrypoint._write_raw("report") is True
    assert written == [1], written


def test_the_raw_floor_reports_nothing_reached_when_both_are_held(
    monkeypatch, no_reservations
):
    written: list[int] = []
    monkeypatch.setattr(os, "write", _recording_write(written))
    no_reservations.update({1, 2})

    assert entrypoint._write_raw("report") is False
    assert written == [], written


def test_a_closed_descriptor_reads_as_closed():
    """The probe itself, on a descriptor this test opened and then closed."""
    fd = os.open(os.devnull, os.O_WRONLY)
    try:
        assert entrypoint._descriptor_is_closed(fd) is False
    finally:
        os.close(fd)
    assert entrypoint._descriptor_is_closed(fd) is True
