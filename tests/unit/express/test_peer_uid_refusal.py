# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The daemon's peer check fails closed, and only the daemon's own uid passes.

The kernel's answer (``SO_PEERCRED`` on Linux, ``LOCAL_PEERCRED`` on macOS) is
the only input -- never anything the peer sent -- and every way of not having
it (neither option on the platform, a getsockopt that raises, a malformed or
wrong-version answer) reads as "not this user". No real socket is opened and
no platform facility is assumed: the check's input is the getsockopt result,
so a stand-in socket object and a forced branch exercise both kernels' shapes
on any OS the unit tier runs on, Windows included (which is also why nothing
here calls ``os.getuid``: the uids are explicit).
"""

import socket
import struct
import sys

import pytest

from automated_security_helper.express import runtime

pytestmark = pytest.mark.unit


class _FakeSock:
    """A stand-in with the one method ``peer_uid`` reads."""

    def __init__(self, answer=None, error=None):
        self._answer = answer
        self._error = error
        self.asked = []

    def getsockopt(self, level, option, buflen):
        self.asked.append((level, option, buflen))
        if self._error is not None:
            raise self._error
        return self._answer


def _ucred(pid: int, uid: int, gid: int) -> bytes:
    return struct.pack(runtime._UCRED_FORMAT, pid, uid, gid)


def _xucred(version: int, uid: int) -> bytes:
    head = struct.pack(runtime._XUCRED_HEAD_FORMAT, version, uid)
    return head + b"\x00" * (runtime._XUCRED_SIZE - len(head))


@pytest.fixture
def linux_branch(monkeypatch):
    """Force the Linux read, whatever this host is."""
    monkeypatch.setattr(socket, "SO_PEERCRED", 17, raising=False)


@pytest.fixture
def darwin_branch(monkeypatch):
    """Force the macOS read, whatever this host is."""
    monkeypatch.delattr(socket, "SO_PEERCRED", raising=False)
    monkeypatch.setattr(sys, "platform", "darwin")


class TestPeerUidLinux:
    def test_the_kernel_answer_is_read_as_pid_uid_gid(self, linux_branch):
        sock = _FakeSock(answer=_ucred(1234, 4321, 100))
        assert runtime.peer_uid(sock) == 4321
        level, _, buflen = sock.asked[0]
        assert level == socket.SOL_SOCKET
        assert buflen == struct.calcsize(runtime._UCRED_FORMAT)

    def test_a_directory_service_uid_above_two_to_the_31_reads_unsigned(
        self, linux_branch
    ):
        """An SSSD/AD id-mapped uid is >= 2**31; read through a signed format
        it came back negative and the daemon refused its own user."""
        big = 2**31 + 12345
        sock = _FakeSock(answer=_ucred(1, big, 1))
        assert runtime.peer_uid(sock) == big
        assert runtime.peer_is_this_user(sock, uid=big)

    def test_a_getsockopt_failure_reads_as_unreadable(self, linux_branch):
        assert runtime.peer_uid(_FakeSock(error=OSError("no peer"))) is None

    def test_a_malformed_answer_reads_as_unreadable(self, linux_branch):
        assert runtime.peer_uid(_FakeSock(answer=b"\x01\x02")) is None


class TestPeerUidDarwin:
    def test_the_xucred_answer_is_read_as_version_and_uid(self, darwin_branch):
        sock = _FakeSock(answer=_xucred(runtime._XUCRED_VERSION, 501))
        assert runtime.peer_uid(sock) == 501
        level, option, buflen = sock.asked[0]
        assert (level, option, buflen) == (0, runtime._LOCAL_PEERCRED, 76)

    def test_an_unknown_xucred_version_reads_as_unreadable(self, darwin_branch):
        sock = _FakeSock(answer=_xucred(runtime._XUCRED_VERSION + 1, 501))
        assert runtime.peer_uid(sock) is None

    def test_a_getsockopt_failure_reads_as_unreadable(self, darwin_branch):
        assert runtime.peer_uid(_FakeSock(error=OSError("no peer"))) is None


class TestPeerUidNowhere:
    def test_a_platform_with_neither_option_reads_as_unreadable(self, monkeypatch):
        monkeypatch.delattr(socket, "SO_PEERCRED", raising=False)
        monkeypatch.setattr(sys, "platform", "sunos5")
        sock = _FakeSock(answer=_ucred(1, 1, 1))
        assert runtime.peer_uid(sock) is None
        assert sock.asked == [], "nothing may be asked without a known option"

    def test_express_supported_requires_a_peer_credential_read(self, monkeypatch):
        """A platform that cannot read peer uids has no express mode AT ALL:
        a daemon there would refuse every connection and look started while
        serving nothing, so the refusal happens up front instead."""
        monkeypatch.delattr(socket, "SO_PEERCRED", raising=False)
        monkeypatch.setattr(sys, "platform", "sunos5")
        assert not runtime.peer_credentials_supported()
        assert not runtime.express_supported()


class TestPeerIsThisUser:
    def test_the_same_uid_passes(self, linux_branch):
        sock = _FakeSock(answer=_ucred(1, 1000, 1))
        assert runtime.peer_is_this_user(sock, uid=1000)

    def test_another_uid_is_refused(self, linux_branch):
        sock = _FakeSock(answer=_ucred(1, 1001, 1))
        assert not runtime.peer_is_this_user(sock, uid=1000)

    def test_an_unreadable_peer_is_refused_not_trusted(self, linux_branch):
        """Fail closed: no answer from the kernel is a refusal, never a pass."""
        assert not runtime.peer_is_this_user(_FakeSock(error=OSError("nope")), uid=1000)

    def test_root_is_not_this_user_either(self, linux_branch):
        """uid 0 gets no special pass from the check itself; the comparison is
        equality, so only the daemon's own uid is served."""
        sock = _FakeSock(answer=_ucred(1, 0, 0))
        assert runtime.peer_is_this_user(sock, uid=1000) is False
