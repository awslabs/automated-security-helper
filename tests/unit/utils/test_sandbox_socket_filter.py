# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The seccomp socket filter every Linux backend starts its scanner under.

``landlock_exec.socket_filter`` builds the program; Landlock applies it in its
wrapper, and bwrap and firejail run the scanner through ``--socket-filter``. The
program is checked here by running it through a small classic-BPF interpreter for
every architecture in ``ARCHES``, so the aarch64 program is tested on an x86_64
runner too, and then installed for real on this machine.
"""

import errno
import struct
import subprocess  # nosec B404 - runs the filter under test
import sys
import textwrap

import pytest

if sys.platform == "win32":
    pytest.skip("the socket filter is Linux-only", allow_module_level=True)

from automated_security_helper.utils.sandbox import landlock_exec as le  # noqa: E402

AF_UNIX, AF_INET, AF_INET6 = 1, 2, 10
SOCK_STREAM, SOCK_DGRAM, SOCK_RAW, SOCK_SEQPACKET = 1, 2, 3, 5
SOCK_NONBLOCK, SOCK_CLOEXEC = 0o4000, 0o2000000
ALLOW = le.SECCOMP_RET_ALLOW
KILL = le.SECCOMP_RET_KILL_PROCESS
EACCES = le.SECCOMP_RET_ERRNO | errno.EACCES
ENOSYS = le.SECCOMP_RET_ERRNO | errno.ENOSYS

#: From the kernel's syscall tables (arch/x86/entry/syscalls/syscall_64.tbl and
#: include/uapi/asm-generic/unistd.h, which arm64 uses) and include/uapi/linux/audit.h.
#: Pinned here rather than read back from ARCHES, so a wrong number in ARCHES fails.
KERNEL = {
    "x86_64": {
        "audit_arch": 0xC000003E,
        "foreign_arch": 0x40000003,  # AUDIT_ARCH_I386, the int 0x80 entry
        "socket": 41,
        "socketpair": 53,
        "connect": 42,
        "sendto": 44,
        "io_uring_setup": 425,
    },
    "aarch64": {
        "audit_arch": 0xC00000B7,
        "foreign_arch": 0x40000028,  # AUDIT_ARCH_ARM, 32-bit compat
        "socket": 198,
        "socketpair": 199,
        "connect": 203,
        "sendto": 206,
        "io_uring_setup": 425,
    },
}


def _run(program, arch: int, nr: int, *args: int) -> int:
    """Evaluate ``program`` on one syscall the way the kernel does, return its verdict.

    struct seccomp_data: int nr; __u32 arch; __u64 instruction_pointer; __u64 args[6].
    """
    padded = (list(args) + [0] * 6)[:6]
    data = struct.pack("=II7Q", nr & 0xFFFFFFFF, arch, 0, *padded)
    acc, pc = 0, 0
    while True:
        code, jt, jf, k = program[pc]
        if code == le.BPF_LD_W_ABS:
            acc = struct.unpack_from("=I", data, k)[0]
            pc += 1
        elif code == le.BPF_ALU_AND_K:
            acc &= k
            pc += 1
        elif code == le.BPF_JMP_JEQ_K:
            pc += 1 + (jt if acc == k else jf)
        elif code == le.BPF_JMP_JGE_K:
            pc += 1 + (jt if acc >= k else jf)
        elif code == le.BPF_RET_K:
            return k
        else:
            raise AssertionError(f"instruction {code:#x} at {pc} is not interpreted")


@pytest.mark.parametrize("machine", sorted(KERNEL))
def test_the_architecture_table_matches_the_kernel(machine):
    kernel = KERNEL[machine]
    audit_arch, nr_socket, nr_socketpair, nr_io_uring_setup, _ = le.ARCHES[machine]
    assert audit_arch == kernel["audit_arch"]
    assert nr_socket == kernel["socket"]
    assert nr_socketpair == kernel["socketpair"]
    assert nr_io_uring_setup == kernel["io_uring_setup"]
    # platform.machine() says arm64 on some systems for the same architecture.
    assert le.ARCHES["arm64"] == le.ARCHES["aarch64"]


@pytest.mark.parametrize("machine", sorted(KERNEL))
@pytest.mark.parametrize("network", [False, True])
def test_the_program_is_one_the_kernel_accepts(machine, network):
    program = le.socket_filter(machine, network)
    assert 0 < len(program) <= 4096
    assert program[-1][0] == le.BPF_RET_K
    for pc, (code, jt, jf, k) in enumerate(program):
        if code in (le.BPF_JMP_JEQ_K, le.BPF_JMP_JGE_K):
            assert pc + 1 + max(jt, jf) < len(program), f"jump out of range at {pc}"
        if code == le.BPF_LD_W_ABS:
            # Aligned 32-bit loads inside struct seccomp_data (64 bytes).
            assert k % 4 == 0 and k < 64, f"bad load offset {k} at {pc}"


@pytest.mark.parametrize("machine", sorted(KERNEL))
@pytest.mark.parametrize("network", [False, True])
def test_unix_sockets_are_refused_and_pipes_are_not(machine, network):
    kernel = KERNEL[machine]
    program = le.socket_filter(machine, network)

    def verdict(name, *args):
        return _run(program, kernel["audit_arch"], kernel[name], *args)

    assert verdict("socket", AF_UNIX, SOCK_STREAM) == EACCES
    assert verdict("socket", AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC) == EACCES
    # The pairs tools use for pipes: connected at birth, so connect() fails with
    # EISCONN and a seqpacket send ignores the address it is given.
    assert verdict("socketpair", AF_UNIX, SOCK_STREAM, 0) == ALLOW
    assert verdict("socketpair", AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0) == ALLOW
    assert verdict("socketpair", AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK, 0) == ALLOW
    # A datagram socket can sendto() or connect() any datagram socket by path.
    # The kernel makes a Unix SOCK_RAW a datagram socket.
    assert verdict("socketpair", AF_UNIX, SOCK_DGRAM, 0) == EACCES
    assert verdict("socketpair", AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0) == EACCES
    assert verdict("socketpair", AF_UNIX, SOCK_RAW, 0) == EACCES
    # The kernel reads the type as an int, and so does the filter.
    assert verdict("socketpair", AF_UNIX, (0xFFFFFFFF << 32) | SOCK_STREAM, 0) == ALLOW
    assert verdict("io_uring_setup", 8, 0) == ENOSYS
    # Nothing else is the filter's business: an IP socket is decided by the
    # network rule below, and connect/sendto by what socket the caller holds.
    assert verdict("connect", 3, 0, 16) == ALLOW
    assert verdict("sendto", 3, 0, 4, 0, 0, 16) == ALLOW
    expected_ip = ALLOW if network else EACCES
    assert verdict("socket", AF_INET, SOCK_STREAM) == expected_ip
    assert verdict("socket", AF_INET6, SOCK_DGRAM) == expected_ip


@pytest.mark.parametrize("machine", sorted(KERNEL))
def test_other_syscall_conventions_are_killed(machine):
    """The numbers above mean other syscalls under another ABI, so it is refused."""
    kernel = KERNEL[machine]
    program = le.socket_filter(machine, True)
    assert _run(program, kernel["foreign_arch"], kernel["socket"], AF_UNIX) == KILL
    if machine == "x86_64":
        x32_socket = kernel["socket"] | 0x40000000
        assert _run(program, kernel["audit_arch"], x32_socket, AF_UNIX) == KILL


_CHILD = textwrap.dedent(
    """
    import json, socket
    out = {}
    def attempt(name, fn):
        try:
            fn()
            out[name] = "ok"
        except OSError as e:
            out[name] = e.errno
    attempt("unix", lambda: socket.socket(socket.AF_UNIX).close())
    attempt("inet", lambda: socket.socket(socket.AF_INET).close())
    def pair(kind):
        a, b = socket.socketpair(socket.AF_UNIX, kind)
        a.sendall(b"x")
        assert b.recv(1) == b"x"
        a.close(); b.close()
    attempt("pair_stream", lambda: pair(socket.SOCK_STREAM))
    attempt("pair_seqpacket", lambda: pair(socket.SOCK_SEQPACKET))
    attempt("pair_dgram", lambda: socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM))
    print(json.dumps(out))
    """
)


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="seccomp is Linux")
@pytest.mark.parametrize(("mode", "inet"), [("unix", "ok"), ("all", errno.EACCES)])
def test_the_installed_filter_behaves_as_the_program_says(mode, inet):
    """``--socket-filter`` installs the program on this machine and execs argv."""
    import json
    import platform

    if platform.machine().lower() not in le.ARCHES:
        pytest.skip(f"no socket filter for {platform.machine()}")
    result = subprocess.run(  # nosec B603 - fixed argv
        [
            sys.executable,
            "-I",
            le.__file__,
            "--socket-filter",
            mode,
            "--",
            sys.executable,
            "-I",
            "-c",
            _CHILD,
        ],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == {
        "unix": errno.EACCES,
        "inet": inet,
        "pair_stream": "ok",
        "pair_seqpacket": "ok",
        "pair_dgram": errno.EACCES,
    }


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="seccomp is Linux")
def test_a_malformed_socket_filter_request_runs_nothing():
    result = subprocess.run(  # nosec B603 - fixed argv
        [sys.executable, "-I", le.__file__, "--socket-filter", "none", "--", "true"],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert result.returncode == 126
    assert "usage" in result.stderr
