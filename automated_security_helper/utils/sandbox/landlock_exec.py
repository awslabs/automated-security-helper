"""Restrict this process with Landlock and seccomp, then exec a scanner.

Run as ``python -I landlock_exec.py --policy JSON -- argv...``. Standard library only,
and deliberately not imported by ASH: it runs as a separate interpreter so the
restrictions apply to it and everything it execs, and to nothing in ASH.

``--abi`` prints the kernel's Landlock ABI version and exits 0, or exits 1 when
Landlock is unavailable.

Filesystem: Landlock rules grant read and execute beneath ``read_only`` and full access
beneath ``writable``; every other path is denied. Sockets: a seccomp filter makes
``socket(AF_UNIX)`` fail with EACCES and ``io_uring_setup`` with ENOSYS always (see
``apply_socket_seccomp``), and ``socket()`` fail for every family when the policy has
no network. Landlock's own network rules cover TCP only, so they are added on ABI 4+
as a second layer, not relied on. ABI 6+ also scopes abstract Unix sockets and signals.

Any failure to apply a restriction is fatal (exit 126): this program never execs the
scanner with less confinement than it was asked for.
"""

import ctypes
import errno
import json
import os
import platform
import signal
import stat
import struct
import time
import sys
from typing import Any, Callable, Dict, List, NoReturn

SYS_LANDLOCK_CREATE_RULESET = 444
SYS_LANDLOCK_ADD_RULE = 445
SYS_LANDLOCK_RESTRICT_SELF = 446
LANDLOCK_CREATE_RULESET_VERSION = 1
LANDLOCK_RULE_PATH_BENEATH = 1

FS_EXECUTE = 1 << 0
FS_WRITE_FILE = 1 << 1
FS_READ_FILE = 1 << 2
FS_READ_DIR = 1 << 3
FS_REMOVE_DIR = 1 << 4
FS_REMOVE_FILE = 1 << 5
FS_MAKE_CHAR = 1 << 6
FS_MAKE_DIR = 1 << 7
FS_MAKE_REG = 1 << 8
FS_MAKE_SOCK = 1 << 9
FS_MAKE_FIFO = 1 << 10
FS_MAKE_BLOCK = 1 << 11
FS_MAKE_SYM = 1 << 12
FS_REFER = 1 << 13  # ABI 2
FS_TRUNCATE = 1 << 14  # ABI 3
FS_IOCTL_DEV = 1 << 15  # ABI 5
NET_BIND_TCP = 1 << 0  # ABI 4
NET_CONNECT_TCP = 1 << 1
SCOPE_ABSTRACT_UNIX_SOCKET = 1 << 0  # ABI 6
SCOPE_SIGNAL = 1 << 1

FILE_ONLY_RIGHTS = (
    FS_EXECUTE | FS_WRITE_FILE | FS_READ_FILE | FS_TRUNCATE | FS_IOCTL_DEV
)

PR_SET_NO_NEW_PRIVS = 38
PR_SET_CHILD_SUBREAPER = 36
#: How long the wrapper keeps reaping after its scanner exits. Below ASH's
#: SANDBOX_STOP_GRACE_SECONDS (10), so the wrapper finishes before ASH gives up on it.
REAP_DEADLINE_SECONDS = 5.0
# prctl(PR_SET_SECCOMP) rather than seccomp(2): the syscall number differs per arch.
PR_SET_SECCOMP = 22
SECCOMP_MODE_FILTER = 2

# seccomp-bpf
BPF_LD_W_ABS = 0x20
BPF_JMP_JEQ_K = 0x15
BPF_JMP_JGE_K = 0x35
BPF_RET_K = 0x06
SECCOMP_RET_ALLOW = 0x7FFF0000
SECCOMP_RET_ERRNO = 0x00050000
SECCOMP_RET_KILL_PROCESS = 0x80000000
SECCOMP_DATA_NR = 0
SECCOMP_DATA_ARCH = 4
SECCOMP_DATA_ARG0 = 16  # low 32 bits on little-endian
AF_UNIX = 1

# (audit arch, socket nr, io_uring_setup nr, x32 bit or None)
ARCHES = {
    "x86_64": (0xC000003E, 41, 425, 0x40000000),
    "aarch64": (0xC00000B7, 198, 425, None),
    "arm64": (0xC00000B7, 198, 425, None),
}

libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long


def fail(message: str) -> NoReturn:
    sys.stderr.write(f"ash-landlock: {message}\n")
    sys.exit(126)


def abi_version() -> int:
    version = libc.syscall(
        SYS_LANDLOCK_CREATE_RULESET,
        None,
        ctypes.c_size_t(0),
        LANDLOCK_CREATE_RULESET_VERSION,
    )
    return max(0, version)


def fs_rights_for(abi: int) -> int:
    rights = (1 << 13) - 1
    if abi >= 2:
        rights |= FS_REFER
    if abi >= 3:
        rights |= FS_TRUNCATE
    if abi >= 5:
        rights |= FS_IOCTL_DEV
    return rights


def add_path_rule(ruleset_fd: int, path: str, access: int) -> None:
    try:
        fd = os.open(path, os.O_PATH | os.O_CLOEXEC)
    except FileNotFoundError:
        return
    except OSError as e:
        fail(f"cannot open {path}: {e}")
    try:
        if not stat.S_ISDIR(os.fstat(fd).st_mode):
            access &= FILE_ONLY_RIGHTS
        if not access:
            return
        attr = struct.pack("=Qi", access, fd)
        buf = ctypes.create_string_buffer(attr, len(attr))
        rc = libc.syscall(
            SYS_LANDLOCK_ADD_RULE, ruleset_fd, LANDLOCK_RULE_PATH_BENEATH, buf, 0
        )
        if rc != 0:
            fail(f"landlock_add_rule({path}): {os.strerror(ctypes.get_errno())}")
    finally:
        os.close(fd)


def apply_landlock(policy: Dict[str, Any], abi: int) -> None:
    handled_fs = fs_rights_for(abi)
    handled_net = (
        (NET_BIND_TCP | NET_CONNECT_TCP) if (abi >= 4 and not policy["network"]) else 0
    )
    scoped = (SCOPE_ABSTRACT_UNIX_SOCKET | SCOPE_SIGNAL) if abi >= 6 else 0
    if abi >= 6:
        attr = struct.pack("=QQQ", handled_fs, handled_net, scoped)
    elif abi >= 4:
        attr = struct.pack("=QQ", handled_fs, handled_net)
    else:
        attr = struct.pack("=Q", handled_fs)
    buf = ctypes.create_string_buffer(attr, len(attr))
    ruleset_fd = libc.syscall(
        SYS_LANDLOCK_CREATE_RULESET, buf, ctypes.c_size_t(len(attr)), 0
    )
    if ruleset_fd < 0:
        fail(f"landlock_create_ruleset: {os.strerror(ctypes.get_errno())}")
    read_rights = FS_EXECUTE | FS_READ_FILE | FS_READ_DIR
    for path in policy["read_only"]:
        add_path_rule(ruleset_fd, path, read_rights)
    for path in policy["writable"]:
        add_path_rule(ruleset_fd, path, handled_fs)
    if libc.syscall(SYS_LANDLOCK_RESTRICT_SELF, ruleset_fd, 0) != 0:
        fail(f"landlock_restrict_self: {os.strerror(ctypes.get_errno())}")
    os.close(ruleset_fd)


class SockFilter(ctypes.Structure):
    _fields_ = [
        ("code", ctypes.c_ushort),
        ("jt", ctypes.c_ubyte),
        ("jf", ctypes.c_ubyte),
        ("k", ctypes.c_uint),
    ]


class SockFprog(ctypes.Structure):
    _fields_ = [("len", ctypes.c_ushort), ("filter", ctypes.POINTER(SockFilter))]


def apply_socket_seccomp(network: bool) -> None:
    """Refuse socket creation the filesystem rules cannot see.

    Landlock does not mediate connect() on a Unix-domain socket path, so a
    sandboxed process that could create an AF_UNIX socket could talk to the Docker
    socket or the session bus whatever the filesystem rules say. socket(AF_UNIX) is
    therefore refused always; socketpair(), which tools use for pipes, is a separate
    syscall and stays allowed. Without a network, socket() is refused for every
    family. io_uring_setup is refused always, because io_uring can create sockets
    without the socket syscall.
    """
    machine = platform.machine().lower()
    if machine not in ARCHES:
        fail(f"no seccomp socket filter for architecture {machine}")
    audit_arch, nr_socket, nr_io_uring_setup, x32_bit = ARCHES[machine]
    refuse = SECCOMP_RET_ERRNO | errno.EACCES
    prog = [
        (BPF_LD_W_ABS, 0, 0, SECCOMP_DATA_ARCH),
        (BPF_JMP_JEQ_K, 1, 0, audit_arch),
        (BPF_RET_K, 0, 0, SECCOMP_RET_KILL_PROCESS),
        (BPF_LD_W_ABS, 0, 0, SECCOMP_DATA_NR),
    ]
    if x32_bit is not None:
        # x32 syscalls carry the same numbers with this bit set; refuse them outright.
        prog += [
            (BPF_JMP_JGE_K, 0, 1, x32_bit),
            (BPF_RET_K, 0, 0, SECCOMP_RET_KILL_PROCESS),
        ]
    # ENOSYS rather than EACCES for io_uring: runtimes that use it when it exists
    # (semgrep-core's OCaml Eio) fall back to plain syscalls on "not implemented"
    # and abort on "permission denied".
    prog += [
        (BPF_JMP_JEQ_K, 0, 1, nr_io_uring_setup),
        (BPF_RET_K, 0, 0, SECCOMP_RET_ERRNO | errno.ENOSYS),
    ]
    if network:
        prog += [
            (BPF_JMP_JEQ_K, 0, 3, nr_socket),
            (BPF_LD_W_ABS, 0, 0, SECCOMP_DATA_ARG0),
            (BPF_JMP_JEQ_K, 0, 1, AF_UNIX),
            (BPF_RET_K, 0, 0, refuse),
        ]
    else:
        prog += [
            (BPF_JMP_JEQ_K, 0, 1, nr_socket),
            (BPF_RET_K, 0, 0, refuse),
        ]
    prog += [(BPF_RET_K, 0, 0, SECCOMP_RET_ALLOW)]
    filters = (SockFilter * len(prog))(*[SockFilter(*ins) for ins in prog])
    fprog = SockFprog(len(prog), filters)
    if libc.prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, ctypes.byref(fprog), 0, 0) != 0:
        fail(f"installing the seccomp socket filter: {os.strerror(ctypes.get_errno())}")


def main(argv: List[str]) -> int:
    if argv[:1] == ["--abi"]:
        abi = abi_version()
        if abi <= 0:
            sys.stderr.write(
                "Landlock is not supported or not enabled (add 'landlock' to the lsm= "
                "kernel parameter)\n"
            )
            return 1
        print(abi)
        return 0
    if len(argv) < 4 or argv[0] != "--policy" or argv[2] != "--":
        fail("usage: landlock_exec.py --policy JSON -- argv...")
    policy = json.loads(argv[1])
    command = argv[3:]
    abi = abi_version()
    if abi <= 0:
        fail("Landlock is not supported or not enabled on this kernel")

    def restrict() -> None:
        # In the child only. The wrapper stays outside the scanner's Landlock
        # domain, so on ABI 6+ the scanner cannot signal it (LANDLOCK_SCOPE_SIGNAL)
        # and cannot stop it from reaping what it leaves behind.
        if libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
            fail(f"prctl(PR_SET_NO_NEW_PRIVS): {os.strerror(ctypes.get_errno())}")
        apply_landlock(policy, abi)
        apply_socket_seccomp(bool(policy["network"]))

    return run_and_reap(command, restrict)


def _children(pid: int = 0) -> List[int]:
    """Processes whose parent is ``pid`` (this process when 0).

    /proc/self/task/*/children when the kernel provides it (CONFIG_PROC_CHILDREN),
    which costs one read per thread; otherwise every /proc/<pid>/stat, which on a
    host with thousands of processes costs a few hundred milliseconds. Read as
    bytes: a text open may need to import a codec, and after Landlock the
    interpreter's own library is not necessarily readable.
    """
    found: List[int] = []
    try:
        base = f"/proc/{pid}" if pid else "/proc/self"
        tasks = os.listdir(f"{base}/task")
        for tid in tasks:
            with open(f"{base}/task/{tid}/children", "rb") as f:
                found += [int(pid) for pid in f.read().split()]
        return found
    except OSError:
        pass
    me = str(pid or os.getpid()).encode()
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        try:
            with open(f"/proc/{entry}/stat", "rb") as f:
                fields = f.read().rsplit(b")", 1)[1].split()
        except (OSError, IndexError):
            continue
        if len(fields) > 1 and fields[1] == me:
            found.append(int(entry))
    return found


def _descendants() -> List[int]:
    """Every process below this one, at any depth, breadth first."""
    found: List[int] = []
    frontier = _children()
    while frontier:
        found += frontier
        frontier = [grandchild for child in frontier for grandchild in _children(child)]
    return found


def run_and_reap(command: List[str], restrict: Callable[[], None]) -> int:
    """Run the scanner and, once it exits, kill whatever it left running.

    Unlike bwrap's PID namespace, Landlock does not end a process's descendants
    with it. A process the scanner left behind could keep writing in the results
    directory after ASH has swept it, so this wrapper stays as a child subreaper
    (orphans are reparented to it, however they detached) and kills them all
    before it exits with the scanner's status. SIGTERM, SIGINT or SIGHUP to the
    wrapper (ASH sends SIGTERM on a timeout) kills the scanner and then everything
    it left, the same way.
    """
    if libc.prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) != 0:
        fail(f"prctl(PR_SET_CHILD_SUBREAPER): {os.strerror(ctypes.get_errno())}")
    stop_signals = {signal.SIGTERM, signal.SIGINT, signal.SIGHUP}
    # Blocked across the fork, so a signal that arrives before the handler is in
    # place is held rather than killing the wrapper and orphaning the scanner.
    signal.pthread_sigmask(signal.SIG_BLOCK, stop_signals)
    pid = os.fork()
    if pid == 0:
        try:
            signal.pthread_sigmask(signal.SIG_UNBLOCK, stop_signals)
            # A new session has no controlling terminal, so the scanner cannot
            # push keystrokes into the user's shell through TIOCSTI.
            os.setsid()
            restrict()
            os.execve(command[0], command, os.environ)
        except OSError as e:
            sys.stderr.write(f"ash-landlock: exec {command[0]}: {e}\n")
        except BaseException:  # noqa: BLE001 - fail() raises SystemExit
            pass
        # Whatever happened, the child never returns into the wrapper's code; a
        # restriction that failed leaves it here, unrestricted, so it exits.
        os._exit(126)

    def stop(_signum: int, _frame: object) -> None:
        # ASH asks the wrapper to stop (a timeout, Ctrl-C): end the scanner now,
        # and the loop below ends everything it started.
        try:
            os.kill(pid, signal.SIGKILL)
        except OSError:
            pass

    for signum in stop_signals:
        signal.signal(signum, stop)
    signal.pthread_sigmask(signal.SIG_UNBLOCK, stop_signals)
    while True:
        try:
            _, status = os.waitpid(pid, 0)
            break
        except InterruptedError:
            continue
    # An orphan is reparented here only once its own parent has exited, which can
    # trail the scanner's exit, so "no children" has to hold for a short while.
    # Every pass kills the whole remaining tree at once, so depth costs nothing;
    # bounded by time rather than by a pass count, and well inside the grace ASH
    # gives a stopping process before it SIGKILLs this wrapper.
    quiet = 0
    deadline = time.monotonic() + REAP_DEADLINE_SECONDS
    while time.monotonic() < deadline:
        leftovers = _descendants()
        if not leftovers:
            quiet += 1
            if quiet >= 5:
                break
            time.sleep(0.01)
            continue
        quiet = 0
        for child in leftovers:
            try:
                os.kill(child, signal.SIGKILL)
            except OSError:
                pass
        while True:
            try:
                reaped, _ = os.waitpid(-1, os.WNOHANG)
            except ChildProcessError:
                break
            if reaped == 0:
                break
    if os.WIFSIGNALED(status):
        # Die of the same signal, so ASH sees -N exactly as it would for the
        # scanner run unwrapped. 128+N is the fallback for a signal that cannot be
        # re-raised that way.
        died_of = os.WTERMSIG(status)
        try:
            if died_of not in (signal.SIGKILL, signal.SIGSTOP):
                # SIGKILL and SIGSTOP cannot be caught, so need no reset.
                signal.signal(died_of, signal.SIG_DFL)
                signal.pthread_sigmask(signal.SIG_UNBLOCK, {died_of})
            os.kill(os.getpid(), died_of)
        except (OSError, ValueError):
            pass
        return 128 + died_of
    return os.WEXITSTATUS(status)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
