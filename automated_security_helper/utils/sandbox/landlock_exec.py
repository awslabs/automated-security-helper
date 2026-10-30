"""Restrict this process with Landlock and seccomp, then exec a scanner.

Run as ``python -I landlock_exec.py --policy JSON -- argv...``. Standard library only,
and deliberately not imported by ASH: it runs as a separate interpreter so the
restrictions apply to it and everything it execs, and to nothing in ASH.

``--abi`` prints the kernel's Landlock ABI version and exits 0, or exits 1 when
Landlock is unavailable.

``--socket-filter unix|all -- argv...`` applies only the seccomp filter (``unix``: the
filter a scanner with a network gets; ``all``: also refuse every ``socket()``) and execs
argv in place. The bwrap and firejail backends run the scanner through it inside
their sandbox: their mounts hide most socket paths, but not one that sits in a mounted
directory (the Nix daemon's socket is under /nix), and with a network the scanner shares
the host's network namespace and with it every abstract Unix socket bound there.

Filesystem: Landlock rules grant read and execute beneath ``read_only``, read alone
beneath ``read_data`` (the scan's own data, which nothing runs from) and full access
beneath ``writable``; every other path is denied. ``cwd``, when the policy names one,
is the directory the wrapper changes into before it runs the command (a spawn with
no working directory of its own). Sockets: a seccomp filter makes
``socket(AF_UNIX)`` and a datagram ``socketpair()`` fail with EACCES and
``io_uring_setup`` with ENOSYS always (see ``apply_socket_seccomp``), and ``socket()``
fail for every family when the policy has no network. Landlock's own network rules
cover TCP only, so they are added on ABI 4+ as a second layer, not relied on. ABI 6+
also scopes abstract Unix sockets and signals.

Any failure to apply a restriction is fatal (exit 126): this program never execs the
scanner with less confinement than it was asked for. So is any failure of the
wrapper's own before the scanner starts (a policy that is not the documented JSON
document, a fork that fails): exit 126 with an ``ash-landlock:`` line, never the
interpreter's traceback and exit 1, which many scanners use for "findings found".
"""

import ctypes
import errno
import json
import os
import platform
import re
import resource
import signal
import stat
import struct
import time
import sys
import unicodedata
from typing import Any, Callable, Dict, List, NoReturn, Optional, Set, Tuple

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
PR_SET_PDEATHSIG = 1
#: The signals that ask the wrapper to stop (ASH sends SIGTERM on a timeout).
STOP_SIGNALS = frozenset({signal.SIGTERM, signal.SIGINT, signal.SIGHUP})
#: The most /proc entries one fallback scan reads (``_parent_map``). A host can
#: carry tens of thousands of processes and each entry costs an open and a read,
#: so an unbounded scan could on its own outlast STOP_REAP_DEADLINE_SECONDS;
#: processes listed past this many are not seen by that scan.
PROC_SCAN_LIMIT = 4096
#: How long the wrapper keeps reaping after its scanner exits on its own. Below
#: ASH's SANDBOX_STOP_GRACE_SECONDS (10), so the wrapper finishes before ASH gives up on it.
REAP_DEADLINE_SECONDS = 5.0
#: How long it keeps reaping once ASH has asked it to stop (SIGTERM, SIGINT or
#: SIGHUP), counted from that signal, if that ends sooner. ASH SIGKILLs a wrapper
#: still running when its grace after SIGTERM ends, and a wrapper killed while it
#: reaps leaves what its scanner started running, so a stop is finished well
#: inside a grace of half a second.
STOP_REAP_DEADLINE_SECONDS = 0.25
# prctl(PR_SET_SECCOMP) rather than seccomp(2): the syscall number differs per arch.
PR_SET_SECCOMP = 22
SECCOMP_MODE_FILTER = 2

# seccomp-bpf
BPF_LD_W_ABS = 0x20
BPF_ALU_AND_K = 0x54
BPF_JMP_JEQ_K = 0x15
BPF_JMP_JGE_K = 0x35
BPF_RET_K = 0x06
SECCOMP_RET_ALLOW = 0x7FFF0000
SECCOMP_RET_ERRNO = 0x00050000
SECCOMP_RET_KILL_PROCESS = 0x80000000
SECCOMP_DATA_NR = 0
SECCOMP_DATA_ARCH = 4
SECCOMP_DATA_ARG0 = 16  # low 32 bits on little-endian
SECCOMP_DATA_ARG1 = 24
AF_UNIX = 1
SOCK_STREAM = 1
SOCK_SEQPACKET = 5
#: The type bits of socket()'s and socketpair()'s second argument, without
#: SOCK_NONBLOCK and SOCK_CLOEXEC (the kernel's SOCK_TYPE_MASK).
SOCK_TYPE_MASK = 0xF

# (audit arch, socket nr, socketpair nr, io_uring_setup nr, x32 bit or None), from
# the kernel's arch/x86/entry/syscalls/syscall_64.tbl and include/uapi/asm-generic/unistd.h.
ARCHES = {
    "x86_64": (0xC000003E, 41, 53, 425, 0x40000000),
    "aarch64": (0xC00000B7, 198, 199, 425, None),
    "arm64": (0xC00000B7, 198, 199, 425, None),
}

libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long


#: The Unicode categories of the characters written as escapes, not printed:
#: utils/terminal_text.py's SHOWN_AS_ESCAPES.
_SHOWN_AS_ESCAPES = frozenset({"Cc", "Cf", "Cs", "Co", "Cn", "Zl", "Zp"})
_ESCAPE_TEXT = re.compile(r"x[0-9A-Fa-f]{2}|u[0-9A-Fa-f]{4}|U[0-9A-Fa-f]{8}")
_CANDIDATES = re.compile(
    r"(?<!\\)(\\+)(?=x[0-9A-Fa-f]{2}|u[0-9A-Fa-f]{4}|U[0-9A-Fa-f]{8}|[^\x20-\x7e])"
    r"|[^\x20-\x7e]"
)


def _escape_for(character: str) -> str:
    code = ord(character)
    if code <= 0xFF:
        return "\\x%02x" % code
    if code <= 0xFFFF:
        return "\\u%04x" % code
    return "\\U%08x" % code


def _shown(text: str) -> str:
    """*text* on one line, shown and not obeyed: what utils/terminal_text.py's
    shown_on_one_line writes, inlined since this program imports nothing from ASH.

    Each control, format, separator, surrogate, private-use and unassigned
    character (tab, newline and carriage return included) as ``\\xNN``,
    ``\\uNNNN`` or ``\\UNNNNNNNN``, a run of backslashes before text that reads as
    one of those or before such a character doubled, and each CI command form
    broken: "::" at the start, and "##" with an optional name and "[" anywhere (a
    bare "##" is left). The error text and the scanner's path it quotes are the
    repository's or the tool's. tests/unit/utils/test_landlock_exec_shows_text.py
    checks that this writes what shown_on_one_line writes.
    """

    def one(match: "re.Match[str]") -> str:
        run = match.group(1)
        if run:
            after = match.end()
            if _ESCAPE_TEXT.match(text, after) or (
                after < len(text)
                and unicodedata.category(text[after]) in _SHOWN_AS_ESCAPES
            ):
                return run * 2
            return run
        character = match.group()
        if unicodedata.category(character) in _SHOWN_AS_ESCAPES:
            return _escape_for(character)
        return character

    shown = _CANDIDATES.sub(one, text)
    shown = re.sub(r"^([^\S\n]*):(?=:)", r"\1\\x3a", shown, flags=re.MULTILINE)
    return re.sub(
        r"(\\*)#(?=#[A-Za-z]*\[)", lambda match: match.group(1) * 2 + "\\x23", shown
    )


def fail(message: str) -> NoReturn:
    # The message quotes policy paths, which name the scanned tree's directories.
    sys.stderr.write(_shown(f"ash-landlock: {message}") + "\n")
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
    # The scan's data: read, never executed. Rules add up, so a data path under a
    # path granted exec stays executable through it; one under no such path (the
    # scanned tree under $HOME) is not.
    for path in policy.get("read_data", ()):
        add_path_rule(ruleset_fd, path, FS_READ_FILE | FS_READ_DIR)
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


def socket_filter(machine: str, network: bool) -> List[Tuple[int, int, int, int]]:
    """The seccomp program ``apply_socket_seccomp`` installs, as (code, jt, jf, k).

    Landlock does not mediate connect() or sendto() on a Unix-domain socket path, so
    a sandboxed process that could create an AF_UNIX socket could talk to the Docker
    socket or the session bus whatever the filesystem rules say. socket(AF_UNIX) is
    therefore refused always. socketpair() is a separate syscall, and the pairs tools
    use for pipes (stream, or seqpacket) stay allowed: they are connected to each
    other at birth, connect() on them fails with EISCONN, and a seqpacket send
    ignores any address. A datagram pair is refused, because a datagram socket can
    sendto() or connect() any datagram socket by path, the journal's /dev/log
    included, however it was created; SOCK_RAW is refused with it, as the kernel
    makes a Unix SOCK_RAW a datagram socket. Without a network, socket() is refused
    for every family. io_uring_setup is refused always, because io_uring can create
    sockets without the socket syscall.

    Separate from installing it so the tests can check the program for every
    architecture in ARCHES, not only the one they run on.
    """
    audit_arch, nr_socket, nr_socketpair, nr_io_uring_setup, x32_bit = ARCHES[machine]
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
    # socketpair: allow a stream or seqpacket pair, refuse every other type. The
    # accumulator still holds the syscall number on the not-socketpair branch.
    prog += [
        (BPF_JMP_JEQ_K, 0, 6, nr_socketpair),
        (BPF_LD_W_ABS, 0, 0, SECCOMP_DATA_ARG1),
        (BPF_ALU_AND_K, 0, 0, SOCK_TYPE_MASK),
        (BPF_JMP_JEQ_K, 2, 0, SOCK_STREAM),
        (BPF_JMP_JEQ_K, 1, 0, SOCK_SEQPACKET),
        (BPF_RET_K, 0, 0, refuse),
        (BPF_RET_K, 0, 0, SECCOMP_RET_ALLOW),
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
    return prog


def apply_socket_seccomp(network: bool) -> None:
    """Install ``socket_filter`` for this machine; see there for what it refuses."""
    machine = platform.machine().lower()
    if machine not in ARCHES:
        fail(f"no seccomp socket filter for architecture {machine}")
    prog = socket_filter(machine, network)
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
        print(abi)  # print-ok: an int, the ABI version the parent reads
        return 0
    if argv[:1] == ["--socket-filter"]:
        if len(argv) < 4 or argv[1] not in ("unix", "all") or argv[2] != "--":
            fail("usage: landlock_exec.py --socket-filter unix|all -- argv...")
        exec_with_socket_filter(argv[1] == "unix", argv[3:])
    if len(argv) < 4 or argv[0] != "--policy" or argv[2] != "--":
        fail("usage: landlock_exec.py --policy JSON -- argv...")
    policy = _parse_policy(argv[1])
    command = argv[3:]
    abi = abi_version()
    if abi <= 0:
        fail("Landlock is not supported or not enabled on this kernel")
    _enter_policy_cwd(policy)

    def restrict() -> None:
        # In the child only. The wrapper stays outside the scanner's Landlock
        # domain, so on ABI 6+ the scanner cannot signal it (LANDLOCK_SCOPE_SIGNAL)
        # and cannot stop it from reaping what it leaves behind.
        if libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
            fail(f"prctl(PR_SET_NO_NEW_PRIVS): {os.strerror(ctypes.get_errno())}")
        apply_landlock(policy, abi)
        apply_socket_seccomp(bool(policy["network"]))

    return run_and_reap(command, restrict)


#: The policy document's keys, each with the type its value must have.
_POLICY_KEYS: Dict[str, type] = {
    "read_only": list,
    "read_data": list,
    "writable": list,
    "network": bool,
    "cwd": str,
}
_REQUIRED_POLICY_KEYS = ("read_only", "writable", "network")


def _parse_policy(text: str) -> Dict[str, Any]:
    """The ``--policy`` document, or exit 126 with what is wrong with it.

    Checked here, in the wrapper, rather than met in the forked child: a document
    that is not JSON raised out of main with the interpreter's traceback and exit
    1, and a wrong value inside one failed in the child with exit 126 and no
    message. Every path list holds strings; ``network`` is a boolean; ``cwd`` and
    ``read_data`` are optional.
    """
    try:
        policy = json.loads(text)
    except ValueError as e:
        fail(f"--policy is not valid JSON: {e}")
    if not isinstance(policy, dict):
        fail("--policy must be a JSON object")
    for key in _REQUIRED_POLICY_KEYS:
        if key not in policy:
            fail(f"--policy lacks the key {key!r}")
    for key, value in policy.items():
        wanted = _POLICY_KEYS.get(key)
        if wanted is None:
            fail(f"--policy holds the unknown key {key!r}")
        if not isinstance(value, wanted) or (wanted is bool) != isinstance(value, bool):
            fail(f"--policy key {key!r} must be a {wanted.__name__}")
        if wanted is list and not all(isinstance(item, str) for item in value):
            fail(f"--policy key {key!r} must list paths as strings")
    return policy


def _enter_policy_cwd(policy: Dict[str, Any]) -> None:
    """Change into the policy's ``cwd``, when it names one, or exit 126.

    For a spawn ASH gives no working directory of its own (a version probe): the
    child would otherwise inherit ASH's, which the policy need not grant, and the
    tool failed reading it. The wrapper changes directory before the fork, so the
    scanner starts there; the wrapper itself reads nothing from its directory.
    """
    cwd = policy.get("cwd")
    if not cwd:
        return
    try:
        os.chdir(cwd)
    except OSError as e:
        fail(f"cannot change into the working directory {cwd}: {e}")


def exec_with_socket_filter(allow_ip: bool, command: List[str]) -> NoReturn:
    """Apply only the socket filter, then become ``command``, searched on PATH.

    For bwrap and firejail, which run this inside their sandbox. Their own
    namespaces end the process tree and their mounts confine the filesystem, so
    there is nothing to reap and no Landlock domain to set up; execvp, not a fork,
    so the scanner keeps the process the sandbox started. ``allow_ip`` leaves IP
    sockets to the sandbox's network namespace (``unix`` mode).
    """
    if libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
        fail(f"prctl(PR_SET_NO_NEW_PRIVS): {os.strerror(ctypes.get_errno())}")
    apply_socket_seccomp(allow_ip)
    _restore_dispositions()
    try:
        os.execvp(command[0], command)
    except OSError as e:
        fail(f"exec {command[0]}: {e}")


def _restore_dispositions() -> None:
    """Put SIGPIPE and SIGXFSZ back to their defaults before an exec.

    The interpreter ignores both at startup and an exec keeps an ignored
    disposition, so without this the scanner would run with them ignored, unlike
    the same scanner started unwrapped (subprocess restores them in every child
    it starts). Both exec routes of this program call it last before the exec.
    """
    for restored in (signal.SIGPIPE, signal.SIGXFSZ):
        signal.signal(restored, signal.SIG_DFL)


def _children_files(pid: int = 0) -> Optional[List[int]]:
    """Children of ``pid`` (this process when 0) from /proc/<pid>/task/*/children.

    One read per thread. None when the kernel provides no children file
    (CONFIG_PROC_CHILDREN off), so the caller lists /proc instead. Any other
    failure gives the children read so far: a process that is gone has nothing
    left to reap, and a file this process may not read is one a listing of /proc
    could not read either, so neither is a reason to scan every entry of /proc.
    Read as bytes: a text open may need to import a codec, and after Landlock the
    interpreter's own library is not necessarily readable.
    """
    base = f"/proc/{pid}" if pid else "/proc/self"
    found: List[int] = []
    try:
        tasks = os.listdir(f"{base}/task")
    except OSError:
        return found
    read_one = False
    for tid in tasks:
        try:
            with open(f"{base}/task/{tid}/children", "rb") as f:
                found += [int(child) for child in f.read().split()]
            read_one = True
        except FileNotFoundError:
            # A thread that exited has no files left; a thread still there with
            # no children file is a kernel that provides none.
            if not read_one and os.path.isdir(f"{base}/task/{tid}"):
                return None
            return found
        except OSError:
            return found
    return found


def _parent_map(
    until: Optional[float] = None, limit: Optional[int] = None
) -> Dict[int, List[int]]:
    """Parent pid to child pids, from one listing of /proc.

    The fallback for a kernel without children files: every /proc/<pid>/stat,
    which on a host with thousands of processes costs a few hundred
    milliseconds. At most ``limit`` entries are read (PROC_SCAN_LIMIT), and none
    past the time.monotonic() deadline ``until``, so the map holds what was read
    by then.
    """
    if limit is None:
        limit = PROC_SCAN_LIMIT
    parents: Dict[int, List[int]] = {}
    read = 0
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        if read >= limit or (until is not None and time.monotonic() >= until):
            break
        read += 1
        try:
            with open(f"/proc/{entry}/stat", "rb") as f:
                fields = f.read().rsplit(b")", 1)[1].split()
        except (OSError, IndexError):
            continue
        if len(fields) > 1:
            parents.setdefault(int(fields[1]), []).append(int(entry))
    return parents


def _children(pid: int = 0) -> List[int]:
    """Processes whose parent is ``pid`` (this process when 0)."""
    found = _children_files(pid)
    if found is not None:
        return found
    return _parent_map().get(pid or os.getpid(), [])


def _parent_pid(pid: int) -> Optional[int]:
    """The parent of ``pid`` from /proc/<pid>/stat, or None when it is gone or unreadable."""
    try:
        with open(f"/proc/{pid}/stat", "rb") as f:
            fields = f.read().rsplit(b")", 1)[1].split()
    except (OSError, IndexError):
        return None
    if len(fields) < 2:
        return None
    try:
        return int(fields[1])
    except ValueError:
        return None


def _kill_descendant(pid: int, tree: Set[int]) -> bool:
    """SIGKILL ``pid`` if it is still a process of this wrapper's tree.

    The pids a reap pass collects are read from /proc and killed afterwards; a
    descendant that exited in between can have had its number reused by an
    unrelated process of the same user, which a bare ``kill`` would then end. So
    the process is pinned first where the kernel allows it (``pidfd_open``, Linux
    5.3+, and ``pidfd_send_signal``), and its parent is read again: a process
    whose parent is not in ``tree`` (the wrapper and the descendants listed with
    it) is not one the scanner started and is left alone. A reused pid whose new
    parent happens to be in the tree is a descendant after all. Returns whether a
    signal was sent.
    """
    parent = _parent_pid(pid)
    if parent is None or parent not in tree:
        return False
    pidfd_open = getattr(os, "pidfd_open", None)
    pidfd_send_signal = getattr(signal, "pidfd_send_signal", None)
    if pidfd_open is not None and pidfd_send_signal is not None:
        try:
            fd = pidfd_open(pid)
        except OSError:
            return False
        try:
            # Read again with the process pinned: a reuse between the first read
            # and the open would otherwise have pinned the new process.
            if _parent_pid(pid) not in tree:
                return False
            pidfd_send_signal(fd, signal.SIGKILL)
            return True
        except OSError:
            return False
        finally:
            os.close(fd)
    try:
        os.kill(pid, signal.SIGKILL)
        return True
    except OSError:
        return False


def _descendants(until: Optional[float] = None) -> List[int]:
    """Every process below this one, at any depth, breadth first.

    ``until`` is a time.monotonic() deadline: past it the walk returns what it
    has found by then, so one reap pass ends inside STOP_REAP_DEADLINE_SECONDS
    however deep the tree or slow /proc, and that pass kills that much. The
    direct children are always read, on either path: the listing that finds them
    is bounded by PROC_SCAN_LIMIT alone, so a late pass still kills what the
    scanner itself started. On a kernel without children files /proc is listed
    once for the whole walk (``_parent_map``), not once per descendant.
    """
    found: List[int] = []
    parents: Optional[Dict[int, List[int]]] = None
    frontier = _children_files()
    if frontier is None:
        parents = _parent_map()
        frontier = parents.get(os.getpid(), [])
    while frontier:
        found += frontier
        following: List[int] = []
        for child in frontier:
            if until is not None and time.monotonic() >= until:
                return found
            if parents is None:
                read = _children_files(child)
                if read is None:
                    parents = _parent_map(until)
                    read = parents.get(child, [])
            else:
                read = parents.get(child, [])
            following += read
        frontier = following
    return found


def _child_setup(restrict: Callable[[], None]) -> None:
    """The forked child, before it becomes the scanner.

    The stop signals the wrapper blocked across the fork are unblocked, the child
    leads a new session, it asks the kernel for SIGTERM should the wrapper exit,
    the dispositions this interpreter ignores are restored, and ``restrict``
    confines it. Failing to restrict is fatal (``restrict`` raises); a parent-death
    signal the kernel will not set is noted and the child goes on, as the file's
    other best-effort steps do.
    """
    signal.pthread_sigmask(signal.SIG_UNBLOCK, STOP_SIGNALS)
    # A new session has no controlling terminal, so the scanner cannot push
    # keystrokes into the user's shell through TIOCSTI.
    os.setsid()
    # Landlock does not end a process's descendants with it, so a wrapper that
    # dies before it reaps (ASH SIGKILLs one that outlives its grace) would leave
    # the scanner running with nothing to end it. SIGTERM on the wrapper's exit
    # is what an unwrapped scanner gets from ASH's own stop; the scanner may
    # still be told to stop before this call lands if the wrapper dies in the
    # few instructions between the fork and here.
    if libc.prctl(PR_SET_PDEATHSIG, int(signal.SIGTERM), 0, 0, 0) != 0:
        sys.stderr.write(
            _shown(
                "ash-landlock: prctl(PR_SET_PDEATHSIG): "
                f"{os.strerror(ctypes.get_errno())}; the scanner outlives a killed "
                "wrapper"
            )
            + "\n"
        )
    _restore_dispositions()
    restrict()


def _run_child(command: List[str], restrict: Callable[[], None]) -> NoReturn:
    """The forked child: set up, restrict, become the scanner; never return.

    A failure is reported for what it is: a restriction step that raised an
    OSError says so (it used to be written as a failed exec of the scanner, which
    had not been attempted), ``fail()``'s SystemExit has written its own line, and
    any other exception is written with its type and text rather than exiting in
    silence. Whatever happened, the child never returns into the wrapper's code; a
    restriction that failed leaves it here, unrestricted, so it exits 126.
    """
    try:
        _child_setup(restrict)
    except SystemExit:
        pass
    except BaseException as e:  # noqa: BLE001 - the child reports and exits
        sys.stderr.write(
            _shown(f"ash-landlock: restricting the scanner: {type(e).__name__}: {e}")
            + "\n"
        )
    else:
        try:
            os.execve(command[0], command, os.environ)
        except OSError as e:
            # The scanner's path, and the error that quotes it.
            sys.stderr.write(_shown(f"ash-landlock: exec {command[0]}: {e}") + "\n")
    os._exit(126)


def _forward_stop(pid: int, signum: int, still_running: Callable[[], bool]) -> None:
    """Pass the stop signal ASH sent on to the scanner; SIGKILL it if it lingers.

    The scanner gets the signal ASH sent the wrapper (SIGTERM on a timeout), as the
    same scanner run unwrapped would, so one that handles it ends the way it
    chooses and its exit is reported as that signal, not as a SIGKILL the wrapper
    made up. A scanner still running STOP_REAP_DEADLINE_SECONDS later is
    SIGKILLed by an interval timer's SIGALRM, so the stop still finishes inside the
    grace ASH gives the wrapper.
    """
    try:
        os.kill(pid, signum)
    except OSError:
        return

    def kill_if_lingering(_signum: int, _frame: object) -> None:
        if still_running():
            try:
                os.kill(pid, signal.SIGKILL)
            except OSError:
                pass

    signal.signal(signal.SIGALRM, kill_if_lingering)
    signal.setitimer(signal.ITIMER_REAL, STOP_REAP_DEADLINE_SECONDS)


def _reap_leftovers(deadline: Callable[[], float]) -> List[int]:
    """Kill and reap what the scanner left, until the tree is empty or the deadline.

    Returns the pids a pass still found once the loop ended: an empty list when
    five quiet passes in a row found nothing, the survivors when the deadline
    ended the loop first, so the caller can say that something outlived the stop.
    An orphan is reparented here only once its own parent has exited, which can
    trail the scanner's exit, so "no children" has to hold for a short while.
    Every pass kills the whole remaining tree at once, so depth costs nothing;
    bounded by time rather than by a pass count, and inside the grace ASH gives a
    stopping process before it SIGKILLs this wrapper. At least one pass is made,
    however late a stop left the scanner's exit.
    """
    quiet = 0
    passes = 0
    leftovers: List[int] = []
    while passes == 0 or time.monotonic() < deadline():
        passes += 1
        leftovers = _descendants(until=deadline())
        if not leftovers:
            quiet += 1
            if quiet >= 5:
                break
            time.sleep(0.01)
            continue
        quiet = 0
        tree = {os.getpid(), *leftovers}
        for child in leftovers:
            _kill_descendant(child, tree)
        while True:
            try:
                reaped, _ = os.waitpid(-1, os.WNOHANG)
            except ChildProcessError:
                break
            if reaped == 0:
                break
    return leftovers


def _die_of(died_of: int) -> int:
    """End the wrapper with the scanner's death signal; return the fallback status.

    ASH then sees -N exactly as it would for the scanner run unwrapped. The
    wrapper's core dumps are turned off first: a core-dumping signal (SIGSEGV,
    SIGABRT) re-raised here would otherwise write the unrestricted wrapper's core
    into the scanner's working directory. 128+N is the fallback for a signal that
    cannot be re-raised that way.
    """
    try:
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    except (OSError, ValueError):
        pass
    try:
        if died_of not in (signal.SIGKILL, signal.SIGSTOP):
            # SIGKILL and SIGSTOP cannot be caught, so need no reset.
            signal.signal(died_of, signal.SIG_DFL)
            signal.pthread_sigmask(signal.SIG_UNBLOCK, {died_of})
        os.kill(os.getpid(), died_of)
    except (OSError, ValueError):
        pass
    return 128 + died_of


def run_and_reap(command: List[str], restrict: Callable[[], None]) -> int:
    """Run the scanner and, once it exits, kill whatever it left running.

    Unlike bwrap's PID namespace, Landlock does not end a process's descendants
    with it. A process the scanner left behind could keep writing in the results
    directory after ASH has swept it, so this wrapper stays as a child subreaper
    (orphans are reparented to it, however they detached) and kills them all
    before it exits with the scanner's status. SIGTERM, SIGINT or SIGHUP to the
    wrapper (ASH sends SIGTERM on a timeout) is passed on to the scanner, which is
    SIGKILLed if it lingers, and then everything it left is ended the same way.
    """
    if libc.prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) != 0:
        fail(f"prctl(PR_SET_CHILD_SUBREAPER): {os.strerror(ctypes.get_errno())}")
    stop_signals = STOP_SIGNALS
    # Blocked across the fork, so a signal that arrives before the handler is in
    # place is held rather than killing the wrapper and orphaning the scanner.
    signal.pthread_sigmask(signal.SIG_BLOCK, stop_signals)
    try:
        pid = os.fork()
    except OSError as e:
        fail(f"fork: {e}")
    if pid == 0:
        _run_child(command, restrict)

    stopped_at: List[float] = []
    scanner_exited = False

    def stop(signum: int, _frame: object) -> None:
        # ASH asks the wrapper to stop (a timeout, Ctrl-C, a cancelled scan): pass
        # it to the scanner now, and the loop below ends everything it started, by
        # STOP_REAP_DEADLINE_SECONDS from the first such signal.
        if not stopped_at:
            stopped_at.append(time.monotonic())
        if scanner_exited:
            # Reaped, or about to be: its pid may already be another process's.
            return
        _forward_stop(pid, signum, lambda: not scanner_exited)

    for signum in stop_signals:
        signal.signal(signum, stop)
    signal.pthread_sigmask(signal.SIG_UNBLOCK, stop_signals)
    # Waited for without reaping (WNOWAIT): until it is reaped below, the
    # scanner's pid stays its own, so a stop that kills it in between kills
    # nothing else.
    while True:
        try:
            os.waitid(os.P_PID, pid, os.WEXITED | os.WNOWAIT)
            break
        except InterruptedError:
            continue
    scanner_exited = True
    _, status = os.waitpid(pid, 0)
    exited_at = time.monotonic()

    def deadline() -> float:
        if stopped_at:
            return min(
                exited_at + REAP_DEADLINE_SECONDS,
                stopped_at[0] + STOP_REAP_DEADLINE_SECONDS,
            )
        return exited_at + REAP_DEADLINE_SECONDS

    survivors = _reap_leftovers(deadline)
    if survivors:
        # The deadline ended the loop with processes still found: said, so ASH's
        # log shows that something the scanner started outlived the stop, where
        # the scanner's own status alone read as a clean end.
        sys.stderr.write(
            _shown(
                f"ash-landlock: {len(survivors)} process(es) the scanner started "
                "could not be ended before the deadline: "
                + ", ".join(str(p) for p in survivors[:10])
            )
            + "\n"
        )
    if os.WIFSIGNALED(status):
        return _die_of(os.WTERMSIG(status))
    return os.WEXITSTATUS(status)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
