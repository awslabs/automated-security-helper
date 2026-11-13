# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The resident express daemon: warm imports once, one fork per scan.

One process per (user, ASH version). It binds the unix socket first -- so an
autostarting client has something to connect to within milliseconds -- then
imports the heavy modules once (:func:`warm_imports`), and serves a small
single-threaded loop. Each ``scan`` request forks this warm process; the child
re-execs nothing (an exec would throw the warm imports away), puts the client's
stdin/stdout/stderr on descriptors 0-2, applies the request's environment
subset, changes to the request's working directory and drops into the ordinary
console entry (:mod:`automated_security_helper.cli.entrypoint`) with the
request's argv, so everything after the fork is the cold run's own code. The
parent reaps the child and reports its exit code back over the connection.

Per-run state is clean by construction: the daemon imports modules but loads no
repository config and builds no plugin registry -- the child does that, as a
cold run does -- so nothing a scan computes outlives it, and invalidation needs
only the version/fingerprint handshake, never a config hash.

Single-threaded on purpose: ``os.fork`` in a multi-threaded process is where
fork bugs live, and a selector loop with a SIGCHLD wakeup pipe serves the same
connections without one extra thread. Concurrency comes from the forks
themselves, capped at the CPU count (:func:`concurrency_cap`); a request past
the cap is refused with ``busy`` and the client runs it cold.

The loop exits on an explicit ``stop``, on SIGTERM, and on its own idle timer:
:func:`should_idle_exit` is the one place that decides, and it never retires a
daemon with a scan still running.
"""

from __future__ import annotations

import errno
import json
import os
import selectors
import signal
import socket
import sys
import time
from typing import Any, Optional

from automated_security_helper.express import runtime
from automated_security_helper.utils.process_env import (
    apply_environ_overrides,
    snapshot_environ,
)
from automated_security_helper.utils.terminal_text import shown_not_obeyed

#: How long one connection's inline handshake reads (the request, then the go
#: that answers the ok) may stall the single-threaded accept loop. A live
#: client has already written its request when connect returns and answers the
#: ok in one round trip, so this is a wedged-client bound, not a budget a
#: healthy handshake approaches -- and it must stay far under the client's own
#: HANDSHAKE_TIMEOUT_SECONDS, so the daemon never waits out a client that is
#: still legitimately waiting for it (the budget-consistency test pins the
#: ordering).
INLINE_HANDSHAKE_TIMEOUT_SECONDS = 2.0

#: Modules imported once at daemon start. The point is the import cache the
#: forked children inherit copy-on-write: the CLI (typer, rich, click and every
#: command module), the scan orchestration, and the built-in plugin package
#: whose scanners/reporters/converters every scan loads. Loading a module here
#: must have no per-run effect; registries and config are built in the child.
WARM_MODULES = (
    "automated_security_helper.cli.main",
    "automated_security_helper.interactions.run_ash_scan",
    "automated_security_helper.core.orchestrator",
    "automated_security_helper.plugins.loader",
    "automated_security_helper.plugin_modules.ash_builtin",
)


def warm_imports() -> list[str]:
    """Import :data:`WARM_MODULES` and ``ash_builtin``'s subpackages; return failures.

    A module that fails to import is skipped and named, not fatal: the forked
    child imports whatever is missing itself, exactly as a cold run would, so a
    broken optional module costs warmth, never correctness.
    """
    import importlib
    import pkgutil

    failures: list[str] = []
    names = list(WARM_MODULES)
    for name in names:
        try:
            module = importlib.import_module(name)
        except Exception as exc:  # noqa: BLE001 - warmth is best effort
            failures.append(f"{name}: {type(exc).__name__}: {exc}")
            continue
        if name.endswith("ash_builtin"):
            search = getattr(module, "__path__", None)
            if not search:
                continue
            # The walk itself can raise, not only the imports inside it:
            # walk_packages imports each package to descend into it, and
            # without ``onerror`` an ImportError there propagates out of the
            # ITERATION -- and anything escaping this function would kill a
            # daemon that has already bound its socket, leaving a dead socket
            # every scan silently colds against. Everything is caught; the
            # cost of any failure here is warmth, never the daemon.
            try:
                walked = list(
                    pkgutil.walk_packages(
                        search,
                        prefix=name + ".",
                        onerror=lambda failed: failures.append(
                            f"{failed}: not walkable"
                        ),
                    )
                )
            except Exception as exc:  # noqa: BLE001
                failures.append(f"{name} walk: {type(exc).__name__}: {exc}")
                continue
            for info in walked:
                try:
                    importlib.import_module(info.name)
                except Exception as exc:  # noqa: BLE001
                    failures.append(f"{info.name}: {type(exc).__name__}: {exc}")
    return failures


def _signal_scan(pid: int, signum: int) -> None:
    """Deliver *signum* to the scan's whole process group, else to the pid.

    The child made itself a group leader at fork (both sides set it), so the
    group id is the pid; the single-pid fallback covers the narrow window
    before that and any platform refusal, where orphaning a scanner subprocess
    is still better than not stopping the scan at all.
    """
    try:
        os.killpg(pid, signum)
        return
    except OSError:
        pass
    try:
        os.kill(pid, signum)
    except OSError:
        pass


def concurrency_cap() -> int:
    """How many scan children may run at once: the CPU count, at least one."""
    return max(os.cpu_count() or 1, 1)


def should_idle_exit(
    last_activity: float, active_children: int, now: float, idle_timeout: float
) -> bool:
    """Whether an idle daemon should retire.

    Never with a scan running, whatever the clock says; otherwise when the
    time since the last request or child exit has passed *idle_timeout*.
    """
    if active_children > 0:
        return False
    return (now - last_activity) >= idle_timeout


def _log(message: str) -> None:
    """One timestamped line on the daemon's stdout (the express log file).

    Shown, not obeyed: a message can quote a request's text or an exception's.
    """
    stamp = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime())
    try:
        print(shown_not_obeyed(f"{stamp}Z {message}"), flush=True)
    except Exception:
        pass


class _Connection:
    """One accepted client connection and the scan child it may be running."""

    def __init__(self, sock: socket.socket) -> None:
        self.sock = sock
        self.reader = runtime.FrameReader(sock)
        self.child_pid: Optional[int] = None
        self.client_fds: list[int] = []

    def close(self) -> None:
        for fd in self.client_fds:
            try:
                os.close(fd)
            except OSError:
                pass
        self.client_fds = []
        try:
            self.sock.close()
        except OSError:
            pass


class ExpressDaemon:
    """The serve loop. One instance per process; :func:`serve` builds and runs it."""

    def __init__(self, idle_timeout: float) -> None:
        self.idle_timeout = idle_timeout
        self.started_at = time.time()
        self.last_activity = time.monotonic()
        self.version = runtime.ash_version()
        self.fingerprint = runtime.runtime_fingerprint()
        self.connections: dict[int, _Connection] = {}
        self.children: dict[int, _Connection] = {}
        self.scans_served = 0
        self.stopping = False
        #: SIGKILL deadlines for scans a hangup already SIGTERMed: a scan (or
        #: a scanner subprocess) that ignores SIGTERM would otherwise sit in
        #: ``children`` forever, holding a concurrency slot and keeping
        #: should_idle_exit False for the daemon's whole life.
        self._kill_deadlines: dict[int, float] = {}
        self.listener: Optional[socket.socket] = None
        self._lock_fd: Optional[int] = None
        self._socket_inode: Optional[int] = None
        self.selector = selectors.DefaultSelector()
        self._wakeup_read, self._wakeup_write = os.pipe()
        os.set_blocking(self._wakeup_write, False)
        os.set_blocking(self._wakeup_read, False)

    # -- setup ---------------------------------------------------------------

    def bind(self) -> bool:
        """Bind the socket; False when another daemon already owns it.

        The False answer matters to a concurrent autostart's LOSER: pre-commit
        runs parallel hook batches, so the first commit after ``--express``
        fires several autostarts at once, and every loser must tell its client
        "a daemon is there, use it" rather than die silently into a cold run.
        """
        path = runtime.socket_path()
        # The probe/unlink/bind sequence below is serialized across daemons by
        # a sibling lock file: without it, two concurrent autostarts could both
        # see nothing serving, both bind (the second unlinking the first's
        # socket file), and the loser's shutdown would later unlink the
        # winner's socket -- after which every scan silently runs cold until
        # the winner idles out. The lock is held for this daemon's whole life
        # (the fcntl lock dies with the process, so a killed daemon leaves
        # nothing stale), and the shutdown unlinks the socket only when its
        # inode is still this daemon's.
        import fcntl

        self._lock_fd = os.open(
            os.fspath(path) + ".lock", os.O_WRONLY | os.O_CREAT, 0o600
        )
        try:
            fcntl.flock(self._lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            # Another daemon holds the lock: it is serving, or about to.
            os.close(self._lock_fd)
            self._lock_fd = None
            return False
        probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        probe.settimeout(1.0)
        try:
            probe.connect(os.fspath(path))
        except OSError:
            # Nothing serving there: a leftover file is removed and replaced.
            try:
                os.unlink(path)
            except OSError:
                pass
        else:
            # Another daemon already serves this socket (one from before this
            # lock existed): not ours; the lock is released for its successor.
            try:
                os.close(self._lock_fd)
            except OSError:
                pass
            self._lock_fd = None
            return False
        finally:
            try:
                probe.close()
            except OSError:
                pass
        self.listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        # The socket file is 0600 from birth: the bind creates it under a
        # tight umask, inside the 0700 directory runtime_dir() polices.
        previous_umask = os.umask(0o177)
        try:
            self.listener.bind(os.fspath(path))
        finally:
            os.umask(previous_umask)
        try:
            self._socket_inode = os.stat(path).st_ino
        except OSError:
            self._socket_inode = None
        self.listener.listen(64)
        self.listener.setblocking(False)
        self.selector.register(self.listener, selectors.EVENT_READ, self._accept)
        self.selector.register(self._wakeup_read, selectors.EVENT_READ, self._drain)
        signal.set_wakeup_fd(self._wakeup_write, warn_on_full_buffer=False)
        signal.signal(signal.SIGCHLD, lambda *_: None)
        signal.signal(signal.SIGTERM, self._on_sigterm)
        signal.signal(signal.SIGINT, self._on_sigterm)
        # A scan child that writes to a client who vanished must die of its
        # own EPIPE semantics, not take the daemon with it.
        signal.signal(signal.SIGPIPE, signal.SIG_IGN)
        return True

    def _on_sigterm(self, *_: Any) -> None:
        self.stopping = True

    # -- loop ----------------------------------------------------------------

    def run(self) -> None:
        _log(
            f"express daemon pid {os.getpid()} serving {runtime.socket_path()} "
            f"(ash {self.version}, idle timeout {int(self.idle_timeout)}s)"
        )
        try:
            # Inside the try: the socket is already bound, so from here on
            # every exit must run _shutdown or a dead socket file stays behind
            # and every scan silently colds against it until someone cleans up.
            failures = warm_imports()
            for failure in failures:
                _log(f"warm import skipped: {failure}")
            _log("warm imports complete")
            while True:
                for key, _ in self.selector.select(timeout=1.0):
                    key.data(key.fileobj)
                self._reap()
                self._enforce_kill_deadlines()
                if self.stopping:
                    break
                if should_idle_exit(
                    self.last_activity,
                    len(self.children),
                    time.monotonic(),
                    self.idle_timeout,
                ):
                    _log("idle timeout reached; exiting")
                    break
        finally:
            self._shutdown()

    def _shutdown(self) -> None:
        # The socket comes down first, so no new scan arrives mid-shutdown --
        # and only when the file is still this daemon's own bind: a daemon that
        # lost a race must never unlink a successor's socket (the inode check;
        # see bind()).
        try:
            path = runtime.socket_path()
            if self._socket_inode is not None and os.stat(path).st_ino == (
                self._socket_inode
            ):
                os.unlink(path)
        except OSError:
            pass
        # The lock goes with the socket, right away: a concurrent autostart in
        # the grace window below must be able to take it and bind a fresh
        # socket, rather than read "another daemon owns this socket" about a
        # file that is already gone. The inode check above keeps this daemon
        # from ever unlinking that successor's socket. The cost, accepted: a
        # successor taking the lock in that window can accept up to
        # concurrency_cap() new scans while this daemon's children still run,
        # so the machine can carry about twice the cap for STOP_GRACE_SECONDS
        # -- the cap is per daemon, and the overlap is bounded by the grace.
        if self._lock_fd is not None:
            try:
                os.close(self._lock_fd)
            except OSError:
                pass
            self._lock_fd = None
        # Running scans are told to stop, by process group so their scanner
        # subprocesses go with them, and given a moment to report real exit
        # codes. A group that outlives the wait is SIGKILLed BEFORE its client
        # is told the scan is over -- and only those report the daemon's 143;
        # a child that exited on its own at any point, the grace's last
        # instant included, keeps its real code.
        for pid in list(self.children):
            _signal_scan(pid, signal.SIGTERM)
        deadline = time.monotonic() + runtime.STOP_GRACE_SECONDS
        while self.children and time.monotonic() < deadline:
            self._reap()
            if self.children:
                time.sleep(0.05)
        # One plain reap BEFORE any SIGKILL: the grace loop can end right
        # after a child exited on its own (its deadline check runs before
        # another reap would), and that child's REAL code -- 0, or 1 with
        # findings, or its own SIGTERM handling -- must win over the uniform
        # 143. Only the pids actually SIGKILLed below report the override.
        self._reap()
        killed = set(self.children)
        for pid in killed:
            _signal_scan(pid, signal.SIGKILL)
        self._reap(code_override=128 + int(signal.SIGTERM), override_pids=killed)
        for connection in list(self.children.values()):
            try:
                runtime.send_frame(connection.sock, {"exit": 128 + int(signal.SIGTERM)})
            except (OSError, runtime.ExpressProtocolError):
                pass
        for connection in list(self.connections.values()):
            connection.close()
        if self.listener is not None:
            try:
                self.listener.close()
            except OSError:
                pass
        _log("express daemon exiting")

    def _enforce_kill_deadlines(self) -> None:
        """SIGKILL discarded scans that outlived their SIGTERM grace.

        Runs once per loop pass (the select tick bounds the lag at about a
        second past the deadline). An entry whose pid was reaped meanwhile is
        dropped; a survivor's whole group is killed and the SIGCHLD reap frees
        its concurrency slot, so the daemon can still idle-retire.
        """
        if not self._kill_deadlines:
            return
        now = time.monotonic()
        for pid, deadline in list(self._kill_deadlines.items()):
            if pid not in self.children:
                self._kill_deadlines.pop(pid, None)
                continue
            if now < deadline:
                continue
            _log(f"scan pid {pid} outlived its SIGTERM grace; sending SIGKILL")
            _signal_scan(pid, signal.SIGKILL)
            self._kill_deadlines.pop(pid, None)

    def _drain(self, fd: int) -> None:
        try:
            while os.read(fd, 4096):
                pass
        except OSError:
            pass

    # -- connections ---------------------------------------------------------

    def _accept(self, listener: socket.socket) -> None:
        try:
            sock, _ = listener.accept()
        except OSError:
            return
        if not runtime.peer_is_this_user(sock):
            # Fails closed: an unreadable peer uid is a refusal too. Nothing is
            # answered -- a peer this check exists for gets no protocol detail.
            _log("refused a connection whose peer uid is not this user")
            try:
                sock.close()
            except OSError:
                pass
            return
        self.last_activity = time.monotonic()
        sock.setblocking(True)
        # The handshake is read inline, so this bounds how long one stalled
        # client can hold the single-threaded loop. A real client has already
        # written its whole request by the time connect returns, and answers
        # the ok with its go in one round trip, so the bound is generous for
        # it and tight for a wedged one.
        sock.settimeout(INLINE_HANDSHAKE_TIMEOUT_SECONDS)
        connection = _Connection(sock)
        try:
            self._handshake(connection)
        except Exception as exc:  # noqa: BLE001 - one bad client, not the daemon
            # OSError and protocol errors are the expected shapes; anything
            # else is a defect worth a log line -- but never worth the daemon,
            # whose death would SIGTERM every running scan.
            _log(f"connection dropped during handshake: {type(exc).__name__}: {exc}")
            connection.close()
            return
        if connection.child_pid is None and connection.sock.fileno() < 0:
            return  # the handshake closed it (status/stop/refusal)
        sock.settimeout(None)
        sock.setblocking(False)
        self.connections[sock.fileno()] = connection
        self.selector.register(
            sock, selectors.EVENT_READ, lambda _s, c=connection: self._on_frames(c)
        )

    def _handshake(self, connection: _Connection) -> None:
        """Read the first message and answer it: scan, status, stop or refusal.

        The client sends its stdin/stdout/stderr with the first byte, then the
        request frame. Control ops (status, stop, ping) carry no descriptors;
        ``recv_fds`` simply returns none for them.
        """
        data, fds, _, _ = socket.recv_fds(connection.sock, 1, 3)
        connection.client_fds = list(fds)
        if not data:
            raise runtime.ExpressProtocolError("connection ended before any request")
        request = connection.reader.read_frame()
        if request is None:
            raise runtime.ExpressProtocolError("connection ended before any request")
        op = request.get("op")
        if op == "status":
            runtime.send_frame(connection.sock, self._status())
            connection.close()
            return
        if op == "stop":
            # The pid is in the answer so the stopper can wait for this
            # process to actually exit instead of guessing with a timer.
            runtime.send_frame(
                connection.sock, {"ok": True, "stopping": True, "pid": os.getpid()}
            )
            connection.close()
            self.stopping = True
            return
        if op != "scan":
            runtime.send_frame(
                connection.sock, {"ok": False, "reason": f"unknown op {op!r}"}
            )
            connection.close()
            return
        refusal = self._scan_refusal(request, connection)
        if refusal is not None:
            reason, stale = refusal
            # ``stale`` tells an explicit --express client that restarting the
            # daemon would help; a ``busy`` refusal must never trigger one,
            # because a restart would kill the scans the daemon is busy with.
            runtime.send_frame(
                connection.sock, {"ok": False, "reason": reason, "stale": stale}
            )
            connection.close()
            return
        self._start_scan(connection, request)

    def _scan_refusal(
        self, request: dict[str, Any], connection: _Connection
    ) -> Optional[tuple[str, bool]]:
        """Why this scan request is refused, as ``(reason, stale)``, or None.

        ``stale`` is True only for the mismatches a daemon restart cures.
        """
        if request.get("protocol") != runtime.PROTOCOL_VERSION:
            return (
                (
                    f"protocol {request.get('protocol')!r} is not this daemon's "
                    f"({runtime.PROTOCOL_VERSION})"
                ),
                True,
            )
        if request.get("version") != self.version:
            return (
                (
                    f"ash version {request.get('version')!r} is not this daemon's "
                    f"({self.version}); the daemon is stale"
                ),
                True,
            )
        if request.get("fingerprint") != self.fingerprint:
            return (
                (
                    "the installed package set changed since this daemon started; "
                    "the daemon is stale"
                ),
                True,
            )
        if len(connection.client_fds) != 3:
            return ("the request carried no stdin/stdout/stderr descriptors", False)
        if not isinstance(request.get("argv"), list) or not all(
            isinstance(item, str) for item in request.get("argv", [])
        ):
            return ("argv is not a list of strings", False)
        if not isinstance(request.get("cwd"), str):
            return ("cwd is not a string", False)
        env = request.get("env")
        if not isinstance(env, dict) or not all(
            isinstance(k, str) and isinstance(v, str) for k, v in env.items()
        ):
            return ("env is not a string-to-string object", False)
        if len(self.children) >= concurrency_cap():
            return (f"busy: {len(self.children)} scans already running", False)
        return None

    # -- the fork ------------------------------------------------------------

    def _start_scan(self, connection: _Connection, request: dict[str, Any]) -> None:
        self.last_activity = time.monotonic()
        # The ok-then-go choreography runs BEFORE the fork, and the order is
        # load-bearing: the client commits to the daemon the moment it sends
        # go (right after reading ok), and falls back to a cold run on
        # anything earlier -- so a scan must never be running before the go
        # has been READ here, or a client whose handshake timed out would run
        # the same scan cold while the forked one wrote into its terminal (a
        # double scan). The ok alone cannot carry that weight: an ok that
        # lands in the client's socket buffer in the same instant its
        # handshake timeout fires is delivered but never read, and an
        # undeliverable ok (EPIPE: the client's `with` already closed the
        # socket) covers only a client that was gone at the send. The go
        # closes both windows -- a client that fell back never sends it, and
        # this daemon forks nothing without it. The inline read runs under
        # the accept-time socket timeout, so a client that dies between ok
        # and go stalls the loop for that bound at most. After the go there
        # is no falling back on either side: a fork that fails reports itself
        # as the scan's exit code, and a client that hangs up is read by
        # _on_frames, which kills the child.
        try:
            runtime.send_frame(connection.sock, {"ok": True})
            go = connection.reader.read_frame()
        except (OSError, runtime.ExpressProtocolError) as exc:
            _log(f"client went away before the scan started ({exc}); not forking")
            self._discard(connection, kill=False)
            return
        if not isinstance(go, dict) or go.get("op") != "go":
            _log("client never sent go after the ok; not forking")
            self._discard(connection, kill=False)
            return
        try:
            pid = os.fork()
        except OSError as exc:
            _log(f"fork failed: {exc}")
            try:
                runtime.send_frame(connection.sock, {"exit": 1})
            except OSError:
                pass
            connection.close()
            return
        if pid == 0:
            self._child(connection, request)  # never returns
            os._exit(70)  # unreachable; EX_SOFTWARE if it somehow is
        # The child leads its own process group (both sides set it, so neither
        # order of scheduling leaves a window where a group signal misses):
        # a scan starts scanner subprocesses, and a single-pid SIGTERM with
        # the group unset would stop the scan while orphaning the tools it was
        # running.
        try:
            os.setpgid(pid, pid)
        except OSError:
            pass
        self.scans_served += 1
        self.children[pid] = connection
        connection.child_pid = pid
        # The parent's copies of the client's descriptors are the child's now.
        for fd in connection.client_fds:
            try:
                os.close(fd)
            except OSError:
                pass
        connection.client_fds = []
        _log(
            f"scan {self.scans_served}: pid {pid}, "
            f"argv {json.dumps(request.get('argv', []))[:512]}"
        )

    def _child(self, connection: _Connection, request: dict[str, Any]) -> None:
        """The forked scan. Everything here ends in ``os._exit``.

        Order matters: descriptors and signals first (so a failure after them
        is reported on the client's own stderr), then environment and cwd, then
        the ordinary console entry with the request argv. ``CHILD_ENV`` is set
        before the entry so the entry's own express client never delegates again.
        """
        code = 1
        try:
            # Group leadership first (the parent sets it too; see _start_scan).
            try:
                os.setpgid(0, 0)
            except OSError:
                pass
            signal.set_wakeup_fd(-1)
            # The dispositions a cold CPython starts with, not a blanket
            # SIG_DFL: the interpreter ignores SIGPIPE (a scan piped into a
            # closed `head` raises BrokenPipeError instead of dying 141) and
            # handles SIGINT with default_int_handler (KeyboardInterrupt, which
            # the console entry's own handler then chains). The daemon's
            # SIGCHLD/SIGTERM handlers go back to the default.
            for signum in (signal.SIGCHLD, signal.SIGTERM):
                try:
                    signal.signal(signum, signal.SIG_DFL)
                except (OSError, ValueError):
                    pass
            try:
                signal.signal(signal.SIGPIPE, signal.SIG_IGN)
            except (OSError, ValueError):
                pass
            try:
                signal.signal(signal.SIGINT, signal.default_int_handler)
            except (OSError, ValueError):
                pass
            stdin_fd, stdout_fd, stderr_fd = connection.client_fds
            os.dup2(stdin_fd, 0)
            os.dup2(stdout_fd, 1)
            os.dup2(stderr_fd, 2)
            for fd in connection.client_fds:
                if fd > 2:
                    try:
                        os.close(fd)
                    except OSError:
                        pass
            # The control channel is the parent's: the child's inherited copy
            # is closed so the client's EOF semantics are the parent's alone.
            try:
                connection.sock.close()
            except OSError:
                pass
            # The daemon's sockets and pipes have no business in a scan: the
            # listener, every connection (this one's control channel stays the
            # parent's), and the wakeup pipe.
            self._close_daemon_fds()
            # The environment first, the streams second: the streams' codec is
            # the request's PYTHONIOENCODING, not the daemon's. Applied through
            # the locked helpers; this forked child is single-threaded.
            overrides = runtime.request_env_overrides(
                dict(request.get("env", {})), snapshot_environ()
            )
            overrides[runtime.CHILD_ENV] = "1"
            apply_environ_overrides(overrides)
            self._reopen_std_streams()
            try:
                os.chdir(request["cwd"])
            except OSError as exc:
                print(
                    shown_not_obeyed(
                        f"ash express: cannot enter the requested working "
                        f"directory {request['cwd']!r}: {exc}"
                    ),
                    file=sys.stderr,
                    flush=True,
                )
                os._exit(1)
            sys.argv = ["ash", *request["argv"]]
            code = self._run_cli_entry()
        except BaseException:  # noqa: BLE001 - the child may not unwind into the loop
            try:
                import traceback

                print(
                    shown_not_obeyed(traceback.format_exc()),
                    file=sys.stderr,
                    flush=True,
                )
            except BaseException:
                pass
            code = 1
        finally:
            # os._exit skips the interpreter's own teardown, so what a cold
            # run's exit would have done is done here first: the atexit hooks
            # (the scan's own, plus whatever the shared imports registered,
            # which a cold run registers identically) and logging's shutdown
            # flush. Then the streams, then the hard exit, which is what keeps
            # the child out of the daemon's stack.
            try:
                import atexit

                atexit._run_exitfuncs()
            except BaseException:
                pass
            try:
                import logging

                logging.shutdown()
            except BaseException:
                pass
            try:
                sys.stdout.flush()
                sys.stderr.flush()
            except BaseException:
                pass
            os._exit(code)

    def _close_daemon_fds(self) -> None:
        if self.listener is not None:
            try:
                self.listener.close()
            except OSError:
                pass
        for other in self.connections.values():
            other.close()
        for sibling in self.children.values():
            sibling.close()
        try:
            os.close(self._wakeup_read)
            os.close(self._wakeup_write)
        except OSError:
            pass
        if self._lock_fd is not None:
            # The child must not hold the daemon's singleton lock: the fcntl
            # lock is per open file description, and the fork shares it.
            try:
                os.close(self._lock_fd)
            except OSError:
                pass
        try:
            self.selector.close()
        except OSError:
            pass

    def _reopen_std_streams(self) -> None:
        """Fresh text streams on descriptors 0-2, as an interpreter start makes them.

        The daemon's ``sys.stdout``/``sys.stderr`` wrap the log file's old
        buffering and encoding; the client's descriptors are under 0-2 now, so
        the child gets new wrappers that read their own isatty (Rich's color
        and progress decisions) and the locale/PYTHONIOENCODING codec, write
        errors backslashreplaced so a report never dies encoding itself.
        """
        # Only the public names are replaced. The saved originals
        # (sys.__stdout__ and friends) keep pointing at the daemon's log file,
        # which is a reasonable last resort for anything that reaches for them,
        # and reassigning them is outside their contract (typeshed marks them
        # Final).
        #
        # Run after apply_request_env, so PYTHONIOENCODING here is the
        # client's. The error handlers are the interpreter's own defaults: the
        # requested handler where PYTHONIOENCODING names one, else strict for
        # stdin/stdout and backslashreplace for stderr -- the same split a cold
        # CPython starts with.
        requested = os.environ.get("PYTHONIOENCODING", "")
        encoding_name, _, errors_name = requested.partition(":")
        encoding = encoding_name or None
        errors = errors_name or None
        try:
            sys.stdin = os.fdopen(
                0, "r", encoding=encoding, errors=errors, closefd=False
            )
        except OSError:
            pass
        try:
            sys.stdout = os.fdopen(
                1,
                "w",
                buffering=1,
                encoding=encoding,
                errors=errors,
                closefd=False,
            )
            sys.stderr = os.fdopen(
                2,
                "w",
                buffering=1,
                encoding=encoding,
                errors=errors or "backslashreplace",
                closefd=False,
            )
        except OSError:
            pass

    def _run_cli_entry(self) -> int:
        """The ordinary console entry, with its exit code read instead of raised."""
        from automated_security_helper.cli.entrypoint import main as entry_main

        try:
            # entry_main is annotated None today; the console script is still
            # sys.exit(main()), so an int return there would be an exit code,
            # and this guard keeps the parity if that annotation ever loosens.
            returned = entry_main()  # type: ignore[func-returns-value]
        except SystemExit as exc:
            if exc.code is None:
                return 0
            if isinstance(exc.code, int):
                return exc.code
            # A string SystemExit prints its message and exits 1, as the
            # interpreter's top level treats it.
            print(shown_not_obeyed(str(exc.code)), file=sys.stderr, flush=True)
            return 1
        except BaseException:
            import traceback

            print(
                shown_not_obeyed(traceback.format_exc()),
                file=sys.stderr,
                flush=True,
            )
            return 1
        # The console script is sys.exit(main()), so a normal int return is an
        # exit code there and must be one here, for exit-code parity.
        return returned if isinstance(returned, int) else 0

    # -- after the fork ------------------------------------------------------

    def _on_frames(self, connection: _Connection) -> None:
        """Frames (or EOF) from a client whose scan is running.

        The socket is non-blocking by now, so a wakeup that delivered only part
        of a frame raises ``BlockingIOError`` from the reader's second recv;
        that is "come back later", never a hangup -- the partial bytes stay in
        the reader's buffer for the next wakeup.
        """
        try:
            frame = connection.reader.read_frame()
        except (BlockingIOError, InterruptedError):
            return
        except (OSError, runtime.ExpressProtocolError):
            frame = None
        if frame is None:
            # The client died or hung up. Nobody is watching the scan, so it
            # is told to stop rather than left running unowned.
            self._discard(connection, kill=True)
            return
        if frame.get("op") == "signal":
            signum = frame.get("signum")
            if connection.child_pid is not None and signum in (
                int(signal.SIGINT),
                int(signal.SIGTERM),
                int(getattr(signal, "SIGHUP", signal.SIGTERM)),
            ):
                _signal_scan(connection.child_pid, int(signum))

    def _discard(self, connection: _Connection, kill: bool) -> None:
        try:
            self.selector.unregister(connection.sock)
        except (KeyError, ValueError, OSError):
            pass
        self.connections.pop(connection.sock.fileno(), None)
        if kill and connection.child_pid is not None:
            _signal_scan(connection.child_pid, signal.SIGTERM)
            # The run loop SIGKILLs the group past this deadline: a scan that
            # ignores SIGTERM must not hold its concurrency slot (and the
            # daemon's idle exit) hostage forever.
            self._kill_deadlines[connection.child_pid] = (
                time.monotonic() + runtime.STOP_GRACE_SECONDS
            )
        connection.close()

    def _reap(
        self,
        code_override: Optional[int] = None,
        override_pids: Optional[set[int]] = None,
    ) -> None:
        """Reap exited scans and report each exit code to its client.

        *code_override* replaces the reported code for the pids in
        *override_pids*: the shutdown's post-SIGKILL reap passes 143 with the
        set it actually SIGKILLed, so a killed scan reports the one "ended by
        the daemon's SIGTERM" code instead of a 137/143 mix for what was, to
        the client, a single event -- while a child that exited on its own in
        the same pass keeps its real code.
        """
        while True:
            try:
                pid, status = os.waitpid(-1, os.WNOHANG)
            except ChildProcessError:
                return
            except OSError as exc:
                if exc.errno == errno.EINTR:
                    continue
                return
            if pid == 0:
                return
            connection = self.children.pop(pid, None)
            self._kill_deadlines.pop(pid, None)
            self.last_activity = time.monotonic()
            if connection is None:
                continue
            code = (
                os.waitstatus_to_exitcode(status)
                if hasattr(os, "waitstatus_to_exitcode")
                else os.WEXITSTATUS(status)
            )
            if code < 0:
                # Died of a signal: report as the shell would, 128 + signal.
                code = 128 - code
            if code_override is not None and (
                override_pids is None or pid in override_pids
            ):
                code = code_override
            connection.child_pid = None
            try:
                runtime.send_frame(connection.sock, {"exit": code})
            except (OSError, runtime.ExpressProtocolError):
                pass
            self._discard(connection, kill=False)
            _log(f"scan pid {pid} exited {code}")

    def _status(self) -> dict[str, Any]:
        return {
            "ok": True,
            "pid": os.getpid(),
            "version": self.version,
            "fingerprint": self.fingerprint,
            "protocol": runtime.PROTOCOL_VERSION,
            "socket": os.fspath(runtime.socket_path()),
            "started_at": self.started_at,
            "active_scans": len(self.children),
            "scans_served": self.scans_served,
            "idle_timeout_seconds": self.idle_timeout,
            "concurrency_cap": concurrency_cap(),
        }


def serve(idle_timeout: Optional[float] = None, ready_fd: Optional[int] = None) -> None:
    """Bind the socket and run the daemon loop in this process until it retires.

    The caller decides detachment: ``ash express start`` double-forks first (as
    the client's autostart does) or runs this in the foreground under
    ``--foreground``. *ready_fd*, when given, is the write end of the
    autostart's readiness pipe: one byte the moment the socket is bound and
    listening, then closed -- a death before that point closes the pipe with
    no byte, which tells the starting client within milliseconds instead of
    its whole poll window.
    """
    if idle_timeout is None:
        idle_timeout = runtime.idle_seconds()
    daemon = ExpressDaemon(idle_timeout=float(idle_timeout))
    bound = daemon.bind()
    if ready_fd is not None:
        # One byte either way: "bound and listening", or "another daemon owns
        # this socket, connect to it". A concurrent autostart's loser (parallel
        # pre-commit batches fire several at once) must not read as a death.
        try:
            os.write(ready_fd, b"\x01" if bound else b"\x02")
        except OSError:
            pass
        try:
            os.close(ready_fd)
        except OSError:
            pass
    if not bound:
        return
    daemon.run()
