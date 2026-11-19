# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The thin express client the console entry point consults before the heavy import.

:func:`delegated_exit_code` is the whole interface: given the process argv
(after the program name), it returns the exit code of a scan the daemon ran, or
``None``, which tells the entry point to run cold in-process exactly as it
always has. Everything here is standard library (``utils.process_env``, the
package's locked environment access, is itself standard library only); the
first heavy import is what the ``None`` answer leads to.

The decision tree, in the order it is walked:

* Not a scan invocation (a known non-scan subcommand, ``--help``,
  ``--version``), or ``--no-express`` given, or this process *is* an express child,
  or the platform has no express mode: ``None``.
* The daemon's socket exists: connect, hand over stdin/stdout/stderr and the
  request, forward Ctrl-C, and return the exit code the daemon reports. A
  daemon that refuses (fingerprint mismatch, busy, stale protocol) or cannot
  be reached means ``None`` -- the silent cold fallback -- unless ``--express``
  was given, in which case the stale daemon is stopped and a fresh one
  started, once, before giving up.
* No socket: ``None``, unless ``--express`` was given, which autostarts the
  daemon and then uses it.

Classification can only err toward the cold run: a token that *looks like* a
subcommand name anywhere in the argv (even where it is really an option value)
classifies the invocation as not-a-scan, and the cold run parses the real
command line with the real CLI. A scan that loses express this way is slower,
never wrong.
"""

from __future__ import annotations

import os
import select
import signal
import socket
import sys
import time
from types import FrameType
from typing import Any, Mapping, Optional, Union

#: A socket path as this module passes it around: runtime.socket_path gives a
#: pathlib.Path, the tests hand in strings.
PathLike = Union[str, "os.PathLike[str]"]

from automated_security_helper.express import runtime
from automated_security_helper.utils.process_env import (
    apply_environ_overrides,
    snapshot_environ,
)
from automated_security_helper.utils.terminal_text import shown_not_obeyed

#: The root CLI's subcommand names that are not a scan (cli/main.py registers
#: them). ``scan`` is deliberately absent. A new subcommand added without
#: updating this list classifies as a scan and reaches the daemon, whose child
#: parses the real command line with the real CLI -- so the command still runs
#: correctly, merely through the daemon; tests pin the list against the app.
NON_SCAN_SUBCOMMANDS = frozenset(
    {
        "build-image",
        "report",
        "merge",
        "mcp",
        "get-genai-guide",
        "config",
        "dependencies",
        "inspect",
        "plugin",
        "express",
    }
)

#: Tokens that end delegation on sight: help and version output comes from the
#: CLI itself, and a completion run must never block on a daemon.
LOCAL_ONLY_TOKENS = frozenset({"--help", "-h", "--version"})


def wants_express(argv: list[str]) -> bool:
    """Whether ``--express`` was given (and ``--no-express`` was not).

    Token scan, not a parse: an option *value* that is literally ``--express``
    would read as the flag, which costs an autostart, never a wrong scan --
    the flag itself is also a real option of the scan command, so the forked
    child's parse treats the command line exactly as a cold run would.
    ``--no-express`` wins over ``--express`` wherever both appear: it is the
    escape hatch, so it cannot be out-argued by ordering.
    """
    return "--express" in argv and "--no-express" not in argv


def is_scan_invocation(argv: list[str]) -> bool:
    """Whether *argv* is a scan this client may delegate.

    ``ash scan ...`` (first token exactly ``scan``), or a bare ``ash ...``
    whose tokens include no other subcommand's name, no help/version token and
    no ``--no-express``. Anything else -- including anything ambiguous -- is not
    delegated and runs cold, where the real parser decides what it means.
    """
    if "--no-express" in argv:
        return False
    if any(token in LOCAL_ONLY_TOKENS for token in argv):
        return False
    if argv and argv[0] == "scan":
        return True
    return not any(token in NON_SCAN_SUBCOMMANDS for token in argv)


#: Exception types that mean a defect in the code, never an unavailable host.
_PROGRAMMING_ERRORS = (AttributeError, TypeError, NameError, AssertionError)


def delegated_exit_code(
    argv: list[str], environ: Optional[Mapping[str, str]] = None
) -> Optional[int]:
    """Run *argv* on the express daemon when that applies; else ``None`` (run cold).

    Never raises: express is an accelerator, and no defect in it may fail a scan
    that would have run cold. Every unexpected exception is the ``None``
    answer, with one line on stderr only when ``--express`` asked for the daemon
    explicitly.
    """
    if environ is None:
        environ = snapshot_environ()
    try:
        return _delegated_exit_code(argv, environ)
    except KeyboardInterrupt:
        # A die-now raise that escaped the inner guards (it can land between
        # them): end with the interrupt code, never a traceback and never a
        # cold scan the operator just asked to stop.
        return 130
    except _PROGRAMMING_ERRORS as exc:
        # The fallback is still the contract (the scan runs cold), but these
        # types are defects in ASH, not conditions of the host: they are named
        # as such on every run, --express or not, so a Windows-only
        # AttributeError cannot hide behind an unexplained cold start.
        _note(
            f"ash express: internal error ({type(exc).__name__}: {exc}); "
            "falling back to a cold run. This is a bug in ASH express mode."
        )
        return None
    except Exception as exc:  # noqa: BLE001 - the fallback is the contract
        if wants_express(argv):
            _note(f"ash express: falling back to a cold run: {exc}")
        return None


#: click's completion variables for ASH's own console scripts (`_<PROG>_COMPLETE`
#: with the program name uppercased and `-` as `_`). Matched exactly: the older
#: any-`_*_COMPLETE` match read an unrelated variable (a profile's
#: `_SETUP_COMPLETE=1`, say) as a completion and silently switched express off
#: for every scan of that shell. Pinned against pyproject's console scripts, and
#: the only list :func:`completion_in_progress` reads. A tuple of literals, not
#: a frozenset call, so the environment-variable reference generator resolves
#: the names through the loop that reads them and documents each one.
COMPLETION_ENV_NAMES = (
    "_ASH_COMPLETE",
    "_ASHV3_COMPLETE",
    "_AUTOMATED_SECURITY_HELPER_COMPLETE",
    "_AGENTIC_SECURITY_HARNESS_COMPLETE",
)


def completion_in_progress(environ: Mapping[str, str]) -> bool:
    """Whether this invocation is a shell completion, which must never scan.

    click's completion protocol re-invokes the program with ``_<PROG>_COMPLETE``
    in the environment (``_ASH_COMPLETE`` and the other console-script names),
    and bash's own machinery exports ``COMP_WORDS``/``COMP_CWORD``. A bare
    ``ash`` is a scan of the working directory by design, so without this
    check, TAB after ``ash `` with a daemon up would have started that scan
    into the completion.
    """
    if "COMP_WORDS" in environ or "COMP_CWORD" in environ:
        return True
    # One variable per console script ASH installs (COMPLETION_ENV_NAMES, the
    # one source of truth). Any of them present means this process is
    # answering a TAB completion, which must never start a scan.
    for name in COMPLETION_ENV_NAMES:
        if name in environ:
            return True
    return False


def _delegated_exit_code(argv: list[str], environ: Mapping[str, str]) -> Optional[int]:
    # ASH_EXPRESS_CHILD (the spelling behind runtime.CHILD_ENV) is set in
    # every forked scan child's environment, so a scan already running inside
    # the daemon never delegates to the daemon again.
    if environ.get("ASH_EXPRESS_CHILD"):
        return None
    if completion_in_progress(environ):
        return None
    if not is_scan_invocation(argv):
        return None
    if not runtime.express_supported():
        # The silent cold fallback, except that --express asked for the daemon
        # by name: one line says why there is none, as every other explicit
        # fallback does (the docs promise exactly this).
        if wants_express(argv):
            _note(
                "ash express: express mode needs unix-domain sockets and a "
                "peer-credential read, which this platform lacks; running cold."
            )
        return None
    explicit = wants_express(argv)
    path = runtime.socket_path()

    sock = _connect(path)
    if sock is None and not explicit:
        return None
    if sock is None:
        if not autostart(environ):
            _note(
                _no_daemon_note(
                    path, "did not come up", f" Its log is {runtime.log_path()}"
                )
            )
            return None
        sock = await_daemon(path)
        if sock is None:
            _note("ash express: the daemon did not come up; running cold.")
            return None
    outcome, detail = _run_on_daemon(sock, argv, environ, explicit=explicit)
    if outcome == "exit":
        return detail
    if not (explicit and outcome == "stale"):
        # The silent cold fallback: a refusal (busy, malformed, mismatch
        # without --express) or a connection that broke before the scan started.
        return None
    # --express and the running daemon is stale (version, fingerprint or
    # protocol): restart it once and try again; a second refusal is a cold run.
    stop_daemon(path)
    if not autostart(environ):
        _note(_no_daemon_note(path, "did not come back up", ""))
        return None
    sock = await_daemon(path)
    if sock is None:
        _note("ash express: the daemon did not come back up; running cold.")
        return None
    outcome, detail = _run_on_daemon(sock, argv, environ, explicit=explicit)
    if outcome == "exit":
        return detail
    _note("ash express: the restarted daemon still refused; running cold.")
    return None


def _no_daemon_note(path: PathLike, what: str, tail: str) -> str:
    """The line saying why --express has no daemon: the recorded retirement
    cause when a daemon recently retired itself, else that it ``what``."""
    if runtime.recent_retirement(path):
        return (
            f"ash express: {runtime.RETIRED_FOR_THREADS_TEXT}. "
            f"'ash express start' tries again now.{tail}"
        )
    return f"ash express: the daemon {what}; running cold.{tail}"


def _signal_exit_code(pending: list[int]) -> Optional[int]:
    """The exit code a recorded-but-undeliverable signal maps to, or None.

    Used when the handshake ends in a refusal or a break with signals still
    recorded: there is no scan to forward them to and no cold run should
    start under an interrupt. SIGTERM beats SIGINT (a CI timeout should read
    as 143 even if an interrupt also landed), and the codes are the shell's,
    128 plus the signal, with SIGINT as 130.
    """
    if int(signal.SIGTERM) in pending:
        return 128 + int(signal.SIGTERM)
    if hasattr(signal, "SIGHUP") and int(signal.SIGHUP) in pending:
        return 128 + int(signal.SIGHUP)
    if int(signal.SIGINT) in pending:
        return 130
    return None


def _note(text: str) -> None:
    """One line to stderr, best effort: a broken stderr must not fail the scan.

    Shown, not obeyed: a note quotes exception text, which can carry a path or
    a message with terminal controls in it.
    """
    try:
        print(shown_not_obeyed(text), file=sys.stderr, flush=True)
    except Exception:
        pass


def _connect(path: PathLike) -> Optional[socket.socket]:
    """A connected socket to the daemon at *path*, or None.

    A socket file the kernel refuses outright (``ECONNREFUSED``: a daemon that
    died without unlinking) is removed, so the next autostart does not trip
    over it; removal is best effort and raced only by this user's own
    processes (the directory is 0700). Any other failure -- a timeout, a full
    backlog, an interrupted call -- proves nothing about the daemon being
    dead, so nothing is unlinked: the answer is simply "run cold this time".
    """
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    # Short on purpose: an implicit scan pays this on every invocation while a
    # socket file exists, so a wedged daemon costs at most these seconds before
    # the silent cold fallback. The one path that legitimately waits longer --
    # the handshake right after an autostart, while the daemon warms its
    # imports -- goes through await_daemon, which re-times its socket to
    # HANDSHAKE_TIMEOUT_SECONDS after connecting.
    sock.settimeout(runtime.CONNECT_TIMEOUT_SECONDS)
    try:
        sock.connect(os.fspath(path))
    except ConnectionRefusedError:
        sock.close()
        _remove_if_dead(path)
        return None
    except OSError:
        sock.close()
        return None
    return sock


def _remove_if_dead(path: PathLike) -> None:
    """Remove a refusing socket file, but only when no daemon is alive for it.

    ``ECONNREFUSED`` alone does not prove death: a daemon between its bind and
    its listen refuses too, so unlinking on the refusal let a second client in
    that window delete a LIVE daemon's socket. The daemon holds an exclusive
    lock on ``<socket>.lock`` for its whole life, so the lock being takeable is
    the proof of death -- and holding it across the unlink serializes this
    removal against a daemon starting right now.
    """
    try:
        import fcntl
    except ImportError:
        return
    try:
        fd = os.open(os.fspath(path) + ".lock", os.O_WRONLY | os.O_CREAT, 0o600)
    except OSError:
        return
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            # A daemon is alive, starting or running: not ours to remove.
            return
        try:
            os.unlink(path)
        except OSError:
            pass
    finally:
        try:
            os.close(fd)
        except OSError:
            pass


def daemon_lock_is_held(path: PathLike) -> bool:
    """Whether some process holds the daemon lock for the socket at *path*.

    The daemon flocks ``<socket>.lock`` exclusively for its whole life, so an
    untakeable lock proves a live holder even when the socket file itself is
    gone -- a daemon wedged between taking the lock and binding, or one whose
    socket was removed by hand. Read-only and best effort: the probe never
    creates the lock file (no ``O_CREAT``), a missing file or platform reads
    as "not held", and a momentarily taken probe lock is simply closed, which
    is the shape :func:`_remove_if_dead` already uses against the same lock.
    """
    try:
        import fcntl
    except ImportError:
        return False
    try:
        fd = os.open(os.fspath(path) + ".lock", os.O_WRONLY)
    except OSError:
        return False
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            return True
        return False
    finally:
        try:
            os.close(fd)
        except OSError:
            pass


def _run_on_daemon(
    sock: socket.socket,
    argv: list[str],
    environ: Mapping[str, str],
    *,
    explicit: bool,
) -> tuple[str, Optional[int]]:
    """One scan over *sock*: hand over the fds, send the request, wait for exit.

    Returns ``("exit", code)`` once the daemon ran the scan. Anything else
    means nothing ran and the caller may fall back: ``("stale", None)`` for a
    refusal a daemon restart cures (version, fingerprint, protocol), and
    ``("fallback", None)`` for the rest (busy, a broken handshake). The commit
    point is the go frame this client sends back on reading the daemon's ok:
    the daemon forks nothing before reading it, so everything up to a failed
    go send may fall back cold -- and once the go is on the wire the scan is
    running against our own stdin/stdout/stderr, so there is no falling back:
    a connection lost after that point is reported and read as exit 1.
    """
    with sock:
        # The whole handshake runs on the handshake budget, whichever path
        # produced the socket. _connect times its socket for the connect
        # itself (CONNECT_TIMEOUT_SECONDS), but the ok can legitimately take
        # far longer: the daemon answers its accept backlog only once its
        # warm imports complete, so a timeout here must mean "fall back
        # cold", never "a healthy daemon was slow". Without this, the
        # implicit path read the ok on the connect budget while only the
        # autostart path (await_daemon) had the handshake budget.
        sock.settimeout(runtime.HANDSHAKE_TIMEOUT_SECONDS)
        request = {
            "op": "scan",
            "protocol": runtime.PROTOCOL_VERSION,
            "version": runtime.ash_version(),
            "fingerprint": runtime.runtime_fingerprint(),
            "argv": list(argv),
            "cwd": os.getcwd(),
            "env": runtime.request_environment(dict(environ)),
            # Reserved: the resident daemon loads no repository config, so
            # invalidation is version/fingerprint-only and the forked child
            # re-reads the config itself. See the express how-to's design notes.
            "config_hash": None,
        }
        reader = runtime.FrameReader(sock)

        # Signal forwarding, installed BEFORE the request goes out, so a
        # Ctrl-C in the handshake window is never delivered to a default
        # handler that would kill this client while the daemon starts the
        # scan. Until the daemon has answered started, a signal is only
        # recorded (writing a frame mid-request would interleave with the
        # request's own bytes); the recorded signals are forwarded the moment
        # started is read. A second Ctrl-C ends the wait at once with the
        # interrupt code, as a cold run's die-now ending does: the forwarded
        # SIGINT is already on its way to the child, and closing the
        # connection makes the daemon SIGTERM it as well.
        state: dict[str, Any] = {
            "started": False,
            "pending": [],
            "deliveries": {},
            "die_now": 130,
        }

        def send_signal_frame(signum: int) -> None:
            try:
                runtime.send_frame(sock, {"op": "signal", "signum": int(signum)})
            except Exception:
                pass

        def forward(signum: int, frame: Optional[FrameType]) -> None:  # noqa: ARG001
            count = state["deliveries"].get(int(signum), 0) + 1
            state["deliveries"][int(signum)] = count
            if not state["started"]:
                state["pending"].append(int(signum))
            else:
                send_signal_frame(signum)
            # The second delivery of an ending signal is "die now", as a cold
            # run's double Ctrl-C is -- and the same for a repeated SIGTERM, so
            # a hung daemon cannot make this client unkillable short of KILL.
            if count >= 2 and signum in (int(signal.SIGINT), int(signal.SIGTERM)):
                state["die_now"] = (
                    128 + int(signum) if signum != int(signal.SIGINT) else 130
                )
                raise KeyboardInterrupt

        previous = {}
        forwarded_signals = [signal.SIGINT, signal.SIGTERM]
        if hasattr(signal, "SIGHUP"):
            # A closed terminal should end the scan the way it ends a cold
            # run's, not leave it running against a gone pty.
            forwarded_signals.append(signal.SIGHUP)
        for signum in forwarded_signals:
            try:
                if signal.getsignal(signum) is signal.SIG_IGN:
                    # An inherited ignore (nohup's SIGHUP, a background job's
                    # SIGINT) means a cold run would have survived this
                    # signal; installing the forwarder here would turn it into
                    # a kill the cold run never saw. Leave it ignored.
                    continue
                previous[signum] = signal.signal(signum, forward)
            except (OSError, ValueError):
                pass
        try:
            try:
                socket.send_fds(sock, [b"\x01"], [0, 1, 2])
                runtime.send_frame(sock, request)
                answer = reader.read_frame()
            except KeyboardInterrupt:
                return ("exit", state["die_now"])
            except (OSError, runtime.ExpressProtocolError) as exc:
                interrupted = _signal_exit_code(state["pending"])
                if interrupted is not None:
                    # A SIGTERM or Ctrl-C arrived while the handshake broke:
                    # falling back cold would run a whole scan the operator
                    # just asked to stop. Exit as the cold run would have.
                    return ("exit", interrupted)
                if explicit:
                    _note(f"ash express: handshake failed: {exc}")
                return ("fallback", None)
            if not answer or not answer.get("ok"):
                interrupted = _signal_exit_code(state["pending"])
                if interrupted is not None:
                    return ("exit", interrupted)
                reason = (answer or {}).get("reason", "no answer")
                if explicit:
                    _note(f"ash express: daemon refused the scan: {reason}")
                return ("stale" if (answer or {}).get("stale") else "fallback", None)

            # The scan is running against our own stdin/stdout/stderr. One
            # KeyboardInterrupt guard covers the whole stretch from here to
            # the exit frame: the die-now raise can land in the flush loop, in
            # settimeout, or in the read, and every one of them is the same
            # "end now with the signal's code", never an escaping traceback.
            try:
                # A signal recorded while the handshake waited (the daemon's
                # warm imports can hold the ok for seconds) ends the run HERE,
                # before the go: nothing has forked, so this is the one free
                # moment to honour the Ctrl-C (or the runner's SIGTERM) as a
                # cold run would -- at once, with that signal's code. Past the
                # go there is a scan to interrupt, and the daemon would fork a
                # whole scan child only for the forwarded signal to kill it.
                # The refusal and broken-handshake roads above do the same.
                interrupted = _signal_exit_code(state["pending"])
                if interrupted is not None:
                    return ("exit", interrupted)
                # The go frame is this client's commit, sent FIRST -- before
                # the signal flush below, because the daemon's inline go read
                # must meet the go, not a signal frame -- and only after it is
                # on the wire does the daemon fork. It exists because the ok
                # alone could not prove this client is still here: an ok
                # landing in the socket buffer in the same instant the
                # handshake timeout fired would leave the daemon scanning for
                # a client already running cold (a double scan). A failed go
                # send is therefore still a safe fallback: no complete go
                # frame reached the wire, so nothing forks.
                try:
                    runtime.send_frame(sock, {"op": "go"})
                except (OSError, runtime.ExpressProtocolError) as exc:
                    interrupted = _signal_exit_code(state["pending"])
                    if interrupted is not None:
                        return ("exit", interrupted)
                    if explicit:
                        _note(f"ash express: handshake failed: {exc}")
                    return ("fallback", None)
                # The recorded signals are flushed by index -- a signal landing
                # mid-flush is appended and picked up by the same loop -- and
                # only then does the handler switch to writing frames itself,
                # with one more drain for a signal that landed between the
                # loop's end and the switch. The switch-then-flush order would
                # have let the handler interleave a frame into the middle of a
                # flush write.
                index = 0
                while index < len(state["pending"]):
                    send_signal_frame(state["pending"][index])
                    index += 1
                state["started"] = True
                while index < len(state["pending"]):
                    send_signal_frame(state["pending"][index])
                    index += 1
                sock.settimeout(None)
                while True:
                    try:
                        frame = reader.read_frame()
                    except (OSError, runtime.ExpressProtocolError) as exc:
                        _note(
                            f"ash express: lost the daemon mid-scan ({exc}); the "
                            "scan's exit code is unknown and is reported as 1."
                        )
                        return ("exit", 1)
                    if frame is None:
                        _note(
                            "ash express: the daemon closed the connection before "
                            "reporting the scan's exit code; reported as 1."
                        )
                        return ("exit", 1)
                    if "exit" in frame:
                        code = frame["exit"]
                        return ("exit", code if isinstance(code, int) else 1)
            except KeyboardInterrupt:
                # The second Ctrl-C (or second SIGTERM): the cold run's
                # die-now ending, at once, with that signal's exit code.
                return ("exit", state["die_now"])
        finally:
            for signum, handler in previous.items():
                try:
                    signal.signal(signum, handler)
                except (OSError, ValueError):
                    pass


def await_daemon(
    path: PathLike, timeout: float = runtime.START_TIMEOUT_SECONDS
) -> Optional[socket.socket]:
    """Poll for the daemon's socket to accept, up to *timeout* seconds."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(1.0)
        try:
            sock.connect(os.fspath(path))
            # The connect poll is tight on purpose, but the socket returned here
            # carries the handshake, and the first request after an autostart
            # lands while the daemon is still warming its imports -- give it the
            # handshake budget, not the poll's second.
            sock.settimeout(runtime.HANDSHAKE_TIMEOUT_SECONDS)
            return sock
        except OSError:
            sock.close()
            time.sleep(0.05)
    return None


def control_request(
    path: PathLike, frame: dict[str, Any], timeout: Optional[float] = None
) -> Optional[dict[str, Any]]:
    """Send one control frame (status, stop) and return the daemon's answer.

    ``None`` when nothing answers. Every request opens with the one hello byte
    the protocol reserves for the descriptor-passing message, so the daemon's
    handshake consumes it and the frame arrives whole; a control request
    simply attaches no descriptors to it.

    *timeout* re-times the socket after the connect, for the read of the
    answer: the connect budget (a few seconds) is right for a probe of a daemon
    that should be up, and wrong for asking a daemon that has just started,
    which answers only once its warm imports finish (the handshake budget).
    """
    sock = _connect(path)
    if sock is None:
        return None
    try:
        with sock:
            if timeout is not None:
                sock.settimeout(timeout)
            sock.sendall(b"\x01")
            runtime.send_frame(sock, frame)
            return runtime.FrameReader(sock).read_frame()
    except (OSError, runtime.ExpressProtocolError):
        return None


def stop_daemon(path: PathLike) -> None:
    """Ask the daemon at *path* to exit, and wait for it to have exited.

    The wait is on the daemon's pid (from the stop answer), not on the socket
    file: the daemon unlinks its own socket, and only its own -- a stopper
    that unlinked the file on a timer once removed a successor daemon's
    socket. A daemon that has not exited within the wait is left as it is,
    socket and all: the caller's fallbacks already cover a daemon that will
    not die, and removing its socket would not kill it, only hide it.
    """
    answer = control_request(path, {"op": "stop"})
    if answer is None:
        return
    pid = answer.get("pid")
    # Longer than the daemon's own child grace (STOP_GRACE_SECONDS plus its
    # select tick and reaping), so a stop during a slow-dying scan is not
    # mis-read as a daemon that refused to exit.
    deadline = time.monotonic() + runtime.STOP_WAIT_SECONDS
    while time.monotonic() < deadline:
        if isinstance(pid, int):
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                return
            except OSError:
                return
        elif not os.path.exists(path):
            return
        time.sleep(0.05)


def autostart(environ: Mapping[str, str]) -> bool:
    """Start the daemon, detached, by double-fork from this thin process.

    True once the daemon has bound its socket (its readiness byte arrived);
    False when it died first or never answered within the start window, so the
    caller can fall back cold at once instead of polling a socket that will
    never exist.

    The intermediate child calls ``setsid`` and forks again, so the daemon has
    no controlling terminal and is not this client's child; the client reaps
    only the intermediate. The daemon's stdout/stderr go to the express log
    file, its stdin to the null device, its working directory to the runtime
    directory, and its environment to the scrubbed set
    (:func:`runtime.scrubbed_daemon_environment`): the daemon outlives this
    invocation, so this invocation's incidentals -- a commit hook's
    ``GIT_INDEX_FILE``, a shell's credentials -- must not become ambient state
    under every later scan. The heavy imports happen in the daemon after it
    binds its socket, which is why the client's wait (:func:`await_daemon`) is
    short.
    """
    if runtime.recent_retirement(runtime.socket_path()):
        # A daemon retired itself over threads a moment ago: another would pay
        # the whole warm-import cost to retire the same way. Back off; the
        # scan runs cold, and the marker expires on its own.
        return False
    log_file = runtime.log_path()
    idle = runtime.idle_seconds(dict(environ))
    scrubbed = runtime.scrubbed_daemon_environment(dict(environ))
    # Flushed before the fork: buffered output would otherwise be duplicated
    # into the daemon and land a second time in its log file.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.flush()
        except Exception:
            pass
    # The readiness pipe: the daemon writes one byte the moment its socket is
    # bound and listening, and a grandchild that dies first closes the pipe
    # with no byte -- so a daemon that cannot start (an import error, a bind
    # refusal) is known here within milliseconds, not after a whole poll
    # window on every invocation.
    ready_read, ready_write = os.pipe()
    middle = os.fork()
    if middle == 0:
        # Intermediate child, then daemon. Every path out of here is os._exit:
        # this process must never return into the client's Python stack.
        code = 1
        try:
            os.close(ready_read)
            os.setsid()
            if os.fork() > 0:
                os._exit(0)
            os.chdir(os.fspath(runtime.runtime_dir()))
            # The scrub, through the locked helpers: everything not in the
            # scrubbed set is removed, the rest set to the scrubbed values.
            # This forked child is single-threaded, so the lock is free.
            overrides: dict[str, Optional[str]] = {
                name: None for name in snapshot_environ() if name not in scrubbed
            }
            overrides.update(scrubbed)
            apply_environ_overrides(overrides)
            null = os.open(os.devnull, os.O_RDONLY)
            os.dup2(null, 0)
            os.close(null)
            log = os.open(
                os.fspath(log_file), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600
            )
            os.dup2(log, 1)
            os.dup2(log, 2)
            os.close(log)
            # Nothing of the starting process's descriptor table may outlive
            # the start: a fork without an exec inherits every open fd, and a
            # CI status pipe or a make jobserver fd held open here would keep
            # its reader waiting for EOF until the daemon idled out.
            try:
                limit = os.sysconf("SC_OPEN_MAX")
            except (OSError, ValueError):
                limit = 65536
            if not isinstance(limit, int) or limit <= 0:
                limit = 65536
            # Everything but the readiness pipe's write end, which the daemon
            # closes itself right after it binds.
            os.closerange(3, ready_write)
            os.closerange(ready_write + 1, limit)
            from automated_security_helper.express.daemon import serve

            serve(idle_timeout=idle, ready_fd=ready_write)
            code = 0
        except BaseException:
            code = 1
        finally:
            os._exit(code)
    os.close(ready_write)
    os.waitpid(middle, 0)
    return _await_readiness(ready_read)


def _await_readiness(ready_read: int) -> bool:
    """Wait for the readiness byte on *ready_read*, then close it.

    One byte means a daemon serves: ours (``\\x01``, bound and listening) or a
    concurrent start's winner (``\\x02``, whose socket the loser found owned).
    EOF with no byte means the launched daemon died before binding, and the
    timeout means nothing answered within the start window.
    """
    deadline = time.monotonic() + runtime.START_TIMEOUT_SECONDS
    became_ready = False
    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            readable, _, _ = select.select([ready_read], [], [], remaining)
            if not readable:
                break
            became_ready = os.read(ready_read, 1) in (b"\x01", b"\x02")
            break
    except OSError:
        became_ready = False
    finally:
        try:
            os.close(ready_read)
        except OSError:
            pass
    return became_ready


def spawn_daemon_process(environ: Mapping[str, str]) -> bool:
    """Start the daemon in a fresh interpreter, detached; True once it serves.

    This is the launch for a caller that is not thin any more: ``ash express
    start`` reaches here after the whole CLI import, with rich, typer and the
    logging stack initialized and main's signal handlers installed, and a fork
    with no exec would carry that state (and any lock an import holds) into
    the daemon. A new ``sys.executable`` begins in the one state the daemon's
    own module expects. The interpreter's argv comes from
    :func:`~automated_security_helper.utils.python_child.python_code_argv`, so
    it imports nothing from the directory it starts in, and the launch itself
    is :func:`~automated_security_helper.express.spawn.start_detached`, the one
    spawn the subprocess choke point exempts (the daemon is ASH itself, never a
    scanner). The environment is the daemon scrub, which keeps the
    interpreter-shaping variables (:data:`runtime.INTERPRETER_ENV`): this
    interpreter resolves the same ASH tree as the client that started it, and
    the fingerprint hashes the values that matter, so a later client whose
    values differ reads the daemon as stale. The implicit scan path keeps
    :func:`autostart`'s double fork: that caller runs before the heavy import,
    single-threaded, which is the state a bare fork is safe in.
    """
    from automated_security_helper.express import spawn
    from automated_security_helper.utils.python_child import python_code_argv

    idle = runtime.idle_seconds(dict(environ))
    scrubbed = runtime.scrubbed_daemon_environment(dict(environ))
    log_file = runtime.log_path()
    runtime_dir = runtime.runtime_dir()
    ready_read, ready_write = os.pipe()
    os.set_inheritable(ready_write, True)
    bootstrap = python_code_argv(
        "import sys\n"
        "from automated_security_helper.express.daemon import serve\n"
        "serve(idle_timeout=float(sys.argv[1]), ready_fd=int(sys.argv[2]))\n"
    )
    # This client's import flags (-s, -E, -I) go to the daemon's interpreter, so
    # it imports the package set its client sees and computes its client's
    # socket key (runtime.interpreter_shape).
    argv = (
        bootstrap[:1]
        + runtime.interpreter_flags()
        + bootstrap[1:]
        + [str(float(idle)), str(ready_write)]
    )
    # The daemon's own stdout/stderr go to the express log file, as the
    # autostart path arranges with its dup2s.
    log = os.open(os.fspath(log_file), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    try:
        spawn.start_detached(
            argv,
            env=scrubbed,
            cwd=os.fspath(runtime_dir),
            log_fd=log,
            keep_fd=ready_write,
        )
    except (OSError, ValueError):
        try:
            os.close(ready_read)
        except OSError:
            pass
        return False
    finally:
        try:
            os.close(log)
        except OSError:
            pass
        try:
            os.close(ready_write)
        except OSError:
            pass
    return _await_readiness(ready_read)
