# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The thin express client the console entry point consults before the heavy import.

:func:`delegated_exit_code` is the whole interface: given the process argv
(after the program name), it returns the exit code of a scan the daemon ran, or
``None``, which tells the entry point to run cold in-process exactly as it
always has. Everything here is standard library; the first heavy import is what
the ``None`` answer leads to.

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
        environ = os.environ
    try:
        return _delegated_exit_code(argv, environ)
    except Exception as exc:  # noqa: BLE001 - the fallback is the contract
        if wants_express(argv):
            _note(f"ash express: falling back to a cold run: {exc}")
        return None


def _delegated_exit_code(argv: list[str], environ: Mapping[str, str]) -> Optional[int]:
    if environ.get(runtime.CHILD_ENV):
        return None
    if not runtime.express_supported():
        return None
    if not is_scan_invocation(argv):
        return None
    explicit = wants_express(argv)
    path = runtime.socket_path()

    sock = _connect(path)
    if sock is None and not explicit:
        return None
    if sock is None:
        autostart(environ)
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
    _stop_daemon(path)
    autostart(environ)
    sock = await_daemon(path)
    if sock is None:
        _note("ash express: the daemon did not come back up; running cold.")
        return None
    outcome, detail = _run_on_daemon(sock, argv, environ, explicit=explicit)
    if outcome == "exit":
        return detail
    _note("ash express: the restarted daemon still refused; running cold.")
    return None


def _note(text: str) -> None:
    """One line to stderr, best effort: a broken stderr must not fail the scan."""
    try:
        print(text, file=sys.stderr, flush=True)
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
    sock.settimeout(5.0)
    try:
        sock.connect(os.fspath(path))
    except ConnectionRefusedError:
        sock.close()
        try:
            os.unlink(path)
        except OSError:
            pass
        return None
    except OSError:
        sock.close()
        return None
    return sock


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
    ``("fallback", None)`` for the rest (busy, a broken handshake). Once the
    daemon has answered started, the scan is running against our own
    stdin/stdout/stderr, so there is no falling back: a connection lost after
    that point is reported and read as exit 1.
    """
    with sock:
        request = {
            "op": "scan",
            "protocol": runtime.PROTOCOL_VERSION,
            "version": runtime.ash_version(),
            "fingerprint": runtime.runtime_fingerprint(),
            "argv": list(argv),
            "cwd": os.getcwd(),
            "env": runtime.honored_env(dict(environ)),
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
        state: dict[str, Any] = {"interrupts": 0, "started": False, "pending": []}

        def forward(signum: int, frame: Optional[FrameType]) -> None:  # noqa: ARG001
            if signum == int(signal.SIGINT):
                state["interrupts"] += 1
            if not state["started"]:
                state["pending"].append(int(signum))
            else:
                try:
                    runtime.send_frame(sock, {"op": "signal", "signum": int(signum)})
                except Exception:
                    pass
            if signum == int(signal.SIGINT) and state["interrupts"] >= 2:
                raise KeyboardInterrupt

        previous = {}
        forwarded_signals = [signal.SIGINT, signal.SIGTERM]
        if hasattr(signal, "SIGHUP"):
            # A closed terminal should end the scan the way it ends a cold
            # run's, not leave it running against a gone pty.
            forwarded_signals.append(signal.SIGHUP)
        for signum in forwarded_signals:
            try:
                previous[signum] = signal.signal(signum, forward)
            except (OSError, ValueError):
                pass
        try:
            try:
                socket.send_fds(sock, [b"\x01"], [0, 1, 2])
                runtime.send_frame(sock, request)
                answer = reader.read_frame()
            except KeyboardInterrupt:
                return ("exit", 130)
            except (OSError, runtime.ExpressProtocolError) as exc:
                if explicit:
                    _note(f"ash express: handshake failed: {exc}")
                return ("fallback", None)
            if not answer or not answer.get("ok"):
                reason = (answer or {}).get("reason", "no answer")
                if explicit:
                    _note(f"ash express: daemon refused the scan: {reason}")
                return ("stale" if (answer or {}).get("stale") else "fallback", None)

            # The scan is running against our own stdin/stdout/stderr.
            state["started"] = True
            for signum in state["pending"]:
                try:
                    runtime.send_frame(sock, {"op": "signal", "signum": signum})
                except Exception:
                    pass
            sock.settimeout(None)
            while True:
                try:
                    frame = reader.read_frame()
                except KeyboardInterrupt:
                    # The second Ctrl-C: the cold run's die-now code, at once.
                    return ("exit", 130)
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
            return sock
        except OSError:
            sock.close()
            time.sleep(0.05)
    return None


def control_request(path: PathLike, frame: dict[str, Any]) -> Optional[dict[str, Any]]:
    """Send one control frame (status, stop) and return the daemon's answer.

    ``None`` when nothing answers. Every request opens with the one hello byte
    the protocol reserves for the descriptor-passing message, so the daemon's
    handshake consumes it and the frame arrives whole; a control request
    simply attaches no descriptors to it.
    """
    sock = _connect(path)
    if sock is None:
        return None
    try:
        with sock:
            sock.sendall(b"\x01")
            runtime.send_frame(sock, frame)
            return runtime.FrameReader(sock).read_frame()
    except (OSError, runtime.ExpressProtocolError):
        return None


def _stop_daemon(path: PathLike) -> None:
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
    deadline = time.monotonic() + 5.0
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


def autostart(environ: Mapping[str, str]) -> None:
    """Start the daemon, detached, by double-fork from this thin process.

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
    log_file = runtime.log_path()
    idle = runtime.idle_seconds(dict(environ))
    scrubbed = runtime.scrubbed_daemon_environment(dict(environ))
    middle = os.fork()
    if middle == 0:
        # Intermediate child, then daemon. Every path out of here is os._exit:
        # this process must never return into the client's Python stack.
        code = 1
        try:
            os.setsid()
            if os.fork() > 0:
                os._exit(0)
            os.chdir(os.fspath(runtime.runtime_dir()))
            os.environ.clear()
            os.environ.update(scrubbed)
            null = os.open(os.devnull, os.O_RDONLY)
            os.dup2(null, 0)
            os.close(null)
            log = os.open(
                os.fspath(log_file), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600
            )
            os.dup2(log, 1)
            os.dup2(log, 2)
            os.close(log)
            from automated_security_helper.express.daemon import serve

            serve(idle_timeout=idle)
            code = 0
        except BaseException:
            code = 1
        finally:
            os._exit(code)
    os.waitpid(middle, 0)
