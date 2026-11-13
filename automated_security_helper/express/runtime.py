# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""What the express client and daemon share: paths, identity, and the wire protocol.

Standard library only, at module scope and below -- plus
``utils.process_env``, itself standard library only, for the locked
environment reads the package requires everywhere: the client imports this
before the heavy CLI, and anything heavier here would spend the startup time
express exists to remove.

The socket lives in a directory this module creates and polices
(:func:`runtime_dir`): mode 0700, owned by the invoking user, never reached
through a symlink. Its name carries the uid and a hash of the ASH version
(:func:`socket_path`), so two users, or two ASH versions, never share a socket,
and upgrading ASH strands the old daemon at its old path, where its idle timer
retires it. The handshake then compares a finer fingerprint of the installed
package set (:func:`runtime_fingerprint`), which catches an environment change
the version number does not show.

The protocol is one JSON object per line (UTF-8, ``\\n``-terminated), capped at
:data:`MAX_FRAME_BYTES`, with the client's stdin/stdout/stderr passed once as
file descriptors over the socket (``SCM_RIGHTS``) ahead of the request frame.
The forked scan child writes to those descriptors directly, so its output --
colors, progress, isatty decisions -- is the cold run's, byte for byte; the
frames carry only control: the request, the started/refused answer, forwarded
signals, and the exit code.
"""

from __future__ import annotations

import hashlib
import json
import os
import socket
import struct
import sys
from pathlib import Path
from typing import Any, Callable, Mapping, MutableMapping, Optional

from automated_security_helper.utils.process_env import snapshot_environ

#: Bumped when a frame's shape changes incompatibly. The daemon refuses a
#: request whose protocol differs, and the client reads that refusal as a stale
#: daemon (fall back cold; restart it under --express).
#: 2: the client answers the daemon's scan ok with a ``{"op": "go"}`` frame,
#: and the daemon forks only after reading it (the double-scan window's
#: close; see _start_scan and _run_on_daemon).
PROTOCOL_VERSION = 2

#: A frame larger than this is a protocol error, not a request to honour: the
#: legitimate frames are argv, cwd and a bounded environment subset, which fit
#: in a fraction of it, and an unbounded readline would let a broken writer
#: grow the reader's buffer without limit.
MAX_FRAME_BYTES = 1024 * 1024

#: Set in the environment of every forked scan child (and honoured by the
#: client, which never delegates when it is set), so a scan running inside the
#: daemon can never try to delegate to the daemon again.
CHILD_ENV = "ASH_EXPRESS_CHILD"

#: Seconds since the last request after which an idle daemon exits.
DEFAULT_IDLE_SECONDS = 30 * 60

#: Environment variable that overrides :data:`DEFAULT_IDLE_SECONDS` for
#: ``ash express start`` and for the daemon an autostart spawns.
IDLE_ENV = "ASH_EXPRESS_IDLE_SECONDS"

#: How long the client gives an autostarted daemon to come up before it gives
#: up and runs cold. The daemon binds its socket before the warm imports, so
#: this covers process start, not the imports.
START_TIMEOUT_SECONDS = 20.0

#: How long the client waits for the daemon to answer a handshake. Sized to
#: cover the warm-import window: the daemon binds its socket first and enters
#: its accept loop only once the imports are done, so the first request after
#: an autostart legitimately waits several seconds (more on a loaded CI
#: runner) with the connection sitting in the listen backlog. A short timeout
#: here made exactly the scan that started the daemon run cold.
HANDSHAKE_TIMEOUT_SECONDS = 30.0

#: How long the client gives a connect on an existing socket file. Short on
#: purpose: an implicit scan meets this on every invocation while a socket
#: file exists, so a wedged daemon may cost at most these seconds before the
#: silent cold fallback. This times the CONNECT only: the handshake that
#: follows legitimately waits out the warm imports on every path, so
#: _run_on_daemon re-times the socket to HANDSHAKE_TIMEOUT_SECONDS before its
#: first read.
CONNECT_TIMEOUT_SECONDS = 5.0

#: How long the daemon gives a running scan after SIGTERM before the SIGKILL
#: escalation at shutdown -- and, with margin for the daemon's own select tick
#: and reaping, how long a stopper waits for the daemon's pid to go away
#: before calling the stop incomplete. One pair of constants, so the stopper
#: can never be made a liar by the grace it is itself granting.
STOP_GRACE_SECONDS = 5.0
STOP_WAIT_SECONDS = 10.0

#: The names a scan request never carries. Everything else travels: a cold
#: run sees the whole shell environment, and any allowlist here was one
#: forgotten scanner variable away from "same command, different findings"
#: (SEMGREP_*, PIP_*, NPM_CONFIG_*, KUBECONFIG, SSH_AUTH_SOCK, ... -- the list
#: of things scanners read has no closed form). The request travels over the
#: same-uid 0600 socket in the 0700 runtime directory, is applied to the one
#: forked child, and never lands in the daemon's own resident environment, so
#: a credential in it has the same reach it has in a cold run's process. The
#: denied name: the express child marker (a client's stale copy must never
#: stop the forked scan's own re-delegation guard from being set fresh).
#:
#: ``LD_PRELOAD`` and the other loader variables are NOT filtered: a cold run
#: hands every scanner subprocess the client's value, so dropping it made a warm
#: scan's scanners run without a library the same command cold runs with -- the
#: one difference express may not introduce -- and bought no protection, since
#: the peer is already checked to be this uid and that user can preload anything
#: in a cold run. (The warm daemon's OWN process is not preloaded with the
#: client's value; that is a limit of a forked process, as for any variable the
#: dynamic loader reads at exec.)
REQUEST_ENV_DENYLIST = frozenset({"ASH_EXPRESS_CHILD"})

#: Execution basics the forked child takes from the client rather than from the
#: shell the daemon happened to be started in: scanner subprocesses are resolved
#: through PATH, temporary files land under TMPDIR, and locale decides stream
#: codecs. Without these a scan through the daemon could find different tools
#: than the same command run cold from the same shell.
EXECUTION_ENV_EXACT = frozenset(
    {
        "PATH",
        "HOME",
        "TMPDIR",
        "TMP",
        "TEMP",
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
    }
)


class ExpressUnavailable(Exception):
    """Express mode cannot run here: the reason is the message.

    Raised for a platform with no unix sockets or no descriptor passing, and
    for a runtime directory that cannot be made safe (a symlink, another
    owner, a mode that cannot be corrected). The client reads it as "run
    cold"; ``ash express start`` prints it.
    """


class ExpressProtocolError(Exception):
    """The peer wrote something that is not this protocol."""


def peer_credentials_supported() -> bool:
    """Whether this platform can read a unix peer's uid from the kernel.

    Linux (``SO_PEERCRED``) and macOS (``LOCAL_PEERCRED``); see
    :func:`peer_uid`. Part of :func:`express_supported` on purpose: the daemon
    refuses every peer whose uid it cannot read, so a platform without a
    peer-credential read would start a daemon that serves nobody -- better to
    refuse cleanly up front than to look started while silently serving
    nothing.
    """
    return hasattr(socket, "SO_PEERCRED") or sys.platform == "darwin"


def express_supported() -> bool:
    """Whether this platform can run express mode at all.

    Unix only, and only where the stdlib exposes descriptor passing
    (``socket.send_fds``/``recv_fds``, Python 3.9+ on posix), ``os.fork``, and
    a kernel peer-credential read (:func:`peer_credentials_supported`). No TCP
    fallback exists on purpose; a platform without unix sockets has no express
    mode rather than a network listener.
    """
    return (
        os.name == "posix"
        and hasattr(socket, "AF_UNIX")
        and hasattr(socket, "send_fds")
        and hasattr(socket, "recv_fds")
        and hasattr(os, "fork")
        and peer_credentials_supported()
    )


def _require_supported() -> None:
    if not express_supported():
        raise ExpressUnavailable(
            "express mode needs a posix platform with unix-domain sockets and "
            "file-descriptor passing (socket.send_fds); this platform has no "
            "express mode and every scan runs cold in-process."
        )


def ash_version() -> str:
    """The installed ASH version, read through the light version module."""
    from automated_security_helper.utils.get_ash_version import get_ash_version

    return get_ash_version()


def _site_directories() -> list[str]:
    """The interpreter's site directories (system and user), not all of ``sys.path``."""
    try:
        import site

        directories = list(site.getsitepackages())
        directories.append(site.getusersitepackages())
    except Exception:  # noqa: BLE001 - a -S interpreter has no site module
        directories = [
            entry for entry in sys.path if entry and "site-packages" in entry
        ]
    return directories


def _site_entries() -> list[str]:
    """The ``*.dist-info``/``*.egg-info`` directory names in the site
    directories, sorted.

    A cheap, stable listing of the installed package set: those names carry the
    distribution name and version, and listing directories costs milliseconds
    where importing ``importlib.metadata`` and reading every distribution costs
    a noticeable slice of the startup this module exists to remove.

    The site directories, deliberately not all of ``sys.path``: under
    ``python -m`` the path starts with the invocation directory, so a
    ``dist-info`` that happens to sit in the scanned project would have poisoned
    the fingerprint of every scan run from there, and the daemon would have read
    as permanently stale from that one directory. Directories that cannot be
    listed are skipped: the fingerprint has to be computable everywhere, and
    the client and the daemon compute it over the same survivors.
    """
    names: set[str] = set()
    for entry in _site_directories():
        try:
            listed = os.scandir(entry)
        except OSError:
            continue
        with listed:
            for item in listed:
                if item.name.endswith((".dist-info", ".egg-info")):
                    # The mtime beside the name: a reinstall of the SAME
                    # version rewrites the dist-info, so it must read as a
                    # different environment though no name changed.
                    try:
                        stamp = item.stat().st_mtime_ns
                    except OSError:
                        stamp = 0
                    names.add(f"{item.name}:{stamp}")
    return sorted(names)


def _own_tree_stamp() -> str:
    """A stamp of ASH's own source tree: newest mtime and file count -- for
    editable installs and source checkouts only.

    An editable install's code changes with no dist-info change at all: a
    developer's edit-scan loop against a warm daemon would otherwise serve the
    pre-edit code for up to the idle window, silently. The whole package is
    walked (it holds many modules and vendored data, so the walk is the cost
    this function exists to pay only where it buys something).

    A regular install is fixed by its dist-info (name, version and mtime, which
    :func:`_site_entries` already hashes: a reinstall rewrites it), so a package
    that sits INSIDE a site directory is not walked and stamps as ``installed``.
    "Editable" is read from where the package is: outside every site directory.
    """
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    package_parent = os.path.realpath(os.path.dirname(root))
    for site_directory in _site_directories():
        if os.path.realpath(site_directory) == package_parent:
            return "installed"
    newest = 0
    count = 0
    for directory, _, files in os.walk(root):
        for name in files:
            if not name.endswith(".py"):
                continue
            count += 1
            try:
                mtime = os.stat(os.path.join(directory, name)).st_mtime_ns
            except OSError:
                continue
            if mtime > newest:
                newest = mtime
    return f"{count}:{newest}"


def runtime_fingerprint() -> str:
    """A fingerprint of the environment a scan would run in.

    The interpreter (version and real executable path) and the installed
    package set (:func:`_site_entries`), hashed. The daemon records its own at
    start; a client whose fingerprint differs is running against different
    code, and the daemon's warm imports would scan with the old one -- so the
    handshake refuses and the client falls back cold (restarting the daemon
    under ``--express``). The package set carries each entry's mtime, so a
    reinstall of the same versions still reads as a change, and ASH's own
    source tree is stamped (:func:`_own_tree_stamp`), so an editable install's
    edits do too. The ASH version and the interpreter-shaping variables are
    not part of it because the socket path already carries them
    (:func:`socket_path`, :func:`interpreter_shape`): a client whose
    ``PYTHONPATH`` differs reaches a different daemon, never a stale one.
    """
    digest = hashlib.sha256()
    digest.update(sys.version.encode("utf-8", "backslashreplace"))
    digest.update(b"\x00")
    digest.update(
        os.path.realpath(sys.executable or "").encode("utf-8", "backslashreplace")
    )
    digest.update(b"\x00")
    digest.update(_own_tree_stamp().encode("utf-8"))
    for name in _site_entries():
        digest.update(b"\x00")
        digest.update(name.encode("utf-8", "backslashreplace"))
    return digest.hexdigest()


def absolute_python_path(value: str) -> str:
    """*value* (a ``PYTHONPATH``) with every entry made absolute against the
    current directory.

    A relative entry (``.``, ``plugins``) is read by each process against its
    own working directory, and the daemon starts in the runtime directory, so
    the same text names different code in the client and in the daemon. The
    client makes its entries absolute once, before anything is hashed or
    handed to a daemon, so both sides hold the same paths. An empty entry is
    the current directory to Python, and is made so too.
    """
    if not value:
        return ""
    return os.pathsep.join(os.path.abspath(entry) for entry in value.split(os.pathsep))


def interpreter_shape(environ: Optional[Mapping[str, str]] = None) -> str:
    """The values that decide which code an interpreter of ours imports, as text.

    ``PYTHONPATH`` (absolute entries, :func:`absolute_python_path`),
    ``PYTHONHOME``, ``PYTHONUSERBASE``, ``PYTHONNOUSERSITE`` and ``VIRTUAL_ENV``
    (:data:`INTERPRETER_ENV`). They are the daemon's own: it keeps them across
    the scrub, so a daemon computes the same text from its environment that its
    starting client computed from theirs. The names are spelled as literals
    where they are read so the environment-variable reference resolves them.
    """
    if environ is None:
        environ = snapshot_environ()
    python_path = absolute_python_path(environ.get("PYTHONPATH", ""))
    return "\x00".join(
        (
            python_path,
            environ.get("PYTHONHOME", ""),
            environ.get("PYTHONUSERBASE", ""),
            environ.get("PYTHONNOUSERSITE", ""),
            environ.get("VIRTUAL_ENV", ""),
        )
    )


def socket_key(
    version: Optional[str] = None,
    uid: Optional[int] = None,
    prefix: Optional[str] = None,
    shape: Optional[str] = None,
) -> str:
    """The short key the socket and log file names carry: hash of (uid,
    version, installation prefix, interpreter shape).

    The prefix (``sys.prefix``, resolved) is part of the key so two
    installations of the same ASH version -- two virtualenvs, say -- never
    share a socket. Without it the second environment's every request would
    fingerprint-refuse against the first one's daemon, and two ``--express``
    users would stop and restart each other's daemons forever.

    The interpreter shape (:func:`interpreter_shape`) is part of it for the same
    reason: two shells that differ only in ``PYTHONPATH`` (a pre-commit hook and
    an IDE terminal, tox and a plain shell) import different plugin code, so
    each gets a daemon of its own instead of reading the other's as stale and
    restarting it, scans in flight included, forever. The key stays 16 hex
    characters, so the socket path's length is unchanged.
    """
    if version is None:
        version = ash_version()
    if uid is None:
        uid = os.getuid()
    if prefix is None:
        prefix = os.path.realpath(sys.prefix)
    if shape is None:
        shape = interpreter_shape()
    digest = hashlib.sha256(f"{uid}:{version}:{prefix}:{shape}".encode("utf-8"))
    return digest.hexdigest()[:16]


def _ensure_private_dir(path: Path) -> Path:
    """Make *path* a private (0700) directory of this user's, or refuse.

    Refusals are :class:`ExpressUnavailable`, so the caller runs cold: a
    directory reached through a symlink, owned by someone else, or whose mode
    cannot be brought to 0700 is not a place to put a credential-equivalent
    socket. The mode of an existing directory this user owns is corrected
    rather than refused -- an older umask should not strand express mode -- and
    checked again after the chmod.
    """
    try:
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
    except OSError as exc:
        raise ExpressUnavailable(
            f"express runtime directory {path} cannot be created: {exc}"
        ) from None
    try:
        info = os.lstat(path)
    except OSError as exc:
        raise ExpressUnavailable(
            f"express runtime directory {path} cannot be read: {exc}"
        ) from None
    import stat as stat_module

    if stat_module.S_ISLNK(info.st_mode) or not stat_module.S_ISDIR(info.st_mode):
        raise ExpressUnavailable(
            f"express runtime directory {path} is not a directory reached without "
            "following a link; refusing to place a socket there."
        )
    if info.st_uid != os.getuid():
        raise ExpressUnavailable(
            f"express runtime directory {path} is owned by uid {info.st_uid}, not "
            f"this user ({os.getuid()}); refusing to place a socket there."
        )
    if stat_module.S_IMODE(info.st_mode) != 0o700:
        try:
            os.chmod(path, 0o700)
        except OSError as exc:
            raise ExpressUnavailable(
                f"express runtime directory {path} mode "
                f"{oct(stat_module.S_IMODE(info.st_mode))} cannot be corrected "
                f"to 0700: {exc}"
            ) from None
        if stat_module.S_IMODE(os.lstat(path).st_mode) != 0o700:
            raise ExpressUnavailable(
                f"express runtime directory {path} did not take mode 0700."
            )
    return path


def runtime_dir(environ: Optional[Mapping[str, str]] = None) -> Path:
    """The private directory the socket and daemon log live in.

    ``$XDG_RUNTIME_DIR/ash-express`` where the variable names a directory (the
    per-user tmpfs systemd provides, already 0700 and cleared at logout), else
    ``~/.ash/run``. Either way the leaf directory is created and policed by
    :func:`_ensure_private_dir`.
    """
    _require_supported()
    if environ is None:
        environ = snapshot_environ()
    base = environ.get("XDG_RUNTIME_DIR", "")
    if base and os.path.isdir(base):
        return _ensure_private_dir(Path(base) / "ash-express")
    # HOME from the mapping the caller gave, so a caller that passes an
    # explicit environment controls the result; the platform's own answer
    # (Path.home) only when the mapping has none.
    home = environ.get("HOME", "")
    return _ensure_private_dir((Path(home) if home else Path.home()) / ".ash" / "run")


#: The longest socket path this module will bind or connect to. AF_UNIX's
#: sun_path caps at 108 bytes on Linux and 104 on macOS (NUL included); past
#: this, bind() fails after the daemon has already forked, so the length is
#: refused up front and the scan runs cold instead of stalling a start window.
MAX_SOCKET_PATH_BYTES = 103


def socket_path(environ: Optional[Mapping[str, str]] = None) -> Path:
    """The unix socket path for this uid and ASH installation."""
    path = runtime_dir(environ) / f"ash-{os.getuid()}-{socket_key()}.sock"
    encoded = len(os.fsencode(os.fspath(path)))
    if encoded > MAX_SOCKET_PATH_BYTES:
        raise ExpressUnavailable(
            f"the socket path is {encoded} bytes, over the {MAX_SOCKET_PATH_BYTES}"
            f"-byte AF_UNIX limit this module binds within: {path}"
        )
    return path


def log_path(environ: Optional[Mapping[str, str]] = None) -> Path:
    """Where a daemonized express daemon sends its stdout/stderr."""
    return runtime_dir(environ) / f"ash-{os.getuid()}-{socket_key()}.log"


def idle_seconds(environ: Optional[Mapping[str, str]] = None) -> int:
    """The configured idle timeout: :data:`IDLE_ENV`, else the default.

    A value that is not a positive integer is ignored rather than refused --
    the daemon's lifetime is not worth failing a scan over -- and the default
    stands.
    """
    if environ is None:
        # Seconds of inactivity after which an idle express daemon exits.
        # `ash express start --idle-seconds` writes it for the daemon it
        # starts, and an autostarted daemon inherits it from the scan's shell.
        # Read through the locked snapshot, under the one constant.
        environ = snapshot_environ()
    raw = environ.get(IDLE_ENV, "")
    try:
        value = int(raw)
    except (TypeError, ValueError):
        return DEFAULT_IDLE_SECONDS
    return value if value > 0 else DEFAULT_IDLE_SECONDS


def request_environment(
    environ: Optional[Mapping[str, str]] = None,
) -> dict[str, str]:
    """The environment a scan request carries: the client's, in full, minus
    :data:`REQUEST_ENV_DENYLIST`.

    The forked child's environment becomes exactly this (plus the child
    marker), so a variable a scanner reads -- whichever scanner, whatever the
    variable -- has the same value warm and cold. The earlier allowlist was
    one forgotten name away from "same command, different findings", which is
    the one thing express may never produce.
    """
    if environ is None:
        environ = snapshot_environ()
    return {
        name: value
        for name, value in environ.items()
        if name not in REQUEST_ENV_DENYLIST
    }


def apply_request_env(
    request_env: dict[str, str], environ: MutableMapping[str, str]
) -> None:
    """Make *environ* exactly *request_env*, except the express internals.

    Run in the forked child before it drops into the CLI: every name the
    request lacks is removed (a stale ``ASH_CONFIG`` in the daemon's own
    environment must not reach a client that unset it; the daemon's residual
    names must not reach a scan at all), the request's pairs are set, and
    :data:`CHILD_ENV` is never removed or overwritten by a request, so a
    request cannot clear the one variable that stops re-delegation.
    """
    for name, value in request_env_overrides(request_env, environ).items():
        if value is None:
            environ.pop(name, None)
        else:
            environ[name] = value


def request_env_overrides(
    request_env: Mapping[str, str], current: Mapping[str, str]
) -> dict[str, Optional[str]]:
    """:func:`apply_request_env`'s plan as a set/remove mapping (``None`` =
    remove), the shape ``utils.process_env.apply_environ_overrides`` takes, for
    the forked child that applies it to the real environment under the lock."""
    overrides: dict[str, Optional[str]] = {
        name: None for name in current if name not in request_env and name != CHILD_ENV
    }
    for name, value in request_env.items():
        if name == CHILD_ENV or name in REQUEST_ENV_DENYLIST:
            continue
        overrides[name] = value
    return overrides


#: The interpreter-shaping variables: they decide which ASH tree and which site
#: set a Python process resolves. The daemon KEEPS them on both start paths
#: (:func:`scrubbed_daemon_environment`), so the fresh interpreter ``ash express
#: start`` launches imports the same code its starting client runs (an ASH
#: checkout reachable only through ``PYTHONPATH``, a ``PYTHONUSERBASE`` site)
#: instead of failing its first import or resolving another user site. Their
#: values are part of the socket key (:func:`interpreter_shape`), so a client
#: with other values reaches a daemon of its own rather than a stale one.
INTERPRETER_ENV = (
    "PYTHONPATH",
    "PYTHONHOME",
    "PYTHONUSERBASE",
    "PYTHONNOUSERSITE",
    "VIRTUAL_ENV",
)

#: What an autostarted daemon's own environment keeps
#: (:func:`scrubbed_daemon_environment`): the execution basics, the terminal
#: and runtime-directory context, the interpreter-shaping variables, and the
#: one express setting the daemon reads.
DAEMON_ENV_KEPT = frozenset(
    {
        *EXECUTION_ENV_EXACT,
        *INTERPRETER_ENV,
        "USER",
        "LOGNAME",
        "SHELL",
        "TERM",
        "XDG_RUNTIME_DIR",
        "PYTHONIOENCODING",
        IDLE_ENV,
    }
)


def scrubbed_daemon_environment(environ: Mapping[str, str]) -> dict[str, str]:
    """What survives of *environ* into an autostarted daemon.

    The daemon is autostarted from whatever invocation happened to come first,
    and it outlives that invocation by up to the idle window -- so the first
    scan's incidentals (``GIT_INDEX_FILE`` from a commit hook, cloud
    credentials in the shell) must not become ambient state every later scan's
    child inherits. Only the names in :data:`DAEMON_ENV_KEPT` survive -- the
    interpreter-shaping set (:data:`INTERPRETER_ENV`) among them, because it
    decides which ASH tree the daemon's own interpreter resolves and the
    fingerprint covers its values. The scan's environment travels in each
    scan's own request instead (:func:`request_environment`), and the child's
    environment becomes exactly that request's, so nothing kept here reaches
    a scan either.
    """
    kept = {name: value for name, value in environ.items() if name in DAEMON_ENV_KEPT}
    if "PYTHONPATH" in kept:
        # The daemon starts in the runtime directory: a relative entry would
        # name a different tree there than in the client that started it.
        kept["PYTHONPATH"] = absolute_python_path(kept["PYTHONPATH"])
    return kept


def send_frame(sock: socket.socket, frame: dict[str, Any]) -> None:
    """Write one frame: a compact JSON object and its newline."""
    data = json.dumps(frame, separators=(",", ":")).encode("utf-8") + b"\n"
    if len(data) > MAX_FRAME_BYTES:
        raise ExpressProtocolError(
            f"frame of {len(data)} bytes exceeds the {MAX_FRAME_BYTES}-byte cap"
        )
    sock.sendall(data)


class FrameReader:
    """Reads newline-delimited JSON frames off a stream socket.

    One reader per connection: it buffers, so bytes it has read belong to it.
    ``read_frame`` returns the next frame as a dict, or ``None`` at a clean
    EOF on a frame boundary; anything else -- EOF mid-frame, a line that is
    not a JSON object, a line past :data:`MAX_FRAME_BYTES` -- is a
    :class:`ExpressProtocolError`.

    *before_recv*, when given, runs before every ``recv``: the daemon uses it to
    shrink the socket's timeout to what is left of a whole-handshake deadline,
    so a peer that dribbles bytes cannot restart the clock with each read.
    """

    def __init__(
        self,
        sock: socket.socket,
        before_recv: Optional[Callable[[], None]] = None,
    ) -> None:
        self._sock = sock
        self._buffer = b""
        self._before_recv = before_recv

    def read_frame(self) -> Optional[dict[str, Any]]:
        while b"\n" not in self._buffer:
            if len(self._buffer) > MAX_FRAME_BYTES:
                raise ExpressProtocolError("frame exceeds the size cap")
            if self._before_recv is not None:
                self._before_recv()
            chunk = self._sock.recv(65536)
            if not chunk:
                if self._buffer:
                    raise ExpressProtocolError("connection ended mid-frame")
                return None
            self._buffer += chunk
        line, _, self._buffer = self._buffer.partition(b"\n")
        if len(line) > MAX_FRAME_BYTES:
            raise ExpressProtocolError("frame exceeds the size cap")
        try:
            frame = json.loads(line)
        except ValueError as exc:
            raise ExpressProtocolError(f"frame is not JSON: {exc}") from None
        except RecursionError:
            # A frame nested past the interpreter's recursion limit is a
            # protocol error like any other malformed frame: as anything else
            # it would unwind through the daemon's event loop, whose teardown
            # ends every running scan over one bad client.
            raise ExpressProtocolError("frame is nested too deeply") from None
        if not isinstance(frame, dict):
            raise ExpressProtocolError("frame is not a JSON object")
        return frame


#: Linux ``struct ucred``: pid (signed), uid and gid (unsigned). The uid is
#: unpacked unsigned on purpose: a directory-service uid at or above 2**31 (an
#: SSSD or AD id mapping) read through a signed format came back negative, and
#: the daemon refused its own user.
_UCRED_FORMAT = "iII"

#: macOS ``struct xucred`` (sys/ucred.h): ``cr_version`` and ``cr_uid``, both
#: unsigned, are all the check reads; the group array behind them is not asked
#: for. ``XUCRED_VERSION`` is 0.
_XUCRED_HEAD_FORMAT = "II"
_XUCRED_SIZE = 76
_LOCAL_PEERCRED = 0x0001  # at option level SOL_LOCAL, which is 0
_XUCRED_VERSION = 0


def peer_uid(sock: socket.socket) -> Optional[int]:
    """The uid of the process on the other end of unix socket *sock*, or None.

    Read from the kernel, never from anything the peer sent: ``SO_PEERCRED``
    on Linux, ``LOCAL_PEERCRED`` (an ``xucred``) on macOS. ``None`` means it
    could not be read -- a platform with neither, a socket that is not
    connected, an answer of an unknown shape -- and the daemon treats None as
    a refusal: the check fails closed.
    """
    so_peercred = getattr(socket, "SO_PEERCRED", None)
    if so_peercred is not None:
        try:
            data = sock.getsockopt(
                socket.SOL_SOCKET, so_peercred, struct.calcsize(_UCRED_FORMAT)
            )
            _, uid, _ = struct.unpack(_UCRED_FORMAT, data)
        except (OSError, struct.error):
            return None
        return uid
    if sys.platform == "darwin":
        try:
            data = sock.getsockopt(0, _LOCAL_PEERCRED, _XUCRED_SIZE)
            version, uid = struct.unpack_from(_XUCRED_HEAD_FORMAT, data)
        except (OSError, struct.error):
            return None
        if version != _XUCRED_VERSION:
            return None
        return uid
    return None


def peer_is_this_user(sock: socket.socket, uid: Optional[int] = None) -> bool:
    """Whether *sock*'s peer runs as this user. Unreadable reads as no."""
    if uid is None:
        uid = os.getuid()
    peer = peer_uid(sock)
    return peer is not None and peer == uid
