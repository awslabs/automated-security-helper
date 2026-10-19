#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Source delivery for the MCP server.

Two delivery channels are supported:

1. ``set_source_git`` — clone a remote repository (optionally at a specific
   ref) into a per-session workspace via ``git clone --depth``. git runs
   without the server's own credentials or configuration (see
   :func:`_git_environment`); no ssh key can be named, and raw private keys are
   never accepted over the wire.
2. ``set_source_zip_chunk`` + ``set_source_zip_finalize`` — accept a zipped
   source tree as base64-encoded chunks (≤ 1 MiB each), reassemble in a
   per-session ``incoming/`` directory, verify a sha256 checksum at finalize
   time, and extract under the session workspace after rejecting any
   path-traversal entries (absolute paths, ``..`` components, symlinks
   pointing outside the workspace). Extraction builds a staging sibling and
   renames it over ``source/`` only once it has succeeded, so a re-delivery that
   is refused leaves the previously delivered tree in place.

Both the ``session_id`` and the ``upload_id`` arriving over the protocol have to
name exactly one path component, and that is enforced by the one validator in
``session_paths`` rather than re-derived per call site. Every path built from
an ``upload_id`` goes through :func:`_upload_path`; every path built from a
``session_id`` goes through :func:`_session_workspace`.

Hard limits guard against pathological inputs:

* ``_MAX_ZIP_BYTES``       — total finalized zip size (default 100 MiB)
* ``_MAX_EXTRACTED_BYTES`` — total uncompressed size after extraction (default 500 MiB)
* ``_MAX_FILES``           — total entry count in the zip (default 50 000)

Workspace root resolution order:

1. ``ASH_MCP_WORKSPACE_ROOT`` environment variable
2. ``$XDG_CACHE_HOME/ash-mcp/``
3. ``~/.cache/ash-mcp/``

Each session lives under ``<workspace_root>/<session_id>/``. ``clear_source``
recursively removes that directory.

The session ↔ source_dir binding is persisted in a process-local registry
(``_SESSION_SOURCE_DIRS``); when the larger session-state class lands
(Track 10.3 / cascade-73), this dict is meant to be replaced by an attribute
on the per-session object.
"""

from __future__ import annotations

import base64
import contextlib
import functools
import hashlib
import inspect
import os
import re
import shutil
import signal
import subprocess  # nosec B404 - git is invoked as a subprocess; see _validate_clone_url
import sys
import time
import zipfile
from pathlib import Path
from typing import Any, Callable, Dict, Iterator, List, Optional, Tuple, TypeVar, cast

from automated_security_helper.cli.mcp.session_identity import (
    UNIDENTIFIED_SESSION_ID,
)
from automated_security_helper.cli.mcp.session_paths import (
    mark_session_workspace,
    session_directory,
    validated_path_component,
)
from automated_security_helper.utils.path_containment import (
    validate_contained_path,
)
from automated_security_helper.utils.git_command import GIT_PROGRAM, git_argv
from automated_security_helper.utils.process_env import snapshot_environ

# ---------------------------------------------------------------------------
# Hard limits — enforced at finalize time.
# ---------------------------------------------------------------------------

_MAX_ZIP_BYTES: int = 100 * 1024 * 1024  # 100 MiB on-disk zip
_MAX_EXTRACTED_BYTES: int = 500 * 1024 * 1024  # 500 MiB uncompressed
_MAX_FILES: int = 50_000  # entry count
_MAX_CHUNK_BYTES: int = 1 * 1024 * 1024  # 1 MiB per chunked b64 upload (decoded)

# Extraction builds here and is renamed onto "source" only once it has
# succeeded, so a refused re-delivery cannot destroy the tree it failed to
# replace. A sibling of "source" rather than a subdirectory of it, so the rename
# is within one directory and therefore atomic.
_STAGING_DIR_NAME = ".source.incoming"

# ZipInfo external_attr bits for a symlink (S_IFLNK == 0xA000) shifted into
# the high half of external_attr.
_S_IFLNK_SHIFTED = 0xA000 << 16
_S_IFMT_SHIFTED = 0xF000 << 16


# ---------------------------------------------------------------------------
# Per-process session → source_dir registry.
#
# Track 10.3 (cascade-73) is expected to land an MCPSession class; when that
# happens, this dict should move onto that object as ``session.source_dir``.
# Until then, we keep a process-local mapping keyed by session id.
# ---------------------------------------------------------------------------

_SESSION_SOURCE_DIRS: Dict[str, Path] = {}


class SourceDeliveryBusyError(RuntimeError):
    """A change to the delivered tree was refused because a scan of the session runs.

    Delivering replaces the tree, and the config files in it, and clearing
    removes it, while the running scan is reading it: a scan whose tree
    disappears under it can report clean for code it never examined, and the
    config the scan checked would not be the config it used.
    """


#: ``error_type`` the MCP tools return for :class:`SourceDeliveryBusyError`.
SOURCE_DELIVERY_BUSY = "source_delivery_busy"


@contextlib.contextmanager
def _no_scan_running(session_id: str) -> Iterator[None]:
    """Hold the session's scan lock for a change to its tree, or refuse.

    Refused too for a scan that has started and not yet taken the lock
    (``MCPSession.try_claim_scan``). Not blocking: a delivery is called on the
    server's event loop, and waiting there for a scan to finish would stall
    every other session. A session that ended while the change held the lock is
    removed once it is released.

    Takes the in-memory session only: a change that is refused leaves no session
    directory, and each change that writes creates and marks the directory
    itself.
    """
    from automated_security_helper.cli.mcp.sessions import (
        finish_ended_session,
        get_default_registry,
    )

    session = get_default_registry().session_for(session_id)
    if not session.try_begin_change():
        raise SourceDeliveryBusyError(
            "a scan of this session is running; change the delivered source after "
            "it finishes"
        )
    try:
        yield
    finally:
        session.end_change()
        finish_ended_session(session_id)


_F = TypeVar("_F", bound=Callable[..., Any])


def _while_no_scan_runs(function: _F) -> _F:
    """Run a change to a session's tree under ``_no_scan_running`` for its session."""

    signature = inspect.signature(function)

    @functools.wraps(function)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        session_id = signature.bind(*args, **kwargs).arguments["session_id"]
        with _no_scan_running(session_id):
            return function(*args, **kwargs)

    return cast(_F, wrapper)


def get_session_source_dir(session_id: str) -> Optional[Path]:
    """Return the recorded ``source_dir`` for ``session_id``, or ``None``."""

    return _SESSION_SOURCE_DIRS.get(session_id)


def delivered_session_count() -> int:
    """Return how many sessions currently have a recorded ``source_dir``.

    Deliberately a count and not the ids. The one caller is a diagnostic that
    needs to distinguish "nobody has delivered anything" from "somebody
    delivered, but not the session asking" -- the second being the signature of
    a caller whose session id is not stable between calls. Returning the ids
    would tell one tenant that another exists and what it is called, which the
    diagnostic does not need.
    """

    return len(_SESSION_SOURCE_DIRS)


def _set_session_source_dir(session_id: str, source_dir: Path) -> None:
    _SESSION_SOURCE_DIRS[session_id] = source_dir


def _drop_session_source_dir(session_id: str) -> None:
    _SESSION_SOURCE_DIRS.pop(session_id, None)


# ---------------------------------------------------------------------------
# Workspace root + per-session workspace resolution.
# ---------------------------------------------------------------------------


def resolve_workspace_root() -> Path:
    """Resolve the configured MCP workspace root.

    Resolution order:

    1. ``$ASH_MCP_WORKSPACE_ROOT``
    2. ``$XDG_CACHE_HOME/ash-mcp/``
    3. ``~/.cache/ash-mcp/``
    """

    env_root = os.environ.get("ASH_MCP_WORKSPACE_ROOT")
    if env_root:
        return Path(env_root).expanduser()

    xdg = os.environ.get("XDG_CACHE_HOME")
    if xdg:
        return Path(xdg).expanduser() / "ash-mcp"

    return Path.home() / ".cache" / "ash-mcp"


def _session_workspace(workspace_root: Path, session_id: str) -> Path:
    """Return the per-session workspace path under ``workspace_root``.

    The session id is validated against an explicit allowlist and the joined path
    is confirmed to stay inside ``workspace_root``; see
    ``cli/mcp/session_paths.py`` for both. That keeps the session sandbox flat, so
    one session's directory is a sibling of another's and never a parent of it.

    The return value is the unresolved join, unchanged from before, so a caller
    comparing it against its own spelling of the path still matches.

    Raises:
        ValueError: for ``UNIDENTIFIED_SESSION_ID``, the caller the server could
            not identify, which owns no workspace; or for an id that does not
            name one directory.
    """

    if session_id == UNIDENTIFIED_SESSION_ID:
        raise ValueError(
            "this caller has no session the server issued, so it has no session "
            "workspace"
        )
    return session_directory(workspace_root, session_id)


def _ensure_dir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    return path


# ---------------------------------------------------------------------------
# ssh keys and the environment git runs with.
# ---------------------------------------------------------------------------


def _refuse_ssh_key_id(ssh_key_id: Optional[str]) -> None:
    """Refuse any ``ssh_key_id``: the server registers no ssh keys.

    The parameter exists so a future operator-side key registry can be added
    without changing the tool's signature. Until one exists every id names a
    key nobody registered. Cloning anyway would authenticate with whatever the
    server process can reach, which is the opposite of what naming a key asks
    for, so the clone is refused before git runs.

    Raises:
        ValueError: for every non-None ``ssh_key_id``.
    """

    if ssh_key_id is not None:
        raise ValueError(
            f"ssh_key_id {ssh_key_id!r} is not registered: this server registers no "
            f"ssh keys, so set_source_git cannot authenticate with one. Clone a "
            f"repository that needs no credentials, or deliver the tree with "
            f"set_source_zip_chunk and set_source_zip_finalize."
        )


#: Environment variables git may inherit from the server. Everything else --
#: ssh agent sockets, askpass helpers, proxies, tokens, ``GIT_*`` overrides and
#: config locations -- is dropped. Trust anchors for TLS are kept: they are not
#: credentials, and an operator who installed a private CA needs them.
_GIT_INHERITED_ENV = (
    "PATH",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "LC_MESSAGES",
    "TZ",
    "TMPDIR",
    "TEMP",
    "TMP",
    "SYSTEMROOT",
    "WINDIR",
    "COMSPEC",
    "PATHEXT",
    "GIT_SSL_CAINFO",
    "GIT_SSL_CAPATH",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
)

#: ssh as git runs it for a clone: no configuration file (``-F`` also skips the
#: system one), no identity file, no agent, no Kerberos, no shared connection,
#: never a prompt, and only the system-wide known hosts. ssh reads the default
#: identity files from the account's home directory in the password database,
#: not from ``$HOME``, so overriding the environment alone would not stop it.
_GIT_SSH_COMMAND = " ".join(
    [
        "ssh",
        "-F",
        os.devnull,
        "-o BatchMode=yes",
        "-o IdentitiesOnly=yes",
        "-o IdentityFile=none",
        "-o IdentityAgent=none",
        "-o GSSAPIAuthentication=no",
        "-o ControlPath=none",
        "-o StrictHostKeyChecking=yes",
        f"-o UserKnownHostsFile={os.devnull}",
    ]
)

#: ``-c`` options on every git invocation of a delivery, placed before the
#: subcommand so they outrank the repository's config and are not written into
#: the clone's ``.git/config``. An empty ``credential.helper`` resets the helper
#: list, so no configured helper runs; only the https and ssh protocols are
#: allowed, for submodules and anything else git might reach as well as for the
#: clone itself; an http redirect is not followed, so an allowed host cannot send
#: git to one that is not. Every command is built by ``git_argv``, which also puts
#: ``core.fsmonitor=false`` and ``core.hooksPath=/dev/null`` before these, so git
#: starts neither the fsmonitor command nor a hook (the clone's post-checkout, the
#: checkout's, a fetch's ref-update hooks), wherever they were configured.
_GIT_CONFIG = (
    "-c",
    "credential.helper=",
    "-c",
    "core.askPass=",
    "-c",
    "protocol.allow=never",
    "-c",
    "protocol.https.allow=always",
    "-c",
    "protocol.ssh.allow=always",
    "-c",
    "http.followRedirects=false",
)

#: The program a delivery runs as git. A tuple so a test can name a stand-in.
_GIT_ARGV: Tuple[str, ...] = (GIT_PROGRAM,)

#: Seconds each git command of a delivery (the clone, and for a ref the fetch
#: and the checkout) may run. A command still running then is stopped together
#: with every process it started, and the delivery fails with
#: :class:`GitTimeoutError`.
GIT_TIMEOUT_SECONDS = 600

#: ``error_type`` the MCP tool returns for :class:`GitTimeoutError`.
CLONE_TIMED_OUT = "clone_timed_out"


class GitTimeoutError(RuntimeError):
    """A git command of a delivery ran past ``GIT_TIMEOUT_SECONDS`` and was stopped."""


#: Bytes a clone may grow the session's source directory to, the same limit the
#: zip channel puts on the extracted tree. A command that passes it is stopped
#: together with every process it started, and the delivery fails with
#: :class:`CloneTooLargeError`.
MAX_CLONE_BYTES = _MAX_EXTRACTED_BYTES

#: Seconds between looks at the size of the tree a git command is writing.
GIT_POLL_SECONDS = 0.5

#: ``error_type`` the MCP tool returns for :class:`CloneTooLargeError`.
CLONE_TOO_LARGE = "clone_too_large"


class CloneTooLargeError(RuntimeError):
    """A clone passed ``MAX_CLONE_BYTES`` or ``_MAX_FILES`` entries, or could not be measured."""


def _walk_failed(error: OSError) -> None:
    """``os.walk`` error handler: only a path that is gone is tolerated."""

    if not isinstance(error, FileNotFoundError):
        raise error


def _tree_extent(root: Path) -> Tuple[int, int]:
    """Bytes of the regular files under ``root`` and the count of its entries.

    Links are not followed. A path that vanishes while the tree is walked (git
    removes its lock files) is skipped, because what is left is still measured.
    Any other error, such as a directory or file that cannot be read, is raised:
    a tree that cannot be measured must not read as an empty one.
    """

    total = 0
    entries = 0
    for dirpath, dirnames, filenames in os.walk(
        root, followlinks=False, onerror=_walk_failed
    ):
        entries += len(dirnames) + len(filenames)
        for name in filenames:
            try:
                total += os.lstat(os.path.join(dirpath, name)).st_size
            except FileNotFoundError:
                continue
    return total, entries


def _tree_bytes(root: Path) -> int:
    """Bytes of the regular files under ``root``; see :func:`_tree_extent`."""

    return _tree_extent(root)[0]


def _refuse_oversized(grows_in: Optional[Path], *, running: bool = False) -> None:
    """Raise :class:`CloneTooLargeError` when ``grows_in`` is past a clone limit.

    The limits are ``MAX_CLONE_BYTES`` and the zip channel's ``_MAX_FILES``
    entries. A tree that cannot be read is refused too.

    Args:
        grows_in: The directory the command writes into, or None.
        running: True when the command is still running, so that it is about to
            be stopped; False when it has already exited.
    """

    if grows_in is None:
        return
    suffix = " and was stopped" if running else ""
    try:
        size, entries = _tree_extent(grows_in)
    except OSError as exc:
        raise CloneTooLargeError(
            f"the size of what git wrote could not be read ({exc.strerror or exc}); "
            f"the delivery was refused"
        ) from exc
    if size > MAX_CLONE_BYTES:
        raise CloneTooLargeError(f"git wrote more than {MAX_CLONE_BYTES} bytes{suffix}")
    if entries > _MAX_FILES:
        raise CloneTooLargeError(
            f"git wrote more than {_MAX_FILES} files and directories{suffix}"
        )


def _stop_process_group(process: "subprocess.Popen[str]") -> None:
    """Kill ``process`` and every process in the group it leads."""

    # sys.platform rather than os.name: it is the check mypy reads, so the
    # Windows-only names below are checked on Windows alone.
    if sys.platform == "win32":
        with contextlib.suppress(OSError, ValueError):
            process.send_signal(signal.CTRL_BREAK_EVENT)
        with contextlib.suppress(OSError):
            process.kill()
        return
    with contextlib.suppress(ProcessLookupError, PermissionError):
        os.killpg(process.pid, signal.SIGKILL)


def _run_git(
    cmd: List[str], *, env: Dict[str, str], grows_in: Optional[Path] = None
) -> subprocess.CompletedProcess[str]:
    """Run one git command of a delivery, for at most ``GIT_TIMEOUT_SECONDS``.

    git runs in a process group of its own, with no stdin, so that on expiry the
    helpers it started (ssh, ``git-remote-https``) are stopped with it.

    Args:
        cmd: The argv, with git as an absolute path.
        env: The environment for the child.
        grows_in: A directory the command writes into. When it passes
            ``MAX_CLONE_BYTES`` the command is stopped.

    Raises:
        GitTimeoutError: when the command runs past the timeout.
        CloneTooLargeError: when ``grows_in`` passes ``MAX_CLONE_BYTES``.
    """

    # An if statement, not a conditional expression: mypy applies a platform
    # check only to statements.
    group: Dict[str, Any]
    if sys.platform == "win32":
        group = {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP}
    else:
        group = {"start_new_session": True}
    process = subprocess.Popen(  # nosec B603 - list-form argv, git from _GIT_ARGV, url and ref validated before any call; see set_source_git
        cmd,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env,
        **group,
    )
    deadline = time.monotonic() + GIT_TIMEOUT_SECONDS
    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired(cmd, GIT_TIMEOUT_SECONDS)
            try:
                stdout, stderr = process.communicate(
                    timeout=min(GIT_POLL_SECONDS, remaining)
                )
                break
            except subprocess.TimeoutExpired:
                pass
            # Stopped, with its helpers, by the handler below.
            _refuse_oversized(grows_in, running=True)
        # A command that finished inside one poll interval was not looked at yet.
        _refuse_oversized(grows_in)
    except subprocess.TimeoutExpired:
        _stop_process_group(process)
        with contextlib.suppress(subprocess.TimeoutExpired):
            process.communicate(timeout=10)
        subcommand = next(
            (part for part in cmd if part in ("clone", "fetch", "checkout")), "command"
        )
        raise GitTimeoutError(
            f"git {subcommand} did not finish within {GIT_TIMEOUT_SECONDS} seconds and "
            f"was stopped"
        ) from None
    except BaseException:
        _stop_process_group(process)
        process.wait()
        raise
    return subprocess.CompletedProcess(cmd, process.returncode, stdout, stderr)


def _git_environment(home: Path) -> Dict[str, str]:
    """The environment git runs with for a delivery.

    Built from an allowlist rather than by deleting known-bad names from the
    server's environment, because the bad set is open-ended: a deployment can
    hold any number of token or proxy variables under names nothing here could
    list. System and global git configuration are switched off, so no helper,
    proxy or rewrite rule the server's own account configured applies, and
    ``HOME`` is the session's own directory.

    Args:
        home: The session directory, used as ``HOME``.
    """

    inherited = snapshot_environ()
    env = {name: inherited[name] for name in _GIT_INHERITED_ENV if name in inherited}
    env.update(
        {
            "HOME": str(home),
            "USERPROFILE": str(home),
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_SSH_COMMAND": _GIT_SSH_COMMAND,
        }
    )
    return env


# ---------------------------------------------------------------------------
# git-ref delivery.
# ---------------------------------------------------------------------------

# git reads any argument beginning with "-" as an option, so passing a
# caller-supplied url or ref straight to the command line is an
# argument-injection sink and not merely a shell-injection one. Building argv as
# a list stops the *shell* from re-parsing the value; it does nothing to stop
# git from treating it as a flag. Two concrete escalations:
#
#   url = "--upload-pack=<cmd>"   -> git executes <cmd>
#   url = "ext::sh -c <cmd>"      -> the ext:: transport executes <cmd>
#
# These values arrive over MCP from a remote client, so they are untrusted by
# construction. This repository has already been bitten by this class of bug
# once (see the GitPython argument-injection dependency patches), so the guards
# below reject the option-like shape outright rather than trying to escape it.
_DANGEROUS_URL_PREFIXES = ("ext::",)


def _reject_option_like(value: str, what: str) -> str:
    """Reject a caller-supplied git argument that git would parse as an option.

    Args:
        value: The caller-supplied value.
        what: Name of the parameter, used in the error message.

    Returns:
        ``value`` unchanged when it is safe to pass as a positional argument.

    Raises:
        ValueError: if ``value`` begins with ``-``.
    """

    if value.startswith("-"):
        raise ValueError(
            f"{what} must not begin with '-': git would parse "
            f"{value!r} as an option rather than a value"
        )
    return value


def _validate_clone_url(url: str) -> str:
    """Reject clone URLs that let git execute an arbitrary command.

    Args:
        url: The caller-supplied remote URL.

    Returns:
        ``url`` unchanged when it is safe to clone from.

    Raises:
        ValueError: if ``url`` is option-like or uses a command-executing
            transport.
    """

    _reject_option_like(url, "url")
    lowered = url.lower()
    for prefix in _DANGEROUS_URL_PREFIXES:
        if lowered.startswith(prefix):
            raise ValueError(
                f"refusing url with {prefix!r} transport: it instructs git to "
                f"execute an arbitrary command"
            )
    return url


#: URL schemes a clone may use. Plain http and the git protocol carry no
#: integrity protection, file:// reads the server's own filesystem, and every
#: other scheme is a transport helper.
_CLONE_SCHEMES = ("https", "ssh")

#: A host name as the allowlist compares it: letters, digits, dots and hyphens,
#: starting with a letter or digit. Anything else is refused rather than
#: interpreted, so this parser and git's cannot disagree about the host.
_HOST_NAME = re.compile(r"[a-z0-9][a-z0-9.-]*")

#: Characters refused between ``ssh://`` and the first ``/``. Without them, the
#: host the allowlist checks is the host git hands ssh.
_SSH_AUTHORITY_REFUSED = frozenset("%?#[]")


def remote_clone_host(url: str) -> str:
    """Return the host ``url`` makes git connect to, or raise if it is not allowed.

    Accepts ``https://`` and ``ssh://`` URLs and the scp-like ``[user@]host:path``
    form, the three ways git reaches a remote over https or ssh. The host is
    returned lower-cased with any trailing dot removed, for comparison against
    the operator's allowlist.

    Raises:
        ValueError: for a local path or ``file://`` URL, any other scheme, or a
            host this parser cannot state unambiguously.
    """

    from urllib.parse import urlsplit

    if any(ch.isspace() or ord(ch) < 0x20 or ch == "\\" for ch in url):
        raise ValueError(
            "refusing a clone url with whitespace, control characters or backslashes"
        )
    if local_clone_path(url) is not None:
        raise ValueError(
            "refusing a local clone source: set_source_git clones from a remote "
            "https or ssh url only; it never reads the server's filesystem"
        )
    if "://" in url:
        scheme, rest = url.split("://", 1)
        scheme = scheme.lower()
        if scheme not in _CLONE_SCHEMES:
            raise ValueError(
                f"refusing a {scheme}:// clone url: only "
                f"{', '.join(s + '://' for s in _CLONE_SCHEMES)} and the scp-like "
                f"user@host:path form are allowed"
            )
        authority = rest.split("/", 1)[0]
        refused = sorted(set(authority) & _SSH_AUTHORITY_REFUSED)
        if scheme == "ssh" and refused:
            raise ValueError(
                f"refusing an ssh:// clone url with {' '.join(refused)} before the "
                f"path; write the host and user plainly."
            )
        try:
            host = urlsplit(url).hostname or ""
        except ValueError:
            raise ValueError(
                f"refusing a clone url whose host cannot be read: {url!r}"
            ) from None
    else:
        authority = url.split(":", 1)[0]
        host = authority.rsplit("@", 1)[-1]
    host = host.lower().rstrip(".")
    if not _HOST_NAME.fullmatch(host):
        raise ValueError(f"refusing a clone url whose host cannot be read: {url!r}")
    return host


#: Hosts ``set_source_git`` may clone from, set by the operator. Comma- or
#: whitespace-separated host names. Unset or empty means no remote is allowed.
ASH_MCP_GIT_ALLOWED_HOSTS_ENV = "ASH_MCP_GIT_ALLOWED_HOSTS"


def git_allowed_hosts() -> frozenset[str]:
    """The hosts the operator allows clones from, lower-cased; possibly none."""

    raw = os.environ.get(ASH_MCP_GIT_ALLOWED_HOSTS_ENV, "")
    return frozenset(
        entry.strip().lower().rstrip(".")
        for entry in raw.replace(",", " ").split()
        if entry.strip()
    )


def _is_windows_drive_path(url: str) -> bool:
    return len(url) >= 2 and url[1] == ":" and url[0].isalpha()


def local_clone_path(url: str) -> Optional[Path]:
    """Return the local path ``url`` makes git clone from, or None for a remote.

    git reads a clone source three ways, and this follows the same rule. A
    ``scheme://`` URL is a URL, and only ``file://`` names this machine. Without
    ``://``, a colon before the first slash is the scp-like ``host:path`` ssh form,
    except for a Windows drive letter. Anything else is a local path, absolute or
    relative to the server's working directory.

    A local path matters because it reads the server's own filesystem, so the MCP
    tool checks it against the session's scan roots before cloning.
    """
    from urllib.parse import unquote, urlsplit

    if "://" in url:
        if url.split("://", 1)[0].lower() != "file":
            return None
        try:
            return Path(unquote(urlsplit(url).path))
        except ValueError:
            # Not a url Python can split, but a file:// source all the same.
            return Path(url)
    colon = url.find(":")
    slash = url.find("/")
    if colon > 0 and (slash == -1 or colon < slash) and not _is_windows_drive_path(url):
        return None
    return Path(url)


def _git_executable() -> str:
    """The git to clone with, as an absolute path: ``_GIT_ARGV``'s program.

    Not the bare name: on Windows a program started by name is looked for in the
    working directory before PATH, and ``find_executable`` does not answer from the
    working directory. A program ``_GIT_ARGV`` names by absolute path is used as is.

    Raises:
        RuntimeError: git was not found, so nothing is run.
    """
    from automated_security_helper.utils.subprocess_utils import find_executable

    program = _GIT_ARGV[0]
    git = program if os.path.isabs(program) else find_executable(program)
    if git is None:
        raise RuntimeError(
            "git was not found on PATH, so the repository cannot be cloned"
        )
    return git


def _validated_clone_depth(depth: object) -> int:
    """``depth`` if it is a positive whole number of commits, else raise ValueError."""

    if isinstance(depth, bool) or not isinstance(depth, int) or depth < 1:
        raise ValueError(
            f"refusing clone depth {depth!r}: the depth is a positive whole number "
            f"of commits"
        )
    return depth


def set_source_git(
    url: str,
    ref: Optional[str] = None,
    *,
    ssh_key_id: Optional[str] = None,
    depth: int = 1,
    workspace_root: Optional[Path] = None,
    session_id: str,
) -> Path:
    """Clone ``url`` (optionally at ``ref``) into the session workspace.

    The operator's host allowlist is the MCP tool boundary's policy
    (``mcp_tools.mcp_set_source_git``); this function enforces what holds for
    every caller: a remote https or ssh url, no ssh key, and git run without the
    server's credentials or configuration.

    Args:
        url: Remote URL to clone (https or ssh).
        ref: Optional branch/tag/commit to check out. When ``None``, the
            remote default branch is used.
        ssh_key_id: Must be None. No ssh keys are registered, so any id is
            refused; raw private keys are never accepted.
        depth: Shallow-clone depth. Defaults to 1 (latest commit only).
        workspace_root: Override workspace root; defaults to
            :func:`resolve_workspace_root`.
        session_id: MCP session identifier used to scope the clone.

    Returns:
        The absolute path of the cloned working tree.

    Raises:
        ValueError: if ``session_id`` is invalid, if ``url``/``ref`` is
            option-like or uses a command-executing git transport, if ``url`` is
            local or not https/ssh, if ``ssh_key_id`` is set, or if ``depth`` is
            not a positive whole number. Raised before anything is created.
        RuntimeError: if git is not on PATH, or ``git clone`` (or the optional
            ``git checkout`` for an explicit ref) fails.
    """

    # Validated here, before the session is taken: taking it creates the session
    # workspace, and a refused request leaves nothing behind.
    url = _validate_clone_url(url)
    remote_clone_host(url)
    _refuse_ssh_key_id(ssh_key_id)
    if ref:
        ref = _reject_option_like(ref, "ref")
    depth = _validated_clone_depth(depth)
    return _clone_into_session(
        url, ref, depth=depth, workspace_root=workspace_root, session_id=session_id
    )


@_while_no_scan_runs
def _clone_into_session(
    url: str,
    ref: Optional[str],
    *,
    depth: int,
    workspace_root: Optional[Path],
    session_id: str,
) -> Path:
    """Clone a validated ``url`` into the session workspace; see ``set_source_git``."""

    root = workspace_root if workspace_root is not None else resolve_workspace_root()
    session_dir = mark_session_workspace(_session_workspace(root, session_id))

    # Wipe any previous source for this session before cloning a fresh one;
    # callers are expected to call clear_source explicitly, but cloning over
    # an existing tree is a footgun we'd rather avoid.
    # Resolved before the session directory is touched, like the validation above.
    git = _git_executable()

    target = session_dir / "source"
    if target.exists():
        shutil.rmtree(target, ignore_errors=True)
    _ensure_dir(target)

    env = _git_environment(session_dir)
    try:
        _clone(url, ref, git=git, depth=depth, target=target, env=env)
    except (GitTimeoutError, CloneTooLargeError):
        shutil.rmtree(target, ignore_errors=True)
        raise

    _set_session_source_dir(session_id, target)
    return target


def _clone(
    url: str,
    ref: Optional[str],
    *,
    depth: int,
    target: Path,
    env: Dict[str, str],
    git: Optional[str] = None,
) -> None:
    """Run the clone, and for a ref the fetch and checkout, into ``target``.

    ``git`` is ``_git_executable()``'s answer, resolved here when not given; the
    rest of ``_GIT_ARGV`` follows it. Every command is built by ``git_argv``.

    Raises:
        RuntimeError: when the clone or the checkout fails; ``target`` is removed.
        GitTimeoutError: when a command runs past ``GIT_TIMEOUT_SECONDS``.
    """

    # PATH's anchored entries only, for the programs git starts by name (ssh, a
    # credential helper); see subprocess_utils._spawn_env.
    from automated_security_helper.utils.subprocess_utils import child_environ

    env = child_environ(env)

    program = (git if git is not None else _git_executable(), *_GIT_ARGV[1:])
    cmd = git_argv(
        *_GIT_CONFIG,
        "clone",
        "--depth",
        str(depth),
        # End-of-options marker, so even a future change that loosens
        # _validate_clone_url cannot turn the url into a git flag.
        "--",
        url,
        str(target),
        program=program,
    )
    result = _run_git(cmd, env=env, grows_in=target)
    if result.returncode != 0:
        shutil.rmtree(target, ignore_errors=True)
        raise RuntimeError(
            f"git clone failed (exit {result.returncode}): {result.stderr.strip() or result.stdout.strip()}"
        )
    if not ref:
        return

    # A shallow clone is single-branch, so a ref off the default branch is not in
    # it. The fetch brings it, and records it only in FETCH_HEAD: a named branch
    # or tag gets no local ref, so the checkout takes FETCH_HEAD. A fetch that
    # fails (a commit id the remote won't serve by id) leaves the checkout to
    # find the ref in the clone itself, and to report it if it isn't there.
    fetch = _run_git(
        git_argv(
            *_GIT_CONFIG,
            "-C",
            str(target),
            "fetch",
            "--depth",
            str(depth),
            "origin",
            ref,
            program=program,
        ),
        env=env,
        grows_in=target,
    )
    revision = "FETCH_HEAD" if fetch.returncode == 0 else ref
    checkout = _run_git(
        git_argv(
            *_GIT_CONFIG,
            "-C",
            str(target),
            "checkout",
            "--detach",
            revision,
            program=program,
        ),
        env=env,
        grows_in=target,
    )
    if checkout.returncode != 0:
        shutil.rmtree(target, ignore_errors=True)
        raise RuntimeError(
            f"git checkout {ref!r} failed (exit {checkout.returncode}): "
            f"{checkout.stderr.strip() or checkout.stdout.strip()}"
        )


# ---------------------------------------------------------------------------
# Chunked zip upload.
# ---------------------------------------------------------------------------


def _incoming_dir(session_dir: Path) -> Path:
    return _ensure_dir(session_dir / "incoming")


def _upload_path(session_dir: Path, upload_id: str, suffix: str) -> Path:
    """Build the one path in this session's ``incoming/`` naming this upload.

    Every upload path is built here so that the validation cannot be attached to
    one builder and missed by the others. That is exactly what had happened:
    ``_part_path`` carried the only check and has a single caller, on the chunk
    path, while ``set_source_zip_finalize`` built through ``_final_zip_path`` and
    reached ``stat()``, ``read()`` and ``unlink()`` on an unvalidated path. An
    absolute ``upload_id`` left no trace of the workspace root in the result --
    ``Path('<incoming>') / '/etc/cron.d/x.zip'`` is ``/etc/cron.d/x.zip`` -- and
    the function's only precondition is that the file exists, which an attacker
    satisfies by naming a file that already does.

    Two separate guards, because neither implies the other:

    * ``upload_id`` must name one path component, which is what stops the
      traversal and the absolute path from being built at all.
    * the built path must be contained in ``incoming/`` and must not itself be a
      symlink. Containment is the assertion that holds even if the component rule
      is later loosened, and the symlink half is not a containment question: a
      link inside ``incoming/`` is contained, and following it would hash and
      then unlink whatever it points at. This is the same call the zip member
      handling makes for symlink entries.

    The unresolved join is returned rather than the canonical path the check
    produced, so the file this names is byte-identical to what the previous
    implementation named; the check is a gate, not a rewrite.

    Raises:
        ValueError: if ``upload_id`` does not name a single path component, or if
            the built path is not a non-symlink inside ``incoming/``.
    """

    validated_path_component(upload_id, "upload_id")

    name = f"{upload_id}{suffix}"
    incoming = _incoming_dir(session_dir)
    result = validate_contained_path(name, incoming.resolve())
    if result.error is not None:
        raise ValueError(
            f"upload_id {upload_id!r} does not name a file inside the session's "
            f"incoming directory: {result.error.message}"
        )
    return incoming / name


def _part_path(session_dir: Path, upload_id: str) -> Path:
    return _upload_path(session_dir, upload_id, ".zip.part")


def _meta_path(session_dir: Path, upload_id: str) -> Path:
    return _upload_path(session_dir, upload_id, ".next")


def _final_zip_path(session_dir: Path, upload_id: str) -> Path:
    return _upload_path(session_dir, upload_id, ".zip")


def _read_next_sequence(session_dir: Path, upload_id: str) -> int:
    meta = _meta_path(session_dir, upload_id)
    if not meta.exists():
        return 0
    try:
        return int(meta.read_text().strip() or "0")
    except ValueError:
        return 0


def _write_next_sequence(session_dir: Path, upload_id: str, value: int) -> None:
    _meta_path(session_dir, upload_id).write_text(str(value))


def set_source_zip_chunk(
    upload_id: str,
    sequence: int,
    data_b64: str,
    last: bool,
    *,
    workspace_root: Optional[Path] = None,
    session_id: str,
) -> Dict[str, object]:
    """Append a base64-encoded chunk to an in-flight zip upload.

    Args:
        upload_id: Caller-chosen identifier scoping a single upload.
        sequence: Zero-based sequence number; chunks must arrive in order.
        data_b64: Base64-encoded chunk payload (≤ 1 MiB decoded).
        last: ``True`` on the final chunk; subsequent chunks for the same
            ``upload_id`` are rejected.
        workspace_root: Override workspace root.
        session_id: MCP session identifier used to scope the upload.

    Returns:
        ``{"received": <bytes-so-far>, "next_sequence": <int>, "last": <bool>}``

    Raises:
        ValueError: on out-of-order sequence, oversize chunk, malformed b64
            payload, or duplicate ``last=True``.
        sessions.SessionWorkspaceBusyError: while the TTL sweep removes the
            session (``sessions.writing_session_state``). The upload is gone
            then, so it is sent again from its first chunk.
    """
    from automated_security_helper.cli.mcp.sessions import writing_session_state

    with writing_session_state(session_id):
        return _append_zip_chunk(
            upload_id,
            sequence,
            data_b64,
            last,
            workspace_root=workspace_root,
            session_id=session_id,
        )


def _append_zip_chunk(
    upload_id: str,
    sequence: int,
    data_b64: str,
    last: bool,
    *,
    workspace_root: Optional[Path],
    session_id: str,
) -> Dict[str, object]:
    """:func:`set_source_zip_chunk`, once the session is held against the sweep."""
    root = workspace_root if workspace_root is not None else resolve_workspace_root()
    session_dir = mark_session_workspace(_session_workspace(root, session_id))
    part = _part_path(session_dir, upload_id)
    _ensure_dir(part.parent)

    expected = _read_next_sequence(session_dir, upload_id)
    if sequence != expected:
        raise ValueError(
            f"out-of-order chunk: expected sequence {expected}, got {sequence}"
        )

    try:
        decoded = base64.b64decode(data_b64, validate=True)
    except Exception as exc:  # noqa: BLE001 — re-raise as a typed error
        raise ValueError(f"invalid base64 payload: {exc}") from exc

    if len(decoded) > _MAX_CHUNK_BYTES:
        raise ValueError(f"chunk too large: {len(decoded)} > {_MAX_CHUNK_BYTES} bytes")

    # Append. Open in "ab" so successive chunks accumulate.
    with part.open("ab") as f:
        f.write(decoded)

    new_total = part.stat().st_size
    if new_total > _MAX_ZIP_BYTES:
        # Refuse to keep growing past the hard cap.
        part.unlink(missing_ok=True)
        _meta_path(session_dir, upload_id).unlink(missing_ok=True)
        raise ValueError(
            f"upload exceeds max zip size {_MAX_ZIP_BYTES} bytes (got {new_total})"
        )

    next_seq = sequence + 1
    if last:
        # Promote the .part to .zip; finalize() will verify checksum and
        # extract.
        final = _final_zip_path(session_dir, upload_id)
        if final.exists():
            final.unlink()
        part.rename(final)
        _meta_path(session_dir, upload_id).unlink(missing_ok=True)
    else:
        _write_next_sequence(session_dir, upload_id, next_seq)

    return {"received": new_total, "next_sequence": next_seq, "last": bool(last)}


# ---------------------------------------------------------------------------
# Zip finalize + safe extraction.
# ---------------------------------------------------------------------------


def _is_symlink_zipinfo(info: zipfile.ZipInfo) -> bool:
    """Detect symlink entries via Unix mode bits in ``external_attr``.

    Zip stores Unix file mode in the high half of ``external_attr``. A
    symlink has S_IFMT == S_IFLNK (0xA000).
    """

    return (info.external_attr & _S_IFMT_SHIFTED) == _S_IFLNK_SHIFTED


def _validate_zip_member(name: str) -> None:
    """Reject path-traversal entries before extracting.

    Specifically rejected:

    * absolute paths (``/etc/passwd``, ``C:\\…``)
    * components starting with ``..``
    * any component equal to ``..``
    """

    if not name:
        raise ValueError("zip entry has empty name")
    # Normalize separators for the pure-text checks below.
    normalized = name.replace("\\", "/")
    if os.path.isabs(normalized) or normalized.startswith("/"):
        raise ValueError(f"absolute path in zip: {name!r}")
    if normalized.startswith("../") or normalized == ".." or "/../" in normalized:
        raise ValueError(f"path traversal in zip: {name!r}")
    parts = [p for p in normalized.split("/") if p not in ("", ".")]
    for p in parts:
        if p == "..":
            raise ValueError(f"path traversal in zip: {name!r}")


@_while_no_scan_runs
def set_source_zip_finalize(
    upload_id: str,
    expected_sha256: str,
    *,
    workspace_root: Optional[Path] = None,
    session_id: str,
) -> Path:
    """Finalize a chunked upload: verify checksum and extract.

    Args:
        upload_id: Identifier matching the prior ``set_source_zip_chunk`` calls.
        expected_sha256: Hex sha256 the assembled zip must hash to.
        workspace_root: Override workspace root.
        session_id: MCP session identifier.

    Returns:
        Absolute path of the extracted source tree (the session's
        ``source_dir``). Unchanged on every failure path: extraction goes to a
        staging sibling and is renamed into place only after it succeeds, so a
        refused re-delivery leaves the previously delivered tree intact rather
        than leaving the session registered against an empty directory.

    Raises:
        FileNotFoundError: if the upload never received its final chunk.
        ValueError: if ``upload_id`` does not name a single path component, or on
            sha256 mismatch, oversize zip, oversize extraction, too-many-files,
            or path-traversal/symlink-out-of-tree entries.
        zipfile.BadZipFile: if the assembled bytes are not a zip archive. The
            checksum matching means the client sent what it meant to send, so
            this is a client-side packaging error rather than corruption.
    """

    root = workspace_root if workspace_root is not None else resolve_workspace_root()
    session_dir = mark_session_workspace(_session_workspace(root, session_id))
    final = _final_zip_path(session_dir, upload_id)
    if not final.exists():
        raise FileNotFoundError(
            f"no finalized zip for upload_id={upload_id!r} "
            f"(did the last chunk arrive with last=True?)"
        )

    # Hard limit on the on-disk zip size.
    actual_size = final.stat().st_size
    if actual_size > _MAX_ZIP_BYTES:
        final.unlink(missing_ok=True)
        raise ValueError(f"zip too large: {actual_size} > {_MAX_ZIP_BYTES} bytes")

    # Verify checksum before opening the archive.
    digest = hashlib.sha256()
    with final.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(block)
    actual_sha = digest.hexdigest()
    if actual_sha.lower() != expected_sha256.lower():
        final.unlink(missing_ok=True)
        raise ValueError(
            f"sha256 mismatch: expected {expected_sha256}, got {actual_sha}"
        )

    # Extract into a staging sibling and swap, rather than clearing the
    # delivered tree first. The checksum and size guards above do precede any
    # write, but the four guards a hostile or malformed archive trips -- entry
    # count, member traversal, uncompressed total, symlink member -- all run
    # after the archive is open, and so did ``zipfile.ZipFile`` itself raising
    # BadZipFile. Removing the tree before that point left the session
    # registered and pointing at an empty directory, which a scan then reports
    # as clean: the false-negative shape, and the worst outcome available to a
    # security scanner. Costs one delivery's worth of extra peak disk, since the
    # old and new trees coexist until the rename.
    target = session_dir / "source"
    staging = session_dir / _STAGING_DIR_NAME
    if staging.exists():
        # Left behind by a delivery that died between extraction and the swap.
        # It is scratch space and never the delivered tree, so removing it
        # cannot lose anything a caller can still reach.
        shutil.rmtree(staging, ignore_errors=True)
    _ensure_dir(staging)

    swapped = False
    try:
        # Pre-extraction validation pass: walk the namelist and the zipinfo
        # list, rejecting absolute paths, traversal components, oversize totals,
        # and symlinks that would resolve outside the session sandbox.
        with zipfile.ZipFile(final) as zf:
            infos = zf.infolist()
            if len(infos) > _MAX_FILES:
                raise ValueError(f"too many files in zip: {len(infos)} > {_MAX_FILES}")

            total_uncompressed = 0
            for info in infos:
                _validate_zip_member(info.filename)
                total_uncompressed += info.file_size
                if total_uncompressed > _MAX_EXTRACTED_BYTES:
                    raise ValueError(
                        f"extracted size exceeds {_MAX_EXTRACTED_BYTES} bytes "
                        f"(at entry {info.filename!r})"
                    )
                if _is_symlink_zipinfo(info):
                    # Reject ALL symlink entries — not just those whose target
                    # resolves outside the sandbox. Pre-extraction resolve()
                    # of a link under (target/info.filename).parent races
                    # extraction: an earlier zip entry that materializes a
                    # directory which is itself a symlink (or a leftover-from-
                    # prior-upload directory that resolves elsewhere) would
                    # let a later symlink entry pass validation but still
                    # escape once extractall() runs.
                    #
                    # Source tree shipping over MCP does not need symlinks.
                    # Refusing them outright eliminates the pre/post-write
                    # divergence. See DA r6 #5.
                    link_target = zf.read(info).decode("utf-8", errors="replace")
                    raise ValueError(
                        f"symlink {info.filename!r} -> {link_target!r}: "
                        f"symlinks are not allowed in MCP source delivery zips"
                    )

            # Validation passed; extract into staging.
            zf.extractall(staging)

        # Swap. The old tree only goes away once the new one is complete on
        # disk, and the rename is within one directory so the window in which
        # neither is in place is two syscalls wide rather than the whole
        # validate-and-extract pass.
        if target.exists():
            shutil.rmtree(target, ignore_errors=True)
        staging.rename(target)
        swapped = True
    finally:
        if not swapped:
            shutil.rmtree(staging, ignore_errors=True)

    _set_session_source_dir(session_id, target)
    # The on-disk zip is no longer needed.
    final.unlink(missing_ok=True)
    return target


# ---------------------------------------------------------------------------
# Cleanup.
# ---------------------------------------------------------------------------


@_while_no_scan_runs
def clear_source(session_id: str, *, workspace_root: Optional[Path] = None) -> None:
    """Wipe the session workspace and forget any recorded ``source_dir``.

    Idempotent: missing workspaces are silently ignored.

    Raises:
        SourceDeliveryBusyError: while a scan of the session runs.
    """

    remove_session_workspace(session_id, workspace_root=workspace_root)


def remove_session_workspace(
    session_id: str, *, workspace_root: Optional[Path] = None
) -> None:
    """Remove the session workspace and its record, without taking the scan lock.

    For a caller that already holds the session's lock --
    ``sessions.end_session`` -- or that has decided a scan cannot be running.
    """

    root = workspace_root if workspace_root is not None else resolve_workspace_root()
    session_dir = _session_workspace(root, session_id)
    shutil.rmtree(session_dir, ignore_errors=True)
    _drop_session_source_dir(session_id)
