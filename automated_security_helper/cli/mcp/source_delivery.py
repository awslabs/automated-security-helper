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
   never accepted over the wire. The clone is made in a staging sibling and
   renamed over ``source/`` only once it has worked, as a zip extraction is, so
   a re-delivery that fails leaves the previously delivered tree in place.
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
(``_SESSION_SOURCE_DIRS``), the single source of truth for it; ``MCPSession``
deliberately holds no ``source_dir`` field.
"""

from __future__ import annotations

import base64
import contextlib
import errno
import functools
import hashlib
import inspect
import os
import re
import shutil
import signal
import stat
import subprocess  # nosec B404 - git is invoked as a subprocess; see _validate_clone_url
import sys
import threading
import time
import unicodedata
import uuid
import zipfile
from pathlib import Path
from typing import Any, Callable, Dict, Iterator, List, Optional, Tuple, TypeVar, cast

from automated_security_helper.cli.mcp.session_identity import (
    UNIDENTIFIED_SESSION_ID,
)
from automated_security_helper.cli.mcp.session_paths import (
    hidden_deleting_name,
    mark_session_workspace,
    session_directory,
    validated_path_component,
)
from automated_security_helper.utils.path_containment import (
    validate_contained_path,
)
from automated_security_helper.utils.git_command import GIT_PROGRAM, git_argv
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.process_env import snapshot_environ
from automated_security_helper.utils.subprocess_utils import (
    run_ended_with_the_server,  # noqa: F401 - tests patch it on this module
)

_logger = ASH_LOGGER

# ---------------------------------------------------------------------------
# Hard limits — enforced at finalize time.
# ---------------------------------------------------------------------------

_MAX_ZIP_BYTES: int = 100 * 1024 * 1024  # 100 MiB on-disk zip
_MAX_EXTRACTED_BYTES: int = 500 * 1024 * 1024  # 500 MiB uncompressed
_MAX_FILES: int = 50_000  # entry count
_MAX_CHUNK_BYTES: int = 1 * 1024 * 1024  # 1 MiB per chunked b64 upload (decoded)
#: How much of a refused symlink entry's content a refusal quotes as its target.
_SYMLINK_TARGET_EXCERPT_BYTES: int = 256

# A zip extraction and a git clone build here, and the result is renamed onto
# "source" only once it has succeeded, so a refused or failed re-delivery cannot
# destroy the tree it failed to replace. A sibling of "source" rather than a
# subdirectory of it, so the rename is within one directory and therefore atomic.
# Each delivery names its staging directory with this prefix and a unique suffix, so
# what an earlier delivery left (and could not delete) is never extracted or cloned
# into and never blocks this one.
_STAGING_DIR_PREFIX = ".source.incoming-"

# A rename of one of the trees a delivery moves (the previous tree aside, the finished
# staging directory onto "source", the previous tree back) is tried this many times,
# this many seconds apart, before the delivery fails. A program that holds a handle
# inside a tree (a virus scanner or a file indexer on Windows) makes the rename fail
# for as long as it holds it, which is usually a fraction of a second. The tree is left
# whole between attempts, so a refusal that passes costs no second clone or extraction;
# the waits of one rename together stay under a second.
_RENAME_ATTEMPTS = 5
_RENAME_WAIT_SECONDS = 0.2

# The staging directory of earlier versions had this fixed name. A delivery deletes
# one it finds, as it does the others.
_LEGACY_STAGING_DIR_NAME = ".source.incoming"

# The previous tree of a re-delivery (zip or git) is renamed to a sibling with this
# prefix (and a unique suffix). The recorded source path is therefore never a tree that
# is being deleted. A tree under this name is whole: it is the previous source, and if
# the swap that set it aside fails without putting it back, the next delivery puts it
# back at "source" (``_put_a_lost_source_back``). It is deleted only after it has been
# renamed to the trash name below.
_REPLACED_DIR_PREFIX = ".source.replaced-"

# A tree that is to be deleted is first renamed to a sibling with this prefix (and a
# unique suffix), and deleted under that name. A delete that stops partway (a file
# that something holds open) leaves a half-deleted tree, and that tree must never be
# taken for the previous source: it would be put back at "source", and a scan of it
# would miss the files that were deleted. A half-deleted tree therefore never carries
# the replaced name; the next delivery deletes what stayed, and never puts it back.
_TRASH_DIR_PREFIX = ".source.trash-"

# ZipInfo external_attr bits for a symlink (S_IFLNK == 0xA000) shifted into
# the high half of external_attr.
_S_IFLNK_SHIFTED = 0xA000 << 16
_S_IFMT_SHIFTED = 0xF000 << 16


# ---------------------------------------------------------------------------
# Per-process session → source_dir registry.
#
# The single source of truth for a session's delivered source directory.
# ``MCPSession`` deliberately holds no ``source_dir`` field (test_sessions.py
# pins the model's fields), so do not grow one there: a second copy of this
# state drifts, and a scan would read a different tree than the delivery
# recorded.
# ---------------------------------------------------------------------------

_SESSION_SOURCE_DIRS: Dict[str, Path] = {}


class SourceDeliveryBusyError(RuntimeError):
    """A change to the delivered tree was refused because a scan of the session runs.

    Delivering replaces the tree, and the config files in it, and clearing
    removes it, while the running scan is reading it: a scan whose tree
    disappears under it can report clean for code it never examined, and the
    config the scan checked would not be the config it used.
    """


#: Worker threads the server runs clones (``set_source_git``) on, across all
#: sessions. A clone beyond this many waits for a worker; scans do not share
#: these, and neither do the chunk, finalize and clear tools, which have a pool of
#: their own.
CLONE_MAX_WORKERS = 8

#: Worker threads the server runs the other three delivery tools on (a chunk, a
#: finalize, a clear), across all sessions. Explicit rather than
#: ``ThreadPoolExecutor``'s default, which depends on the host's CPU count: the
#: default is 5-6 workers on a 1-2 vCPU container, and before Python 3.13
#: ``os.cpu_count`` ignores cgroup CPU quotas, so a big host gets 32 whatever
#: its container's quota. A finalize (a sha256 and an extraction) or a clear
#: (an ``rmtree``) can hold a worker for seconds, so the size bounds how many
#: of those one tenant's calls can queue another's chunk behind.
DELIVERY_MAX_WORKERS = 8

#: ``error_type`` the MCP tools return for :class:`SourceDeliveryBusyError`.
SOURCE_DELIVERY_BUSY = "source_delivery_busy"


@contextlib.contextmanager
def _no_scan_running(
    session_id: str, *, removes_workspace: bool = True
) -> Iterator[None]:
    """Hold the session's scan lock for a change to its tree, or refuse.

    Refused too for a scan that has started and not yet taken the lock
    (``MCPSession.try_claim_scan``). Not blocking: a delivery runs on one of the
    server's few delivery threads, and waiting there for a scan to finish would
    hold the thread for the scan's length and queue other sessions' deliveries
    behind it. A session that ended while the change held the lock is removed
    once it is released.

    The session's change excludes the scans of this process. A scan of the same
    session in another server sharing the workspace root (a replica behind a
    load balancer, or a sibling stdio server of the same user on the stdio
    session, which every stdio server of that user shares) holds a locked
    presence entry instead (``sessions.ScanPresence``), read once the change is
    held (``sessions.a_scan_in_another_server_holds``): a tree replaced or
    removed under it would make its result one of code it never examined, as
    under a scan of this process. Refused the same way, naming the other server.

    ``removes_workspace`` is True for a change that deletes the session's whole
    directory (``clear_source``). Such a change also excludes writes
    (``MCPSession.try_begin_write``): it is refused while a chunk or a profile
    binding is being written, and a write that comes meanwhile is refused. A
    clone and a finalize pass False, so a write goes on beside them: a clone
    replaces ``source/`` and its staging sibling and touches neither
    ``incoming/`` nor ``config/``; a finalize replaces the same two and also
    reads and removes its own upload's ``incoming/<id>.zip`` (it opens the zip
    under the upload's lock (:func:`_upload_lock`), hashes and extracts the open
    handle without the lock, and deletes the path under the lock again), so
    only a chunk of that same upload waits for either step.

    Takes the in-memory session only: a change that is refused leaves no session
    directory, and each change that writes creates and marks the directory
    itself.
    """
    from automated_security_helper.cli.mcp.sessions import (
        CHANGE_REFUSED_BY_CHANGE,
        CHANGE_REFUSED_BY_WRITE,
        a_scan_in_another_server_holds,
        finish_ended_session,
        get_default_registry,
    )

    session = get_default_registry().session_for(session_id)
    refused = session.try_begin_change(removes_workspace=removes_workspace)
    if refused is not None:
        # The message names what refused this attempt
        # (MCPSession.try_begin_change says why), so a client is not told to
        # wait for a scan that does not exist.
        if refused == CHANGE_REFUSED_BY_WRITE:
            raise SourceDeliveryBusyError(
                "a chunk of an upload or a profile selection is being "
                "written; change the delivered source after it finishes"
            )
        if refused == CHANGE_REFUSED_BY_CHANGE:
            raise SourceDeliveryBusyError(
                "another change to this session's source is in progress (a "
                "delivery, a clear, the end of the session, or the removal "
                "of an idle session); change the delivered source after it "
                "finishes"
            )
        raise SourceDeliveryBusyError(
            "a scan of this session is running; change the delivered source "
            "after it finishes"
        )
    try:
        # Inside the try: a refusal here releases the change in the finally.
        if a_scan_in_another_server_holds(session_id):
            raise SourceDeliveryBusyError(
                "a scan of this session is running in another server sharing "
                "the workspace root; change the delivered source after it "
                "finishes"
            )
        yield
    finally:
        session.end_change()
        finish_ended_session(session_id)


_F = TypeVar("_F", bound=Callable[..., Any])


def _while_no_scan_runs(*, removes_workspace: bool = True) -> Callable[[_F], _F]:
    """Run a change to a session's tree under ``_no_scan_running`` for its session.

    Used as ``@_while_no_scan_runs()`` for a change that deletes the session's
    directory, and as ``@_while_no_scan_runs(removes_workspace=False)`` for one
    that replaces ``source/`` only; see :func:`_no_scan_running`.
    """

    def decorate(function: _F) -> _F:
        signature = inspect.signature(function)

        @functools.wraps(function)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            session_id = signature.bind(*args, **kwargs).arguments["session_id"]
            with _no_scan_running(session_id, removes_workspace=removes_workspace):
                return function(*args, **kwargs)

        return cast(_F, wrapper)

    return decorate


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


class InvalidSessionIdError(ValueError):
    """The session id is not one a workspace directory can be made for.

    A ValueError, so a caller that catches ValueError catches it. The MCP tools
    report it as ``invalid_session_id``. ``set_source_git`` raises it before the
    session is taken, so its caller can tell it from a ValueError raised while
    git's step runs.
    """


def _session_workspace(workspace_root: Path, session_id: str) -> Path:
    """Return the per-session workspace path under ``workspace_root``.

    The session id is validated against an explicit allowlist and the joined path
    is confirmed to stay inside ``workspace_root``; see
    ``cli/mcp/session_paths.py`` for both. That keeps the session sandbox flat, so
    one session's directory is a sibling of another's and never a parent of it.

    The return value is the unresolved join, unchanged from before, so a caller
    comparing it against its own spelling of the path still matches.

    Raises:
        InvalidSessionIdError: for ``UNIDENTIFIED_SESSION_ID``, the caller the
            server could not identify, which owns no workspace; or for an id
            that does not name one directory.
    """

    if session_id == UNIDENTIFIED_SESSION_ID:
        raise InvalidSessionIdError(
            "this caller has no session the server issued, so it has no session "
            "workspace"
        )
    try:
        return session_directory(workspace_root, session_id)
    except ValueError as e:
        raise InvalidSessionIdError(str(e)) from e


#: ``error_type`` every delivery tool returns for :class:`SessionWorkspaceError`.
SESSION_WORKSPACE_UNAVAILABLE = "session_workspace_unavailable"


class SessionWorkspaceError(OSError):
    """The session's workspace could not be prepared for, or hold, the new source.

    A directory of it could not be created, the previously delivered tree could
    not be moved aside, or the new tree could not be moved into place. A tree that
    a failed delivery could not fully delete is not one of these: it stays in its
    staging directory, logged, and the delivery reports the failure that ended it.
    An OSError, so a caller that catches OSError catches it. The MCP tools report it as
    SESSION_WORKSPACE_UNAVAILABLE, an ``error_type`` a client can branch on, not
    the exception's class name and not the errno's.
    """


class UploadNotFoundError(FileNotFoundError):
    """A finalize named an upload that never received its last chunk.

    The client's own mistake, which it fixes by sending the chunks, so the MCP tool
    answers it with an ``error`` and no ``error_type``. A ``FileNotFoundError`` that
    is not this one is a file that vanished on disk, during the extraction or the
    checksum, and is a failure on disk like any other ``OSError`` raised there.
    """


def _ensure_dir(path: Path) -> Path:
    """Create ``path`` and its parents; SessionWorkspaceError if that fails."""
    try:
        path.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        raise SessionWorkspaceError(
            e.errno, f"could not create the session workspace directory {path}: {e}"
        ) from e
    return path


def _make_writable(path: str) -> bool:
    """Give the owner write access to ``path`` (and read and search, for a directory).

    A symlink is left alone, because chmod would follow it out of the tree. A
    failure is ignored: the caller's retry reports it. Returns whether the mode
    changed, read again after the chmod: a file system can accept a chmod and change
    nothing (a CIFS mount without permissions, vfat, some FUSE file systems), and a
    call that did nothing is not progress for the caller's loop.
    """

    with contextlib.suppress(OSError):
        st_mode = os.lstat(path).st_mode
        if stat.S_ISLNK(st_mode):
            return False
        mode = stat.S_IMODE(st_mode)
        owner = stat.S_IRWXU if stat.S_ISDIR(st_mode) else stat.S_IRUSR | stat.S_IWUSR
        if mode | owner == mode:
            return False
        os.chmod(path, mode | owner)
        return stat.S_IMODE(os.lstat(path).st_mode) != mode
    return False


#: Most passes ``_remove_tree`` makes over a tree. Each level of directories the owner
#: cannot open costs a pass, so this is also the deepest such nesting it undoes.
_REMOVE_TREE_MAX_PASSES = 64


def _remove_tree(path: Path) -> bool:
    """Delete ``path`` and everything under it; return whether it is gone.

    A file or directory the delete cannot remove has its read-only bit cleared
    (and its parent directory's, inside the tree) and the delete retried once:
    git makes its pack files read-only, and Windows does not delete a read-only
    file. A directory the owner cannot open is made accessible by the pass that
    meets it and deleted by the next, so the tree is walked again while the
    previous pass changed a permission, once more for each level of such
    directories, at most ``_REMOVE_TREE_MAX_PASSES`` times and never fewer than
    twice. What still cannot be removed (files another account owns) stays on disk
    and the walk goes on with the rest, as ``ignore_errors=True`` did, and the
    result is False, so a caller does not take scratch for gone.
    """

    root = str(path)
    changed_a_permission = False

    def clear_and_retry(func: Callable[[str], Any], failing: str, _error: Any) -> None:
        nonlocal changed_a_permission
        if _make_writable(failing):
            changed_a_permission = True
        if failing != root and _make_writable(os.path.dirname(failing)):
            changed_a_permission = True
        # Only a removal is retried: the other calls rmtree reports (open, scandir,
        # lstat) take arguments this one does not pass, and the walk does not come
        # back to an entry it could not open.
        if func in (os.unlink, os.remove, os.rmdir):
            with contextlib.suppress(OSError):
                func(failing)

    # Another pass when the root survives one: a directory the owner could not open
    # is reported as a failed open, which the handler makes accessible but does not
    # retry, so the walk went past it and the directories above it stayed. A
    # directory inside it that the owner cannot open either is reported only once
    # this pass has made the one above accessible, so it takes the pass after.
    passes = 0
    while True:
        changed_a_permission = False
        with contextlib.suppress(OSError):
            if sys.version_info >= (3, 12):
                shutil.rmtree(root, onexc=clear_and_retry)
            else:
                shutil.rmtree(root, onerror=clear_and_retry)
        passes += 1
        try:
            os.lstat(root)
        except OSError:
            return True
        if passes >= _REMOVE_TREE_MAX_PASSES:
            return False
        if passes >= 2 and not changed_a_permission:
            return False


def _move_aside(path: Path, session_dir: Path, what: str) -> Path:
    """Rename ``path`` to a sibling of its own in the session workspace; return it.

    A rename, unlike a delete in place, cannot leave ``path`` holding a
    half-deleted tree: when it returns nothing is at ``path``, and when it raises
    ``path`` is as it was. The sibling is named like the tree a zip re-delivery
    replaces, so what a caller does not delete is deleted by the next delivery. A
    refused rename is tried again (``_rename_with_retries``).

    Raises:
        SessionWorkspaceError: if every attempt is refused; ``path`` is then as it
            was.
    """

    aside = session_dir / f"{_REPLACED_DIR_PREFIX}{uuid.uuid4().hex}"
    try:
        _rename_with_retries(path, aside)
    except OSError as e:
        raise SessionWorkspaceError(
            e.errno, f"could not move {what} at {path} aside: {e}"
        ) from e
    return aside


def _a_wait_may_clear(error: OSError) -> bool:
    """Whether a refused rename can be allowed by waiting for it.

    A program that holds a handle inside a tree lets go of it within a fraction of a
    second. What it causes is a permission error (access denied), a busy device, or on
    Windows error 5 (access denied) or 32 (sharing violation), whichever errno those
    were mapped to. Any other error is not about a handle: the tree to move is gone,
    something took the place of its target, the file system is read-only or full, or
    the move crosses devices. Waiting changes none of them.
    """

    return (
        isinstance(error, PermissionError)
        or error.errno == errno.EBUSY
        or getattr(error, "winerror", None) in (5, 32)
    )


def _rename_with_retries(source: Path, target: Path) -> None:
    """Rename ``source`` to ``target``, again after a refusal, a few times at most.

    A program that holds a handle inside a tree (a virus scanner or a file indexer
    on Windows) refuses the rename for as long as it holds the handle. A refusal
    that waiting can clear (``_a_wait_may_clear``) is tried again, up to
    ``_RENAME_ATTEMPTS`` times in all, ``_RENAME_WAIT_SECONDS`` apart; any other
    error is raised at once, because the delivery runs inside the server's event
    loop and every wait stalls it. ``source`` is not touched between attempts, and
    not by the last one either: it is where it was when this raises.

    Raises:
        OSError: the refusal of the last attempt.
    """

    for attempt in range(1, _RENAME_ATTEMPTS + 1):
        try:
            source.rename(target)
            return
        except OSError as e:
            if attempt == _RENAME_ATTEMPTS or not _a_wait_may_clear(e):
                raise
        time.sleep(_RENAME_WAIT_SECONDS)


def _swap_into_place(
    staging: Path, target: Path, session_dir: Path, what: str
) -> Optional[Path]:
    """Put the staged tree at ``target``, the previously delivered tree set aside first.

    The old tree only goes away once the new one is complete on disk, and the
    renames are within one directory, so the window in which neither is in place is
    the rename of the staged tree into place rather than the whole fetch or
    extraction: two renames when nothing refuses them, and when something holds a
    handle inside a tree, up to ``_RENAME_ATTEMPTS`` attempts of that rename with
    ``_RENAME_WAIT_SECONDS`` between them (under a second). The old tree
    is renamed aside, never deleted where it stands: a delete that leaves entries
    behind would leave the path the session is recorded against naming a
    half-deleted tree, and what blocks the rename of a directory (an open handle
    under it, a process whose working directory is in it) usually blocks the delete
    as well. Each of the three renames (the old tree aside, the staged tree into
    place, the old tree back) is tried again after a refusal that a wait can clear
    (``_rename_with_retries``), because a handle that blocks a tree is often let go
    within a fraction of a second, and the finished clone or extraction is worth
    waiting for; a delivery already runs for the whole fetch or extraction, so the
    waits add under a second to it for each rename that is refused.

    ``what`` names the staged tree in the error message (``extracted``,
    ``cloned``). Returns the ``.source.replaced-<hex>`` sibling the previous tree
    was renamed to, for the caller to delete once the new tree is recorded, or None
    when there was no previous tree.

    Raises:
        SessionWorkspaceError: when the previous tree cannot be renamed aside (it,
            and the recorded ``source_dir``, stay as they were), or the staged tree
            cannot be renamed into place after every attempt (the previous tree is
            put back; when that fails too nothing is at ``target``, the error says
            the previous source could not be restored and where it stays, a warning
            names the same path, and the recorded ``source_dir`` names a path with
            nothing at it, which ``run_ash_scan`` refuses as
            ``delivered_source_missing``, where dropping the record would send a
            stdio scan to the server's working directory).
    """

    replaced: Optional[Path] = None
    try:
        os.lstat(target)
    except OSError:
        pass
    else:
        replaced = _move_aside(target, session_dir, "the previously delivered source")
    try:
        _rename_with_retries(staging, target)
    except OSError as e:
        message = f"could not move the {what} source into place at {target}: {e}"
        if replaced is not None:
            try:
                _rename_with_retries(replaced, target)
            except OSError as restore_error:
                # The previous tree stays under its hidden name, and the next
                # delivery to the session puts it back before it does anything else
                # (``_put_a_lost_source_back``); say where it is.
                _logger.warning(
                    "could not put the previous source back at %s from %s: %s; it "
                    "stays under that name, and the next delivery to this session "
                    "tries to put it back first",
                    target,
                    replaced,
                    restore_error,
                )
                message += (
                    f"; the previous source could not be restored from {replaced}: "
                    f"{restore_error}"
                )
        raise SessionWorkspaceError(e.errno, message) from e
    return replaced


def _move_to_trash(tree: Path) -> Optional[Path]:
    """Rename ``tree`` to a trash name beside it; return the new path.

    Returns None when the rename is refused, and ``tree`` is then as it was. A delete
    is only ever done on a tree that carries the trash name, so what a delete leaves
    behind is never mistaken for the previous source (``_TRASH_DIR_PREFIX``). The
    rename is tried once: a tree that is refused it stays whole, and the next
    delivery tries again.
    """

    trash = tree.with_name(f"{_TRASH_DIR_PREFIX}{uuid.uuid4().hex}")
    try:
        tree.rename(trash)
    except OSError:
        return None
    return trash


def _delete_replaced_tree(replaced: Path) -> None:
    """Delete a tree :func:`_move_aside` moved; log what stays. Never raises for it.

    The delivery that replaced the tree took effect when its own tree was recorded,
    so what is left of the old one is scratch under a name the next delivery
    deletes, not a reason to fail. The tree is renamed to the trash name first and
    deleted under it; a tree that cannot be renamed is not deleted in place. It stays
    whole under the replaced name.
    """

    trash = _move_to_trash(replaced)
    if trash is None:
        _logger.warning(
            "could not move the replaced source tree %s aside to delete it; it stays "
            "whole in the session workspace and the next delivery to this session "
            "tries again",
            replaced,
        )
        return
    if not _remove_tree(trash):
        _logger.warning(
            "could not delete the replaced source tree %s; it stays in the session "
            "workspace and the next delivery to this session tries again",
            trash,
        )


def _is_delivery_scratch(name: str) -> bool:
    return name == _LEGACY_STAGING_DIR_NAME or name.startswith(
        (_STAGING_DIR_PREFIX, _REPLACED_DIR_PREFIX, _TRASH_DIR_PREFIX)
    )


def _put_a_lost_source_back(
    session_dir: Path, session_id: str, leftovers: List[Path]
) -> List[Path]:
    """Rename the previous source an earlier delivery lost back onto ``source/``.

    A delivery that set the previous tree aside and could neither move the staged
    tree into place nor put the previous one back leaves ``source/`` missing, the
    previous tree under a ``.source.replaced-<hex>`` name, and the session's record
    naming ``source/``. That tree is the delivered source, not scratch: sweeping it
    would delete the only copy, and a delivery that then failed would leave the
    session with none. While ``source/`` is missing and the record of ``session_id``
    names ``source/`` (``clear_source`` and ``end_session`` drop the record, and a
    restarted server has none, so a tree they left behind stays scratch), no tree
    under the replaced name is deleted. When exactly one exists it is put back. When
    several exist nothing says which is the source, so none is put back and none is
    deleted; a warning says so, a delivery that works puts a new source in place, and
    the next delivery deletes them. Only
    whole trees carry the replaced name (``_delete_replaced_tree`` renames a tree to
    the trash name before it deletes it), so a tree put back is not half-deleted. A
    rename that is refused again keeps the tree out of the sweep and is logged; the
    delivery goes on either way.

    Returns the leftovers the sweep still has to delete.
    """

    target = session_dir / "source"
    hidden = [
        path
        for path in leftovers
        if path.name.startswith(_REPLACED_DIR_PREFIX)
        and path.is_dir()
        and not path.is_symlink()
    ]
    if not hidden:
        return leftovers
    try:
        os.lstat(target)
    except OSError:
        pass
    else:
        return leftovers
    if get_session_source_dir(session_id) != target:
        return leftovers
    if len(hidden) > 1:
        _logger.warning(
            "the previous source of this session is missing and %d trees that may "
            "hold it are in the session workspace; none of them is deleted or "
            "restored, a delivery that works puts a new source in place, and the "
            "next delivery deletes them",
            len(hidden),
        )
        return [path for path in leftovers if path not in hidden]
    previous = hidden[0]
    try:
        _rename_with_retries(previous, target)
    except OSError as e:
        _logger.warning(
            "could not put the previous source back at %s from %s: %s; it stays "
            "under that name and this delivery goes on",
            target,
            previous,
            e,
        )
        return [path for path in leftovers if path != previous]
    _logger.warning(
        "the previous source was left under %s by an earlier delivery that could "
        "not put it back; it is back at %s",
        previous,
        target,
    )
    return [path for path in leftovers if path != previous]


def _sweep_delivery_scratch(session_dir: Path, session_id: str) -> None:
    """Delete what earlier deliveries left beside ``source/``, as far as it can be.

    A staging directory of a delivery that died between extraction (or the clone) and
    the swap, a tree a delivery renamed aside whose delete left entries behind, and
    the fixed staging name earlier versions used. None of it is the delivered tree or
    reachable by a caller, and none of it ends a delivery: what cannot be deleted is
    logged (once) and the delivery goes on, because each delivery works under names
    of its own. One server's delivery to a session runs at a time
    (``_no_scan_running``). The one hidden previous tree of a session whose
    ``source/`` is missing is the delivered source, and is put back first
    (``_put_a_lost_source_back``).
    """

    try:
        with os.scandir(session_dir) as entries:
            leftovers = [Path(e.path) for e in entries if _is_delivery_scratch(e.name)]
    except OSError:
        return
    leftovers = _put_a_lost_source_back(session_dir, session_id, leftovers)
    stuck: List[Path] = []
    for leftover in leftovers:
        if leftover.is_dir() and not leftover.is_symlink():
            if leftover.name.startswith(_REPLACED_DIR_PREFIX):
                # Deleted under the trash name, so a delete that stops partway does
                # not leave a half-deleted tree under the name a lost previous
                # source is put back from. A tree that cannot be renamed stays whole.
                moved = _move_to_trash(leftover)
                if moved is None:
                    stuck.append(leftover)
                    continue
                leftover = moved
            gone = _remove_tree(leftover)
        else:
            with contextlib.suppress(OSError):
                leftover.unlink()
            try:
                os.lstat(leftover)
            except OSError:
                gone = True
            else:
                gone = False
        if not gone:
            stuck.append(leftover)
    if stuck:
        _logger.warning(
            "could not delete %s, left in the session workspace by an earlier source "
            "delivery; this delivery goes on and the next one tries again",
            ", ".join(str(path) for path in stuck),
        )


def _discard_staging(staging: Path) -> None:
    """Delete the staging directory of a delivery that did not finish; log what stays.

    An error ended the delivery, and it is the one to report. The next delivery
    deletes what stays, and does not need it to be gone. Never raises for it.
    """

    if not _remove_tree(staging):
        _logger.warning(
            "could not delete the staging directory %s of a source delivery "
            "that did not finish; it stays in the session workspace and the "
            "next delivery to this session tries again",
            staging,
        )


def _created_session_dir(root: Path, session_id: str) -> Path:
    """Create the session's directory, refusing one that is the default's.

    ``session_identity.is_reserved_session_id`` refuses the spellings of the
    default id that are known to map onto its directory. A volume can mint
    spellings no list anticipates: a case-insensitive volume folds case, a
    trailing dot is dropped from a path component on Windows volumes, and NTFS
    generates short names (``__DEFA~1``, or two characters and four hex digits,
    then ``~N``) that pass every lexical check. The filesystem is therefore
    asked directly: once the directory exists, an id whose directory turns out
    to be the default session's directory under another name is refused,
    however it is spelled.

    Raises:
        ValueError: when ``session_id`` turned out to name the default
            session's directory. The delivery tools report it as
            ``invalid_session_id``, like a reserved-id refusal.
        SessionWorkspaceError: when the directory could not be created
            (``mark_session_workspace``). The delivery tools report it as
            ``session_workspace_unavailable``.
    """

    from automated_security_helper.cli.mcp.profile_registry import (
        DEFAULT_SESSION_ID,
    )

    workspace = _session_workspace(root, session_id)
    try:
        session_dir = mark_session_workspace(workspace)
    except OSError as e:
        raise SessionWorkspaceError(
            e.errno,
            f"could not create the session workspace directory {workspace}: {e}",
        ) from e
    if session_id != DEFAULT_SESSION_ID:
        default_dir = _session_workspace(root, DEFAULT_SESSION_ID)
        try:
            is_alias = os.path.samefile(session_dir, default_dir)
        except OSError:
            # The default session's directory does not exist, so there is
            # nothing this one could alias.
            is_alias = False
        if is_alias:
            raise ValueError(
                f"session_id {session_id!r} names the default session's "
                "directory under another spelling; supply a different id"
            )
    return session_dir


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

    An empty string is unset, as ``ref=""`` is on the tool side: a client that
    sends the field with no value names no key.

    Raises:
        ValueError: for every non-blank ``ssh_key_id``.
    """

    if ssh_key_id:
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
#: checkout's, a fetch's ref-update hooks), wherever they were configured. Git also
#: starts no background maintenance (``gc.auto=0``, ``maintenance.auto=false``): a
#: ``gc --auto`` that the fetch of a ref starts (a checkout starts none) runs detached
#: inside the staging directory, and the handle it holds there makes the rename of the
#: finished clone into place fail on Windows.
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
    # No core.symlinks setting: a delivered tree keeps its links, and a config
    # reached through one is judged by every name it has when it is read
    # (config_sources and validate_config_input), as tests/unit/cli/mcp/
    # test_delivered_config_links.py pins. Checking links out as files would
    # turn each into a plain file holding its target path.
    "-c",
    "gc.auto=0",
    "-c",
    "maintenance.auto=false",
)

#: The program a delivery runs as git. A tuple so a test can name a stand-in.
_GIT_ARGV: Tuple[str, ...] = (GIT_PROGRAM,)

#: Seconds each git command of a delivery (the clone, and for a ref the fetch
#: and the checkout) may run. A command still running then is stopped together
#: with every process it started, and the delivery fails with
#: :class:`GitTimeoutError`.
GIT_TIMEOUT_SECONDS = 600


class CloneRefusedError(RuntimeError):
    """A clone was stopped or refused; the partial tree is removed.

    A subclass names its ``error_type``. ``_clone_into_session`` removes the
    partial tree for every subclass, and ``mcp_set_source_git`` returns the
    subclass's ``error_type``, so a new refusal type needs no other change.
    """

    error_type = "clone_refused"


#: ``error_type`` the MCP tool returns for :class:`GitTimeoutError`.
CLONE_TIMED_OUT = "clone_timed_out"


class GitTimeoutError(CloneRefusedError):
    """A git command of a delivery ran past ``GIT_TIMEOUT_SECONDS`` and was stopped."""

    error_type = CLONE_TIMED_OUT


#: Bytes a clone may grow the session's source directory to, the same limit the
#: zip channel puts on the extracted tree. A command that passes it is stopped
#: together with every process it started, and the delivery fails with
#: :class:`CloneTooLargeError`.
MAX_CLONE_BYTES = _MAX_EXTRACTED_BYTES

#: Seconds between looks at the size of the tree a git command is writing.
GIT_POLL_SECONDS = 0.5

#: ``error_type`` the MCP tool returns for :class:`CloneTooLargeError`.
CLONE_TOO_LARGE = "clone_too_large"


class CloneTooLargeError(CloneRefusedError):
    """A clone passed ``MAX_CLONE_BYTES`` or ``_MAX_FILES`` entries."""

    error_type = CLONE_TOO_LARGE


#: ``error_type`` the MCP tool returns for :class:`CloneTreeUnreadableError`.
CLONE_TREE_UNREADABLE = "clone_tree_unreadable"


class CloneTreeUnreadableError(CloneRefusedError):
    """The tree a git command wrote could not be read once the command had exited."""

    error_type = CLONE_TREE_UNREADABLE


def _walk_failed(error: OSError) -> None:
    """``os.walk`` error handler: only a path that is gone is tolerated."""

    if not isinstance(error, FileNotFoundError):
        raise error


def _walk_failed_during_poll(error: OSError) -> None:
    """``os.walk`` error handler for a poll of a tree git is still writing.

    Tolerates only the two shapes git's own writing produces under the walk: a
    path that is gone (``FileNotFoundError``, git removes its lock files) and a
    directory that became a file (``NotADirectoryError``, a checkout replaces
    one with the other). Any other error is raised, so the poll stops the
    command instead of leaving the subtree uncounted: this poll is the only
    size check that runs while git writes, and a subtree it cannot read
    (``ENAMETOOLONG``, ``EACCES``, ``EMFILE``) would otherwise not count
    toward the limits until the command exits.
    """

    if not isinstance(error, (FileNotFoundError, NotADirectoryError)):
        raise error


def _tree_extent(root: Path, *, running: bool = False) -> Tuple[int, int]:
    """Bytes of the regular files under ``root`` and the count of its entries.

    Links are not followed. A path that vanishes while the tree is walked (git
    removes its lock files) is skipped, because what is left is still measured.

    Args:
        root: The directory to measure.
        running: True for a poll while the command still writes into ``root``.
            Git then changes the tree under the walk, so a path that vanished
            (git removes its lock files) or a directory that became a file (a
            checkout replaces one with the other) is skipped, and the figures
            are a lower bound; the next poll and the check after the command
            exits look again. Any other error is raised in both modes, because
            a subtree that cannot be read must not count as empty: while the
            command runs this walk is the only size check, and once it has
            exited a tree that cannot be measured must not read as an empty
            one.
    """

    onerror = _walk_failed_during_poll if running else _walk_failed
    total = 0
    entries = 0
    for dirpath, dirnames, filenames in os.walk(
        root, followlinks=False, onerror=onerror
    ):
        entries += len(dirnames) + len(filenames)
        for name in filenames:
            try:
                total += os.lstat(os.path.join(dirpath, name)).st_size
            except FileNotFoundError:
                continue
            except NotADirectoryError:
                # A directory became a file under the walk: one of git's own
                # rewrites while it runs, impossible on a still tree.
                if not running:
                    raise
    return total, entries


def _tree_bytes(root: Path) -> int:
    """Bytes of the regular files under ``root``; see :func:`_tree_extent`."""

    return _tree_extent(root)[0]


def _refuse_oversized(grows_in: Optional[Path], *, running: bool = False) -> None:
    """Raise :class:`CloneTooLargeError` when ``grows_in`` is past a clone limit.

    The limits are ``MAX_CLONE_BYTES`` and the zip channel's ``_MAX_FILES``
    entries. A tree that cannot be read is refused with
    :class:`CloneTreeUnreadableError`, which is not a limit, whether the command
    has exited or still runs: while it runs the refusal stops it, because this
    poll is the only size check until it exits and an unreadable subtree must
    not stay uncounted. Only a path git itself removed or rewrote under the
    walk leaves a running poll's figures short; see :func:`_tree_extent`.

    Args:
        grows_in: The directory the command writes into, or None.
        running: True when the command is still running, so that it is about to
            be stopped; False when it has already exited.
    """

    if grows_in is None:
        return
    suffix = " and was stopped" if running else ""
    try:
        size, entries = _tree_extent(grows_in, running=running)
    except OSError as exc:
        raise CloneTreeUnreadableError(
            f"the tree git wrote could not be read ({exc.strerror or exc}); "
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

    git's output is read as text, and a byte that is not valid in the encoding
    (a path or a remote's message written in another one) is kept as its
    ``\\xNN`` escape instead of raising, so git's exit status decides the result
    and its message stays readable.

    Raises:
        GitTimeoutError: when the command runs past the timeout.
        CloneTooLargeError: when ``grows_in`` passes ``MAX_CLONE_BYTES``.
        CloneTreeUnreadableError: when ``grows_in`` cannot be read after the
            command exits.
    """

    # An if statement, not a conditional expression: mypy applies a platform
    # check only to statements.
    group: Dict[str, Any]
    if sys.platform == "win32":
        group = {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP}
    else:
        group = {"start_new_session": True}
    # The group is recorded with the scanners' tools' groups for as long as it
    # runs, so a server that stops while a clone, fetch or checkout runs ends
    # it (subprocess_utils.kill_running_groups) instead of leaving it to run
    # on, writing into a workspace the server has given up.
    from automated_security_helper.utils.subprocess_utils import (
        _register_group,
        _unregister_group,
    )

    process = subprocess.Popen(  # nosec B603 - list-form argv, git from _GIT_ARGV, url and ref validated before any call; see set_source_git
        cmd,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        errors="backslashreplace",
        env=env,
        **group,
    )
    _register_group(process)
    deadline = time.monotonic() + GIT_TIMEOUT_SECONDS
    try:
        return _await_git(cmd, process, deadline, grows_in)
    finally:
        _unregister_group(process)


def _await_git(
    cmd: List[str],
    process: "subprocess.Popen[str]",
    deadline: float,
    grows_in: Optional[Path],
) -> subprocess.CompletedProcess[str]:
    """Wait for ``process``, a git command of a delivery, within its deadline."""
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
    ``HOME`` is the session's own directory. LFS smudging is off
    (``GIT_LFS_SKIP_SMUDGE=1``, which git-lfs honors), so a checkout writes
    pointer files and starts no transfer. git prints its messages in English
    (``LC_MESSAGES=C``).

    Args:
        home: The session directory, used as ``HOME``.
    """

    inherited = snapshot_environ()
    env = {name: inherited[name] for name in _GIT_INHERITED_ENV if name in inherited}
    # git's messages in English, whatever the server's locale: the delivery tells a
    # full disk from other failures by reading them (``_DISK_FULL_MESSAGES``).
    # LC_ALL outranks LC_MESSAGES, so it is passed on as LC_CTYPE, which keeps how git
    # handles text as the server set it and leaves only the language of the messages
    # pinned. LANGUAGE, which gettext reads first, is not in the allowlist. The
    # Windows message for a full disk comes from the system and follows the system's
    # language, which no variable here changes.
    if "LC_ALL" in env:
        env["LC_CTYPE"] = env.pop("LC_ALL")
    env["LC_MESSAGES"] = "C"
    env.update(
        {
            "HOME": str(home),
            "USERPROFILE": str(home),
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_SSH_COMMAND": _GIT_SSH_COMMAND,
            "GIT_LFS_SKIP_SMUDGE": "1",
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

#: A url whose text before its first ``::`` is made of scheme characters (letters,
#: digits, ``+``, ``-`` and ``.``) names a git remote helper, ``ext::`` among them.
#: Tested as a plain string prefix; every such form is refused.
_REMOTE_HELPER_PREFIX = re.compile(r"[A-Za-z0-9+.\-]+::")


def _refuse_remote_helper_prefix(url: str) -> None:
    """Refuse ``url`` when a scheme-shaped prefix precedes its first ``::``.

    Raises:
        ValueError: if ``url`` names a remote helper before ``::``.
    """

    helper = _REMOTE_HELPER_PREFIX.match(url)
    if helper is not None:
        raise ValueError(
            f"refusing a clone url with the {helper.group()!r} remote helper "
            f"transport: git would run that helper rather than connect to a host"
        )


#: ``error_type`` values set_source_git returns, besides the scan-target refusal
#: of a local clone source (scan_target_not_permitted) and invalid_session_id.
#: A client branches on these, so they are stable; the message is for a person.
CLONE_URL_NOT_PERMITTED = "clone_url_not_permitted"
CLONE_REF_NOT_PERMITTED = "clone_ref_not_permitted"
INVALID_CLONE_DEPTH = "invalid_clone_depth"
GIT_CLONE_FAILED = "git_clone_failed"
GIT_CHECKOUT_FAILED = "git_checkout_failed"

#: The most commits of history ``set_source_git`` fetches: a limit on how much history
#: a delivery fetches. It is not a limit on disk or time (a depth of 1000 is the whole
#: history of a repository with 1000 commits or fewer, and one commit of a large
#: repository can be many gigabytes). A depth above it is refused as
#: ``invalid_clone_depth``, as ``0`` and a negative one are. The default depth is 1.
MAX_CLONE_DEPTH = 1000


class GitCommandError(RuntimeError):
    """``git clone`` or ``git checkout`` failed; ``error_type`` says which.

    ``disk_full`` is True when git's own message says the disk is full. The delivery
    that knows whether it has a source to free adds the advice to the message
    (``_with_the_disk_advice``).
    """

    def __init__(
        self, message: str, error_type: str, *, disk_full: bool = False
    ) -> None:
        super().__init__(message)
        self.error_type = error_type
        self.disk_full = disk_full


def _reject_option_like(value: str, what: str) -> str:
    """Reject a git argument that is option-like or holds a control character.

    Two kinds of value are refused here, before anything is created or cloned:

    * one that begins with ``-``, which git parses as an option;
    * one that holds a control character (NUL, the other C0 controls, DEL and the
      C1 controls) or a lone surrogate. A process cannot be started with an argument
      that holds a NUL character, nor on POSIX with one the file system encoding
      cannot write, so the delivery would otherwise clone for up to
      ``GIT_TIMEOUT_SECONDS`` and fail at the next command that carries the value.
      A control character is no part of a ref name or a url either, and the
      refusal's text does not quote the value.

    Args:
        value: The caller-supplied value.
        what: Name of the parameter, used in the error message.

    Returns:
        ``value`` unchanged when it is safe to pass as a positional argument.

    Raises:
        ValueError: if ``value`` begins with ``-``, or holds a control character
            or a lone surrogate.
    """

    if value.startswith("-"):
        raise ValueError(
            f"{what} must not begin with '-': git would parse "
            f"{value!r} as an option rather than a value"
        )
    if any(unicodedata.category(ch) in ("Cc", "Cs") for ch in value):
        raise ValueError(
            f"{what} must not contain a NUL character, another control character or "
            f"a lone surrogate"
        )
    return value


def _validate_clone_url(url: str) -> str:
    """Reject clone URLs that let git execute an arbitrary command.

    Args:
        url: The caller-supplied remote URL.

    Returns:
        ``url`` unchanged when it is safe to clone from.

    Raises:
        ValueError: if ``url`` is option-like, holds a control character or a
            lone surrogate, or names a remote helper before ``::``.
    """

    _reject_option_like(url, "url")
    _refuse_remote_helper_prefix(url)
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


#: The port a clone url without one reaches, by scheme. The scp-like form is ssh
#: and has no way to name a port.
_DEFAULT_PORTS = {"https": 443, "ssh": 22}


def remote_clone_host(url: str) -> str:
    """Return the host ``url`` makes git connect to, or raise if it is not allowed.

    The host of :func:`remote_clone_endpoint`: lower-cased with any trailing dot
    removed.

    Raises:
        ValueError: as :func:`remote_clone_endpoint`.
    """

    return remote_clone_endpoint(url)[1]


def remote_clone_endpoint(url: str) -> tuple[str, str, int]:
    """Return the ``(scheme, host, port)`` ``url`` makes git connect to.

    Accepts ``https://`` and ``ssh://`` URLs and the scp-like ``[user@]host:path``
    form, the three ways git reaches a remote over https or ssh. The scheme is
    ``https`` or ``ssh`` (scp-like is ``ssh``), the host is lower-cased with any
    trailing dot removed, and the port is the one the url names or its scheme's
    default, for comparison against the operator's allowlist.

    Raises:
        ValueError: for a local path or ``file://`` URL, any other scheme, port 0,
            or a host or port this parser cannot state unambiguously.
    """

    from urllib.parse import urlsplit

    if any(ch.isspace() or ord(ch) < 0x20 or ch == "\\" for ch in url):
        raise ValueError(
            "refusing a clone url with whitespace, control characters or backslashes"
        )
    # Before the scp-like reading below, which would take the helper name for a host.
    _refuse_remote_helper_prefix(url)
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
            parts = urlsplit(url)
            host = parts.hostname or ""
            named_port = parts.port
        except ValueError:
            raise ValueError(
                f"refusing a clone url whose host cannot be read: {url!r}"
            ) from None
        if named_port == 0:
            raise ValueError(f"refusing a clone url that names port 0: {url!r}")
        port = _DEFAULT_PORTS[scheme] if named_port is None else named_port
    else:
        scheme = "ssh"
        port = _DEFAULT_PORTS[scheme]
        authority = url.split(":", 1)[0]
        host = authority.rsplit("@", 1)[-1]
    host = host.lower().rstrip(".")
    if not _HOST_NAME.fullmatch(host):
        raise ValueError(f"refusing a clone url whose host cannot be read: {url!r}")
    return scheme, host, port


#: Where ``set_source_git`` may clone from, set by the operator. Comma- or
#: whitespace-separated ``[scheme://]host[:port]`` entries. A bare host stands for
#: its scheme's default port (https 443, ssh 22) on either scheme; ``host:port``
#: names the port, and ``https://`` or ``ssh://`` the scheme. Unset or empty means
#: no remote is allowed.
ASH_MCP_GIT_ALLOWED_HOSTS_ENV = "ASH_MCP_GIT_ALLOWED_HOSTS"


def _read_git_allowed_entry(
    text: str,
) -> Optional[tuple[Optional[str], str, Optional[int]]]:
    """One allowlist entry as ``(scheme, host, port)``, or None when unreadable."""

    scheme: Optional[str] = None
    rest = text.strip().lower()
    if "://" in rest:
        scheme, rest = rest.split("://", 1)
        if scheme not in _CLONE_SCHEMES:
            return None
    host, colon, port_text = rest.partition(":")
    port: Optional[int] = None
    if colon:
        if not (port_text.isascii() and port_text.isdigit()):
            return None
        port = int(port_text)
        if not 1 <= port <= 65535:
            return None
    host = host.rstrip(".")
    if not _HOST_NAME.fullmatch(host):
        return None
    return scheme, host, port


def _git_allowed_entries() -> list[tuple[Optional[str], str, Optional[int]]]:
    """The operator's entries as ``(scheme, host, port)``, None where unnamed.

    An entry this cannot read (another scheme, a port that is not a number from 1
    to 65535, a host that is not a plain name) allows nothing, and is logged once
    per read of the list by its position, so an operator whose entry is dropped
    learns which one. The entry's text is not logged.
    """

    raw = os.environ.get(ASH_MCP_GIT_ALLOWED_HOSTS_ENV, "")
    entries: list[tuple[Optional[str], str, Optional[int]]] = []
    for position, text in enumerate(raw.replace(",", " ").split(), start=1):
        entry = _read_git_allowed_entry(text)
        if entry is None:
            _logger.warning(
                "%s: entry %d cannot be read and allows nothing; an entry is "
                "[scheme://]host[:port] with scheme https or ssh, a plain host "
                "name and a port from 1 to 65535",
                ASH_MCP_GIT_ALLOWED_HOSTS_ENV,
                position,
            )
            continue
        entries.append(entry)
    return entries


def git_allowed_hosts() -> frozenset[str]:
    """The host names the operator allows clones from, lower-cased; possibly none."""

    return frozenset(host for _, host, _ in _git_allowed_entries())


def clone_endpoint_allowed(scheme: str, host: str, port: int) -> bool:
    """Whether an entry of the operator's list allows ``scheme``, ``host`` and ``port``.

    The three come from :func:`remote_clone_endpoint`. An entry allows a clone when
    its host is the url's, its scheme (if it names one) is the url's, and its port
    (the scheme's default when it names none) is the url's.
    """

    return any(
        entry_host == host
        and entry_scheme in (None, scheme)
        and (_DEFAULT_PORTS[scheme] if entry_port is None else entry_port) == port
        for entry_scheme, entry_host, entry_port in _git_allowed_entries()
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
    """``depth`` if it is a whole number of commits from 1 to ``MAX_CLONE_DEPTH``.

    Anything else raises ValueError: ``0`` and a negative number, a bool, a float, a
    string and ``None``, and a number above the maximum. (Over MCP the tool's argument
    model declares the depth an integer and validates it before the tool runs, so
    what reaches this check is an integer, and only a number outside the range is
    answered ``invalid_clone_depth``; a value that is not an integer is refused by the
    argument model first. A caller of the function gets every refusal from here.)
    """

    if (
        isinstance(depth, bool)
        or not isinstance(depth, int)
        or depth < 1
        or depth > MAX_CLONE_DEPTH
    ):
        raise ValueError(
            f"refusing clone depth {depth!r}: the depth is a whole number of commits "
            f"from 1 to {MAX_CLONE_DEPTH}"
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

    A re-delivery needs room for both trees at once: the new clone is made beside
    the delivered source, which is deleted only after it. A clone, fetch or checkout
    that fails for want of space is raised with git's own message. When the session
    has a delivered source the message adds the advice to call ``clear_source`` to
    free it first (``_DISK_FULL_HINT``); on a first delivery it adds only that the
    disk is full (``_DISK_FULL_NOTE``), because there is nothing to free.

    Args:
        url: Remote URL to clone (https or ssh).
        ref: Optional branch/tag/commit to check out. When ``None``, the
            remote default branch is used.
        ssh_key_id: Must be None. No ssh keys are registered, so any id is
            refused; raw private keys are never accepted.
        depth: Shallow-clone depth, a whole number of commits from 1 to
            ``MAX_CLONE_DEPTH``. Defaults to 1 (latest commit only).
        workspace_root: Override workspace root; defaults to
            :func:`resolve_workspace_root`.
        session_id: MCP session identifier used to scope the clone.

    Returns:
        The absolute path of the cloned working tree.

    Raises:
        InvalidSessionIdError: a ValueError, if ``session_id`` is not one a
            workspace can be made for. Raised before anything is created.
        ValueError: if ``url``/``ref`` is option-like, holds a control character or
            a lone surrogate, or uses a command-executing git transport, if ``url``
            is local or not https/ssh, if ``ssh_key_id`` is set, or if ``depth`` is
            not a whole number from 1 to ``MAX_CLONE_DEPTH`` (``0``, a negative
            number, a number above the maximum, a bool, a float, a string and
            ``None`` are refused). Raised before anything is created.
        RuntimeError: if git is not on PATH.
        GitCommandError: if ``git clone`` (or the optional ``git checkout``
            for an explicit ref) fails, or if git cannot be started for a step
            with the url or the ref given. The partial clone is deleted; one that
            cannot be fully deleted stays in the delivery's staging directory beside
            ``source``, logged, for the next delivery to delete, and this is still
            the error raised.
        SessionWorkspaceError: if a directory of the session's workspace cannot be
            created, if the previous clone cannot be moved aside once the new one is
            made (it and the session's recorded ``source_dir`` stay as they were), or
            if the new clone cannot be moved into place (the previous clone is put
            back; when that fails too nothing is at ``source`` and the recorded
            ``source_dir`` names a path with nothing at it). The clone is made in the
            staging directory and replaces the previous clone only when it has worked,
            so a delivery that fails leaves the previous clone and the recorded
            ``source_dir`` as they were.
    """

    # Validated here, before the session is taken: taking it creates the session
    # workspace, and a refused request leaves nothing behind.
    url = _validate_clone_url(url)
    remote_clone_host(url)
    _refuse_ssh_key_id(ssh_key_id)
    if ref:
        ref = _reject_option_like(ref, "ref")
    depth = _validated_clone_depth(depth)
    # The session id last, still before the session is taken. An id no workspace
    # can be made for raises InvalidSessionIdError here rather than a plain
    # ValueError from the session registry, so a caller can tell it from a
    # ValueError raised while git's step runs.
    _session_workspace(
        workspace_root if workspace_root is not None else resolve_workspace_root(),
        session_id,
    )
    return _clone_into_session(
        url, ref, depth=depth, workspace_root=workspace_root, session_id=session_id
    )


@_while_no_scan_runs(removes_workspace=False)
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
    session_dir = _created_session_dir(root, session_id)

    # Resolved before the session directory is touched, like the validation above.
    git = _git_executable()

    # What earlier deliveries left beside source/ goes first; it never ends this one.
    _sweep_delivery_scratch(session_dir, session_id)

    # The clone goes into a staging directory of this delivery's own and replaces the
    # previous tree only once it, and the checkout of a ref, have worked, as a zip
    # extraction does. Replacing first would leave the session without a source for a
    # mistyped ref, a network error or a timeout, and the client's clone would be gone
    # for nothing. Anything that ends the delivery before the swap leaves the previous
    # tree, and the record that names it, as they were.
    target = session_dir / "source"
    staging = session_dir / f"{_STAGING_DIR_PREFIX}{uuid.uuid4().hex}"
    _ensure_dir(staging)

    swapped = False
    replaced: Optional[Path] = None
    # Read before the clone: only a session that has a source to free, or previous
    # source trees kept, is told that freeing them makes room (``_DISK_FULL_HINT``,
    # ``_DISK_FULL_KEPT_HINT``).
    try:
        os.lstat(target)
    except OSError:
        a_source_is_delivered = False
    else:
        a_source_is_delivered = True
    kept_trees = _kept_previous_trees(session_dir)
    try:
        env = _git_environment(session_dir)
        try:
            _clone(url, ref, git=git, depth=depth, target=staging, env=env)
        except GitCommandError as e:
            if e.disk_full:
                raise GitCommandError(
                    _with_the_disk_advice(str(e), a_source_is_delivered, kept_trees),
                    e.error_type,
                    disk_full=True,
                ) from e
            raise
        replaced = _swap_into_place(staging, target, session_dir, "cloned")
        swapped = True
    finally:
        # Whatever ended the delivery (git failed or ran too long, the environment git
        # runs with could not be built, an error no handler names, an interrupt), the
        # staging directory is empty or holds a clone of the wrong ref. It is deleted;
        # what cannot be deleted is logged, and the exception that ended the delivery
        # is the one raised.
        if not swapped:
            _discard_staging(staging)

    _set_session_source_dir(session_id, target)
    if replaced is not None:
        # The new tree is in place and recorded; what is left of the old one is
        # session scratch that the next delivery, clear_source or the end of the
        # session removes.
        _delete_replaced_tree(replaced)
    return target


def _run_git_step(
    cmd: List[str],
    *,
    env: Dict[str, str],
    what: str,
    error_type: str,
) -> subprocess.CompletedProcess[str]:
    """``_run_git``, except that a git which cannot be run fails the delivery.

    A git the system cannot start (the program is gone since an earlier command
    of the delivery ran, it is not executable, no process could be made) makes
    ``Popen`` raise an ``OSError``, and an argument it cannot pass to the process
    (one holding a NUL character, or on POSIX one the file system encoding cannot
    write) makes it raise a ``ValueError``. To a client either is a failed command
    like one git ran and refused: the answer carries ``error_type``, not the
    exception's class name. The clone's staging directory is not touched here. The
    delivery that made it deletes it, and logs what it could not delete, whatever
    ended the delivery, so the error raised is git's, never a workspace error about
    the cleanup.

    Args:
        what: The command as the message names it, such as ``git clone``.
        error_type: The ``error_type`` of the step this command belongs to.

    Raises:
        GitCommandError: when git cannot be run.
        GitTimeoutError: when the command runs past ``GIT_TIMEOUT_SECONDS``.
    """

    try:
        return _run_git(cmd, env=env)
    except (OSError, ValueError) as e:
        raise GitCommandError(
            f"{what} failed: git could not be run ({e})", error_type
        ) from e


#: Appended to the text of a failed https clone: git's environment here does not
#: follow http redirects, and a host that answers with one is a common cause.
_REDIRECT_HINT = (
    "If the host answered with a redirect, HTTP redirects are not followed; "
    "give the URL the host redirects to (for example with the .git suffix)."
)


def _with_the_redirect_hint(detail: str) -> str:
    """``detail`` (git's text) followed by the redirect hint as a sentence of its own.

    A full stop is added after git's text unless it ends in one, and when git
    printed nothing the hint is the whole detail.
    """

    text = detail.rstrip()
    if not text:
        return _REDIRECT_HINT
    return f"{text}{' ' if text.endswith('.') else '. '}{_REDIRECT_HINT}"


#: Appended to the text of a failed clone, fetch or checkout when git's message says
#: the disk is full and the session has a delivered source. A re-delivery clones
#: beside the source already delivered, so a repository that fits once may not fit
#: twice, and git's own words say only that the disk is full.
_DISK_FULL_HINT = (
    "A re-delivery needs room for both the delivered source and the new clone at "
    "once; call clear_source to free the delivered one, then deliver again."
)

#: Appended instead when the session has no delivered source but keeps previous source
#: trees under the replaced name (``_put_a_lost_source_back`` keeps every one when it
#: cannot tell which is the source). Each takes a source's worth of space, and
#: ``clear_source`` frees them.
_DISK_FULL_KEPT_HINT = (
    "The session workspace also keeps previous source trees that take room; call "
    "clear_source to free them, then deliver again."
)

#: Appended when the session has neither: there is nothing to free, and
#: ``clear_source`` would only wipe the session's workspace.
_DISK_FULL_NOTE = "The disk is full."

#: What git prints, lowercased, when a write fails for want of space: the POSIX
#: strerror of ENOSPC, and the Windows message of ERROR_DISK_FULL.
_DISK_FULL_MESSAGES = ("no space left on device", "not enough space on the disk")


#: git prints the messages of the server it talks to behind this prefix.
_REMOTE_LINE_PREFIX = "remote:"


def _is_disk_full(detail: str) -> bool:
    """Whether a line git wrote itself says that this disk is full.

    A ``remote:`` line is the server's message, in the server's language: when it says
    the disk is full, the server's disk is, and freeing the delivered source here does
    not help. Those lines are not read.
    """

    own_lines = [
        line
        for line in detail.splitlines()
        if not line.lstrip().lower().startswith(_REMOTE_LINE_PREFIX)
    ]
    lowered = "\n".join(own_lines).lower()
    return any(message in lowered for message in _DISK_FULL_MESSAGES)


def _kept_previous_trees(session_dir: Path) -> int:
    """How many whole previous source trees ``session_dir`` keeps under the replaced name."""

    try:
        with os.scandir(session_dir) as entries:
            return sum(
                1
                for entry in entries
                if entry.name.startswith(_REPLACED_DIR_PREFIX)
                and entry.is_dir(follow_symlinks=False)
            )
    except OSError:
        return 0


def _with_the_disk_advice(
    detail: str, a_source_is_delivered: bool, kept_trees: int = 0
) -> str:
    """``detail`` followed by what to do about a full disk, as a sentence of its own.

    The advice is to free the delivered source when the session has one
    (``_DISK_FULL_HINT``), to free the previous source trees it keeps when it has
    only those (``_DISK_FULL_KEPT_HINT``), and only the fact that the disk is full
    when it has neither (``_DISK_FULL_NOTE``). A full stop is added after ``detail``
    unless it ends in one. ``detail`` is the text of a message that names a full disk,
    so it is never empty.
    """

    text = detail.rstrip()
    if a_source_is_delivered:
        advice = _DISK_FULL_HINT
    elif kept_trees:
        advice = _DISK_FULL_KEPT_HINT
    else:
        advice = _DISK_FULL_NOTE
    return f"{text}{' ' if text.endswith('.') else '. '}{advice}"


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

    ``target`` is the caller's: whatever ends this function, it is left as it is,
    whole or partial, and the caller deletes it (``_clone_into_session`` does, in a
    ``finally``). Deleting it here as well would delete the same tree twice, and a
    tree that cannot be deleted would replace git's own error with a workspace error.

    Raises:
        GitCommandError: when the clone or the checkout fails, or when git cannot be
            run for the clone, the fetch or the checkout. ``error_type`` is
            ``git_checkout_failed`` for the checkout and ``git_clone_failed`` for the
            clone and the fetch.
        GitTimeoutError: when a command runs past ``GIT_TIMEOUT_SECONDS``.
    """

    # PATH's anchored entries only, for the programs git starts by name (ssh, a
    # credential helper); see subprocess_utils._spawn_env.
    from automated_security_helper.utils.subprocess_utils import child_environ

    env = child_environ(env)

    program = (git if git is not None else _git_executable(), *_GIT_ARGV[1:])
    # git_argv: no hook or fsmonitor that git config names runs for the
    # clone, the fetch or the checkout.
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
    result = _run_git_step(cmd, env=env, what="git clone", error_type=GIT_CLONE_FAILED)
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip()
        disk_full = _is_disk_full(detail)
        # A full disk is not a redirect, whatever the scheme. The advice for it is
        # added by the delivery, which knows whether there is a source to free.
        if not disk_full and url.lower().startswith("https://"):
            # A common failure shape behind http.followRedirects=false: the
            # host answers with a redirect (often to the .git form) and git
            # refuses to follow it. Git's text does not say that was the cause,
            # so the hint is worded as a condition, and it is a sentence of its
            # own after git's text (or the whole detail when git printed none).
            detail = _with_the_redirect_hint(detail)
        message = f"git clone failed (exit {result.returncode}): {detail}"
        raise GitCommandError(message, GIT_CLONE_FAILED, disk_full=disk_full)
    if not ref:
        # A clone of a repository whose HEAD names a branch that does not exist
        # (an empty repository, or one whose default branch was deleted) exits 0
        # with no commit and an empty working tree. Registered as the session's
        # source, that tree scans clean for code the client never delivered, so
        # the clone is refused unless its HEAD is a commit.
        head = _run_git_step(
            git_argv(
                *_GIT_CONFIG,
                "-C",
                str(target),
                "rev-parse",
                "--verify",
                "--quiet",
                "HEAD^{commit}",
                program=program,
            ),
            env=env,
            what="git rev-parse HEAD",
            error_type=GIT_CLONE_FAILED,
        )
        if head.returncode != 0:
            raise GitCommandError(
                "git clone produced no commit: the repository's default branch "
                "has no commits or does not exist. Name a ref to deliver.",
                GIT_CLONE_FAILED,
            )
        return

    # A shallow clone is single-branch, so a ref off the default branch is not in
    # it. The fetch brings it, and records it only in FETCH_HEAD: a named branch
    # or tag gets no local ref, so the checkout takes FETCH_HEAD. A fetch that
    # fails (a commit id the remote won't serve by id) leaves the checkout to
    # find the ref in the clone itself, and to report it if it isn't there. A git
    # that cannot be run is not such a fetch: it says nothing about what the clone
    # holds, so the delivery fails there, as a failed clone. Neither is a fetch
    # that ran out of space: the ref may well exist, and a checkout that follows
    # would report it as missing.
    fetch = _run_git_step(
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
        what=f"git fetch {ref!r}",
        error_type=GIT_CLONE_FAILED,
    )
    if fetch.returncode != 0:
        fetch_detail = fetch.stderr.strip() or fetch.stdout.strip()
        if _is_disk_full(fetch_detail):
            raise GitCommandError(
                f"git fetch {ref!r} failed (exit {fetch.returncode}): {fetch_detail}",
                GIT_CLONE_FAILED,
                disk_full=True,
            )
    revision = "FETCH_HEAD" if fetch.returncode == 0 else ref
    checkout = _run_git_step(
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
        what=f"git checkout {ref!r}",
        error_type=GIT_CHECKOUT_FAILED,
    )
    if checkout.returncode != 0:
        detail = checkout.stderr.strip() or checkout.stdout.strip()
        message = f"git checkout {ref!r} failed (exit {checkout.returncode}): {detail}"
        raise GitCommandError(
            message, GIT_CHECKOUT_FAILED, disk_full=_is_disk_full(detail)
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


#: How many uploads a session may hold in ``incoming/`` at once, and how many
#: bytes they may hold together. Each upload is capped at ``_MAX_ZIP_BYTES`` on
#: its own; without a bound across uploads a session could open any number of
#: upload ids and hold that many archives on the server's disk until it ended
#: or was swept.
_MAX_UPLOADS_PER_SESSION: int = 4
_MAX_INCOMING_BYTES: int = 2 * _MAX_ZIP_BYTES

_UPLOAD_SUFFIXES = (".zip.part", ".zip")


def _other_uploads(incoming: Path, upload_id: str) -> Tuple[int, int]:
    """How many archives and partial archives other than ``upload_id``'s own sit
    in ``incoming/``, and how many bytes they hold together.

    An upload sent again under its id replaces its own file, so its own files
    are left out. An upload whose chunks all arrived and whose finalize was never
    sent holds its bytes until the next delivery, a clear or the end of the
    session; this is what the per-session bounds below count. ``(0, 0)`` when the
    directory cannot be read.
    """
    own = {f"{upload_id}{suffix}" for suffix in _UPLOAD_SUFFIXES}
    held = 0
    held_bytes = 0
    try:
        entries = list(os.scandir(incoming))
    except OSError:
        return 0, 0
    for entry in entries:
        if not entry.name.endswith(_UPLOAD_SUFFIXES) or entry.name in own:
            continue
        try:
            st = entry.stat(follow_symlinks=False)
        except OSError:
            continue
        if not stat.S_ISREG(st.st_mode):
            continue
        held += 1
        held_bytes += st.st_size
    return held, held_bytes


def _refuse_another_upload(incoming: Path, upload_id: str) -> None:
    """Refuse the first chunk of an upload when the session holds the most it may."""
    held, _held_bytes = _other_uploads(incoming, upload_id)
    if held >= _MAX_UPLOADS_PER_SESSION:
        raise ValueError(
            f"too many uploads in progress for this session: {held} already held, "
            f"the limit is {_MAX_UPLOADS_PER_SESSION}; finalize or clear them first"
        )


def _refuse_a_chunk_past_the_session_bound(
    incoming: Path, upload_id: str, own_bytes: int
) -> None:
    """Refuse a chunk that would take the session's held bytes past the bound.

    ``own_bytes`` is what this upload will hold once the chunk is appended: its
    partial archive so far plus the chunk. Read on every chunk, not only the
    first: a bound read only at an upload's first chunk let each of a session's
    uploads start small and then grow to ``_MAX_ZIP_BYTES`` on its own, and the
    session's uploads together held that many times the per-upload cap.
    """
    _held, held_bytes = _other_uploads(incoming, upload_id)
    if held_bytes + own_bytes > _MAX_INCOMING_BYTES:
        raise ValueError(
            f"uploads in progress for this session hold {held_bytes} bytes and "
            f"this chunk would make it {held_bytes + own_bytes}, the limit is "
            f"{_MAX_INCOMING_BYTES}; finalize or clear them first"
        )


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


#: Locks that serialize the chunks of one upload. An upload maps to one of a fixed
#: number of locks by its (session, upload id), so the table never grows with the
#: number of uploads; two uploads that share a lock only take turns.
_UPLOAD_LOCK_STRIPES = 64
_UPLOAD_LOCKS = tuple(threading.Lock() for _ in range(_UPLOAD_LOCK_STRIPES))

#: Locks that serialize the chunk writers of one session against each other,
#: taken before the upload's own lock. The per-session bounds are read from the
#: directory and enforced under this lock: with only the per-upload lock, two
#: first chunks of two uploads each counted the other as absent and both passed.
#: The session's write hold (``sessions.writing_session_state``) does not
#: serialize writes against each other, by design.
_SESSION_UPLOAD_LOCKS = tuple(threading.Lock() for _ in range(_UPLOAD_LOCK_STRIPES))


def _upload_lock(session_id: str, upload_id: str) -> threading.Lock:
    """The lock held while a chunk of this upload reads and moves its sequence."""

    digest = hashlib.sha256(f"{session_id}\0{upload_id}".encode()).digest()
    return _UPLOAD_LOCKS[digest[0] % _UPLOAD_LOCK_STRIPES]


def _session_upload_lock(session_id: str) -> threading.Lock:
    """The lock held while a chunk of any of this session's uploads is appended."""

    digest = hashlib.sha256(session_id.encode()).digest()
    return _SESSION_UPLOAD_LOCKS[digest[0] % _UPLOAD_LOCK_STRIPES]


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
        sessions.SessionWorkspaceBusyError: while another request holds the
            session's workspace (``sessions.writing_session_state``): the TTL
            sweep, a ``clear_source``, or the end of the session. The hold can
            end without removing the upload, so the chunk is sent again as it
            is; only an out-of-order answer means the upload was removed, and
            the upload is then sent again from its first chunk.
    """
    from automated_security_helper.cli.mcp.sessions import writing_session_state

    with (
        writing_session_state(session_id),
        _session_upload_lock(session_id),
        _upload_lock(session_id, upload_id),
    ):
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
    session_dir = _created_session_dir(root, session_id)
    part = _part_path(session_dir, upload_id)
    _ensure_dir(part.parent)

    expected = _read_next_sequence(session_dir, upload_id)
    if sequence != expected:
        raise ValueError(
            f"out-of-order chunk: expected sequence {expected}, got {sequence}"
        )
    if sequence == 0:
        _refuse_another_upload(part.parent, upload_id)

    try:
        decoded = base64.b64decode(data_b64, validate=True)
    except Exception as exc:  # noqa: BLE001 — re-raise as a typed error
        raise ValueError(f"invalid base64 payload: {exc}") from exc

    if len(decoded) > _MAX_CHUNK_BYTES:
        raise ValueError(f"chunk too large: {len(decoded)} > {_MAX_CHUNK_BYTES} bytes")

    try:
        so_far = part.stat().st_size
    except OSError:
        so_far = 0
    try:
        _refuse_a_chunk_past_the_session_bound(
            part.parent, upload_id, so_far + len(decoded)
        )
    except ValueError:
        # As for the per-upload cap below: what this upload holds is dropped
        # with the refusal, and the upload is sent again from its first chunk.
        part.unlink(missing_ok=True)
        _meta_path(session_dir, upload_id).unlink(missing_ok=True)
        raise

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
    if "\\" in name:
        # The zip format's separator is "/". An entry named with backslashes
        # passed the checks below as a nested path, since they read a backslash
        # as a separator, and was then extracted on POSIX as one flat file whose
        # name holds the backslashes, which a scanner keyed on directories never
        # sees. Refused rather than rewritten, as every other malformed entry.
        raise ValueError(f"backslash in zip entry name: {name!r}")
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


@_while_no_scan_runs(removes_workspace=False)
def set_source_zip_finalize(
    upload_id: str,
    expected_sha256: str,
    *,
    workspace_root: Optional[Path] = None,
    session_id: str,
) -> Path:
    """Finalize a chunked upload: verify checksum and extract.

    Holds the upload's lock (:func:`_upload_lock`) only to open the zip and to
    remove its path afterwards, not while the zip is hashed and extracted: the
    lock is one of 64 shared by every session, and holding it across up to the
    size limit of work would starve the delivery pool. The checksum and the
    extraction read one open handle, so the bytes extracted are exactly the bytes
    hashed whatever happens to the path meanwhile, and the removal deletes the
    path only while it still names the file that was read, so a zip a chunk
    assembled over it meanwhile is kept; see :func:`_finalize_zip_upload`.

    Args:
        upload_id: Identifier matching the prior ``set_source_zip_chunk`` calls.
        expected_sha256: Hex sha256 the assembled zip must hash to.
        workspace_root: Override workspace root.
        session_id: MCP session identifier.

    Returns:
        Absolute path of the extracted source tree (the session's
        ``source_dir``). Unchanged on every failure path: extraction goes to a
        staging directory of the delivery's own and is renamed into place only
        after it succeeds, so a refused re-delivery leaves the previously
        delivered tree intact rather than leaving the session registered against
        an empty directory. The one exception is a swap that cannot complete (see
        SessionWorkspaceError below). What earlier deliveries left beside
        ``source/`` and could not delete is logged and never ends this one.

    Raises:
        SessionWorkspaceError: if a directory of the session's workspace cannot
            be created, or the swap fails: the previous tree cannot be renamed
            aside (it and the recorded ``source_dir`` stay as they were; nothing is
            deleted where it stands, and the uploaded zip stays, so the same
            finalize can be sent again), or the extracted tree cannot be moved into
            place (the previous tree is put back; when that fails too nothing is at
            ``source/`` and the recorded ``source_dir`` names a path with nothing at
            it). The recorded ``source_dir`` is never dropped, so a scan given no
            ``source_dir`` is refused as ``delivered_source_missing`` and never
            reads the server's working directory. The failure is one error whatever
            the OSError was.
        UploadNotFoundError: a FileNotFoundError, if the upload never received its
            final chunk. A FileNotFoundError that is not this one is a file that
            vanished while the archive was read or extracted, a failure on disk.
        ValueError: if ``upload_id`` does not name a single path component, or on
            sha256 mismatch, oversize zip, oversize extraction, too-many-files,
            or path-traversal/symlink-out-of-tree entries.
        zipfile.BadZipFile: if the assembled bytes are not a zip archive. The
            checksum matching means the client sent what it meant to send, so
            this is a client-side packaging error rather than corruption.
    """

    return _finalize_zip_upload(
        upload_id,
        expected_sha256,
        workspace_root=workspace_root,
        session_id=session_id,
    )


class _ZipRefused(Exception):
    """A finalized zip the finalize refuses before it extracts anything.

    Raised inside the ``with`` that holds the zip open, so the zip is removed and
    the refusal raised as a ``ValueError`` only after the handle is closed:
    Windows does not delete a file that is open.
    """


@contextlib.contextmanager
def _refusing_after_close(
    handle: Any, remove_zip: Callable[[], None]
) -> Iterator[None]:
    """Hold ``handle`` open; on :class:`_ZipRefused`, close it, ``remove_zip()``, refuse."""

    try:
        with handle:
            yield
    except _ZipRefused as refused:
        remove_zip()
        raise ValueError(str(refused)) from None


@contextlib.contextmanager
def _removing_a_refused_zip(remove_zip: Callable[[], None]) -> Iterator[None]:
    """Call ``remove_zip`` when the validation or extraction inside refuses the zip.

    Entered outside the handle and the ``zipfile.ZipFile`` that read the zip, so
    both are closed before the removal: Windows does not delete a file that is
    open. Best effort, as for the oversize and checksum refusals: a held file
    must not replace the refusal the caller is owed, and a zip that stays is
    refused again by the same call. Only a refusal (``ValueError``,
    ``zipfile.BadZipFile``) removes it; a failure on disk (``OSError``) leaves it
    for the next attempt.
    """
    try:
        yield
    except (ValueError, zipfile.BadZipFile):
        with contextlib.suppress(OSError):
            remove_zip()
        raise


def _remove_zip_still_at(
    final: Path, opened: os.stat_result, session_id: str, upload_id: str
) -> None:
    """Remove ``final`` if it still names the file ``opened`` describes.

    Under the upload's lock, so no chunk of the upload assembles a zip over the
    path between the comparison and the removal. A zip a chunk assembled over the
    path while the finalize ran is a different file and is kept.
    """

    with _upload_lock(session_id, upload_id):
        try:
            if os.path.samestat(opened, final.stat()):
                final.unlink(missing_ok=True)
        except FileNotFoundError:
            pass


def _finalize_zip_upload(
    upload_id: str,
    expected_sha256: str,
    *,
    workspace_root: Optional[Path],
    session_id: str,
) -> Path:
    """:func:`set_source_zip_finalize`: the work behind its docstring."""

    root = workspace_root if workspace_root is not None else resolve_workspace_root()
    session_dir = _created_session_dir(root, session_id)
    final = _final_zip_path(session_dir, upload_id)
    # The one handle every read below uses: the size bound, the checksum and the
    # extraction all see the file that was open here, whatever a chunk of the
    # same upload (set_source_zip_chunk's last=True renames a new zip over the
    # path) puts at the path meanwhile. ``opened`` identifies that file, so each
    # removal (_remove_zip_still_at) deletes the path only while it still names
    # it, and a newer zip is kept for its own finalize.
    try:
        handle = final.open("rb")
    except FileNotFoundError:
        raise UploadNotFoundError(
            f"no finalized zip for upload_id={upload_id!r} "
            f"(did the last chunk arrive with last=True?)"
        ) from None
    opened = os.fstat(handle.fileno())

    def remove_zip() -> None:
        _remove_zip_still_at(final, opened, session_id, upload_id)

    # Hard limit on the on-disk zip size.
    actual_size = opened.st_size
    if actual_size > _MAX_ZIP_BYTES:
        handle.close()
        # Removing the refused zip is scratch cleanup, best effort: an AV scanner
        # or indexer holding the file (routine on Windows) makes the unlink raise
        # PermissionError, and that must not replace the refusal the caller is
        # owed. A zip that stays is refused again by the same call.
        with contextlib.suppress(OSError):
            remove_zip()
        raise ValueError(f"zip too large: {actual_size} > {_MAX_ZIP_BYTES} bytes")

    # Verify checksum before opening the archive, from the same handle.
    digest = hashlib.sha256()
    try:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
        handle.seek(0)
    except BaseException:
        handle.close()
        raise
    actual_sha = digest.hexdigest()
    if actual_sha.lower() != expected_sha256.lower():
        handle.close()
        # Best effort, as above: the mismatch is the answer, not a held file.
        with contextlib.suppress(OSError):
            remove_zip()
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
    # Left behind by a delivery that died between extraction and the swap, or
    # renamed aside by one whose delete stopped short: scratch space, never the
    # delivered tree, so deleting it cannot lose anything a caller can still reach.
    # What cannot be deleted does not end this delivery, which extracts into a
    # directory of its own name and so cannot put those entries in source/.
    _sweep_delivery_scratch(session_dir, session_id)
    staging = session_dir / f"{_STAGING_DIR_PREFIX}{uuid.uuid4().hex}"
    _ensure_dir(staging)

    swapped = False
    replaced: Optional[Path] = None
    try:
        # Pre-extraction validation pass: walk the namelist and the zipinfo
        # list, rejecting absolute paths, traversal components, oversize totals,
        # and symlinks that would resolve outside the session sandbox. An archive
        # one of them refuses is removed with the refusal (_removing_a_refused_zip):
        # it held its bytes in incoming/ until the session ended otherwise, and a
        # client that sends the same finalize again is told the upload is gone.
        # The archive is read from the handle the checksum read, so the bytes
        # extracted are the bytes hashed; the handle closes before the removal.
        with (
            _removing_a_refused_zip(remove_zip),
            handle,
            zipfile.ZipFile(handle) as zf,
        ):
            infos = zf.infolist()
            if len(infos) > _MAX_FILES:
                raise ValueError(f"too many files in zip: {len(infos)} > {_MAX_FILES}")

            total_uncompressed = 0
            for info in infos:
                # The name as the archive spells it. On Windows the reader
                # rewrites a backslash in ``filename`` to ``/`` (ZipInfo keeps
                # the raw spelling in ``orig_filename``), so an archive judged
                # by ``filename`` was refused on POSIX and admitted on Windows
                # as a nested path; one spelling is judged on every platform.
                _validate_zip_member(info.orig_filename)
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
                    # divergence, as an earlier review noted.
                    #
                    # Only the first bytes of the entry are shown. A link entry's
                    # content is whatever the archive says it is, up to the
                    # uncompressed total this loop admits, and the refusal text
                    # is carried through every per-character pass the error path
                    # makes on the event loop; the whole of it in the message
                    # was that many bytes read, held and re-processed for one
                    # line nobody reads past its first few words.
                    with zf.open(info) as member:
                        head = member.read(_SYMLINK_TARGET_EXCERPT_BYTES + 1)
                    link_target = head[:_SYMLINK_TARGET_EXCERPT_BYTES].decode(
                        "utf-8", errors="replace"
                    )
                    if len(head) > _SYMLINK_TARGET_EXCERPT_BYTES:
                        link_target += "..."
                    raise ValueError(
                        f"symlink {info.filename!r} -> {link_target!r}: "
                        f"symlinks are not allowed in MCP source delivery zips"
                    )

            # Validation passed; extract into staging.
            zf.extractall(staging)

        # Swap (_swap_into_place). The window in which neither tree is in place is
        # the rename of the staged tree into place (two renames when nothing refuses
        # them, under a second more when a held handle makes one be tried again)
        # rather than the whole validate-and-extract pass, and a
        # previous tree that cannot be renamed aside ends the delivery with that
        # tree, and the record that names it, as they were.
        replaced = _swap_into_place(staging, target, session_dir, "extracted")
        swapped = True
    finally:
        if not swapped:
            _discard_staging(staging)

    _set_session_source_dir(session_id, target)
    if replaced is not None:
        # The new tree is in place and recorded; what is left of the old one is
        # session scratch that the next delivery, clear_source or the end of the
        # session removes.
        _delete_replaced_tree(replaced)
    # The on-disk zip is no longer needed. Best effort: the delivery took effect
    # at _set_session_source_dir, and a failed unlink of a scratch file must not
    # report that delivery as failed, which invites a retry of a done delivery.
    # Only the zip that was delivered: a newer one at the path is kept.
    with contextlib.suppress(OSError):
        remove_zip()
    return target


# ---------------------------------------------------------------------------
# Cleanup.
# ---------------------------------------------------------------------------


@_while_no_scan_runs()
def clear_source(session_id: str, *, workspace_root: Optional[Path] = None) -> None:
    """Wipe the session workspace and forget any recorded ``source_dir``.

    Idempotent: missing workspaces are silently ignored. Read-only entries are
    made writable and deleted (see :func:`_remove_tree`). Entries the process
    cannot delete (files another account owns) stay on disk and are logged; the
    recorded ``source_dir`` is forgotten whatever the delete leaves behind.

    Raises:
        SourceDeliveryBusyError: while a scan of the session runs, or a chunk of
            an upload or a profile selection is being written, because this
            removes the directory they write into.
    """

    # The binding select_profile made is kept. It names the profile materialized
    # in this workspace's config/ directory, which goes with the workspace; the
    # binding is the source of truth and the resolver writes the file again from
    # it when the file is gone (profile_registry.resolve_session_config_path),
    # refusing the scan when it cannot. The binding ends with the session
    # (sessions.end_session), not with its files.
    if not remove_session_workspace(session_id, workspace_root=workspace_root):
        _logger.warning(
            "could not delete the whole workspace of session %s; the entries that "
            "stay are not part of any delivered source",
            session_id,
        )


def remove_session_workspace(
    session_id: str, *, workspace_root: Optional[Path] = None
) -> bool:
    """Remove the session workspace and its record, without taking the scan lock.

    For a caller that already holds the session's lock --
    ``sessions.end_session`` -- or that has decided a scan cannot be running.
    Read-only entries are made writable and deleted, as in ``clear_source``.

    The workspace is renamed to a hidden sibling first and the delete runs on
    that name, so the session's own path is free for the whole delete: a request
    for the same id that arrives during it builds a workspace of its own there,
    and nothing in this removal touches that one. What the delete cannot remove
    stays under the hidden name, which the TTL sweep clears
    (``sessions.sweep_stale_workspaces``). A rename the filesystem refuses falls
    back to deleting the workspace where it stands.

    The record is dropped whatever the delete leaves behind, and nothing is
    raised for it, so a caller that is ending a session goes on with the rest of
    its work. Returns whether the workspace is gone.
    """

    root = workspace_root if workspace_root is not None else resolve_workspace_root()
    session_dir = _session_workspace(root, session_id)
    doomed = _set_aside_for_removal(session_dir, session_id)
    gone = True if doomed is None else _remove_tree(doomed)
    _drop_session_source_dir(session_id)
    return gone


def _set_aside_for_removal(workspace: Path, session_id: str) -> Optional[Path]:
    """Rename ``workspace`` to its hidden delete name and return that path.

    Returns None only when the stat says nothing is on disk at ``workspace``
    (``FileNotFoundError``). It returns ``workspace`` itself when the stat fails
    for any other reason (EACCES, EIO and ESTALE say nothing about whether the
    tree is there) or when the rename fails (the entry vanished between the check
    and the rename, or the filesystem refused it), so the caller's delete still
    runs; only that path deletes at the session's own name.
    """

    try:
        os.lstat(workspace)
    except FileNotFoundError:
        return None
    except OSError:
        return workspace
    doomed = workspace.parent / hidden_deleting_name(session_id)
    try:
        os.rename(workspace, doomed)
    except OSError:
        return workspace
    # A same-parent rename leaves the directory's own modification time as it was.
    # Set to the time of the rename, the directory is young for as long as a TTL
    # sweep of another server sharing the root would wait before it took the
    # leftover for its own to delete.
    with contextlib.suppress(OSError):
        os.utime(doomed)
    return doomed
