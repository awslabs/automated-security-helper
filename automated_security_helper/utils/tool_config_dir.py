# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The directory that holds the config files ASH writes for a scanner's tool.

Why this exists
---------------
bandit, grype, syft, trivy and ferret-scan each read a config file of their own
from the scanned tree unless they are given one, so ASH always gives one: the
operator's, or a file ASH writes that sets nothing
(``config/tool_config_trust.empty_tool_config``). A tool that loads what a
directory holds (trivy-repo's modules directory) gets an empty one the same way
(``empty_tool_directory``, :func:`make_tool_config_directory`). cfn-guard is
handed copies of the operator's rules files ASH read, and gitleaks' re-scan
copies of the files a ``.gitleaksignore`` names, which are written here too.
Those used to be written in
the scanner's results directory. That is under the output directory, which
defaults to ``<source>/.ash/ash_output``, so the file sat inside the tree being
scanned, at a path the scanned repository could already occupy with a committed
file or link, and the tool read it from there.

What happens now
----------------
Each scanner run has a directory of its own for these files
(:func:`tool_config_scope`, entered by the scanner executor around each
``scan()``). It is

* made by ``tempfile.mkdtemp``, so it is new, its name is not known in advance,
  and its mode is 0700. It is in the system temporary directory, or under the
  output directory when the temporary directory is inside the scanned tree and the
  output directory is not, or when there is no usable temporary directory;
* never under a directory another local account could change: one it owns, or
  one its group or everyone can write without the sticky bit, anywhere from the
  candidate up to ``/``. Such an account could otherwise rename the new directory
  and put its own in its place between ``mkdtemp`` and the writes, since
  ``O_NOFOLLOW`` covers only the last component. A sticky ``/tmp`` is fine;
* made only when the run writes its first file, and each file in it is created
  with ``O_EXCL`` and ``O_NOFOLLOW``, so it is a new file ASH wrote;
* readable, and not writable, by that scanner under ``--sandbox``:
  ``utils/sandbox/scope.prepare_spawn`` adds :func:`active_tool_config_dir` to each
  spawn's read grants, as scan data, which sandbox-exec (the one backend that
  limits where programs run from) does not let a program run from;
* removed when the run ends, whether the tool succeeded, failed or never started.

Failure modes and known limitations
-----------------------------------
* When neither the temporary directory nor the output directory is both private
  and outside the scanned tree (a scan of a whole filesystem, or a ``TMPDIR``
  other accounts can write with the output directory in its default place), the
  directory is made in the first private one inside the tree, and a warning names
  each candidate passed over and why. It is still new and private, so nothing in
  the repository can be at its path, but a tool that walks the tree may come
  across it.
* When neither is private, nothing is written: the scanner run fails with an
  ``OSError`` that names each directory and says to set ``TMPDIR`` to one only
  this account can write.
* The check is POSIX only. On Windows, where these modes do not exist, the
  directory is made as before.
* A scanner run outside the scanner executor (a test, a scanner module run as a
  script) has no scope. Each file it writes gets a directory of its own, removed
  when the process exits.
* An ASH process killed by a signal (SIGTERM, which the CLI does not handle, or
  SIGKILL) runs neither the scope's ``finally`` nor ``atexit``, so its directory
  stays behind in the temporary directory. It is 0700 and holds only the empty
  configs. Turning SIGTERM into ``SystemExit`` would not remove it promptly either:
  scanner runs are in worker threads, and the executor's pool waits for them, and
  for their tools, before the process could exit.
"""

from __future__ import annotations

import atexit
import contextvars
import os
import shutil
import stat
import tempfile
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator, List, Optional, Tuple, cast

from automated_security_helper.utils.log import ASH_LOGGER

#: The name every such directory starts with.
TOOL_CONFIG_DIR_PREFIX = "ash-tool-config-"

_CREATE_FLAGS = (
    os.O_WRONLY
    | os.O_CREAT
    | os.O_EXCL
    | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_BINARY", 0)
)


class _ToolConfigDir:
    """One scanner run's directory, made when the run writes its first file."""

    def __init__(self, context: Any) -> None:
        config = getattr(context, "config", None)
        source_dir = getattr(context, "source_dir", None)
        output_dir = getattr(context, "output_dir", None)
        root = getattr(config, "_scanned_root", None) or source_dir
        self.scan_root: Optional[Path] = Path(root) if root is not None else None
        self.output_dir: Optional[Path] = (
            Path(os.path.abspath(output_dir)) if output_dir is not None else None
        )
        self.path: Optional[Path] = None
        self._lock = threading.Lock()

    def directory(self) -> Path:
        with self._lock:
            if self.path is None:
                self.path = _new_directory(self.scan_root, self.output_dir)
            return self.path

    def remove(self) -> None:
        with self._lock:
            path, self.path = self.path, None
        if path is None:
            return
        try:
            shutil.rmtree(path)
        except FileNotFoundError:
            pass
        except OSError as e:
            ASH_LOGGER.warning(
                f"Could not remove {path.as_posix()}, which holds the config files "
                f"ASH wrote for a scanner: {e}"
            )


_ACTIVE: contextvars.ContextVar[Optional[_ToolConfigDir]] = contextvars.ContextVar(
    "ash_tool_config_dir", default=None
)

_unscoped_lock = threading.Lock()
_unscoped: List[_ToolConfigDir] = []
_unscoped_cleanup_registered = False


def _remove_unscoped() -> None:
    with _unscoped_lock:
        pending = list(_unscoped)
        _unscoped.clear()
    for holder in pending:
        holder.remove()


def _inside_tree(path: Path, scan_root: Optional[Path]) -> bool:
    # Imported here: path_trust reaches the config models, which import the
    # scanners that use this module.
    from automated_security_helper.config.path_trust import in_scanned_tree

    return scan_root is not None and in_scanned_tree(path, scan_root)


def _changeable_by_others(resolved: Path) -> Optional[str]:
    """Why another local account could change what ``resolved`` names, or None.

    ``resolved`` is a path the caller already resolved (``os.path.realpath``) and
    will use as it is: the check does not resolve it again, so what it walks is
    what the caller goes on to use, and a link re-pointed between a second
    resolution and the use cannot send the use somewhere the check never saw.

    Every directory from ``resolved`` up to ``/`` is checked. One
    that another account owns (root aside), or that its group or everyone can write
    without the sticky bit, lets someone else rename an entry in it, and so put a
    directory of their own where ASH made one, after the ``mkdtemp`` and before the
    files are written or the tool reads them. ``O_NOFOLLOW`` protects only the last
    component of a path. A sticky directory such as ``/tmp`` is fine: only an
    entry's owner may rename it there. POSIX only; Windows has no such modes.
    """
    if not hasattr(os, "geteuid"):
        return None
    me = os.geteuid()
    for directory in (resolved, *resolved.parents):
        try:
            st = os.stat(directory)
        except OSError as e:
            return f"{directory.as_posix()} cannot be checked ({e.strerror})"
        if st.st_uid not in (0, me):
            return f"{directory.as_posix()} belongs to another account"
        shared = st.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        if shared and not st.st_mode & stat.S_ISVTX:
            return (
                f"{directory.as_posix()} can be written by other accounts and does "
                "not have the sticky bit"
            )
    return None


def _make(parent: Path) -> Tuple[Optional[Path], Optional[str]]:
    """A new 0700 directory under ``parent``, or the reason none could be made.

    The reason is kept, not dropped: a full disk, a read-only file system or a
    permission error on a candidate used to leave the warning and the final
    error naming only the privacy reasons of the other candidates, so the
    operator was told to fix TMPDIR's permissions when the cause was elsewhere.
    """
    try:
        return Path(tempfile.mkdtemp(prefix=TOOL_CONFIG_DIR_PREFIX, dir=parent)), None
    except OSError as e:
        detail = e.strerror or str(e)
        return None, f"{parent.as_posix()}: a directory could not be made ({detail})"


def _new_directory(scan_root: Optional[Path], output_dir: Optional[Path]) -> Path:
    """A new 0700 directory on a path only this account can change.

    Outside the scanned tree where possible: the temporary directory, then the
    output directory. Then, with a warning, inside it: the same two in that order.
    A candidate that another account could change (:func:`_changeable_by_others`)
    is never used, and with no other candidate nothing is written. Every
    candidate passed over is named with its reason in the warning or the error,
    one that does not exist yet and one no directory could be made in included.
    """
    candidates: List[Path] = []
    passed_over: List[str] = []
    try:
        candidates.append(Path(tempfile.gettempdir()))
    except OSError as e:
        # tempfile raises FileNotFoundError when no candidate it tries is usable.
        passed_over.append(f"the temporary directory: {e}")
    if output_dir is not None:
        if output_dir.is_dir():
            candidates.append(output_dir)
        else:
            passed_over.append(f"{output_dir.as_posix()}: is not a directory yet")
    private: List[Path] = []
    for parent in candidates:
        # Resolved once. The check walks this path and the directory is made and
        # written under this same path, so a symbolic link in the path as given
        # (TMPDIR, or the output directory) is never resolved a second time, by
        # a path the check did not see.
        resolved = Path(os.path.realpath(parent))
        reason = _changeable_by_others(resolved)
        if reason is None:
            private.append(resolved)
        else:
            passed_over.append(f"{parent.as_posix()}: {reason}")
    inside: List[Path] = []
    for parent in private:
        if _inside_tree(parent, scan_root):
            passed_over.append(f"{parent.as_posix()}: inside the scanned tree")
            inside.append(parent)
            continue
        made, reason = _make(parent)
        if made is None:
            passed_over.append(cast(str, reason))
            continue
        if not _inside_tree(made, scan_root):
            return made
        os.rmdir(made)
        passed_over.append(f"{made.as_posix()}: inside the scanned tree")
        inside.append(parent)
    # Only the candidates that ARE inside the tree are tried here: one outside
    # it that no directory could be made in has its reason recorded above, and
    # a directory made in it would not be "inside the scanned tree".
    for parent in inside:
        made, reason = _make(parent)
        if made is not None:
            ASH_LOGGER.warning(
                f"The config files ASH writes for the scanner's tool are in "
                f"{made.as_posix()}, inside the scanned tree, because no private "
                f"directory outside it is available ({'; '.join(passed_over)})."
            )
            return made
        passed_over.append(cast(str, reason))
    raise OSError(
        "No private directory for the config files ASH writes for the scanner's "
        f"tool ({'; '.join(passed_over)}). Set TMPDIR to a directory only this "
        "account can write."
    )


@contextmanager
def tool_config_scope(context: Any) -> Iterator[None]:
    """One scanner run: files written during it share a directory, removed at the end.

    Args:
        context: The run's PluginContext. Its source directory (or the wider root
            ``AshConfig._scanned_root`` records) is the tree the directory must be
            outside, and its output directory the second place one is made.
    """
    holder = _ToolConfigDir(context)
    reset = _ACTIVE.set(holder)
    try:
        yield
    finally:
        _ACTIVE.reset(reset)
        holder.remove()


def active_tool_config_dir() -> Optional[Path]:
    """The directory of the scanner run in progress, if it has written a file."""
    holder = _ACTIVE.get()
    return holder.path if holder is not None else None


def _run_directory(name: str, context: Any) -> Path:
    """The directory of the run in progress, made if needed, for an entry ``name``.

    Outside a scope, a directory of its own, outside ``context``'s scanned tree and
    removed when the process exits.
    """
    if Path(name).name != name or name in ("", ".", ".."):
        raise ValueError(f"not a file name: {name!r}")
    global _unscoped_cleanup_registered
    holder = _ACTIVE.get()
    if holder is None:
        holder = _ToolConfigDir(context)
        with _unscoped_lock:
            if not _unscoped_cleanup_registered:
                atexit.register(_remove_unscoped)
                _unscoped_cleanup_registered = True
            _unscoped.append(holder)
    return holder.directory()


def write_tool_config(
    name: str, content: str, *, context: Any = None, errors: str = "strict"
) -> Path:
    """Write ``content`` as ``name`` in the run's directory and return its path.

    The file is created, never opened as an existing one, and a link at its name is
    not followed. A second file of the same name in one run gets a new
    subdirectory, so each caller gets the content it wrote.

    Args:
        name: The file's name, which the tool may read its format from
            (``grype-empty.yaml``).
        content: What the file holds.
        context: The scanner's PluginContext, for a run outside a scope: the file
            then gets a directory of its own, outside that context's scanned tree,
            removed when the process exits.
        errors: How ``content`` is encoded to UTF-8, as for ``open``.
            ``surrogateescape`` writes back the bytes of a file that was read
            with it (cfn-guard's copies of the operator's rules).
    """
    directory = _run_directory(name, context)
    path = directory / name
    try:
        fd = os.open(path, _CREATE_FLAGS, 0o600)
    except FileExistsError:
        path = Path(tempfile.mkdtemp(dir=directory)) / name
        fd = os.open(path, _CREATE_FLAGS, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8", errors=errors, newline="") as handle:
        handle.write(content)
    return path


def make_tool_config_directory(name: str, *, context: Any = None) -> Path:
    """Make an empty directory ``name`` in the run's directory and return its path.

    For a tool that reads whatever a directory it is given holds (trivy's
    ``--module-dir``, gitleaks' ``--gitleaks-ignore-path``). The directory is
    created, never an existing one reused, so it is empty, and a second one of
    the same name in one run gets a new subdirectory, as a file does in
    :func:`write_tool_config`.

    Args:
        name: The directory's name (``trivy-modules``).
        context: The scanner's PluginContext, for a run outside a scope, as for
            :func:`write_tool_config`.
    """
    directory = _run_directory(name, context)
    path = directory / name
    try:
        os.mkdir(path, 0o700)
    except FileExistsError:
        path = Path(tempfile.mkdtemp(dir=directory)) / name
        os.mkdir(path, 0o700)
    return path
