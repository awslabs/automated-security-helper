# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Keeping the previous scan's results until a new scan has its own.

Why this exists
---------------
A scan writes its results into a fixed set of entries of its output directory
(``RESULT_ENTRIES``). ``ASHScanOrchestrator.initialize`` deletes all of them when
a scan starts. An MCP scan that then failed or was cancelled left the directory
with the previous complete results gone and none of its own: observed live, a
scan cancelled right after it started emptied the previous scan's ``reports/``.

So for an MCP scan (``keep_previous_results``) the previous results are set aside
instead (:meth:`PreviousResults.set_aside`), into
``<output dir>/.ash_previous_results``, and the new scan writes where it always
has. The CLI does not keep them: nothing but the MCP server reads the marker
described below, so for anything else that reads the directory (a CI publish
step, the container and Nix wrappers' read-back) put-back results would pass for
the scan that just failed. A CLI scan deletes them, and what a kept set left,
when it starts. When it finishes its phases they are dropped
(:meth:`PreviousResults.discard`); when it ends any other way they are put back
(:meth:`PreviousResults.restore`) and the results the new scan had written are
removed; its logs, which are not among ``RESULT_ENTRIES``, stay. Moving rather
than copying keeps both cheap, and the new scan's paths and the paths inside its
reports stay what they were.

After a restore the directory holds the results of an earlier scan than the one
that ran last, and a reader that goes by the directory alone would take them for
that scan's. So a restore also leaves a marker file (``RESTORED_MARKER_NAME``)
saying so, which the next scan removes when it starts; the MCP server's progress
reports read it (:func:`holds_restored_results`) and do not present the restored
files as the failed scan's. A scan with no previous results to set aside leaves
whatever it wrote before it failed, and no marker: that output is its own.

A process killed while a scan runs cannot restore anything. The held results
then stay in ``.ash_previous_results``, and the next scan in that directory
treats them as the last complete set: it removes what the killed scan left at the
top level and keeps the held set as its own previous results.

Each of the two moves is a few renames, and a rename can be refused. A set aside
moves the entries into a staging directory (``STAGING_DIR_NAME``) and then renames
that to the held set. One that stops on anything, a refused rename, an interrupt
or any other error, puts back what it had already staged, then raises. One whose
process is killed between two renames leaves part of the set staged, and the next
set aside puts that back before it moves anything, so the set it holds is whole.
A restore first renames the held set to ``.ash_previous_results.restoring``, then
moves the entries back from there, so a restore that stopped halfway, refused or
killed, is resumed by the next restore or the next scan's set aside, and the
marker is written only once everything is back.

Nothing is moved or removed when the output directory is itself a link.

Everything is moved and removed without following links, so an entry a scanned
repository planted as a symlink is moved or removed as a link, never through it.
"""

from __future__ import annotations

import os
import shutil
import threading
from pathlib import Path
from typing import Iterator

from automated_security_helper.core.committed_output import PREVIOUS_RUN_FILE_NAMES
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.scan_output_dirs import WORKING_DIR_NAMES

#: What a scan writes at the top of its output directory and replaces on the next
#: scan: the working directories and the files beside them, the same names the
#: orchestrator and the host side of container and Nix mode clear. Among the files
#: is the record of the run that wrote the scan-set lists (utils/get_scan_set),
#: moved with them so that lists put back are never read as a later run's. The
#: logs (``ash.log``, ``ash.log.jsonl``) are not here: the logger truncates them
#: itself when it opens them.
RESULT_ENTRIES = (*WORKING_DIR_NAMES, *PREVIOUS_RUN_FILE_NAMES)

#: Where the previous results wait while a scan runs.
HELD_DIR_NAME = ".ash_previous_results"

#: The held set while a restore moves it back, so that a restore stopped halfway
#: (a refused rename) is resumed rather than started over.
RESTORING_DIR_NAME = HELD_DIR_NAME + ".restoring"

#: Where a set aside moves the entries before it renames them to the held set.
STAGING_DIR_NAME = HELD_DIR_NAME + ".partial"

#: Left beside the results a restore put back. Its text is for a person reading
#: the directory; code checks only that it exists.
RESTORED_MARKER_NAME = ".ash_previous_results_restored"

_RESTORED_MARKER_TEXT = (
    "The last scan in this directory ended without results, so ASH put back the "
    "results of the scan before it. The next scan here removes this file.\n"
)


def _exists(path: Path) -> bool:
    """Whether anything is at path, a link included, without following it."""
    return os.path.lexists(path)


def _remove(path: Path) -> None:
    """Remove a file, a link or a directory tree, never following a link."""
    if path.is_symlink() or not path.is_dir():
        path.unlink(missing_ok=True)
    else:
        shutil.rmtree(path)


def holds_restored_results(output_dir: Path) -> bool:
    """Whether the results in output_dir were put back after a scan that failed.

    True from the restore until the next scan starts in that directory. While it
    is true, the files there are the results of a scan before the last one.
    """
    return _exists(Path(output_dir) / RESTORED_MARKER_NAME)


class PreviousResults:
    """The previous scan's results in one output directory, while a scan runs."""

    def __init__(self, output_dir: Path) -> None:
        self.output_dir = Path(output_dir)
        self.held = self.output_dir / HELD_DIR_NAME
        self.restoring = self.output_dir / RESTORING_DIR_NAME
        self.marker = self.output_dir / RESTORED_MARKER_NAME

    def _output_dir_is_a_link(self) -> bool:
        """An output directory that is itself a link was not made by a scan.

        Moving into or out of it would move entries wherever the link points, and
        a scanned repository controls what sits in its own output tree (a
        workspace project's output is ``projects/<key>`` under it). Nothing is
        moved or removed through it.
        """
        if self.output_dir.is_symlink():
            ASH_LOGGER.warning(
                f"{self.output_dir} is a link; leaving the previous results there "
                "untouched"
            )
            return True
        return False

    @staticmethod
    def _real_dir(path: Path) -> bool:
        """Whether path is a directory made here. A link or a file in its place
        was not made here; it is removed, never followed."""
        if path.is_symlink() or (path.exists() and not path.is_dir()):
            _remove(path)
            return False
        return path.is_dir()

    def _holding(self) -> bool:
        """Whether a held set exists."""
        return self._real_dir(self.held)

    def _top_level(self) -> Iterator[Path]:
        for name in RESULT_ENTRIES:
            path = self.output_dir / name
            if _exists(path):
                yield path

    def set_aside(self) -> None:
        """Move the previous results out of the new scan's way.

        If results are already held, an earlier scan in this directory ended
        without discarding or restoring them (its process was killed). Those are
        the last complete results, so they stay held and what that scan left at
        the top level is removed. A restore that stopped halfway is finished
        first, so that what is set aside is the whole previous set.

        The entries are moved into a staging directory, which is then renamed to
        the held set. A move stopped by anything, a refused rename (OSError), an
        interrupt or any other error, puts back what was already staged before it
        raises, so the previous results are where they were and the next call
        starts over. What a staging directory still holds when a call starts, left
        by a process killed in the middle of the moves or by a put-back that was
        itself refused, is part of the previous results: it is put back first, and
        a move of it that is refused raises with the rest still staged.
        """
        if not self.output_dir.is_dir() or self._output_dir_is_a_link():
            return
        if self._real_dir(self.restoring):
            self._finish_restore()
        # A scan is starting: whatever happens next, the directory no longer holds
        # results put back after the last one.
        if _exists(self.marker):
            _remove(self.marker)
        staging = self.output_dir / STAGING_DIR_NAME
        if self._real_dir(staging):
            self._put_back(staging)
        if self._holding():
            leftovers = list(self._top_level())
            if leftovers:
                ASH_LOGGER.info(
                    f"{self.held} holds the results of the last scan that finished in "
                    "this directory; removing what an interrupted scan left beside it"
                )
            for path in leftovers:
                _remove(path)
            return
        entries = list(self._top_level())
        if not entries:
            return
        staging.mkdir()
        try:
            for path in entries:
                path.rename(staging / path.name)
            staging.rename(self.held)
        except BaseException:
            # Whatever stopped the moves, an interrupt included: the previous
            # results go back where they were before it reaches the caller.
            self._unstage(staging)
            raise
        ASH_LOGGER.debug(f"Set the previous results aside in {self.held}")

    def _put_back(self, staging: Path) -> None:
        """Move what staging holds back to the top level, then remove staging.

        Only result entries, each moved as it is, a link as a link, and none over
        an entry already at the top level: a set aside stages only result entries
        and only ones it moved from there, so anything else in staging was not
        put there by one, and it goes with the staging directory. A move that is
        refused raises (OSError) with the rest still staged.
        """
        for path in list(staging.iterdir()):
            target = self.output_dir / path.name
            if path.name in RESULT_ENTRIES and not _exists(target):
                path.rename(target)
        _remove(staging)

    def _unstage(self, staging: Path) -> None:
        """Move what a failed set_aside had staged back to the top level.

        Raises nothing for a refused move: it runs on the way out of the error
        that stopped the set_aside, which is the one the caller gets. What it
        could not move stays staged, and the next set_aside puts it back first.
        """
        if not _exists(staging):
            # Stopped after the rename to the held set: nothing is staged.
            return
        try:
            self._put_back(staging)
        except OSError as e:
            ASH_LOGGER.error(
                f"Could not move the previous results staged in {staging} back to "
                f"{self.output_dir}: {e}"
            )

    def discard(self) -> None:
        """The new scan has its results: drop the previous ones."""
        if self._output_dir_is_a_link():
            return
        for path in (self.held, self.restoring):
            if _exists(path):
                _remove(path)
        _remove(self.output_dir / STAGING_DIR_NAME)
        if _exists(self.marker):
            _remove(self.marker)

    def restore(self) -> None:
        """The new scan ended without results: put the previous ones back.

        Whatever the new scan wrote among RESULT_ENTRIES is removed first, and the
        marker is left beside what was put back. With nothing held (no previous
        results, or already discarded or restored) this does nothing, so it is
        safe on every path that ends a scan.

        Resumable. Once the top level is clear the held set is renamed to
        RESTORING_DIR_NAME, and the entries are moved back from there. A move
        that is refused (OSError) raises with the rest still in it, and the next
        restore moves those without clearing the top level again: what is there
        by then is previous results it already put back. The marker is written
        only once every entry is back.
        """
        if self._output_dir_is_a_link():
            return
        if not self._real_dir(self.restoring):
            if not self._holding():
                return
            for path in list(self._top_level()):
                _remove(path)
            self.held.rename(self.restoring)
        self._finish_restore()

    def _finish_restore(self) -> None:
        """Move what RESTORING_DIR_NAME still holds back, then mark the restore."""
        for path in list(self.restoring.iterdir()):
            path.rename(self.output_dir / path.name)
        self.restoring.rmdir()
        self._mark_restored()
        ASH_LOGGER.info(
            f"The scan did not finish; restored the previous results in {self.output_dir}"
        )

    def _mark_restored(self) -> None:
        if _exists(self.marker):
            _remove(self.marker)
        # O_EXCL and O_NOFOLLOW: created here, never written through a link.
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(self.marker, flags, 0o644)
        with os.fdopen(fd, "w", encoding="utf-8") as marker:
            marker.write(_RESTORED_MARKER_TEXT)


class SettleHandoff:
    """Who settles the previous results of a scan that runs on a worker thread.

    The MCP server runs a scan on an executor thread and awaits it from a task.
    The thread is the one that must drop or restore the previous results: when the
    task is cancelled the thread runs on until the scan stops, and a restore from
    the task would race the scan's writes. But a task cancelled while the job is
    still queued makes the executor drop it, and then the thread never runs and
    only the task can restore them. This settles which of the two it is, once:
    the thread calls :meth:`thread_starts` before anything else, and the task
    calls :meth:`task_abandons` on every path that does not get the thread's
    result.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._started = False
        self._abandoned = False

    def thread_starts(self) -> bool:
        """On the thread. False if the task gave up first: do nothing then."""
        with self._lock:
            if self._abandoned:
                return False
            self._started = True
            return True

    def task_abandons(self) -> bool:
        """On the task. True if the thread never started, so the task settles."""
        with self._lock:
            self._abandoned = True
            return not self._started
