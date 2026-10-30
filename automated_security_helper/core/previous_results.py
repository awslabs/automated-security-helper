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
killed, is resumed by the next restore or the next scan's set aside. The marker
is written right after that rename, before the first entry moves back, so from
the moment any put-back entry is at the top level the directory says so; a
restore refused before the rename leaves no marker, because nothing was put back.

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

#: Where a discard moves the held set before it deletes it, so a delete that
#: stops partway (a refused unlink) never leaves a half-deleted set at
#: HELD_DIR_NAME for the next set aside to take for the last complete results
#: and use to remove that scan's newer output. The next set aside or discard
#: removes a leftover.
DISCARDING_DIR_NAME = HELD_DIR_NAME + ".discarding"

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
        # A discard that stopped partway left its half-deleted set: finished here.
        self._remove_discarding_leftover()
        if self._real_dir(self.restoring):
            # A restore stopped halfway, or a directory of that name that outlived
            # a completed scan (its discard failed) or that a scanned repository
            # planted. Nothing it holds is newer than what is at the top level, so
            # an entry already there stays, and only result entries move; anything
            # else in it goes with the directory.
            self._finish_restore(replace_existing=False, mark=False)
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
            self._remove_marker()
            return
        entries = list(self._top_level())
        if not entries:
            self._remove_marker()
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
        # The marker goes only once the moves are done: a set aside that raised
        # leaves put-back results at the top level, and removing the marker
        # before the renames left them there as if they were the next scan's.
        self._remove_marker()
        ASH_LOGGER.debug(f"Set the previous results aside in {self.held}")

    def _remove_marker(self) -> None:
        """A scan is starting, or is set up to: the directory no longer holds
        results put back after the last one."""
        if _exists(self.marker):
            _remove(self.marker)

    def forget_restored_marker(self) -> None:
        """Drop the restore marker without moving anything. Never raises.

        For a set aside that FAILED while the scan goes on: the orchestrator then
        removes the previous results at the top level and this scan writes its
        own there, so the marker, which says those files were put back after a
        failed scan, would misreport this scan's output. A set aside that
        completes removes the marker itself, once its moves are done.
        """
        try:
            self._remove_marker()
        except OSError as e:
            ASH_LOGGER.warning(
                f"Could not remove the restore marker {self.marker}: {e}; a reader "
                "of holds_restored_results may take this scan's results for put-back "
                "ones until the next scan removes it"
            )

    def _remove_discarding_leftover(self) -> None:
        """Remove the half-deleted set a discard that stopped partway left.

        Best effort: a refusal (a permission, a lock another process holds on a
        file in it) is logged and the caller goes on. Raising here made every
        later set aside and discard in the directory fail on the same leftover,
        which turned keep-previous-results off for that directory for good; the
        leftover's name is never taken for the held set, so leaving it costs
        only the space it holds.
        """
        try:
            _remove(self.output_dir / DISCARDING_DIR_NAME)
        except OSError as e:
            ASH_LOGGER.warning(
                f"Could not remove {self.output_dir / DISCARDING_DIR_NAME}, left by a "
                f"discard that stopped partway: {e}; it is left in place"
            )

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
        """The new scan has its results: drop the previous ones.

        The held set is renamed to DISCARDING_DIR_NAME before it is deleted, so a
        delete that stops partway (a refused unlink raises out of here) leaves no
        half-deleted set at HELD_DIR_NAME: the next set aside took one for the
        last complete results and used it to remove that scan's newer output.
        """
        if self._output_dir_is_a_link():
            return
        discarding = self.output_dir / DISCARDING_DIR_NAME
        self._remove_discarding_leftover()
        if self._real_dir(self.held):
            try:
                self.held.rename(discarding)
            except OSError:
                # Deleted in place then; the rename is a precaution, not the
                # discard itself.
                pass
        # The held set before the leftover: when the rename above was refused
        # because the leftover is still there, the held set is deleted in place
        # first, so a leftover that cannot be removed does not shield it (the
        # next set aside would take it for the last complete results).
        for path in (self.held, self.restoring, discarding):
            if _exists(path):
                _remove(path)
        _remove(self.output_dir / STAGING_DIR_NAME)
        self._remove_marker()

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
        right after the rename, before the first move, so a restore that stops
        on a refused move already says the top level holds put-back results; a
        restore refused before the rename leaves no marker.
        """
        if self._output_dir_is_a_link():
            return
        if self._real_dir(self.restoring):
            if _exists(self.marker):
                # A restore stopped halfway after it wrote the marker: what is at
                # the top level is previous results it already put back, so it is
                # kept, and the rest is moved.
                self._finish_restore(replace_existing=False, mark=True)
                return
            # A RESTORING_DIR_NAME with no marker is not a restore of this
            # directory's last state that this code left: a restore killed before
            # its marker, or a directory a later scan ran beside. What is at the
            # top level is not put-back results, so it is cleared as for a fresh
            # restore; moving the held entries over it mixed two scans' output.
            for path in list(self._top_level()):
                _remove(path)
            self._mark_restored()
            self._finish_restore(replace_existing=True, mark=True)
            return
        if not self._holding():
            return
        for path in list(self._top_level()):
            _remove(path)
        self.held.rename(self.restoring)
        # The marker before the moves, not after the last one: a restore that
        # stops on a refused rename leaves previous results at the top level, and
        # holds_restored_results has to say so from that moment. A resumed restore
        # reads it (above), and the next scan's set aside removes it.
        self._mark_restored()
        self._finish_restore(replace_existing=True, mark=True)

    def _finish_restore(self, *, replace_existing: bool, mark: bool) -> None:
        """Move what RESTORING_DIR_NAME still holds back, then remove it.

        Only result entries move: a directory of that name a scanned repository
        planted, or a leftover an earlier run left, can hold any name, and every
        entry of it used to be renamed to the top level. An entry already at the
        top level is replaced when *replace_existing* (a fresh restore, whose
        top level was just cleared) and left in place otherwise (a resumed
        restore, or a set aside finishing a leftover: what is there is newer or
        already put back). With *mark* the restore is marked and logged.
        """
        for path in list(self.restoring.iterdir()):
            target = self.output_dir / path.name
            if path.name not in RESULT_ENTRIES:
                _remove(path)
                continue
            if _exists(target):
                if not replace_existing:
                    _remove(path)
                    continue
                _remove(target)
            path.rename(target)
        if mark:
            # Before the directory goes, and only when there is no marker: every
            # caller that marks has written one already (restore() writes it
            # before the first move), and writing it again removed the marker
            # first, so a write that failed left put-back results with neither a
            # marker nor a restoring directory for a later call to finish from.
            if not _exists(self.marker):
                self._mark_restored()
        self.restoring.rmdir()
        if mark:
            ASH_LOGGER.info(
                f"The scan did not finish; restored the previous results in "
                f"{self.output_dir}"
            )

    def _mark_restored(self) -> None:
        if _exists(self.marker):
            _remove(self.marker)
        # Not at the top: fs_guard imports the sandbox package.
        from automated_security_helper.utils.sandbox.fs_guard import open_for_write

        # Exclusive and not followed: created here, never written through a link.
        with open_for_write(self.marker, mode=0o644, exclusive=True) as marker:
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
