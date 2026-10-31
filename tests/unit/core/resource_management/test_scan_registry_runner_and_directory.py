# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The registry's directory comparison and its handling of a stopping runner.

Five mechanisms, each pinned against the behavior it replaced:

* ``_canonical_directory`` caught OSError only. ``Path.resolve`` raises
  RuntimeError for a symlink loop on Python 3.10 to 3.12, and the comparison ran
  over every entry at each registration, so one historical entry whose directory
  had since become a loop made every later ``register_scan`` raise.
* The directory an entry occupies was re-resolved from its raw string at every
  lookup, so a symlink retargeted after the scan started moved the entry to the
  link's new target: a second scan of the real directory was admitted and an
  unrelated directory was refused.
* ``cleanup_scan`` deleted an entry whose runner was still stopping, which let
  ``register_scan`` admit a second scan of the directory into the window the
  runner still writes in.
* ``check_scan_progress`` of an ended scan read the output directory, which a
  later scan of the same directory now writes, and reported that scan's files
  as the old scan's.
* The coverage re-assessment of a finished entry closed without coverage ran
  with no guard on every poll, so a results set that made it raise failed every
  progress call for that scan from then on.
"""

import json
import os
import threading
import time
from datetime import timedelta
from pathlib import Path
from unittest.mock import patch

import pytest

from automated_security_helper.core.resource_management import scan_registry
from automated_security_helper.core.resource_management.exceptions import (
    MCPResourceError,
)
from automated_security_helper.core.resource_management.scan_registry import (
    MCScanStatus,
    ScanRegistry,
    _canonical_directory,
)

pytestmark = pytest.mark.unit

_MODULE = "automated_security_helper.core.resource_management.scan_registry"


def _register(registry, directory, output=None, **options):
    output = output if output is not None else directory / ".ash" / "ash_output"
    return registry.register_scan(
        directory_path=str(directory), output_directory=str(output), **options
    )


def _symlink_or_skip(link, target):
    """Make ``link`` point at ``target``, or skip where links cannot be made.

    ``hasattr(os, "symlink")`` is true on Windows, where creating one still
    fails without the privilege (OSError, winerror 1314); a platform limit is
    a skip, not a failure of the behavior under test.
    """
    if not hasattr(os, "symlink"):
        pytest.skip("symlinks are not available on this platform")
    try:
        link.symlink_to(target)
    except (OSError, NotImplementedError) as e:
        pytest.skip(f"this platform refuses to create a symlink: {e}")


def _results_document(scanner_name):
    return {
        "metadata": {"generated_at": "2024-01-01T00:00:00", "summary_stats": {}},
        "scanner_results": {
            scanner_name: {
                "status": "PASSED",
                "finding_count": 1,
                "severity_counts": {"high": 1},
            }
        },
    }


class TestCanonicalDirectorySurvivesAnUnresolvablePath:
    def test_a_symlink_loop_falls_back_to_the_raw_path(self, tmp_path):
        if not hasattr(os, "symlink"):
            pytest.skip("symlinks are not available on this platform")
        loop = tmp_path / "loop"
        try:
            loop.symlink_to(loop)
        except (OSError, NotImplementedError):
            pytest.skip("this platform refuses a self-referencing link")

        # Python 3.10-3.12 raise RuntimeError here; 3.13 resolves as far as it
        # can without raising. Neither may escape, and the path keeps its name.
        assert _canonical_directory(str(loop)).name == "loop"

    def test_a_nul_byte_falls_back_to_the_raw_path(self, tmp_path):
        bad = str(tmp_path / "pro\x00j")

        assert str(_canonical_directory(bad)) == bad

    def test_a_refused_resolve_falls_back_on_every_python(self, tmp_path):
        """The loop test above reaches the fallback only on the Pythons whose
        resolve() raises for a loop; here the refusal is forced, so the
        fallback itself is measured on every interpreter, and so is what the
        lookups make of a directory the registry cannot resolve any more."""
        if not hasattr(os, "symlink"):
            pytest.skip("symlinks are not available on this platform")
        registry = ScanRegistry()
        target = tmp_path / "target"
        target.mkdir()
        link = tmp_path / "link"
        _symlink_or_skip(link, target)
        scan_id = _register(registry, link)
        registry.update_scan_status(scan_id, MCScanStatus.RUNNING)

        # The directory of the running scan becomes a loop after registration.
        link.unlink()
        try:
            link.symlink_to(link)
        except (OSError, NotImplementedError):
            pytest.skip("this platform refuses a self-referencing link")

        with patch("pathlib.Path.resolve", side_effect=RuntimeError("loop")):
            # The fallback: the raw path, no exception.
            assert _canonical_directory(str(link)) == Path(str(link))
            # The lookups take the same fallback and compare the raw
            # path with the entry's resolved one: no match, no exception. The
            # scan is still found by the directory it was registered as.
            assert registry.get_scan_by_directory(str(link)) is None
            assert (
                registry.scan_writing_output(str(link / ".ash" / "ash_output")) is None
            )
        assert registry.get_scan_by_directory(str(target)).scan_id == scan_id
        assert (
            registry.scan_writing_output(str(target / ".ash" / "ash_output")) == scan_id
        )

    def test_one_looping_historical_entry_does_not_break_registration(self, tmp_path):
        """The high finding end to end: register, retarget, register again."""
        if not hasattr(os, "symlink"):
            pytest.skip("symlinks are not available on this platform")
        registry = ScanRegistry()
        target = tmp_path / "target"
        target.mkdir()
        link = tmp_path / "link"
        _symlink_or_skip(link, target)
        first = _register(registry, link)
        registry.update_scan_status(first, MCScanStatus.COMPLETED)

        # The directory of the historical entry becomes a loop.
        link.unlink()
        try:
            link.symlink_to(link)
        except (OSError, NotImplementedError):
            pytest.skip("this platform refuses a self-referencing link")
        other = tmp_path / "other"
        other.mkdir()

        second = _register(registry, other)

        assert second != first
        assert registry.get_scan_count() == 2


class TestDirectoryOccupancyIsFixedAtRegistration:
    def test_a_retargeted_link_does_not_move_the_scan(self, tmp_path):
        if not hasattr(os, "symlink"):
            pytest.skip("symlinks are not available on this platform")
        registry = ScanRegistry()
        real = tmp_path / "real"
        real.mkdir()
        unrelated = tmp_path / "unrelated"
        unrelated.mkdir()
        link = tmp_path / "link"
        _symlink_or_skip(link, real)
        first = _register(registry, link)

        # After the scan started, the link is pointed somewhere else.
        link.unlink()
        _symlink_or_skip(link, unrelated)

        # The real directory is still being scanned: a second scan is refused.
        with pytest.raises(MCPResourceError) as excinfo:
            _register(registry, real)
        assert "already has an active scan" in str(excinfo.value)
        assert excinfo.value.context["scan_id"] == first

        # The unrelated directory the link now names is not: it registers.
        second = _register(registry, unrelated)
        assert second != first

    def test_the_lookup_by_directory_follows_the_registered_target(self, tmp_path):
        if not hasattr(os, "symlink"):
            pytest.skip("symlinks are not available on this platform")
        registry = ScanRegistry()
        real = tmp_path / "real"
        real.mkdir()
        elsewhere = tmp_path / "elsewhere"
        elsewhere.mkdir()
        link = tmp_path / "link"
        _symlink_or_skip(link, real)
        first = _register(registry, link)
        link.unlink()
        _symlink_or_skip(link, elsewhere)

        assert registry.get_scan_by_directory(str(real)).scan_id == first
        assert registry.get_scan_by_directory(str(elsewhere)) is None


class TestCleanupKeepsAStoppingRunner:
    def test_a_cancelled_scan_whose_runner_runs_is_kept(self, tmp_path):
        registry = ScanRegistry()
        project = tmp_path / "proj"
        project.mkdir()
        scan_id = _register(registry, project)
        entry = registry.get_scan(scan_id)
        entry.has_runner = True
        registry.update_scan_status(scan_id, MCScanStatus.RUNNING)
        registry.cancel_scan(scan_id)

        assert registry.cleanup_scan(scan_id) is False
        assert registry.get_scan(scan_id) is entry
        # And so a second scan of the directory is still refused.
        with pytest.raises(MCPResourceError) as excinfo:
            _register(registry, project)
        assert "still stopping" in str(excinfo.value)

        entry.runner_done.set()

        assert registry.cleanup_scan(scan_id) is True
        assert registry.get_scan(scan_id) is None

    def test_a_scan_without_a_runner_is_removed_as_before(self, tmp_path):
        registry = ScanRegistry()
        project = tmp_path / "proj"
        project.mkdir()
        scan_id = _register(registry, project)

        assert registry.cleanup_scan(scan_id) is True

    def test_cleanup_completed_scans_keeps_a_stopping_runner(self, tmp_path):
        registry = ScanRegistry()
        project = tmp_path / "proj"
        project.mkdir()
        scan_id = _register(registry, project)
        entry = registry.get_scan(scan_id)
        entry.has_runner = True
        registry.update_scan_status(scan_id, MCScanStatus.CANCELLED)
        entry.end_time = entry.end_time - timedelta(days=2)

        assert registry.cleanup_completed_scans(max_age_hours=1) == 0
        entry.runner_done.set()
        assert registry.cleanup_completed_scans(max_age_hours=1) == 1

    def test_the_lookup_by_output_tree_names_the_occupying_scan(self, tmp_path):
        registry = ScanRegistry()
        project = tmp_path / "proj"
        project.mkdir()
        output = project / ".ash" / "ash_output"
        first = _register(registry, project)
        registry.update_scan_status(first, MCScanStatus.COMPLETED)
        second = _register(registry, project)

        assert registry.scan_writing_output(str(output)) == second
        assert registry.scan_writing_output(str(output) + os.sep) == second


class TestRemovingAnOutputDirectoryAsksTheRegistry:
    """The directory-occupancy lookup counted only scans that were running or
    settling, so cleanup of an old scan removed the shared output tree while a
    later, completed scan's results sat in it, and the check ran long before the
    delete with the lock released in between. The first cure ran the delete
    under the registry lock, which held every synchronous registry caller (the
    event-loop thread's get_scan, list_scans, cancel_scan and register_scan
    among them) for as long as the tree took to remove. The delete now runs off
    the lock behind a per-entry mark: a registration of the same output tree
    waits on the mark (for a bounded time: see
    TestARegistrationWaitsForARemovalForABoundedTime), a second removal is
    refused, and nothing else waits.

    The threaded tests release their remover in ``finally``, so an assertion
    that fails leaves no thread blocked for its 10 s timeout, and they read the
    fact that the registration waited from the removal mark's own event (its
    ``wait`` is observed) rather than from a wall-clock join."""

    @staticmethod
    def _two_scans(registry, tmp_path, later_status):
        project = tmp_path / "proj"
        project.mkdir()
        old = _register(registry, project)
        registry.update_scan_status(old, MCScanStatus.COMPLETED)
        new = _register(registry, project)
        registry.update_scan_status(new, later_status)
        return old, new

    def test_a_later_completed_scans_results_are_not_removed(self, tmp_path):
        registry = ScanRegistry()
        old, _new = self._two_scans(registry, tmp_path, MCScanStatus.COMPLETED)
        ran = []

        reason, removed = registry.remove_output_of_scan(
            registry.get_scan(old), lambda: ran.append(1) or True
        )

        assert "later scan" in reason
        assert removed is False
        assert ran == []

    def test_an_occupying_scan_refuses(self, tmp_path):
        registry = ScanRegistry()
        old, _new = self._two_scans(registry, tmp_path, MCScanStatus.RUNNING)

        reason, removed = registry.remove_output_of_scan(
            registry.get_scan(old), lambda: True
        )

        assert "running or stopping" in reason
        assert removed is False

    def test_the_latest_scan_of_a_directory_removes_off_the_lock(self, tmp_path):
        registry = ScanRegistry()
        _old, new = self._two_scans(registry, tmp_path, MCScanStatus.COMPLETED)
        seen = []

        def remover():
            seen.append(registry._registry_lock.locked())
            # A registry read from the remover's own thread: it takes the lock,
            # which the delete no longer holds, and sees the removal mark.
            seen.append(registry.get_scan(new).output_removal is not None)
            return True

        reason, removed = registry.remove_output_of_scan(
            registry.get_scan(new), remover
        )

        assert reason is None
        assert removed is True
        assert seen == [False, True]
        assert registry.get_scan(new).output_removal is None

    @staticmethod
    def _removal_in_progress(registry, scan_id):
        """Start a removal of ``scan_id``'s tree whose remover blocks until
        ``release`` is set; returns (thread, release) once the remover runs.
        Every caller sets ``release`` in a ``finally``."""
        started, release = threading.Event(), threading.Event()

        def remover():
            started.set()
            release.wait(timeout=10)
            return True

        thread = threading.Thread(
            target=registry.remove_output_of_scan,
            args=(registry.get_scan(scan_id), remover),
        )
        thread.start()
        assert started.wait(timeout=10)
        return thread, release

    @staticmethod
    def _observed_wait(registry, scan_id):
        """An Event set when something waits on ``scan_id``'s removal mark:
        the fact that a registration waited, read from the wait itself."""
        waited = threading.Event()
        mark = registry.get_scan(scan_id).output_removal
        original_wait = mark.wait

        def wait(timeout=None):
            waited.set()
            return original_wait(timeout)

        mark.wait = wait
        return waited

    def test_a_registration_of_the_tree_waits_and_other_callers_do_not(
        self, tmp_path, monkeypatch
    ):
        registry = ScanRegistry()
        # The bound cannot fire under load: the test is about the wait, not
        # the bound (the bound has its own tests above).
        monkeypatch.setattr(scan_registry, "OUTPUT_REMOVAL_WAIT_SECONDS", 30.0)
        _old, new = self._two_scans(registry, tmp_path, MCScanStatus.COMPLETED)
        removing, release = self._removal_in_progress(registry, new)
        outcome = {}
        registering = None
        try:
            waited = self._observed_wait(registry, new)

            def register_a_third_scan():
                outcome["scan_id"] = _register(registry, tmp_path / "proj")
                # Registered only once the delete had ended and cleared its mark.
                outcome["mark_after"] = registry.get_scan(new).output_removal

            registering = threading.Thread(target=register_a_third_scan)
            registering.start()

            # The registration waits on the delete's mark; a plain registry
            # read does not wait at all.
            assert waited.wait(timeout=10)
            assert "scan_id" not in outcome
            assert registry.get_scan(new).output_removal is not None
            assert registry.get_scan_count() == 2
        finally:
            release.set()
            removing.join(timeout=10)
            if registering is not None:
                registering.join(timeout=10)

        assert not registering.is_alive()
        assert registry.get_scan(outcome["scan_id"]) is not None
        assert outcome["mark_after"] is None
        assert registry.get_scan_count() == 3

    def test_a_second_removal_of_the_tree_during_one_is_refused(self, tmp_path):
        registry = ScanRegistry()
        old, new = self._two_scans(registry, tmp_path, MCScanStatus.COMPLETED)
        removing, release = self._removal_in_progress(registry, new)
        ran = []
        try:
            again = registry.remove_output_of_scan(
                registry.get_scan(new), lambda: ran.append(1) or True
            )
            the_old_one = registry.remove_output_of_scan(
                registry.get_scan(old), lambda: ran.append(1) or True
            )
        finally:
            release.set()
            removing.join(timeout=10)

        assert again == ("this scan's output directory is already being removed", False)
        assert "in progress" in the_old_one[0]
        assert the_old_one[1] is False
        assert ran == []

    def test_cleanup_keeps_an_entry_whose_output_is_being_removed(
        self, tmp_path, monkeypatch
    ):
        """The mark lives on the registry entry and register_scan's wait is
        keyed on entries in the registry. cleanup_scan and the age sweep
        dropped a marked entry (a second cleanup of the same scan during the
        first's delete, whose refused removal is a warning to its caller; a
        COMPLETED entry under removal does not occupy its directory), so a
        registration of the tree arriving after the drop found no mark and did
        not wait: the window the lock-held delete closed, re-opened."""
        registry = ScanRegistry()
        monkeypatch.setattr(scan_registry, "OUTPUT_REMOVAL_WAIT_SECONDS", 30.0)
        _old, new = self._two_scans(registry, tmp_path, MCScanStatus.COMPLETED)
        entry = registry.get_scan(new)
        entry.end_time = entry.end_time - timedelta(days=2)
        removing, release = self._removal_in_progress(registry, new)
        outcome = {}
        registering = None
        try:
            # The second cleanup of the same scan, and the age sweep, during
            # the first's delete.
            assert registry.cleanup_scan(new) is False
            assert registry.cleanup_completed_scans(max_age_hours=1) == 0
            assert registry.get_scan(new) is entry

            # So a registration of the tree arriving now still waits.
            waited = self._observed_wait(registry, new)
            registering = threading.Thread(
                target=lambda: outcome.setdefault(
                    "scan_id", _register(registry, tmp_path / "proj")
                )
            )
            registering.start()
            assert waited.wait(timeout=10)
            assert "scan_id" not in outcome
        finally:
            release.set()
            removing.join(timeout=10)
            if registering is not None:
                registering.join(timeout=10)

        assert registry.get_scan(outcome["scan_id"]) is not None
        # With the delete finished, the entry is removable again.
        assert registry.cleanup_scan(new) is True
        assert registry.get_scan(new) is None

    def test_a_remover_that_raises_clears_the_mark(self, tmp_path):
        registry = ScanRegistry()
        _old, new = self._two_scans(registry, tmp_path, MCScanStatus.COMPLETED)

        def remover():
            raise PermissionError("not ours")

        with pytest.raises(PermissionError):
            registry.remove_output_of_scan(registry.get_scan(new), remover)

        assert registry.get_scan(new).output_removal is None
        reason, removed = registry.remove_output_of_scan(
            registry.get_scan(new), lambda: True
        )
        assert (reason, removed) == (None, True)

    def test_a_registration_still_waiting_at_the_bound_is_refused(self, tmp_path):
        """The wait runs on the caller's thread, which for the MCP tools is the
        event-loop thread, so it is bounded: a removal still running at the
        bound refuses the scan with an error the client can retry on, instead
        of holding the caller, and the loop it runs on, for as long as the
        delete takes. The wait used to have no limit."""
        registry = ScanRegistry()
        _old, new = self._two_scans(registry, tmp_path, MCScanStatus.COMPLETED)
        removing, release = self._removal_in_progress(registry, new)
        try:
            started = time.monotonic()
            with pytest.raises(MCPResourceError) as refused:
                _register(registry, tmp_path / "proj", removal_wait_seconds=0.2)
            elapsed = time.monotonic() - started
        finally:
            release.set()
            removing.join(timeout=10)

        assert "being removed" in str(refused.value)
        assert refused.value.context["error_category"] == "operation_timeout"
        assert refused.value.context["output_directory"] == str(
            tmp_path / "proj" / ".ash" / "ash_output"
        )
        assert refused.value.context["waited_seconds"] == 0.2
        # Waited about the bound, not the delete's 10 s (the floor is loose
        # for timer granularity).
        assert 0.1 <= elapsed < 5
        # Nothing was registered by the refused call; with the delete over, the
        # tree can be registered again.
        assert registry.get_scan_count() == 2
        assert registry.get_scan(_register(registry, tmp_path / "proj")) is not None

    def test_a_registration_whose_wait_ends_within_the_bound_proceeds(self, tmp_path):
        registry = ScanRegistry()
        _old, new = self._two_scans(registry, tmp_path, MCScanStatus.COMPLETED)
        removing, release = self._removal_in_progress(registry, new)
        outcome = {}

        registering = threading.Thread(
            target=lambda: outcome.setdefault(
                "scan_id",
                _register(registry, tmp_path / "proj", removal_wait_seconds=10),
            )
        )
        registering.start()
        registering.join(timeout=0.3)
        assert registering.is_alive()

        release.set()
        removing.join(timeout=10)
        registering.join(timeout=10)
        assert registry.get_scan(outcome["scan_id"]) is not None
        assert registry.get_scan_count() == 3

    def test_a_zero_wait_refuses_at_once(self, tmp_path):
        """For a caller that would rather retry on its own schedule than hold
        its thread at all."""
        registry = ScanRegistry()
        _old, new = self._two_scans(registry, tmp_path, MCScanStatus.COMPLETED)
        removing, release = self._removal_in_progress(registry, new)
        try:
            started = time.monotonic()
            with pytest.raises(MCPResourceError, match="being removed"):
                _register(registry, tmp_path / "proj", removal_wait_seconds=0)
            elapsed = time.monotonic() - started
        finally:
            release.set()
            removing.join(timeout=10)
        assert elapsed < 1

    def test_the_default_bound_is_the_module_constant(self, tmp_path):
        """A caller that names no bound gets OUTPUT_REMOVAL_WAIT_SECONDS, read
        at call time, so the wait is bounded for every existing caller."""
        registry = ScanRegistry()
        _old, new = self._two_scans(registry, tmp_path, MCScanStatus.COMPLETED)
        removing, release = self._removal_in_progress(registry, new)
        try:
            with patch(f"{_MODULE}.OUTPUT_REMOVAL_WAIT_SECONDS", 0.2):
                with pytest.raises(MCPResourceError) as refused:
                    _register(registry, tmp_path / "proj")
        finally:
            release.set()
            removing.join(timeout=10)
        assert refused.value.context["waited_seconds"] == 0.2


class TestAScanWritingWithinAnOutputTree:
    """``scan_writing_within`` answers for a TREE (the same directory, one
    inside it, one containing it); ``scan_writing_output`` for one directory.
    A workspace's output root is written by the run and named by no entry, so
    the one-directory question admitted a scan sharing the root."""

    @staticmethod
    def _live(registry, tmp_path, name, output):
        source = tmp_path / "src" / name
        source.mkdir(parents=True)
        return _register(registry, source, output)

    def test_the_same_directory_is_found_until_the_scan_finishes(self, tmp_path):
        registry = ScanRegistry()
        root = tmp_path / "out"
        same = self._live(registry, tmp_path, "same", root)

        assert registry.scan_writing_within(str(root)) == same
        registry.update_scan_status(same, MCScanStatus.COMPLETED)
        assert registry.scan_writing_within(str(root)) is None

    def test_a_tree_inside_the_root_is_found_and_the_one_directory_question_misses_it(
        self, tmp_path
    ):
        registry = ScanRegistry()
        root = tmp_path / "out"
        inside = self._live(registry, tmp_path, "inside", root / "projects" / "web")

        assert registry.scan_writing_within(str(root)) == inside
        assert registry.scan_writing_output(str(root)) is None
        # A sibling folder under the same root shares nothing with it.
        assert registry.scan_writing_within(str(root / "projects" / "api")) is None

    def test_a_tree_containing_the_root_is_found(self, tmp_path):
        registry = ScanRegistry()
        root = tmp_path / "out"
        above = self._live(registry, tmp_path, "above", root)

        assert registry.scan_writing_within(str(root / "nested")) == above

    def test_a_string_prefix_sibling_is_not_found(self, tmp_path):
        """By path component, never by prefix: out-backup is not out."""
        registry = ScanRegistry()
        root = tmp_path / "out"
        self._live(registry, tmp_path, "sibling", tmp_path / "out-backup")

        assert registry.scan_writing_within(str(root)) is None
        assert registry.scan_writing_within(str(tmp_path / "out-backup")) is not None


class TestProgressOfASupersededScanReadsNoFiles:
    def test_a_later_scans_files_are_not_reported_as_the_old_scans(self, tmp_path):
        registry = ScanRegistry()
        project = tmp_path / "proj"
        project.mkdir()
        output = project / ".ash" / "ash_output"
        output.mkdir(parents=True)
        old = _register(registry, project, output)
        registry.update_scan_status(old, MCScanStatus.COMPLETED)
        # The old scan's results are on disk...
        (output / "ash_aggregated_results.json").write_text(
            json.dumps(_results_document("bandit")), encoding="utf-8"
        )
        before = registry.check_scan_progress(old)
        assert "bandit" in before["scanners"]

        # ...until a later scan of the directory takes the output tree over.
        new = _register(registry, project, output)
        registry.update_scan_status(new, MCScanStatus.RUNNING)
        (output / "ash_aggregated_results.json").write_text(
            json.dumps(_results_document("semgrep")), encoding="utf-8"
        )

        after = registry.check_scan_progress(old)

        assert after["scan_id"] == old
        assert after["status"] == "completed"
        assert after["scanners"] == {}
        assert after["total_scanners"] == 0
        assert after["skipped_scanners"] == []
        assert registry.get_scan(old).status is MCScanStatus.COMPLETED
        # The later scan still reads its own files.
        assert "semgrep" in registry.check_scan_progress(new)["scanners"]

    def test_a_superseded_scan_says_so(self, tmp_path):
        """Reading no files made a superseded scan look exactly like a clean one:
        completed, results_available, 0 findings, no scanners. The response now
        carries output_superseded so a client can tell the two apart."""
        registry = ScanRegistry()
        project = tmp_path / "proj"
        project.mkdir()
        output = project / ".ash" / "ash_output"
        output.mkdir(parents=True)
        old = _register(registry, project, output)
        registry.update_scan_status(old, MCScanStatus.COMPLETED)
        (output / "ash_aggregated_results.json").write_text(
            json.dumps(_results_document("bandit")), encoding="utf-8"
        )
        assert registry.check_scan_progress(old)["output_superseded"] is False

        new = _register(registry, project, output)
        registry.update_scan_status(new, MCScanStatus.RUNNING)

        progress = registry.check_scan_progress(old)

        assert progress["output_superseded"] is True
        assert progress["total_findings"] == 0
        # Reading no files is having no results of this scan's to read: a
        # superseded scan used to say results_available True over 0 findings,
        # the shape of a clean scan, with only the new flag to tell them apart.
        assert progress["results_available"] is False
        assert progress["coverage_complete"] is None
        assert registry.check_scan_progress(new)["output_superseded"] is False

    def test_a_later_scan_that_put_the_previous_results_back_does_not_supersede(
        self, tmp_path
    ):
        """A later scan that failed before writing anything has the previous
        results put back, which are the earlier scan's own; they are not hidden."""
        registry = ScanRegistry()
        project = tmp_path / "proj"
        project.mkdir()
        output = project / ".ash" / "ash_output"
        output.mkdir(parents=True)
        old = _register(registry, project, output)
        registry.update_scan_status(old, MCScanStatus.COMPLETED)
        (output / "ash_aggregated_results.json").write_text(
            json.dumps(_results_document("bandit")), encoding="utf-8"
        )

        new = _register(registry, project, output)
        # The later scan ran (claimed the tree) and then failed: without the
        # restore it would supersede, so this is the restore's exclusion.
        registry.update_scan_status(new, MCScanStatus.RUNNING)
        registry.update_scan_status(new, MCScanStatus.FAILED, "ASH exited with code 1")
        registry.get_scan(new).output_holds_previous_results = True

        progress = registry.check_scan_progress(old)

        assert progress["output_superseded"] is False
        assert "bandit" in progress["scanners"]

    def test_a_later_scan_that_never_ran_does_not_supersede(self, tmp_path):
        """A workspace registration rolled back marks its never-run entries
        CANCELLED (cli/mcp/workspace.py _register_projects). Recorded as a
        later scan at registration, such an entry hid the earlier COMPLETED
        scan's results (output_superseded True, scanners {}, 0 findings) behind
        a scan that touched no file, and its removal was refused for it."""
        registry = ScanRegistry()
        project = tmp_path / "proj"
        project.mkdir()
        output = project / ".ash" / "ash_output"
        output.mkdir(parents=True)
        old = _register(registry, project, output)
        registry.update_scan_status(old, MCScanStatus.COMPLETED)
        (output / "ash_aggregated_results.json").write_text(
            json.dumps(_results_document("bandit")), encoding="utf-8"
        )

        rolled_back = _register(registry, project, output)
        registry.update_scan_status(rolled_back, MCScanStatus.CANCELLED)

        progress = registry.check_scan_progress(old)
        assert progress["output_superseded"] is False
        assert progress["superseded_by"] == []
        assert "bandit" in progress["scanners"]
        assert registry.get_scan(old).later_scan_ids == []

        ran = []
        reason, removed = registry.remove_output_of_scan(
            registry.get_scan(old), lambda: ran.append(1) or True
        )
        assert reason is None
        assert removed is True
        assert ran == [1]

    def test_a_later_scan_that_failed_before_running_does_not_supersede(self, tmp_path):
        """FAILED straight from PENDING with no runner: nothing ran, nothing
        was written. Same shape as the rollback, through the other closing status."""
        registry = ScanRegistry()
        project = tmp_path / "proj"
        project.mkdir()
        output = project / ".ash" / "ash_output"
        output.mkdir(parents=True)
        old = _register(registry, project, output)
        registry.update_scan_status(old, MCScanStatus.COMPLETED)
        (output / "ash_aggregated_results.json").write_text(
            json.dumps(_results_document("bandit")), encoding="utf-8"
        )

        refused = _register(registry, project, output)
        registry.update_scan_status(
            refused, MCScanStatus.FAILED, "refused before start"
        )

        progress = registry.check_scan_progress(old)
        assert progress["output_superseded"] is False
        assert "bandit" in progress["scanners"]

    def test_a_later_scan_cancelled_while_running_still_supersedes(self, tmp_path):
        """A cancel of a RUNNING scan may land after it wrote: it claimed the
        tree, so it supersedes, through update_scan_status and through
        cancel_scan alike."""
        for cancel in ("update", "cancel_scan"):
            registry = ScanRegistry()
            project = tmp_path / cancel
            project.mkdir()
            output = project / ".ash" / "ash_output"
            output.mkdir(parents=True)
            old = _register(registry, project, output)
            registry.update_scan_status(old, MCScanStatus.COMPLETED)
            new = _register(registry, project, output)
            if cancel == "update":
                registry.update_scan_status(new, MCScanStatus.RUNNING)
                registry.update_scan_status(new, MCScanStatus.CANCELLED)
            else:
                registry.update_scan_status(new, MCScanStatus.RUNNING)
                assert registry.cancel_scan(new) is True

            progress = registry.check_scan_progress(old)
            assert progress["output_superseded"] is True, cancel
            assert progress["superseded_by"] == [new], cancel

    def test_a_pending_later_scan_neither_supersedes_nor_frees_the_tree(self, tmp_path):
        """Registered and not yet running, a later scan has written nothing, so
        the earlier scan's results are still its own; the tree is still held
        (the pending scan occupies it), so a removal is refused for occupancy."""
        registry = ScanRegistry()
        project = tmp_path / "proj"
        project.mkdir()
        output = project / ".ash" / "ash_output"
        output.mkdir(parents=True)
        old = _register(registry, project, output)
        registry.update_scan_status(old, MCScanStatus.COMPLETED)
        (output / "ash_aggregated_results.json").write_text(
            json.dumps(_results_document("bandit")), encoding="utf-8"
        )
        _pending = _register(registry, project, output)

        progress = registry.check_scan_progress(old)
        assert progress["output_superseded"] is False
        assert "bandit" in progress["scanners"]
        reason, removed = registry.remove_output_of_scan(
            registry.get_scan(old), lambda: True
        )
        assert "running or stopping" in reason
        assert removed is False

    def test_a_claim_is_recorded_once(self, tmp_path):
        """Marked running and then closed, the later scan appears once in
        superseded_by, not once per status change."""
        registry = ScanRegistry()
        project = tmp_path / "proj"
        project.mkdir()
        output = project / ".ash" / "ash_output"
        output.mkdir(parents=True)
        old = _register(registry, project, output)
        registry.update_scan_status(old, MCScanStatus.COMPLETED)
        new = _register(registry, project, output)
        registry.update_scan_status(new, MCScanStatus.RUNNING)
        registry.update_scan_status(new, MCScanStatus.COMPLETED)

        assert registry.get_scan(old).later_scan_ids == [new]
        assert registry.check_scan_progress(old)["superseded_by"] == [new]

    def test_the_claim_is_a_flag_on_the_entry_and_a_second_record_is_a_no_op(
        self, tmp_path
    ):
        """What makes "once" hold: the entry's ``claimed_output_tree`` flag, False
        until the scan claims its tree and True from then on, and a direct second
        record of a claimed entry appends nothing."""
        registry = ScanRegistry()
        project = tmp_path / "proj"
        project.mkdir()
        output = project / ".ash" / "ash_output"
        output.mkdir(parents=True)
        old = _register(registry, project, output)
        registry.update_scan_status(old, MCScanStatus.COMPLETED)
        new = _register(registry, project, output)
        assert registry.get_scan(new).claimed_output_tree is False
        assert registry.get_scan(old).later_scan_ids == []

        registry.update_scan_status(new, MCScanStatus.RUNNING)

        assert registry.get_scan(new).claimed_output_tree is True
        assert registry.get_scan(old).later_scan_ids == [new]
        # ``_record_supersession`` is called with ``_registry_lock`` held, as its
        # callers hold it; the lock is a plain ``Lock`` and ``get_scan`` takes it,
        # so the entry is read before the lock is taken, not inside it.
        entry = registry.get_scan(new)
        with registry._registry_lock:
            registry._record_supersession(entry)
        assert registry.get_scan(old).later_scan_ids == [new]

    def test_supersession_survives_the_later_scans_removal(self, tmp_path):
        """Worked out from registry membership alone, cleaning the later scan
        up made the old scan read the later scan's files as its own again."""
        registry = ScanRegistry()
        project = tmp_path / "proj"
        project.mkdir()
        output = project / ".ash" / "ash_output"
        output.mkdir(parents=True)
        old = _register(registry, project, output)
        registry.update_scan_status(old, MCScanStatus.COMPLETED)
        new = _register(registry, project, output)
        registry.update_scan_status(new, MCScanStatus.COMPLETED)
        (output / "ash_aggregated_results.json").write_text(
            json.dumps(_results_document("semgrep")), encoding="utf-8"
        )
        assert registry.cleanup_scan(new) is True

        progress = registry.check_scan_progress(old)

        assert progress["output_superseded"] is True
        assert progress["superseded_by"] == [new]
        assert progress["scanners"] == {}

    def test_a_later_scan_writing_elsewhere_does_not_supersede(self, tmp_path):
        """Supersession is about the output tree, not the source directory: a
        later scan of the same source that writes to another output directory
        leaves the old scan's files untouched."""
        registry = ScanRegistry()
        project = tmp_path / "proj"
        project.mkdir()
        output = project / ".ash" / "ash_output"
        output.mkdir(parents=True)
        elsewhere = project / ".ash" / "other_output"
        elsewhere.mkdir(parents=True)
        old = _register(registry, project, output)
        registry.update_scan_status(old, MCScanStatus.COMPLETED)
        (output / "ash_aggregated_results.json").write_text(
            json.dumps(_results_document("bandit")), encoding="utf-8"
        )
        new = _register(registry, project, elsewhere)
        registry.update_scan_status(new, MCScanStatus.RUNNING)

        progress = registry.check_scan_progress(old)

        assert progress["output_superseded"] is False
        assert progress["superseded_by"] == []
        assert "bandit" in progress["scanners"]

    def test_the_order_of_scans_is_the_order_of_registration_not_the_clock(
        self, tmp_path
    ):
        """Two registrations inside one clock tick, or a clock that steps back,
        used to tie or reverse under datetime.now() ordering."""
        registry = ScanRegistry()
        project = tmp_path / "proj"
        project.mkdir()
        output = project / ".ash" / "ash_output"
        output.mkdir(parents=True)
        old = _register(registry, project, output)
        registry.update_scan_status(old, MCScanStatus.COMPLETED)
        new = _register(registry, project, output)
        registry.update_scan_status(new, MCScanStatus.RUNNING)
        # The clock stepped back between the two registrations.
        registry.get_scan(new).start_time = registry.get_scan(
            old
        ).start_time - timedelta(hours=1)
        (output / "ash_aggregated_results.json").write_text(
            json.dumps(_results_document("semgrep")), encoding="utf-8"
        )

        assert (
            registry.get_scan(new).registration_seq
            > registry.get_scan(old).registration_seq
        )
        assert registry.check_scan_progress(old)["output_superseded"] is True
        assert registry.check_scan_progress(old)["scanners"] == {}


class TestSupersessionIsAboutWritingNotRegistering:
    """later_scan_ids used to record registration, and a registered scan can end
    without ever writing: refused at mkdir right after registering, or marked
    CANCELLED by a workspace registration that rolled back. Counted as
    superseding, such a scan hid the earlier scan's results while they sat on
    disk; it is now recorded on the claim (_record_supersession), so it is never
    there. And the two readers of the list disagreed, check_scan_progress
    counting a removed later scan while remove_output_of_scan counted registered
    ones only, so an old scan read as superseded by a scan whose files its
    cleanup then deleted; both read _later_scans_holding now, and a removed
    later scan that put the previous results back is forgotten on removal."""

    @staticmethod
    def _old_scan_with_results(registry, tmp_path):
        project = tmp_path / "proj"
        project.mkdir()
        output = project / ".ash" / "ash_output"
        output.mkdir(parents=True)
        old = _register(registry, project, output)
        registry.update_scan_status(old, MCScanStatus.COMPLETED)
        (output / "ash_aggregated_results.json").write_text(
            json.dumps(_results_document("bandit")), encoding="utf-8"
        )
        return project, output, old

    def test_a_later_scan_that_never_ran_does_not_supersede(self, tmp_path):
        registry = ScanRegistry()
        project, output, old = self._old_scan_with_results(registry, tmp_path)
        # Registered, then refused at mkdir: closed FAILED with no runner.
        new = _register(registry, project, output)
        registry.finish_scan(new, MCScanStatus.FAILED, error_message="mkdir refused")

        progress = registry.check_scan_progress(old)

        assert progress["output_superseded"] is False
        assert progress["superseded_by"] == []
        assert "bandit" in progress["scanners"]
        assert progress["results_available"] is True

    def test_a_cancelled_registration_that_never_ran_does_not_supersede(self, tmp_path):
        """The workspace rollback shape: registered, then CANCELLED, no runner."""
        registry = ScanRegistry()
        project, output, old = self._old_scan_with_results(registry, tmp_path)
        new = _register(registry, project, output)
        registry.update_scan_status(new, MCScanStatus.CANCELLED)

        assert registry.check_scan_progress(old)["output_superseded"] is False
        # Never recorded: supersession is recorded on the claim, and a scan
        # cancelled straight from PENDING with no runner never claimed the tree.
        assert registry.get_scan(old).later_scan_ids == []

    def test_removing_a_later_scan_that_never_ran_drops_it_from_the_record(
        self, tmp_path
    ):
        """Once such a scan leaves the registry its id would read as a removed
        scan whose files the tree holds; it never had any, so it is dropped."""
        registry = ScanRegistry()
        project, output, old = self._old_scan_with_results(registry, tmp_path)
        new = _register(registry, project, output)
        registry.update_scan_status(new, MCScanStatus.CANCELLED)
        assert registry.cleanup_scan(new) is True

        assert registry.get_scan(old).later_scan_ids == []
        assert registry.check_scan_progress(old)["output_superseded"] is False
        reason, removed = registry.remove_output_of_scan(
            registry.get_scan(old), lambda: True
        )
        assert (reason, removed) == (None, True)

    def test_removing_a_later_scan_that_put_the_results_back_drops_it_too(
        self, tmp_path
    ):
        """cleanup_scan(B), where B put the previous results back, used to turn A
        superseded with nothing changed on disk."""
        registry = ScanRegistry()
        project, output, old = self._old_scan_with_results(registry, tmp_path)
        new = _register(registry, project, output)
        registry.get_scan(new).has_runner = True
        registry.update_scan_status(new, MCScanStatus.RUNNING)
        registry.finish_scan(new, MCScanStatus.FAILED, error_message="exit 1")
        registry.get_scan(new).output_holds_previous_results = True
        registry.get_scan(new).runner_done.set()
        assert registry.check_scan_progress(old)["output_superseded"] is False

        assert registry.cleanup_scan(new) is True

        assert registry.get_scan(old).later_scan_ids == []
        assert registry.check_scan_progress(old)["output_superseded"] is False
        assert "bandit" in registry.check_scan_progress(old)["scanners"]

    def test_the_age_sweep_drops_it_the_same_way(self, tmp_path):
        registry = ScanRegistry()
        project, output, old = self._old_scan_with_results(registry, tmp_path)
        new = _register(registry, project, output)
        registry.update_scan_status(new, MCScanStatus.CANCELLED)
        registry.get_scan(new).end_time -= timedelta(days=2)
        registry.get_scan(old).end_time = registry.get_scan(old).end_time + timedelta(
            days=1
        )

        assert registry.cleanup_completed_scans(max_age_hours=1) == 1

        assert registry.get_scan(old) is not None
        assert registry.get_scan(old).later_scan_ids == []

    def test_cleaning_the_old_scan_keeps_a_removed_later_scans_files(self, tmp_path):
        """The two readers agree: a removed later scan that wrote holds the tree
        for check_scan_progress (superseded) AND for remove_output_of_scan
        (refused), where the latter used to count registered scans only and
        deleted the files the former called the later scan's."""
        registry = ScanRegistry()
        project, output, old = self._old_scan_with_results(registry, tmp_path)
        new = _register(registry, project, output)
        registry.update_scan_status(new, MCScanStatus.COMPLETED)
        assert registry.cleanup_scan(new) is True
        ran = []

        assert registry.check_scan_progress(old)["superseded_by"] == [new]
        reason, removed = registry.remove_output_of_scan(
            registry.get_scan(old), lambda: ran.append(1) or True
        )

        assert "later scan" in reason
        assert removed is False
        assert ran == []


class TestAFileClosedEntryIsNotReopenedOverAnotherScan:
    """An entry a poll closed from a results file no longer occupies its
    directory, so register_scan admits a second scan of it; the first runner's
    RUNNING claim was still admitted (closed_from_file), and both scans were
    RUNNING on one output tree."""

    @staticmethod
    def _file_closed(registry, tmp_path):
        project = tmp_path / "proj"
        project.mkdir()
        output = project / ".ash" / "ash_output"
        output.mkdir(parents=True)
        (output / "ash_aggregated_results.json").write_text(
            json.dumps(_results_document("bandit")), encoding="utf-8"
        )
        first = _register(registry, project, output)
        registry.check_scan_progress(first)
        assert registry.get_scan(first).closed_from_file is True
        return project, output, first

    def test_the_reopen_is_refused_while_a_second_scan_occupies_the_tree(
        self, tmp_path
    ):
        registry = ScanRegistry()
        project, output, first = self._file_closed(registry, tmp_path)
        second = _register(registry, project, output)
        registry.update_scan_status(second, MCScanStatus.RUNNING)

        assert registry.update_scan_status(first, MCScanStatus.RUNNING) is False

        assert registry.get_scan(first).status is not MCScanStatus.RUNNING
        assert registry.get_scan(second).status is MCScanStatus.RUNNING

    def test_the_reopen_is_refused_once_a_later_scan_has_taken_the_tree(self, tmp_path):
        registry = ScanRegistry()
        project, output, first = self._file_closed(registry, tmp_path)
        second = _register(registry, project, output)
        registry.update_scan_status(second, MCScanStatus.COMPLETED)

        assert registry.update_scan_status(first, MCScanStatus.RUNNING) is False

    def test_the_reopen_still_works_while_the_tree_is_its_own(self, tmp_path):
        """The control: the case the reopen exists for."""
        registry = ScanRegistry()
        _project, _output, first = self._file_closed(registry, tmp_path)

        assert registry.update_scan_status(first, MCScanStatus.RUNNING) is True
        assert registry.get_scan(first).status is MCScanStatus.RUNNING


class TestAFinishedScanWhoseOutputIsGoneHasNoResults:
    """validate_directory_path's FILE_NOT_FOUND made the poll read no files, and
    the empty progress then reached the COMPLETED arm and was marked completed:
    status completed, results_available True, total_findings 0, error_message
    None and, with a recorded gap-free coverage, coverage_complete True. A clean
    scan, with nothing in the response saying the directory was gone."""

    def test_a_completed_scan_with_a_missing_directory_says_so(self, tmp_path):
        registry = ScanRegistry()
        project = tmp_path / "proj"
        project.mkdir()
        output = project / ".ash" / "ash_output"
        output.mkdir(parents=True)
        scan_id = _register(registry, project, output)
        registry.finish_scan(
            scan_id,
            MCScanStatus.COMPLETED,
            coverage={
                "incomplete_scanners": [],
                "no_scanner_ran": False,
                "incomplete_converters": [],
                "unevaluated_rules": [],
                "stale_content_databases": [],
                "could_not_stop": [],
            },
        )
        output.rmdir()

        progress = registry.check_scan_progress(scan_id)

        assert progress["status"] == "completed"
        assert progress["is_complete"] is True
        assert progress["results_available"] is False
        assert progress["coverage_complete"] is None
        assert progress["total_findings"] == 0
        assert progress["error_message"]
        assert str(output) in progress["error_message"]
        assert "missing" in progress["error_message"]
        # The recorded gap lists still describe the run.
        assert progress["incomplete_scanners"] == []

    def test_a_running_scan_with_no_directory_yet_carries_no_message(self, tmp_path):
        """The control: a scan whose output is not created yet is not finished,
        so there are no results to be missing."""
        registry = ScanRegistry()
        project = tmp_path / "proj"
        project.mkdir()
        scan_id = _register(registry, project)
        registry.update_scan_status(scan_id, MCScanStatus.RUNNING)

        progress = registry.check_scan_progress(scan_id)

        assert progress["status"] == "running"
        assert progress["results_available"] is False
        assert progress["error_message"] is None


class TestAStoppedScansCoverageNamesTheToolsThatSurvived:
    """_empty_coverage put could_not_stop [] into every response whose entry had
    no coverage, which is every CANCELLED scan and every timed-out FAILED one:
    the entries record_cancel_outcome fills. A client reading the key was told
    no tool survived while the warnings said one did."""

    def test_the_payload_names_the_tool_by_basename(self, tmp_path):
        registry = ScanRegistry()
        project = tmp_path / "proj"
        project.mkdir()
        (project / ".ash" / "ash_output").mkdir(parents=True)
        scan_id = _register(registry, project)
        entry = registry.get_scan(scan_id)
        entry.has_runner = True
        registry.update_scan_status(scan_id, MCScanStatus.RUNNING)
        registry.cancel_scan(scan_id)
        registry.record_cancel_outcome(
            scan_id, (("/opt/tools/bin/bandit", 4242),), name_process_ids=False
        )
        entry.runner_done.set()

        progress = registry.check_scan_progress(scan_id)

        assert progress["status"] == "cancelled"
        assert progress["could_not_stop"] == [
            {
                "scanner": "bandit",
                "reason": "bandit's tool was still running after the cancel",
            }
        ]
        assert "4242" not in json.dumps(progress["could_not_stop"])
        assert "/opt/tools" not in json.dumps(progress["could_not_stop"])

    def test_a_scan_nothing_stopped_still_reads_an_empty_list(self, tmp_path):
        registry = ScanRegistry()
        project = tmp_path / "proj"
        project.mkdir()
        (project / ".ash" / "ash_output").mkdir(parents=True)
        scan_id = _register(registry, project)
        registry.update_scan_status(scan_id, MCScanStatus.RUNNING)
        registry.cancel_scan(scan_id)

        assert registry.check_scan_progress(scan_id)["could_not_stop"] == []


def _stopped_with_a_surviving_tool(tmp_path, tool="bandit", pid=4242, started="100"):
    """A cancelled scan whose cancel could not end ``tool`` (``pid``), recorded
    while the system reported ``started`` as the pid's start time."""
    registry = ScanRegistry()
    project = tmp_path / "proj"
    project.mkdir()
    (project / ".ash" / "ash_output").mkdir(parents=True)
    scan_id = _register(registry, project)
    entry = registry.get_scan(scan_id)
    entry.has_runner = True
    registry.update_scan_status(scan_id, MCScanStatus.RUNNING)
    registry.cancel_scan(scan_id)
    with patch(f"{_MODULE}._process_start_time", return_value=started):
        registry.record_cancel_outcome(scan_id, ((tool, pid),), name_process_ids=False)
    entry.runner_done.set()
    return registry, entry


class TestAReusedPidDoesNotHoldTheDirectory:
    """The probe behind could_not_stop asked only whether the pid names a live
    process, so once the system gave the tool's pid to another process the
    directory, and the server's concurrency slot, stayed held until that
    stranger ended, which can be the server's own lifetime. The entry now
    records each pid's start time as the system reports it (/proc/<pid>/stat
    on Linux); a pid whose start time has changed names another process and
    reads as gone. A zombie keeps its start time and stays until it is reaped;
    where the system reports no start time the probe alone decides, as before."""

    def test_the_start_time_is_recorded_with_the_pid(self, tmp_path):
        _registry, entry = _stopped_with_a_surviving_tool(tmp_path, started="100")

        assert entry.could_not_stop == (("bandit", 4242),)
        assert entry.tool_start_times == {4242: "100"}

    def test_a_pid_with_another_start_time_reads_as_gone(self, tmp_path):
        _registry, entry = _stopped_with_a_surviving_tool(tmp_path, started="100")

        with (
            patch(f"{_MODULE}._process_start_time", return_value="200"),
            patch(f"{_MODULE}._tool_may_be_running", return_value=True),
        ):
            assert entry.a_surviving_tool_is_running() is False
            assert entry.occupies_its_directory() is False

    def test_the_same_start_time_still_holds_the_directory(self, tmp_path):
        _registry, entry = _stopped_with_a_surviving_tool(tmp_path, started="100")

        with (
            patch(f"{_MODULE}._process_start_time", return_value="100"),
            patch(f"{_MODULE}._tool_may_be_running", return_value=True),
        ):
            assert entry.a_surviving_tool_is_running() is True
            assert entry.occupies_its_directory() is True

    def test_with_no_recorded_start_time_the_probe_alone_decides(self, tmp_path):
        """A system that reports no start time (no /proc) recorded None; the
        pid then holds the directory for as long as the probe reads it alive,
        the hold the entry had before start times were recorded."""
        _registry, entry = _stopped_with_a_surviving_tool(tmp_path, started=None)

        assert entry.tool_start_times == {4242: None}
        with (
            patch(f"{_MODULE}._process_start_time", return_value="200"),
            patch(f"{_MODULE}._tool_may_be_running", return_value=True),
        ):
            assert entry.a_surviving_tool_is_running() is True

    def test_a_start_time_unreadable_now_leaves_the_probe_to_decide(self, tmp_path):
        """An entry gone from /proc between two reads, or a system that reports
        no start time: with nothing to compare, the probe's answer stands. (A
        zombie is NOT this case: it keeps its /proc entry and its start time
        until it is reaped, so it is the same-start-time test above; its pid is
        still a process to kill(pid, 0), so it stays held until reaped.)"""
        _registry, entry = _stopped_with_a_surviving_tool(tmp_path, started="100")

        with (
            patch(f"{_MODULE}._process_start_time", return_value=None),
            patch(f"{_MODULE}._tool_may_be_running", return_value=True),
        ):
            assert entry.a_surviving_tool_is_running() is True

    def test_a_second_record_of_the_same_pid_keeps_the_first_start_time(self, tmp_path):
        registry, entry = _stopped_with_a_surviving_tool(tmp_path, started="100")

        with patch(f"{_MODULE}._process_start_time", return_value="999"):
            # The same pair again is nothing new; another tool on the same pid
            # is a new pair but the pid's first reading stands.
            assert (
                registry.record_cancel_outcome(
                    entry.scan_id, (("bandit", 4242),), name_process_ids=False
                )
                is False
            )
            registry.record_cancel_outcome(
                entry.scan_id, (("semgrep", 4242),), name_process_ids=False
            )

        assert entry.tool_start_times == {4242: "100"}


class TestTheStartTimeIsReadFromProcStat:
    _STAT = (
        b"4242 (my tool) S 1 4242 4242 0 -1 4194560 100 0 0 0 5 3 0 0 20 0 1 0 "
        b"7654321 1024000 300 4096 1 1 0 0 0 0 0 0 0 0 0 0 0 "
        b"17 3 0 0 0 0 0 0 0 0 0 0 0 0 0\n"
    )

    def test_field_22_is_the_start_time_even_with_a_space_in_the_command_name(
        self,
    ):
        from unittest.mock import mock_open

        from automated_security_helper.core.resource_management.scan_registry import (
            _process_start_time,
        )

        if os.name == "nt":
            pytest.skip("Windows reports no /proc start time; the probe alone decides")
        with patch("builtins.open", mock_open(read_data=self._STAT)):
            assert _process_start_time(4242) == "7654321"

    def test_a_pid_with_no_proc_entry_reads_none(self):
        from automated_security_helper.core.resource_management.scan_registry import (
            _process_start_time,
        )

        with patch("builtins.open", side_effect=FileNotFoundError):
            assert _process_start_time(4242) is None
        assert _process_start_time(0) is None

    @pytest.mark.skipif(
        os.name == "nt" or not Path("/proc/self/stat").exists(),
        reason="the start time is a Linux /proc fact",
    )
    def test_this_process_has_a_start_time(self):
        from automated_security_helper.core.resource_management.scan_registry import (
            _process_start_time,
        )

        started = _process_start_time(os.getpid())

        assert started is not None
        assert started.isdigit()


class TestARemoteReadKeepsProcessIdsOutOfTheResponse:
    """The entry's warnings name each surviving tool with its pid on a local
    transport, and the stored coverage's could_not_stop reasons carry the pid
    the executor recorded. Both were written for the transport of the moment;
    a later progress read by a remote client (or under the every-caller-remote
    override) was handed them as recorded, while the cancel warning's own rule
    withholds pids from a remote client. check_scan_progress now redacts both
    at the read when name_process_ids is False, and leaves the entry's records
    as they are, so a local read still names them."""

    @staticmethod
    def _stopped_with_recorded_pids(tmp_path):
        registry = ScanRegistry()
        project = tmp_path / "proj"
        project.mkdir()
        (project / ".ash" / "ash_output").mkdir(parents=True)
        scan_id = _register(registry, project)
        entry = registry.get_scan(scan_id)
        entry.has_runner = True
        registry.update_scan_status(scan_id, MCScanStatus.RUNNING)
        registry.cancel_scan(scan_id)
        with patch(f"{_MODULE}._process_start_time", return_value="100"):
            # The local transport's warning: the tool AND its pid.
            registry.record_cancel_outcome(scan_id, (("bandit", 4242),))
        entry.runner_done.set()
        from automated_security_helper.core.resource_management.scan_registry import (
            _empty_coverage,
        )

        entry.coverage = {
            **_empty_coverage(),
            "could_not_stop": [
                {"scanner": "bandit", "reason": "the tool kept running (pid 4242)"}
            ],
        }
        return registry, entry

    @staticmethod
    def _stand_in_redactor(text):
        return text.replace(" (pid 4242)", "")

    def test_a_local_read_names_the_pids_as_recorded(self, tmp_path):
        registry, entry = self._stopped_with_recorded_pids(tmp_path)

        progress = registry.check_scan_progress(entry.scan_id)

        assert "4242" in json.dumps(progress["warnings"])
        assert "4242" in json.dumps(progress["could_not_stop"])

    def test_a_remote_read_goes_through_the_redactor(self, tmp_path):
        registry, entry = self._stopped_with_recorded_pids(tmp_path)

        with patch(f"{_MODULE}._without_process_ids", self._stand_in_redactor):
            progress = registry.check_scan_progress(
                entry.scan_id, name_process_ids=False
            )

        assert "4242" not in json.dumps(progress["warnings"])
        assert "bandit" in json.dumps(progress["warnings"])
        assert progress["could_not_stop"] == [
            {"scanner": "bandit", "reason": "the tool kept running"}
        ]
        # The entry's own records are not changed by the read.
        assert "4242" in json.dumps(entry.warnings)
        assert "4242" in json.dumps(entry.coverage["could_not_stop"])

    def test_a_remote_read_with_the_real_redactor(self, tmp_path):
        """The redactor is utils.subprocess_utils.without_process_ids (U01's);
        where the tree carries it, the real one is exercised."""
        from automated_security_helper.utils import subprocess_utils

        if getattr(subprocess_utils, "without_process_ids", None) is None:
            pytest.skip(
                "utils.subprocess_utils.without_process_ids is not in this tree"
            )
        registry, entry = self._stopped_with_recorded_pids(tmp_path)

        progress = registry.check_scan_progress(entry.scan_id, name_process_ids=False)

        assert "4242" not in json.dumps(progress["warnings"])
        assert "4242" not in json.dumps(progress["could_not_stop"])
        assert "bandit" in json.dumps(progress["warnings"])


class TestATrailingSeparatorStillGivesTheBasename:
    def test_the_tool_is_named_without_its_trailing_slash(self, tmp_path):
        """argv0 recorded with a trailing separator gave an empty basename, so
        the fallback showed the whole recorded name, path included."""
        _registry, entry = _stopped_with_a_surviving_tool(
            tmp_path, tool="/opt/tools/bin/bandit/"
        )

        assert entry.tool_display_names() == ["bandit"]
        assert "bandit" in entry.warnings[-1]
        assert "/opt/tools" not in entry.warnings[-1]


class TestTheRefusalNamesASurvivingToolByBasename:
    def test_the_servers_path_to_the_tool_is_not_shown(self, tmp_path):
        """record_cancel_outcome reduces the name to its basename on a network
        transport because argv0 can be the tool's full path on the server; the
        directory-busy refusal joined the raw names and showed that path."""
        registry = ScanRegistry()
        project = tmp_path / "proj"
        project.mkdir()
        scan_id = _register(registry, project)
        entry = registry.get_scan(scan_id)
        entry.has_runner = True
        registry.update_scan_status(scan_id, MCScanStatus.RUNNING)
        registry.cancel_scan(scan_id)
        registry.record_cancel_outcome(
            scan_id, (("/opt/tools/bin/bandit", 4242),), name_process_ids=False
        )
        entry.runner_done.set()

        with patch(f"{_MODULE}._tool_may_be_running", return_value=True):
            with pytest.raises(MCPResourceError) as excinfo:
                _register(registry, project)

        assert "could not be stopped" in str(excinfo.value)
        assert "bandit" in str(excinfo.value)
        assert "/opt/tools" not in str(excinfo.value)
        assert "4242" not in str(excinfo.value)


class TestAReadOnlyPollDoesNotRecloseACompletedScan:
    """A COMPLETED entry whose results file later reads as unusable used to be
    turned FAILED, with a new end_time, by every progress poll: the "failed"
    file status was applied to any entry but RUNNING, FAILED, CANCELLED and
    INCOMPLETE. Only a PENDING entry no runner has claimed takes its status from
    the file (a PENDING entry with a runner is that runner's to close, as a
    RUNNING one is); a finished scan keeps its status and reports the file
    problem.

    Keeping the status is not keeping the results: with the status kept, the
    response still said ``results_available`` True, ``total_findings`` 0 and
    ``coverage_complete`` True (when the runner had recorded coverage), so a
    client reading those fields saw a clean scan that found nothing and the
    reason sat in ``error_message`` alone. The results fields now follow the
    file: there are none to read. The same holds for a results file that is a
    JSON object with neither ``scanner_results`` nor ``sarif``, which used to
    re-close a COMPLETED entry as FAILED while the unreadable file kept it."""

    @staticmethod
    def _closed_scan(tmp_path, registry, coverage=None):
        project = tmp_path / "proj"
        project.mkdir()
        output = project / ".ash" / "ash_output"
        output.mkdir(parents=True)
        scan_id = _register(registry, project, output)
        if coverage is None:
            registry.update_scan_status(scan_id, MCScanStatus.COMPLETED)
        else:
            registry.finish_scan(scan_id, MCScanStatus.COMPLETED, coverage=coverage)
        return scan_id, output / "ash_aggregated_results.json"

    def test_a_completed_entry_keeps_its_status_and_reports_the_file(self, tmp_path):
        registry = ScanRegistry()
        scan_id, results_file = self._closed_scan(tmp_path, registry)
        entry = registry.get_scan(scan_id)
        closed_at = entry.end_time
        results_file.write_text("{ not json", encoding="utf-8")

        progress = registry.check_scan_progress(scan_id)

        assert progress["status"] == "completed"
        assert progress["is_complete"] is True
        assert progress["error_message"]
        assert str(results_file) in progress["error_message"]
        assert entry.status is MCScanStatus.COMPLETED
        assert entry.end_time == closed_at
        assert entry.error_message is None
        # The results fields say what the status cannot: nothing to read.
        assert progress["results_available"] is False
        assert progress["coverage_complete"] is None
        assert progress["total_findings"] == 0
        assert progress["scanners"] == {}

    def test_a_completed_scan_whose_output_directory_is_gone_has_no_results(
        self, tmp_path
    ):
        """The directory gone (removed since, or never created), nothing was
        read and the poll no longer raised; but the COMPLETED arm then marked the
        empty progress completed, so the response read results_available True,
        total_findings 0, coverage_complete True from the recorded coverage and
        error_message None: a clean scan that found nothing, with no field
        saying the directory is missing."""
        registry = ScanRegistry()
        scan_id, results_file = self._closed_scan(
            tmp_path,
            registry,
            coverage={
                "incomplete_scanners": [],
                "no_scanner_ran": False,
                "incomplete_converters": [],
                "unevaluated_rules": [],
                "stale_content_databases": [],
                "could_not_stop": [],
            },
        )
        output = results_file.parent
        output.rmdir()
        entry = registry.get_scan(scan_id)

        progress = registry.check_scan_progress(scan_id)

        assert progress["status"] == "completed"
        assert progress["is_complete"] is True
        assert progress["results_available"] is False
        assert progress["coverage_complete"] is None
        assert progress["total_findings"] == 0
        assert progress["scanners"] == {}
        assert progress["error_message"]
        assert str(output) in progress["error_message"]
        # The entry is not re-closed and carries no reason of its own.
        assert entry.status is MCScanStatus.COMPLETED
        assert entry.error_message is None
        # The recorded gap lists still describe the run.
        assert progress["incomplete_scanners"] == []

    def test_a_superseded_scan_has_no_results_of_its_own(self, tmp_path):
        """output_superseded said the files are a later scan's; results_available
        still said True beside total_findings 0, the same clean-scan reading."""
        registry = ScanRegistry()
        project = tmp_path / "proj"
        project.mkdir()
        output = project / ".ash" / "ash_output"
        output.mkdir(parents=True)
        old = _register(registry, project, output)
        registry.update_scan_status(old, MCScanStatus.COMPLETED)
        (output / "ash_aggregated_results.json").write_text(
            json.dumps(_results_document("bandit")), encoding="utf-8"
        )
        new = _register(registry, project, output)
        registry.update_scan_status(new, MCScanStatus.RUNNING)

        progress = registry.check_scan_progress(old)

        assert progress["output_superseded"] is True
        assert progress["superseded_by"] == [new]
        assert progress["results_available"] is False
        assert progress["coverage_complete"] is None
        assert progress["status"] == "completed"
        # The later scan's own results are still its own.
        assert registry.check_scan_progress(new)["results_available"] is False
        registry.update_scan_status(new, MCScanStatus.COMPLETED)
        assert registry.check_scan_progress(new)["results_available"] is True

    def test_recorded_coverage_does_not_make_unreadable_results_complete(
        self, tmp_path
    ):
        """The runner recorded a gap-free coverage when it closed the scan (the
        workspace path closes project entries this way); the file is then
        unreadable. coverage_complete read True from the record alone."""
        registry = ScanRegistry()
        scan_id, results_file = self._closed_scan(
            tmp_path,
            registry,
            coverage={
                "incomplete_scanners": [],
                "no_scanner_ran": False,
                "incomplete_converters": [],
                "unevaluated_rules": [],
                "stale_content_databases": [],
                "could_not_stop": [],
            },
        )
        results_file.write_text("{ not json", encoding="utf-8")

        progress = registry.check_scan_progress(scan_id)

        assert progress["status"] == "completed"
        assert progress["results_available"] is False
        assert progress["coverage_complete"] is None
        # The recorded gap lists still describe the run.
        assert progress["incomplete_scanners"] == []

    def test_a_readable_results_file_still_reports_its_results(self, tmp_path):
        """The control: the same closed entry with a results document."""
        registry = ScanRegistry()
        scan_id, results_file = self._closed_scan(tmp_path, registry)
        results_file.write_text(
            json.dumps(_results_document("bandit")), encoding="utf-8"
        )

        progress = registry.check_scan_progress(scan_id)

        assert progress["status"] == "completed"
        assert progress["results_available"] is True
        assert progress["total_findings"] == 1
        assert progress["error_message"] is None

    def test_a_keyless_document_under_an_incomplete_entry_has_no_results(
        self, tmp_path
    ):
        """The keyless-document rule sat below the terminal-status arm, which
        kept an INCOMPLETE entry's progress as the file view left it (status
        in_progress, results_pending), so results_available read True with 0
        findings for a scan whose final document never arrived."""
        registry = ScanRegistry()
        project = tmp_path / "proj"
        project.mkdir()
        output = project / ".ash" / "ash_output"
        output.mkdir(parents=True)
        scan_id = _register(registry, project, output)
        registry.update_scan_status(scan_id, MCScanStatus.RUNNING)
        registry.finish_scan(
            scan_id,
            MCScanStatus.INCOMPLETE,
            coverage={
                "incomplete_scanners": [{"name": "semgrep", "reason": "missing"}],
                "no_scanner_ran": False,
                "incomplete_converters": [],
                "unevaluated_rules": [],
                "stale_content_databases": [],
                "could_not_stop": [],
            },
        )
        results_file = output / "ash_aggregated_results.json"
        results_file.write_text(
            json.dumps({"metadata": {"generated_at": "2024-01-01T00:00:00"}}),
            encoding="utf-8",
        )

        progress = registry.check_scan_progress(scan_id)

        assert progress["status"] == "incomplete"
        assert progress["is_complete"] is True
        assert progress["results_available"] is False
        assert progress["coverage_complete"] is None
        assert progress["total_findings"] == 0
        assert "neither scanner_results nor sarif" in progress["error_message"]
        assert registry.get_scan(scan_id).status is MCScanStatus.INCOMPLETE

    def test_a_document_with_neither_results_nor_sarif_keeps_a_completed_entry(
        self, tmp_path
    ):
        registry = ScanRegistry()
        scan_id, results_file = self._closed_scan(tmp_path, registry)
        entry = registry.get_scan(scan_id)
        closed_at = entry.end_time
        results_file.write_text(
            json.dumps({"metadata": {"generated_at": "2024-01-01T00:00:00"}}),
            encoding="utf-8",
        )

        progress = registry.check_scan_progress(scan_id)

        assert entry.status is MCScanStatus.COMPLETED
        assert entry.end_time == closed_at
        assert progress["status"] == "completed"
        assert progress["is_complete"] is True
        assert progress["results_available"] is False
        assert progress["coverage_complete"] is None
        assert progress["total_findings"] == 0
        assert "neither scanner_results nor sarif" in progress["error_message"]
        assert str(results_file) in progress["error_message"]

    def test_a_pending_entry_still_takes_the_failure_from_the_file(self, tmp_path):
        """The case the file-decides rule exists for, preserved."""
        registry = ScanRegistry()
        project = tmp_path / "proj"
        project.mkdir()
        output = project / ".ash" / "ash_output"
        output.mkdir(parents=True)
        scan_id = _register(registry, project, output)
        (output / "ash_aggregated_results.json").write_text(
            "{ not json", encoding="utf-8"
        )

        progress = registry.check_scan_progress(scan_id)

        assert progress["status"] == "failed"
        assert registry.get_scan(scan_id).status is MCScanStatus.FAILED

    def test_a_pending_entry_a_runner_has_claimed_is_not_closed_from_the_file(
        self, tmp_path
    ):
        """In the MCP flow an entry stays PENDING while its runner task exists
        but has not taken its first step, and the file on disk is then the
        previous scan's: a stale, unreadable one must not close the entry FAILED
        underneath the runner that owns it."""
        registry = ScanRegistry()
        project = tmp_path / "proj"
        project.mkdir()
        output = project / ".ash" / "ash_output"
        output.mkdir(parents=True)
        scan_id = _register(registry, project, output)
        registry.get_scan(scan_id).has_runner = True
        (output / "ash_aggregated_results.json").write_text(
            "{ not json", encoding="utf-8"
        )

        progress = registry.check_scan_progress(scan_id)

        assert progress["status"] == "pending"
        assert progress["is_complete"] is False
        assert progress["error_message"] is None
        assert registry.get_scan(scan_id).status is MCScanStatus.PENDING
        assert registry.get_scan(scan_id).closed_from_file is False


class TestAnEndedScanReportsNoRunningScanner:
    """A cancel or a crash mid-write leaves a per-scanner file that is not yet a
    JSON object and no aggregated file. The file view reports that scanner as
    running until a later poll reads a document; for an ended scan none will,
    so the response said is_complete True beside scanner_status_counts.running 1
    on every poll. An ended entry now reports such a scanner as failed."""

    @staticmethod
    def _truncated_scanner_file(output):
        path = output / "scanners" / "bandit" / "source" / "ASH.ScanResults.json"
        path.parent.mkdir(parents=True)
        path.write_text('{"scanner_name": "bandit", "fin', encoding="utf-8")

    def test_a_running_scanner_of_an_ended_scan_reads_as_failed(self, tmp_path):
        registry = ScanRegistry()
        project = tmp_path / "proj"
        project.mkdir()
        output = project / ".ash" / "ash_output"
        output.mkdir(parents=True)
        scan_id = _register(registry, project, output)
        registry.update_scan_status(scan_id, MCScanStatus.RUNNING)
        self._truncated_scanner_file(output)
        registry.finish_scan(scan_id, MCScanStatus.FAILED, "crashed")

        progress = registry.check_scan_progress(scan_id)

        assert progress["is_complete"] is True
        assert progress["scanner_status_counts"]["running"] == 0
        assert progress["scanner_status_counts"]["failed"] == 1
        assert progress["scanners"]["bandit"]["source"]["status"] == "failed"
        assert progress["finished_scanners"] == 1

    def test_a_running_scanner_of_a_running_scan_still_reads_as_running(self, tmp_path):
        registry = ScanRegistry()
        project = tmp_path / "proj"
        project.mkdir()
        output = project / ".ash" / "ash_output"
        output.mkdir(parents=True)
        scan_id = _register(registry, project, output)
        registry.update_scan_status(scan_id, MCScanStatus.RUNNING)
        self._truncated_scanner_file(output)

        progress = registry.check_scan_progress(scan_id)

        assert progress["is_complete"] is False
        assert progress["scanner_status_counts"]["running"] == 1
        assert progress["scanners"]["bandit"]["source"]["status"] == "running"


class TestCoverageAssessmentFailureDoesNotFailTheProgressCall:
    def test_a_raising_assessment_leaves_coverage_unknown(self, tmp_path):
        registry = ScanRegistry()
        project = tmp_path / "proj"
        project.mkdir()
        output = project / ".ash" / "ash_output"
        output.mkdir(parents=True)
        scan_id = _register(registry, project, output)
        (output / "ash_aggregated_results.json").write_text(
            json.dumps(_results_document("bandit")), encoding="utf-8"
        )
        # Closed without coverage, as a caller using update_scan_status does.
        registry.update_scan_status(scan_id, MCScanStatus.COMPLETED)

        with patch(
            f"{_MODULE}.assess_coverage", side_effect=KeyError("rule without id")
        ) as assess:
            progress = registry.check_scan_progress(scan_id)
            again = registry.check_scan_progress(scan_id)

        # The patched assessment was reached, and reached again on the second
        # poll: a failed assessment is not cached as "unknown", so a transient
        # failure is retried on the next poll rather than pinned to the scan.
        assert assess.call_count == 2
        assert progress["success"] is True
        assert progress["status"] == "completed"
        assert progress["coverage_complete"] is None
        assert again["success"] is True
        assert again["coverage_complete"] is None
