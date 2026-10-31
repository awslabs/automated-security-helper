# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""cleanup_scan_resources against a runner that is still stopping and a shared output tree.

Three mechanisms, each pinned against the behavior it replaced:

* A cancel closes the entry at once while the in-process runner thread runs on
  for seconds, stopping its scanner's child process and putting the previous
  results back. Cleanup removed the registry entry and the output directory
  in that window: the directory was deleted from under a thread still writing
  into it, and a new scan of the directory was admitted while the old runner's
  restore could still overwrite it.
* Every scan of one source directory writes the same ``<source>/.ash/ash_output``,
  so removing an old scan's output removed a newer, possibly running, scan's.
* The output path is a string recorded at registration and was removed by that
  path with no re-check, so a ``.ash`` that became a symbolic link after the
  scan redirected the recursive delete to wherever the link pointed.

Doubles follow test_scan_management_lifecycle.py: a ``MagicMock(spec=ScanRegistry)``
registry and real ``ScanRegistryEntry`` instances, whose runner flags are
instance attributes.
"""

import asyncio
import os
import shutil
import threading
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from automated_security_helper.core.resource_management import scan_registry
from automated_security_helper.core.resource_management.error_handling import (
    ErrorCategory,
)
from automated_security_helper.core.resource_management.scan_management import (
    check_scan_progress,
    cleanup_scan_resources,
)
from automated_security_helper.core.resource_management.scan_registry import (
    MCScanStatus,
    ScanRegistry,
    ScanRegistryEntry,
)

pytestmark = pytest.mark.unit

_MODULE = "automated_security_helper.core.resource_management.scan_management"


@pytest.fixture
def registry():
    registry = MagicMock(spec=ScanRegistry)
    registry.cleanup_scan.return_value = True
    registry.cancel_scan.return_value = True
    # The real method decides under the registry lock and runs the remover off
    # it, unless another scan holds the directory; the double admits by default
    # and runs it.
    registry.remove_output_of_scan.side_effect = lambda entry, remover: (
        None,
        remover(),
    )
    return registry


@contextmanager
def _use(registry):
    with patch(f"{_MODULE}.get_scan_registry", return_value=registry):
        yield


def _entry(tmp_path, status=MCScanStatus.RUNNING, has_runner=True):
    source = tmp_path / "src"
    source.mkdir(exist_ok=True)
    entry = ScanRegistryEntry(
        scan_id="scan-1",
        directory_path=str(source),
        output_directory=str(source / ".ash" / "ash_output"),
    )
    entry.status = status
    entry.has_runner = has_runner
    return entry


def _output_of(entry):
    output = Path(entry.output_directory)
    output.mkdir(parents=True, exist_ok=True)
    (output / "ash_aggregated_results.json").write_text("{}", encoding="utf-8")
    return output


class TestCleanupWaitsForTheRunner:
    def test_a_runner_still_stopping_keeps_everything(self, registry, tmp_path):
        entry = _entry(tmp_path)
        output = _output_of(entry)
        registry.get_scan.return_value = entry

        with _use(registry), patch(f"{_MODULE}._RUNNER_SETTLE_TIMEOUT_SECONDS", 0.05):
            result = asyncio.run(cleanup_scan_resources("scan-1", remove_output=True))

        assert result["success"] is False
        assert result["removed_output"] is False
        assert result["removed_from_registry"] is False
        assert "still stopping" in result["message"]
        registry.cancel_scan.assert_called_once_with("scan-1")
        registry.cleanup_scan.assert_not_called()
        assert output.exists()

    def test_a_runner_that_settles_in_time_is_cleaned_up(self, registry, tmp_path):
        entry = _entry(tmp_path)
        output = _output_of(entry)
        entry.runner_done.set()
        registry.get_scan.return_value = entry

        with _use(registry):
            result = asyncio.run(cleanup_scan_resources("scan-1", remove_output=True))

        assert result["success"] is True
        assert result["removed_output"] is True
        assert not output.exists()
        registry.cleanup_scan.assert_called_once_with("scan-1")

    def test_a_runner_that_settles_during_the_wait_is_cleaned_up(
        self, registry, tmp_path
    ):
        """The event is set 50 ms after the cancel, so the wait starts on an
        unset event and has to block. (Set inside the cancel, it was already set
        when the wait began, and a wait that only read is_set() once passed.)"""
        entry = _entry(tmp_path)
        registry.get_scan.return_value = entry
        timers = []

        def cancel(scan_id):
            timer = threading.Timer(0.05, entry.runner_done.set)
            timers.append(timer)
            timer.start()
            return True

        registry.cancel_scan.side_effect = cancel
        real_wait = entry.runner_done.wait
        unset_at_wait = []

        def wait(timeout=None):
            unset_at_wait.append(not entry.runner_done.is_set())
            return real_wait(timeout)

        entry.runner_done.wait = wait

        try:
            with (
                _use(registry),
                patch(f"{_MODULE}._RUNNER_SETTLE_TIMEOUT_SECONDS", 2.0),
            ):
                result = asyncio.run(cleanup_scan_resources("scan-1"))
        finally:
            for timer in timers:
                timer.cancel()

        assert unset_at_wait == [True]
        assert result["success"] is True
        registry.cancel_scan.assert_called_once_with("scan-1")
        registry.cleanup_scan.assert_called_once_with("scan-1")

    def test_a_cancelled_scan_whose_runner_still_stops_is_kept(
        self, registry, tmp_path
    ):
        """The file's own sequence: a cancel closed the entry, the runner keeps
        stopping, and only then is cleanup called. The wait is gated on
        has_runner and runner_done, not on the entry being RUNNING; an
        implementation that waited for RUNNING entries only would remove this
        scan's output while its runner restored the previous results."""
        entry = _entry(tmp_path, status=MCScanStatus.CANCELLED, has_runner=True)
        output = _output_of(entry)
        registry.get_scan.return_value = entry

        with _use(registry), patch(f"{_MODULE}._RUNNER_SETTLE_TIMEOUT_SECONDS", 0.05):
            result = asyncio.run(cleanup_scan_resources("scan-1", remove_output=True))

        assert result["success"] is False
        assert "still stopping" in result["message"]
        assert result["status"] == "cancelled"
        registry.cancel_scan.assert_not_called()
        registry.cleanup_scan.assert_not_called()
        assert output.exists()

    def test_a_scan_with_no_runner_is_not_waited_for(self, registry, tmp_path):
        """Measured at the wait itself, as the settles-during-the-wait test
        does: a patch of the module's ``asyncio.to_thread`` passed with no wait
        made (through run_in_executor, a from-import or a polling loop) and
        broke on any other use of to_thread in the call."""
        entry = _entry(tmp_path, status=MCScanStatus.COMPLETED, has_runner=False)
        registry.get_scan.return_value = entry
        waits = []
        entry.runner_done.wait = lambda timeout=None: waits.append(timeout) or True

        with _use(registry):
            result = asyncio.run(cleanup_scan_resources("scan-1"))

        assert result["success"] is True
        assert waits == []


class TestOutputSharedWithAnotherScanIsKept:
    def test_another_scans_output_is_not_removed(self, registry, tmp_path):
        entry = _entry(tmp_path, status=MCScanStatus.COMPLETED, has_runner=False)
        output = _output_of(entry)
        registry.get_scan.return_value = entry
        registry.remove_output_of_scan.side_effect = lambda entry, remover: (
            # The reason the real remove_output_of_scan gives for this case.
            ("another scan is running or stopping and shares this output directory"),
            False,
        )

        with _use(registry):
            result = asyncio.run(cleanup_scan_resources("scan-1", remove_output=True))

        assert result["success"] is True
        assert result["removed_from_registry"] is True
        assert result["removed_output"] is False
        assert "shares this output directory" in result["output_dir_error"]
        assert output.exists()
        registry.remove_output_of_scan.assert_called_once()
        assert registry.remove_output_of_scan.call_args.args[0] is entry

    def test_the_output_is_removed_when_no_other_scan_holds_the_directory(
        self, registry, tmp_path
    ):
        entry = _entry(tmp_path, status=MCScanStatus.COMPLETED, has_runner=False)
        output = _output_of(entry)
        registry.get_scan.return_value = entry

        with _use(registry):
            result = asyncio.run(cleanup_scan_resources("scan-1", remove_output=True))

        assert result["removed_output"] is True
        assert not output.exists()

    def test_the_delete_runs_inside_the_registrys_decision(self, registry, tmp_path):
        """The check and the delete are one call on the registry, so a scan
        registered between them waits on the entry's removal mark instead of
        losing its output; the remover is what the registry runs, not the
        caller."""
        entry = _entry(tmp_path, status=MCScanStatus.COMPLETED, has_runner=False)
        output = _output_of(entry)
        registry.get_scan.return_value = entry
        order = []

        def decide(entry, remover):
            order.append("check")
            assert output.exists()
            removed = remover()
            order.append("delete")
            return None, removed

        registry.remove_output_of_scan.side_effect = decide

        with _use(registry):
            result = asyncio.run(cleanup_scan_resources("scan-1", remove_output=True))

        assert order == ["check", "delete"]
        assert result["removed_output"] is True
        assert not output.exists()


class TestALinkOnTheOutputPathIsNotFollowed:
    def test_a_dot_ash_that_became_a_link_is_not_removed_through(
        self, registry, tmp_path
    ):
        if not hasattr(os, "symlink"):
            pytest.skip("symlinks are not available on this platform")
        entry = _entry(tmp_path, status=MCScanStatus.COMPLETED, has_runner=False)
        source = tmp_path / "src"
        elsewhere = tmp_path / "elsewhere"
        (elsewhere / "ash_output").mkdir(parents=True)
        (elsewhere / "ash_output" / "keep.txt").write_text("keep", encoding="utf-8")
        # After the scan, <source>/.ash is replaced by a link to another tree.
        try:
            (source / ".ash").symlink_to(elsewhere)
        except OSError:
            # hasattr(os, "symlink") is true on Windows too, where creating one
            # needs a privilege or Developer Mode (WinError 1314).
            pytest.skip("this platform refuses to create a symlink here")
        registry.get_scan.return_value = entry

        with _use(registry):
            result = asyncio.run(cleanup_scan_resources("scan-1", remove_output=True))

        assert result["removed_output"] is False
        assert "symbolic link" in result["output_dir_error"]
        assert (elsewhere / "ash_output" / "keep.txt").exists()

    def test_the_output_directory_itself_as_a_link_is_not_removed_through(
        self, registry, tmp_path
    ):
        if not hasattr(os, "symlink"):
            pytest.skip("symlinks are not available on this platform")
        entry = _entry(tmp_path, status=MCScanStatus.COMPLETED, has_runner=False)
        source = tmp_path / "src"
        (source / ".ash").mkdir()
        elsewhere = tmp_path / "elsewhere"
        elsewhere.mkdir()
        (elsewhere / "keep.txt").write_text("keep", encoding="utf-8")
        try:
            (source / ".ash" / "ash_output").symlink_to(elsewhere)
        except OSError:
            pytest.skip("this platform refuses to create a symlink here")
        registry.get_scan.return_value = entry

        with _use(registry):
            result = asyncio.run(cleanup_scan_resources("scan-1", remove_output=True))

        assert result["removed_output"] is False
        assert (elsewhere / "keep.txt").exists()

    def test_a_source_directory_that_is_a_retargeted_link_is_not_removed_through(
        self, registry, tmp_path
    ):
        """The lstat walk started below the source directory, so a source that
        was itself a link, retargeted after registration, still redirected the
        delete: resolving the stored path against the canonical directory does
        not."""
        if not hasattr(os, "symlink"):
            pytest.skip("symlinks are not available on this platform")
        real = tmp_path / "real"
        (real / ".ash" / "ash_output").mkdir(parents=True)
        link = tmp_path / "link"
        try:
            link.symlink_to(real)
        except OSError:
            pytest.skip("this platform refuses to create a symlink here")
        entry = ScanRegistryEntry(
            scan_id="scan-1",
            directory_path=str(link),
            output_directory=str(link / ".ash" / "ash_output"),
        )
        entry.status = MCScanStatus.COMPLETED
        entry.has_runner = False
        assert entry.canonical_directory == real.resolve()
        # After the scan, the link is pointed at an unrelated tree.
        elsewhere = tmp_path / "elsewhere"
        (elsewhere / ".ash" / "ash_output").mkdir(parents=True)
        (elsewhere / ".ash" / "ash_output" / "keep.txt").write_text(
            "keep", encoding="utf-8"
        )
        link.unlink()
        link.symlink_to(elsewhere)
        registry.get_scan.return_value = entry

        with _use(registry):
            result = asyncio.run(cleanup_scan_resources("scan-1", remove_output=True))

        assert result["removed_output"] is False
        assert "outside the output directory" in result["output_dir_error"]
        assert (elsewhere / ".ash" / "ash_output" / "keep.txt").exists()

    def test_a_workspace_projects_output_outside_its_directory_is_removed(
        self, registry, tmp_path
    ):
        """A workspace scan registers each project with an output directory
        under the workspace's output_dir (``<output_dir>/projects/<key>``,
        cli/mcp/workspace.py), not under the project's own directory. Compared
        against the scanned directory, that output never resolved "inside" and
        every workspace entry's cleanup refused the removal, blaming a symbolic
        link that was not there; compared against the registered output
        directory, it is removed."""
        project = tmp_path / "ws" / "proj"
        project.mkdir(parents=True)
        output = tmp_path / "ws" / ".ash" / "ash_output" / "projects" / "proj-key"
        output.mkdir(parents=True)
        (output / "ash_aggregated_results.json").write_text("{}", encoding="utf-8")
        entry = ScanRegistryEntry(
            scan_id="scan-1",
            directory_path=str(project),
            output_directory=str(output),
        )
        entry.status = MCScanStatus.COMPLETED
        entry.has_runner = False
        registry.get_scan.return_value = entry

        with _use(registry):
            result = asyncio.run(cleanup_scan_resources("scan-1", remove_output=True))

        assert result["removed_output"] is True
        assert result.get("output_dir_error") is None
        assert not output.exists()
        assert project.exists()

    def test_a_workspace_projects_directory_that_became_a_link_is_not_removed_through(
        self, registry, tmp_path
    ):
        """The same fail-closed shape for the workspace layout: a ``projects``
        component that became a link after registration redirects the stored
        path outside the registered output tree, and nothing is removed."""
        if not hasattr(os, "symlink"):
            pytest.skip("symlinks are not available on this platform")
        project = tmp_path / "ws" / "proj"
        project.mkdir(parents=True)
        ash_output = tmp_path / "ws" / ".ash" / "ash_output"
        (ash_output / "projects" / "proj-key").mkdir(parents=True)
        entry = ScanRegistryEntry(
            scan_id="scan-1",
            directory_path=str(project),
            output_directory=str(ash_output / "projects" / "proj-key"),
        )
        entry.status = MCScanStatus.COMPLETED
        entry.has_runner = False
        # After registration, `projects` is replaced by a link to another tree.
        elsewhere = tmp_path / "elsewhere"
        (elsewhere / "proj-key").mkdir(parents=True)
        (elsewhere / "proj-key" / "keep.txt").write_text("keep", encoding="utf-8")
        shutil.rmtree(ash_output / "projects")
        try:
            (ash_output / "projects").symlink_to(elsewhere)
        except OSError:
            pytest.skip("this platform refuses to create a symlink here")
        registry.get_scan.return_value = entry

        with _use(registry):
            result = asyncio.run(cleanup_scan_resources("scan-1", remove_output=True))

        assert result["removed_output"] is False
        assert "outside the output directory" in result["output_dir_error"]
        assert (elsewhere / "proj-key" / "keep.txt").exists()

    def test_a_real_output_tree_is_still_removed(self, registry, tmp_path):
        entry = _entry(tmp_path, status=MCScanStatus.COMPLETED, has_runner=False)
        output = _output_of(entry)
        registry.get_scan.return_value = entry

        with _use(registry):
            result = asyncio.run(cleanup_scan_resources("scan-1", remove_output=True))

        assert result["removed_output"] is True
        assert not output.exists()


BANDIT_PID = 4242


class TestASurvivingToolKeepsTheTree:
    """A cancel that could not end a scanner tool leaves the tool writing into the
    output directory after the runner has finished (``could_not_stop``). The
    cleanup waited for the runner only and asked the registry only whether OTHER
    scans held the tree, so the tree came down under the writing tool;
    ``cleanup_scan`` then refused the unregister (it keeps such an entry), and
    the caller read ``removed_output`` True beside ``removed_from_registry``
    False with a generic message. It is handed back as still stopping, with the
    tool named and nothing removed, as the docstring promises."""

    @pytest.fixture
    def alive(self, monkeypatch):
        """Which pids the probe reports running; a pid not listed is gone."""
        table = {}
        monkeypatch.setattr(
            scan_registry, "_tool_may_be_running", lambda pid: table.get(pid, False)
        )
        return table

    @staticmethod
    def _stopped_with_a_surviving_tool(tmp_path):
        entry = _entry(tmp_path, status=MCScanStatus.CANCELLED, has_runner=True)
        entry.runner_done.set()
        entry.could_not_stop = (("bandit", BANDIT_PID),)
        return entry

    def test_nothing_is_removed_while_the_tool_runs(self, registry, tmp_path, alive):
        alive[BANDIT_PID] = True
        entry = self._stopped_with_a_surviving_tool(tmp_path)
        output = _output_of(entry)
        registry.get_scan.return_value = entry

        with _use(registry):
            result = asyncio.run(cleanup_scan_resources("scan-1", remove_output=True))

        assert result["success"] is False
        assert result["removed_output"] is False
        assert result["removed_from_registry"] is False
        assert "still stopping" in result["message"]
        assert "bandit" in result["message"]
        assert result["status"] == "cancelled"
        assert output.exists()
        registry.remove_output_of_scan.assert_not_called()
        registry.cleanup_scan.assert_not_called()

    def test_the_tool_is_named_by_basename_not_by_the_servers_path(
        self, registry, tmp_path, alive
    ):
        """The tool is recorded as argv0 as spawned, which can be the server's
        full path; this message reaches a remote MCP client, so it names the
        tool as record_cancel_outcome does on a network transport: by basename,
        with no path and no pid."""
        alive[BANDIT_PID] = True
        entry = self._stopped_with_a_surviving_tool(tmp_path)
        entry.could_not_stop = (("/opt/tools/bin/bandit", BANDIT_PID),)
        registry.get_scan.return_value = entry

        with _use(registry):
            result = asyncio.run(cleanup_scan_resources("scan-1", remove_output=True))

        assert "still stopping" in result["message"]
        assert "bandit" in result["message"]
        assert "/opt/tools" not in result["message"]
        assert str(BANDIT_PID) not in result["message"]

    def test_the_scan_is_cleaned_up_once_the_tool_is_gone(
        self, registry, tmp_path, alive
    ):
        entry = self._stopped_with_a_surviving_tool(tmp_path)
        output = _output_of(entry)
        registry.get_scan.return_value = entry

        with _use(registry):
            result = asyncio.run(cleanup_scan_resources("scan-1", remove_output=True))

        assert result["success"] is True
        assert result["removed_output"] is True
        assert not output.exists()
        registry.cleanup_scan.assert_called_once_with("scan-1")


class TestTheProgressReadPassesTheTransportsWord:
    def test_name_process_ids_reaches_the_registry(self, registry):
        registry.check_scan_progress.return_value = {"success": True}

        with _use(registry):
            result = asyncio.run(check_scan_progress("scan-1", name_process_ids=False))

        assert result == {"success": True}
        registry.check_scan_progress.assert_called_once_with(
            "scan-1", name_process_ids=False
        )

    def test_the_default_names_them(self, registry):
        registry.check_scan_progress.return_value = {"success": True}

        with _use(registry):
            asyncio.run(check_scan_progress("scan-1"))

        registry.check_scan_progress.assert_called_once_with(
            "scan-1", name_process_ids=True
        )


class TestTheEntryIsReadAgainAfterTheWait:
    """The cancel and the runner wait both give up control. A cleanup of the same
    scan that ran meanwhile removed the entry; this call then went on with the
    stale object: it marked and deleted the output of an entry the registry no
    longer held, so a ``register_scan`` of the same tree found no mark and was
    admitted into a tree being deleted, and the unregister found nothing."""

    def test_a_scan_removed_during_the_wait_is_reported_not_found(
        self, registry, tmp_path
    ):
        entry = _entry(tmp_path, status=MCScanStatus.CANCELLED, has_runner=True)
        output = _output_of(entry)
        registry.get_scan.return_value = entry

        def settle_and_vanish(timeout=None):
            # The runner settles, and by then the concurrent cleanup has
            # removed the entry from the registry.
            entry.runner_done.set()
            registry.get_scan.return_value = None
            return True

        entry.runner_done.wait = settle_and_vanish

        with _use(registry), patch(f"{_MODULE}._RUNNER_SETTLE_TIMEOUT_SECONDS", 2.0):
            result = asyncio.run(cleanup_scan_resources("scan-1", remove_output=True))

        assert result["success"] is False
        assert result["error_category"] == ErrorCategory.SCAN_NOT_FOUND.value
        assert output.exists()
        registry.remove_output_of_scan.assert_not_called()
        registry.cleanup_scan.assert_not_called()

    def test_the_entry_read_after_the_wait_is_the_one_acted_on(
        self, registry, tmp_path
    ):
        """The second read is what the removal and the unregister work from."""
        stale = _entry(tmp_path, status=MCScanStatus.CANCELLED, has_runner=True)
        output = _output_of(stale)
        current = _entry(tmp_path, status=MCScanStatus.CANCELLED, has_runner=True)
        current.runner_done.set()
        registry.get_scan.return_value = stale

        def settle(timeout=None):
            stale.runner_done.set()
            registry.get_scan.return_value = current
            return True

        stale.runner_done.wait = settle

        with _use(registry), patch(f"{_MODULE}._RUNNER_SETTLE_TIMEOUT_SECONDS", 2.0):
            result = asyncio.run(cleanup_scan_resources("scan-1", remove_output=True))

        assert result["success"] is True
        assert registry.remove_output_of_scan.call_args.args[0] is current
        assert not output.exists()
