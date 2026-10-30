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
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from automated_security_helper.core.resource_management.scan_management import (
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
    # The real method runs the remover under the registry lock unless another
    # scan holds the directory; the double admits by default and runs it.
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
        entry = _entry(tmp_path)
        registry.get_scan.return_value = entry
        registry.cancel_scan.side_effect = lambda scan_id: entry.runner_done.set()

        with _use(registry):
            result = asyncio.run(cleanup_scan_resources("scan-1"))

        assert result["success"] is True
        registry.cleanup_scan.assert_called_once_with("scan-1")

    def test_a_scan_with_no_runner_is_not_waited_for(self, registry, tmp_path):
        entry = _entry(tmp_path, status=MCScanStatus.COMPLETED, has_runner=False)
        registry.get_scan.return_value = entry

        with _use(registry), patch(f"{_MODULE}.asyncio.to_thread") as to_thread:
            result = asyncio.run(cleanup_scan_resources("scan-1"))

        assert result["success"] is True
        to_thread.assert_not_called()


class TestOutputSharedWithAnotherScanIsKept:
    def test_another_scans_output_is_not_removed(self, registry, tmp_path):
        entry = _entry(tmp_path, status=MCScanStatus.COMPLETED, has_runner=False)
        output = _output_of(entry)
        registry.get_scan.return_value = entry
        registry.remove_output_of_scan.side_effect = lambda entry, remover: (
            (
                "another scan of the same directory is running or stopping and "
                "shares this output directory"
            ),
            False,
        )

        with _use(registry):
            result = asyncio.run(cleanup_scan_resources("scan-1", remove_output=True))

        assert result["success"] is True
        assert result["removed_from_registry"] is True
        assert result["removed_output"] is False
        assert "another scan of the same directory" in result["output_dir_error"]
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
        registered between them waits on the registry lock instead of losing
        its output; the remover is what the registry runs, not the caller."""
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
        (source / ".ash").symlink_to(elsewhere)
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
        (source / ".ash" / "ash_output").symlink_to(elsewhere)
        registry.get_scan.return_value = entry

        with _use(registry):
            result = asyncio.run(cleanup_scan_resources("scan-1", remove_output=True))

        assert result["removed_output"] is False
        assert (elsewhere / "keep.txt").exists()

    def test_a_real_output_tree_is_still_removed(self, registry, tmp_path):
        entry = _entry(tmp_path, status=MCScanStatus.COMPLETED, has_runner=False)
        output = _output_of(entry)
        registry.get_scan.return_value = entry

        with _use(registry):
            result = asyncio.run(cleanup_scan_resources("scan-1", remove_output=True))

        assert result["removed_output"] is True
        assert not output.exists()
