# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A single scan and a workspace's projects share one output tree, whichever came first.

A workspace scan writes each project under ``<root>/projects/<key>`` and asks
``scan_writing_within`` about the root before it registers anything, so a live
single scan of the root, inside it or above it refuses the workspace. The
registry itself compared output directories by equality, so the other order went
unchecked: a single scan aimed at the root, registered after the workspace's
projects, was admitted and wrote beside them, and the removal of a single scan's
tree was not refused while a project wrote under it.

Registration and removal now ask the registry's tree question
(``_shares_an_output_tree``) as ``scan_writing_within`` does.
"""

from __future__ import annotations

import pytest

from automated_security_helper.core.resource_management.exceptions import (
    MCPResourceError,
)
from automated_security_helper.core.resource_management.scan_registry import (
    MCScanStatus,
    ScanRegistry,
)

pytestmark = pytest.mark.unit


def _source(tmp_path, name):
    source = tmp_path / "src" / name
    source.mkdir(parents=True)
    return source


def _register(registry, tmp_path, name, output):
    return registry.register_scan(
        directory_path=str(_source(tmp_path, name)), output_directory=str(output)
    )


class TestARegistrationSharesTheTreeWithEveryLiveScan:
    def test_a_scan_of_the_root_is_refused_while_a_project_writes_under_it(
        self, tmp_path
    ):
        registry = ScanRegistry()
        root = tmp_path / "out"
        _register(registry, tmp_path, "web", root / "projects" / "web")

        # RED at the base: the project's output differs from the root, so the
        # exact-equality compare admitted the second scan into the shared tree.
        with pytest.raises(MCPResourceError, match="in use by a scan"):
            _register(registry, tmp_path, "whole", root)

    def test_a_scan_inside_the_tree_of_a_live_scan_is_refused(self, tmp_path):
        registry = ScanRegistry()
        root = tmp_path / "out"
        _register(registry, tmp_path, "whole", root)

        # RED at the base, for the same reason.
        with pytest.raises(MCPResourceError, match="in use by a scan"):
            _register(registry, tmp_path, "web", root / "projects" / "web")

    def test_a_sibling_project_and_a_prefix_sibling_are_admitted(self, tmp_path):
        """Control, green on both sides: by path component, never by prefix."""
        registry = ScanRegistry()
        root = tmp_path / "out"
        _register(registry, tmp_path, "web", root / "projects" / "web")

        assert _register(registry, tmp_path, "api", root / "projects" / "api")
        assert _register(registry, tmp_path, "other", tmp_path / "out-backup")

    def test_a_scan_that_has_ended_no_longer_holds_the_tree(self, tmp_path):
        """Control, green on both sides: only a scan that occupies its tree counts."""
        registry = ScanRegistry()
        root = tmp_path / "out"
        web = _register(registry, tmp_path, "web", root / "projects" / "web")
        registry.update_scan_status(web, MCScanStatus.COMPLETED)

        assert _register(registry, tmp_path, "whole", root)


class TestARemovalSharesTheTreeWithEveryLiveScan:
    def test_the_removal_of_a_root_is_refused_while_a_project_writes_under_it(
        self, tmp_path
    ):
        registry = ScanRegistry()
        root = tmp_path / "out"
        whole = _register(registry, tmp_path, "whole", root)
        registry.update_scan_status(whole, MCScanStatus.COMPLETED)
        _register(registry, tmp_path, "web", root / "projects" / "web")
        removed = []

        reason, done = registry.remove_output_of_scan(
            registry.get_scan(whole), lambda: removed.append(True) or True
        )

        # RED at the base: the project's output differs from the root, so the
        # remover ran and deleted the tree the project was writing.
        assert done is False
        assert removed == []
        assert "shares this output directory" in reason

    def test_the_removal_of_an_unrelated_tree_runs(self, tmp_path):
        """Control, green on both sides."""
        registry = ScanRegistry()
        whole = _register(registry, tmp_path, "whole", tmp_path / "out")
        registry.update_scan_status(whole, MCScanStatus.COMPLETED)
        _register(registry, tmp_path, "web", tmp_path / "out-backup")

        reason, done = registry.remove_output_of_scan(
            registry.get_scan(whole), lambda: True
        )

        assert reason is None
        assert done is True


class TestARemovalKeepsTheResultsOfALaterScanNestedInTheTree:
    """A project that ran under a finished root scan's tree holds results there."""

    def test_the_removal_of_a_root_is_refused_once_a_nested_project_completed(
        self, tmp_path
    ):
        registry = ScanRegistry()
        root = tmp_path / "out"
        whole = _register(registry, tmp_path, "whole", root)
        registry.update_scan_status(whole, MCScanStatus.COMPLETED)
        web = _register(registry, tmp_path, "web", root / "projects" / "web")
        registry.update_scan_status(web, MCScanStatus.RUNNING)
        registry.update_scan_status(web, MCScanStatus.COMPLETED)
        removed = []

        reason, done = registry.remove_output_of_scan(
            registry.get_scan(whole), lambda: removed.append(True) or True
        )

        # RED at the base: the project is not running, so the live-scan arm
        # passes, and its id was never recorded on the root scan (supersession
        # was recorded by exact directory), so the later-scan arm passed too and
        # the remover deleted the completed project's results.
        assert done is False
        assert removed == []
        assert "a later scan holds its results" in reason

    def test_a_nested_project_that_never_ran_does_not_refuse_the_removal(
        self, tmp_path
    ):
        """Control, green on both sides: a scan that claimed nothing holds nothing."""
        registry = ScanRegistry()
        root = tmp_path / "out"
        whole = _register(registry, tmp_path, "whole", root)
        registry.update_scan_status(whole, MCScanStatus.COMPLETED)
        web = _register(registry, tmp_path, "web", root / "projects" / "web")
        registry.update_scan_status(web, MCScanStatus.CANCELLED)

        reason, done = registry.remove_output_of_scan(
            registry.get_scan(whole), lambda: True
        )

        assert reason is None
        assert done is True

    def test_the_root_scans_own_results_are_not_read_as_superseded(self, tmp_path):
        """Control, green on both sides: a project under the root does not write
        the root's files, so the progress record stays an exact-directory one."""
        registry = ScanRegistry()
        root = tmp_path / "out"
        whole = _register(registry, tmp_path, "whole", root)
        registry.update_scan_status(whole, MCScanStatus.COMPLETED)
        web = _register(registry, tmp_path, "web", root / "projects" / "web")
        registry.update_scan_status(web, MCScanStatus.COMPLETED)

        assert registry.get_scan(whole).later_scan_ids == []
