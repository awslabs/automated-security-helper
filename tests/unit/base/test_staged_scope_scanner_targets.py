# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The scanner side of ``--mode precommit --staged``.

A template scanner with a staged scope in its context either gets the staged
files as its tool's targets (``staged_target_style``) or, when none of them is
something it scans (``staged_scope_patterns``), is skipped before the tool
starts, in the same clean shape as an empty target directory. Without a staged
scope in the context nothing changes, which is what keeps the flag opt-in.
"""

from __future__ import annotations

from pathlib import Path
from typing import ClassVar, Literal, Optional, Tuple

import pytest

from automated_security_helper.base.scanner_plugin import (
    ScannerPluginBase,
    ScannerPluginConfigBase,
)
from automated_security_helper.core.enums import OfflineStrategy, ScannerToolType

pytestmark = pytest.mark.unit


class _Config(ScannerPluginConfigBase):
    name: Literal["staged-stub"] = "staged-stub"


def _scanner(
    plugin_context,
    patterns: Optional[Tuple[str, ...]] = None,
    style: Optional[str] = None,
    flag: str = "--file",
):
    class StagedStubScanner(ScannerPluginBase):
        offline_strategy: ClassVar[OfflineStrategy] = OfflineStrategy.BUNDLED
        staged_scope_patterns: ClassVar[Optional[Tuple[str, ...]]] = patterns
        staged_target_style: ClassVar[Optional[str]] = style
        staged_target_flag: ClassVar[str] = flag

        def model_post_init(self, context):
            self.command = "stub-tool"
            self.tool_type = ScannerToolType.SAST
            super().model_post_init(context)

        def validate_plugin_dependencies(self) -> bool:
            return True

        def _execute_scan(self, target, target_type, global_ignore_paths):
            raise AssertionError("the tool must not be started by these tests")

    return StagedStubScanner(config=_Config(), context=plugin_context)


def _target_with(plugin_context, *names: str) -> Path:
    target = plugin_context.source_dir
    for name in names:
        path = target / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("x = 1\n")
    return target


class TestSkipWhenNothingStagedMatches:
    def test_the_tool_is_not_run_and_the_reason_says_staged(self, plugin_context):
        plugin_context.staged_files = ["notes.md"]
        scanner = _scanner(plugin_context, patterns=("*.py",))
        target = _target_with(plugin_context, "app.py", "notes.md")

        result = scanner.scan(target=target, target_type="source")

        assert result is True
        assert "skipped under --staged" in (scanner._nothing_scanned_reason or "")

    def test_a_staged_file_deleted_from_disk_is_not_a_target(self, plugin_context):
        """Staged, then removed from the working tree: there is nothing to hand
        the tool, so the scanner skips rather than failing on a missing path."""
        plugin_context.staged_files = ["gone.py"]
        scanner = _scanner(plugin_context, patterns=("*.py",))
        target = _target_with(plugin_context, "present.md")

        assert scanner.scan(target=target, target_type="source") is True
        assert "skipped under --staged" in (scanner._nothing_scanned_reason or "")

    def test_the_converted_target_is_outside_the_staged_scope(self, plugin_context):
        """The converted tree holds what the converters made from staged inputs
        already, so the scope does not second-guess it: no skip, no file list."""
        plugin_context.staged_files = ["notes.md"]
        scanner = _scanner(plugin_context, patterns=("*.py",))
        assert scanner._staged_scope_paths(plugin_context.work_dir, "converted") is None

    def test_without_a_staged_scope_nothing_is_decided(self, plugin_context):
        scanner = _scanner(plugin_context, patterns=("*.py",))
        target = _target_with(plugin_context, "app.py")
        assert scanner._staged_scope_paths(target, "source") is None


class TestFileListTargets:
    def test_positional_style_replaces_the_directory_with_the_staged_files(
        self, plugin_context
    ):
        plugin_context.staged_files = ["pkg/app.py", "notes.md"]
        scanner = _scanner(plugin_context, patterns=("*.py",), style="positional")
        target = _target_with(plugin_context, "pkg/app.py", "notes.md")

        files = scanner._staged_scope_paths(target, "source")
        assert [f.name for f in files] == ["app.py"]

        scanner._staged_scan_files = files
        argv = scanner._resolve_arguments(target)
        assert (target / "pkg" / "app.py").as_posix() in argv
        assert target.as_posix() not in argv, "the directory target is replaced"

    def test_per_file_flag_style_repeats_the_flag_before_each_file(
        self, plugin_context
    ):
        plugin_context.staged_files = ["a.tf", "b.tf"]
        scanner = _scanner(plugin_context, style="per-file-flag", flag="--file")
        target = _target_with(plugin_context, "a.tf", "b.tf")

        scanner._staged_scan_files = scanner._staged_scope_paths(target, "source")
        argv = scanner._resolve_arguments(target)
        first = argv.index("--file")
        assert argv[first + 1].endswith("a.tf")
        assert argv[first + 2] == "--file"
        assert argv[first + 3].endswith("b.tf")
        assert target.as_posix() not in argv

    def test_without_staged_files_the_argv_keeps_the_directory_target(
        self, plugin_context
    ):
        scanner = _scanner(plugin_context, patterns=("*.py",), style="positional")
        target = _target_with(plugin_context, "app.py")
        argv = scanner._resolve_arguments(target)
        assert target.as_posix() in argv


class TestShippedDeclarations:
    """Drift guards: the two precommit scanners that take file targets declare
    the shapes this unit shipped; the scan-set readers declare none and ride the
    restricted scan set instead."""

    def test_bandit_takes_staged_python_files_positionally(self):
        from automated_security_helper.plugin_modules.ash_builtin.scanners.bandit_scanner import (
            BanditScanner,
        )

        assert BanditScanner.staged_scope_patterns == ("*.py",)
        assert BanditScanner.staged_target_style == "positional"

    def test_checkov_takes_every_staged_file_behind_file_flags(self):
        from automated_security_helper.plugin_modules.ash_builtin.scanners.checkov_scanner import (
            CheckovScanner,
        )

        assert CheckovScanner.staged_scope_patterns is None
        assert CheckovScanner.staged_target_style == "per-file-flag"
        assert CheckovScanner.staged_target_flag == "--file"
