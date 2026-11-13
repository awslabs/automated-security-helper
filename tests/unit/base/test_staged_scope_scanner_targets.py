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
    max_files: Optional[int] = None,
    execute=None,
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
            if execute is None:
                raise AssertionError("the tool must not be started by these tests")
            return execute(self, target, target_type, global_ignore_paths)

    if max_files is not None:
        StagedStubScanner._STAGED_TARGET_MAX_FILES = max_files
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


class TestScanSetFiltering:
    """The staged targets honor the same filters as the whole-tree scan set:
    a force-added ignored file and a staged symlink must never become a
    file-target scanner's input."""

    def test_a_staged_gitignored_file_is_not_a_target(self, plugin_context):
        (plugin_context.source_dir / ".gitignore").write_text("ignored.py\n")
        plugin_context.staged_files = ["app.py", "ignored.py"]
        scanner = _scanner(plugin_context, patterns=("*.py",), style="positional")
        target = _target_with(plugin_context, "app.py", "ignored.py")

        files = scanner._staged_scope_paths(target, "source")

        assert [f.name for f in files] == ["app.py"]

    def test_all_staged_matches_filtered_out_say_so_not_nothing_matches(
        self, plugin_context
    ):
        """Distinct reasons: files that matched and were all left out by the
        run's scan set must never pass as "no staged file matches", or a filter
        defect (a spelling mismatch) could silently skip a scanner."""
        (plugin_context.source_dir / ".gitignore").write_text("ignored.py\n")
        plugin_context.staged_files = ["ignored.py"]
        scanner = _scanner(plugin_context, patterns=("*.py",), style="positional")
        target = _target_with(plugin_context, "ignored.py", "unrelated.md")

        assert scanner.scan(target=target, target_type="source") is True
        reason = scanner._nothing_scanned_reason or ""
        assert "leaves every one of them out" in reason
        assert "no staged file matches" not in reason

    def test_a_staged_symlink_is_not_a_target(self, plugin_context, tmp_path):
        outside = tmp_path / "outside.py"
        outside.write_text("x = 1\n")
        plugin_context.staged_files = ["link.py", "app.py"]
        scanner = _scanner(plugin_context, patterns=("*.py",), style="positional")
        target = _target_with(plugin_context, "app.py")
        (target / "link.py").symlink_to(outside)

        files = scanner._staged_scope_paths(target, "source")

        assert [f.name for f in files] == ["app.py"]


class TestArgvBound:
    """Past the bound the staged files are not put on argv: a mass change must
    not make the tool fail to start (ARG_MAX; ~32 KB on Windows). The scanner
    falls back to the directory target instead."""

    def test_more_files_than_the_bound_do_not_fit(self, plugin_context):
        scanner = _scanner(plugin_context, patterns=("*.py",), style="positional")
        many = [Path(f"/x/f{index}.py") for index in range(501)]
        assert scanner._staged_targets_fit(many) is False

    def test_argv_bytes_over_the_bound_do_not_fit(self, plugin_context):
        scanner = _scanner(plugin_context, patterns=("*.py",), style="positional")
        long_paths = [Path("/x/" + "a" * 300 + f"{index}.py") for index in range(100)]
        assert scanner._staged_targets_fit(long_paths) is False

    def test_a_small_set_fits(self, plugin_context):
        scanner = _scanner(plugin_context, patterns=("*.py",), style="positional")
        assert scanner._staged_targets_fit([Path("/x/a.py"), Path("/x/b.py")]) is True

    def test_over_the_bound_scans_the_directory_target(self, plugin_context):
        """The wiring: over the bound, _execute_scan sees no staged file list,
        so _resolve_arguments keeps the directory target; under it, it sees the
        list. The execute stub records what the scan was about to use and stops
        the scan there; what it recorded is the assertion, not the scan's end."""
        recorded = {}

        def record_and_stop(scanner, target, target_type, global_ignore_paths):
            recorded["staged"] = scanner._staged_scan_files
            raise RuntimeError("recorded; the tool itself is not under test")

        plugin_context.staged_files = ["a.py", "b.py"]
        target = _target_with(plugin_context, "a.py", "b.py")

        over = _scanner(
            plugin_context,
            patterns=("*.py",),
            style="positional",
            max_files=1,
            execute=record_and_stop,
        )
        try:
            over.scan(target=target, target_type="source")
        except BaseException:
            pass
        assert recorded["staged"] is None

        under = _scanner(
            plugin_context,
            patterns=("*.py",),
            style="positional",
            execute=record_and_stop,
        )
        try:
            under.scan(target=target, target_type="source")
        except BaseException:
            pass
        assert [f.name for f in recorded["staged"]] == ["a.py", "b.py"]


def _checkov(plugin_context):
    from automated_security_helper.plugin_modules.ash_builtin.scanners.checkov_scanner import (
        CheckovScanner,
    )

    return CheckovScanner(context=plugin_context)


class TestCheckovStagedShape:
    """checkov's staged shape: skip on a commit with nothing it reads, pull in
    a staged Terraform file's SAME-DIRECTORY siblings as extra file targets
    (variables/locals context), and never a directory target: --directory
    recurses, so a staged root main.tf became a full-tree scan."""

    def test_a_readme_only_commit_has_nothing_for_checkov(self, plugin_context):
        plugin_context.staged_files = ["README.md"]
        scanner = _checkov(plugin_context)
        target = plugin_context.source_dir
        (target / "README.md").write_text("docs\n")

        assert scanner._staged_scope_paths(target, "source") == []

    def test_a_staged_root_terraform_file_never_targets_the_whole_tree(
        self, plugin_context
    ):
        plugin_context.staged_files = ["main.tf"]
        scanner = _checkov(plugin_context)
        target = _target_with(
            plugin_context, "main.tf", "variables.tf", "modules/deep.tf", "app.py"
        )

        staged = scanner._staged_scope_paths(target, "source")

        assert set(staged) == {target / "main.tf", target / "variables.tf"}
        assert target not in staged, "--directory on the source root is a full tree"
        assert target / "modules" / "deep.tf" not in staged, "nothing recurses"
        argv = scanner._staged_target_arguments(staged)
        assert "--directory" not in argv
        assert argv.count("--file") == len(staged)

    def test_a_nested_terraform_file_pulls_its_own_dir_siblings_only(
        self, plugin_context
    ):
        plugin_context.staged_files = ["infra/main.tf"]
        scanner = _checkov(plugin_context)
        target = _target_with(
            plugin_context,
            "infra/main.tf",
            "infra/variables.tf",
            "infra/modules/deep.tf",
        )

        staged = scanner._staged_scope_paths(target, "source")

        assert set(staged) == {
            target / "infra" / "main.tf",
            target / "infra" / "variables.tf",
        }

    def test_overlapping_staged_entries_target_each_file_once(self, plugin_context):
        plugin_context.staged_files = ["modules/a.tf", "modules/cfg.yaml"]
        scanner = _checkov(plugin_context)
        target = _target_with(
            plugin_context, "modules/a.tf", "modules/b.tf", "modules/cfg.yaml"
        )

        staged = scanner._staged_scope_paths(target, "source")
        argv = scanner._staged_target_arguments(staged)

        assert len(staged) == len(set(staged)), "no file is targeted twice"
        assert set(staged) == {
            target / "modules" / "a.tf",
            target / "modules" / "b.tf",
            target / "modules" / "cfg.yaml",
        }
        assert argv.count((target / "modules" / "cfg.yaml").as_posix()) == 1

    def test_terraform_detection_is_case_insensitive(self, plugin_context):
        plugin_context.staged_files = ["Main.TF"]
        scanner = _checkov(plugin_context)
        target = _target_with(plugin_context, "Main.TF", "other.tf")

        staged = scanner._staged_scope_paths(target, "source")

        assert set(staged) == {target / "Main.TF", target / "other.tf"}

    def test_an_ignored_sibling_is_not_brought_back_in(self, plugin_context):
        (plugin_context.source_dir / ".gitignore").write_text("secret.tfvars\n")
        plugin_context.staged_files = ["main.tf"]
        scanner = _checkov(plugin_context)
        target = _target_with(plugin_context, "main.tf", "secret.tfvars")

        staged = scanner._staged_scope_paths(target, "source")

        assert set(staged) == {target / "main.tf"}


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

    def test_checkov_takes_matching_staged_files_behind_file_flags(self):
        from automated_security_helper.plugin_modules.ash_builtin.scanners.checkov_scanner import (
            CheckovScanner,
        )

        patterns = CheckovScanner.staged_scope_patterns
        assert patterns is not None, (
            "checkov declares what it reads, so a commit staging none of it "
            "skips checkov's startup"
        )
        for expected in ("*.tf", "*.tfvars", "*.yaml", "*.yml", "*.json", "*.bicep"):
            assert expected in patterns
        assert CheckovScanner.staged_target_style == "per-file-flag"
        assert CheckovScanner.staged_target_flag == "--file"
        assert CheckovScanner._STAGED_TERRAFORM_SUFFIXES == (
            ".tf",
            ".tfvars",
            ".tf.json",
        )
