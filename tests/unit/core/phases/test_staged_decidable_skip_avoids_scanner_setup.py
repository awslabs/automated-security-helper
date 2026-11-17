# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A decidable staged skip costs a commit no scanner setup.

Under ``--mode precommit --staged``, a scanner that declares
``staged_scope_patterns`` (bandit, checkov) already skips its source scan when
no staged file matches -- but only inside ``scan()``, AFTER its dependency
check has run, so a docs-only commit still paid for the version probes of
tools that were never going to start. The decision is decidable earlier: the
convert phase has run, so with no staged match and an empty converted tree
there is nothing such a scanner could scan.

What must hold, and what these tests pin:

* decidably nothing -> SKIPPED without the dependency check running, with the
  same row ``scan()``'s own staged skip produces (targets_attempted 0, not
  excluded, dependencies satisfied), and the completeness gate unchanged;
* a staged match, a non-empty converted tree, or no staged scope at all ->
  the dependency check runs exactly as today (the conservative side: the skip
  may only fire when the answer is a fact, never a prediction);
* the absent-tool case reads SKIPPED, not MISSING: the dependency-failure
  arm's own documented rule ("a scanner with nothing to scan loses this scan
  nothing by lacking its tool"), applied as soon as the answer is decidable.
  Before this change bandit and checkov could not answer
  ``nothing_to_scan_reason`` and were MISSING there, so a docs-only commit on
  a machine without their tools failed the hook for tools it did not need.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.constants import ASH_WORK_DIR_NAME
from automated_security_helper.core.enums import ScannerStatus
from automated_security_helper.core.phases.scan_phase import ScanPhase
from automated_security_helper.core.unified_metrics import (
    populate_metrics_from_unified_source,
)
from automated_security_helper.interactions.run_ash_scan import incomplete_scanners
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.plugin_modules.ash_builtin.scanners.bandit_scanner import (
    BanditScanner,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.checkov_scanner import (
    CheckovScanner,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.detect_secrets_scanner import (
    DetectSecretsScanner,
)
from automated_security_helper.utils.staged_files import tree_holds_a_file

pytestmark = pytest.mark.unit

AshConfig.model_rebuild()
AshAggregatedResults.model_rebuild()


#: One recording slot per test: which scanner classes had their dependency
#: check asked. The class is built per test, so no state crosses tests.
def _recording(scanner_class, calls: list, answer: bool = False):
    """The real scanner class, its dependency check recording and answering
    *answer*. False keeps the scanner off the execution path (MISSING or
    SKIPPED, as the phase grades it), which is all these tests need."""

    class _Recorded(scanner_class):
        def validate_plugin_dependencies(self) -> bool:
            calls.append(scanner_class.__name__)
            return answer

    _Recorded.__name__ = scanner_class.__name__
    _Recorded.__module__ = scanner_class.__module__
    return _Recorded


def _context(tmp_path: Path, staged) -> PluginContext:
    source = tmp_path / "source"
    source.mkdir(exist_ok=True)
    (source / "README.md").write_text("# docs\n", encoding="utf-8")
    output = tmp_path / "output"
    (output / ASH_WORK_DIR_NAME).mkdir(parents=True, exist_ok=True)
    return PluginContext(
        source_dir=source,
        output_dir=output,
        work_dir=output / ASH_WORK_DIR_NAME,
        config=get_default_config(),
        staged_files=staged,
    )


def _scan(context, plugins) -> AshAggregatedResults:
    aggregated = AshAggregatedResults()
    phase = ScanPhase(
        plugin_context=context,
        plugins=plugins,
        progress_display=MagicMock(),
        asharp_model=aggregated,
    )
    results = phase._execute_phase(aggregated_results=aggregated, parallel=False)
    return populate_metrics_from_unified_source(aggregated_results=results)


class TestDecidableStagedSkipAvoidsSetup:
    def test_a_docs_only_commit_skips_bandit_without_its_dependency_check(
        self, tmp_path
    ):
        calls: list = []
        context = _context(tmp_path, staged=["README.md"])

        results = _scan(context, [_recording(BanditScanner, calls)])

        assert calls == [], (
            "the skip is decidable before setup, so the dependency check "
            f"must not run: {calls}"
        )
        row = results.scanner_results["bandit"]
        assert row.status == ScannerStatus.SKIPPED, row
        assert row.excluded is False, "nothing deselected it"
        assert row.dependencies_satisfied is True, row
        assert "--staged" in (row.skipped_reason or ""), row.skipped_reason
        assert incomplete_scanners(results) == []

    def test_the_absent_tool_reads_skipped_not_missing(self, tmp_path):
        """The dependency-failure arm's rule, applied pre-setup: a decidably
        target-free scanner loses this commit nothing by lacking its tool."""
        calls: list = []
        context = _context(tmp_path, staged=["README.md"])

        results = _scan(context, [_recording(BanditScanner, calls, answer=False)])

        assert results.scanner_results["bandit"].status == ScannerStatus.SKIPPED
        assert incomplete_scanners(results) == []

    def test_a_staged_match_runs_the_dependency_check_as_today(self, tmp_path):
        calls: list = []
        context = _context(tmp_path, staged=["app.py"])
        (context.source_dir / "app.py").write_text("x = 1\n", encoding="utf-8")

        results = _scan(context, [_recording(BanditScanner, calls)])

        assert calls == ["BanditScanner"]
        # Something to scan and no tool is MISSING: the completeness gate holds.
        assert results.scanner_results["bandit"].status == ScannerStatus.MISSING

    def test_a_non_empty_converted_tree_runs_the_dependency_check(self, tmp_path):
        """Converter output is scanned whole, outside the staged scope, so any
        file there makes the skip undecidable."""
        calls: list = []
        context = _context(tmp_path, staged=["README.md"])
        (context.work_dir / "notebook-converted.py").write_text(
            "x = 1\n", encoding="utf-8"
        )

        _scan(context, [_recording(BanditScanner, calls)])

        assert calls == ["BanditScanner"]

    def test_without_a_staged_scope_nothing_changes(self, tmp_path):
        calls: list = []
        context = _context(tmp_path, staged=None)

        _scan(context, [_recording(BanditScanner, calls)])

        assert calls == ["BanditScanner"]

    def test_checkov_is_covered_by_the_same_decision(self, tmp_path):
        calls: list = []
        context = _context(tmp_path, staged=["README.md"])

        results = _scan(context, [_recording(CheckovScanner, calls)])

        assert calls == []
        assert results.scanner_results["checkov"].status == ScannerStatus.SKIPPED


class TestTheHookItself:
    def test_bandit_answers_for_a_docs_only_staged_set(self, tmp_path):
        context = _context(tmp_path, staged=["README.md"])
        scanner = BanditScanner(context=context)

        reason = scanner.staged_nothing_to_scan_reason()

        assert reason is not None and "--staged" in reason

    def test_bandit_has_no_answer_when_a_python_file_is_staged(self, tmp_path):
        context = _context(tmp_path, staged=["pkg/app.py"])
        scanner = BanditScanner(context=context)

        assert scanner.staged_nothing_to_scan_reason() is None

    def test_a_scanner_without_patterns_never_answers(self, tmp_path):
        """detect-secrets reads any file: nothing is decidable for it, and a
        staged .md commit is exactly what it scans."""
        context = _context(tmp_path, staged=["README.md"])
        scanner = DetectSecretsScanner(context=context)

        assert scanner.staged_nothing_to_scan_reason() is None

    def test_an_empty_staged_list_is_not_this_decision(self, tmp_path):
        """Nothing staged inside the source dir keeps today's path (the CLI
        already fast-exits; the library run scans the machinery through)."""
        context = _context(tmp_path, staged=[])
        scanner = BanditScanner(context=context)

        assert scanner.staged_nothing_to_scan_reason() is None

    def test_converter_output_blocks_the_answer(self, tmp_path):
        context = _context(tmp_path, staged=["README.md"])
        (context.work_dir / "out.py").write_text("x = 1\n", encoding="utf-8")
        scanner = BanditScanner(context=context)

        assert scanner.staged_nothing_to_scan_reason() is None


class TestTreeHoldsAFile:
    def test_an_empty_tree_holds_nothing(self, tmp_path):
        (tmp_path / "converted").mkdir()

        assert tree_holds_a_file(tmp_path / "converted") is False

    def test_a_missing_tree_holds_nothing(self, tmp_path):
        assert tree_holds_a_file(tmp_path / "absent") is False

    def test_none_holds_nothing(self):
        assert tree_holds_a_file(None) is False

    def test_a_nested_file_counts(self, tmp_path):
        nested = tmp_path / "converted" / "deep"
        nested.mkdir(parents=True)
        (nested / "member.py").write_text("x = 1\n", encoding="utf-8")

        assert tree_holds_a_file(tmp_path / "converted") is True

    def test_empty_directories_alone_do_not_count(self, tmp_path):
        (tmp_path / "converted" / "only" / "dirs").mkdir(parents=True)

        assert tree_holds_a_file(tmp_path / "converted") is False
