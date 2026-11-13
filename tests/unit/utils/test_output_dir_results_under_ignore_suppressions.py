# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""ASH's output directory stays out of the results under ``--ignore-suppressions``.

ASH writes its reports to the output directory, which by default is inside the
scanned tree. ``apply_suppressions_to_sarif`` removes results located there, apart
from the work directory converters write into, as its first step. Every caller
skipped that function when the flag was set, so a scanner that reads the whole
tree reported files under the output directory as findings. The flag lifts
suppressions and ignore paths, and the output directory is neither.

One test per place a scan applies suppressions to SARIF: the function itself, the
per-scanner metrics, the per-scanner merge into the aggregated results, the final
pass before the report phase, and ``ash merge``. Each also keeps a result in the
scanned tree and one in the work directory, so a pass that removed everything
would fail.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import List

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.constants import ASH_WORK_DIR_NAME
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.models.core import AshSuppression, IgnorePathWithReason
from automated_security_helper.schemas.sarif_schema_model import (
    ArtifactLocation,
    Location,
    Message,
    PhysicalLocation2,
    Result,
    Run,
    SarifReport,
    Tool,
    ToolComponent,
)

pytestmark = pytest.mark.unit

AshConfig.model_rebuild()
AshAggregatedResults.model_rebuild()

IN_TREE = "app.py"
IN_OUTPUT = ".ash/ash_output/planted.py"
IN_WORK = f".ash/ash_output/{ASH_WORK_DIR_NAME}/jupyter/notebook-converted.py"


def _result(uri: str) -> Result:
    return Result(
        ruleId="RULE-1",
        message=Message(text="finding"),
        locations=[
            Location(
                physicalLocation=PhysicalLocation2(
                    artifactLocation=ArtifactLocation(uri=uri)
                )
            )
        ],
        properties={"scanner_name": "scripted"},
    )


def _sarif(*uris: str) -> SarifReport:
    return SarifReport(
        version="2.1.0",
        runs=[
            Run(
                tool=Tool(driver=ToolComponent(name="scripted")),
                results=[_result(uri) for uri in uris],
            )
        ],
    )


def _uris(report: SarifReport) -> List[str]:
    return [
        location.physicalLocation.root.artifactLocation.uri
        for run in report.runs
        for result in run.results or []
        for location in result.locations or []
    ]


def _context(tmp_path: Path, config: AshConfig | None = None) -> PluginContext:
    """The default layout: the output directory inside the scanned tree."""
    source = tmp_path / "src"
    output = source / ".ash" / "ash_output"
    (output / ASH_WORK_DIR_NAME).mkdir(parents=True)
    return PluginContext(
        source_dir=source,
        output_dir=output,
        work_dir=output / ASH_WORK_DIR_NAME,
        config=config or AshConfig(project_name="output-dir"),
        ignore_suppressions=True,
    )


def exclude_output_dir_results(report: SarifReport, context: PluginContext):
    """Imported per call, so the scan-path tests below run without it."""
    from automated_security_helper.utils import sarif_utils

    return sarif_utils.exclude_output_dir_results(report, context)


class TestTheExclusion:
    def test_it_removes_results_in_the_output_directory_only(self, tmp_path):
        context = _context(tmp_path)

        report = exclude_output_dir_results(
            _sarif(IN_TREE, IN_OUTPUT, IN_WORK), context
        )

        assert _uris(report) == [IN_TREE, IN_WORK]

    def test_it_reads_an_absolute_uri(self, tmp_path):
        context = _context(tmp_path)
        absolute = (context.source_dir / IN_OUTPUT).as_posix()

        report = exclude_output_dir_results(_sarif(IN_TREE, absolute), context)

        assert _uris(report) == [IN_TREE]

    def test_it_applies_no_ignore_path_or_suppression(self, tmp_path):
        config = AshConfig(
            project_name="output-dir",
            global_settings={
                "ignore_paths": [IgnorePathWithReason(path=IN_TREE, reason="x")],
                "suppressions": [
                    AshSuppression(rule_id="RULE-1", path=IN_TREE, reason="x")
                ],
            },
        )
        context = _context(tmp_path, config)

        report = exclude_output_dir_results(_sarif(IN_TREE), context)

        assert _uris(report) == [IN_TREE]
        assert not report.runs[0].results[0].suppressions

    def test_nothing_is_removed_when_the_output_directory_holds_the_tree(
        self, tmp_path
    ):
        source = tmp_path / "src"
        source.mkdir()
        context = PluginContext(
            source_dir=source,
            output_dir=tmp_path,
            config=AshConfig(project_name="output-dir"),
            ignore_suppressions=True,
        )

        report = exclude_output_dir_results(_sarif(IN_TREE, "other.py"), context)

        assert _uris(report) == [IN_TREE, "other.py"]


class TestEachScanPathAppliesIt:
    def test_the_per_scanner_merge_into_the_results(self, tmp_path):
        from automated_security_helper.core.phases.scan_result_processor import (
            ScanResultProcessor,
        )
        from automated_security_helper.models.scan_results_container import (
            ScanResultsContainer,
        )

        context = _context(tmp_path)
        container = ScanResultsContainer(
            scanner_name="scripted",
            target_type="source",
            raw_results=_sarif(IN_TREE, IN_OUTPUT, IN_WORK),
        )
        aggregated = AshAggregatedResults()

        ScanResultProcessor(plugin_context=context).process_container(
            container, aggregated
        )

        assert IN_OUTPUT not in _uris(aggregated.sarif)
        assert IN_TREE in _uris(aggregated.sarif)

    def test_the_per_scanner_finding_count(self, tmp_path):
        from unittest.mock import MagicMock

        from automated_security_helper.base.scanner_plugin import (
            ScannerPluginBase,
            ScannerPluginConfigBase,
        )
        from automated_security_helper.core.phases.scanner_executor import (
            ScannerExecutor,
        )

        class _Config(ScannerPluginConfigBase):
            name: str = "scripted"

        class _Scanner(ScannerPluginBase):
            def validate_plugin_dependencies(self) -> bool:
                return True

            def _execute_scan(self, target, target_type, global_ignore_paths):
                raise NotImplementedError("scan() is overridden directly")

            def scan(self, target, target_type=None, *args, **kwargs):
                return _sarif(IN_TREE, IN_OUTPUT, IN_WORK)

        context = _context(tmp_path)
        scanner = _Scanner(config=_Config(), context=context)
        scanner.start_time = datetime(2026, 1, 1, 10, 0, 0)
        scanner.end_time = datetime(2026, 1, 1, 10, 0, 1)
        scanner.exit_code = 0
        executor = ScannerExecutor(
            plugin_context=context, progress_display=MagicMock(), scanner_tasks=[]
        )

        (container,) = executor._execute_scanner(
            "scripted", scanner, [{"path": context.source_dir, "type": "source"}]
        )

        assert container.finding_count == 2

    def test_the_final_pass_before_the_reports(self, tmp_path):
        from automated_security_helper.core.orchestrator import ASHScanOrchestrator

        context = _context(tmp_path)
        model = AshAggregatedResults()
        model.sarif = _sarif(IN_TREE, IN_OUTPUT, IN_WORK)
        existing = tmp_path / "existing.json"
        existing.write_text(model.model_dump_json(by_alias=True), encoding="utf-8")

        results = ASHScanOrchestrator.create(
            source_dir=context.source_dir,
            output_dir=context.output_dir,
            existing_results_path=existing,
            ignore_suppressions=True,
            show_progress=False,
            offline=True,
        ).execute_scan(phases=["report"])

        assert IN_OUTPUT not in _uris(results.sarif)
        assert IN_TREE in _uris(results.sarif)

    def test_ash_merge_keeps_what_the_shards_kept(self, tmp_path):
        """Each shard already dropped its own output-directory results, with its
        own run ID and git answer, so ``ash merge`` does not decide again: it has
        no run ID and may run outside git, and deciding again dropped a committed
        file every shard kept."""
        from automated_security_helper.cli.merge import apply_aggregated_suppressions

        context = _context(tmp_path)
        model = AshAggregatedResults()
        model.sarif = _sarif(IN_TREE, IN_OUTPUT, IN_WORK)

        merged = apply_aggregated_suppressions(model, context)

        assert _uris(merged.sarif) == [IN_TREE, IN_OUTPUT, IN_WORK]


@pytest.mark.parametrize("flag", [False, True])
def test_the_output_directory_is_excluded_either_way(tmp_path, flag):
    """The same SARIF through the per-scanner pass, with and without the flag.

    That pass applies suppressions without the flag and only the output-directory
    exclusion with it; both leave out the output directory.
    """
    from automated_security_helper.core.phases.scan_result_processor import (
        ScanResultProcessor,
    )
    from automated_security_helper.models.scan_results_container import (
        ScanResultsContainer,
    )

    context = _context(tmp_path)
    context.ignore_suppressions = flag
    container = ScanResultsContainer(
        scanner_name="scripted",
        target_type="source",
        raw_results=_sarif(IN_TREE, IN_OUTPUT),
    )
    aggregated = AshAggregatedResults()

    ScanResultProcessor(plugin_context=context).process_container(container, aggregated)

    assert IN_OUTPUT not in _uris(aggregated.sarif)
    assert IN_TREE in _uris(aggregated.sarif)
