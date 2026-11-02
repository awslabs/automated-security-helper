# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""The shard fixtures the ``ash merge`` tests share.

``build_shards`` builds the results every shard of a sharded scan of one tree would
write, and ``write_shards`` writes them out the way a CI job's artifact would land.
They live here, not in ``test_merge``, so a test module that needs shards does not
have to import another test module for them (``off_host_plugin_support`` is one).
``test_merge`` imports them back, so the modules that already take them from there
keep working. This module has no tests of its own.
"""

from pathlib import Path
from typing import Dict, List, Sequence, Tuple

from automated_security_helper.cli.merge import (
    RESULTS_FILE_NAME,
    stamp_shard_assignment,
)
from automated_security_helper.core.enums import ScannerStatus
from automated_security_helper.core.sharding import ShardAssignment, partition_scanners
from automated_security_helper.models.asharp_model import (
    AshAggregatedResults,
    ScannerStatusInfo,
    ScannerTargetStatusInfo,
)
from automated_security_helper.schemas.sarif_schema_model import (
    ArtifactLocation,
    Level,
    Location,
    Message,
    Message1,
    PhysicalLocation,
    PhysicalLocation2,
    PropertyBag,
    Region,
    ReportingDescriptor,
    Result,
    Run,
    SarifReport,
    Tool,
    ToolComponent,
)

# A deliberately unsorted scanner list, so a partition that depended on input
# order could not pass by accident, and one scanner with no findings so the
# "clean scanner still has to appear" case is covered.
SCANNERS = ["semgrep", "bandit", "grype", "checkov", "detect-secrets"]

# scanner -> [(sarif level, issue_severity)]. Only checkov and bandit carry
# anything actionable at the default MEDIUM threshold; semgrep's single LOW
# finding is the case that must be counted as a finding but not as actionable.
FINDINGS: Dict[str, List[Tuple[str, str]]] = {
    "bandit": [("error", "HIGH"), ("warning", "MEDIUM")],
    "checkov": [("error", "CRITICAL")],
    "semgrep": [("note", "LOW")],
    "grype": [],
    "detect-secrets": [("warning", "MEDIUM")],
}


#: A tool component every shard reports, unlike the per-scanner ones. Real
#: aggregates carry components that are not one-per-scanner -- ASH's own driver
#: ends up in extensions once merging starts -- so the union has to cope with the
#: same component arriving from several shards with different rules.
SHARED_COMPONENT = ("ash-core", "ASH core rules", "test")


def _build_config(fail_on_findings=None, suppressions=None):
    """A minimal real AshConfig.

    Supplied rather than left as None because ``AshAggregatedResults`` logs a
    validation error for a None config on every construction, and because
    ``_compute_exit_code`` reads ``global_settings.severity_threshold`` off it --
    a test with no config would exercise a default that no real scan uses.

    ``suppressions`` defaults to none, and that default is why the equivalence
    property in ``TestShardedEqualsUnsharded`` passed while ``ash merge`` never
    applied the aggregated suppression pass at all: with no suppression in the
    config, both paths agree no matter which one skips the pass.
    ``TestSuppressionsAcrossShards`` supplies some.
    """
    from automated_security_helper.config.ash_config import (
        AshConfig,
        AshConfigGlobalSettingsSection,
    )

    config = AshConfig(
        project_name="test-merge",
        global_settings=AshConfigGlobalSettingsSection(
            severity_threshold="MEDIUM",
            suppressions=list(suppressions or []),
        ),
    )
    if fail_on_findings is not None:
        config.fail_on_findings = fail_on_findings
    return config


def _sarif_result(scanner: str, index: int, level: str, severity: str) -> Result:
    return Result(
        ruleId=f"{scanner}-RULE-{index}",
        level=Level(level),
        message=Message(root=Message1(text=f"{scanner} finding {index}")),
        properties=PropertyBag(scanner_name=scanner, issue_severity=severity),
        locations=[
            Location(
                physicalLocation=PhysicalLocation(
                    root=PhysicalLocation2(
                        artifactLocation=ArtifactLocation(
                            uri=f"src/{scanner}_{index}.py"
                        ),
                        region=Region(startLine=index + 1),
                    )
                )
            )
        ],
    )


def _sarif_for(scanners: Sequence[str]) -> SarifReport:
    """Build the SARIF a scan of *scanners* would produce.

    Each scanner contributes a tool component under ``extensions`` carrying its
    rules, which is the shape a real ASH aggregate has and the shape that would
    silently lose rule metadata if merging only handled ``tool.driver``.
    """
    results: List[Result] = []
    extensions: List[ToolComponent] = []
    for scanner in scanners:
        rules = []
        for index, (level, severity) in enumerate(FINDINGS[scanner]):
            results.append(_sarif_result(scanner, index, level, severity))
            rules.append(ReportingDescriptor(id=f"{scanner}-RULE-{index}"))
        extensions.append(
            ToolComponent(
                name=scanner,
                fullName=f"{scanner} scanner",
                organization="test",
                rules=rules,
            )
        )
    # One component with a stable identity across every shard, carrying a
    # different rule per shard. Merging must keep one copy of the component and
    # the union of its rules; appending blindly would produce n copies, and
    # keeping only the first would lose the other shards' rules.
    name, full_name, organization = SHARED_COMPONENT
    extensions.append(
        ToolComponent(
            name=name,
            fullName=full_name,
            organization=organization,
            rules=[ReportingDescriptor(id=f"shared-{scanner}") for scanner in scanners],
        )
    )
    return SarifReport(
        version="2.1.0",
        runs=[
            Run(
                tool=Tool(
                    driver=ToolComponent(name="ASH", version="test"),
                    extensions=extensions,
                ),
                results=results,
                invocations=[],
                properties=PropertyBag(),
            )
        ],
    )


def _ran_entries(model: AshAggregatedResults, scanner: str) -> None:
    """Record *scanner* on *model* as a scanner this executor actually ran."""
    model.scanner_results[scanner] = ScannerTargetStatusInfo(
        status=ScannerStatus.FAILED if FINDINGS[scanner] else ScannerStatus.PASSED,
        excluded=False,
        dependencies_satisfied=True,
    )
    model.additional_reports[scanner] = {
        "source": {
            "scanner_name": scanner,
            "status": "FAILED" if FINDINGS[scanner] else "PASSED",
            "duration": 2.0,
        }
    }


def _skipped_entries(model: AshAggregatedResults, scanner: str) -> None:
    """Record *scanner* the way a shard records a scanner it did not own.

    Both halves matter. ``ScanPhase`` writes the ``scanner_results`` entry, and
    ``_process_results`` writes the ``additional_reports[name]["None"]`` marker --
    and it is the marker that ``get_scanner_status_info`` consults first, so a
    fixture that only wrote the ``scanner_results`` half would let a broken merge
    pass.
    """
    model.scanner_results[scanner] = ScannerStatusInfo(
        status=ScannerStatus.SKIPPED, excluded=True, dependencies_satisfied=True
    )
    model.additional_reports[scanner] = {
        "None": {"scanner_name": scanner, "status": "SKIPPED", "excluded": True}
    }


def build_shard(
    shard_index: int,
    shard_count: int,
    owned: Sequence[str],
    all_scanners: Sequence[str] = SCANNERS,
    stamp: bool = True,
    suppressions=None,
) -> AshAggregatedResults:
    """Build the results one shard of a sharded scan would write.

    The SARIF this produces is never pre-suppressed, whatever ``suppressions``
    says. That is deliberate and it is the state a real shard is in when a
    suppression's path only becomes matchable after merge and normalization: the
    shard carries the config, its own per-scanner pass did not match, and the
    aggregated pass on the merged product is the only thing left that can.
    """
    model = AshAggregatedResults()
    model.ash_config = _build_config(suppressions=suppressions)
    # Distinct per shard so it is observable which shard supplied the merged
    # report's identity. Without something base-dependent in the fixture, a merge
    # that took its base from whichever shard happened to be listed first would
    # be indistinguishable from one that took the lowest index.
    model.name = f"shard-{shard_index} scan"
    model.sarif = _sarif_for(owned)
    for scanner in all_scanners:
        if scanner in owned:
            _ran_entries(model, scanner)
        else:
            _skipped_entries(model, scanner)
    model.metadata.summary_stats.start = f"2026-08-28T10:{shard_index:02d}:00"
    model.metadata.summary_stats.end = f"2026-08-28T10:{shard_index + 20:02d}:00"
    model.metadata.summary_stats.duration = 60.0 + shard_index
    if stamp:
        stamp_shard_assignment(
            model,
            ShardAssignment(
                shard_index=shard_index,
                shard_count=shard_count,
                assigned_scanners=list(owned),
                # Recorded because a real ScanPhase records it. Fixtures that left
                # it None would exercise only the backward-compatibility path, in
                # which verify_shard_coverage skips the union check entirely -- so
                # the mainline merge tests would run against a weaker contract than
                # any real scan produces.
                candidate_scanners=list(all_scanners),
            ),
        )
    return model


def build_shards(shard_count: int = 3, suppressions=None) -> List[AshAggregatedResults]:
    """Build every shard of a *shard_count*-way split of the same tree."""
    return [
        build_shard(
            index,
            shard_count,
            partition_scanners(SCANNERS, index, shard_count),
            suppressions=suppressions,
        )
        for index in range(shard_count)
    ]


def as_loaded(
    models: Sequence[AshAggregatedResults],
) -> List[Tuple[Path, AshAggregatedResults]]:
    """Pair models with placeholder paths, for tests that skip disk entirely."""
    return [(Path(f"shard-{index}.json"), model) for index, model in enumerate(models)]


def write_shards(
    tmp_path: Path, models: Sequence[AshAggregatedResults], as_dirs: bool = True
) -> List[str]:
    """Write each shard's results out the way a CI job's artifact would land."""
    paths: List[str] = []
    for index, model in enumerate(models):
        target = tmp_path / f"shard-{index}"
        target.mkdir(parents=True, exist_ok=True)
        results_file = target / RESULTS_FILE_NAME
        results_file.write_text(model.model_dump_json(indent=2), encoding="utf-8")
        paths.append(str(target if as_dirs else results_file))
    return paths
