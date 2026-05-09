# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import json
import logging
import os
import platform
import sys
import time
from pathlib import Path
from typing import List, Optional, Union, cast

import typer
from pydantic import BaseModel, Field, field_validator
from rich import print

from automated_security_helper.core.constants import (
    ASH_CONFIG_FILE_NAMES,
    ASH_WORK_DIR_NAME,
    is_offline_mode,
)
from automated_security_helper.core.enums import (
    AshLogLevel,
    BuildTarget,
    ExecutionPhase,
    ExecutionStrategy,
    ExportFormat,
    RunMode,
)
from automated_security_helper.core.exceptions import ASHConfigValidationError
from automated_security_helper.core.progress import ExecutionPhaseType
from automated_security_helper.core.unified_metrics import (
    format_duration,
    get_unified_scanner_metrics,
)
from automated_security_helper.interactions.run_ash_container import run_ash_container
from automated_security_helper.models.asharp_model import AshAggregatedResults


# ---------------------------------------------------------------------------
# ScanOptions — bundles all 40+ parameters; eliminates 7 None-rebinding stanzas
# ---------------------------------------------------------------------------

class ScanOptions(BaseModel):
    """All parameters for a single run_ash_scan invocation."""

    # Core paths
    source_dir: Path
    output_dir: Path

    # General scan options
    config: Optional[str] = None
    config_overrides: Optional[List[str]] = Field(default_factory=list)
    offline: bool = False
    strategy: ExecutionStrategy = ExecutionStrategy.PARALLEL
    scanners: Optional[List[str]] = Field(default_factory=list)
    excluded_scanners: Optional[List[str]] = Field(default_factory=list)
    progress: bool = True
    output_formats: Optional[List[ExportFormat]] = Field(default_factory=list)
    cleanup: bool = False
    phases: Optional[List[ExecutionPhase]] = Field(
        default_factory=lambda: [
            ExecutionPhase.CONVERT,
            ExecutionPhase.SCAN,
            ExecutionPhase.REPORT,
        ]
    )
    inspect: bool = False
    existing_results: Optional[str] = None
    python_based_plugins_only: bool = False
    quiet: bool = False
    simple: bool = False
    verbose: bool = False
    debug: bool = False
    color: bool = True
    fail_on_findings: Optional[bool] = None
    ignore_suppressions: bool = False
    min_severity: str = "low"
    changed_files_only: bool = False
    base_ref: str = "origin/main"
    mode: RunMode = RunMode.local
    show_summary: bool = True
    log_level: AshLogLevel = AshLogLevel.INFO

    # Container-specific
    build: bool = True
    run: bool = True
    force: bool = False
    oci_runner: Optional[str] = None
    build_target: Optional[BuildTarget] = None
    offline_semgrep_rulesets: str = "p/ci"
    container_uid: Optional[str] = None
    container_gid: Optional[str] = None
    ash_revision_to_install: Optional[str] = None
    custom_containerfile: Optional[str] = None
    custom_build_arg: Optional[List[str]] = Field(default_factory=list)
    ash_plugin_modules: Optional[List[str]] = Field(default_factory=list)
    container_network: str = "bridge"

    @field_validator("source_dir", "output_dir", mode="before")
    @classmethod
    def _coerce_absolute_path(cls, v):
        return Path(v).absolute()

    @field_validator("scanners", "excluded_scanners", "output_formats",
                     "config_overrides", "custom_build_arg", "ash_plugin_modules",
                     mode="before")
    @classmethod
    def _none_to_empty_list(cls, v):
        return v if v is not None else []

    @field_validator("phases", mode="before")
    @classmethod
    def _phases_default(cls, v):
        if v is None:
            return [ExecutionPhase.CONVERT, ExecutionPhase.SCAN, ExecutionPhase.REPORT]
        return v


# ---------------------------------------------------------------------------
# Severity helpers (module-level so _compute_exit_code can be patched cleanly)
# ---------------------------------------------------------------------------

_SEVERITY_RANK = {"critical": 3, "high": 3, "medium": 2, "low": 1, "none": 0}
_SARIF_LEVEL_TO_SEVERITY = {"error": "high", "warning": "medium", "note": "low"}


def _severity_filters_finding(result, min_sev_rank: int) -> bool:
    """Return True when *result* meets the minimum severity threshold."""
    if result.suppressions:
        return False
    level = getattr(result, "level", "note")
    if isinstance(level, str):
        level = level.lower()
    mapped = _SARIF_LEVEL_TO_SEVERITY.get(level, "low")
    return _SEVERITY_RANK.get(mapped, 1) >= min_sev_rank


# ---------------------------------------------------------------------------
# Helper: resolve final AshLogLevel
# ---------------------------------------------------------------------------

def _resolve_config_fail_on_findings(opts: ScanOptions) -> Optional[bool]:
    """Read fail_on_findings from the YAML config file, without loading the full orchestrator.

    Returns None when no config file is found or when the field is absent.
    Used by both container and local mode so that YAML overrides are honoured
    regardless of execution path.
    """
    from automated_security_helper.config.ash_config import AshConfig

    config_path_str = opts.config
    if config_path_str is None:
        for config_file in ASH_CONFIG_FILE_NAMES:
            for candidate in (
                opts.source_dir / config_file,
                opts.source_dir / ".ash" / config_file,
            ):
                if candidate.exists():
                    config_path_str = candidate.as_posix()
                    break
            if config_path_str is not None:
                break

    if config_path_str is None:
        return None

    try:
        cfg = AshConfig.from_file(Path(config_path_str))
        return getattr(cfg, "fail_on_findings", None)
    except Exception:
        return None


def _resolve_log_level(opts: ScanOptions) -> AshLogLevel:
    if opts.verbose:
        return AshLogLevel.VERBOSE
    if opts.debug:
        return AshLogLevel.DEBUG
    if opts.quiet or opts.simple or opts.log_level in [
        AshLogLevel.QUIET, AshLogLevel.ERROR, AshLogLevel.SIMPLE
    ]:
        return AshLogLevel.ERROR
    return opts.log_level


# ---------------------------------------------------------------------------
# _setup_logger
# ---------------------------------------------------------------------------

def _setup_logger(opts: ScanOptions):
    from automated_security_helper.utils.log import get_logger

    final_log_level = _resolve_log_level(opts)
    final_logging_level = logging._nameToLevel.get(final_log_level.value, logging.INFO)
    simple_logging = opts.simple or opts.log_level == AshLogLevel.SIMPLE

    return get_logger(
        level=final_logging_level,
        output_dir=opts.output_dir,
        show_progress=(
            opts.progress
            and not opts.quiet
            and not opts.simple
            and os.environ.get("ASH_IN_CONTAINER", "NO").upper() not in ["YES", "1", "TRUE"]
        ),
        use_color=opts.color,
        simple_format=simple_logging,
        truncate_log=opts.existing_results is None,
    )


# ---------------------------------------------------------------------------
# _run_container_mode
# ---------------------------------------------------------------------------

def _run_container_mode(
    opts: ScanOptions,
    logger,
    resolved_fail_on_findings: Optional[bool] = None,
) -> AshAggregatedResults:
    if opts.changed_files_only:
        logger.warning(
            "--changed-files-only is not supported in container mode; performing full scan"
        )

    # Use the CLI-supplied value when present; fall back to the value already read from
    # the config file on the host.  Passing the resolved value avoids a race where the
    # user mutates the config file between the host read and the container's own read.
    effective_fail_on_findings = (
        opts.fail_on_findings if opts.fail_on_findings is not None else resolved_fail_on_findings
    )

    container_result = run_ash_container(
        source_dir=opts.source_dir,
        output_dir=opts.output_dir,
        offline=opts.offline,
        log_level=opts.log_level,
        verbose=opts.verbose,
        debug=opts.debug,
        color=opts.color,
        simple=opts.simple,
        quiet=opts.quiet,
        build=opts.build,
        run=opts.run,
        force=opts.force,
        oci_runner=opts.oci_runner,
        build_target=opts.build_target,
        offline_semgrep_rulesets=opts.offline_semgrep_rulesets,
        container_uid=opts.container_uid,
        container_gid=opts.container_gid,
        config=opts.config,
        config_overrides=opts.config_overrides,
        strategy=opts.strategy,
        scanners=opts.scanners,
        exclude_scanners=opts.excluded_scanners,
        progress=opts.progress,
        output_formats=opts.output_formats,
        cleanup=opts.cleanup,
        phases=opts.phases,
        inspect=opts.inspect,
        existing_results=opts.existing_results,
        python_based_plugins_only=opts.python_based_plugins_only,
        fail_on_findings=effective_fail_on_findings,
        ash_revision_to_install=opts.ash_revision_to_install,
        custom_containerfile=opts.custom_containerfile,
        custom_build_arg=opts.custom_build_arg,
        ash_plugin_modules=opts.ash_plugin_modules,
        container_network=opts.container_network,
    )

    if opts.debug:
        print("\n[bold blue]Debug: Container Command[/bold blue]")
        if hasattr(container_result, "args"):
            print(f"Command: {' '.join(str(arg) for arg in container_result.args)}")
        print(f"Return code: {container_result.returncode}")
        print(
            f"Stdout length: {len(container_result.stdout) if hasattr(container_result, 'stdout') else 'N/A'}"
        )
        print(
            f"Stderr length: {len(container_result.stderr) if hasattr(container_result, 'stderr') else 'N/A'}"
        )

    if hasattr(container_result, "returncode") and container_result.returncode != 0:
        logger.error(f"Container execution failed with code {container_result.returncode}")
        if hasattr(container_result, "stderr") and container_result.stderr:
            logger.error(f"Container stderr:\n{container_result.stderr}")
            print(f"\n[bold red]Container Error Output:[/bold red]\n{container_result.stderr}")
        if hasattr(container_result, "stdout") and container_result.stdout:
            logger.debug(f"Container stdout:\n{container_result.stdout}")
            if opts.debug:
                print(f"\n[bold blue]Container Standard Output:[/bold blue]\n{container_result.stdout}")

    if not opts.run:
        if hasattr(container_result, "returncode") and container_result.returncode != 0:
            sys.exit(container_result.returncode)
        sys.exit(0)

    output_file = opts.output_dir / "ash_aggregated_results.json"
    if output_file.exists():
        with open(output_file, mode="r", encoding="utf-8") as f:
            content = f.read()
        try:
            return AshAggregatedResults.model_validate_json(content)
        except Exception as e:
            logger.error(f"Failed to parse results file: {e}")
            sys.exit(1)
    else:
        logger.error(f"Results file not found at {output_file}")
        sys.exit(1)


# ---------------------------------------------------------------------------
# _run_local_mode
# ---------------------------------------------------------------------------

def _run_local_mode(opts: ScanOptions, logger) -> tuple[AshAggregatedResults, Optional[bool]]:
    from automated_security_helper.core.orchestrator import ASHScanOrchestrator

    _offline_was_set = False
    if opts.offline:
        os.environ["ASH_OFFLINE"] = "YES"
        _offline_was_set = True

    _changed_file_set = None
    if opts.changed_files_only:
        from automated_security_helper.utils.get_scan_set import get_changed_files
        changed_paths = get_changed_files(base_ref=opts.base_ref, cwd=opts.source_dir)
        if changed_paths is not None:
            _changed_file_set = {
                opts.source_dir.joinpath(p).resolve() for p in changed_paths
            }

    try:
        if not opts.quiet and not opts.simple:
            logger.verbose(f"Source directory: {opts.source_dir.as_posix()}")
            logger.verbose(f"Output directory: {opts.output_dir.as_posix()}")
            logger.verbose(f"Scanners specified: {opts.scanners}")
            logger.verbose(f"Scanners excluded: {opts.excluded_scanners}")

        config = opts.config
        if config is None:
            for config_file in ASH_CONFIG_FILE_NAMES:
                def_paths = [
                    opts.source_dir / config_file,
                    opts.source_dir / ".ash" / config_file,
                ]
                for def_path in def_paths:
                    if def_path.exists():
                        logger.info(f"Using config file found at: {def_path.as_posix()}")
                        config = def_path.as_posix()
                        break
                if config is not None:
                    break
        else:
            logger.info(f"Using config file specified at: {config}")

        if opts.config_overrides:
            logger.info(f"Applying {len(opts.config_overrides or [])} configuration overrides")

        final_log_level = _resolve_log_level(opts)
        final_scanners = list(opts.scanners or [])
        if opts.mode == RunMode.precommit:
            fast_scanners = ["bandit", "detect-secrets", "checkov", "cdk-nag", "npm-audit"]
            final_scanners = list(set(final_scanners + fast_scanners))

        final_show_progress = (
            opts.progress
            and final_log_level not in [
                AshLogLevel.QUIET,
                AshLogLevel.SIMPLE,
                AshLogLevel.VERBOSE,
                AshLogLevel.DEBUG,
            ]
            and os.environ.get("CI") is None
            and os.environ.get("ASH_IN_CONTAINER", "NO").upper() not in ["YES", "1", "TRUE"]
        )

        orchestrator = ASHScanOrchestrator.create(
            source_dir=opts.source_dir,
            output_dir=opts.output_dir,
            work_dir=opts.output_dir / ASH_WORK_DIR_NAME,
            enabled_scanners=final_scanners,
            excluded_scanners=list(opts.excluded_scanners or []),
            config_path=config,
            config_overrides=opts.config_overrides or [],
            verbose=opts.verbose or opts.debug,
            debug=opts.debug,
            strategy=(
                ExecutionStrategy.PARALLEL
                if opts.strategy == ExecutionStrategy.PARALLEL
                else ExecutionStrategy.SEQUENTIAL
            ),
            no_cleanup=not opts.cleanup,
            output_formats=opts.output_formats or [],
            show_progress=final_show_progress,
            simple_mode=opts.simple,
            show_summary=opts.show_summary,
            color_system=(
                "windows" if platform.system() == "Windows" else "auto" if opts.color else None
            ),
            offline=(opts.offline if opts.offline is not None else is_offline_mode()),
            existing_results_path=(
                Path(opts.existing_results) if opts.existing_results else None
            ),
            python_based_plugins_only=opts.python_based_plugins_only,
            ignore_suppressions=opts.ignore_suppressions,
            ash_plugin_modules=opts.ash_plugin_modules or [],
            metadata=None,
        )
        _config_fail_on_findings: Optional[bool] = getattr(
            getattr(orchestrator, "config", None), "fail_on_findings", None
        )

        _phases = opts.phases or []
        phases_to_run = []
        if ExecutionPhase.CONVERT in _phases:
            phases_to_run.append("convert")
        if ExecutionPhase.SCAN in _phases:
            phases_to_run.append("scan")
        if ExecutionPhase.REPORT in _phases:
            phases_to_run.append("report")
        if ExecutionPhase.INSPECT in _phases or opts.inspect:
            phases_to_run.append("inspect")
        if not phases_to_run:
            phases_to_run = ["convert", "scan", "report"]

        if not opts.quiet and not opts.simple:
            logger.debug(f"Running phases: {phases_to_run}")

        results = orchestrator.execute_scan(phases=cast(List[ExecutionPhaseType], phases_to_run))

        if opts.simple and not opts.quiet:
            typer.echo("\nASH scan completed.")

        if _changed_file_set and results is not None:
            results = _filter_results_to_changed_files(results, _changed_file_set, opts.source_dir)
            sarif_path = opts.output_dir / "reports" / "ash.sarif"
            if sarif_path.exists() and results.sarif:
                sarif_path.write_text(
                    results.sarif.model_dump_json(indent=2, by_alias=True),
                    encoding="utf-8",
                )

        if isinstance(results, BaseModel):
            content = results.model_dump_json(indent=2, by_alias=True)
        else:
            content = json.dumps(results, indent=2, default=str)

        output_file = opts.output_dir / "ash_aggregated_results.json"
        with open(output_file, mode="w", encoding="utf-8") as f:
            f.write(content)

        return results, _config_fail_on_findings

    except ASHConfigValidationError as e:
        print(f"[bold red]ERROR (3) Invalid configuration: {e}[/bold red]")
        sys.exit(3)
    except Exception as e:
        logger.exception(e)
        print(f"[bold red]ERROR (1) Exiting due to exception during ASH scan: {e}[/bold red]")
        sys.exit(1)
    finally:
        if _offline_was_set:
            os.environ.pop("ASH_OFFLINE", None)


# ---------------------------------------------------------------------------
# _compute_exit_code — pure function from in-memory results; no disk reads
#
# The prior implementation re-read ash.sarif from disk to work around a
# concern that Pydantic in-memory suppression state wasn't reliable. That
# read unconditionally overwrote the in-memory actionable count.
# Root-cause investigation: get_unified_scanner_metrics() already re-derives
# all counts from the final SARIF model in memory via ScannerStatisticsCalculator,
# which reads result.suppressions reliably through the Pydantic field accessor
# (not a stale __dict__ key). The disk-re-read was masking the issue rather
# than fixing it. Using in-memory results only is both correct and faster.
# ---------------------------------------------------------------------------

def _compute_exit_code(
    results: Optional[AshAggregatedResults],
    opts: ScanOptions,
    config_fail_on_findings: Optional[bool] = None,
) -> int:
    if results is None:
        logging.getLogger(__name__).error(
            "ASH scan produced no results — scan may have crashed"
        )
        return 1

    final_fail_on_findings: bool
    if opts.fail_on_findings is not None:
        final_fail_on_findings = opts.fail_on_findings
    elif config_fail_on_findings is not None:
        final_fail_on_findings = config_fail_on_findings
    else:
        final_fail_on_findings = True

    if not final_fail_on_findings:
        return 0

    scanner_metrics = get_unified_scanner_metrics(asharp_model=results)
    actionable_findings = sum(item.actionable for item in scanner_metrics)

    min_sev_rank = _SEVERITY_RANK.get(opts.min_severity.lower(), 1)
    if min_sev_rank > 0 and actionable_findings > 0:
        has_qualifying = False
        try:
            sarif = getattr(results, "sarif", None)
            if sarif is None or not getattr(sarif, "runs", None):
                has_qualifying = True
            for run in (getattr(sarif, "runs", []) if not has_qualifying else []):
                for result in getattr(run, "results", []):
                    if _severity_filters_finding(result, min_sev_rank):
                        has_qualifying = True
                        break
                if has_qualifying:
                    break
        except Exception:
            has_qualifying = True
        if not has_qualifying:
            actionable_findings = 0

    if actionable_findings > 0:
        return 2
    return 0


# ---------------------------------------------------------------------------
# _print_summary
# ---------------------------------------------------------------------------

def _print_summary(
    results: Optional[AshAggregatedResults],
    opts: ScanOptions,
    scan_start_time: float,
    actionable_findings: int,
) -> None:
    scan_duration = time.time() - scan_start_time
    duration_str = format_duration(scan_duration)

    output_file = opts.output_dir / "ash_aggregated_results.json"
    relative_out_dir = (
        opts.output_dir.relative_to(opts.source_dir)
        if opts.output_dir.is_relative_to(opts.source_dir)
        else opts.output_dir
    )
    out_dir_alias = os.environ.get("ASH_ACTUAL_OUTPUT_DIR", relative_out_dir.as_posix())

    if not opts.quiet:
        if results and hasattr(results, "validation_checkpoints"):
            config_warnings = [
                cp for cp in results.validation_checkpoints if cp.get("type") == "config_warning"
            ]
            if config_warnings:
                print("\n[bold yellow]⚠️  CONFIGURATION WARNING ⚠️[/bold yellow]")
                for cw in config_warnings:
                    print(f"[yellow]  {cw['message']}[/yellow]")
                print("")

        print(f"\n[cyan]=== ASH Scan Completed in {duration_str}: Next Steps ===[/cyan]")
        print("View detailed findings...")
        print(f"  - SARIF: '{out_dir_alias}/reports/ash.sarif'")
        print(f"  - JUnit: '{out_dir_alias}/reports/ash.junit.xml'")
        print(
            f"  - ASH aggregated results JSON available at: "
            f"'{out_dir_alias}/{output_file.relative_to(opts.output_dir).as_posix()}'"
        )

    if actionable_findings > 0:
        print("\n[magenta]=== Actionable findings detected! ===[/magenta]")
        print("To investigate...")
        print("  1. Open one of the summary reports for a user-friendly table of the findings:")
        print(f"    - HTML report of all findings: '{out_dir_alias}/reports/ash.html'")
        print(f"    - Markdown summary: '{out_dir_alias}/reports/ash.summary.md'")
        print(f"    - Text summary: '{out_dir_alias}/reports/ash.summary.txt'")
        print(
            "  2. Use [magenta]ash report[/magenta] to view a short text summary of the scan in your terminal"
        )
        print(
            "  3. Use [magenta]ash inspect findings[/magenta] to explore the findings interactively"
        )
        print(
            f"  4. Review scanner-specific reports and outputs in the '{out_dir_alias}/scanners' directory"
        )


# ---------------------------------------------------------------------------
# _filter_results_to_changed_files (unchanged helper)
# ---------------------------------------------------------------------------

def _filter_results_to_changed_files(
    results: "AshAggregatedResults",
    changed_files: set,
    source_dir: Path,
) -> "AshAggregatedResults":
    """Remove SARIF results whose primary location is not in *changed_files*."""
    if not results or not results.sarif or not results.sarif.runs:
        return results
    for run in results.sarif.runs:
        if not run.results:
            continue
        filtered = []
        for result in run.results:
            if not result.locations:
                filtered.append(result)
                continue
            loc = result.locations[0]
            if not loc.physicalLocation or not loc.physicalLocation.root.artifactLocation:
                filtered.append(result)
                continue
            uri = loc.physicalLocation.root.artifactLocation.uri or ""
            if uri.startswith("file://"):
                uri = uri[7:]
                if uri.startswith("///"):
                    uri = uri[2:]
            resolved = Path(source_dir).joinpath(uri).resolve()
            if resolved in changed_files:
                filtered.append(result)
        run.results = filtered
    return results


# ---------------------------------------------------------------------------
# run_ash_scan — top-level entry point (~50 lines)
# ---------------------------------------------------------------------------

def run_ash_scan(
    source_dir: str | Path | None = None,
    output_dir: str | Path | None = None,
    config: str | None = None,
    config_overrides: List[str] | None = None,
    offline: bool = False,
    strategy: ExecutionStrategy = ExecutionStrategy.PARALLEL,
    scanners: List[str] | None = None,
    exclude_scanners: List[str] | None = None,
    progress: bool = True,
    output_formats: List[ExportFormat] | None = None,
    cleanup: bool = False,
    phases: List[ExecutionPhase] | None = None,
    inspect: bool = False,
    existing_results: str | None = None,
    python_based_plugins_only: bool = False,
    quiet: bool = False,
    simple: bool = False,
    verbose: bool = False,
    debug: bool = False,
    color: bool = True,
    fail_on_findings: bool | None = None,
    ignore_suppressions: bool = False,
    min_severity: str = "low",
    changed_files_only: bool = False,
    base_ref: str = "origin/main",
    mode: RunMode = RunMode.local,
    show_summary: bool = True,
    log_level: AshLogLevel = AshLogLevel.INFO,
    # Container-specific args
    build: bool = True,
    run: bool = True,
    force: bool = False,
    oci_runner: str | None = None,
    build_target: BuildTarget | None = None,
    offline_semgrep_rulesets: str = "p/ci",
    container_uid: str | None = None,
    container_gid: str | None = None,
    ash_revision_to_install: str | None = None,
    custom_containerfile: str | None = None,
    custom_build_arg: List[str] | None = None,
    ash_plugin_modules: List[str] | None = None,
    container_network: str = "bridge",
    *args,
    **kwargs,
):
    """Run an ASH scan against source_dir, outputting results to output_dir."""
    scan_start_time = time.time()

    # Resolve cwd-based defaults at call time (not import time).
    _source_dir: Path = Path(source_dir).absolute() if source_dir is not None else Path.cwd()
    _output_dir: Path = Path(output_dir).absolute() if output_dir is not None else Path.cwd().joinpath(".ash", "ash_output")

    opts = ScanOptions(
        source_dir=_source_dir,
        output_dir=_output_dir,
        config=config,
        config_overrides=config_overrides,
        offline=offline,
        strategy=strategy,
        scanners=scanners,
        excluded_scanners=exclude_scanners,
        progress=progress,
        output_formats=output_formats,
        cleanup=cleanup,
        phases=phases,
        inspect=inspect,
        existing_results=existing_results,
        python_based_plugins_only=python_based_plugins_only,
        quiet=quiet,
        simple=simple,
        verbose=verbose,
        debug=debug,
        color=color,
        fail_on_findings=fail_on_findings,
        ignore_suppressions=ignore_suppressions,
        min_severity=min_severity,
        changed_files_only=changed_files_only,
        base_ref=base_ref,
        mode=mode,
        show_summary=show_summary,
        log_level=log_level,
        build=build,
        run=run,
        force=force,
        oci_runner=oci_runner,
        build_target=build_target,
        offline_semgrep_rulesets=offline_semgrep_rulesets,
        container_uid=container_uid,
        container_gid=container_gid,
        ash_revision_to_install=ash_revision_to_install,
        custom_containerfile=custom_containerfile,
        custom_build_arg=custom_build_arg,
        ash_plugin_modules=ash_plugin_modules,
        container_network=container_network,
    )

    logger = _setup_logger(opts)

    config_fail_on_findings: Optional[bool] = _resolve_config_fail_on_findings(opts)
    results: Optional[AshAggregatedResults]
    if opts.mode == RunMode.container:
        results = _run_container_mode(opts, logger, resolved_fail_on_findings=config_fail_on_findings)
    else:
        results, _local_config_fof = _run_local_mode(opts, logger)
        # _run_local_mode resolves config via the live orchestrator; prefer that
        # value over the file-based pre-read when it differs (e.g. config_overrides
        # applied by the orchestrator may alter fail_on_findings).
        if _local_config_fof is not None:
            config_fail_on_findings = _local_config_fof

    exit_code = _compute_exit_code(results, opts, config_fail_on_findings)

    if opts.show_summary:
        scanner_metrics = get_unified_scanner_metrics(asharp_model=results) if results else []
        actionable_findings = sum(item.actionable for item in scanner_metrics)
        _print_summary(results, opts, scan_start_time, actionable_findings)

        if exit_code == 2 and not opts.quiet:
            actionable_count = sum(
                item.actionable
                for item in (get_unified_scanner_metrics(asharp_model=results) if results else [])
            )
            print("\n[yellow]=== ASH Exit Codes ===[/yellow]")
            print("  0: Success - No actionable findings or not configured to fail on findings")
            print("  1: Error during execution")
            print(
                f"  2: Actionable findings detected when configured with `fail_on_findings: true`."
                f" Default is True. Current value: {opts.fail_on_findings if opts.fail_on_findings is not None else True}"
            )
            print(
                f"[bold red]ERROR (2) Exiting due to {actionable_count} actionable findings found in ASH scan[/bold red]"
            )

    if exit_code == 1:
        print("[bold red]ERROR (1) Exiting due to exception during ASH scan[/bold red]")

    if exit_code != 0:
        sys.exit(exit_code)

    return results
