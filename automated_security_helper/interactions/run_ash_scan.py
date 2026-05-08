# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# Removed unused import
import logging
import os
import platform
import time
from typing import List
from pydantic import BaseModel
import typer
import json
import sys
from pathlib import Path
from rich import print

from automated_security_helper.core.constants import (
    ASH_CONFIG_FILE_NAMES,
    ASH_WORK_DIR_NAME,
    is_offline_mode,
)
from automated_security_helper.core.enums import AshLogLevel, BuildTarget
from automated_security_helper.core.enums import ExecutionPhase
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.core.enums import ExecutionStrategy
from automated_security_helper.core.enums import RunMode
from automated_security_helper.interactions.run_ash_container import (
    run_ash_container,
)
from automated_security_helper.core.enums import ExportFormat
from automated_security_helper.core.unified_metrics import (
    get_unified_scanner_metrics,
)


def format_duration(seconds):
    """Format duration in seconds to a human-readable string."""
    # Extract hours, minutes, seconds
    hours, remainder = divmod(int(seconds), 3600)
    minutes, seconds = divmod(remainder, 60)

    # Format the duration string
    if hours > 0:
        return f"{hours}h {minutes}m {seconds}s"
    elif minutes > 0:
        return f"{minutes}m {seconds}s"
    else:
        return f"{seconds}s"


def _filter_results_to_changed_files(
    results: "AshAggregatedResults",
    changed_files: set,
    source_dir: Path,
) -> "AshAggregatedResults":
    """Remove SARIF results whose primary location is not in *changed_files*.

    Operates on the aggregated SARIF report in-place and returns results for
    convenience.  If *changed_files* is empty, all findings are removed (no
    files changed means zero relevant findings).
    """
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
            # Strip file:// prefix variants emitted by some scanners.
            if uri.startswith("file://"):
                uri = uri[7:]
                if uri.startswith("///"):
                    uri = uri[2:]
            resolved = Path(source_dir).joinpath(uri).resolve()
            if resolved in changed_files:
                filtered.append(result)
        run.results = filtered
    return results


def run_ash_scan(
    source_dir: str | Path | None = None,
    output_dir: str | Path | None = None,
    config: str | None = None,
    config_overrides: List[str] | None = None,
    offline: bool = False,
    strategy: ExecutionStrategy = ExecutionStrategy.PARALLEL.value,
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
    *args,
    **kwargs,
):
    """Runs an ASH scan against the source-dir, outputting results to the output-dir. This is the default command used when there is no explicit. subcommand specified."""

    # Resolve cwd-based defaults at call time (not import time).
    if source_dir is None:
        source_dir = Path.cwd().as_posix()
    if output_dir is None:
        output_dir = Path.cwd().joinpath(".ash", "ash_output").as_posix()

    # Rebind mutable defaults so each call gets its own collection.
    if config_overrides is None:
        config_overrides = []
    if scanners is None:
        scanners = []
    if exclude_scanners is None:
        exclude_scanners = []
    if output_formats is None:
        output_formats = []
    if phases is None:
        phases = [ExecutionPhase.CONVERT, ExecutionPhase.SCAN, ExecutionPhase.REPORT]
    if custom_build_arg is None:
        custom_build_arg = []
    if ash_plugin_modules is None:
        ash_plugin_modules = []

    # Record the start time for calculating scan duration
    scan_start_time = time.time()

    source_dir = Path(source_dir).absolute()
    output_dir = Path(output_dir).absolute()

    # These are lazy-loaded to prevent slow CLI load-in, which impacts tab-completion
    from automated_security_helper.core.orchestrator import ASHScanOrchestrator
    from automated_security_helper.utils.log import get_logger

    final_log_level = (
        AshLogLevel.VERBOSE
        if verbose
        else (
            AshLogLevel.DEBUG
            if debug
            else (
                AshLogLevel.ERROR
                if (
                    quiet
                    or simple
                    or log_level
                    in [
                        AshLogLevel.QUIET,
                        AshLogLevel.ERROR,
                        AshLogLevel.SIMPLE,
                    ]
                )
                else log_level
            )
        )
    )
    final_logging_log_level = logging._nameToLevel.get(
        final_log_level.value, logging.INFO
    )
    # Handle simple mode - this will be used to configure the logger for simplified output
    simple_logging = simple or log_level == AshLogLevel.SIMPLE

    logger = get_logger(
        level=final_logging_log_level,
        output_dir=Path(output_dir),
        show_progress=progress
        and not quiet  # Don't show progress in quiet mode
        and not simple  # Don't show progress in simple mode
        and os.environ.get("ASH_IN_CONTAINER", "NO").upper()
        not in ["YES", "1", "TRUE"],
        use_color=color,
        simple_format=simple_logging,  # Pass the simple flag to the logger
        truncate_log=existing_results
        is None,  # Don't truncate when using existing results
    )
    # Initialize results as None at the start to avoid UnboundLocalError
    results = None
    # If mode is container, run the container version
    if mode == RunMode.container:
        if changed_files_only:
            logger.warning("--changed-files-only is not supported in container mode; performing full scan")

        # Pass the current context to run_ash_container
        new_args = []

        # Convert phases to args
        for phase in phases:
            new_args.extend(["--phases", phase.value])

        # Run the container version
        container_result = run_ash_container(
            source_dir=source_dir,
            output_dir=output_dir,
            offline=offline,
            log_level=log_level,
            verbose=verbose,
            debug=debug,
            color=color,
            simple=simple,
            quiet=quiet,
            build=build,
            run=run,
            force=force,
            oci_runner=oci_runner,
            build_target=build_target,
            offline_semgrep_rulesets=offline_semgrep_rulesets,
            container_uid=container_uid,
            container_gid=container_gid,
            config=config,
            config_overrides=config_overrides,
            strategy=strategy,
            scanners=scanners,
            exclude_scanners=exclude_scanners,
            progress=progress,
            output_formats=output_formats,
            cleanup=cleanup,
            phases=phases,
            inspect=inspect,
            existing_results=existing_results,
            python_based_plugins_only=python_based_plugins_only,
            fail_on_findings=fail_on_findings,
            ash_revision_to_install=ash_revision_to_install,
            custom_containerfile=custom_containerfile,
            custom_build_arg=custom_build_arg,
            ash_plugin_modules=ash_plugin_modules,
            # *new_args,
            # **kwargs,
        )

        # Add debug output to print the full command
        if debug:
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

        # Check if the container run was successful
        if hasattr(container_result, "returncode") and container_result.returncode != 0:
            # If container failed, propagate the error
            logger.error(
                f"Container execution failed with code {container_result.returncode}"
            )
            # Print stderr to help debug the issue
            if hasattr(container_result, "stderr") and container_result.stderr:
                logger.error(f"Container stderr:\n{container_result.stderr}")
                print(
                    f"\n[bold red]Container Error Output:[/bold red]\n{container_result.stderr}"
                )
            if hasattr(container_result, "stdout") and container_result.stdout:
                logger.debug(f"Container stdout:\n{container_result.stdout}")
                if debug:
                    print(
                        f"\n[bold blue]Container Standard Output:[/bold blue]\n{container_result.stdout}"
                    )

        # When build-only (run=False), no scan results are produced
        if not run:
            if hasattr(container_result, "returncode") and container_result.returncode != 0:
                sys.exit(container_result.returncode)
            sys.exit(0)

        # Load the results from the output file
        output_file = Path(output_dir).joinpath("ash_aggregated_results.json")
        if output_file.exists():
            with open(output_file, mode="r", encoding="utf-8") as f:
                content = f.read()
                try:
                    results = AshAggregatedResults.model_validate_json(content)
                except Exception as e:
                    logger.error(f"Failed to parse results file: {e}")
                    sys.exit(1)
        else:
            logger.error(f"Results file not found at {output_file}")
            sys.exit(1)

    else:
        # Local mode - use the orchestrator directly
        starting_dir = Path.cwd()
        os.chdir(source_dir)
        _offline_was_set = False
        if offline:
            os.environ["ASH_OFFLINE"] = "YES"
            _offline_was_set = True

        # Resolve the set of changed files (if requested) before entering
        # the orchestrator so we can restrict the scan set and later filter
        # SARIF output.
        _changed_file_set = None
        if changed_files_only:
            from automated_security_helper.utils.get_scan_set import (
                get_changed_files,
            )

            changed_paths = get_changed_files(base_ref=base_ref, cwd=Path(source_dir))
            if changed_paths is not None:
                # Resolve to absolute paths rooted in source_dir for
                # consistent comparison later.
                _changed_file_set = {
                    Path(source_dir).joinpath(p).resolve() for p in changed_paths
                }

        try:
            # Create orchestrator instance
            source_dir = Path(source_dir)
            output_dir = Path(output_dir)

            # Placeholder for an optional shallow-clone of the source tree.
            # The cleanup block at the end of this branch still references
            # temp_clone_dir, so keep the sentinel even though no code path
            # currently assigns it.
            temp_clone_dir = None

            if not quiet and not simple:
                logger.verbose(f"Source directory: {source_dir.as_posix()}")
                logger.verbose(f"Output directory: {output_dir.as_posix()}")
                logger.verbose(f"Scanners specified: {scanners}")
                logger.verbose(f"Scanners excluded: {exclude_scanners}")

            if config is None:
                for config_file in ASH_CONFIG_FILE_NAMES:
                    def_paths = [
                        Path(source_dir).joinpath(config_file),
                        Path(source_dir).joinpath(".ash", config_file),
                    ]
                    for def_path in def_paths:
                        if def_path.exists():
                            logger.info(
                                f"Using config file found at: {def_path.as_posix()}"
                            )
                            config = def_path.as_posix()
                            break
                    if config is not None:
                        break
            else:
                logger.info(f"Using config file specified at: {config}")

            if config_overrides:
                logger.info(f"Applying {len(config_overrides)} configuration overrides")

            final_scanners = scanners or []
            if mode == RunMode.precommit:
                fast_scanners = [
                    "bandit",
                    "detect-secrets",
                    "checkov",
                    "cdk-nag",
                    "npm-audit",
                ]
                final_scanners = list(set(final_scanners + fast_scanners))

            # Process excluded scanners
            final_excluded_scanners = exclude_scanners or []

            final_show_progress = (
                progress
                and final_log_level
                not in [
                    AshLogLevel.QUIET,
                    AshLogLevel.SIMPLE,
                    AshLogLevel.VERBOSE,
                    AshLogLevel.DEBUG,
                ]
                and os.environ.get("CI", None) is None
                and os.environ.get("ASH_IN_CONTAINER", "NO").upper()
                not in [
                    "YES",
                    "1",
                    "TRUE",
                ]
            )

            orchestrator = ASHScanOrchestrator(
                source_dir=source_dir,
                output_dir=output_dir,
                work_dir=output_dir.joinpath(ASH_WORK_DIR_NAME),
                enabled_scanners=final_scanners,
                excluded_scanners=final_excluded_scanners,
                config_path=config,
                config_overrides=config_overrides,
                verbose=verbose or debug,
                debug=debug,
                strategy=(
                    ExecutionStrategy.PARALLEL
                    if strategy == ExecutionStrategy.PARALLEL
                    else ExecutionStrategy.SEQUENTIAL
                ),
                no_cleanup=not cleanup,
                output_formats=output_formats,
                show_progress=final_show_progress,
                simple_mode=simple,
                show_summary=show_summary,
                color_system=(
                    "windows"
                    if platform.system() == "Windows"
                    else "auto"
                    if color
                    else None
                ),
                offline=(offline if offline is not None else is_offline_mode()),
                existing_results_path=(
                    Path(existing_results) if existing_results else None
                ),
                python_based_plugins_only=python_based_plugins_only,
                ignore_suppressions=ignore_suppressions,
                ash_plugin_modules=ash_plugin_modules,  # Pass the ash_plugin_modules parameter to the orchestrator
            )

            # Determine which phases to run. Process them in required order to build the
            # final ordered list of execution.
            phases_to_run = []
            if ExecutionPhase.CONVERT in phases:
                phases_to_run.append("convert")
            if ExecutionPhase.SCAN in phases:
                phases_to_run.append("scan")
            if ExecutionPhase.REPORT in phases:
                phases_to_run.append("report")
            if ExecutionPhase.INSPECT in phases or inspect:
                phases_to_run.append("inspect")

            # Default to all phases if none specified
            if not phases_to_run:
                phases_to_run = ["convert", "scan", "report"]

            if not quiet and not simple:
                logger.debug(f"Running phases: {phases_to_run}")

            # Execute scan with specified phases
            results = orchestrator.execute_scan(phases=phases_to_run)

            # For simple mode, print a minimal completion message
            if simple and not quiet:
                typer.echo("\nASH scan completed.")

            # When scanning only changed files, strip findings whose
            # primary location falls outside the changed set.
            if _changed_file_set and results is not None:
                results = _filter_results_to_changed_files(
                    results, _changed_file_set, source_dir
                )
                # Re-write SARIF and reports since the report phase already
                # wrote them before filtering. Overwrite with filtered data.
                sarif_path = Path(output_dir) / "reports" / "ash.sarif"
                if sarif_path.exists() and results.sarif:
                    sarif_path.write_text(
                        results.sarif.model_dump_json(indent=2, by_alias=True),
                        encoding="utf-8",
                    )

            if isinstance(results, BaseModel):
                content = results.model_dump_json(indent=2, by_alias=True)
            else:
                content = json.dumps(results, indent=2, default=str)

            # Write results to output file
            output_file = Path(output_dir).joinpath("ash_aggregated_results.json")
            with open(output_file, mode="w", encoding="utf-8") as f:
                f.write(content)

            # Clean up the temporary clone directory if it was created
            try:
                if (
                    "temp_clone_dir" in locals()
                    and temp_clone_dir
                    and os.path.exists(temp_clone_dir)
                ):
                    import shutil

                    shutil.rmtree(temp_clone_dir)
                    logger.debug(
                        f"Cleaned up temporary clone directory: {temp_clone_dir}"
                    )
            except Exception as e:
                logger.warning(f"Error cleaning up temporary clone directory: {e}")

        except Exception as e:
            logger.exception(e)
            print(
                f"[bold red]ERROR (1) Exiting due to exception during ASH scan: {e}[/bold red]",
            )
            sys.exit(1)
        finally:
            os.chdir(starting_dir)
            if _offline_was_set:
                os.environ.pop("ASH_OFFLINE", None)

    # Check if we should fail on findings
    final_fail_on_findings = (
        fail_on_findings
        if fail_on_findings is not None
        else (
            orchestrator.config.fail_on_findings
            if "orchestrator" in locals()
            and hasattr(orchestrator, "config")
            and orchestrator.config.fail_on_findings is not None
            else True
        )
    )

    # Count actionable findings from the persisted SARIF report file.
    # The SARIF reporter correctly serializes all suppressions (including those
    # from the final suppression pass), while in-memory model access has a
    # Pydantic mutation bug where result.suppressions isn't reliably set.
    scanner_metrics = get_unified_scanner_metrics(asharp_model=results)
    actionable_findings = sum(item.actionable for item in scanner_metrics)
    sarif_file = Path(output_dir).joinpath("reports", "ash.sarif")
    if sarif_file.exists():
        try:
            with open(sarif_file, encoding="utf-8") as f:
                sarif_json = json.load(f)  # nosec
            sarif_active = 0
            for run in sarif_json.get("runs", []):
                for r in run.get("results", []):
                    if not r.get("suppressions"):
                        sarif_active += 1
            actionable_findings = sarif_active
        except Exception:  # nosec B110
            pass  # Fall through to unified metrics count

    # Apply --min-severity filtering: if no finding meets the threshold,
    # treat actionable_findings as 0 for exit-code purposes.  Findings are
    # still present in all reports for transparency.
    _SEVERITY_RANK = {"critical": 3, "high": 3, "medium": 2, "low": 1, "none": 0}
    _SARIF_LEVEL_TO_SEVERITY = {"error": "high", "warning": "medium", "note": "low"}
    min_sev_rank = _SEVERITY_RANK.get(min_severity.lower(), 1)
    if min_sev_rank > 0 and actionable_findings > 0 and results is not None:
        has_qualifying = False
        try:
            sarif = getattr(results, "sarif", None)
            if sarif is None or not getattr(sarif, "runs", None):
                has_qualifying = True
            for run in getattr(sarif, "runs", []) if not has_qualifying else []:
                for result in getattr(run, "results", []):
                    if result.suppressions:
                        continue
                    level = getattr(result, "level", "note")
                    if isinstance(level, str):
                        level = level.lower()
                    mapped = _SARIF_LEVEL_TO_SEVERITY.get(level, "low")
                    if _SEVERITY_RANK.get(mapped, 1) >= min_sev_rank:
                        has_qualifying = True
                        break
                if has_qualifying:
                    break
        except Exception:
            # If we can't inspect the model, don't suppress the exit code
            has_qualifying = True
        if not has_qualifying:
            actionable_findings = 0
    # Only display the final metrics and guidance if show_summary is True
    if show_summary:
        # Calculate scan duration
        scan_duration = time.time() - scan_start_time
        duration_str = format_duration(scan_duration)

        # Add helpful guidance about where to find reports
        relative_out_dir = (
            Path(output_dir).relative_to(source_dir)
            if Path(output_dir).is_relative_to(source_dir)
            else Path(output_dir)
        )
        out_dir_alias = os.environ.get(
            "ASH_ACTUAL_OUTPUT_DIR",
            relative_out_dir.as_posix(),
        )
        if not quiet:
            # Show config resolution warnings prominently before results
            if results and hasattr(results, "validation_checkpoints"):
                config_warnings = [
                    cp
                    for cp in results.validation_checkpoints
                    if cp.get("type") == "config_warning"
                ]
                if config_warnings:
                    print("\n[bold yellow]⚠️  CONFIGURATION WARNING ⚠️[/bold yellow]")
                    for cw in config_warnings:
                        print(f"[yellow]  {cw['message']}[/yellow]")
                    print("")

            print(
                f"\n[cyan]=== ASH Scan Completed in {duration_str}: Next Steps ===[/cyan]"
            )
            print("View detailed findings...")
            print(f"  - SARIF: '{out_dir_alias}/reports/ash.sarif'")
            print(f"  - JUnit: '{out_dir_alias}/reports/ash.junit.xml'")
            print(
                f"  - ASH aggregated results JSON available at: '{out_dir_alias}/{output_file.relative_to(output_dir).as_posix()}'"
            )

        # If there are actionable findings, provide guidance
        if actionable_findings is not None and actionable_findings > 0:
            print("\n[magenta]=== Actionable findings detected! ===[/magenta]")
            print("To investigate...")
            print(
                "  1. Open one of the summary reports for a user-friendly table of the findings:"
            )
            print(
                f"    - HTML report of all findings: '{out_dir_alias}/reports/ash.html'"
            )
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

    # Exit with non-zero code if configured to fail on findings and there are actionable findings
    if final_fail_on_findings and (
        actionable_findings is None or actionable_findings > 0
    ):
        # Document exit codes
        if show_summary and not quiet:
            print(
                "\n[yellow]=== ASH Exit Codes ===[/yellow]",
            )
            print(
                "  0: Success - No actionable findings or not configured to fail on findings",
            )
            print(
                "  1: Error during execution",
            )
            print(
                f"  2: Actionable findings detected when configured with `fail_on_findings: true`. Default is True. Current value: {final_fail_on_findings}",
            )
        if actionable_findings is None:
            print(
                "[bold red]ERROR (1) Exiting due to exception during ASH scan[/bold red]"
            )
            sys.exit(
                1
            )  # Using exit code 1 specifically for errors due to None actionable findings
        else:
            print(
                f"[bold red]ERROR (2) Exiting due to {actionable_findings} actionable findings found in ASH scan[/bold red]",
            )
            sys.exit(2)  # Using exit code 2 specifically for actionable findings

    return results
