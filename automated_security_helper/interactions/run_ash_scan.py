# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import logging
import os
from typing import List
import typer
import json
import sys
from pathlib import Path
from rich import print

from automated_security_helper.core.constants import (
    ASH_CONFIG_FILE_NAMES,
    ASH_WORK_DIR_NAME,
)
from automated_security_helper.core.enums import AshLogLevel, BuildTarget
from automated_security_helper.core.enums import Phases
from automated_security_helper.core.enums import Strategy
from automated_security_helper.core.enums import RunMode
from automated_security_helper.interactions.run_ash_container import (
    run_ash_container,
)
from automated_security_helper.core.enums import ExportFormat


def run_ash_scan(
    source_dir: str = Path.cwd().as_posix(),
    output_dir: str = Path.cwd().joinpath(".ash", "ash_output").as_posix(),
    config: str = None,
    offline: bool = False,
    strategy: Strategy = Strategy.parallel.value,
    scanners: List[str] = [],
    exclude_scanners: List[str] = [],
    progress: bool = True,
    output_formats: List[ExportFormat] = [],
    cleanup: bool = False,
    phases: List[Phases] = [
        Phases.convert,
        Phases.scan,
        Phases.report,
    ],
    inspect: bool = False,
    existing_results: str = None,
    python_based_plugins_only: bool = False,
    quiet: bool = False,
    simple: bool = False,
    verbose: bool = False,
    debug: bool = False,
    color: bool = True,
    fail_on_findings: bool | None = None,
    mode: RunMode = RunMode.local,
    show_summary: bool = True,
    log_level: AshLogLevel = AshLogLevel.INFO,
    # Container-specific args
    build: bool = True,
    run: bool = True,
    force: bool = False,
    oci_runner: str = None,
    build_target: BuildTarget = BuildTarget.NON_ROOT,
    offline_semgrep_rulesets: str = "p/ci",
    container_uid: str | None = None,
    container_gid: str | None = None,
    ash_revision_to_install: str | None = None,
    custom_containerfile: str | None = None,
    custom_build_arg: List[str] = [],
    *args,
    **kwargs,
):
    """Runs an ASH scan against the source-dir, outputting results to the output-dir. This is the default command used when there is no explicit. subcommand specified."""

    # These are lazy-loaded to prevent slow CLI load-in, which impacts tab-completion
    from automated_security_helper.core.enums import ExecutionStrategy
    from automated_security_helper.core.orchestrator import ASHScanOrchestrator
    from automated_security_helper.models.asharp_model import ASHARPModel
    from automated_security_helper.utils.log import get_logger

    final_log_level = (
        AshLogLevel.VERBOSE
        if verbose
        else AshLogLevel.DEBUG
        if debug
        else AshLogLevel.ERROR
        if (
            quiet
            or log_level
            in [
                AshLogLevel.QUIET,
                AshLogLevel.ERROR,
            ]
        )
        else AshLogLevel.INFO
        if (simple or log_level in [AshLogLevel.SIMPLE])
        else log_level
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
    )

    # If mode is container, run the container version
    if mode == RunMode.container:
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

        # Load the results from the output file
        output_file = Path(output_dir).joinpath("ash_aggregated_results.json")
        if output_file.exists():
            with open(output_file, mode="r", encoding="utf-8") as f:
                content = f.read()
                try:
                    results = ASHARPModel.model_validate_json(content)
                except Exception as e:
                    logger.error(f"Failed to parse results file: {e}")
                    raise sys.exit(1) from None
        else:
            logger.error(f"Results file not found at {output_file}")
            raise sys.exit(1) from None

    else:
        # Local mode - use the orchestrator directly
        try:
            # Create orchestrator instance
            source_dir = Path(source_dir)
            output_dir = Path(output_dir)

            if not quiet and not simple:
                logger.debug(f"Scanners specified: {scanners}")

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

            orchestrator = ASHScanOrchestrator(
                source_dir=source_dir,
                output_dir=output_dir,
                work_dir=output_dir.joinpath(ASH_WORK_DIR_NAME),
                enabled_scanners=final_scanners,
                excluded_scanners=final_excluded_scanners,
                config_path=config,
                verbose=verbose or debug,
                debug=debug,
                strategy=(
                    ExecutionStrategy.PARALLEL
                    if strategy == Strategy.parallel
                    else ExecutionStrategy.SEQUENTIAL
                ),
                no_cleanup=not cleanup,
                output_formats=output_formats,
                show_progress=progress
                and not quiet  # Don't show progress in quiet mode
                and not simple  # Don't show progress in simple mode
                and (
                    os.environ.get("ASH_IN_CONTAINER", "NO").upper()
                    not in [
                        "YES",
                        "1",
                        "TRUE",
                    ]  # Running inside the container is not guaranteed to produce the live progress outputs correctly
                    or os.environ.get("CI", None)
                    is not None  # Neither is running in a CI pipeline
                ),
                simple_mode=simple,  # Pass the simple mode flag to the orchestrator
                color_system="auto" if color else None,
                offline=(
                    offline
                    if offline is not None
                    else os.environ.get("ASH_OFFLINE", "NO").upper()
                    in ["YES", "1", "TRUE"]
                ),
                existing_results_path=(
                    Path(existing_results) if existing_results else None
                ),
                python_based_plugins_only=python_based_plugins_only,  # Pass the python_based_plugins_only flag to the orchestrator
            )

            # Determine which phases to run. Process them in required order to build the
            # final ordered list of execution.
            phases_to_run = []
            if Phases.convert in phases:
                phases_to_run.append("convert")
            if Phases.scan in phases:
                phases_to_run.append("scan")
            if Phases.report in phases:
                phases_to_run.append("report")
            if Phases.inspect in phases or inspect:
                phases_to_run.append("inspect")

                # If inspect is enabled via command line, update the config
                if inspect and orchestrator.config:
                    if not hasattr(orchestrator.config, "inspect"):
                        setattr(orchestrator.config, "inspect", {})
                    orchestrator.config.inspect["enabled"] = True

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

            if isinstance(results, ASHARPModel):
                content = results.model_dump_json(indent=2, by_alias=True)
            else:
                content = json.dumps(results, indent=2, default=str)

            # Write results to output file
            output_file = Path(output_dir).joinpath("ash_aggregated_results.json")
            with open(output_file, mode="w", encoding="utf-8") as f:
                f.write(content)

        except Exception as e:
            logger.exception(e)
            print(
                f"[bold red]ERROR (1) Exiting due to exception during ASH scan: {e}[/bold red]",
            )
            raise sys.exit(1) from None

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

    # Get the count of actionable findings from summary_stats
    actionable_findings = results.metadata.summary_stats.get("actionable", 0)

    # Only display the final metrics and guidance if show_summary is True
    if show_summary:
        # Add helpful guidance about where to find reports
        relative_out_dir = (
            Path(output_dir).relative_to(source_dir)
            if Path(output_dir).is_relative_to(source_dir)
            else output_dir
        )
        out_dir_alias = os.environ.get(
            "ASH_ACTUAL_OUTPUT_DIR",
            relative_out_dir.as_posix(),
        )
        if not quiet:
            print("\n[cyan]=== Scan Complete: Next Steps ===[/cyan]")
            print("View detailed findings...")
            print(f"  - HTML report of findings: '{out_dir_alias}/reports/ash.html'")
            print(f"  - Markdown summary: '{out_dir_alias}/reports/ash.summary.md'")
            print(f"  - Text summary: '{out_dir_alias}/reports/ash.summary.txt'")
            print(f"  - Full SARIF report: '{out_dir_alias}/reports/ash.sarif'")
            print(f"  - Full JUnitXML report: '{out_dir_alias}/reports/ash.junit.xml'")
            print(
                f"  - ASH aggregated results JSON available at: '{out_dir_alias}/{output_file.relative_to(output_dir).as_posix()}'"
            )

        # If there are actionable findings, provide guidance
        if actionable_findings > 0:
            print("\n[magenta]=== Actionable findings detected! ===[/magenta]")
            print("To investigate...")
            print("  1. Open the HTML report for a user-friendly view")
            print("  2. Use `ash inspect findings` for an interactive exploration")
            print(
                f"  3. Review scanner-specific reports and outputs in the '{out_dir_alias}/scanners' directory"
            )

    # Exit with non-zero code if configured to fail on findings and there are actionable findings
    if (
        final_fail_on_findings
        and actionable_findings > 0
        or actionable_findings is None
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
                f"  2: Actionable findings detected when configured with fail_on_findings: {final_fail_on_findings} (default: True)",
            )
            print(
                f"[bold red]ERROR (2) Exiting due to {actionable_findings} actionable findings found in ASH scan[/bold red]",
            )
        raise sys.exit(
            2
        ) from None  # Using exit code 2 specifically for actionable findings

    return results
