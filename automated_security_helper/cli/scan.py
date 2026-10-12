# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import contextlib
import os

# `print` shadows the builtin on purpose: this is rich's documented import
# idiom, so every print() below renders markup and respects the console. The
# fix A004 wants is an alias, which would mean rewriting every call in this
# module for no behavior change -- and tests/unit/cli/mcp/test_stdout_jsonrpc_safety.py
# reasons about this exact import form.
from rich import print  # noqa: A004
from typing import Annotated, List, NoReturn, Optional
import typer
from pathlib import Path

from automated_security_helper.core.constants import (
    ASH_CONFIG_SOURCES_DESCRIPTION,
)
from automated_security_helper.core.enums import (
    AshLogLevel,
    BuildTarget,
    ExecutionPhase,
    ExecutionStrategy,
    RunMode,
    SandboxMode,
)
from automated_security_helper.core.exceptions import (
    ASHConfigValidationError,
    ShardSelectionError,
    WorkspaceDefinitionError,
)
from automated_security_helper.core.sharding import validate_shard_selection
from automated_security_helper.interactions.run_ash_scan import (
    resolve_workspace_execution_config,
    run_ash_scan,
)
from automated_security_helper.core.enums import ExportFormat
from automated_security_helper.models.workspace import WorkspaceExitCode
from automated_security_helper.utils.content_databases import (
    content_db_staleness_flag_overrides,
    get as get_content_database,
    go_duration,
)
from automated_security_helper.utils.get_ash_version import get_ash_version
from automated_security_helper.utils.get_scan_set import (
    InvalidBaseRefError,
    validate_base_ref,
)
from automated_security_helper.workspace.plan import WorkspacePlan
from automated_security_helper.workspace.resolver import resolve_workspace
from automated_security_helper.workspace.workspace_file import (
    WORKSPACE_AUTO,
    discover_workspace_file,
)


def _from_environment(ctx: typer.Context, param: str) -> bool:
    """Whether click took *param*'s value from its ``envvar``."""
    return getattr(ctx.get_parameter_source(param), "name", None) == "ENVIRONMENT"


def _fail_config_mark(message: str) -> NoReturn:
    """A usage error in container mode's marks for the scan inside: exit 3."""
    typer.secho(message, fg=typer.colors.RED, err=True)
    raise typer.Exit(3)


def _marked_outside_the_chain(configs: List[Path], marked: List[str]) -> List[str]:
    """The paths of *marked* that are not files of the extends chain of any of
    *configs*: ``--config`` and the file ``ASH_CONFIG`` names.

    Container mode names each file it marks by its path inside the container, so a
    name that misses both chains would leave that file's grants in place
    unnoticed; it is refused instead. A chain that does not load is left for the
    scan to report, with its own exit code.
    """
    if not marked:
        return []
    from automated_security_helper.config.config_sources import (
        default_confinement_root,
    )
    from automated_security_helper.config.resolve_config import read_config_document

    files: set[Path] = set()
    for config in configs:
        try:
            chain = read_config_document(
                config, confine_to=default_confinement_root(config), log_failure=False
            ).chain
        except Exception:  # noqa: BLE001 - the scan reports a config that does not load
            return []
        files.update(Path(os.path.realpath(path)) for path in chain)
    return [path for path in marked if Path(os.path.realpath(path)) not in files]


def _fail_workspace(
    message: str,
    code: WorkspaceExitCode = WorkspaceExitCode.WORKSPACE_ERROR,
) -> NoReturn:
    """Report a workspace-mode refusal and exit with its contract code.

    Written with ``typer.echo`` rather than the Rich ``print`` imported above,
    because these messages quote operator-supplied paths and Rich would read a
    bracketed fragment in one as a style name and fail while rendering the error.
    """
    typer.echo(message, err=True)
    raise typer.Exit(code)


def _fail_shard_selection(message: str) -> NoReturn:
    """Report a shard-selection refusal and exit 1.

    Exit 1, and deliberately not the 2 that click gives a ``typer.BadParameter``:
    ASH already spends 2 on "actionable findings were found", so a usage error
    exiting 2 would be read by a CI gate as a scan that found problems. 1 is ASH's
    generic error code, which a pipeline treats as "this job produced no scan" --
    the truth here.

    Written with ``typer.echo`` rather than the Rich ``print`` imported above, for
    the same reason as :func:`_fail_workspace`: these messages quote
    operator-supplied values.
    """
    typer.echo(message, err=True)
    raise typer.Exit(1)


def _fail_usage(message: str) -> NoReturn:
    """Report a refused invocation and exit 1, the way shard-selection errors do.

    Exit 1 for the reason :func:`_fail_shard_selection` gives: 2 already means
    "actionable findings were found", so a usage error must not exit 2 and be
    read by a CI gate as a scan that found problems. Written with ``typer.echo``
    to stderr because these messages quote operator-supplied paths, which Rich
    would try to read as markup.
    """
    typer.echo(message, err=True)
    raise typer.Exit(1)


def _validate_shard_options(
    shard_index: int | None,
    shard_count: int | None,
    workspace: str | None,
) -> None:
    """Refuse an unusable shard selection, or one that workspace mode cannot honour.

    Called before workspace resolution and before any cwd-based default is
    applied. Every case here means the operator's CI matrix is wrong, and the scan
    they are about to pay for would cover part of the repository while reporting
    itself as a whole one.

    The workspace conflict is checked first. When both problems are present,
    telling the operator the pair is unavailable in workspace mode saves them from
    fixing a missing ``--shard-count`` that would then be rejected anyway.
    """
    if workspace is not None and (shard_index is not None or shard_count is not None):
        _fail_shard_selection(
            "--shard-index/--shard-count cannot be combined with --workspace. "
            "Both spread one scan over more compute, but along different axes, and "
            "only sharding is recombinable: it partitions the scanners and stamps "
            "the partition onto the results so 'ash merge' can prove the shards "
            "reconstruct exactly one whole scan. Workspace mode's unified results "
            "file is assembled from the per-project payloads and carries none of "
            "each project's scan metadata, so a sharded workspace run would write "
            "results that merge has no provenance to verify coverage from -- and "
            "an unverifiable partial scan reads as a clean one. Either scan the "
            "workspace whole on one executor, or give each CI job one project via "
            "--source-dir and shard that."
        )

    try:
        validate_shard_selection(shard_index, shard_count)
    except ShardSelectionError as exc:
        _fail_shard_selection(str(exc))


def _handle_workspace_mode(
    workspace: str,
    source_dir: str | None,
    allow_missing_projects: bool,
    dry_run: bool,
    workspace_config: str | None = None,
    config_overrides: tuple[str, ...] = (),
    config: str | None = None,
) -> "WorkspacePlan":
    """Resolve a workspace and return the plan, or exit.

    Every failure path is an exit, because a workspace that will not resolve has
    nothing to scan: 4 for a workspace definition or policy problem, 3 for a
    project whose own config is invalid. Never 2 -- that code means a scan ran and
    found actionable findings, which is the opposite of what any exit from here
    reports. ``--dry-run`` also exits, at 0, after printing the plan.

    The success path returns rather than exiting, and the caller runs the scans
    from the same plan object the operator would have inspected. Re-resolving for
    execution would let the two drift, which is exactly what ``--dry-run`` exists
    to rule out.

    Argument validation happens before any filesystem work, so an operator who
    passed a contradictory pair of flags is told that rather than being sent to
    debug their workspace file first.

    ``config`` is ``--config`` (or ``ASH_CONFIG``). The fields it sets are final
    for every project, so it has to reach resolution as well as the scan, which
    gets it as ``ProjectScanSettings.default_config_path``: resolved without it,
    the plan and ``--dry-run`` would report each project's own values for them.
    """
    if source_dir is not None:
        _fail_workspace(
            "--workspace and --source-dir are mutually exclusive. In workspace "
            "mode the directory holding the workspace file is the scan root, so "
            "honouring both would leave it ambiguous which tree was scanned. "
            "Note that --source-dir is also set by the ASH_SOURCE_DIR "
            "environment variable, which counts as setting it."
        )

    try:
        workspace_file = (
            discover_workspace_file(Path.cwd())
            if workspace == WORKSPACE_AUTO
            else Path(workspace)
        )
        plan = resolve_workspace(
            workspace_file,
            allow_missing_projects=allow_missing_projects,
            workspace_config=(
                Path(workspace_config) if workspace_config is not None else None
            ),
            # Resolution needs these so each project's DECLARED threshold
            # reflects an override. The ceiling applies to that, and --dry-run
            # prints the value the scan will actually enforce.
            config_overrides=config_overrides,
            # The same reason, for the operator's config file. Resolved here as
            # the scan resolves it, so a missing or broken file is refused at
            # planning, --dry-run included, and the plan's thresholds are the
            # ones the scan applies.
            default_config=Path(config) if config else None,
        )
    except WorkspaceDefinitionError as exc:
        _fail_workspace(str(exc))
    except ASHConfigValidationError as exc:
        _fail_workspace(str(exc), code=WorkspaceExitCode.INVALID_PROJECT_CONFIG)

    # The workspace root's own config sets how the run executes (parallelism,
    # timeouts), and the run refuses one that cannot be loaded with exit 3. Read
    # here too, so --dry-run does not report a plan the run would refuse.
    try:
        resolve_workspace_execution_config(Path(plan.workspace_root), config)
    except ASHConfigValidationError as exc:
        _fail_workspace(str(exc), code=WorkspaceExitCode.INVALID_PROJECT_CONFIG)

    if dry_run:
        typer.echo(plan.render())
        raise typer.Exit(WorkspaceExitCode.SUCCESS)

    return plan


def run_ash_scan_cli_command(
    ctx: typer.Context,
    source_dir: Annotated[
        str | None,
        typer.Option(
            help="The source directory to scan",
            envvar="ASH_SOURCE_DIR",
            writable=False,
        ),
    ] = None,
    output_dir: Annotated[
        str | None,
        typer.Option(
            help="The directory to output results to",
            envvar="ASH_OUTPUT_DIR",
            writable=True,
        ),
    ] = None,
    scanners: Annotated[
        Optional[List[str]],
        typer.Option(
            help="Specific scanner names to run. Defaults to all scanners.",
            envvar="ASH_SCANNERS",
        ),
    ] = None,
    exclude_scanners: Annotated[
        Optional[List[str]],
        typer.Option(
            help="Specific scanner names to exclude from running. Takes precedence over scanners parameter.",
            envvar="ASH_EXCLUDED_SCANNERS",
        ),
    ] = None,
    ash_plugin_modules: Annotated[
        Optional[List[str]],
        typer.Option(
            help="List of Python modules to import containing ASH plugins and/or event subscribers. These are loaded in addition to the default modules.",
            envvar="ASH_PLUGIN_MODULES",
        ),
    ] = None,
    config_overrides: Annotated[
        Optional[List[str]],
        typer.Option(
            "--config-overrides",
            help="Configuration overrides specified as key-value pairs (e.g., 'reporters.cloudwatch-logs.options.aws_region=us-west-2'). "
            "Supports lists with [item1,item2], append mode with key+=[value], and JSON syntax. See docs/config-overrides.md",
        ),
    ] = None,
    offline: Annotated[
        bool,
        typer.Option(
            help="Run scan in offline/airgapped mode (skips NPM/PNPM/Yarn Audit checks). IMPORTANT: Online access is needed when building ASH to prepare it for usage during a scan! If selecting Offline while performing a build, the ASH container image will be built in offline mode and any typically online-only dependencies like downloadable tool vulnerability databases will be cached in the image itself before publishing for scan usage."
        ),
    ] = False,
    sandbox: Annotated[
        Optional[SandboxMode],
        typer.Option(
            "--sandbox",
            help="Run every scanner subprocess in an OS-level sandbox: read-only source, writable results directory only, private home and temporary directory, no network unless the scanner needs one (never under --offline). 'auto' picks the best available (Linux: bwrap, firejail, landlock; macOS: sandbox-exec). A scanner that cannot be sandboxed as requested is reported MISSING. Overrides the config file's sandbox.mode; default off. Ignored in container mode. See docs/content/docs/scanner-sandbox.md",
            case_sensitive=False,
        ),
    ] = None,
    offline_semgrep_rulesets: Annotated[
        str,
        typer.Option(
            "--offline-semgrep-rulesets",
            help="Specify Semgrep rulesets for use in ASH offline mode",
        ),
    ] = "p/ci",
    strategy: Annotated[
        ExecutionStrategy,
        typer.Option(help="Whether to run scanners in parallel or sequential"),
    ] = ExecutionStrategy.PARALLEL.value,
    progress: Annotated[
        bool,
        typer.Option(
            "--progress/--no-progress",
            "-p/-P",
            help="Show progress of each job live in the console. Defaults to True.",
        ),
    ] = True,
    output_formats: Annotated[
        Optional[List[str]],
        typer.Option(
            "--output-formats",
            "--output-format",
            "--formats",
            "--format",
            "-f",
            help=f"The output formats to use (comma-separated). Available formats: {', '.join([f.value for f in ExportFormat])}",
        ),
    ] = None,
    cleanup: Annotated[
        bool,
        typer.Option(
            help="Clean up 'converted' directory and other temporary files after scan completes. Defaults to False. Note: Scans will always clean up existing files in the output directory before a new scan starts. This parameter only affects the cleanup of the temporary work directory after a scan has completed, typically for inspection of temporary artifacts."
        ),
    ] = False,
    phases: Annotated[
        Optional[List[ExecutionPhase]],
        typer.Option(
            help="The phases to run. Defaults to all phases except inspect.",
        ),
    ] = None,
    inspect: Annotated[
        bool,
        typer.Option(
            help="Enable inspection of SARIF fields after running. This adds the inspect phase to the execution.",
        ),
    ] = False,
    use_existing: Annotated[
        bool,
        typer.Option(
            help="Use an existing ash_aggregated_results.json file in the output-dir. If True, the scan phase will be skipped and reports will be generated from this file.",
        ),
    ] = False,
    version: Annotated[
        bool,
        typer.Option(
            "--version",
            help="Prints version number",
        ),
    ] = False,
    mode: Annotated[
        Optional[RunMode],
        typer.Option(
            help="Execution mode preset. 'precommit' enables python-based plugins only and simplified output. 'container' runs non-Python plugins in a container. 'local' (default) runs everything in the local Python process.",
            envvar="ASH_MODE",
        ),
    ] = RunMode.local,
    python_based_plugins_only: Annotated[
        bool,
        typer.Option(
            "--python-only/--full",
            "--python-based-scanners-only/--all-enabled-scanners",
            "--python-based-plugins-only/--all-enabled-plugins",
            help="Exclude execution of any plugins or tools that have depencies external to Python.",
        ),
    ] = False,
    show_summary: Annotated[
        bool, typer.Option(help="Show metrics table and results summary")
    ] = True,
    quiet: Annotated[bool, typer.Option(help="Hide all log output")] = False,
    log_level: Annotated[
        AshLogLevel,
        typer.Option(
            "--log-level",
            help="Set the log level.",
        ),
    ] = AshLogLevel.INFO,
    config: Annotated[
        str | None,
        typer.Option(
            "--config",
            "-c",
            help=f"The path to the configuration file. By default, ASH looks for the following config file names in the source directory of a scan: {ASH_CONFIG_SOURCES_DESCRIPTION}. Alternatively, the full path to a config file can be provided by setting the ASH_CONFIG environment variable before running ASH.",
            envvar="ASH_CONFIG",
        ),
    ] = None,
    verbose: Annotated[
        bool,
        typer.Option(
            "--verbose",
            "-v",
            help="Enable verbose logging. Any log flag on the command line overrides ASH_VERBOSE.",
            envvar="ASH_VERBOSE",
        ),
    ] = False,
    debug: Annotated[
        bool,
        typer.Option(
            "--debug",
            "-d",
            help="Enable debug logging. Any log flag on the command line overrides ASH_DEBUG.",
            envvar="ASH_DEBUG",
        ),
    ] = False,
    color: Annotated[bool, typer.Option(help="Enable/disable colorized output")] = True,
    fail_on_findings: Annotated[
        bool | None,
        typer.Option(
            help="Enable/disable throwing non-successful exit codes if any actionable findings are found. Defaults to unset, which prefers the configuration value. If this is set directly, it takes precedence over the configuration value."
        ),
    ] = None,
    fail_on_incomplete_scanners: Annotated[
        bool | None,
        typer.Option(
            help=(
                "Exit 1 when a selected scanner did not complete -- ERROR (ran and "
                "failed) or MISSING (dependencies unavailable, so it never ran). "
                "Without this, a run where nothing ran exits 0, the same code as a "
                "clean scan, because no scanner produced any finding. A SKIPPED "
                "scanner, one you did not select or one with nothing of its kind "
                "to scan, does not trip it by itself, so --scanners and "
                "--exclude-scanners both narrow what is gated; but a run in which "
                "every scanner is SKIPPED, such as one where no selected scanner "
                "had a file to scan, exits 1. "
                "Independent of --fail-on-findings, and takes precedence over it "
                "when both would fail: a partial scan's findings are real but its "
                "clean bill of health is not. Defaults to unset, which prefers the "
                "configuration value and then on. Pass "
                "--no-fail-on-incomplete-scanners to accept a partial scan's exit "
                "code, or --exclude-scanners for a tool you do not have, which "
                "records it SKIPPED and says so in the report."
            )
        ),
    ] = None,
    allow_stale_content_db: Annotated[
        bool | None,
        typer.Option(
            help=(
                "Let the scan pass when a scanner's content database (grype's or "
                "trivy's vulnerability database, the offline semgrep/opengrep "
                "rulesets) is older than its declared bound -- for grype, "
                f"{go_duration(get_content_database('grype-db').max_age)} after the "
                "database was built. Without it such a scan exits 1. With it the "
                "scan proceeds and the warning is recorded in the log and in the "
                "reports. --no-allow-stale-content-db forces the default failure. "
                "Defaults to unset, which prefers the `content_db_staleness` config "
                "value and then 'fail'; either form of the flag takes precedence over "
                "the config."
            )
        ),
    ] = None,
    simple: Annotated[
        bool,
        typer.Option(
            help="Simplified output mode with minimal logging",
        ),
    ] = False,
    ignore_suppressions: Annotated[
        bool,
        typer.Option(
            help="Ignore all suppression rules and report all findings regardless of suppression status."
        ),
    ] = False,
    honor_ignore_files: Annotated[
        bool | None,
        typer.Option(
            help=(
                "Whether the .gitignore and .ignore files in the scanned tree decide "
                "which files are left out of ASH's scan set (the files "
                "detect-secrets, cfn-nag, cdk-nag, npm-audit and the converters "
                "read). --no-honor-ignore-files scans the files they match too; "
                "ASH's own exclusions such as .git still apply. Defaults to unset, "
                "which prefers the operator's `honor_ignore_files` config value and "
                "then honoring them. Either form takes precedence over the config. "
                "A config file inside the scanned tree cannot set it. The results "
                "and summaries record whether the ignore files were honored and how "
                "many files they excluded."
            )
        ),
    ] = None,
    min_severity: Annotated[
        str,
        typer.Option(
            help="Minimum severity to trigger non-zero exit code (critical, high, medium, low, none). 'critical' and 'high' are equivalent because SARIF does not distinguish them. Findings below this threshold are still reported but don't affect the exit code.",
        ),
    ] = "low",
    compact_report: Annotated[
        bool,
        typer.Option(
            "--compact-report",
            help="Produce a shorter markdown report suitable for PR comments. Omits the severity legend, scan metadata, footer, and rows for scanners that were skipped or had zero findings.",
        ),
    ] = False,
    changed_files_only: Annotated[
        bool,
        typer.Option(
            "--changed-files-only",
            help="Limit the scan to files changed between the base branch and HEAD. Useful in CI to scan only PR changes. Falls back to a full scan when git is unavailable.",
            envvar="ASH_CHANGED_FILES_ONLY",
        ),
    ] = False,
    base_ref: Annotated[
        str,
        typer.Option(
            "--base-ref",
            help="Git ref to diff against when --changed-files-only is set.",
            envvar="ASH_BASE_REF",
        ),
    ] = "origin/main",
    allow_in_tree_tools: Annotated[
        bool,
        typer.Option(
            "--allow-in-tree-tools",
            help="Let ASH start scanners and other tools found inside the scanned directory, such as an activated in-repo .venv/bin or node_modules/.bin. Off by default: a tool inside the scanned directory is treated as missing. Only this flag (also the allow_in_tree_tools key of --cli-json-input) and the ASH_ALLOW_IN_TREE_TOOLS environment variable (1, true, yes or on) turn it on, never a config file, and `ash mcp` never does.",
        ),
    ] = False,
    shard_index: Annotated[
        Optional[int],
        typer.Option(
            "--shard-index",
            help="Zero-based index of this shard when one scan is split across several executors. Requires --shard-count. A 3-way split uses indices 0, 1 and 2. Each shard runs a disjoint subset of the scanners and records which ones in its results; recombine them with 'ash merge'.",
            envvar="ASH_SHARD_INDEX",
        ),
    ] = None,
    shard_count: Annotated[
        Optional[int],
        typer.Option(
            "--shard-count",
            help="Total number of shards this scan is split across. Requires --shard-index. Balance is by scanner count rather than scanner cost, so counts above about four buy little: wall clock is bounded by the slowest single scanner.",
            envvar="ASH_SHARD_COUNT",
        ),
    ] = None,
    config_from_scanned_repository: Annotated[
        bool,
        typer.Option(
            "--config-from-scanned-repository",
            hidden=True,
            help="Apply the limits ASH puts on a repository-written config file to the --config file and every file it extends, wherever they are. Container mode passes this to the scan inside the container when the config is inside a git checkout (the scanned one or another) but outside --source-dir, where that scan cannot see it. In a workspace scan it marks the --config file that is layered over every project's own config and used alone by a project without one, from planning on.",
        ),
    ] = False,
    config_files_from_scanned_repository: Annotated[
        Optional[List[str]],
        typer.Option(
            "--config-file-from-scanned-repository",
            hidden=True,
            help="Apply the limits ASH puts on a repository-written config file to this one file of the extends chain of the --config file or of the file ASH_CONFIG names. Container mode passes it, once per file, for each file the config extends that is inside a git checkout when the config itself is not, so the config keeps the sandbox settings it writes itself, as on the host, and for each file of ASH_CONFIG's chain that is inside one. Refused for a file that is in neither chain.",
        ),
    ] = None,
    ash_config_from_host: Annotated[
        Optional[str],
        typer.Option(
            "--ash-config-from-host",
            hidden=True,
            help="Read this file as the file ASH_CONFIG names, for the whole command. Container mode passes it to the scan inside the container, with the path there of the file the host's ASH_CONFIG names, which a local scan reads as its base whatever names the config. Not --config, whose environment variable ASH_CONFIG is.",
        ),
    ] = None,
    ### WORKSPACE-RELATED OPTIONS
    workspace: Annotated[
        str | None,
        typer.Option(
            "--workspace",
            help="Path to a '.code-workspace' file whose folders are scanned as separate, independently-scoped projects. Pass 'auto' to use the single '*.code-workspace' file in the current directory. Mutually exclusive with --source-dir.",
            envvar="ASH_WORKSPACE",
        ),
    ] = None,
    workspace_config: Annotated[
        str | None,
        typer.Option(
            "--workspace-config",
            help="Path to the workspace policy file (severity ceiling, workspace-wide suppressions and ignore paths, additional scanners). Without this, ASH looks for 'ash-workspace.{yaml,yml,json}' in the workspace root or its '.ash' directory; finding none is not an error. Must not be any project's own ASH config: workspace policy governs every project, so reading one project's config as policy would apply its settings to its siblings.",
            envvar="ASH_WORKSPACE_CONFIG",
        ),
    ] = None,
    allow_missing_projects: Annotated[
        bool,
        typer.Option(
            "--allow-missing-projects",
            help="In workspace mode, skip project folders that are absent or unreadable instead of failing. Skipped projects are recorded in the plan. Without this, a missing project fails the whole workspace, so a typo or an un-cloned repository cannot pass as a clean scan.",
        ),
    ] = False,
    dry_run: Annotated[
        bool,
        typer.Option(
            "--dry-run",
            help="In workspace mode, print the resolved execution plan and exit without scanning anything.",
        ),
    ] = False,
    ### CONTAINER-RELATED OPTIONS
    build: Annotated[
        bool,
        typer.Option(
            "--build/--no-build",
            "-b/-B",
            help="Whether to build the ASH container image",
        ),
    ] = True,
    run: Annotated[
        bool,
        typer.Option(
            "--run/--no-run",
            "-r/-R",
            help="Whether to run the ASH container image",
        ),
    ] = True,
    force: Annotated[
        bool,
        typer.Option(
            "--force",
            help="Force rebuild of the ASH container image",
        ),
    ] = False,
    oci_runner: Annotated[
        Optional[str],
        typer.Option(
            "--oci-runner",
            "--oci",
            "--runner",
            "-o",
            help="Use the specified OCI runner instead of docker to run the containerized tools",
            envvar="OCI_RUNNER",
        ),
    ] = None,
    build_target: Annotated[
        BuildTarget | None,
        typer.Option(
            "--build-target",
            help="The ASH image stage to build and run: 'non-root' (an unprivileged user, the default) or 'ci' (root, the default on Windows). CI environment variables do not change it; --custom-containerfile builds on 'ci'.",
            case_sensitive=False,
        ),
    ] = None,
    container_uid: Annotated[
        Optional[str],
        typer.Option(
            "--container-uid",
            "-u",
            help="UID to use for the container user",
        ),
    ] = None,
    container_gid: Annotated[
        Optional[str],
        typer.Option(
            "--container-gid",
            "-g",
            help="GID to use for the container user",
        ),
    ] = None,
    ash_revision_to_install: Annotated[
        str | None,
        typer.Option(
            help="ASH branch or tag to install in the container image for usage during containerized scans",
        ),
    ] = None,
    custom_containerfile: Annotated[
        str | None,
        typer.Option(
            help="Path to a custom container definition (e.g. Dockerfile) that you would like to build *after* the ASH container image builds. This is typically used when building a custom container image for ASH and including custom tooling that ASH does not come with by default. The fully qualified image name for the ASH image is passed in as the `ASH_BASE_IMAGE` build-arg so you can use it as a base. IMPORTANT: When a custom_containerfile path is provided, the build-target is set to `ci` so the container run-as configuration is not shifted to the non-root user. If you are using this parameter, you are responsible for securing your final container as appropriate.",
        ),
    ] = None,
    custom_build_arg: Annotated[
        Optional[List[str]],
        typer.Option(
            help="Custom build arguments to pass to the container build",
        ),
    ] = None,
):
    """Runs an ASH scan against the source-dir, outputting results to the output-dir. This is the default command used when there is no explicit. subcommand specified."""
    # Skip if this is tab completion or if a subcommand was invoked
    # When invoked_subcommand is not None, it means we're in the callback and a subcommand
    # (like 'scan') will handle the actual execution with the correct arguments
    if ctx.resilient_parsing or ctx.invoked_subcommand is not None:
        return

    if version:
        typer.echo(f"awslabs/automated-security-helper v{get_ash_version()}")
        raise typer.Exit

    # envvar= above documents ASH_VERBOSE/ASH_DEBUG in --help, but click would
    # also let the variable set the flag outright, so ASH_DEBUG=true would beat
    # an explicit --quiet or --log-level. A value that came from the environment
    # is dropped here and run_ash_scan reads the variable itself, below every
    # CLI flag -- one precedence rule for the CLI, MCP and library callers alike.
    #
    # Compared by name: typer vendors its own click, so click.core.ParameterSource
    # is a different enum from the one this context returns.
    if _from_environment(ctx, "verbose"):
        verbose = False
    if _from_environment(ctx, "debug"):
        debug = False

    _validate_shard_options(shard_index, shard_count, workspace)

    # Through the environment rather than a parameter, so that every lookup in this
    # process and in the processes it starts (the cdk-nag worker, a container, a
    # nix shell) sees the same answer; see utils/subprocess_utils.in_tree_tools_allowed.
    if allow_in_tree_tools:
        from automated_security_helper.utils.process_env import (
            apply_environ_overrides,
        )
        from automated_security_helper.utils.subprocess_utils import (
            ALLOW_IN_TREE_TOOLS_ENV,
        )

        apply_environ_overrides({ALLOW_IN_TREE_TOOLS_ENV: "1"})

    # With --changed-files-only the base ref goes to `git diff`, so it is refused
    # here, before any git process starts, when git could read it as anything but
    # a revision. Without the flag no diff runs and the value is not used.
    if changed_files_only:
        try:
            validate_base_ref(base_ref)
        except InvalidBaseRefError as exc:
            _fail_usage(f"{exc} The value comes from --base-ref or ASH_BASE_REF.")

    # Workspace mode is handled before any cwd-based default is applied, because
    # --workspace and --source-dir are mutually exclusive and defaulting
    # source_dir first would make every invocation look like it had both.
    if workspace is None and (
        dry_run or allow_missing_projects or workspace_config is not None
    ):
        # None of these flags mean anything outside workspace mode. Silently
        # ignoring --dry-run would run a full scan for someone who asked for
        # none; silently ignoring --workspace-config would scan with no policy
        # for someone who believes a severity ceiling is in force.
        offending = [
            flag
            for flag, given in (
                ("--dry-run", dry_run),
                ("--allow-missing-projects", allow_missing_projects),
                ("--workspace-config", workspace_config is not None),
            )
            if given
        ]
        _fail_workspace(
            f"{' and '.join(offending)} only applies in workspace mode; pass "
            f"'--workspace <file>' or '--workspace auto' as well."
        )

    # Built HERE, above the workspace block, rather than with the other
    # None-to-empty normalisations below. Workspace resolution needs the COMPLETE
    # override list, because a threshold override changes what each project
    # declares and therefore what --dry-run must print. Normalising afterwards
    # would hand resolution an empty list and the plan would report a threshold
    # the scan does not enforce.
    #
    # --compact-report is why this is not just a None check: it synthesises an
    # override, so config_overrides is non-empty for an operator who never passed
    # --config-overrides. Leaving that below the workspace block would omit it
    # from the plan while the scan applied it.
    if config_overrides is None:
        config_overrides = []
    if compact_report:
        config_overrides.append("reporters.markdown.options.compact=true")
    # The same route as --compact-report, for the same reason and one more: as a config
    # override it reaches every mode unchanged -- local, nix, workspace, and the container,
    # which is handed config_overrides verbatim -- and overrides are applied after the
    # config file, which is what makes the flag win over `content_db_staleness` there.
    if allow_stale_content_db is not None:
        config_overrides.extend(
            content_db_staleness_flag_overrides(allow_stale=allow_stale_content_db)
        )

    # A config override for the same reasons as the two above: it reaches local, nix
    # and workspace runs unchanged and wins over the config file's sandbox.mode.
    if sandbox is not None:
        config_overrides.append(f"sandbox.mode={SandboxMode(sandbox).value}")

    # The same route again. As an override it is operator input, which a config
    # file inside the scanned tree cannot outvote (resolve_config's
    # confine_honor_ignore_files), and the container runs it unchanged.
    if honor_ignore_files is not None:
        config_overrides.append(
            f"honor_ignore_files={'true' if honor_ignore_files else 'false'}"
        )

    # Container mode's marks for the scan inside, which cannot see where the host
    # found the --config it mounted at /ash-config: --config-from-scanned-repository
    # for a --config in a git checkout or the scanned directory, with every file it
    # extends, and --config-file-from-scanned-repository for each file the config
    # extends that is in one when the config itself is not. Every scan holds them,
    # one-directory and workspace alike, for the whole command, from planning on
    # (sandbox_grants.marked_repository_written, marked_files_repository_written).
    # Neither is resolve_config's untrusted_config, which is for a file an MCP
    # client delivered and holds it to the client's rules. The scan inside runs in
    # local mode with a --config; any other scan cannot apply them, so they are a
    # usage error with exit 3 rather than run_ash_scan's ValueError.
    #
    # --ash-config-from-host is the file the host's ASH_CONFIG names, mounted at
    # /ash-env-config: set as ASH_CONFIG here, after click has read --config, so
    # it is the base the scan reads (default_config.get_default_config), as on the
    # host, and not the --config it would be as the option's environment variable.
    # A file of its chain the host counts as repository-written comes marked with
    # --config-file-from-scanned-repository.
    marked_files = list(config_files_from_scanned_repository or [])
    if config_from_scanned_repository or marked_files or ash_config_from_host:
        if (mode or RunMode.local) != RunMode.local:
            _fail_config_mark(
                "--config-from-scanned-repository, "
                "--config-file-from-scanned-repository and --ash-config-from-host "
                "are passed by container mode to the scan inside the container and "
                "apply only to a scan in local mode. Leave them out: container mode "
                "decides them on the host."
            )
        from automated_security_helper.config.sandbox_grants import (
            marked_files_repository_written,
            marked_repository_written,
        )
        from automated_security_helper.utils.process_env import environ_overrides

        marks = contextlib.ExitStack()
        ctx.call_on_close(marks.close)
        if ash_config_from_host is not None:
            marks.enter_context(environ_overrides({"ASH_CONFIG": ash_config_from_host}))
        chains = [Path(path) for path in (config, ash_config_from_host) if path]
        if (config_from_scanned_repository or marked_files) and not chains:
            _fail_config_mark(
                "--config-from-scanned-repository and "
                "--config-file-from-scanned-repository mark the --config file and the "
                "files it extends, and this scan has none. Leave them out: container "
                "mode decides them on the host."
            )
        if config_from_scanned_repository and config is None:
            _fail_config_mark(
                "--config-from-scanned-repository marks the --config file and every "
                "file it extends, and this scan has none. Leave it out: container "
                "mode decides it on the host."
            )
        outside = _marked_outside_the_chain(chains, marked_files)
        if outside:
            _fail_config_mark(
                f"--config-file-from-scanned-repository names {', '.join(outside)}, "
                "which is not a file of the chain of --config or of the file "
                "ASH_CONFIG names."
            )
        if config_from_scanned_repository and config is not None:
            marks.enter_context(marked_repository_written(Path(config)))
        if marked_files:
            marks.enter_context(
                marked_files_repository_written(Path(path) for path in marked_files)
            )

    workspace_plan: WorkspacePlan | None = None
    if workspace is not None:
        workspace_plan = _handle_workspace_mode(
            workspace=workspace,
            source_dir=source_dir,
            allow_missing_projects=allow_missing_projects,
            dry_run=dry_run,
            workspace_config=workspace_config,
            config_overrides=tuple(config_overrides),
            config=config,
        )
        # The workspace root is the scan root: it is what container mode mounts at
        # /src, and what every workspace-relative finding path is relative to.
        # Individual projects get their own source_dir inside the executor.
        source_dir = workspace_plan.workspace_root

    # Rebind list defaults to fresh empty lists at call time so each CLI
    # invocation gets its own collection (typer will populate them if the
    # user supplies --scanners etc., but we guard against reusing aliases).
    if scanners is None:
        scanners = []
    if exclude_scanners is None:
        exclude_scanners = []
    if ash_plugin_modules is None:
        ash_plugin_modules = []
    # config_overrides is normalised above the workspace block; see the comment
    # there for why it cannot happen here.
    if output_formats is None:
        output_formats = []
    if phases is None:
        phases = [ExecutionPhase.CONVERT, ExecutionPhase.SCAN, ExecutionPhase.REPORT]
    if custom_build_arg is None:
        custom_build_arg = []

    # Resolve cwd-based defaults at call time (not import time).
    if source_dir is None:
        source_dir = Path.cwd().as_posix()
    # Refused before anything else uses it. A missing --source-dir used to run a
    # real scan of nothing -- every scanner finds no files -- and could exit 0,
    # which reads exactly like a clean scan of the directory the operator named.
    if not Path(source_dir).exists():
        _fail_usage(
            f"Source directory does not exist: {source_dir}. "
            "Check --source-dir (or ASH_SOURCE_DIR)."
        )
    if not Path(source_dir).is_dir():
        _fail_usage(
            f"Source directory is not a directory: {source_dir}. "
            "--source-dir must name the directory to scan."
        )
    if output_dir is None:
        # Default output_dir is relative to source_dir, not CWD.
        # This ensures that when --source-dir points to a different project,
        # the output (and config resolution) happens in the correct location.
        output_dir = Path(source_dir).joinpath(".ash", "ash_output").as_posix()

    if Path(source_dir).absolute().as_posix() == Path(output_dir).absolute().as_posix():
        output_dir = Path(output_dir).joinpath(".ash", "ash_output")
        print(
            f"[bold yellow]output-dir has been adjusted to the following to avoid collisions and potential impact to source code: {Path(output_dir).as_posix()}[/bold yellow]"
        )

    # Apply mode presets if specified
    precommit_mode = mode == RunMode.precommit or str(mode).lower() == "precommit"
    if precommit_mode:
        print(
            "[green]-------------- Running ASH in pre-commit mode with minimal output --------------[/green]"
        )

    existing_results = None
    if use_existing:
        poss_existing_results = Path(output_dir).joinpath("ash_aggregated_results.json")
        if poss_existing_results.exists():
            existing_results = poss_existing_results.as_posix()
        else:
            # A clean refusal, not the uncaught ValueError traceback this was.
            _fail_usage(
                f"--use-existing was given, but there are no existing results to "
                f"use: {poss_existing_results.as_posix()} does not exist. Run a "
                "scan first, or point --output-dir at the output of a previous one."
            )

    cli_final_show_progress = (
        progress
        and not verbose
        and not precommit_mode
        and os.environ.get("CI", None) is None
        and os.environ.get("ASH_IN_CONTAINER", "NO").upper()
        not in [
            "YES",
            "1",
            "TRUE",
        ]
    )

    # --compact-report is translated into its config override above the workspace
    # block, so that workspace resolution sees it. Appending here as well would
    # apply it twice.

    # Parse comma-separated output formats
    parsed_output_formats = []
    for item in output_formats:
        for fmt in item.split(","):
            fmt = fmt.strip()
            if fmt:
                try:
                    parsed_output_formats.append(ExportFormat(fmt))
                except ValueError:
                    valid_formats = [f.value for f in ExportFormat]
                    raise typer.BadParameter(
                        f"'{fmt}' is not a valid format. Valid formats are: {', '.join(valid_formats)}"
                    )

    # Call run_ash_scan with all parameters
    run_ash_scan(
        source_dir=source_dir,
        output_dir=output_dir,
        config=config,
        config_overrides=config_overrides,
        offline=offline,
        strategy=strategy,
        scanners=scanners,
        exclude_scanners=exclude_scanners,
        progress=cli_final_show_progress,
        output_formats=parsed_output_formats,
        cleanup=cleanup,
        phases=phases,
        inspect=inspect,
        existing_results=existing_results,
        python_based_plugins_only=python_based_plugins_only,
        log_level=log_level,
        quiet=quiet,
        verbose=verbose,
        debug=debug,
        color=color,
        fail_on_findings=fail_on_findings,
        fail_on_incomplete_scanners=fail_on_incomplete_scanners,
        ignore_suppressions=ignore_suppressions,
        min_severity=min_severity,
        changed_files_only=changed_files_only,
        base_ref=base_ref,
        shard_index=shard_index,
        shard_count=shard_count,
        mode=mode or RunMode.local,
        show_summary=show_summary,
        simple=simple
        or precommit_mode
        or log_level == AshLogLevel.SIMPLE
        or str(log_level).lower() == "simple",
        # Pass the ash_plugin_modules parameter
        ash_plugin_modules=ash_plugin_modules,
        # Container-specific params
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
        workspace_plan=workspace_plan,
        allow_missing_projects=allow_missing_projects,
        workspace_config_as_named=workspace_config,
    )
