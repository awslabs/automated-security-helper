# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from typing import Annotated, Optional, List
import typer

# Import subprocess utilities
from automated_security_helper.core.constants import ASH_CONFIG_FILE_NAMES
from automated_security_helper.core.enums import AshLogLevel, BuildTarget, RunMode
from automated_security_helper.interactions.run_ash_scan import run_ash_scan


def build_ash_image_cli_command(
    ctx: typer.Context,
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
    ] = False,
    force: Annotated[
        bool,
        typer.Option(
            "--force",
            "-f",
            help="Force rebuild of the ASH container image",
        ),
    ] = False,
    oci_runner: Annotated[
        Optional[str],
        typer.Option(
            "--oci-runner",
            "--oci",
            "--runner",
            "-r",
            help="Use the specified OCI runner instead of docker to run the containerized tools",
            envvar="OCI_RUNNER",
        ),
    ] = None,
    # preserve_report: Annotated[
    #     bool,
    #     typer.Option(
    #         "--preserve-report",
    #         "-p",
    #         help="Add timestamp to the final report file to avoid overwriting it after multiple executions",
    #     ),
    # ] = False,
    # extension: Annotated[
    #     Optional[str],
    #     typer.Option(
    #         "--ext",
    #         "--extension",
    #         "-e",
    #         help="Force a file extension to scan. Defaults to identify files automatically",
    #     ),
    # ] = None,
    build_target: Annotated[
        BuildTarget,
        typer.Option(
            "--build-target",
            help="Specify the target stage of the ASH image to build",
            case_sensitive=False,
        ),
    ] = BuildTarget.NON_ROOT,
    offline_semgrep_rulesets: Annotated[
        str,
        typer.Option(
            "--offline-semgrep-rulesets",
            help="Specify Semgrep rulesets for use in ASH offline mode",
        ),
    ] = "p/ci",
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
        List[str],
        typer.Option(
            help="Custom build arguments to pass to the container build",
        ),
    ] = [],
    # General Options
    config: Annotated[
        str,
        typer.Option(
            help=f"The path to the configuration file. By default, ASH looks for the following config file names in the source directory of a scan: {ASH_CONFIG_FILE_NAMES}. Alternatively, the full path to a config file can be provided by setting the ASH_CONFIG environment variable before running ASH.",
            envvar="ASH_CONFIG",
        ),
    ] = None,
    offline: Annotated[
        bool,
        typer.Option(
            help="Run scan in offline/airgapped mode (skips NPM/PNPM/Yarn Audit checks). IMPORTANT: Online access is needed when building ASH to prepare it for usage during a scan! If selecting Offline while performing a build, the ASH container image will be built in offline mode and any typically online-only dependencies like downloadable tool vulnerability databases will be cached in the image itself before publishing for scan usage."
        ),
    ] = False,
    quiet: Annotated[bool, typer.Option(help="Hide all log output")] = False,
    log_level: Annotated[
        AshLogLevel,
        typer.Option(
            "--log-level",
            help="Set the log level.",
        ),
    ] = AshLogLevel.INFO,
    verbose: Annotated[bool, typer.Option(help="Enable verbose logging")] = False,
    debug: Annotated[bool, typer.Option(help="Enable debug logging")] = False,
    color: Annotated[bool, typer.Option(help="Enable/disable colorized output")] = True,
):
    if ctx.resilient_parsing or ctx.invoked_subcommand not in [None, "image"]:
        return

    # Call run_ash_scan with all parameters
    run_ash_scan(
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
        # General params
        show_summary=run,
        config=config,
        offline=offline,
        progress=False,
        log_level=log_level,
        quiet=quiet,
        verbose=verbose,
        debug=debug,
        color=color,
        mode=RunMode.container,
    )
