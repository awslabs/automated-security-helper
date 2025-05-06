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


# #########
#     source_dir: Annotated[
#         Optional[str],
#         typer.Option(
#             "--source-dir",
#             "-s",
#             help="Path to the directory containing the code/files you wish to scan",
#         ),
#     ] = None,
#     output_dir: Annotated[
#         Optional[str],
#         typer.Option(
#             "--output-dir",
#             "-o",
#             help="Path to the directory that will contain the report of the scans",
#         ),
#     ] = None,
#     build: Annotated[
#         bool,
#         typer.Option(
#             "--build/--no-build",
#             "-b/-B",
#             help="Whether to build the ASH container image",
#         ),
#     ] = True,
#     run: Annotated[
#         bool,
#         typer.Option(
#             "--run/--no-run",
#             "-r/-R",
#             help="Whether to run the ASH container image",
#         ),
#     ] = True,
#     force: Annotated[
#         bool,
#         typer.Option(
#             "--force",
#             "-f",
#             help="Force rebuild of the ASH container image",
#         ),
#     ] = False,
#     quiet: Annotated[
#         bool,
#         typer.Option(
#             "--quiet",
#             "-q",
#             help="Don't print verbose text about the build process",
#         ),
#     ] = False,
#     oci_runner: Annotated[
#         Optional[str],
#         typer.Option(
#             "--oci-runner",
#             "--oci",
#             "--runner",
#             "-r",
#             help="Use the specified OCI runner instead of docker to run the containerized tools",
#             envvar="OCI_RUNNER",
#         ),
#     ] = None,
#     # preserve_report: Annotated[
#     #     bool,
#     #     typer.Option(
#     #         "--preserve-report",
#     #         "-p",
#     #         help="Add timestamp to the final report file to avoid overwriting it after multiple executions",
#     #     ),
#     # ] = False,
#     # extension: Annotated[
#     #     Optional[str],
#     #     typer.Option(
#     #         "--ext",
#     #         "--extension",
#     #         "-e",
#     #         help="Force a file extension to scan. Defaults to identify files automatically",
#     #     ),
#     # ] = None,
#     build_target: Annotated[
#         BuildTarget,
#         typer.Option(
#             "--build-target",
#             help="Specify the target stage of the ASH image to build",
#             case_sensitive=False,
#         ),
#     ] = BuildTarget.NON_ROOT,
#     offline: Annotated[
#         bool,
#         typer.Option(
#             "--offline",
#             help="Build ASH for offline execution",
#         ),
#     ] = False,
#     offline_semgrep_rulesets: Annotated[
#         str,
#         typer.Option(
#             "--offline-semgrep-rulesets",
#             help="Specify Semgrep rulesets for use in ASH offline mode",
#         ),
#     ] = "p/ci",
#     container_uid: Annotated[
#         Optional[str],
#         typer.Option(
#             "--container-uid",
#             "-u",
#             help="UID to use for the container user",
#         ),
#     ] = None,
#     container_gid: Annotated[
#         Optional[str],
#         typer.Option(
#             "--container-gid",
#             "-g",
#             help="GID to use for the container user",
#         ),
#     ] = None,
#     verbose: Annotated[bool, typer.Option(help="Enable verbose logging")] = False,
#     debug: Annotated[bool, typer.Option(help="Enable debug logging")] = False,
#     color: Annotated[bool, typer.Option(help="Enable/disable colorized output")] = True,
# ):
#     """
#     Build and run the ASH container image.
#     """
#     # Configure logging
#     logging.basicConfig(
#         level=logging.DEBUG if debug else logging.INFO,
#         format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
#     )
#     logger = get_logger(level=logging.DEBUG if debug else logging.INFO)

#     # Create console
#     console = Console(color_system="auto" if color else None)

#     # Create command output streamer
#     cmd_streamer = CommandOutputStreamer(
#         console=console,
#         output_title="ASH Build Output",
#         debug=debug,
#     )

#     # Validate source directory
#     if source_dir:
#         try:
#             source_dir = validate_path(source_dir)
#         except ValueError as e:
#             typer.secho(str(e), fg=typer.colors.RED)
#             raise typer.Exit(1)

#     # Set default source directory if not provided
#     if not source_dir:
#         source_dir = Path.cwd()
#         logger.info(f"Using current directory as source: {source_dir}")

#     # Validate output directory
#     if output_dir:
#         try:
#             # Create output directory if it doesn't exist
#             output_dir = Path(output_dir)
#             output_dir.mkdir(parents=True, exist_ok=True)
#             output_dir = output_dir.resolve()
#         except Exception as e:
#             typer.secho(f"Error creating output directory: {e}", fg=typer.colors.RED)
#             raise typer.Exit(1)
#     else:
#         # Default to ash_output in the source directory
#         output_dir = Path(source_dir).joinpath("ash_output")
#         output_dir.mkdir(parents=True, exist_ok=True)
#         logger.info(f"Using default output directory: {output_dir}")

#     # Get host UID and GID using safe subprocess calls
#     try:
#         host_uid = get_host_uid()
#         host_gid = get_host_gid()
#     except Exception as e:
#         typer.secho(f"Error getting user ID information: {e}", fg=typer.colors.RED)
#         raise typer.Exit(1)

#     # Validate container UID and GID if specified
#     if container_uid is not None:
#         if not container_uid.isdigit():
#             typer.secho("Container UID must be a numeric value", fg=typer.colors.RED)
#             raise typer.Exit(1)
#     else:
#         container_uid = host_uid

#     if container_gid is not None:
#         if not container_gid.isdigit():
#             typer.secho("Container GID must be a numeric value", fg=typer.colors.RED)
#             raise typer.Exit(1)
#     else:
#         container_gid = host_gid

#     # Resolve OCI runner
#     resolved_oci_runner = None
#     runners = [oci_runner] if oci_runner else ["docker", "finch", "nerdctl", "podman"]

#     for runner in runners:
#         try:
#             exists = find_executable(runner)
#             if not exists:
#                 continue
#             resolved_oci_runner = exists
#             break
#         except Exception:
#             logger.verbose(f"Unable to find {runner} -- continuing")
#             continue

#     if not resolved_oci_runner:
#         typer.secho("Unable to resolve an OCI runner -- exiting", fg=typer.colors.RED)
#         raise typer.Exit(1)

#     logger.info(f"Resolved OCI_RUNNER to: {resolved_oci_runner}")

#     # Get ASH root directory
#     ash_root_dir = Path(__file__).parent.parent.parent.resolve()
#     dockerfile_path = ash_root_dir.joinpath("Dockerfile")

#     if not dockerfile_path.exists():
#         typer.secho(f"Dockerfile not found at {dockerfile_path}", fg=typer.colors.RED)
#         raise typer.Exit(1)

#     # Set image name from environment or use default
#     ash_image_name = os.environ.get(
#         "ASH_IMAGE_NAME", f"automated-security-helper:{build_target.value}"
#     )

#     # Build the image if the --build flag is set
#     if build:
#         typer.echo(
#             f"Building image {ash_image_name} -- this may take a few minutes during the first build..."
#         )

#         # Prepare build command
#         build_cmd = [
#             resolved_oci_runner,
#             "build",
#         ]

#         # Add UID/GID build args
#         build_cmd.extend(["--build-arg", f"UID={container_uid}"])
#         build_cmd.extend(["--build-arg", f"GID={container_gid}"])

#         # Add other build args
#         build_cmd.extend(
#             [
#                 "--tag",
#                 ash_image_name,
#                 "--target",
#                 build_target.value,
#                 "--file",
#                 dockerfile_path.as_posix(),
#                 "--build-arg",
#                 f"OFFLINE={'YES' if offline else 'NO'}",
#                 "--build-arg",
#                 f"OFFLINE_SEMGREP_RULESETS={offline_semgrep_rulesets}",
#                 "--build-arg",
#                 f"BUILD_DATE={int(datetime.now().timestamp())}",
#             ]
#         )

#         # Add extra build args
#         docker_extra_args = []
#         if force:
#             docker_extra_args.append("--no-cache")
#         if quiet:
#             docker_extra_args.append("-q")

#         # Add any extra args
#         build_cmd.extend(docker_extra_args)

#         # Add the build context
#         build_cmd.append(ash_root_dir.as_posix())

#         try:
#             build_result = cmd_streamer.run_cmd(build_cmd)
#             if debug:
#                 logger.debug(f"Build stdout: {build_result.stdout}")
#                 logger.debug(f"Build stderr: {build_result.stderr}")
#         except Exception as e:
#             typer.secho(f"Error building ASH image: {e}", fg=typer.colors.RED)
#             if debug:
#                 if hasattr(e, "stdout"):
#                     logger.debug(f"Build stdout: {e.stdout}")
#                 if hasattr(e, "stderr"):
#                     logger.debug(f"Build stderr: {e.stderr}")
#             raise typer.Exit(1)

#     # Run the image if the --run flag is set
#     if run:
#         run_cmd = [
#             resolved_oci_runner,
#             "run",
#             "--rm",
#         ]

#         # Add environment variables
#         run_cmd.extend(
#             [
#                 "-e",
#                 f"ASH_ACTUAL_SOURCE_DIR={source_dir}",
#                 "-e",
#                 f"ASH_ACTUAL_OUTPUT_DIR={output_dir}",
#                 "-e",
#                 f"ASH_DEBUG={'YES' if debug else 'NO'}",
#             ]
#         )

#         # Add mount for source directory
#         mount_source_dir = f"type=bind,source={source_dir},destination=/src"

#         # Only make source dir readonly if output dir is not a subdirectory
#         if output_dir and not str(output_dir).startswith(str(source_dir)):
#             mount_source_dir += ",readonly"

#         run_cmd.extend(["--mount", mount_source_dir])

#         # Add mount for output directory
#         run_cmd.extend(["--mount", f"type=bind,source={output_dir},destination=/out"])

#         # Add offline mode flag
#         if offline:
#             run_cmd.append("--network=none")

#         # Add terminal size environment variables
#         try:
#             import shutil

#             columns, lines = shutil.get_terminal_size()
#             run_cmd.extend(["-e", f"COLUMNS={columns}", "-e", f"LINES={lines}"])
#         except Exception as e:
#             logger.trace(f"Unable to determine terminal size via shutil: {e}")

#         # Add color support
#         if color:
#             run_cmd.append("-t")

#         # Add image name
#         run_cmd.append(ash_image_name)

#         # Add ASH command
#         run_cmd.append("ashv3")

#         # Add ASH arguments
#         run_cmd.extend(["--source-dir", "/src", "--output-dir", "/out"])

#         # Add additional ASH arguments, starting with ctx.args in case any extra args
#         # were passed in at CLI runtime
#         ash_args = ctx.args or []
#         if quiet:
#             ash_args.append("--quiet")
#         if not color:
#             ash_args.append("--no-color")
#         if debug:
#             ash_args.append("--debug")
#         if verbose:
#             ash_args.append("--verbose")

#         # Add any additional ASH arguments
#         run_cmd.extend(ash_args)

#         typer.echo("Running ASH scan using built image...")
#         try:
#             run_result = cmd_streamer.run_cmd(run_cmd)
#             # Return the exit code from the run command
#             if run_result.returncode != 0:
#                 raise sys.exit(run_result.returncode) from None
#             return sys.exit(run_result.returncode)
#         except CalledProcessError as e:
#             raise sys.exit(e.returncode) from None

#     return sys.exit(0)
