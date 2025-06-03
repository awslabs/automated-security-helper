# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import json
import os
import shlex
from subprocess import (
    CalledProcessError,
)  # nosec B404 - Using the exception class to evaluate subprocess invocations
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import List
import typer
import threading
import io
from importlib.metadata import import_module

# Import subprocess utilities
from automated_security_helper.core.constants import (
    ASH_ASSETS_DIR,
    ASH_REPO_LATEST_REVISION,
)
from automated_security_helper.core.enums import (
    AshLogLevel,
    BuildTarget,
    ExportFormat,
    Phases,
    Strategy,
)
from automated_security_helper.utils.subprocess_utils import (
    create_process_with_pipes,
    create_completed_process,
    raise_called_process_error,
    get_host_uid,
    get_host_gid,
    find_executable,
)
from automated_security_helper.utils.log import ASH_LOGGER


def get_ash_revision() -> str | None:
    """
    Get the revision of the Automated Security Helper repo to install based on how the
    current version of the package was installed.

    - If ASH is installed in editable mode or is within a full clone of the
    repository, return 'LOCAL'
    - If ASH was installed via `pip install` where only the package info and some of
    the source is available, then attempt to resolve the installed source and provide the
    target Git revision to install ASH within the container image.

    Returns:
        str: The revision of the Automated Security Helper container
    """
    return_val = None
    ash_repo_root = Path(__file__).parent.parent.parent
    if all(
        [
            ash_repo_root.joinpath(".github").exists(),
            ash_repo_root.joinpath(".gitignore").exists(),
            ash_repo_root.joinpath(".dockerignore").exists(),
            ash_repo_root.joinpath("Dockerfile").exists(),
            ash_repo_root.joinpath("pyproject.toml").exists(),
            ash_repo_root.joinpath("NOTICE").exists(),
            ash_repo_root.joinpath("docs").exists(),
            ash_repo_root.joinpath("tests").exists(),
        ]
    ):
        ASH_LOGGER.info(
            "ASH installation appears to be alongide the repository contents, building with LOCAL source"
        )
        return "LOCAL"

    mod = import_module("automated_security_helper")
    direct_url_json_path = Path(
        mod.__path__[0] + "-" + mod.__version__ + ".dist-info"
    ).joinpath("direct_url.json")
    if direct_url_json_path.exists():
        print(
            f"Found direct_url.json file for module @ {direct_url_json_path.as_posix()}"
        )
        direct_url_json = json.loads(direct_url_json_path.read_text())
        if isinstance(direct_url_json, dict) and "url" in direct_url_json:
            if "vcs_info" in direct_url_json:
                revision = (
                    direct_url_json["vcs_info"]["requested_revision"]
                    or ASH_REPO_LATEST_REVISION
                )
                return_val = revision
                ASH_LOGGER.info(
                    f"Resolved source revision for ASH to use during container image build: {return_val}"
                )
    else:
        return_val = ASH_REPO_LATEST_REVISION

    return return_val


def validate_path(path: str) -> Path:
    """
    Validate that a path is safe and convert it to a Path object.

    Args:
        path: The path string to validate

    Returns:
        Path: The validated Path object

    Raises:
        ValueError: If the path is not safe
    """
    # Convert to absolute path
    abs_path = Path(path).resolve()

    # Check if the path exists
    if not abs_path.exists():
        raise ValueError(f"Path does not exist: {abs_path}")

    return abs_path


def run_cmd_direct(cmd_list, check=True, debug=False, shell=False):
    """
    Run a command and stream output directly to console without Rich panels.

    Args:
        cmd_list: List of command arguments
        check: Whether to check the return code
        debug: Whether to print debug information

    Returns:
        subprocess.CompletedProcess: The result of the command
    """
    # Filter out empty or None values
    cmd_list = [str(item) for item in cmd_list if item is not None]

    # Log the command for debugging
    if debug:
        print(f"Running command: {' '.join(shlex.quote(arg) for arg in cmd_list)}")

    # Create process using subprocess_utils
    process = create_process_with_pipes(  # nosec B604 - Args for this command are evaluated for security prior to this internal method being invoked
        args=cmd_list,
        text=True,
        shell=shell,
    )

    # Create buffers for stdout and stderr
    stdout_buffer = io.StringIO()
    stderr_buffer = io.StringIO()

    # Function to read from a pipe and stream output
    def read_pipe(pipe, is_stderr=False):
        buffer = stderr_buffer if is_stderr else stdout_buffer
        try:
            for line in iter(pipe.readline, ""):
                buffer.write(line)
                # Print directly to console
                print(line, end="", file=sys.stderr if is_stderr else sys.stdout)
        except Exception as e:
            error_msg = f"Error reading {'stderr' if is_stderr else 'stdout'}: {str(e)}"
            print(error_msg, file=sys.stderr)

    # Create threads to read stdout and stderr
    stdout_thread = threading.Thread(target=read_pipe, args=(process.stdout, False))
    stderr_thread = threading.Thread(target=read_pipe, args=(process.stderr, True))

    # Mark as daemon threads so they don't block program exit
    stdout_thread.daemon = True
    stderr_thread.daemon = True

    # Start threads
    stdout_thread.start()
    stderr_thread.start()

    # Wait for process to complete
    try:
        while process.poll() is None:
            time.sleep(0.1)
    except KeyboardInterrupt:
        # Handle Ctrl+C gracefully
        process.terminate()
        print("Command interrupted by user", file=sys.stderr)

    # Wait for threads to complete with timeout
    stdout_thread.join(timeout=2.0)
    stderr_thread.join(timeout=2.0)

    # Get the captured output
    stdout = stdout_buffer.getvalue()
    stderr = stderr_buffer.getvalue()

    # Create a CompletedProcess object
    result = create_completed_process(
        args=cmd_list,
        returncode=process.returncode if process.returncode is not None else -1,
        stdout=stdout,
        stderr=stderr,
    )

    # Check return code if requested
    if check and result.returncode != 0:
        raise_called_process_error(
            returncode=result.returncode,
            cmd=cmd_list,
            output=stdout,
            stderr=stderr,
        )

    return result


def run_ash_container(
    ctx=None,
    source_dir: str = Path.cwd().as_posix(),
    output_dir: str = Path.cwd().joinpath(".ash", "ash_output").as_posix(),
    log_level: AshLogLevel = AshLogLevel.INFO,
    config: str = None,
    config_overrides: List[str] = None,
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
    # Container-specific args
    build: bool = True,
    run: bool = True,
    force: bool = False,
    oci_runner: str = None,
    build_target: BuildTarget | None = None,
    offline_semgrep_rulesets: str = "p/ci",
    container_uid: str | None = None,
    container_gid: str | None = None,
    ash_revision_to_install: str | None = None,
    custom_containerfile: str | None = None,
    custom_build_arg: List[str] = [],
    ash_plugin_modules: List[str] = [],
):
    """Build and run the ASH container image.

    Args:
        ctx: Typer context object
        source_dir: Path to the directory containing the code/files you wish to scan
        output_dir: Path to the directory that will contain the report of the scans
        build: Whether to build the ASH container image
        run: Whether to run the ASH container image
        force: Force rebuild of the ASH container image
        quiet: Don't print verbose text about the build process
        oci_runner: Use the specified OCI runner instead of docker to run the containerized tools
        build_target: Specify the target stage of the ASH image to build
        offline: Build ASH for offline execution
        offline_semgrep_rulesets: Specify Semgrep rulesets for use in ASH offline mode
        container_uid: UID to use for the container user
        container_gid: GID to use for the container user
        verbose: Enable verbose logging
        debug: Enable debug logging
        color: Enable/disable colorized output

    Returns:
        CompletedProcess: The result of the container execution
    """
    # Get host UID and GID using safe subprocess calls
    try:
        host_uid = get_host_uid()
        host_gid = get_host_gid()
    except Exception as e:
        typer.secho(f"Error getting user ID information: {e}", fg=typer.colors.RED)
        return create_completed_process(args=[], returncode=1, stdout="", stderr=str(e))

    # Validate container UID and GID if specified
    if container_uid is not None:
        if not container_uid.isdigit():
            typer.secho("Container UID must be a numeric value", fg=typer.colors.RED)
            return create_completed_process(
                args=[],
                returncode=1,
                stdout="",
                stderr="Container UID must be a numeric value",
            )
    else:
        container_uid = host_uid

    if container_gid is not None:
        if not container_gid.isdigit():
            typer.secho("Container GID must be a numeric value", fg=typer.colors.RED)
            return create_completed_process(
                args=[],
                returncode=1,
                stdout="",
                stderr="Container GID must be a numeric value",
            )
    else:
        container_gid = host_gid

    # Resolve OCI runner
    resolved_oci_runner = None
    runners = [oci_runner] if oci_runner else ["docker", "finch", "nerdctl", "podman"]

    for runner in runners:
        try:
            exists = find_executable(runner)
            if not exists:
                continue
            resolved_oci_runner = exists
            break
        except Exception:
            ASH_LOGGER.debug(f"Unable to find {runner} -- continuing")
            continue

    if not resolved_oci_runner:
        typer.secho("Unable to resolve an OCI runner -- exiting", fg=typer.colors.RED)
        return create_completed_process(
            args=[], returncode=1, stdout="", stderr="Unable to resolve an OCI runner"
        )

    ASH_LOGGER.info(f"Resolved OCI_RUNNER to: {resolved_oci_runner}")

    # Get ASH root directory
    rev = get_ash_revision()
    resolved_revision = (
        ash_revision_to_install if ash_revision_to_install is not None else rev
    )
    dockerfile_path = (
        ASH_ASSETS_DIR.joinpath("Dockerfile")
        if resolved_revision != "LOCAL"
        else Path(__file__).parent.parent.parent.joinpath("Dockerfile")
    )

    if not dockerfile_path.exists():
        typer.secho(f"Dockerfile not found at {dockerfile_path}", fg=typer.colors.RED)
        return create_completed_process(
            args=[],
            returncode=1,
            stdout="",
            stderr=f"Dockerfile not found at {dockerfile_path}",
        )

    # Set image name from environment or use default
    resolved_build_target = (
        "ci"
        # Force CI if a custom containerfile was provided
        if (
            custom_containerfile is not None
            or os.environ.get(
                "CI",
                os.environ.get(
                    "IsCI",
                    os.environ.get("ISCI", os.environ.get("CODEBUILD_BUILD_ID", None)),
                ),
            )
            is not None
        )
        else (
            build_target.value
            if hasattr(build_target, "value") and build_target is not None
            else str(build_target)
            if build_target is not None
            else "non-root"
        )
    )
    ash_base_image_name = os.environ.get(
        "ASH_IMAGE_NAME", f"automated-security-helper:{resolved_build_target}"
    )

    # Build the image if the --build flag is set
    if build:
        typer.echo(
            f"Building image {ash_base_image_name} -- this may take a few minutes during the first build..."
        )

        # Prepare build command
        build_cmd = [
            resolved_oci_runner,
            "build",
        ]

        # Add other build args
        # Add UID/GID build args
        build_cmd.extend(["--build-arg", f"UID={container_uid}"])
        build_cmd.extend(["--build-arg", f"GID={container_gid}"])

        build_cmd.extend(
            [
                "--tag",
                ash_base_image_name,
                "--target",
                resolved_build_target,
                "--file",
                dockerfile_path.as_posix(),
                "--build-arg",
                f"INSTALL_ASH_REVISION={resolved_revision}",
                "--build-arg",
                f"OFFLINE={'YES' if offline else 'NO'}",
                "--build-arg",
                f"OFFLINE_SEMGREP_RULESETS={offline_semgrep_rulesets}",
                "--build-arg",
                f"BUILD_DATE={int(datetime.now().timestamp())}",
            ]
        )

        # Add extra build args
        docker_extra_args = []
        # Set environment variables for color output
        if force:
            docker_extra_args.append("--no-cache")
        if quiet:
            docker_extra_args.append("-q")

        # Add any extra args
        build_cmd.extend(docker_extra_args)

        # Add the build context
        build_cmd.append(dockerfile_path.parent.as_posix())

        try:
            if debug:
                print(
                    f"Building image {ash_base_image_name} -- this may take a few minutes during the first build..."
                )
                print(
                    f"Running build command: {' '.join(str(arg) for arg in build_cmd)}"
                )

            build_result = run_cmd_direct(build_cmd, debug=debug)

            if debug:
                print(f"Build completed with return code: {build_result.returncode}")

            if custom_containerfile is not None:
                if not Path(custom_containerfile).exists():
                    raise FileNotFoundError(
                        f"Custom containerfile not found at {custom_containerfile}"
                    )

                # Prepare build command
                custom_build_cmd = [
                    resolved_oci_runner,
                    "build",
                ]

                custom_build_cmd.extend(
                    [
                        "--tag",
                        "automated-security-helper:custom",
                        "--file",
                        Path(custom_containerfile).as_posix(),
                        "--build-arg",
                        f"ASH_BASE_IMAGE={ash_base_image_name}",
                    ]
                )
                # Add any extra args (do not map --no-cache at this point, we need
                # to build on top of the base image that was built just before this.
                if quiet:
                    custom_build_cmd.append("-q")

                # Add the build context
                custom_build_cmd.append(Path(custom_containerfile).parent.as_posix())

        except Exception as e:
            typer.secho(f"Error building ASH image: {e}", fg=typer.colors.RED)
            if debug:
                if hasattr(e, "stdout"):
                    print(f"Build stdout: {e.stdout}")
                if hasattr(e, "stderr"):
                    print(f"Build stderr: {e.stderr}")
            if isinstance(e, CalledProcessError):
                return e
            return create_completed_process(
                args=build_cmd, returncode=1, stdout="", stderr=str(e)
            )

    # Run the image if the --run flag is set
    if run:
        # Validate source directory
        if source_dir:
            try:
                source_dir = validate_path(source_dir)
            except ValueError as e:
                typer.secho(str(e), fg=typer.colors.RED)
                return create_completed_process(
                    args=[], returncode=1, stdout="", stderr=str(e)
                )

        # Set default source directory if not provided
        if not source_dir:
            source_dir = Path.cwd()
            ASH_LOGGER.info(f"Using current directory as source: {source_dir}")

        # Validate output directory
        if output_dir:
            try:
                # Create output directory if it doesn't exist
                output_dir = Path(output_dir)
                output_dir.mkdir(parents=True, exist_ok=True)
                output_dir = output_dir.resolve()
            except Exception as e:
                typer.secho(
                    f"Error creating output directory: {e}", fg=typer.colors.RED
                )
                return create_completed_process(
                    args=[], returncode=1, stdout="", stderr=str(e)
                )
        else:
            # Default to ash_output in the source directory
            output_dir = source_dir.joinpath("ash_output")
            output_dir.mkdir(parents=True, exist_ok=True)
            ASH_LOGGER.info(f"Using default output directory: {output_dir}")

        run_cmd = [
            resolved_oci_runner,
            "run",
            "--rm",
        ]

        # Add environment variables
        run_cmd.extend(
            [
                "-e",
                f"ASH_ACTUAL_SOURCE_DIR={source_dir}",
                "-e",
                f"ASH_ACTUAL_OUTPUT_DIR={output_dir}",
                "-e",
                f"ASH_DEBUG={'YES' if debug else 'NO'}",
            ]
        )

        # Add mount for source directory
        mount_source_dir = f"type=bind,source={source_dir},destination=/src"

        # Only make source dir readonly if output dir is not a subdirectory
        if output_dir and not str(output_dir).startswith(str(source_dir)):
            mount_source_dir += ",readonly"

        run_cmd.extend(["--mount", mount_source_dir])

        # Add mount for output directory
        run_cmd.extend(["--mount", f"type=bind,source={output_dir},destination=/out"])

        # Add offline mode flag
        if offline:
            run_cmd.append("--network=none")

        # Add terminal size environment variables
        try:
            import shutil

            columns, lines = shutil.get_terminal_size()
            run_cmd.extend(["-e", f"COLUMNS={columns}", "-e", f"LINES={lines}"])
        except Exception as e:
            ASH_LOGGER.debug(f"Unable to determine terminal size via shutil: {e}")

        # Add color support
        if color:
            run_cmd.append("-t")

        # Add image name
        run_cmd.append(ash_base_image_name)

        # Add ASH command
        run_cmd.append("ash")

        # Add ASH arguments
        run_cmd.extend(["--source-dir", "/src", "--output-dir", "/out"])

        # Add additional ASH arguments
        if ctx and hasattr(ctx, "args"):
            ash_args = ctx.args or []
        else:
            ash_args = []

        # Add parameters based on function arguments
        if quiet:
            ash_args.append("--quiet")
        if not progress:
            ash_args.append("--no-progress")
        if not color:
            ash_args.append("--no-color")
        if debug:
            ash_args.append("--debug")
        if verbose:
            ash_args.append("--verbose")
        if simple:
            ash_args.append("--simple")
        if python_based_plugins_only:
            ash_args.append("--python-based-plugins-only")
        if cleanup:
            ash_args.append("--cleanup")
        if inspect:
            ash_args.append("--inspect")
        if fail_on_findings:
            ash_args.append("--fail-on-findings")
        elif fail_on_findings is not None:
            ash_args.append("--no-fail-on-findings")

        # Add phases if specified
        if phases:
            for phase in phases:
                if hasattr(phase, "value"):
                    ash_args.extend(["--phases", phase.value])
                else:
                    ash_args.extend(["--phases", str(phase)])

        # Add scanners if specified
        if scanners:
            for scanner in scanners:
                ash_args.extend(["--scanners", scanner])

        # Add exclude_scanners if specified
        if exclude_scanners:
            for scanner in exclude_scanners:
                ash_args.extend(["--exclude-scanners", scanner])

        # Add output formats if specified
        if output_formats:
            for format in output_formats:
                if hasattr(format, "value"):
                    ash_args.extend(["--output-formats", format.value])
                else:
                    ash_args.extend(["--output-formats", str(format)])

        # Add config if specified
        if config:
            ash_args.extend(["--config", config])

        # Add config overrides if specified
        if config_overrides:
            for override in config_overrides:
                ash_args.extend(["--config-overrides", override])

        # Add existing results if specified
        if existing_results:
            ash_args.extend(["--existing-results", existing_results])

        # Add ash_plugin_modules if specified
        if ash_plugin_modules:
            for module in ash_plugin_modules:
                ash_args.extend(["--ash-plugin-modules", module])

        # Add strategy if not default
        if strategy:
            if hasattr(strategy, "value"):
                ash_args.extend(["--strategy", strategy.value])
            else:
                ash_args.extend(["--strategy", str(strategy)])

        ash_args.append("--no-show-summary")

        # Add any additional ASH arguments
        run_cmd.extend(ash_args)

        typer.echo("Running ASH scan using built image...")
        try:
            # Print the full command if debug is enabled
            if debug:
                print(
                    f"Running container command: {' '.join(str(arg) for arg in run_cmd)}"
                )

            run_result = run_cmd_direct(run_cmd, debug=debug)

            if debug:
                print(
                    f"Container execution completed with return code: {run_result.returncode}"
                )

            # Return the result instead of exiting
            return run_result
        except CalledProcessError as e:
            # Return the error instead of exiting
            if debug:
                print(f"Container execution failed with error: {e}")
            return e

    # If we only built but didn't run, return a success result
    return create_completed_process(args=[], returncode=0, stdout="", stderr="")
