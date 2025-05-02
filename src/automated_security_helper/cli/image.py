# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import os
import re
import logging
import shlex
from subprocess import CalledProcessError, CompletedProcess
import sys
import time
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Annotated, Optional, List
import typer
from rich.console import Console
from rich.panel import Panel
from rich.live import Live
from rich.layout import Layout
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskID
from rich import box
import threading
import io

# Import subprocess utilities
from automated_security_helper.utils.log import get_logger
from automated_security_helper.utils.subprocess_utils import (
    create_process_with_pipes,
    create_completed_process,
    raise_called_process_error,
    get_host_uid,
    get_host_gid,
    find_executable,
)


class BuildTarget(str, Enum):
    NON_ROOT = "non-root"
    CI = "ci"


class OutputFormat(str, Enum):
    TEXT = "text"
    JSON = "json"


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


class CommandOutputStreamer:
    """
    A class to stream command output to a Rich panel with live updates.
    """

    def __init__(
        self,
        console: Console = None,
        output_title: str = "Command Output",
        border_style: str = "green",
        box_style=box.MINIMAL,
        max_output_lines: int = 30,
        refresh_rate: int = 10,
        debug: bool = False,
    ):
        """
        Initialize the command output streamer.

        Args:
            console: Rich console to use
            output_title: Title for the output panel
            border_style: Style for the panel border
            box_style: Box style for the panel
            max_output_lines: Maximum number of output lines to display
            refresh_rate: Refresh rate for the live display
            debug: Whether to print debug information
        """
        self.console = console or Console(
            color_system="auto",
        )
        self.output_title = output_title
        self.border_style = border_style
        self.box_style = box_style
        self.max_output_lines = max_output_lines
        self.refresh_rate = refresh_rate
        self.debug = debug

        # Initialize output buffers
        self.stdout_buffer = io.StringIO()
        self.stderr_buffer = io.StringIO()

        # Initialize output lines
        self.output_lines = []

        # Initialize output panel
        self.output_panel = Panel(
            "",
            title=output_title,
            border_style=border_style,
            box=box_style,
            expand=True,
        )

        # Initialize progress
        self.progress = Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]{task.description}"),
            BarColumn(),
            TextColumn("[bold]{task.fields[status]}"),
        )
        self.task_id = None

        # Initialize layout
        self.layout = Layout()
        self.layout.split(
            Layout(name="progress", size=3),
            Layout(name="output", ratio=1),
        )
        self.layout["progress"].update(self.progress)
        self.layout["output"].update(self.output_panel)

        # Thread lock for synchronization
        self._lock = threading.Lock()

    def _reset_buffers(self):
        """Reset the output buffers."""
        self.stdout_buffer = io.StringIO()
        self.stderr_buffer = io.StringIO()
        self.start_time = datetime.now()

    def start_task(self, description: str) -> TaskID:
        """
        Start a new progress task.

        Args:
            description: Description of the task

        Returns:
            TaskID: The ID of the created task
        """
        with self._lock:
            if self.task_id is not None:
                self.progress.remove_task(self.task_id)
            self.task_id = self.progress.add_task(
                description, total=None, status="Starting..."
            )
            return self.task_id

    def update_task(self, status: str) -> None:
        """
        Update the progress task status.

        Args:
            status: New status text
        """
        with self._lock:
            if self.task_id is not None:
                self.progress.update(self.task_id, status=status)

    def complete_task(self, status: str = "Done") -> None:
        """
        Mark the progress task as complete.

        Args:
            status: Final status text
        """
        with self._lock:
            if self.task_id is not None:
                self.progress.update(self.task_id, status=status, completed=100)

    def fail_task(self, status: str = "Failed") -> None:
        """
        Mark the progress task as failed.

        Args:
            status: Final status text
        """
        with self._lock:
            if self.task_id is not None:
                self.progress.update(self.task_id, status=status, completed=0)

    def _update_terminal_dimensions(self) -> None:
        """Update the terminal dimensions for the layout."""
        # This is a no-op for now, but could be used to handle terminal resizing
        pass

    def add_output_line(self, line: str, filter_pattern: str = None) -> None:
        """
        Add a line to the output panel.

        Args:
            line: Line to add
            filter_pattern: Optional regex pattern to filter lines
        """
        if not line.strip():  # Skip empty lines
            return

        # Apply filter if specified
        if filter_pattern and not re.search(filter_pattern, line):
            return

        with self._lock:
            self.output_lines.append(line.rstrip())
            # Keep only the last N lines
            if len(self.output_lines) > self.max_output_lines:
                self.output_lines.pop(0)

            # Update the panel content
            self.output_panel = Panel(
                "\n".join(self.output_lines),
                title=self.output_title,
                border_style=self.border_style,
                box=self.box_style,
            )
            self.layout["output"].update(self.output_panel)

    def cleanup(self):
        """Clean up resources used by the streamer."""
        self._reset_buffers()
        with self._lock:
            self.output_lines = []
            self.start_time = None

    def run_cmd(
        self, cmd_list: List[str], check: bool = True, filter_pattern: str = None
    ) -> CompletedProcess:
        """
        Run a command with live output streaming.

        Args:
            cmd_list: List of command arguments
            check: Whether to check the return code
            filter_pattern: Optional regex pattern to filter output lines

        Returns:
            subprocess.CompletedProcess: The result of the command

        Raises:
            subprocess.CalledProcessError: If the command returns non-zero and check is True
        """
        # Reset buffers before starting
        self._reset_buffers()

        # Filter out empty or None values
        cmd_list = [str(item) for item in cmd_list if item]

        # Log the command for debugging
        if self.debug:
            self.console.print(
                f"Running command: {' '.join(shlex.quote(arg) for arg in cmd_list)}"
            )

        # Start the progress task
        self.start_task(f"Running {cmd_list[0]}")

        try:
            # Create process using subprocess_utils
            process = create_process_with_pipes(
                args=cmd_list,
                text=True,
            )

            # Create a live display
            with Live(
                self.layout, console=self.console, refresh_per_second=self.refresh_rate
            ):
                # Function to read from a pipe and update the display
                def read_pipe(pipe, is_stderr=False):
                    buffer = self.stderr_buffer if is_stderr else self.stdout_buffer
                    try:
                        for line in iter(pipe.readline, ""):
                            with self._lock:
                                buffer.write(line)
                            self.add_output_line(line, filter_pattern)
                            if is_stderr:
                                self.update_task("Processing...")
                    except Exception as e:
                        error_msg = f"Error reading {'stderr' if is_stderr else 'stdout'}: {str(e)}"
                        self.add_output_line(error_msg)
                        if self.debug:
                            self.console.print(error_msg, style="bold red")

                # Create threads to read stdout and stderr
                stdout_thread = threading.Thread(
                    target=read_pipe, args=(process.stdout, False)
                )
                stderr_thread = threading.Thread(
                    target=read_pipe, args=(process.stderr, True)
                )

                # Mark as daemon threads so they don't block program exit
                stdout_thread.daemon = True
                stderr_thread.daemon = True

                # Start threads
                stdout_thread.start()
                stderr_thread.start()

                # Wait for process to complete
                try:
                    while process.poll() is None:
                        self.update_task("Running...")
                        # Check for terminal resize
                        self._update_terminal_dimensions()
                        time.sleep(0.1)
                except KeyboardInterrupt:
                    # Handle Ctrl+C gracefully
                    process.terminate()
                    self.add_output_line("Command interrupted by user")
                    self.update_task("Interrupted")

                # Wait for threads to complete with timeout
                stdout_thread.join(timeout=2.0)
                stderr_thread.join(timeout=2.0)

                # Update final status
                if process.returncode == 0:
                    self.update_task("Completed")
                elif process.returncode is None:
                    self.update_task("Terminated")
                else:
                    self.update_task(f"Failed (code {process.returncode})")

            # Get the captured output
            stdout = self.stdout_buffer.getvalue()
            stderr = self.stderr_buffer.getvalue()

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

        except Exception as e:
            if not isinstance(e, CalledProcessError):
                self.console.print(
                    f"Error executing command: {str(e)}", style="bold red"
                )
            raise
        finally:
            # Ensure we clean up resources even if there's an exception
            pass


def image_build(
    ctx: typer.Context,
    source_dir: Annotated[
        Optional[str],
        typer.Option(
            "--source-dir",
            "-s",
            help="Path to the directory containing the code/files you wish to scan",
        ),
    ] = None,
    output_dir: Annotated[
        Optional[str],
        typer.Option(
            "--output-dir",
            "-o",
            help="Path to the directory that will contain the report of the scans",
        ),
    ] = None,
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
            "-f",
            help="Force rebuild of the ASH container image",
        ),
    ] = False,
    quiet: Annotated[
        bool,
        typer.Option(
            "--quiet",
            "-q",
            help="Don't print verbose text about the build process",
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
    offline: Annotated[
        bool,
        typer.Option(
            "--offline",
            help="Build ASH for offline execution",
        ),
    ] = False,
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
    verbose: Annotated[bool, typer.Option(help="Enable verbose logging")] = False,
    debug: Annotated[bool, typer.Option(help="Enable debug logging")] = False,
    color: Annotated[bool, typer.Option(help="Enable/disable colorized output")] = True,
):
    """
    Build and run the ASH container image.
    """
    # Configure logging
    logging.basicConfig(
        level=logging.DEBUG if debug else logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )
    logger = get_logger(level=logging.DEBUG if debug else logging.INFO)

    # Create console
    console = Console(color_system="auto" if color else None)

    # Create command output streamer
    cmd_streamer = CommandOutputStreamer(
        console=console,
        output_title="ASH Build Output",
        debug=debug,
    )

    # Validate source directory
    if source_dir:
        try:
            source_dir = validate_path(source_dir)
        except ValueError as e:
            typer.secho(str(e), fg=typer.colors.RED)
            raise typer.Exit(1)

    # Set default source directory if not provided
    if not source_dir:
        source_dir = Path.cwd()
        logger.info(f"Using current directory as source: {source_dir}")

    # Validate output directory
    if output_dir:
        try:
            # Create output directory if it doesn't exist
            output_dir = Path(output_dir)
            output_dir.mkdir(parents=True, exist_ok=True)
            output_dir = output_dir.resolve()
        except Exception as e:
            typer.secho(f"Error creating output directory: {e}", fg=typer.colors.RED)
            raise typer.Exit(1)
    else:
        # Default to ash_output in the source directory
        output_dir = source_dir / "ash_output"
        output_dir.mkdir(parents=True, exist_ok=True)
        logger.info(f"Using default output directory: {output_dir}")

    # Get host UID and GID using safe subprocess calls
    try:
        host_uid = get_host_uid()
        host_gid = get_host_gid()
    except Exception as e:
        typer.secho(f"Error getting user ID information: {e}", fg=typer.colors.RED)
        raise typer.Exit(1)

    # Validate container UID and GID if specified
    if container_uid is not None:
        if not container_uid.isdigit():
            typer.secho("Container UID must be a numeric value", fg=typer.colors.RED)
            raise typer.Exit(1)
    else:
        container_uid = host_uid

    if container_gid is not None:
        if not container_gid.isdigit():
            typer.secho("Container GID must be a numeric value", fg=typer.colors.RED)
            raise typer.Exit(1)
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
            logger.verbose(f"Unable to find {runner} -- continuing")
            continue

    if not resolved_oci_runner:
        typer.secho("Unable to resolve an OCI runner -- exiting", fg=typer.colors.RED)
        raise typer.Exit(1)

    logger.info(f"Resolved OCI_RUNNER to: {resolved_oci_runner}")

    # Get ASH root directory
    ash_root_dir = Path(__file__).parent.parent.parent.parent.resolve()
    dockerfile_path = ash_root_dir / "Dockerfile"

    if not dockerfile_path.exists():
        typer.secho(f"Dockerfile not found at {dockerfile_path}", fg=typer.colors.RED)
        raise typer.Exit(1)

    # Set image name from environment or use default
    ash_image_name = os.environ.get(
        "ASH_IMAGE_NAME", f"automated-security-helper:{build_target.value}"
    )

    # Build the image if the --build flag is set
    if build:
        typer.echo(
            f"Building image {ash_image_name} -- this may take a few minutes during the first build..."
        )

        # Prepare build command
        build_cmd = [
            resolved_oci_runner,
            "build",
        ]

        # Add UID/GID build args
        build_cmd.extend(["--build-arg", f"UID={container_uid}"])
        build_cmd.extend(["--build-arg", f"GID={container_gid}"])

        # Add other build args
        build_cmd.extend(
            [
                "--tag",
                ash_image_name,
                "--target",
                build_target.value,
                "--file",
                dockerfile_path.as_posix(),
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
        if force:
            docker_extra_args.append("--no-cache")
        if quiet:
            docker_extra_args.append("-q")

        # Add any extra args
        build_cmd.extend(docker_extra_args)

        # Add the build context
        build_cmd.append(ash_root_dir.as_posix())

        try:
            build_result = cmd_streamer.run_cmd(build_cmd)
            if debug:
                logger.debug(f"Build stdout: {build_result.stdout}")
                logger.debug(f"Build stderr: {build_result.stderr}")
        except Exception as e:
            typer.secho(f"Error building ASH image: {e}", fg=typer.colors.RED)
            if debug:
                if hasattr(e, "stdout"):
                    logger.debug(f"Build stdout: {e.stdout}")
                if hasattr(e, "stderr"):
                    logger.debug(f"Build stderr: {e.stderr}")
            raise typer.Exit(1)

    # Run the image if the --run flag is set
    if run:
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
            logger.trace(f"Unable to determine terminal size via shutil: {e}")

        # Add color support
        if color:
            run_cmd.append("-t")

        # Add image name
        run_cmd.append(ash_image_name)

        # Add ASH command
        run_cmd.append("ashv3")

        # Add ASH arguments
        run_cmd.extend(["--source-dir", "/src", "--output-dir", "/out"])

        # Add additional ASH arguments, starting with ctx.args in case any extra args
        # were passed in at CLI runtime
        ash_args = ctx.args or []
        if quiet:
            ash_args.append("--quiet")
        if not color:
            ash_args.append("--no-color")
        if debug:
            ash_args.append("--debug")
        if verbose:
            ash_args.append("--verbose")

        # Add any additional ASH arguments
        run_cmd.extend(ash_args)

        typer.echo("Running ASH scan using built image...")
        try:
            run_result = cmd_streamer.run_cmd(run_cmd)
            # Return the exit code from the run command
            if run_result.returncode != 0:
                raise sys.exit(run_result.returncode) from None
            return sys.exit(run_result.returncode)
        except CalledProcessError as e:
            raise sys.exit(e.returncode) from None

    return sys.exit(0)
