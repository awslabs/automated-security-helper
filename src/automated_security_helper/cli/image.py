# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import os
import re
import shutil
import logging
import subprocess
import shlex
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

image_app = typer.Typer(
    name="image",
    help="Build and run ASH container image",
    pretty_exceptions_enable=True,
    pretty_exceptions_short=True,
    pretty_exceptions_show_locals=True,
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
        Path: A validated Path object

    Raises:
        typer.BadParameter: If the path is not valid
    """
    try:
        # Convert to absolute path and resolve any symlinks
        resolved_path = Path(path).resolve()
        return resolved_path
    except (ValueError, TypeError) as e:
        raise typer.BadParameter(f"Invalid path: {path}. Error: {str(e)}")


def safe_split_args(args_str: str) -> List[str]:
    """
    Safely split a string into command arguments.

    Args:
        args_str: String containing command arguments

    Returns:
        List[str]: List of split arguments
    """
    if not args_str:
        return []
    return shlex.split(args_str)


class CommandOutputStreamer:
    """
    Stream and capture command output in real-time using Rich.

    This class provides a rich UI for displaying command output in real-time,
    with progress tracking, elapsed time, and customizable display options.
    """

    def __init__(
        self,
        console: Console,
        debug: bool = False,
        border_style: str = "green",
        box_style: box = box.ROUNDED,
        refresh_rate: int = 10,
        output_title: str = "Command Output",
    ):
        """
        Initialize the CommandOutputStreamer.

        Args:
            console: Rich console instance for output
            debug: Whether to show debug information
            border_style: Style for the output panel border
            box_style: Box style for the output panel
            refresh_rate: UI refresh rate per second
            output_title: Title for the output panel
        """
        self.console = console
        self.debug = debug
        self.border_style = border_style
        self.box_style = box_style
        self.refresh_rate = refresh_rate
        self.output_title = output_title

        # Thread synchronization
        self._lock = threading.Lock()

        # Initialize buffers and UI components
        self._update_terminal_dimensions()
        self._reset_buffers()
        self._setup_layout()

        # Track command execution
        self.start_time = None

    def _update_terminal_dimensions(self):
        """Update terminal dimensions and adjust layout accordingly."""
        self.width, self.height = shutil.get_terminal_size()
        self.max_output_lines = max(10, self.height - 10)

    def _setup_layout(self):
        """Set up the Rich layout components."""
        self.layout = Layout()
        self.progress = Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]{task.description}"),
            BarColumn(),
            TextColumn("[bold]{task.fields[status]}"),
            TextColumn("[dim]{task.fields[elapsed]}"),
        )
        self.task_id = None
        self.output_lines = []
        self.output_panel = Panel(
            "",
            title=self.output_title,
            border_style=self.border_style,
            box=self.box_style,
        )

        # Set up the layout
        self.layout.split(
            Layout(name="progress", size=3),
            Layout(name="output", ratio=1),
        )
        self.layout["progress"].update(self.progress)
        self.layout["output"].update(self.output_panel)

    def _reset_buffers(self):
        """Reset the stdout and stderr buffers."""
        with self._lock:
            self.stdout_buffer = io.StringIO()
            self.stderr_buffer = io.StringIO()

    def start_task(self, description: str) -> TaskID:
        """
        Start a new progress task with elapsed time tracking.

        Args:
            description: Description of the task

        Returns:
            TaskID: ID of the created task
        """
        self.task_id = self.progress.add_task(
            description, total=None, status="Starting...", elapsed="0s"
        )
        self.start_time = time.time()
        return self.task_id

    def update_task(self, status: str):
        """
        Update the task status with elapsed time.

        Args:
            status: New status message
        """
        if self.task_id is not None and self.start_time is not None:
            elapsed = time.time() - self.start_time
            elapsed_str = f"{int(elapsed)}s"
            with self._lock:
                self.progress.update(self.task_id, status=status, elapsed=elapsed_str)

    def add_output_line(self, line: str, filter_pattern: str = None):
        """
        Add a line to the output panel, optionally filtering by pattern.

        Args:
            line: The line to add
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

    def run_command(
        self, cmd_list: List[str], check: bool = True, filter_pattern: str = None
    ) -> subprocess.CompletedProcess:
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
            # Create process
            process = subprocess.Popen(
                cmd_list,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,  # Line buffered
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
            result = subprocess.CompletedProcess(
                args=cmd_list,
                returncode=process.returncode if process.returncode is not None else -1,
                stdout=stdout,
                stderr=stderr,
            )

            # Check return code if requested
            if check and result.returncode != 0:
                raise subprocess.CalledProcessError(
                    result.returncode, cmd_list, output=stdout, stderr=stderr
                )

            return result

        except Exception as e:
            if not isinstance(e, subprocess.CalledProcessError):
                self.console.print(
                    f"Error executing command: {str(e)}", style="bold red"
                )
            raise
        finally:
            # Ensure we clean up resources even if there's an exception
            self.cleanup()


@image_app.callback(invoke_without_command=True)
def image(
    ctx: typer.Context,
    source_dir: Annotated[
        Optional[str],
        typer.Option(
            help="Path to the directory containing the code/files you wish to scan",
        ),
    ] = None,
    output_dir: Annotated[
        Optional[str],
        typer.Option(
            help="Path to the directory that will contain the report of the scans",
        ),
    ] = None,
    format: Annotated[
        OutputFormat,
        typer.Option(
            help="Output format of the aggregated_results file segments",
            case_sensitive=False,
        ),
    ] = OutputFormat.TEXT,
    build_target: Annotated[
        BuildTarget,
        typer.Option(
            help="Specify the target stage of the ASH image to build",
            case_sensitive=False,
        ),
    ] = BuildTarget.NON_ROOT,
    offline: Annotated[
        bool,
        typer.Option(
            help="Build ASH for offline execution",
        ),
    ] = False,
    offline_semgrep_rulesets: Annotated[
        str,
        typer.Option(
            help="Specify Semgrep rulesets for use in ASH offline mode",
        ),
    ] = "p/ci",
    force: Annotated[
        bool,
        typer.Option(
            help="Force rebuild the entire framework to obtain latest changes",
        ),
    ] = False,
    build: Annotated[
        bool,
        typer.Option(
            help="Skip rebuild of the ASH container image, run a scan only",
        ),
    ] = True,
    run: Annotated[
        bool,
        typer.Option(
            help="Skip running a scan with ASH, build a new ASH container image only",
        ),
    ] = True,
    cleanup: Annotated[
        bool,
        typer.Option(
            help="Don't cleanup the work directory where temp reports are stored",
        ),
    ] = False,
    ext: Annotated[
        Optional[str],
        typer.Option(
            "--ext",
            "-extension",
            help="Force a file extension to scan",
        ),
    ] = None,
    color: Annotated[
        bool,
        typer.Option(
            help="Enable/disable colorized output",
        ),
    ] = True,
    single_process: Annotated[
        bool,
        typer.Option(
            "-s",
            "--single-process",
            help="Run ash scanners serially rather than as separate, parallel sub-processes",
        ),
    ] = False,
    oci_runner: Annotated[
        Optional[str],
        typer.Option(
            "-o",
            "--oci-runner",
            help="Use the specified OCI runner instead of docker to run the containerized tools",
            envvar="ASH_OCI_RUNNER",
        ),
    ] = None,
    container_uid: Annotated[
        Optional[str],
        typer.Option(
            "-u",
            "--container-uid",
            help="Specify the UID to use in the container",
        ),
    ] = None,
    container_gid: Annotated[
        Optional[str],
        typer.Option(
            "--container-gid",
            help="Specify the GID to use in the container",
        ),
    ] = None,
    preserve_report: Annotated[
        bool,
        typer.Option(
            "-p",
            "--preserve-report",
            help="Add timestamp to the final report file to avoid overwriting it",
        ),
    ] = False,
    debug: Annotated[
        bool,
        typer.Option(
            "-d",
            "--debug",
            help="Print ASH debug log information where applicable",
        ),
    ] = False,
    quiet: Annotated[
        bool,
        typer.Option(
            "-q",
            "--quiet",
            help="Don't print verbose text about the build process",
        ),
    ] = False,
    version: Annotated[
        bool,
        typer.Option(
            "-v",
            "--version",
            help="Prints version number",
        ),
    ] = False,
):
    """
    Build and run ASH container for security scanning.
    """
    if ctx.resilient_parsing or ctx.invoked_subcommand not in [None, "image"]:
        return

    if version:
        from automated_security_helper import __version__

        typer.echo(f"awslabs/automated-security-helper v{__version__}")
        raise typer.Exit()

    # Set up logging based on verbosity flags
    log_level = logging.INFO
    if debug:
        log_level = logging.DEBUG
    elif quiet:
        log_level = logging.WARNING

    logging.basicConfig(level=log_level)
    logger = logging.getLogger("ash.image")

    # Create Rich console
    cur_term_width, cur_term_height = shutil.get_terminal_size()
    term_width = int(os.environ.get("TERM_WIDTH", cur_term_width))
    term_height = int(os.environ.get("TERM_HEIGHT", cur_term_height))
    console = Console(color_system="auto")

    # Create command output streamer
    cmd_streamer = CommandOutputStreamer(
        console,
        debug=debug,
        border_style="green" if color else "none",
        refresh_rate=10 if color else 5,
    )

    # Set default source directory if not provided
    if source_dir is None:
        source_dir = os.getcwd()

    # Validate and convert paths
    try:
        source_path = validate_path(source_dir)
        if not source_path.exists():
            typer.secho(
                f"Source directory does not exist: {source_dir}", fg=typer.colors.RED
            )
            raise typer.Exit(1)
        if not source_path.is_dir():
            typer.secho(
                f"Source path is not a directory: {source_dir}", fg=typer.colors.RED
            )
            raise typer.Exit(1)
        source_dir = source_path.as_posix()
    except typer.BadParameter as e:
        typer.secho(str(e), fg=typer.colors.RED)
        raise typer.Exit(1)

    # Create and validate output directory if specified
    output_dir_specified = output_dir is not None
    if output_dir_specified:
        try:
            output_path = validate_path(output_dir)
            # Create the directory if it doesn't exist
            output_path.mkdir(parents=True, exist_ok=True)
            if not output_path.is_dir():
                typer.secho(
                    f"Output path is not a directory: {output_dir}", fg=typer.colors.RED
                )
                raise typer.Exit(1)
            output_dir = output_path.as_posix()
        except typer.BadParameter as e:
            typer.secho(str(e), fg=typer.colors.RED)
            raise typer.Exit(1)

    # Set image name from environment or use default
    ash_image_name = os.environ.get(
        "ASH_IMAGE_NAME", f"automated-security-helper:{build_target.value}"
    )

    # Get host UID and GID using safe subprocess calls
    try:
        host_uid_result = subprocess.run(
            ["id", "-u"], capture_output=True, text=True, check=True
        )
        host_uid = host_uid_result.stdout.strip()

        host_gid_result = subprocess.run(
            ["id", "-g"], capture_output=True, text=True, check=True
        )
        host_gid = host_gid_result.stdout.strip()
    except subprocess.CalledProcessError as e:
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

    # Prepare docker extra args - use safe splitting
    docker_extra_args = safe_split_args(os.environ.get("DOCKER_EXTRA_ARGS", ""))
    docker_run_extra_args = []

    # Add force rebuild flag if specified
    if force:
        docker_extra_args.append("--no-cache")

    # Add quiet flag if specified
    if quiet:
        docker_extra_args.append("-q")

    # Add offline mode flag if specified
    if offline:
        docker_run_extra_args.append("--network=none")

    # Prepare ASH args
    ash_args = []

    if quiet:
        ash_args.append("--quiet")

    if ext:
        ash_args.append("--ext")
        ash_args.append(ext)

    if not color:
        ash_args.append("--no-color")

    if single_process:
        ash_args.append("--single-process")

    if preserve_report:
        ash_args.append("--preserve-report")

    if cleanup:
        ash_args.append("--cleanup")

    # Resolve OCI runner
    resolved_oci_runner = oci_runner
    if not resolved_oci_runner:
        for runner in ["docker", "finch", "nerdctl", "podman"]:
            try:
                exists = shutil.which(runner)
                if not exists:
                    continue
                resolved_oci_runner = exists
                break
            except subprocess.CalledProcessError:
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

    # Build the image if the --no-build flag is not set
    if build:
        typer.echo(
            f"Building image {ash_image_name} -- this may take a few minutes during the first build..."
        )

        build_cmd = [
            resolved_oci_runner,
            "build",
        ]

        # Add UID/GID build args if specified
        if container_uid:
            build_cmd.extend(["--build-arg", f"UID={container_uid}"])

        if container_gid:
            build_cmd.extend(["--build-arg", f"GID={container_gid}"])

        # Add remaining build arguments
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

        # Add any extra docker args
        build_cmd.extend(docker_extra_args)

        # Add the build context
        build_cmd.append(ash_root_dir.as_posix())

        try:
            build_result = cmd_streamer.run_command(build_cmd)
            if debug:
                logger.debug(f"Build stdout: {build_result.stdout}")
                logger.debug(f"Build stderr: {build_result.stderr}")
        except subprocess.CalledProcessError as e:
            typer.secho(f"Error building ASH image: {e}", fg=typer.colors.RED)
            if debug:
                logger.debug(f"Build stdout: {e.stdout}")
                logger.debug(f"Build stderr: {e.stderr}")
            raise typer.Exit(1)

    # Run the image if the --no-run flag is not set
    if run:
        run_cmd = [
            resolved_oci_runner,
            "run",
            "--rm",
        ]

        # Add environment variables
        run_cmd.extend(["-e", f"ACTUAL_SOURCE_DIR={source_dir}"])
        run_cmd.extend(["-e", f"ASH_DEBUG={'YES' if debug else 'NO'}"])
        run_cmd.extend(["-e", f"ASH_OUTPUT_FORMAT={format.value}"])
        term_width, term_height = shutil.get_terminal_size()
        # Add to environment variables passed to container
        run_cmd.extend(["-e", f"TERM_WIDTH={term_width}"])
        run_cmd.extend(["-e", f"TERM_HEIGHT={term_height}"])

        # Add source directory mount
        mount_source_option = f"type=bind,source={source_dir},destination=/src"

        # Only make source dir readonly if output dir is not a subdirectory of source
        if output_dir_specified and not output_dir.startswith(source_dir):
            mount_source_option += ",readonly"

        run_cmd.extend(["--mount", mount_source_option])

        # Add output directory mount if specified
        if output_dir_specified:
            run_cmd.extend(
                ["--mount", f"type=bind,source={output_dir},destination=/out"]
            )

        # Add extra docker run args
        run_cmd.extend(docker_run_extra_args)

        # Add image name
        run_cmd.append(ash_image_name)

        # Add ASH command and args
        run_cmd.append("ashv3")
        run_cmd.extend(["--source-dir", "/src"])

        # Add output dir option if specified
        if output_dir_specified:
            run_cmd.extend(["--output-dir", "/out"])

        # Add any additional ASH args
        run_cmd.extend(ash_args)

        typer.echo("Running ASH scan using built image...")

        try:
            run_result = cmd_streamer.run_command(run_cmd, check=False)
            if debug:
                logger.debug(f"Run stdout: {run_result.stdout}")
                logger.debug(f"Run stderr: {run_result.stderr}")

            if run_result.returncode != 0:
                typer.secho(
                    f"ASH scan completed with non-zero exit code: {run_result.returncode}",
                    fg=typer.colors.YELLOW,
                )
                raise typer.Exit(run_result.returncode)
        except Exception as e:
            typer.secho(f"Error running ASH scan: {e}", fg=typer.colors.RED)
            raise typer.Exit(1)


if __name__ == "__main__":
    image_app()
