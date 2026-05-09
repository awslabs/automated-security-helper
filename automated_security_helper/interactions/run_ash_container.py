# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import json
import os
import re
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
from importlib_metadata import import_module

# Import subprocess utilities
from automated_security_helper.core.constants import (
    ASH_ASSETS_DIR,
    ASH_REPO_LATEST_REVISION,
)
from automated_security_helper.core.enums import (
    AshLogLevel,
    BuildTarget,
    ExecutionPhase,
    ExecutionStrategy,
    ExportFormat,
)
from automated_security_helper.utils import subprocess_utils
from automated_security_helper.utils.subprocess_utils import (
    create_completed_process,
    raise_called_process_error,
)
from automated_security_helper.utils.log import ASH_LOGGER

# Pattern for safe git revision values: alphanumeric, dots, hyphens, underscores, forward slashes
_SAFE_REVISION_PATTERN = re.compile(r"^[A-Za-z0-9._\-/]+$")

# Discovery order for OCI runners (first found wins)
_OCI_RUNNER_CANDIDATES = ["finch", "docker", "nerdctl", "podman"]


def _validate_ash_revision(revision: str) -> bool:
    """Validate that an ASH revision string is safe for use as a Docker build-arg.

    Rejects values containing shell metacharacters that could enable
    command injection in build-arg contexts.

    Args:
        revision: The revision string to validate.

    Returns:
        True if the revision is safe, False otherwise.
    """
    if not revision:
        return False
    return _SAFE_REVISION_PATTERN.match(revision) is not None


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
        try:
            direct_url_json = json.loads(direct_url_json_path.read_text())
            if isinstance(direct_url_json, dict) and "url" in direct_url_json:
                url = direct_url_json["url"]
                if url.startswith("file://"):
                    ASH_LOGGER.info(
                        "ASH installed from local file path, building with LOCAL source"
                    )
                    return "LOCAL"
                elif "vcs_info" in direct_url_json and isinstance(
                    direct_url_json["vcs_info"], dict
                ):
                    vcs_info = direct_url_json["vcs_info"]
                    revision = (
                        vcs_info.get("requested_revision")
                        or vcs_info.get("commit_id")
                        or ASH_REPO_LATEST_REVISION
                    )
                    return_val = revision
                    ASH_LOGGER.info(
                        f"Resolved source revision for ASH to use during container image build: {return_val}"
                    )
                else:
                    ASH_LOGGER.warning(
                        "direct_url.json exists but lacks vcs_info, falling back to latest revision"
                    )
                    return_val = ASH_REPO_LATEST_REVISION
        except (json.JSONDecodeError, KeyError, TypeError) as e:
            ASH_LOGGER.warning(
                f"Failed to parse direct_url.json: {e}, falling back to latest revision"
            )
            return_val = ASH_REPO_LATEST_REVISION
    else:
        return_val = ASH_REPO_LATEST_REVISION

    return return_val


def validate_path(path: str | Path) -> Path:
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
    process = subprocess_utils.create_process_with_pipes(  # nosec B604 - Args for this command are evaluated for security prior to this internal method being invoked
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
        # Handle Ctrl+C gracefully: terminate, wait, then escalate to kill
        process.terminate()
        try:
            process.wait(timeout=5)
        except Exception:
            process.kill()
            process.wait()
        print("Command interrupted by user", file=sys.stderr)

    # Join threads before reading buffers to avoid race condition
    stdout_thread.join(timeout=5.0)
    stderr_thread.join(timeout=5.0)

    # Get the captured output (safe now that threads are joined)
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


# ---------------------------------------------------------------------------
# Private helpers extracted from run_ash_container
# ---------------------------------------------------------------------------


def _find_runner(name: str) -> str | None:
    """Thin wrapper around find_executable used to enable test monkeypatching."""
    try:
        return subprocess_utils.find_executable(name)
    except Exception:
        ASH_LOGGER.debug(f"Unable to find {name} -- continuing")
        return None


def _resolve_oci_runner(oci_runner: str | None) -> str:
    """Discover and return the path to an OCI runner.

    Args:
        oci_runner: Explicit runner name to use, or None to auto-discover.

    Returns:
        The resolved path to the OCI runner binary.

    Raises:
        RuntimeError: When no runner is found.
    """
    candidates = [oci_runner] if oci_runner else _OCI_RUNNER_CANDIDATES
    for runner in candidates:
        path = _find_runner(runner)
        if path:
            ASH_LOGGER.info(f"Resolved OCI_RUNNER to: {path}")
            return path
    raise RuntimeError("Unable to resolve an OCI runner")


def _get_oci_wrapper_prefix() -> List[str]:
    """Return the OCI_RUNNER_WRAPPER as a list suitable for command prefix."""
    oci_wrapper = os.environ.get("OCI_RUNNER_WRAPPER", "").strip()
    return shlex.split(oci_wrapper) if oci_wrapper else []


def _find_dockerfile(resolved_revision: str | None) -> Path:
    """Locate the Dockerfile to use for image builds.

    Args:
        resolved_revision: The resolved ASH revision string (or None).

    Returns:
        Path to the Dockerfile.

    Raises:
        FileNotFoundError: When the Dockerfile cannot be located.
    """
    if resolved_revision == "LOCAL":
        dockerfile_path = Path.cwd().joinpath("Dockerfile")
        if not dockerfile_path.exists():
            current_path = Path.cwd().resolve()
            while current_path.parent != current_path:
                if (
                    current_path.joinpath("Dockerfile").exists()
                    and current_path.joinpath("pyproject.toml").exists()
                ):
                    dockerfile_path = current_path.joinpath("Dockerfile")
                    break
                current_path = current_path.parent
    else:
        cwd_dockerfile = Path.cwd().joinpath("Dockerfile")
        if cwd_dockerfile.exists() and Path.cwd().joinpath("pyproject.toml").exists():
            dockerfile_path = cwd_dockerfile
            ASH_LOGGER.info(
                f"Found Dockerfile in current directory, using LOCAL build context despite revision={resolved_revision}"
            )
        else:
            dockerfile_path = ASH_ASSETS_DIR.joinpath("Dockerfile")

    if not dockerfile_path.exists():
        raise FileNotFoundError(f"Dockerfile not found at {dockerfile_path}")

    return dockerfile_path


def _build_image(
    oci_command_prefix: List[str],
    resolved_oci_runner: str,
    dockerfile_path: Path,
    image_name: str,
    build_target: str,
    container_uid: str,
    container_gid: str,
    resolved_revision: str | None,
    offline: bool,
    offline_semgrep_rulesets: str,
    force: bool,
    quiet: bool,
    custom_build_arg: List[str],
    debug: bool,
) -> None:
    """Build the base ASH container image.

    Raises:
        CalledProcessError: On non-zero exit from the build command.
        Exception: On any other build failure.
    """
    typer.echo(
        f"Building image {image_name} -- this may take a few minutes during the first build..."
    )

    build_cmd = [*oci_command_prefix, resolved_oci_runner, "build"]
    build_cmd.extend(["--build-arg", f"UID={container_uid}"])
    build_cmd.extend(["--build-arg", f"GID={container_gid}"])
    build_cmd.extend(
        [
            "--tag",
            image_name,
            "--target",
            build_target,
            "--file",
            dockerfile_path.as_posix(),
            "--build-arg",
            f"INSTALL_ASH_REVISION={resolved_revision}",
            "--build-arg",
            f"OFFLINE={'YES' if offline else 'NO'}",
            "--build-arg",
            f"OFFLINE_SEMGREP_RULESETS={offline_semgrep_rulesets}",
            "--build-arg",
            f"BUILD_DATE_EPOCH={int(datetime.now().timestamp())}",
        ]
    )

    extra_args: List[str] = []
    if force:
        extra_args.append("--no-cache")
    if quiet:
        extra_args.append("-q")
    build_cmd.extend(extra_args)
    build_cmd.append(dockerfile_path.parent.as_posix())

    if debug:
        print(f"Running build command: {' '.join(str(a) for a in build_cmd)}")

    result = run_cmd_direct(build_cmd, debug=debug)

    if debug:
        print(f"Build completed with return code: {result.returncode}")


def _build_custom_image(
    oci_command_prefix: List[str],
    resolved_oci_runner: str,
    base_image_name: str,
    custom_containerfile: str,
    quiet: bool,
    debug: bool,
) -> str:
    """Build a custom image layered on top of the base ASH image.

    Args:
        base_image_name: Name of the base image to build on top of.
        custom_containerfile: Path to the custom Containerfile/Dockerfile.

    Returns:
        The image name of the custom image.

    Raises:
        FileNotFoundError: When the custom containerfile does not exist.
        CalledProcessError: On non-zero exit from the build command.
    """
    if not Path(custom_containerfile).exists():
        raise FileNotFoundError(
            f"Custom containerfile not found at {custom_containerfile}"
        )

    custom_build_cmd = [*oci_command_prefix, resolved_oci_runner, "build"]
    custom_build_cmd.extend(
        [
            "--tag",
            "automated-security-helper:custom",
            "--file",
            Path(custom_containerfile).as_posix(),
            "--build-arg",
            f"ASH_BASE_IMAGE={base_image_name}",
        ]
    )
    if quiet:
        custom_build_cmd.append("-q")
    custom_build_cmd.append(Path(custom_containerfile).parent.as_posix())

    result = run_cmd_direct(custom_build_cmd, debug=debug)

    if debug:
        print(f"Custom build completed with return code: {result.returncode}")

    return "automated-security-helper:custom"


def _assemble_run_command(
    oci_command_prefix: List[str],
    resolved_oci_runner: str,
    image_name: str,
    source_dir: Path,
    output_dir: Path,
    offline: bool,
    debug: bool,
    color: bool,
    quiet: bool,
    progress: bool,
    verbose: bool,
    simple: bool,
    python_based_plugins_only: bool,
    cleanup: bool,
    inspect: bool,
    fail_on_findings: bool | None,
    phases: List,
    scanners: List[str],
    exclude_scanners: List[str],
    output_formats: List,
    config: str | None,
    config_overrides: List[str],
    existing_results: str | None,
    ash_plugin_modules: List[str],
    strategy,
    ctx,
) -> List[str]:
    """Assemble the full `docker run` command list.

    Returns:
        A list of strings representing the complete run command.
    """
    cmd: List[str] = [*oci_command_prefix, resolved_oci_runner, "run", "--rm"]

    # Environment variables
    cmd.extend(
        [
            "-e", f"ASH_ACTUAL_SOURCE_DIR={source_dir}",
            "-e", f"ASH_ACTUAL_OUTPUT_DIR={output_dir}",
            "-e", f"ASH_DEBUG={'YES' if debug else 'NO'}",
        ]
    )

    # Source dir mount
    mount_source = f"type=bind,source={source_dir},destination=/src"
    if not str(output_dir).startswith(str(source_dir)):
        mount_source += ",readonly"
    cmd.extend(["--mount", mount_source])

    # Output dir mount
    cmd.extend(["--mount", f"type=bind,source={output_dir},destination=/out"])

    # Offline mode
    if offline:
        cmd.append("--network=none")
        cmd.extend(["-e", "ASH_OFFLINE=YES"])

    # Terminal size
    try:
        import shutil as _shutil
        columns, lines = _shutil.get_terminal_size()
        cmd.extend(["-e", f"COLUMNS={columns}", "-e", f"LINES={lines}"])
    except Exception as e:
        ASH_LOGGER.debug(f"Unable to determine terminal size via shutil: {e}")

    if debug:
        print(
            f"TTY check (skipped): color={color}, stdout.isatty()={sys.stdout.isatty()}, stdin.isatty()={sys.stdin.isatty()}"
        )

    # Image name then ash subcommand
    cmd.append(image_name)
    cmd.append("ash")

    # Core ASH path arguments
    cmd.extend(["--source-dir", "/src", "--output-dir", "/out"])

    # Build ash_args from context + parameters
    ash_args: List[str] = []
    if ctx and hasattr(ctx, "args"):
        ash_args = list(ctx.args or [])

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

    for phase in phases:
        ash_args.extend(["--phases", phase.value if hasattr(phase, "value") else str(phase)])

    for scanner in scanners:
        ash_args.extend(["--scanners", scanner])

    for scanner in exclude_scanners:
        ash_args.extend(["--exclude-scanners", scanner])

    for fmt in output_formats:
        ash_args.extend(["--output-formats", fmt.value if hasattr(fmt, "value") else str(fmt)])

    if config:
        ash_args.extend(["--config", config])

    for override in config_overrides:
        ash_args.extend(["--config-overrides", override])

    if existing_results:
        ash_args.extend(["--existing-results", existing_results])

    for module in ash_plugin_modules:
        ash_args.extend(["--ash-plugin-modules", module])

    if strategy:
        ash_args.extend(
            ["--strategy", strategy.value if hasattr(strategy, "value") else str(strategy)]
        )

    ash_args.append("--no-show-summary")

    cmd.extend(ash_args)
    return cmd


def _execute_container(cmd: List[str], debug: bool):
    """Run the assembled container command and return the result.

    Returns:
        subprocess.CompletedProcess on success, CalledProcessError on failure.
    """
    typer.echo("Running ASH scan using built image...")
    if debug:
        print(f"Running container command: {' '.join(str(a) for a in cmd)}")
    try:
        result = run_cmd_direct(cmd, debug=debug)
        if debug:
            print(f"Container execution completed with return code: {result.returncode}")
        return result
    except CalledProcessError as e:
        if debug:
            print(f"Container execution failed with error: {e}")
        return e


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def run_ash_container(
    ctx=None,
    source_dir: str | Path | None = None,
    output_dir: str | Path | None = None,
    log_level: AshLogLevel = AshLogLevel.INFO,
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

    # Get host UID and GID using safe subprocess calls
    try:
        host_uid = subprocess_utils.get_host_uid()
        host_gid = subprocess_utils.get_host_gid()
    except Exception as e:
        typer.secho(f"Error getting user ID information: {e}", fg=typer.colors.RED)
        return create_completed_process(args=[], returncode=1, stdout="", stderr=str(e))

    # Validate container UID and GID if specified
    if container_uid is not None:
        if not container_uid.isdigit():
            typer.secho("Container UID must be a numeric value", fg=typer.colors.RED)
            return create_completed_process(
                args=[], returncode=1, stdout="", stderr="Container UID must be a numeric value",
            )
    else:
        container_uid = str(host_uid)

    if container_gid is not None:
        if not container_gid.isdigit():
            typer.secho("Container GID must be a numeric value", fg=typer.colors.RED)
            return create_completed_process(
                args=[], returncode=1, stdout="", stderr="Container GID must be a numeric value",
            )
    else:
        container_gid = str(host_gid)

    # Resolve OCI runner
    try:
        resolved_oci_runner = _resolve_oci_runner(oci_runner)
    except RuntimeError as e:
        typer.secho(str(e), fg=typer.colors.RED)
        return create_completed_process(
            args=[], returncode=1, stdout="", stderr=str(e)
        )

    oci_command_prefix = _get_oci_wrapper_prefix()

    # Resolve ASH revision
    rev = get_ash_revision()
    resolved_revision = ash_revision_to_install if ash_revision_to_install is not None else rev

    if resolved_revision is not None and resolved_revision != "LOCAL":
        if not _validate_ash_revision(resolved_revision):
            typer.secho(
                f"Invalid ASH revision value: {resolved_revision!r}. "
                "Only alphanumeric characters, dots, hyphens, underscores, "
                "and forward slashes are allowed.",
                fg=typer.colors.RED,
            )
            return create_completed_process(
                args=[], returncode=1, stdout="", stderr=f"Invalid ASH revision value: {resolved_revision!r}",
            )

    # Resolve Dockerfile path
    try:
        dockerfile_path = _find_dockerfile(resolved_revision)
    except FileNotFoundError as e:
        typer.secho(str(e), fg=typer.colors.RED)
        return create_completed_process(
            args=[], returncode=1, stdout="", stderr=str(e)
        )

    # Resolve build target
    resolved_build_target = (
        "ci"
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

    # Build phase
    if build:
        try:
            _build_image(
                oci_command_prefix=oci_command_prefix,
                resolved_oci_runner=resolved_oci_runner,
                dockerfile_path=dockerfile_path,
                image_name=ash_base_image_name,
                build_target=resolved_build_target,
                container_uid=container_uid,
                container_gid=container_gid,
                resolved_revision=resolved_revision,
                offline=offline,
                offline_semgrep_rulesets=offline_semgrep_rulesets,
                force=force,
                quiet=quiet,
                custom_build_arg=custom_build_arg,
                debug=debug,
            )

            if custom_containerfile is not None:
                ash_base_image_name = _build_custom_image(
                    oci_command_prefix=oci_command_prefix,
                    resolved_oci_runner=resolved_oci_runner,
                    base_image_name=ash_base_image_name,
                    custom_containerfile=custom_containerfile,
                    quiet=quiet,
                    debug=debug,
                )

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
                args=[], returncode=1, stdout="", stderr=str(e)
            )

    # Run phase
    if run:
        if source_dir:
            try:
                source_dir = validate_path(source_dir)
            except ValueError as e:
                typer.secho(str(e), fg=typer.colors.RED)
                return create_completed_process(
                    args=[], returncode=1, stdout="", stderr=str(e)
                )

        if not source_dir:
            source_dir = Path.cwd()
            ASH_LOGGER.info(f"Using current directory as source: {source_dir}")

        if output_dir:
            try:
                output_dir = Path(output_dir)
                output_dir.mkdir(parents=True, exist_ok=True)
                output_dir = output_dir.resolve()
            except Exception as e:
                typer.secho(f"Error creating output directory: {e}", fg=typer.colors.RED)
                return create_completed_process(
                    args=[], returncode=1, stdout="", stderr=str(e)
                )
        else:
            output_dir = source_dir.joinpath("ash_output")
            output_dir.mkdir(parents=True, exist_ok=True)
            ASH_LOGGER.info(f"Using default output directory: {output_dir}")

        run_cmd = _assemble_run_command(
            oci_command_prefix=oci_command_prefix,
            resolved_oci_runner=resolved_oci_runner,
            image_name=ash_base_image_name,
            source_dir=source_dir,
            output_dir=output_dir,
            offline=offline,
            debug=debug,
            color=color,
            quiet=quiet,
            progress=progress,
            verbose=verbose,
            simple=simple,
            python_based_plugins_only=python_based_plugins_only,
            cleanup=cleanup,
            inspect=inspect,
            fail_on_findings=fail_on_findings,
            phases=phases,
            scanners=scanners,
            exclude_scanners=exclude_scanners,
            output_formats=output_formats,
            config=config,
            config_overrides=config_overrides,
            existing_results=existing_results,
            ash_plugin_modules=ash_plugin_modules,
            strategy=strategy,
            ctx=ctx,
        )

        return _execute_container(run_cmd, debug=debug)

    # Built but not run
    return create_completed_process(args=[], returncode=0, stdout="", stderr="")
