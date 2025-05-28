"""Centralized subprocess execution utilities for ASH."""

import logging
import platform
import shutil
import subprocess  # nosec B404 - suprocess module required for the nature of this package to orchestrate SAST/SCA/IAC/SBOM scanners
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union, Any, Literal

from automated_security_helper.core.constants import ASH_BIN_PATH
from automated_security_helper.utils.log import ASH_LOGGER


def find_executable(command: str) -> Optional[str]:
    """Find the full path to an executable.

    Args:
        command: The command to find

    Returns:
        The full path to the executable, or None if not found
    """
    commands = list(
        set(
            [
                command,
                f"{command}.exe" if platform.system().lower() == "windows" else command,
            ]
        )
    )
    for cmd in commands:
        try:
            found = shutil.which(cmd)
            if found:
                return found
            possibles = [
                item
                for item in [
                    ASH_BIN_PATH.joinpath(cmd),
                    (
                        Path("/usr/local/bin").joinpath(cmd)
                        if platform.system().lower() != "windows"
                        else None
                    ),
                ]
                if item is not None
            ]
            for poss in possibles:
                ASH_LOGGER.debug(f"Checking for executable: {poss}")
                if poss.exists():
                    return poss.as_posix()
        except Exception as e:
            ASH_LOGGER.error(e)

        return None


def run_command(
    args: List[str],
    cwd: Optional[Union[str, Path]] = None,
    env: Optional[Dict[str, str]] = None,
    capture_output: bool = True,
    text: bool = True,
    check: bool = False,
    shell: bool = False,
    log_level: int = logging.INFO,
    timeout: Optional[float] = None,
) -> subprocess.CompletedProcess:
    """Run a command and return the completed process.

    Args:
        args: Command arguments as a list
        cwd: Working directory for the command
        env: Environment variables for the command
        capture_output: Whether to capture stdout and stderr
        text: Whether to decode stdout and stderr as text
        check: Whether to raise an exception if the command fails
        shell: Whether to run the command in a shell
        log_level: Log level for command execution
        timeout: Timeout for the command in seconds

    Returns:
        The completed process

    Raises:
        subprocess.CalledProcessError: If check=True and the command fails
        subprocess.TimeoutExpired: If the command times out
    """
    # Resolve the full path to the executable if possible
    if args and not shell:
        binary_full_path = find_executable(args[0])
        if binary_full_path:
            args[0] = binary_full_path

    # Log the command being executed
    cmd_str = " ".join(args) if isinstance(args, list) else args
    ASH_LOGGER.log(log_level, f"Running command: {cmd_str}")

    try:
        result = subprocess.run(  # nosec - Commands are required to be arrays and user input at runtime for the invocation command is not allowed.
            args,
            cwd=cwd.as_posix() if isinstance(cwd, Path) else cwd,
            env=env,
            capture_output=capture_output,
            text=text,
            check=check,
            shell=shell,
            timeout=timeout,
        )

        # Log command result
        if result.returncode == 0:
            ASH_LOGGER.debug(f"Command succeeded with return code {result.returncode}")
        else:
            ASH_LOGGER.warning(f"Command failed with return code {result.returncode}")
            if result.stderr:
                ASH_LOGGER.debug(f"Command stderr: {result.stderr}")

        return result
    except subprocess.CalledProcessError as e:
        ASH_LOGGER.error(f"Command failed with return code {e.returncode}: {cmd_str}")
        if e.stderr:
            ASH_LOGGER.debug(f"Command stderr: {e.stderr}")
        if check:
            raise
        return e
    except subprocess.TimeoutExpired as e:
        ASH_LOGGER.error(f"Command timed out after {timeout} seconds: {cmd_str}")
        if check:
            raise
        return e
    except Exception as e:
        ASH_LOGGER.error(f"Error running command {cmd_str}: {e}")
        if check:
            raise
        # Create a CompletedProcess-like object with error info
        return subprocess.CompletedProcess(
            args=args,
            returncode=1,
            stdout="",
            stderr=f"Error: {str(e)}",
        )


def run_command_with_output_handling(
    command: List[str],
    results_dir: Optional[Union[str, Path]] = None,
    stdout_preference: Literal["return", "write", "both", "none"] = "write",
    stderr_preference: Literal["return", "write", "both", "none"] = "write",
    cwd: Optional[Union[str, Path]] = None,
    env: Optional[Dict[str, str]] = None,
    shell: bool = False,
    class_name: str = None,
) -> Dict[str, Any]:
    """Run a subprocess with the given command and handle output according to preferences.

    Args:
        command: Command to run as a list of arguments
        results_dir: Directory to write output files to
        stdout_preference: How to handle stdout ("return", "write", "both", or "none")
        stderr_preference: How to handle stderr ("return", "write", "both", or "none")
        cwd: Working directory for the command
        env: Environment variables for the command
        shell: Whether to run the command in a shell
        class_name: Optional class name for log file naming

    Returns:
        Dictionary with stdout, stderr, and returncode if requested
    """
    # Resolve the full path to the executable if possible
    if command and not shell:
        binary_full_path = find_executable(command[0])
        if binary_full_path:
            command[0] = binary_full_path

    # Log the command being executed
    cmd_str = " ".join(command) if isinstance(command, list) else command
    ASH_LOGGER.verbose(f"Running: {cmd_str}")

    try:
        result = subprocess.run(  # nosec - Commands are required to be arrays and user input at runtime for the invocation command is not allowed.
            command,
            capture_output=True,
            text=True,
            shell=shell,
            check=False,
            cwd=cwd.as_posix() if isinstance(cwd, Path) else cwd,
            env=env,
        )

        # Default to 1 if it doesn't exist, something went wrong during execution
        returncode = result.returncode or 1

        response = {"returncode": returncode}

        # Process stdout
        if result.stdout:
            if results_dir is not None and stdout_preference in ["write", "both"]:
                results_dir_path = Path(results_dir)
                results_dir_path.mkdir(parents=True, exist_ok=True)
                stdout_filename = (
                    f"{class_name}.stdout.log" if class_name else "stdout.log"
                )
                with open(
                    results_dir_path.joinpath(stdout_filename),
                    "w",
                ) as stdout_file:
                    stdout_file.write(result.stdout)

            if stdout_preference in ["return", "both"]:
                response["stdout"] = result.stdout

        # Process stderr
        if result.stderr:
            if results_dir is not None and stderr_preference in ["write", "both"]:
                results_dir_path = Path(results_dir)
                results_dir_path.mkdir(parents=True, exist_ok=True)
                stderr_filename = (
                    f"{class_name}.stderr.log" if class_name else "stderr.log"
                )
                with open(
                    results_dir_path.joinpath(stderr_filename),
                    "w",
                ) as stderr_file:
                    stderr_file.write(result.stderr)

            if stderr_preference in ["return", "both"]:
                response["stderr"] = result.stderr

        return response

    except Exception as e:
        error_msg = f"Error running {cmd_str}: {e}"
        ASH_LOGGER.error(error_msg)
        return {"error": str(e), "returncode": 1, "stderr": error_msg}


def run_command_get_output(
    args: List[str],
    cwd: Optional[Union[str, Path]] = None,
    env: Optional[Dict[str, str]] = None,
    shell: bool = False,
    check: bool = False,
) -> Tuple[int, str, str]:
    """Run a command and return the exit code, stdout, and stderr.

    Args:
        args: Command arguments as a list
        cwd: Working directory for the command
        env: Environment variables for the command
        shell: Whether to run the command in a shell
        check: Whether to raise an exception if the command fails

    Returns:
        Tuple of (exit_code, stdout, stderr)

    Raises:
        subprocess.CalledProcessError: If check=True and the command fails
    """
    result = run_command(  # nosec B604 - Args for this command are evaluated for security prior to this internal method being invoked
        args=args,
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
        check=check,
        shell=shell,
    )

    return result.returncode, result.stdout, result.stderr


def run_command_stream_output(
    args: List[str],
    cwd: Optional[Union[str, Path]] = None,
    env: Optional[Dict[str, str]] = None,
    shell: bool = False,
) -> int:
    """Run a command and stream its output to the console.

    Args:
        args: Command arguments as a list
        cwd: Working directory for the command
        env: Environment variables for the command
        shell: Whether to run the command in a shell

    Returns:
        The exit code of the command
    """
    # Resolve the full path to the executable if possible
    if args and not shell:
        binary_full_path = find_executable(args[0])
        if binary_full_path:
            args[0] = binary_full_path

    # Log the command being executed
    cmd_str = " ".join(args) if isinstance(args, list) else args
    ASH_LOGGER.info(f"Running command: {cmd_str}")

    try:
        process = subprocess.Popen(  # nosec - Commands are required to be arrays and user input at runtime for the invocation command is not allowed.
            args,
            cwd=cwd.as_posix() if isinstance(cwd, Path) else cwd,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            shell=shell,
        )

        # Stream output
        for line in process.stdout:
            print(line.rstrip())

        # Wait for process to complete
        process.wait()
        return process.returncode

    except Exception as e:
        ASH_LOGGER.error(f"Error running command {cmd_str}: {e}")
        return 1


def get_host_uid() -> int:
    """Get the current user's UID.

    Returns:
        The UID of the current user
    """
    try:
        result = run_command(["id", "-u"], capture_output=True, text=True, check=True)
        return int(result.stdout.strip())
    except Exception as e:
        ASH_LOGGER.error(f"Error getting host UID: {e}")
        return 1000  # Default UID as fallback


def get_host_gid() -> int:
    """Get the current user's GID.

    Returns:
        The GID of the current user
    """
    try:
        result = run_command(["id", "-g"], capture_output=True, text=True, check=True)
        return int(result.stdout.strip())
    except Exception as e:
        ASH_LOGGER.error(f"Error getting host GID: {e}")
        return 1000  # Default GID as fallback


def create_completed_process(
    args: List[str], returncode: int, stdout: str = "", stderr: str = ""
) -> subprocess.CompletedProcess:
    """Create a CompletedProcess object with the given attributes.

    Args:
        args: Command arguments
        returncode: Return code
        stdout: Standard output
        stderr: Standard error

    Returns:
        A CompletedProcess object
    """
    return subprocess.CompletedProcess(
        args=args, returncode=returncode, stdout=stdout, stderr=stderr
    )


def raise_called_process_error(
    returncode: int, cmd: List[str], output: str = None, stderr: str = None
) -> None:
    """Raise a CalledProcessError with the given attributes.

    Args:
        returncode: Return code
        cmd: Command arguments
        output: Standard output
        stderr: Standard error

    Raises:
        subprocess.CalledProcessError: Always raised with the given attributes
    """
    raise subprocess.CalledProcessError(
        returncode=returncode, cmd=cmd, output=output, stderr=stderr
    )


def create_process_with_pipes(
    args: List[str],
    cwd: Optional[Union[str, Path]] = None,
    env: Optional[Dict[str, str]] = None,
    text: bool = True,
    shell: bool = False,
    stderr_to_stdout: bool = False,
) -> subprocess.Popen:
    """Create a process with pipes for stdout and stderr.

    Args:
        args: Command arguments
        cwd: Working directory
        env: Environment variables
        text: Whether to decode stdout and stderr as text
        shell: Whether to run the command in a shell
        stderr_to_stdout: Whether to redirect stderr to stdout

    Returns:
        A Popen object with pipes for stdout and stderr
    """
    # Resolve the full path to the executable if possible
    if args and not shell:
        binary_full_path = find_executable(args[0])
        if binary_full_path:
            args[0] = binary_full_path

    # Log the command being executed
    cmd_str = " ".join(args) if isinstance(args, list) else args
    ASH_LOGGER.verbose(f"Creating process with pipes: {cmd_str}")

    stderr = subprocess.STDOUT if stderr_to_stdout else subprocess.PIPE

    try:
        process = subprocess.Popen(  # nosec - Commands are required to be arrays and user input at runtime for the invocation command is not allowed.
            args,
            cwd=cwd.as_posix() if isinstance(cwd, Path) else cwd,
            env=env,
            stdout=subprocess.PIPE,
            stderr=stderr,
            text=text,
            shell=shell,
        )
        return process
    except Exception as e:
        ASH_LOGGER.error(f"Error creating process with pipes: {e}")
        raise
