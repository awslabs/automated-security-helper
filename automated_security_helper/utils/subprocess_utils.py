"""Centralized subprocess execution utilities for ASH."""

import logging
import os
import platform
import shutil
import subprocess  # nosec B404 - suprocess module required for the nature of this package to orchestrate SAST/SCA/IAC/SBOM scanners
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union, Any, Literal

from automated_security_helper.core.constants import ASH_BIN_PATH
from automated_security_helper.utils.log import ASH_LOGGER, NO_MARKUP
from automated_security_helper.utils.process_env import snapshot_environ


_find_executable_cache: dict[str, str | None] = {}


def _spawn_env(env: Optional[Dict[str, str]]) -> Dict[str, str]:
    """The environment to hand a child: the caller's, or a copy of ours.

    Never None. On Linux, CPython 3.10+ spawns with vfork, and with ``env=None``
    the child execs against the parent's live ``environ`` array. Scanners run in
    parallel threads and some of them change the environment while they work
    (cdk_nag_wrapper's JSII variables), which can free that array under a child
    that has not reached ``execve`` yet; the spawn then fails with
    ``[Errno 14] Bad address``. A copy is built into a fresh ``envp`` that no other
    thread can touch, and the child sees the same variables. See
    ``utils/process_env.py``.
    """
    return env if env is not None else snapshot_environ()


# Exit code reported for a command killed at its timeout, matching coreutils
# ``timeout(1)``. run_command keeps its own -1 for compatibility; see there.
TIMEOUT_RETURNCODE = 124


class TimedOutProcess(subprocess.CompletedProcess):
    """A CompletedProcess for a command that was killed at its timeout.

    ``run_command_with_output_handling`` reports a timeout as ``timed_out: True``
    in its dict. Anything that converts that dict into a ``CompletedProcess`` has
    to keep the fact, and a plain ``CompletedProcess`` has no field for it:
    ``UVToolRunner.run_tool`` used to rebuild the result from returncode, stdout
    and stderr alone, so every uv-run scanner (checkov, bandit, semgrep) reported
    a timeout as the missing results file it left behind. Returning this type
    instead lets the flag survive the conversion without changing the return
    type callers already check for.
    """

    timed_out = True


# Exit code reported for a command that never started: the OS refused to spawn it
# (missing or non-executable binary, a bad cwd, EFAULT/ETXTBSY from exec). Shells
# use 127 for "command not found or not runnable" and no scanner accepts it, so a
# spawn failure is never read as a tool that ran and signalled findings.
#
# It used to be 1, the generic failure code. bandit and semgrep both accept 1, so
# a uv binary that failed to exec with [Errno 14] Bad address let the scan carry
# on, and the only error anyone saw was the SARIF file the tool never wrote.
SPAWN_FAILURE_RETURNCODE = 127


class SpawnFailedProcess(subprocess.CompletedProcess):
    """A CompletedProcess for a command the OS could not start.

    The counterpart of ``TimedOutProcess``: ``run_command_with_output_handling``
    reports the fact as ``spawn_failed: True`` in its dict, and this type keeps it
    when a caller (``UVToolRunner.run_tool``) converts that dict back.
    """

    spawn_failed = True


def spawn_failure_message(cmd_str: str, exc: OSError) -> str:
    """The stderr text for a command that never ran."""
    return (
        f"Could not start {cmd_str}: {exc}. The command never ran "
        f"(exit code {SPAWN_FAILURE_RETURNCODE})."
    )


def clear_find_executable_cache() -> None:
    """Clear the find_executable lookup cache.

    Call this after installing a new tool so subsequent lookups can
    discover the newly available binary.
    """
    _find_executable_cache.clear()


def _bin_path() -> Path:
    """The ASH bin directory, resolved when asked rather than at import time.

    ``core.constants.ASH_BIN_PATH`` is computed the first time that module is
    imported. ``ash dependencies install --bin-path X`` sets ASH_BIN_PATH in the
    environment after that has already happened, so a lookup against the constant
    searched the default directory and reported a tool ASH had just installed into
    X as absent.

    The module-level constant remains the fallback, so tests that patch
    ``subprocess_utils.ASH_BIN_PATH`` keep working.
    """
    from_env = os.environ.get("ASH_BIN_PATH")
    return Path(from_env) if from_env else ASH_BIN_PATH


def path_independent_dirs() -> List[Path]:
    """The directories ``find_executable`` searches whatever PATH says, in order.

    These are the fallbacks after ``shutil.which``: ASH's bin directory, then
    /usr/local/bin except on Windows. A tool in one of them is found by every
    later lookup in any environment, which is not true of a tool found only
    through PATH -- a different shell, a CI job or a cron entry may not have the
    same PATH. ``download_utils.find_verified_pinned_executable`` relies on that
    difference, so the list lives here, where ``find_executable`` reads it too,
    rather than being restated there.
    """
    dirs = [_bin_path()]
    if platform.system().lower() != "windows":
        dirs.append(Path("/usr/local/bin"))
    return dirs


def _executable_candidate_names(command: str) -> List[str]:
    """The filenames to try for ``command``, in the order to try them.

    On POSIX this is the command itself and nothing else, so the search there is
    what it was before this function existed.

    Windows needs more, because the file carrying a tool's name is often not the
    file Windows can execute. ``CreateProcess`` runs PE images and nothing else:
    handed a text file with a shebang it fails with ``[WinError 193] %1 is not a
    valid Win32 application``. Package managers therefore write a wrapper Windows
    *can* run beside the script, and expect the wrapper to be what gets invoked.

    Why these three suffixes, in this order:

    * ``.exe`` first. A real PE image should always beat a wrapper.
    * ``.bat`` next, for RubyGems, which writes exactly this and only this.
      ``Gem::Installer#generate_windows_script`` builds
      ``formatted_program_filename(filename) + ".bat"`` (rubygems/installer.rb)
      and is called from ``generate_bin_script`` immediately after the
      extensionless binstub is written -- so on Windows a gem's bindir holds both
      ``cfn_nag_scan`` and ``cfn_nag_scan.bat``, and only the second one runs.
      Read from the installer source rather than recalled, because guessing
      between ``.bat`` and ``.cmd`` here is the whole bug.
    * ``.cmd`` last of the three, for npm, whose shims are ``npm.cmd`` and
      ``node_modules/.bin/*.cmd``. ``npm_audit_scanner`` resolves ``npm`` through
      this same function, so it had the same defect for the same reason.

    The bare name stays in the list, last, as a fallback rather than a preference.
    ``shutil.which`` on Windows can legitimately resolve a name that already
    carries a non-PATHEXT extension, and a directory probe can find a file Windows
    happens to be able to run; dropping the bare name would turn both into "not
    found". Putting it last is what fixes cfn-nag: the extensionless binstub does
    exist in ASH's bin directory, so a search that reaches it first returns the one
    file that cannot be executed, which is what ``[WinError 193]`` was.

    Ordering is also now fixed rather than incidental. The previous list was built
    through ``set()``, so on Windows whether the bare name or ``.exe`` was tried
    first depended on set iteration order -- fine while both lookups failed
    identically, not fine once one of the candidates is the wrong file rather than
    a missing one.

    A command already ending in one of the suffixes is returned unchanged;
    appending ``.exe`` to ``foo.bat`` only adds a lookup that cannot hit.
    """
    if platform.system().lower() != "windows":
        return [command]

    suffixes = (".exe", ".bat", ".cmd")
    if command.lower().endswith(suffixes):
        return [command]
    return [f"{command}{suffix}" for suffix in suffixes] + [command]


def find_executable(command: str) -> Optional[str]:
    """Find the full path to an executable.

    Args:
        command: The command to find

    Returns:
        The full path to the executable, or None if not found
    """
    if command in _find_executable_cache:
        return _find_executable_cache[command]

    for cmd in _executable_candidate_names(command):
        try:
            found = shutil.which(cmd)
            if found:
                _find_executable_cache[command] = found
                return found
            possibles = [
                directory.joinpath(cmd) for directory in path_independent_dirs()
            ]
            for poss in possibles:
                ASH_LOGGER.debug(f"Checking for executable: {poss}", extra=NO_MARKUP)
                if poss.exists():
                    result = poss.as_posix()
                    _find_executable_cache[command] = result
                    return result
        except Exception as e:
            ASH_LOGGER.error(e, extra=NO_MARKUP)

    _find_executable_cache[command] = None
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
    encoding: Optional[str] = None,
    errors: str = "replace",
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
    # Copy args to avoid mutating the caller's list
    args = list(args)

    # Resolve the full path to the executable if possible
    if args and not shell:
        binary_full_path = find_executable(args[0])
        if binary_full_path:
            args[0] = binary_full_path

    # Log the command being executed
    cmd_str = " ".join(args) if isinstance(args, list) else args
    ASH_LOGGER.log(log_level, f"Running command: {cmd_str}", extra=NO_MARKUP)

    # Set encoding for Windows compatibility
    if encoding is None and platform.system().lower() == "windows":
        encoding = "utf-8"

    try:
        result = subprocess.run(  # nosec - Commands are required to be arrays and user input at runtime for the invocation command is not allowed.
            args,
            cwd=cwd.as_posix() if isinstance(cwd, Path) else cwd,
            env=_spawn_env(env),
            capture_output=capture_output,
            text=text,
            check=check,
            shell=shell,
            timeout=timeout,
            encoding=encoding,
            errors=errors,
        )

        # Log command result
        if result.returncode == 0:
            ASH_LOGGER.debug(f"Command succeeded with return code {result.returncode}")
        else:
            ASH_LOGGER.warning(f"Command failed with return code {result.returncode}")
            if result.stderr:
                ASH_LOGGER.debug(f"Command stderr: {result.stderr}", extra=NO_MARKUP)

        return result
    except subprocess.CalledProcessError as e:
        ASH_LOGGER.error(
            f"Command failed with return code {e.returncode}: {cmd_str}",
            extra=NO_MARKUP,
        )
        if e.stderr:
            ASH_LOGGER.debug(f"Command stderr: {e.stderr}", extra=NO_MARKUP)
        if check:
            raise
        return subprocess.CompletedProcess(
            args=e.cmd,
            returncode=e.returncode,
            stdout=e.output or "",
            stderr=e.stderr or "",
        )
    except subprocess.TimeoutExpired as e:
        ASH_LOGGER.error(
            f"Command timed out after {timeout} seconds: {cmd_str}", extra=NO_MARKUP
        )
        if check:
            raise
        # -1 rather than TIMEOUT_RETURNCODE because callers and tests already pin
        # it; the type carries the timeout so nothing has to infer it from the code.
        return TimedOutProcess(
            args=e.cmd,
            returncode=-1,
            stdout=e.stdout or "",
            stderr=e.stderr or f"Command timed out after {e.timeout}s",
        )
    except OSError as e:
        # Ahead of the generic branch, whose returncode 1 reads as "ran and
        # failed" and is an accepted exit code for most scanners.
        error_msg = spawn_failure_message(cmd_str, e)
        ASH_LOGGER.error(error_msg, extra=NO_MARKUP)
        if check:
            raise
        return SpawnFailedProcess(
            args=args,
            returncode=SPAWN_FAILURE_RETURNCODE,
            stdout="",
            stderr=error_msg,
        )
    except Exception as e:
        ASH_LOGGER.error(f"Error running command {cmd_str}: {e}", extra=NO_MARKUP)
        if check:
            raise
        # Create a CompletedProcess-like object with error info
        return subprocess.CompletedProcess(
            args=args,
            returncode=1,
            stdout="",
            stderr=f"Error: {str(e)}",
        )


def _write_stream_log(
    results_dir: Optional[Union[str, Path]],
    class_name: Optional[str],
    stream_name: str,
    preference: str,
    text: str,
) -> None:
    """Write one captured stream to ``<results_dir>/<class_name>.<stream>.log``."""
    if results_dir is None or preference not in ["write", "both"]:
        return
    results_dir_path = Path(results_dir)
    results_dir_path.mkdir(parents=True, exist_ok=True)
    filename = f"{class_name}.{stream_name}.log" if class_name else f"{stream_name}.log"
    with open(
        results_dir_path.joinpath(filename),
        "w",
        encoding="utf-8",
        errors="replace",
    ) as log_file:
        log_file.write(text)


def _spawn_failure_response(
    cmd_str: str,
    exc: OSError,
    results_dir: Optional[Union[str, Path]],
    class_name: Optional[str],
    stderr_preference: str,
) -> Dict[str, Any]:
    """The ``run_command_with_output_handling`` result for a command that never ran.

    There is no tool output, so the reason is the whole stderr. It is written to
    the stderr log as a completed run's would be, because scanners default to
    "write" and read that file to explain a failure.
    """
    error_msg = spawn_failure_message(cmd_str, exc)
    ASH_LOGGER.error(error_msg, extra=NO_MARKUP)
    try:
        _write_stream_log(
            results_dir, class_name, "stderr", stderr_preference, error_msg
        )
    except OSError as log_error:
        ASH_LOGGER.debug(f"Could not write the stderr log: {log_error}")
    return {
        "error": str(exc),
        "returncode": SPAWN_FAILURE_RETURNCODE,
        "spawn_failed": True,
        "stderr": error_msg,
    }


def run_command_with_output_handling(
    command: List[str],
    results_dir: Optional[Union[str, Path]] = None,
    stdout_preference: Literal["return", "write", "both", "none"] = "write",
    stderr_preference: Literal["return", "write", "both", "none"] = "write",
    cwd: Optional[Union[str, Path]] = None,
    env: Optional[Dict[str, str]] = None,
    shell: bool = False,
    class_name: str = None,
    encoding: Optional[str] = None,
    errors: str = "replace",
    timeout: Optional[float] = None,
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
        timeout: Seconds to allow the command before it is killed. None leaves it
            unbounded, which is the previous behaviour and the default so that
            existing callers are unchanged.

    Returns:
        Dictionary with stdout, stderr, and returncode if requested. A timed-out
        command returns returncode 124 (matching coreutils ``timeout(1)``) and
        ``timed_out: True``, so callers can tell it from the generic failure path.
        A command the OS could not start returns returncode 127 and
        ``spawn_failed: True``, with the reason as its stderr.
    """
    # Resolve the full path to the executable if possible
    if command and not shell:
        binary_full_path = find_executable(command[0])
        if binary_full_path:
            command[0] = binary_full_path

    # Log the command being executed
    cmd_str = " ".join(command) if isinstance(command, list) else command
    ASH_LOGGER.verbose(f"Running: {cmd_str}", extra=NO_MARKUP)

    # Set encoding for Windows compatibility
    if encoding is None and platform.system().lower() == "windows":
        encoding = "utf-8"

    try:
        try:
            result = subprocess.run(  # nosec - Commands are required to be arrays and user input at runtime for the invocation command is not allowed.
                command,
                capture_output=True,
                text=True,
                shell=shell,
                check=False,
                cwd=cwd.as_posix() if isinstance(cwd, Path) else cwd,
                env=_spawn_env(env),
                encoding=encoding,
                errors=errors,
                timeout=timeout,
            )
        except OSError as e:
            # Caught here, around the spawn alone, so an OSError from writing the
            # stream logs below is not reported as a command that never ran.
            return _spawn_failure_response(
                cmd_str, e, results_dir, class_name, stderr_preference
            )

        # Use the actual returncode from the result
        returncode = result.returncode

        response = {"returncode": returncode}

        for stream_name, preference, text in (
            ("stdout", stdout_preference, result.stdout),
            ("stderr", stderr_preference, result.stderr),
        ):
            if not text:
                continue
            _write_stream_log(results_dir, class_name, stream_name, preference, text)
            if preference in ["return", "both"]:
                response[stream_name] = text

        return response

    except subprocess.TimeoutExpired as e:
        # subprocess.run has already killed the child by the time this is raised,
        # which is the point: without the kill the tool would keep running after
        # ASH stopped waiting for it.
        #
        # Handled ahead of the generic branch below so a timeout is reported as
        # such. That branch returns returncode 1 for everything, which cannot be
        # told apart from a tool that simply exited 1.
        error_msg = f"Command timed out after {timeout}s: {cmd_str}"
        # NO_MARKUP rather than escaping error_msg: it is also returned to the
        # caller below and lands in the scanner's stderr, which must stay verbatim.
        ASH_LOGGER.error(error_msg, extra=NO_MARKUP)
        partial = {}
        for stream_name, preference in (
            ("stdout", stdout_preference),
            ("stderr", stderr_preference),
        ):
            captured = getattr(e, stream_name, None)
            if not captured:
                continue
            if isinstance(captured, bytes):
                captured = captured.decode("utf-8", errors="replace")
            partial[stream_name] = captured
            # Written where a completed run's output goes. What a tool printed
            # before it was killed is usually the only clue to why it hung, and
            # returning it was not enough: scanners default to "write", so the
            # partial stderr reached no file and no log.
            _write_stream_log(
                results_dir, class_name, stream_name, preference, captured
            )
        return {
            "error": error_msg,
            "returncode": TIMEOUT_RETURNCODE,
            "timed_out": True,
            "stderr": f"{partial.get('stderr', '')}\n{error_msg}".strip(),
            **{k: v for k, v in partial.items() if k == "stdout"},
        }

    except Exception as e:
        error_msg = f"Error running {cmd_str}: {e}"
        ASH_LOGGER.error(error_msg, extra=NO_MARKUP)
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
    encoding: Optional[str] = None,
    errors: str = "replace",
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
    ASH_LOGGER.info(f"Running command: {cmd_str}", extra=NO_MARKUP)

    # Set encoding for Windows compatibility
    if encoding is None and platform.system().lower() == "windows":
        encoding = "utf-8"

    try:
        process = subprocess.Popen(  # nosec - Commands are required to be arrays and user input at runtime for the invocation command is not allowed.
            args,
            cwd=cwd.as_posix() if isinstance(cwd, Path) else cwd,
            env=_spawn_env(env),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            shell=shell,
            encoding=encoding,
            errors=errors,
        )

        try:
            # Stream output
            for line in process.stdout:
                print(line.rstrip())

            # Wait for process to complete
            process.wait()
            return process.returncode
        except Exception as e:
            ASH_LOGGER.error(f"Error running command {cmd_str}: {e}", extra=NO_MARKUP)
            return 1
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()

    except OSError as e:
        ASH_LOGGER.error(spawn_failure_message(cmd_str, e), extra=NO_MARKUP)
        return SPAWN_FAILURE_RETURNCODE
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
        ASH_LOGGER.error(f"Error getting host UID: {e}", extra=NO_MARKUP)
        ASH_LOGGER.warning(
            "Falling back to default UID 1000 (command 'id -u' unavailable on this platform)"
        )
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
        ASH_LOGGER.error(f"Error getting host GID: {e}", extra=NO_MARKUP)
        ASH_LOGGER.warning(
            "Falling back to default GID 1000 (command 'id -g' unavailable on this platform)"
        )
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
    encoding: Optional[str] = None,
    errors: str = "replace",
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
    ASH_LOGGER.verbose(f"Creating process with pipes: {cmd_str}", extra=NO_MARKUP)

    stderr = subprocess.STDOUT if stderr_to_stdout else subprocess.PIPE

    # Set encoding for Windows compatibility
    if encoding is None and platform.system().lower() == "windows":
        encoding = "utf-8"

    try:
        process = subprocess.Popen(  # nosec - Commands are required to be arrays and user input at runtime for the invocation command is not allowed.
            args,
            cwd=cwd.as_posix() if isinstance(cwd, Path) else cwd,
            env=_spawn_env(env),
            stdout=subprocess.PIPE,
            stderr=stderr,
            text=text,
            shell=shell,
            encoding=encoding,
            errors=errors,
        )
        return process
    except Exception as e:
        ASH_LOGGER.error(f"Error creating process with pipes: {e}", extra=NO_MARKUP)
        raise
