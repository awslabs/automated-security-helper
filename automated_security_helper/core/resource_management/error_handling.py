#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Comprehensive error handling utilities for ASH MCP server.

This module provides utilities for handling errors in file operations,
validating input parameters, and creating meaningful error messages for
various failure scenarios.
"""

import errno
import json
import os
import stat
import sys
import time
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple, Union

from automated_security_helper.core.resource_management.exceptions import (
    MCPResourceError,
)
from automated_security_helper.utils.directory_refusals import output_dir_refusal
from automated_security_helper.utils.log import ASH_LOGGER


# Configure module logger
_logger = ASH_LOGGER

#: How a result file is opened for reading: by descriptor, never following a
#: link at its name (O_NOFOLLOW, where the platform has it; Windows has not),
#: never blocking on a FIFO left at the name (O_NONBLOCK), closed on exec.
_READ_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_NONBLOCK", 0)
    | getattr(os, "O_CLOEXEC", 0)
    | getattr(os, "O_BINARY", 0)
)

#: On Windows an open that lands inside ``os.replace`` of the file gets a sharing
#: violation (``PermissionError``) for a moment; retried for the bounded time
#: the writer allows itself (utils/atomic_write.py's _REPLACE_ATTEMPTS and
#: _REPLACE_BACKOFF_SECONDS, 40 x 0.05 s). POSIX never retries.
_REPLACED_FILE_ATTEMPTS = 40
_REPLACED_FILE_BACKOFF_SECONDS = 0.05


class _NotARegularFile(Exception):
    """The descriptor opened at the path is not a regular file's."""


def _read_regular_file_text(path_obj: Path) -> str:
    """Read ``path_obj`` through a descriptor that is checked before it is read.

    The name is opened with :data:`_READ_FLAGS` and the descriptor is
    ``fstat``-ed: what is read is what was checked, so a link or a FIFO swapped
    in at the name between a caller's look and this open is refused (the open
    fails with ELOOP for a link under O_NOFOLLOW; a FIFO or a directory opens
    and is refused as :class:`_NotARegularFile`) instead of followed or waited
    on. Raises what ``os.open`` raises otherwise, with the Windows replace
    retry of ``atomic_write.read_text_of_replaced_file``.
    """
    for attempt in range(_REPLACED_FILE_ATTEMPTS):
        try:
            fd = os.open(path_obj, _READ_FLAGS)
        except PermissionError:
            if sys.platform != "win32" or attempt == _REPLACED_FILE_ATTEMPTS - 1:
                raise
            time.sleep(_REPLACED_FILE_BACKOFF_SECONDS)
            continue
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode):
                raise _NotARegularFile(str(path_obj))
        except BaseException:
            os.close(fd)
            raise
        with os.fdopen(fd, "r", encoding="utf-8") as handle:
            return handle.read()
    raise AssertionError("unreachable: the last attempt returns or raises")


class ErrorCategory(Enum):
    """Categories of errors for better error handling and reporting."""

    FILE_NOT_FOUND = "file_not_found"
    PERMISSION_DENIED = "permission_denied"
    INVALID_FORMAT = "invalid_format"
    INVALID_PARAMETER = "invalid_parameter"
    INVALID_PATH = "invalid_path"
    RESOURCE_EXHAUSTED = "resource_exhausted"
    OPERATION_TIMEOUT = "operation_timeout"
    SCAN_NOT_FOUND = "scan_not_found"
    SCAN_INCOMPLETE = "scan_incomplete"
    #: A configuration that loaded and parsed, whose plugin-module list a
    #: scan refuses. Not a format problem: a format category sent clients
    #: to re-format a healthy file.
    PLUGIN_MODULE_REFUSED = "plugin_module_refused"
    UNEXPECTED_ERROR = "unexpected_error"


def safe_read_json_file(
    file_path: Union[str, Path], required: bool = True
) -> Tuple[Optional[Dict[str, Any]], Optional[MCPResourceError]]:
    """
    Safely read a JSON file with comprehensive error handling.

    Args:
        file_path: Path to the JSON file
        required: If True, raise an error if the file doesn't exist

    Returns:
        Tuple of (parsed_json, error)
        If successful, error will be None
        If failed, parsed_json will be None and error will contain the error information

    The file is looked at without following a link at its name, and a link there
    is refused as an invalid path: every caller reads a result file under a scan's
    output directory, where a sandboxed scanner may have left a link to a file
    outside the tree (utils/sandbox/fs_guard.py), and through a plain open that
    file would have been read as the scan's own. The look is not the check: the
    file is then opened by descriptor without following a link and without
    blocking (``_read_regular_file_text``), and the descriptor is checked to be
    a regular file's before it is read, so a link or a FIFO that the scanner
    swaps in between the look and the open is refused too, where a reopen by
    name followed the link or waited on the FIFO. Each way the read can fail
    has its own category, so a caller branching on ``error_category`` is not
    told "unexpected" for a file that vanished (``file_not_found``), could not
    be read (``permission_denied``), or is not UTF-8 or is nested past what the
    decoder can follow (``invalid_format``).

    The error contexts name the file and nothing about the process: the server's
    working directory used to be in every one, read with ``Path.cwd()`` inside
    the handlers, so a removed working directory made the "safe" read raise
    FileNotFoundError, and create_error_response handed that directory to the
    MCP client with the rest of the context.
    """
    try:
        path_obj = Path(file_path)

        try:
            info = os.lstat(path_obj)
        except (FileNotFoundError, NotADirectoryError):
            if required:
                error = MCPResourceError(
                    f"File not found: {path_obj}",
                    context={
                        "file_path": str(path_obj),
                        "error_category": ErrorCategory.FILE_NOT_FOUND.value,
                    },
                )
                return None, error
            else:
                return None, None
        except PermissionError as e:
            return None, _read_permission_error(path_obj, e)

        if stat.S_ISLNK(info.st_mode):
            error = MCPResourceError(
                f"Path is a symbolic link: {path_obj}",
                context={
                    "file_path": str(path_obj),
                    "error_category": ErrorCategory.INVALID_PATH.value,
                },
            )
            return None, error

        # Check if it's a file
        if not stat.S_ISREG(info.st_mode):
            error = MCPResourceError(
                f"Path is not a file: {path_obj}",
                context={
                    "file_path": str(path_obj),
                    "error_category": ErrorCategory.INVALID_PATH.value,
                },
            )
            return None, error

        # Check if file is readable
        if not os.access(path_obj, os.R_OK):
            error = MCPResourceError(
                f"Permission denied: Cannot read file {path_obj}",
                context={
                    "file_path": str(path_obj),
                    "error_category": ErrorCategory.PERMISSION_DENIED.value,
                },
            )
            return None, error

        # Read and parse the file, by a descriptor checked before it is read (see
        # the docstring). Result files are replaced atomically while scans run,
        # and on Windows an open that lands inside the replace fails with a
        # transient PermissionError; the reader retries that instead of
        # reporting it. One that outlasts the retry is a read error, reported as
        # such and not as a file that failed to parse.
        try:
            text = _read_regular_file_text(path_obj)
        except _NotARegularFile:
            # A FIFO, a directory or a device swapped in at the name since the
            # look above.
            error = MCPResourceError(
                f"Path is not a file: {path_obj}",
                context={
                    "file_path": str(path_obj),
                    "error_category": ErrorCategory.INVALID_PATH.value,
                },
            )
            return None, error
        except (FileNotFoundError, NotADirectoryError):
            # Removed between the look above and the open.
            if not required:
                return None, None
            error = MCPResourceError(
                f"File not found: {path_obj}",
                context={
                    "file_path": str(path_obj),
                    "error_category": ErrorCategory.FILE_NOT_FOUND.value,
                },
            )
            return None, error
        except PermissionError as e:
            return None, _read_permission_error(path_obj, e)
        except OSError as e:
            if e.errno != errno.ELOOP:
                raise
            # A link swapped in at the name since the look above: O_NOFOLLOW
            # refuses to open through it.
            error = MCPResourceError(
                f"Path is a symbolic link: {path_obj}",
                context={
                    "file_path": str(path_obj),
                    "error_category": ErrorCategory.INVALID_PATH.value,
                },
            )
            return None, error
        except UnicodeDecodeError as e:
            error = MCPResourceError(
                f"Invalid JSON format in file {path_obj}: the file is not valid "
                f"UTF-8 ({str(e)})",
                context={
                    "file_path": str(path_obj),
                    "error_category": ErrorCategory.INVALID_FORMAT.value,
                    "error_type": type(e).__name__,
                    "error_message": str(e),
                },
            )
            return None, error
        try:
            data = json.loads(text)
        except json.JSONDecodeError as e:
            error = MCPResourceError(
                f"Invalid JSON format in file {path_obj}: {str(e)}",
                context={
                    "file_path": str(path_obj),
                    "error_category": ErrorCategory.INVALID_FORMAT.value,
                    "json_error": str(e),
                    "error_line": e.lineno,
                    "error_column": e.colno,
                },
            )
            return None, error
        except RecursionError as e:
            # Nested deeper than the decoder follows: a document that cannot
            # be read as JSON here, which is a format problem of the file.
            error = MCPResourceError(
                f"Invalid JSON format in file {path_obj}: the document is nested "
                f"too deeply to decode ({str(e)})",
                context={
                    "file_path": str(path_obj),
                    "error_category": ErrorCategory.INVALID_FORMAT.value,
                    "error_type": type(e).__name__,
                    "error_message": str(e),
                },
            )
            return None, error

        # The callers read the result as a mapping (``data.get``, ``data.keys``),
        # which is what the return type says. A file that parses to a list, a
        # string or a number is valid JSON and not a JSON object, so it is a
        # format error here rather than an AttributeError in the caller.
        if not isinstance(data, dict):
            error = MCPResourceError(
                f"Expected a JSON object in file {path_obj}, found "
                f"{type(data).__name__}",
                context={
                    "file_path": str(path_obj),
                    "error_category": ErrorCategory.INVALID_FORMAT.value,
                    "found_type": type(data).__name__,
                },
            )
            return None, error
        return data, None

    except Exception as e:
        error = MCPResourceError(
            f"Unexpected error reading file {file_path}: {str(e)}",
            context={
                "file_path": str(file_path),
                "error_category": ErrorCategory.UNEXPECTED_ERROR.value,
                "error_type": type(e).__name__,
                "error_message": str(e),
            },
        )
        return None, error


def _read_permission_error(path_obj: Path, e: PermissionError) -> MCPResourceError:
    """The ``permission_denied`` error for a file that could not be read."""
    return MCPResourceError(
        f"Permission denied: Cannot read file {path_obj}: {str(e)}",
        context={
            "file_path": str(path_obj),
            "error_category": ErrorCategory.PERMISSION_DENIED.value,
            "error_type": type(e).__name__,
            "error_message": str(e),
        },
    )


def safe_write_json_file(
    file_path: Union[str, Path], data: Dict[str, Any]
) -> Optional[MCPResourceError]:
    """
    Safely write a JSON file with comprehensive error handling.

    Args:
        file_path: Path to the JSON file
        data: Data to write to the file

    Returns:
        None if successful, MCPResourceError if failed

    Missing parent directories are made by the guarded open itself
    (``open_for_write(make_parents=True)``), never by a ``mkdir(parents=True)``
    of its own first: below a registered writable root the guard makes each
    component without following a link, where mkdir followed one, so the
    directories were created wherever the link pointed and the open that came
    after refused the link, leaving them behind. A link met on the way is
    reported as an invalid path, with the guard's own words.
    """
    try:
        path_obj = Path(file_path)

        # Write the file. Below an output directory, as ASH's other writes there:
        # never through a link (fs_guard).
        from automated_security_helper.utils.output_dir_links import (
            OutputDirLinkRefused,
        )
        from automated_security_helper.utils.sandbox.fs_guard import open_for_write

        # Serialized in full before the file is opened: ``json.dump`` streams
        # into an already truncated file, so a value that cannot be serialized
        # partway through left the previous content gone and a partial document
        # in its place. A serialization error leaves the file as it was. Its
        # own try: the open raises ValueError too, for a path the system
        # refuses (an embedded NUL), and caught together that path error was
        # reported as "Invalid data format for JSON serialization".
        try:
            text = json.dumps(data, indent=2)
        except (TypeError, ValueError) as e:
            # TypeError for a value json cannot encode; ValueError for a
            # structure that refers to itself.
            return MCPResourceError(
                f"Invalid data format for JSON serialization: {str(e)}",
                context={
                    "file_path": str(path_obj),
                    "error_category": ErrorCategory.INVALID_FORMAT.value,
                    "error_message": str(e),
                },
            )

        try:
            with open_for_write(path_obj, make_parents=True) as f:
                f.write(text)
            return None
        except OutputDirLinkRefused as e:
            return MCPResourceError(
                f"Cannot write file {path_obj}: {str(e)}",
                context={
                    "file_path": str(path_obj),
                    "error_category": ErrorCategory.INVALID_PATH.value,
                    "error_type": type(e).__name__,
                    "error_message": str(e),
                },
            )
        except PermissionError as e:
            return MCPResourceError(
                f"Permission denied: Cannot write to file {path_obj}",
                context={
                    "file_path": str(path_obj),
                    "error_category": ErrorCategory.PERMISSION_DENIED.value,
                    "error_type": type(e).__name__,
                    "error_message": str(e),
                },
            )
        except ValueError as e:
            # The path itself, not the data: a string the system refuses as a
            # path (an embedded NUL) is raised by the open as ValueError.
            return MCPResourceError(
                f"Cannot write file {path_obj}: the path is not valid ({str(e)})",
                context={
                    "file_path": str(path_obj),
                    "error_category": ErrorCategory.INVALID_PATH.value,
                    "error_type": type(e).__name__,
                    "error_message": str(e),
                },
            )

    except Exception as e:
        return MCPResourceError(
            f"Unexpected error writing file {file_path}: {str(e)}",
            context={
                "file_path": str(file_path),
                "error_category": ErrorCategory.UNEXPECTED_ERROR.value,
                "error_type": type(e).__name__,
                "error_message": str(e),
            },
        )


def validate_directory_path(
    directory_path: Union[str, Path],
) -> Optional[MCPResourceError]:
    """
    Validate a directory path with comprehensive error handling.

    Path.resolve() canonicalizes the path first, collapsing '..' components and
    following symlinks, so the existence and is-a-directory checks below apply
    to the real target rather than to the name the caller supplied.

    Canonicalization says nothing about *where* the result lands. A resolved
    path is not constrained to any root, prefix or allowlist, so this function
    accepts any existing directory it is given. Callers that need the target
    confined to particular directories have to enforce that themselves; for MCP
    scan targets, automated_security_helper.cli.mcp.scan_target does it, and
    runs before this function.

    This is also used to validate output directories, which is why no root
    policy belongs here.

    Each answer has its own category, read from ``os.stat`` of the resolved path
    rather than from ``Path.exists()``: a path that exists and is not a directory
    is ``invalid_path`` (it used to be reported as not found, so the default
    suggestions told the client to check that it exists); one below a directory
    that cannot be searched is ``permission_denied`` (``exists()`` raised
    PermissionError on some Python versions and answered False on others, so
    the same path was "unexpected" on one and "not found" on another).

    Args:
        directory_path: Path to validate

    Returns:
        None if valid, MCPResourceError if invalid
    """
    path_obj = Path(directory_path)
    try:
        # Canonicalize: resolve symlinks and '..' components. A relative path
        # resolves against the working directory, as the caller means it.
        resolved = path_obj.resolve()
        mode: Optional[int] = os.stat(resolved).st_mode
    except (FileNotFoundError, NotADirectoryError):
        mode = None
    except RuntimeError:
        # Path.resolve's answer for a symlink loop before Python 3.13: a name
        # that leads nowhere.
        mode = None
    except PermissionError as e:
        return MCPResourceError(
            f"Permission denied: Cannot read directory path {directory_path}: {str(e)}",
            context={
                "directory_path": str(directory_path),
                "error_category": ErrorCategory.PERMISSION_DENIED.value,
                "error_type": type(e).__name__,
                "error_message": str(e),
            },
        )
    except OSError as e:
        if e.errno == errno.ELOOP:
            mode = None
        else:
            return _unexpected_directory_error(directory_path, e)
    except Exception as e:
        return _unexpected_directory_error(directory_path, e)

    if mode is not None:
        if stat.S_ISDIR(mode):
            return None  # Path is valid
        return MCPResourceError(
            f"Path is not a directory: {directory_path}",
            context={
                "directory_path": str(directory_path),
                "error_category": ErrorCategory.INVALID_PATH.value,
            },
        )

    # If we get here, nothing is at the path
    return MCPResourceError(
        f"Directory not found or not a directory: {directory_path}",
        context={
            "directory_path": str(directory_path),
            "error_category": ErrorCategory.FILE_NOT_FOUND.value,
        },
    )


def _unexpected_directory_error(
    directory_path: Union[str, Path], e: Exception
) -> MCPResourceError:
    """The ``unexpected_error`` for a directory path that could not be examined."""
    return MCPResourceError(
        f"Unexpected error validating directory path {directory_path}: {str(e)}",
        context={
            "directory_path": str(directory_path),
            "error_category": ErrorCategory.UNEXPECTED_ERROR.value,
            "error_type": type(e).__name__,
            "error_message": str(e),
        },
    )


def source_directory_error(
    directory_path: Union[str, Path],
) -> Optional[MCPResourceError]:
    """Why ``directory_path`` cannot be scanned as a source directory, or None.

    In the words the CLI uses for ``--source-dir``, quoting the path as given:
    "Source directory does not exist" (a link to nothing included), "Source
    directory is not a directory", and "Source directory cannot be entered" for
    one whose entries cannot be listed and read, or that sits below a directory
    that cannot be. For source directories only: validate_directory_path, which
    output-directory lookups also use, keeps its own words.

    A string the operating system refuses as a path at all is worded as the
    CLI words it (utils/directory_refusals.py, ./ash and Invoke-ASH say the
    same): one with an embedded NUL (``ValueError`` from stat) "does not
    exist", and one longer than the system allows (``ENAMETOOLONG``) "cannot be
    entered". Both carry the ``invalid_path`` category, since neither names a
    directory that is absent or closed to this process; the text is the
    surfaces' shared one, the category is this surface's.
    """
    try:
        status = os.stat(directory_path)
    except (FileNotFoundError, NotADirectoryError):
        problem, category = "does not exist", ErrorCategory.FILE_NOT_FOUND
    except ValueError:
        problem, category = "does not exist", ErrorCategory.INVALID_PATH
    except OSError as error:
        if error.errno == errno.ELOOP:
            problem, category = "does not exist", ErrorCategory.FILE_NOT_FOUND
        elif error.errno == errno.ENAMETOOLONG:
            problem, category = "cannot be entered", ErrorCategory.INVALID_PATH
        else:
            problem, category = "cannot be entered", ErrorCategory.PERMISSION_DENIED
    else:
        if not stat.S_ISDIR(status.st_mode):
            problem, category = "is not a directory", ErrorCategory.INVALID_PATH
        elif not os.access(directory_path, os.R_OK | os.X_OK):
            problem, category = "cannot be entered", ErrorCategory.PERMISSION_DENIED
        else:
            return None
    return MCPResourceError(
        f"Source directory {problem}: {directory_path}",
        context={
            "directory_path": str(directory_path),
            "error_category": category.value,
        },
    )


def validate_output_directory_path(
    directory_path: Union[str, Path],
) -> Optional[MCPResourceError]:
    """Validate a scan's output directory, which need not exist yet.

    A scan creates its output directory only once the registry has given it the
    scan, so that a scan refused at max_concurrent_scans leaves nothing on disk.
    Registration therefore accepts a directory that does not exist. It still
    refuses a path that exists and is not a directory, which no scan can write
    into, in the words the CLI uses for an ``--output-dir`` that is a file
    (``utils/directory_refusals.py``). Where the directory may be is the
    caller's to check, as for :func:`validate_directory_path`.

    The category follows what a stat of the path says, not the refusal's words:
    a path that is there and is not a directory is ``invalid_path``; a directory
    that is there and is refused (it cannot be entered, or nothing can be made in
    it) is ``permission_denied``, as is a path stat itself refuses; a path that
    cannot be made because of what is on the way to it is ``invalid_path``. Every
    refusal used to be ``invalid_parameter``, so a client was told to check its
    parameter for a directory it had no permission to write.
    """
    refusal = output_dir_refusal(directory_path)
    if refusal is None:
        return None
    return MCPResourceError(
        refusal,
        context={
            "directory_path": str(directory_path),
            "error_category": _output_directory_refusal_category(directory_path).value,
        },
    )


def _output_directory_refusal_category(
    directory_path: Union[str, Path],
) -> ErrorCategory:
    """The category of a refused output directory, from a stat of the path."""
    try:
        mode = os.stat(directory_path).st_mode
    except PermissionError:
        return ErrorCategory.PERMISSION_DENIED
    except OSError:
        # Not there, or something on the way to it (a file, a link to
        # nothing) keeps it from being made.
        return ErrorCategory.INVALID_PATH
    except ValueError:
        return ErrorCategory.INVALID_PATH
    if not stat.S_ISDIR(mode):
        return ErrorCategory.INVALID_PATH
    return ErrorCategory.PERMISSION_DENIED


def validate_scan_id(scan_id: str) -> Optional[MCPResourceError]:
    """
    Validate a scan ID with comprehensive error handling.

    Args:
        scan_id: Scan ID to validate

    Returns:
        None if valid, MCPResourceError if invalid
    """
    if not scan_id:
        return MCPResourceError(
            "Scan ID cannot be empty",
            context={"error_category": ErrorCategory.INVALID_PARAMETER.value},
        )

    if not isinstance(scan_id, str):
        return MCPResourceError(
            f"Scan ID must be a string, got {type(scan_id).__name__}",
            context={
                "error_category": ErrorCategory.INVALID_PARAMETER.value,
                "parameter_type": type(scan_id).__name__,
            },
        )

    # Additional validation could be added here if needed
    # For example, checking if the scan ID matches a specific format

    return None


#: The severity thresholds a scan accepts, in any case: the values
#: ``AshConfig.global_settings.severity_threshold`` allows, loosest first.
VALID_SEVERITY_THRESHOLDS = ("ALL", "LOW", "MEDIUM", "HIGH", "CRITICAL")


def validate_severity_threshold(severity_threshold: str) -> Optional[MCPResourceError]:
    """
    Validate a severity threshold with comprehensive error handling.

    The accepted set is the full set of values ASH's own configuration allows:
    ``AshConfig.global_settings.severity_threshold`` is
    ``Literal['ALL', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL']``. "ALL" was missing
    here, so a caller passing a threshold read straight out of a valid ASH config
    was refused, and the MCP layer's only options were to fail the scan or to
    substitute a different value. Substituting is the worse of the two: nothing
    gates on the threshold recorded in the scan registry, but ``get_scan_progress``
    reports it, so a scan configured at the strictest setting was reported at a
    middling one -- a loosening direction, in a security tool.

    Widening an accepted set cannot break an input that already worked, so this is
    additive for every existing caller.

    Args:
        severity_threshold: Severity threshold to validate

    Returns:
        None if valid, MCPResourceError if invalid
    """
    valid_severities = list(VALID_SEVERITY_THRESHOLDS)

    if not severity_threshold:
        return MCPResourceError(
            "Severity threshold cannot be empty",
            context={"error_category": ErrorCategory.INVALID_PARAMETER.value},
        )

    if not isinstance(severity_threshold, str):
        return MCPResourceError(
            f"Severity threshold must be a string, got {type(severity_threshold).__name__}",
            context={
                "error_category": ErrorCategory.INVALID_PARAMETER.value,
                "parameter_type": type(severity_threshold).__name__,
            },
        )

    if severity_threshold.upper() not in valid_severities:
        return MCPResourceError(
            f"Invalid severity threshold: '{severity_threshold}'. Must be one of: {', '.join(valid_severities)}",
            context={
                "error_category": ErrorCategory.INVALID_PARAMETER.value,
                "valid_values": valid_severities,
            },
        )

    return None


def validate_config_path(
    config_path: Optional[Union[str, Path]],
) -> Optional[MCPResourceError]:
    """
    Validate a configuration file path with comprehensive error handling.

    Args:
        config_path: Path to the configuration file, or None

    Returns:
        None if valid or None, MCPResourceError if invalid

    ``None`` means no configuration file. An empty string is not that: it is a
    path that names nothing, and the scan tool refuses it, so it is refused here
    too rather than read as "no config" (``Path("")`` is the working directory).
    """
    if config_path is None:
        return None
    if isinstance(config_path, str) and not config_path.strip():
        return MCPResourceError(
            "Configuration path cannot be empty",
            context={
                "config_path": config_path,
                "error_category": ErrorCategory.INVALID_PARAMETER.value,
            },
        )

    try:
        path_obj = (
            Path(config_path)
            if Path(config_path).is_absolute()
            else Path.cwd().joinpath(config_path)
        )

        # Check if file exists
        if not path_obj.exists():
            return MCPResourceError(
                f"Configuration file not found: {path_obj}",
                context={
                    "config_path": str(path_obj),
                    "error_category": ErrorCategory.FILE_NOT_FOUND.value,
                },
            )

        # Check if it's a file
        if not path_obj.is_file():
            return MCPResourceError(
                f"Configuration path is not a file: {path_obj}",
                context={
                    "config_path": str(path_obj),
                    "error_category": ErrorCategory.INVALID_PATH.value,
                },
            )

        # Check if file is readable
        if not os.access(path_obj, os.R_OK):
            return MCPResourceError(
                f"Permission denied: Cannot read configuration file {path_obj}",
                context={
                    "config_path": str(path_obj),
                    "error_category": ErrorCategory.PERMISSION_DENIED.value,
                },
            )

        # Validate file extension. The set is what the config loader reads:
        # YAML, JSON, and TOML (an ``.ashrc.toml`` or a ``pyproject.toml`` whose
        # ``[tool.ash]`` table configures ASH). Discovery hands a workspace
        # project's TOML source to register_scan as its config_path, so a set
        # without ``.toml`` refused every project configured that way.
        valid_extensions = [".yaml", ".yml", ".json", ".toml"]
        if not any(str(path_obj).lower().endswith(ext) for ext in valid_extensions):
            return MCPResourceError(
                f"Invalid configuration file extension: {path_obj}. Supported extensions: {', '.join(valid_extensions)}",
                context={
                    "config_path": str(path_obj),
                    "error_category": ErrorCategory.INVALID_FORMAT.value,
                    "valid_extensions": valid_extensions,
                },
            )

        return None

    except Exception as e:
        return MCPResourceError(
            f"Unexpected error validating configuration path {config_path}: {str(e)}",
            context={
                "config_path": str(config_path),
                "error_category": ErrorCategory.UNEXPECTED_ERROR.value,
                "error_type": type(e).__name__,
                "error_message": str(e),
            },
        )


def validate_scan_parameters(
    directory_path: Union[str, Path],
    severity_threshold: str = "MEDIUM",
    config_path: Optional[Union[str, Path]] = None,
) -> Tuple[bool, List[MCPResourceError]]:
    """
    Validate scan parameters with comprehensive error handling.

    Args:
        directory_path: Path to the directory to scan
        severity_threshold: Minimum severity threshold
        config_path: Optional path to ASH configuration file

    Returns:
        Tuple of (is_valid, list_of_errors)
    """
    errors = []

    # Validate the source directory
    dir_error = source_directory_error(directory_path)
    if dir_error:
        errors.append(dir_error)

    # Validate severity threshold
    severity_error = validate_severity_threshold(severity_threshold)
    if severity_error:
        errors.append(severity_error)

    # Validate configuration path if provided. ``is not None`` and not a
    # truthiness test: an empty string is a config path the scan refuses, and
    # skipping it here passed the parameters as valid.
    if config_path is not None:
        config_error = validate_config_path(config_path)
        if config_error:
            errors.append(config_error)

    return len(errors) == 0, errors


def check_file_exists(file_path: Union[str, Path]) -> bool:
    """
    Check if a file exists with error handling.

    Args:
        file_path: Path to the file

    Returns:
        True if the file exists, False otherwise
    """
    try:
        path_obj = (
            Path(file_path)
            if Path(file_path).is_absolute()
            else Path.cwd().joinpath(file_path)
        )
        return path_obj.exists() and path_obj.is_file()
    except Exception as e:
        _logger.warning(f"Error checking if file exists {file_path}: {str(e)}")
        return False


def check_directory_exists(directory_path: Union[str, Path]) -> bool:
    """
    Check if a directory exists with error handling.

    Args:
        directory_path: Path to the directory

    Returns:
        True if the directory exists, False otherwise
    """
    try:
        path_obj = (
            Path(directory_path)
            if Path(directory_path).is_absolute()
            else Path.cwd().joinpath(directory_path)
        )
        return path_obj.exists() and path_obj.is_dir()
    except Exception as e:
        _logger.warning(
            f"Error checking if directory exists {directory_path}: {str(e)}"
        )
        return False


def create_error_response(
    error: Union[MCPResourceError, Exception],
    operation: str,
    suggestions: Optional[List[str]] = None,
    category: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Create a standardized error response for API operations.

    Args:
        error: The error that occurred
        operation: The operation that was being performed
        suggestions: Optional list of suggestions for resolving the error
        category: The error category, for an error that is not an
            MCPResourceError and so names none in its context

    Returns:
        Standardized error response dictionary
    """
    # Extract error category if available
    error_category = "unexpected_error"
    context = {}

    if isinstance(error, MCPResourceError) and hasattr(error, "context"):
        context = error.context
        error_category = context.get("error_category", "unexpected_error")
    if category is not None:
        error_category = category

    # Generate default suggestions based on error category
    if suggestions is None:
        suggestions = _get_default_suggestions(error_category)

    from automated_security_helper.utils.error_text import error_text
    from automated_security_helper.utils.terminal_text import raw_controls_on_one_line

    return {
        "success": False,
        "operation": operation,
        # The MCP response of every tool's failure: a pydantic error's own text
        # quotes the refused input, which can be a secret (utils/error_text.py).
        # A client reads and may display it, so it holds no control character:
        # each is written as its escape, on one line.
        "error": raw_controls_on_one_line(error_text(error)),
        "error_type": type(error).__name__,
        "error_category": error_category,
        # Its strings name paths and values the error quotes: shown the same way,
        # in a copy, so the error's own context keeps them as raised.
        "context": _strings_shown(context),
        "suggestions": suggestions,
        "timestamp": None,  # Will be set by caller if needed
    }


def _strings_shown(value: Any, _on_path: Optional[set] = None) -> Any:
    """*value* with each string in it, in nested dicts, lists, tuples, sets and
    frozensets too, written for a client that may display it: on one line, each
    control as its escape (utils/terminal_text.py's raw_controls_on_one_line).
    Anything else is returned as it is.

    A dict's string keys are shown the same way as its values: a context keyed
    by a name the repository chose (a scanner's, a path's) reached the client
    with its control characters raw while the values beside it were escaped.

    This runs inside the error handler, so it must not raise on what a context
    can hold. A namedtuple is rebuilt through ``_make`` (its constructor takes
    fields, not an iterable), any other tuple subclass that refuses the rebuilt
    items comes back as a plain tuple, a set whose shown members are not all
    hashable comes back as a list, and a container that refers to itself is cut
    at the second visit with a marker instead of recursing until the interpreter
    stops it.
    """
    from automated_security_helper.utils.terminal_text import raw_controls_on_one_line

    if isinstance(value, str):
        return raw_controls_on_one_line(value)
    if not isinstance(value, (dict, list, tuple, set, frozenset)):
        return value

    on_path = set() if _on_path is None else _on_path
    if id(value) in on_path:
        return "<recursive>"
    on_path.add(id(value))
    try:
        if isinstance(value, dict):
            return {
                (raw_controls_on_one_line(key) if isinstance(key, str) else key): (
                    _strings_shown(item, on_path)
                )
                for key, item in value.items()
            }
        items = [_strings_shown(item, on_path) for item in value]
        if isinstance(value, (set, frozenset)):
            try:
                return type(value)(items)
            except TypeError:
                return items
        if hasattr(type(value), "_make"):
            return type(value)._make(items)
        try:
            return type(value)(items)
        except TypeError:
            return list(items) if isinstance(value, list) else tuple(items)
    finally:
        on_path.discard(id(value))


#: The one wording for the plugin-module refusal's suggestions: the MCP
#: get_config/scan refusal (cli/mcp_tools._plugin_module_refusal) and this
#: module's category defaults answer with the same list, naming only what an
#: MCP client can change. Two wordings for one category sent a reader of the
#: defaults to a "configuration" the MCP client may never have as a file.
#: A tuple, so every response is built as its own ``list(...)`` copy: handed
#: out by identity, one caller's append rewrote the suggestions of every
#: later refusal in the process.
PLUGIN_MODULE_REFUSED_SUGGESTIONS: Tuple[str, ...] = (
    (
        "Review the ash_plugin_modules entries in the config file or the "
        "config content sent"
    ),
    "Remove the entries a scan refuses",
)


def _get_default_suggestions(error_category: str) -> List[str]:
    """
    Get default suggestions based on error category.

    Args:
        error_category: The category of the error

    Returns:
        List of suggestions
    """
    default_suggestions = {
        ErrorCategory.FILE_NOT_FOUND.value: [
            "Check that the file or directory exists",
            "Verify the path is correct",
            "Ensure the file has not been moved or deleted",
        ],
        ErrorCategory.PERMISSION_DENIED.value: [
            "Check file and directory permissions",
            "Ensure the user has appropriate access rights",
            "Verify ownership of the file or directory",
        ],
        ErrorCategory.INVALID_FORMAT.value: [
            "Check the file format and structure",
            "Ensure the file is properly formatted JSON/YAML",
            "Validate the file against the expected schema",
        ],
        ErrorCategory.INVALID_PARAMETER.value: [
            "Check the parameter values provided",
            "Ensure all required parameters are provided",
            "Verify parameter types and formats",
        ],
        ErrorCategory.INVALID_PATH.value: [
            "Verify the path is correct and properly formatted",
            "Check for invalid characters or syntax in the path",
            "Ensure the path points to the correct type (file/directory)",
        ],
        ErrorCategory.RESOURCE_EXHAUSTED.value: [
            "Check system resources (memory, disk space)",
            "Reduce the number of concurrent operations",
            "Wait and try again later",
        ],
        ErrorCategory.OPERATION_TIMEOUT.value: [
            "Check if the operation is still running",
            "Increase the timeout value if possible",
            "Verify system performance and resource availability",
        ],
        ErrorCategory.SCAN_NOT_FOUND.value: [
            "Verify the scan ID is correct",
            "Check if the scan has been cleaned up or expired",
            "Ensure the scan was properly registered",
        ],
        ErrorCategory.SCAN_INCOMPLETE.value: [
            "Wait for the scan to complete",
            "Check for errors in the scan process",
            "Verify the scan is still running",
        ],
        ErrorCategory.PLUGIN_MODULE_REFUSED.value: list(
            PLUGIN_MODULE_REFUSED_SUGGESTIONS
        ),
        ErrorCategory.UNEXPECTED_ERROR.value: [
            "Check logs for additional information",
            "Verify system stability and resource availability",
            "Report the issue if it persists",
        ],
    }

    return default_suggestions.get(
        error_category,
        [
            "Check logs for additional information",
            "Verify input parameters and system state",
            "Report the issue if it persists",
        ],
    )
