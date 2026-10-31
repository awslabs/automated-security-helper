#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Scan management functions for ASH MCP server.

This module provides functions for managing scans, including listing active scans,
cancelling scans, and cleaning up completed scans. It builds on the scan registry
to provide a higher-level interface for scan management.
"""

import asyncio
import shutil
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any

from automated_security_helper.core.resource_management.exceptions import (
    MCPResourceError,
)
from automated_security_helper.core.resource_management.scan_registry import (
    DEFAULT_SCAN_SESSION,
    get_scan_registry,
)
from automated_security_helper.utils.log import ASH_LOGGER


# Configure module logger
_logger = ASH_LOGGER

#: How long cleanup waits for a cancelled scan's runner thread to stop and settle
#: its output directory before giving the scan back to the caller as still
#: stopping. The runner stops its scanner's child process and puts the previous
#: results back, which takes seconds; the registry entry and the output
#: directory are removed only once it is done.
_RUNNER_SETTLE_TIMEOUT_SECONDS = 30.0


class _OutputDirectoryInUse(Exception):
    """The output directory must not be removed now; the message says why."""


def _resolved_output_dir(
    output_dir: Path, canonical_output_directory: Path
) -> Optional[Path]:
    """``output_dir`` resolved, when it still resolves into the registered output tree.

    The output directory is stored as a string at registration and removed by
    that path later; the registry fixed its resolved form at registration as
    ``canonical_output_directory``. The recursive delete must land in that
    tree. Resolving the stored path at cleanup time and requiring the result
    to be at or under the registered output directory refuses every way a
    link can redirect it: a ``.ash`` or ``ash_output`` that became a link
    after the scan, a source directory that is itself a link retargeted since,
    a ``projects`` directory of a workspace that became a link, and a link
    anywhere above them. (A per-component lstat walk from the source directory
    down checked none of the source's own ancestors, and checked only the last
    component when the stored spelling did not sit under the stored source.)
    A link that stays inside the tree is admitted: the delete then removes a
    directory the scan owned.

    The caller deletes the path this returns, never the stored spelling: the
    kernel resolves a path again when the delete opens it, so a link on the
    stored spelling retargeted between this check and the delete would land
    the recursive delete in the new target. The resolved path holds no link
    when it is read.

    The comparison is against the OUTPUT tree, not the scanned directory. A
    single MCP scan writes under its source (``<source>/.ash/ash_output``), but
    a workspace scan registers each project with
    ``<settings.output_dir>/projects/<key>`` (cli/mcp/workspace.py), which is
    not under the project's own directory; compared against the scanned
    directory, every workspace entry's cleanup refused the removal and blamed
    a symbolic link that was not there.

    None when the path cannot be resolved at all (a link loop, a NUL byte), or
    resolves outside the registered tree: nothing is removed through a path
    that cannot be read.
    """
    try:
        resolved = output_dir.resolve()
    except (OSError, RuntimeError, ValueError):
        return None
    try:
        resolved.relative_to(canonical_output_directory)
    except ValueError:
        return None
    return resolved


def _remove_output_tree(output_dir: Path) -> bool:
    """Remove ``output_dir`` if it is a directory; True when it is absent afterwards.

    Runs on a worker thread. An already-absent directory is "absent afterwards"
    too: the question the result answers is whether the output is gone, not
    who removed it.
    """
    if output_dir.exists() and output_dir.is_dir():
        shutil.rmtree(output_dir)
    return not output_dir.exists()


def _scoped(session_id: Optional[str]) -> Dict[str, str]:
    """The registry keyword that scopes a lookup to ``session_id``, if one is given.

    An unscoped call passes nothing, so it reaches the registry's unscoped
    lookup.
    """
    return {} if session_id is None else {"session_id": session_id}


def session_holds_scan(scan_id: str, session_id: Optional[str]) -> bool:
    """Whether the registry holds scan ``scan_id`` for ``session_id``.

    A session lookup, never the unscoped one: another session's scan answers
    exactly like an id that was never issued, and ``None`` names the stdio
    session (``DEFAULT_SCAN_SESSION``), not every session. Synchronous, for a
    caller that decides whether a file belongs to a running scan of the session
    (``cli.mcp.sandbox``).
    """
    entry = get_scan_registry().get_scan(scan_id, session_id or DEFAULT_SCAN_SESSION)
    return entry is not None


async def list_active_scans(session_id: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    List all active scans.

    Args:
        session_id: When given, only that session's scans are listed.

    Returns:
        List of active scan information dictionaries
    """
    registry = get_scan_registry()
    return registry.list_scans(active_only=True, **_scoped(session_id))


async def list_all_scans(session_id: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    List all scans, including completed ones.

    Args:
        session_id: When given, only that session's scans are listed. Unscoped,
            this lists every session's scans with their ids, directories and
            error messages, which the registry otherwise shows only to the
            owning session.

    Returns:
        List of all scan information dictionaries
    """
    registry = get_scan_registry()
    return registry.list_scans(**_scoped(session_id))


async def cancel_scan(scan_id: str, session_id: Optional[str] = None) -> Dict[str, Any]:
    """
    Cancel a running scan.

    Args:
        scan_id: ID of the scan to cancel
        session_id: When given, another session's scan answers exactly like an
            unknown id: same response, nothing cancelled.

    Returns:
        Dictionary with cancellation result information, or the error response
        produced by ``create_error_response`` on failure. This does not raise;
        callers should branch on ``success``.
    """
    from automated_security_helper.core.resource_management.error_handling import (
        validate_scan_id,
        ErrorCategory,
        create_error_response,
    )

    # Validate scan ID
    error = validate_scan_id(scan_id)
    if error:
        return create_error_response(
            error=error,
            operation="cancel_scan",
            suggestions=[
                "Check that the scan ID is correct",
                "Verify that the scan exists in the registry",
                "Ensure the scan ID format is valid",
            ],
        )

    registry = get_scan_registry()

    # Get scan information before cancellation
    entry = registry.get_scan(scan_id, **_scoped(session_id))
    if entry is None:
        error = MCPResourceError(
            f"Scan {scan_id} not found",
            context={
                "scan_id": scan_id,
                "error_category": ErrorCategory.SCAN_NOT_FOUND.value,
            },
        )
        return create_error_response(
            error=error,
            operation="cancel_scan",
            suggestions=[
                "Check that the scan ID is correct",
                "Verify that the scan exists in the registry",
                "The scan may have been cleaned up if it was completed a long time ago",
            ],
        )

    # Check if scan is already completed
    if not entry.is_active():
        return {
            "success": False,
            "scan_id": scan_id,
            "message": f"Scan is already in {entry.status.value} state and cannot be cancelled",
            "status": entry.status.value,
            "suggestions": [
                "No action needed as the scan is already completed/incomplete/failed/cancelled",
                "Use get_scan_results to retrieve results if the scan is completed",
                "Start a new scan if needed",
            ],
        }

    try:
        # Try to cancel the scan
        success = registry.cancel_scan(scan_id, **_scoped(session_id))

        if success:
            return {
                "success": True,
                "scan_id": scan_id,
                "message": "Scan cancelled successfully",
                "status": "cancelled",
                "timestamp": datetime.now().isoformat(),
            }

        # The registry declined. The pre-check above ran without the registry
        # lock, and the registry declines only a scan it cannot see or one no
        # longer active, so the scan ended or was removed between the two.
        # Ended is the already-ended answer; removed is the not-found answer
        # the lookup above gives, which cleanup_old_scans branches on. Neither
        # is an unexpected error, and the status shown is read now, not the
        # pre-check's (which read "running" for a scan that was gone).
        ended = registry.get_scan(scan_id, **_scoped(session_id))
        if ended is None:
            return create_error_response(
                error=MCPResourceError(
                    f"Scan {scan_id} not found",
                    context={
                        "scan_id": scan_id,
                        "error_category": ErrorCategory.SCAN_NOT_FOUND.value,
                    },
                ),
                operation="cancel_scan",
                suggestions=[
                    "The scan was removed during the cancellation attempt",
                    "Check that the scan ID is correct",
                    "Start a new scan if needed",
                ],
            )
        if not ended.is_active():
            return {
                "success": False,
                "scan_id": scan_id,
                "message": (
                    f"Scan is already in {ended.status.value} state and cannot "
                    "be cancelled"
                ),
                "status": ended.status.value,
                "suggestions": [
                    "No action needed as the scan is already completed/incomplete/failed/cancelled",
                    "Use get_scan_results to retrieve results if the scan is completed",
                    "Start a new scan if needed",
                ],
            }
        return {
            "success": False,
            "scan_id": scan_id,
            "message": "Failed to cancel scan",
            "status": ended.status.value,
            "error_category": ErrorCategory.UNEXPECTED_ERROR.value,
            "suggestions": [
                "Check scan status using get_scan_progress",
                "Try again if the scan is still active",
            ],
        }
    except MCPResourceError as e:
        # Handle specific MCPResourceError with enhanced context
        return create_error_response(
            error=e,
            operation="cancel_scan",
            suggestions=[
                "Check if you have permission to cancel the scan",
                "Verify that the scan process is still running",
                "The scan may have completed or failed during cancellation attempt",
            ],
        )
    except Exception as e:
        # Handle unexpected errors
        _logger.error(
            f"Unexpected error cancelling scan {scan_id}: {str(e)}", exc_info=True
        )
        return create_error_response(
            error=MCPResourceError(
                f"Unexpected error cancelling scan: {str(e)}",
                context={
                    "scan_id": scan_id,
                    "error_category": ErrorCategory.UNEXPECTED_ERROR.value,
                    "error_type": type(e).__name__,
                    "error_message": str(e),
                },
            ),
            operation="cancel_scan",
        )


async def cleanup_scan_resources(
    scan_id: str, remove_output: bool = False, session_id: Optional[str] = None
) -> Dict[str, Any]:
    """
    Clean up resources associated with a scan.

    Args:
        scan_id: ID of the scan to clean up
        remove_output: If True, also remove output files
        session_id: When given, another session's scan answers exactly like an
            unknown id: same response, nothing cancelled, removed or deleted.

    Returns:
        Dictionary with cleanup result information, or the error response
        produced by ``create_error_response`` on failure. This does not raise;
        callers should branch on ``success``. A scan whose runner is still
        stopping after the cancel is reported with ``success`` False and
        nothing removed; retry once it has settled.

    ``removed_output`` answers whether the output directory is absent once the
    call has run: True for one this call removed and for one that was already
    gone, False for one that is still there. It used to be False for an
    already-absent directory and True for one that vanished partway through
    the walk, whether or not part of the tree remained.

    When the output directory was asked to be removed and could not be, the
    scan stays in the registry and ``success`` is False, so the directory is
    still reachable through the entry for a retry. Removing the entry anyway,
    as this used to, reported success and left the directory with nothing
    pointing at it. The two deliberate refusals are different: an output tree
    another scan of the directory still holds, or a link on the output path,
    is left in place while the entry is removed, because no retry would change
    either, and the warning says so.
    """
    from automated_security_helper.core.resource_management.error_handling import (
        validate_scan_id,
        ErrorCategory,
        create_error_response,
    )

    # Validate scan ID
    error = validate_scan_id(scan_id)
    if error:
        return create_error_response(
            error=error,
            operation="cleanup_scan_resources",
            suggestions=[
                "Check that the scan ID is correct",
                "Verify that the scan exists in the registry",
                "Ensure the scan ID format is valid",
            ],
        )

    registry = get_scan_registry()

    # Get scan information before cleanup
    entry = registry.get_scan(scan_id, **_scoped(session_id))
    if entry is None:
        error = MCPResourceError(
            f"Scan {scan_id} not found",
            context={
                "scan_id": scan_id,
                "error_category": ErrorCategory.SCAN_NOT_FOUND.value,
            },
        )
        return create_error_response(
            error=error,
            operation="cleanup_scan_resources",
            suggestions=[
                "Check that the scan ID is correct",
                "Verify that the scan exists in the registry",
                "The scan may have been cleaned up already",
            ],
        )

    try:
        # Check if scan is still active
        if entry.is_active():
            # Try to cancel the scan first
            try:
                cancel_result = await cancel_scan(scan_id, **_scoped(session_id))
                if not cancel_result.get("success", False):
                    _logger.warning(
                        f"Failed to cancel scan {scan_id} during cleanup: {cancel_result.get('message', 'Unknown error')}"
                    )
            except Exception as e:
                _logger.warning(
                    f"Failed to cancel scan {scan_id} during cleanup: {str(e)}"
                )

        # A cancel closes the entry at once, while the in-process runner thread
        # may run for seconds more: it stops its scanner's child process and
        # puts the previous results back into the output directory. Removing
        # that directory and the entry while it does so deletes a tree the
        # runner still writes into, and lets a new scan of the directory in
        # that the restore then overwrites. So the runner is waited for, and a
        # scan whose runner has not settled in time is handed back as still
        # stopping with nothing removed.
        if entry.has_runner and not entry.runner_done.is_set():
            settled = await asyncio.to_thread(
                entry.runner_done.wait, _RUNNER_SETTLE_TIMEOUT_SECONDS
            )
            if not settled:
                return {
                    "success": False,
                    "scan_id": scan_id,
                    "removed_output": False,
                    "removed_from_registry": False,
                    "message": (
                        "Scan is still stopping: its runner has not finished "
                        "settling the output directory"
                    ),
                    "status": entry.status.value,
                    "error_category": ErrorCategory.RESOURCE_EXHAUSTED.value,
                    "suggestions": [
                        (
                            "Retry in a few seconds: the scan stops its scanner and "
                            "puts the previous results back before its resources "
                            "can be removed"
                        ),
                    ],
                    "timestamp": datetime.now().isoformat(),
                }

        # The entry was read before the cancel and the wait, and both give up
        # control: a concurrent cleanup of the same scan can have removed the
        # entry meanwhile. Working on from the stale object, the output removal
        # marked an entry the registry no longer held, so register_scan found
        # no mark and admitted a new scan of the same tree while this call was
        # deleting it. So the entry is read again here, and a scan that is gone
        # is reported as not found: whoever removed it did this work.
        entry = registry.get_scan(scan_id, **_scoped(session_id))
        if entry is None:
            return create_error_response(
                error=MCPResourceError(
                    f"Scan {scan_id} not found",
                    context={
                        "scan_id": scan_id,
                        "error_category": ErrorCategory.SCAN_NOT_FOUND.value,
                    },
                ),
                operation="cleanup_scan_resources",
                suggestions=[
                    "The scan was removed from the registry while it was stopping",
                    "Nothing is left to clean up for this scan id",
                ],
            )

        # The runner's finish is not the last writer's. A cancel that could not
        # end one of the scanner tools leaves that tool writing into the output
        # directory on its own clock (ScanRegistryEntry.could_not_stop), and
        # cleanup_scan keeps the entry for as long as it runs. The removal did
        # not ask: it deleted the tree under the writing tool, cleanup_scan then
        # refused, and the caller read removed_output True beside
        # removed_from_registry False with a generic message. Handed back as
        # still stopping instead, with the tools named and nothing removed, as
        # the docstring promises for a scan that has not settled.
        if entry.a_surviving_tool_is_running():
            # By basename: a tool is recorded as argv0 as spawned, which can be
            # the server's full path, and this message reaches a remote MCP
            # client (record_cancel_outcome names the tools the same way).
            tools = ", ".join(entry.tool_display_names())
            return {
                "success": False,
                "scan_id": scan_id,
                "removed_output": False,
                "removed_from_registry": False,
                "message": (
                    "Scan is still stopping: a scanner tool the cancel could not "
                    f"end is still running ({tools})"
                ),
                "status": entry.status.value,
                "error_category": ErrorCategory.RESOURCE_EXHAUSTED.value,
                "suggestions": [
                    (
                        "End the tool's process (the scan's entry names it in its "
                        "warnings), then retry: the output directory may still be "
                        "written to while it runs"
                    ),
                ],
                "timestamp": datetime.now().isoformat(),
            }

        # Remove output files if requested
        removed_output = False
        output_dir_error = None
        # Whether a failed removal keeps the entry for a retry (True), or is a
        # deliberate refusal that a retry would not change (False).
        output_removal_failed = False
        if remove_output and entry.output_directory:
            try:
                output_dir = Path(entry.output_directory)

                def remove() -> bool:
                    # The path was recorded at registration; a link placed on
                    # or above it since would redirect the delete outside the
                    # output tree the scan registered. Checked here, on the
                    # worker thread the registry runs this remover on, OFF the
                    # registry's lock (remove_output_of_scan marks the entry
                    # under its lock and runs the remover outside it) and right
                    # before the delete, against the registered OUTPUT
                    # directory: a workspace project's output sits under the
                    # workspace's output_dir, not under the project's own
                    # directory. Nothing serializes this check with the delete
                    # but their order on this thread.
                    resolved = _resolved_output_dir(
                        output_dir, entry.canonical_output_directory
                    )
                    if resolved is None:
                        raise _OutputDirectoryInUse(
                            "the output path now resolves outside the output "
                            "directory the scan registered (a component of it "
                            "became a symbolic link)"
                        )
                    # A link as the last component is left in place, with
                    # what it points to: rmtree refuses a link, so the delete
                    # would fail on every retry and keep the entry for good.
                    if output_dir.is_symlink():
                        raise _OutputDirectoryInUse(
                            "the output directory is itself a symbolic link, "
                            "which is left in place with what it points to"
                        )
                    # The stats and the recursive delete, on the worker thread
                    # this remover runs on, of the path that was just checked
                    # and not of the stored spelling; True when the tree is
                    # absent afterwards, an already-absent one included.
                    return _remove_output_tree(resolved)

                # Every scan of one source directory writes the same output
                # tree under it, so this scan's output directory is also every
                # other scan of the directory's. The registry decides, under
                # its lock, whether another scan holds the tree (running or
                # stopping, or registered later with its results in it), marks
                # the entry as removing, and runs the delete off the lock; a
                # scan registered while the tree comes down waits on that mark
                # instead of writing into it, and every other registry caller
                # is not held by the delete. Off the event loop: the delete
                # blocks for as long as the tree takes to remove.
                reason, removed_output = await asyncio.to_thread(
                    registry.remove_output_of_scan, entry, remove
                )
                if reason is not None:
                    raise _OutputDirectoryInUse(reason)
                if not removed_output:
                    # The remover ran and raised nothing, yet the path is still
                    # there: it is not a directory (a file or a device at the
                    # output name is not removed), or the tree was re-created
                    # while it came down. Not a success, and nothing a second
                    # try could not change, so the entry is kept for the retry
                    # as for any other failed removal.
                    output_removal_failed = True
                    output_dir_error = (
                        "Failed to remove output directory: the path is still "
                        "present (not a directory, or re-created while it was "
                        "being removed)"
                    )
                    _logger.error(
                        f"Failed to remove output directory for scan {scan_id}: "
                        "the path is still present"
                    )
            except _OutputDirectoryInUse as e:
                output_dir_error = f"Output directory not removed: {e}"
                _logger.warning(f"Output directory of scan {scan_id} not removed: {e}")
            except PermissionError as e:
                output_removal_failed = True
                output_dir_error = (
                    f"Permission denied: Cannot remove output directory: {str(e)}"
                )
                _logger.error(
                    f"Permission denied: Cannot remove output directory for scan {scan_id}: {str(e)}"
                )
            except FileNotFoundError as e:
                # Raised from inside the walk when an entry vanished under it.
                # The directory itself may be gone (someone else removed it,
                # which is not an error) or may still be there with part of
                # the tree in it.
                removed_output = not await asyncio.to_thread(output_dir.exists)
                if not removed_output:
                    output_removal_failed = True
                    output_dir_error = (
                        f"Failed to remove output directory: {str(e)}; part of the "
                        "tree remains"
                    )
                    _logger.error(
                        f"Failed to remove output directory for scan {scan_id}: "
                        f"{str(e)}; part of the tree remains"
                    )
            except Exception as e:
                output_removal_failed = True
                output_dir_error = f"Failed to remove output directory: {str(e)}"
                _logger.error(
                    f"Failed to remove output directory for scan {scan_id}: {str(e)}"
                )

        if output_removal_failed:
            # Kept in the registry: the entry is what still names the output
            # directory, so a retry can reach it.
            return {
                "success": False,
                "scan_id": scan_id,
                "removed_output": False,
                "removed_from_registry": False,
                "message": (
                    "Output directory could not be removed; the scan stays in the "
                    "registry so the cleanup can be retried"
                ),
                "output_dir_error": output_dir_error,
                "warnings": [
                    (
                        "Output directory could not be removed; the scan was kept "
                        "in the registry"
                    )
                ],
                "timestamp": datetime.now().isoformat(),
            }

        # Remove scan from registry
        removed_from_registry = registry.cleanup_scan(scan_id, **_scoped(session_id))

        result = {
            "success": removed_from_registry,
            "scan_id": scan_id,
            "removed_output": removed_output,
            "removed_from_registry": removed_from_registry,
            "message": "Scan resources cleaned up successfully"
            if removed_from_registry
            else "Failed to clean up scan resources",
            "timestamp": datetime.now().isoformat(),
        }

        # Add output directory error if there was one. The warning says what
        # happened to the entry, which depends on what the registry answered.
        if output_dir_error:
            result["output_dir_error"] = output_dir_error
            result["warnings"] = [
                "Output directory could not be removed, but scan was removed from registry"
                if removed_from_registry
                else "Output directory could not be removed, and the scan was not "
                "removed from the registry"
            ]

        return result

    except Exception as e:
        # Handle unexpected errors
        _logger.error(
            f"Unexpected error cleaning up scan {scan_id}: {str(e)}", exc_info=True
        )
        return create_error_response(
            error=MCPResourceError(
                f"Unexpected error cleaning up scan: {str(e)}",
                context={
                    "scan_id": scan_id,
                    "error_category": ErrorCategory.UNEXPECTED_ERROR.value,
                    "error_type": type(e).__name__,
                    "error_message": str(e),
                },
            ),
            operation="cleanup_scan_resources",
        )


async def cleanup_old_scans(
    max_age_hours: int = 24,
    remove_output: bool = False,
    session_id: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Clean up old completed scans.

    Args:
        max_age_hours: Maximum age in hours for completed scans
        remove_output: If True, also remove output files
        session_id: When given, only that session's scans are cleaned up.

    Returns:
        Dictionary with cleanup result information. A scan that was removed by
        a concurrent cleanup between the listing and its own cleanup is listed
        under ``already_removed`` and counts as neither cleaned up nor failed.
    """
    registry = get_scan_registry()

    # Get list of all scans before cleanup
    all_scans = registry.list_scans(**_scoped(session_id))

    # Find old scans that should be cleaned up
    now = datetime.now()
    cutoff_time = now.timestamp() - (max_age_hours * 3600)
    scans_to_cleanup = []

    for scan in all_scans:
        if scan["status"] in ["completed", "incomplete", "failed", "cancelled"]:
            end_time_str = scan.get("end_time") or scan.get("start_time")
            if end_time_str:
                try:
                    end_time = datetime.fromisoformat(end_time_str)
                    if end_time.timestamp() < cutoff_time:
                        scans_to_cleanup.append(scan["scan_id"])
                except (ValueError, TypeError):
                    _logger.warning(
                        f"Invalid timestamp format for scan {scan['scan_id']}"
                    )

    from automated_security_helper.core.resource_management.error_handling import (
        ErrorCategory,
    )

    # Clean up each old scan
    cleaned_up_scans = []
    failed_cleanups = []
    already_removed = []

    for scan_id in scans_to_cleanup:
        try:
            result = await cleanup_scan_resources(
                scan_id, remove_output, **_scoped(session_id)
            )
            if result["success"]:
                cleaned_up_scans.append(scan_id)
            elif result.get("error_category") == ErrorCategory.SCAN_NOT_FOUND.value:
                already_removed.append(scan_id)
            else:
                failed_cleanups.append(scan_id)
        except Exception as e:
            _logger.error(f"Error cleaning up scan {scan_id}: {str(e)}")
            failed_cleanups.append(scan_id)

    return {
        "success": len(failed_cleanups) == 0,
        "cleaned_up_count": len(cleaned_up_scans),
        "failed_count": len(failed_cleanups),
        "cleaned_up_scans": cleaned_up_scans,
        "failed_cleanups": failed_cleanups,
        "already_removed": already_removed,
        "message": f"Cleaned up {len(cleaned_up_scans)} old scans, {len(failed_cleanups)} failed",
    }


async def get_scan_statistics(session_id: Optional[str] = None) -> Dict[str, Any]:
    """
    Get statistics about scans.

    Args:
        session_id: When given, count only that session's scans. Unscoped, the
            counts are server-wide, the figure register_scan keeps from other
            sessions.

    Returns:
        Dictionary with scan statistics. The three counts come from one
        registry read, so they agree with each other.
    """
    registry = get_scan_registry()

    return {
        **registry.get_scan_statistics(**_scoped(session_id)),
        "timestamp": datetime.now().isoformat(),
    }


async def check_scan_exists(scan_id: str, session_id: Optional[str] = None) -> bool:
    """
    Check if a scan exists in the registry.

    Args:
        scan_id: ID of the scan to check
        session_id: When given, another session's scan answers False, as every
            session-scoped lookup answers for a scan it does not own.

    Returns:
        True if the scan exists, False otherwise
    """
    registry = get_scan_registry()
    return registry.get_scan(scan_id, **_scoped(session_id)) is not None


async def get_scan_by_directory(
    directory_path: str, session_id: Optional[str] = None
) -> Optional[Dict[str, Any]]:
    """
    Get the scan that occupies a directory.

    Args:
        directory_path: Path to the directory
        session_id: When given, another session's scan answers None; unscoped,
            this returns any session's scan as a full dict, scan id and output
            directory included.

    Returns:
        Scan information dictionary or None if not found
    """
    registry = get_scan_registry()
    entry = registry.get_scan_by_directory(directory_path, **_scoped(session_id))
    if entry:
        return entry.to_dict()
    return None


async def check_scan_progress(
    scan_id: str,
    session_id: Optional[str] = None,
    *,
    name_process_ids: bool = True,
) -> Dict[str, Any]:
    """
    Check the progress of a scan.

    Args:
        scan_id: ID of the scan to check
        session_id: When given, another session's scan is reported exactly as an
            unknown id is.
        name_process_ids: False keeps server process ids out of the response's
            warnings and could_not_stop reasons (``ScanRegistry.check_scan_progress``);
            the caller passes the transport's word, a remote client reading
            False.

    Returns:
        Dictionary with scan progress information, or, on any failure, the
        error response produced by ``create_error_response``. This does not
        raise: the registry method underneath raises, and every raise is caught
        here and converted, so callers should branch on ``success`` rather than
        on an exception.
    """
    from automated_security_helper.core.resource_management.error_handling import (
        validate_scan_id,
        ErrorCategory,
        create_error_response,
    )

    # Validate scan ID
    error = validate_scan_id(scan_id)
    if error:
        return create_error_response(
            error=error,
            operation="check_scan_progress",
            suggestions=[
                "Check that the scan ID is correct",
                "Verify that the scan exists in the registry",
                "Ensure the scan ID format is valid",
            ],
        )

    try:
        registry = get_scan_registry()
        # On a worker thread: the registry reads and parses the aggregated
        # results file, which blocked the event loop for the duration while
        # it ran here.
        return await asyncio.to_thread(
            registry.check_scan_progress,
            scan_id,
            name_process_ids=name_process_ids,
            **_scoped(session_id),
        )
    except MCPResourceError as e:
        # Add operation context to the error
        return create_error_response(error=e, operation="check_scan_progress")
    except Exception as e:
        # Handle unexpected errors
        _logger.error(
            f"Unexpected error checking scan progress for {scan_id}: {str(e)}",
            exc_info=True,
        )
        return create_error_response(
            error=MCPResourceError(
                f"Unexpected error checking scan progress: {str(e)}",
                context={
                    "scan_id": scan_id,
                    "error_category": ErrorCategory.UNEXPECTED_ERROR.value,
                    "error_type": type(e).__name__,
                    "error_message": str(e),
                },
            ),
            operation="check_scan_progress",
        )
