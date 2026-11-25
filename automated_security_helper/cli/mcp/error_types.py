#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The ``error_type`` values the MCP server returns for a refusal it names.

A client branches on ``error_type``, so each value here is a stable wire
spelling: renaming one is a protocol change. The member name is the spelling
upper-cased, except for the few members that were module constants before this
module existed and kept their constant's name.

This module is a leaf: it imports nothing from the package, so every MCP module
can import it without a cycle.

The field itself stays typed ``str``. Several handlers answer an unexpected
failure with the exception's class name (``type(e).__name__``), which is an open
set no enum can close; those sites are the one recorded exception to "every
``error_type`` is a member" (the drift test names them by shape). A writer puts
``McpErrorType.X.value`` in the response, so what travels is a plain ``str``
whatever JSON encoder serializes it. A reader compares against the member
(``(str, Enum)`` members equal their value) or against ``.value``.
"""

from __future__ import annotations

from enum import Enum, unique


@unique
class McpErrorType(str, Enum):
    """A closed ``error_type`` of an MCP tool's refusal.

    ``(str, Enum)`` and not ``StrEnum``: the supported floor is Python 3.10. Use
    ``.value`` wherever the spelling becomes text (a response dict, an f-string,
    a log line); the str/format rendering of a member differs across interpreter
    versions.
    """

    # --- config input refusals (cli/mcp_tools.py) ---
    #: ``error_type`` of every refusal of a config input outside the permitted roots,
    #: whichever tool refused it. The same value ``run_ash_scan`` returns.
    CONFIG_INPUT_NOT_PERMITTED = "config_input_not_permitted"
    #: ``error_type`` for a client-delivered config that sets a field the session's
    #: runtime-override policy denies; see ``config/client_config_policy.py``.
    CONFIG_FIELD_DENIED = "config_field_denied"
    #: ``error_type`` for a client-delivered config whose policy cannot be established.
    CONFIG_POLICY_UNREADABLE = "config_policy_unreadable"
    #: ``error_type`` for a scan refused because the check of the config sources in
    #: its target could not finish (an unreadable entry, a link loop). The config is
    #: not known to be outside the permitted roots, so this is not
    #: ``CONFIG_INPUT_NOT_PERMITTED``.
    CONFIG_CHECK_FAILED = "config_check_failed"
    #: ``error_type`` of the refusal of a config file an MCP client delivered that
    #: reads from the environment, which such a file may not
    #: (``ASHConfigEnvNotResolvedError``).
    CONFIG_ENV_NOT_RESOLVED = "config_env_not_resolved"
    #: ``error_type`` of the refusal of a profile in which a value read from the
    #: environment is part of a longer string, which a session's copy would hold as
    #: the value (``EnvironmentValueInPath``). The message names the key path and the
    #: variable, never the value.
    ENV_VALUE_IN_LONGER_STRING = "environment_value_in_longer_string"
    #: ``error_type`` of the refusal of a config whose ``ash_plugin_modules`` a
    #: scan refuses (a module outside the plugin namespace, or one no installed
    #: package provides). Its own type: the file loaded and parsed, so the
    #: load-failure frame sent a client to re-format a healthy file.
    PLUGIN_MODULE_REFUSED = "plugin_module_refused"
    BOUND_PROFILE_UNAVAILABLE = "bound_profile_unavailable"

    # --- scan target, source and output refusals ---
    SCAN_TARGET_NOT_PERMITTED = "scan_target_not_permitted"
    #: ``error_type`` of a scan refused for its source directory: one that does not
    #: exist, is not a directory, or cannot be entered. The same value
    #: ``run_ash_scan`` returns.
    SOURCE_DIR_NOT_USABLE = "source_dir_not_usable"
    #: ``error_type`` of a scan refused because a file is where its output directory
    #: goes. The same value ``run_ash_scan`` returns.
    OUTPUT_DIR_NOT_USABLE = "output_dir_not_usable"
    OUTPUT_DIR_NOT_PERMITTED = "output_dir_not_permitted"
    COMMITTED_OUTPUT_FILES = "committed_output_files"
    NO_SOURCE_DELIVERED = "no_source_delivered"
    DELIVERED_SOURCE_MISSING = "delivered_source_missing"
    DELIVERED_IMAGE_MISSING = "delivered_image_missing"
    SESSION_SOURCE_MISMATCH = "session_source_mismatch"
    SCAN_START_FAILURE = "scan_start_failure"
    SCAN_NOT_FOUND = "scan_not_found"
    #: The two ``get_scan_results`` answers for a directory that is not there.
    #: The spelling is CamelCase like an exception class name, which is how it
    #: was first written; it is a fixed wire value, not an open class-name arm.
    DIRECTORY_NOT_FOUND = "DirectoryNotFound"

    # --- suggest_suppression and diff_scan_results refusals ---
    #: ``error_type`` of a suggest_suppression refused because no suppression path names
    #: the finding's file alone: its path holds a backslash, a separator in a pattern
    #: (path_matching.literal_path_pattern).
    PATH_NOT_EXPRESSIBLE = "path_not_expressible"
    #: ``error_type`` of a suggest_suppression refused because the finding names no
    #: file or no rule: a suppression built from it would match nothing (an empty
    #: path), or every rule in the file (no rule id), never that finding alone.
    SUPPRESSION_NOT_SPECIFIC = "suppression_not_specific"
    #: ``error_type`` of a suggest_suppression refused for an ``expiration`` that is
    #: not a YYYY-MM-DD date (``models.core.EXPIRATION_RULE``).
    INVALID_EXPIRATION = "invalid_expiration"
    #: ``error_type`` of a diff_scan_results refused because the two results files
    #: cannot be compared (``finding_diff.ComparabilityRefusal``): a sharded or
    #: ``--changed-files-only`` scan, different projects, a workspace mixed with a
    #: standalone scan, or duplicate finding IDs.
    RESULTS_NOT_COMPARABLE = "results_not_comparable"

    # --- session identity and workspace ---
    #: ``error_type`` of the refusal a session-dependent tool returns for
    #: :data:`UNIDENTIFIED_SESSION_ID`.
    SESSION_IDENTITY_REQUIRED = "session_identity_required"
    INVALID_SESSION_ID = "invalid_session_id"
    SESSION_BUSY = "session_busy"
    #: ``error_type`` the MCP tools return for :class:`SessionWorkspaceBusyError`.
    SESSION_WORKSPACE_BUSY = "session_workspace_busy"
    #: ``error_type`` the MCP tools return for :class:`SessionChangeInProgressError`.
    SESSION_CHANGE_IN_PROGRESS = "session_change_in_progress"
    #: ``error_type`` of a scan refused because its session is at the per-session limit.
    SESSION_SCAN_LIMIT = "session_scan_limit"
    #: ``error_type`` every delivery tool returns for :class:`SessionWorkspaceError`.
    SESSION_WORKSPACE_UNAVAILABLE = "session_workspace_unavailable"

    # --- source delivery (set_source_git, set_source_zip_*, clear_source) ---
    #: ``error_type`` the MCP tools return for :class:`SourceDeliveryBusyError`.
    SOURCE_DELIVERY_BUSY = "source_delivery_busy"
    LOCAL_CLONE_SOURCE_REFUSED = "local_clone_source_refused"
    CLONE_REFUSED = "clone_refused"
    #: ``error_type`` the MCP tool returns for :class:`GitTimeoutError`.
    CLONE_TIMED_OUT = "clone_timed_out"
    #: ``error_type`` the MCP tool returns for :class:`CloneTooLargeError`.
    CLONE_TOO_LARGE = "clone_too_large"
    #: ``error_type`` the MCP tool returns for :class:`CloneTreeUnreadableError`.
    CLONE_TREE_UNREADABLE = "clone_tree_unreadable"
    # The ``error_type`` values set_source_git returns, besides the refusal of a
    # local clone source (LOCAL_CLONE_SOURCE_REFUSED above) and invalid_session_id.
    # A client branches on these, so they are stable; the message is for a person.
    CLONE_URL_NOT_PERMITTED = "clone_url_not_permitted"
    CLONE_HOST_NOT_PERMITTED = "clone_host_not_permitted"
    CLONE_REF_NOT_PERMITTED = "clone_ref_not_permitted"
    INVALID_CLONE_DEPTH = "invalid_clone_depth"
    GIT_CLONE_FAILED = "git_clone_failed"
    GIT_CHECKOUT_FAILED = "git_checkout_failed"
    SSH_KEY_NOT_REGISTERED = "ssh_key_not_registered"
