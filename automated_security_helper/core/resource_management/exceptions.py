# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Exception classes for MCP resource management.

This module defines the exception hierarchy for resource management operations
in the ASH MCP server implementation.
"""


class MCPResourceError(Exception):
    """Base exception for MCP resource management errors."""

    def __init__(self, message: str, context: dict | None = None):
        super().__init__(message)
        self.context = context or {}


class TaskManagementError(MCPResourceError):
    """Exception for task management failures."""

    pass


class StateManagementError(MCPResourceError):
    """Exception for state management failures."""

    pass


class ResourceExhaustionError(MCPResourceError):
    """Exception for resource exhaustion conditions."""

    pass
