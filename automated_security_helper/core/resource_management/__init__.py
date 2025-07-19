# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Resource management module for ASH MCP server.

This module provides resource management classes to handle async task tracking,
thread-safe global state management, shared resource management, and graceful
shutdown mechanisms for the MCP server implementation.
"""

from automated_security_helper.core.resource_management.exceptions import (
    MCPResourceError,
    TaskManagementError,
    StateManagementError,
    ResourceExhaustionError,
)
from automated_security_helper.core.resource_management.task_manager import TaskManager
from automated_security_helper.core.resource_management.state_manager import (
    StateManager,
)
from automated_security_helper.core.resource_management.resource_manager import (
    ResourceManager,
)
from automated_security_helper.core.resource_management.event_manager import (
    EventSubscriptionManager,
    EventSubscriptionContextManager,
    EventSubscription,
)
from automated_security_helper.core.resource_management.shutdown_manager import (
    ShutdownManager,
)
from automated_security_helper.core.resource_management.monitoring import (
    ResourceMonitor,
    HealthStatus,
    AlertLevel,
    HealthCheckResult,
    ResourceMetrics,
    AlertThresholds,
    Alert,
)
from automated_security_helper.core.resource_management.scan_tracking import (
    check_scan_completion,
    find_scanner_result_files,
    get_completed_scanners,
    get_scanner_progress,
    parse_scanner_result_file,
    parse_aggregated_results,
    get_scan_progress_info,
    extract_findings_summary,
    validate_output_directory,
)
from automated_security_helper.core.resource_management.scan_registry import (
    ScanRegistry,
    ScanRegistryEntry,
    ScanStatus,
    get_scan_registry,
)
from automated_security_helper.core.resource_management.scan_management import (
    list_active_scans,
    list_all_scans,
    cancel_scan,
    cleanup_scan_resources,
    cleanup_old_scans,
    get_scan_statistics,
    check_scan_exists,
    get_scan_by_directory,
    check_scan_progress,
)

__all__ = [
    "MCPResourceError",
    "TaskManagementError",
    "StateManagementError",
    "ResourceExhaustionError",
    "TaskManager",
    "StateManager",
    "ResourceManager",
    "EventSubscriptionManager",
    "EventSubscriptionContextManager",
    "EventSubscription",
    "ShutdownManager",
    "ResourceMonitor",
    "HealthStatus",
    "AlertLevel",
    "HealthCheckResult",
    "ResourceMetrics",
    "AlertThresholds",
    "Alert",
    # Scan tracking utilities
    "check_scan_completion",
    "find_scanner_result_files",
    "get_completed_scanners",
    "get_scanner_progress",
    "parse_scanner_result_file",
    "parse_aggregated_results",
    "get_scan_progress_info",
    "extract_findings_summary",
    "validate_output_directory",
    # Scan registry components
    "ScanRegistry",
    "ScanRegistryEntry",
    "ScanStatus",
    "get_scan_registry",
    # Scan management functions
    "list_active_scans",
    "list_all_scans",
    "cancel_scan",
    "cleanup_scan_resources",
    "cleanup_old_scans",
    "get_scan_statistics",
    "check_scan_exists",
    "get_scan_by_directory",
    "check_scan_progress",
]
