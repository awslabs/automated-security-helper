# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Example external plugin package for ASH."""

from automated_security_helper.plugins.events import AshEventType

from my_ash_plugins.converter import ExampleConverter
from my_ash_plugins.scanner import ExampleScanner
from my_ash_plugins.reporter import ExampleReporter


def handle_scan_complete(**kwargs):
    """Example event handler for scan complete event."""
    scanner = kwargs.get("scanner", "Unknown")
    remaining_count = kwargs.get("remaining_count", 0)
    remaining_scanners = kwargs.get("remaining_scanners", [])

    print(f"Example plugin: Scanner '{scanner}' completed!")
    if remaining_count > 0:
        print(
            f"Example plugin: {remaining_count} scanners remaining: {', '.join(remaining_scanners)}"
        )
    else:
        print("Example plugin: All scanners completed!")

    return True


def handle_scan_start(**kwargs):
    """Example event handler for scan start event."""
    print("Example plugin: Scan phase started!")
    return True


# Make plugins discoverable
ASH_CONVERTERS = [ExampleConverter]
ASH_SCANNERS = [ExampleScanner]
ASH_REPORTERS = [ExampleReporter]

# Event callback registry following the same pattern as ASH_SCANNERS, ASH_REPORTERS, etc.
ASH_EVENT_HANDLERS = {
    AshEventType.SCAN_COMPLETE: [handle_scan_complete],
    AshEventType.SCAN_START: [handle_scan_start],
}
