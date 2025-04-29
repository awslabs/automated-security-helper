# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Example external plugin package for ASH."""

from automated_security_helper.plugins.events import AshEventType
from automated_security_helper.plugins.decorators import event_subscriber

from .converter import ExampleConverter
from .scanner import ExampleScanner
from .reporter import ExampleReporter

# Make plugins discoverable
ASH_CONVERTERS = [ExampleConverter]
ASH_SCANNERS = [ExampleScanner]
ASH_REPORTERS = [ExampleReporter]


# Register event handlers
@event_subscriber(AshEventType.SCAN_COMPLETE)
def handle_scan_complete(results, plugin_context, **kwargs):
    """Example event handler for scan complete event."""
    print(
        f"Example plugin received scan complete event with {len(results) if results else 0} results"
    )
    return True
