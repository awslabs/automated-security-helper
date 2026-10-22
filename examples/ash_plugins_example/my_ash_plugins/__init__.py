# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Example external plugin package for ASH.

Importing this package registers its plugins: each class carries an
``@ash_converter_plugin``, ``@ash_scanner_plugin`` or ``@ash_reporter_plugin``
decorator, and ASH imports the package when ``ash_plugin_modules`` names it.
"""

from automated_security_helper.plugins.events import AshEventType

from my_ash_plugins.converter import ExampleConverter
from my_ash_plugins.scanner import ExampleScanner
from my_ash_plugins.reporter import ExampleReporter


def handle_scan_start(**kwargs):
    """Called as each scanner starts."""
    print(f"Example plugin: scanner '{kwargs.get('scanner')}' started")
    return True


def handle_scan_complete(**kwargs):
    """Called as each scanner finishes."""
    scanner = kwargs.get("scanner", "Unknown")
    remaining_count = kwargs.get("remaining_count", 0)
    remaining_scanners = kwargs.get("remaining_scanners", [])

    print(f"Example plugin: scanner '{scanner}' completed")
    if remaining_count > 0:
        print(
            f"Example plugin: {remaining_count} scanners remaining: {', '.join(remaining_scanners)}"
        )
    else:
        print("Example plugin: all scanners completed")

    return True


# The plugins this package declares. The decorators do the registering; the loader
# reads these lists only to report what each package provided.
ASH_CONVERTERS = [ExampleConverter]
ASH_SCANNERS = [ExampleScanner]
ASH_REPORTERS = [ExampleReporter]

# Event handlers, registered when ASH loads the package.
ASH_EVENT_HANDLERS = {
    AshEventType.SCAN_START: [handle_scan_start],
    AshEventType.SCAN_COMPLETE: [handle_scan_complete],
}
