# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Event subscribers for ASH."""

# Import all event subscribers to ensure they are registered
from automated_security_helper.events.scan_completion_logger import (
    handle_scan_completion_logging,
)
from automated_security_helper.plugins.events import AshEventType

# Event callback registry following the same pattern as ASH_SCANNERS, ASH_REPORTERS, etc.
ASH_EVENT_CALLBACKS = {
    AshEventType.SCAN_COMPLETE: [
        handle_scan_completion_logging,
    ],
}
