# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from automated_security_helper.plugin_modules.ash_agent_scan_plugins.agent_scan_scanner import (
    AgentScanScanner,
)

# Make plugins discoverable
ASH_SCANNERS = [
    AgentScanScanner,
]
ASH_REPORTERS: list[type] = []
