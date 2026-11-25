# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from automated_security_helper.plugin_modules.ash_dotnet_vulnerable_plugins.dotnet_vulnerable_scanner import (
    DotnetVulnerableScanner,
)

# Make plugins discoverable
ASH_SCANNERS = [
    DotnetVulnerableScanner,
]
ASH_REPORTERS: list[type] = []
