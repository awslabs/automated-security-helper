# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from automated_security_helper.plugin_modules.ash_govulncheck_plugins.govulncheck_scanner import (
    GovulncheckScanner,
)

# Make plugins discoverable
ASH_SCANNERS = [
    GovulncheckScanner,
]
ASH_REPORTERS: list[type] = []
