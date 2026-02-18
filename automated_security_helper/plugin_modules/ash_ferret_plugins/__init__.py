# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from automated_security_helper.plugin_modules.ash_ferret_plugins.ferret_scanner import (
    FerretScanScanner,
)

# Make plugins discoverable
ASH_SCANNERS = [
    FerretScanScanner,
]
ASH_REPORTERS = []
