# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from automated_security_helper.plugin_modules.ash_cdxgen_plugins.cdxgen_scanner import (
    CdxgenScanner,
)

# Make plugins discoverable
ASH_SCANNERS = [
    CdxgenScanner,
]
ASH_REPORTERS: list[type] = []
