# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from automated_security_helper.plugin_modules.ash_snyk_plugins.snyk_code_scanner import (
    SnykCodeScanner,
)

# Make plugins discoverable
ASH_SCANNERS = [
    SnykCodeScanner,
]
ASH_REPORTERS = []
