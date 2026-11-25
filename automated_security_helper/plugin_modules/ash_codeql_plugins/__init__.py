# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from automated_security_helper.plugin_modules.ash_codeql_plugins.codeql_scanner import (
    CodeqlScanner,
)

# Make plugins discoverable
ASH_SCANNERS = [
    CodeqlScanner,
]
ASH_REPORTERS: list[type] = []
