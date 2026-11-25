# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from automated_security_helper.plugin_modules.ash_cppcheck_plugins.cppcheck_scanner import (
    CppcheckScanner,
)

# Make plugins discoverable
ASH_SCANNERS = [
    CppcheckScanner,
]
ASH_REPORTERS: list[type] = []
