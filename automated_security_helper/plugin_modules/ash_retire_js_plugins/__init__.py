# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from automated_security_helper.plugin_modules.ash_retire_js_plugins.retire_js_scanner import (
    RetireJsScanner,
)

# Make plugins discoverable
ASH_SCANNERS = [
    RetireJsScanner,
]
ASH_REPORTERS: list[type] = []
