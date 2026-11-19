# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from automated_security_helper.plugin_modules.ash_tflint_plugins.tflint_scanner import (
    TflintScanner,
)

# Make plugins discoverable
ASH_SCANNERS = [
    TflintScanner,
]
ASH_REPORTERS: list[type] = []
