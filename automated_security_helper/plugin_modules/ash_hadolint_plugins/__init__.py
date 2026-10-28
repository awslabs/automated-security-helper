# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from automated_security_helper.plugin_modules.ash_hadolint_plugins.hadolint_scanner import (
    HadolintScanner,
)

# Make plugins discoverable
ASH_SCANNERS = [
    HadolintScanner,
]
ASH_REPORTERS: list[type] = []
