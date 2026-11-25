# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from automated_security_helper.plugin_modules.ash_bearer_plugins.bearer_scanner import (
    BearerScanner,
)

# Make plugins discoverable
ASH_SCANNERS = [
    BearerScanner,
]
ASH_REPORTERS: list[type] = []
