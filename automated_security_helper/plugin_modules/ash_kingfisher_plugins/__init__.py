# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from automated_security_helper.plugin_modules.ash_kingfisher_plugins.kingfisher_scanner import (
    KingfisherScanner,
)

# Make plugins discoverable
ASH_SCANNERS = [
    KingfisherScanner,
]
ASH_REPORTERS: list[type] = []
