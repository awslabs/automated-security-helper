# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from automated_security_helper.plugin_modules.ash_malcontent_plugins.malcontent_scanner import (
    MalcontentScanner,
)

# Make plugins discoverable
ASH_SCANNERS = [
    MalcontentScanner,
]
ASH_REPORTERS: list[type] = []
