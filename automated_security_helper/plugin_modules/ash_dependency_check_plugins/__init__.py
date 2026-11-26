# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from automated_security_helper.plugin_modules.ash_dependency_check_plugins.dependency_check_scanner import (
    DependencyCheckScanner,
)

# Make plugins discoverable
ASH_SCANNERS = [
    DependencyCheckScanner,
]
ASH_REPORTERS: list[type] = []
