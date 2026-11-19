# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from automated_security_helper.plugin_modules.ash_kube_linter_plugins.kube_linter_scanner import (
    KubeLinterScanner,
)

# Make plugins discoverable
ASH_SCANNERS = [
    KubeLinterScanner,
]
ASH_REPORTERS: list[type] = []
