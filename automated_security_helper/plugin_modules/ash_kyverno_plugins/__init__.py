# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from automated_security_helper.plugin_modules.ash_kyverno_plugins.kyverno_scanner import (
    KyvernoScanner,
)

# Make plugins discoverable
ASH_SCANNERS = [
    KyvernoScanner,
]
ASH_REPORTERS: list[type] = []
