# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from automated_security_helper.plugin_modules.ash_cargo_audit_plugins.cargo_audit_scanner import (
    CargoAuditScanner,
)

# Make plugins discoverable
ASH_SCANNERS = [
    CargoAuditScanner,
]
ASH_REPORTERS: list[type] = []
