# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from automated_security_helper.plugin_modules.ash_pip_audit_plugins.pip_audit_scanner import (
    PipAuditScanner,
)

# Make plugins discoverable
ASH_SCANNERS = [
    PipAuditScanner,
]
ASH_REPORTERS: list[type] = []
