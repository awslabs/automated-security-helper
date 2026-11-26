# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from automated_security_helper.plugin_modules.ash_composer_audit_plugins.composer_audit_scanner import (
    ComposerAuditScanner,
)

# Make plugins discoverable
ASH_SCANNERS = [
    ComposerAuditScanner,
]
ASH_REPORTERS: list[type] = []
