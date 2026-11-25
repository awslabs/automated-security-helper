# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from automated_security_helper.plugin_modules.ash_bundler_audit_plugins.bundler_audit_scanner import (
    BundlerAuditScanner,
)

# Make plugins discoverable
ASH_SCANNERS = [
    BundlerAuditScanner,
]
ASH_REPORTERS: list[type] = []
