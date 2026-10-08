# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from automated_security_helper.plugin_modules.ash_cfn_plugins.cfn_guard_scanner import (
    CfnGuardScanner,
)
from automated_security_helper.plugin_modules.ash_cfn_plugins.cfn_lint_scanner import (
    CfnLintScanner,
)

# Make plugins discoverable
ASH_SCANNERS = [
    CfnGuardScanner,
    CfnLintScanner,
]
ASH_REPORTERS: list[type] = []
