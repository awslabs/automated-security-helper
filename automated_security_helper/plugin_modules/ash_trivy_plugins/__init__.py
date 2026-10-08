# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from automated_security_helper.plugin_modules.ash_trivy_plugins.trivy_repo_scanner import (
    TrivyRepoScanner,
)
from automated_security_helper.plugin_modules.ash_trivy_plugins.trivy_scanner import (
    TrivyScanner,
)

# Make plugins discoverable
ASH_SCANNERS = [
    TrivyRepoScanner,
    TrivyScanner,
]
ASH_REPORTERS: list[type] = []
