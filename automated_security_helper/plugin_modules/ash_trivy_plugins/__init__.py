# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from automated_security_helper.plugin_modules.ash_trivy_plugins.trivy_repo_scanner import (
    TrivyRepoScanner,
)

# Make plugins discoverable
ASH_SCANNERS = [
    TrivyRepoScanner,
]
ASH_REPORTERS = []
