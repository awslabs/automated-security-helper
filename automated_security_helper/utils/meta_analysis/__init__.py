# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
# Mapping of scanner names in SARIF reports to their ASH configuration names

"""
Utility function submodule for analyzing SARIF fields across different scanners.

This module provides functions to:
1. Extract field paths from SARIF reports
2. Identify field types and group them by scanner
3. Compare fields between original and aggregated reports
4. Validate that fields from original scanner reports are preserved in aggregated reports
5. Track field presence in aggregate and flat reports
6. Support reporter field mappings
"""

SCANNER_NAME_MAP = {
    "Semgrep OSS": "semgrep",
    "Bandit": "bandit",
    "cfn_nag": "cfn-nag",
    "Checkov": "checkov",
    "Grype": "grype",
    "Syft": "syft",
    "detect-secrets": "detect-secrets",  # pragma: allowlist secret - Not actually a secret
    "npm-audit": "npm-audit",
    "cdk-nag": "cdk-nag",
}
# List of fields expected to change during aggregation
EXPECTED_TRANSFORMATIONS = [
    "ruleIndex",  # Rule array changes during aggregation
    "tool.driver",  # Tool driver information is consolidated
    "invocations",  # Invocation details may change
    "properties.scanner_details",  # Scanner details may be reformatted
    "properties.tags",  # Tags may be consolidated
    "run.tool",  # Tool information is consolidated
    "run.invocations",  # Invocation details may change
    "analysisTarget",  # Analysis target may be normalized
]
