# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from automated_security_helper.scanners.ash_default import (
    BanditScanner,
    CdkNagScanner,
    CfnNagScanner,
    CheckovScanner,
    DetectSecretsScanner,
    GrypeScanner,
    SyftScanner,
    OpengrepScanner,
)
from automated_security_helper.scanners.ash_default.npm_audit_scanner import (
    NpmAuditScanner,
)
from automated_security_helper.scanners.ash_default.semgrep_scanner import (
    SemgrepScanner,
)

# Make plugins discoverable
ASH_SCANNERS = [
    BanditScanner,
    CdkNagScanner,
    CfnNagScanner,
    CheckovScanner,
    DetectSecretsScanner,
    GrypeScanner,
    NpmAuditScanner,
    OpengrepScanner,
    SemgrepScanner,
    SyftScanner,
]
