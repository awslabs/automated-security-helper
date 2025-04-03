# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
from automated_security_helper.models.config import (
    ASHConfig,
    BuildConfig,
    SASTScannerConfig,
    SBOMScannerConfig,
)
from automated_security_helper.models.scanner_types import (
    BanditScanner,
    CdkNagPacks,
    CdkNagScannerOptions,
    CfnNagScanner,
    CheckovScanner,
    GitSecretsScanner,
    NpmAuditScanner,
    SemgrepScanner,
    CdkNagScanner,
    GrypeScanner,
    SyftScanner,
)


DEFAULT_ASH_CONFIG = ASHConfig(
    project_name="automated-security-helper",
    output_dir="ash_output",
    fail_on_findings=True,
    ignore_paths=["tests/**"],
    build=BuildConfig(),
    sast=SASTScannerConfig(
        output_formats=["json", "csv", "junitxml", "html"],
        scanners=[
            BanditScanner(),
            CdkNagScanner(
                cdknag=CdkNagScannerOptions(
                    enabled=True,
                    nag_packs=CdkNagPacks(
                        AwsSolutionsChecks=True,
                        HIPAASecurityChecks=False,
                        NIST80053R4Checks=False,
                        NIST80053R5Checks=False,
                        PCIDSS321Checks=False,
                    ),
                ),
            ),
            CfnNagScanner(),
            CheckovScanner(),
            GitSecretsScanner(),
            GrypeScanner(),
            NpmAuditScanner(),
            SemgrepScanner(),
        ],
    ),
    sbom=SBOMScannerConfig(
        output_formats=["cyclonedx", "html"],
        scanners=[
            SyftScanner(),
        ],
    ),
)
