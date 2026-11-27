# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The strings ASH uses to identify itself inside the reports it writes.

Each value is defined once here and imported by the writers and comparisons that
need it. Several readers decide whether a finding is ASH's own by comparing
a SARIF driver name with ``SARIF_DRIVER_NAME``, so a copy of the literal that
drifts from this module changes which findings are attributed to ASH without
raising an error. ``tests/unit/test_report_identity_strings.py`` fails when a
literal copy returns to one of the nine modules it lists.

This module sits in the contract layer (``base``) and imports nothing, so models,
utils, reporters and workspace code can all import it without creating an import
cycle or an edge the layer order forbids. The values are the exact strings
earlier releases wrote; changing one changes report output.
"""

#: ASFF ``ProductName`` (also re-exported as ``PRODUCT_NAME`` by asff_formatter).
ASFF_PRODUCT_NAME = "Automated Security Helper"

#: SARIF ``tool.driver.name`` for ASH's own aggregated report. Readers compare a
#: driver's name with this value to tell ASH findings from scanner findings.
SARIF_DRIVER_NAME = "AWS Labs - Automated Security Helper"

#: ``tool.driver.name`` in the SARIF the GitHub code-scanning reporter writes.
GHAS_DRIVER_NAME = "ASH - Automated Security Helper"

#: GitLab SAST ``scan.analyzer.name``.
GITLAB_ANALYZER_NAME = "Automated Security Helper (ASH)"

#: GitLab SAST ``scan.scanner.name``.
GITLAB_SCANNER_NAME = "Automated Security Helper"

#: OCSF product name (``metadata.product.name`` and the matching scan record).
OCSF_PRODUCT_NAME = "Automated Security Helper"

#: Default ``description`` of the aggregated report model.
AGGREGATED_REPORT_NAME = "Automated Security Helper - Aggregated Report"

#: Description of the aggregated report's SARIF post-processor.
AGGREGATED_REPORT_POST_PROCESSOR_DESCRIPTION = (
    "Automated Security Helper Aggregated Report Post-processor"
)

#: ``metadata.description`` of a workspace-mode aggregated report.
WORKSPACE_REPORT_METADATA_DESCRIPTION = (
    "Automated Security Helper workspace-mode aggregated report"
)

#: Opening words of a workspace-mode aggregated report's ``description``.
WORKSPACE_REPORT_DESCRIPTION_LEAD = (
    "Automated Security Helper - aggregated workspace report. One "
)
