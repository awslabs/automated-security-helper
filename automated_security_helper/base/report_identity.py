# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The names and descriptions ASH writes to identify itself in its reports.

Each value is defined once here and imported by the writers and comparisons that
need it. Several readers decide whether a finding is ASH's own by comparing
a SARIF driver name with ``SARIF_DRIVER_NAME``, so a copy of the literal that
drifts from this module changes which findings are attributed to ASH without
raising an error.

``tests/unit/test_report_identity_strings.py`` reads every Python module of the
package except this one and fails when one of them holds a whole-string literal
equal to the SARIF driver name, the GitHub code-scanning driver name, the GitLab
analyzer name, the aggregated report's description or post-processor description,
or the two workspace report descriptions. The generic product names
(``ASFF_PRODUCT_NAME``, ``GITLAB_SCANNER_NAME``, ``OCSF_PRODUCT_NAME``) and
``AGGREGATED_REPORT_NAME`` are not searched for, because the same words can
appear in unrelated text; the test checks only that the nine modules it lists
import the constants they use.

This module covers names and descriptions only. It does not cover the
``organization`` or vendor fields, the tool URLs, or any other identity field the
same writers produce.

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

#: Default ``name`` of the aggregated report model.
AGGREGATED_REPORT_NAME = "ASH Scan Report"

#: Default ``description`` of the aggregated report model.
AGGREGATED_REPORT_DESCRIPTION = "Automated Security Helper - Aggregated Report"

#: Description of the aggregated report's SARIF post-processor.
AGGREGATED_REPORT_POST_PROCESSOR_DESCRIPTION = (
    "Automated Security Helper Aggregated Report Post-processor"
)

#: ``metadata.description`` of a workspace-mode aggregated report.
WORKSPACE_REPORT_METADATA_DESCRIPTION = (
    "Automated Security Helper workspace-mode aggregated report"
)

#: ``description`` of a workspace-mode aggregated report.
WORKSPACE_REPORT_DESCRIPTION = (
    "Automated Security Helper - aggregated workspace report. One "
    "SARIF run per project; see the 'workspace' block for "
    "attribution and per-project verdicts."
)
