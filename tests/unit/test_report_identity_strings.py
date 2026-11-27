# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Each report identity string is defined once and the nine modules listed here read it.

Readers decide whether a finding is ASH's own by comparing a SARIF driver name
with the shared constant, so a literal copy that drifts misattributes findings
without raising an error. These tests pin the values the reports carry today and
fail when one of the nine listed modules goes back to a literal. They read only
those nine modules; a module not in ``SITES`` is not checked.
"""

import ast
from pathlib import Path
from typing import Dict, List

import pytest

import automated_security_helper
from automated_security_helper.base import report_identity

pytestmark = pytest.mark.unit

PACKAGE_ROOT = Path(automated_security_helper.__file__).resolve().parent

# The values earlier releases wrote. Changing one changes report output.
EXPECTED_VALUES: Dict[str, str] = {
    "ASFF_PRODUCT_NAME": "Automated Security Helper",
    "SARIF_DRIVER_NAME": "AWS Labs - Automated Security Helper",
    "GHAS_DRIVER_NAME": "ASH - Automated Security Helper",
    "GITLAB_ANALYZER_NAME": "Automated Security Helper (ASH)",
    "GITLAB_SCANNER_NAME": "Automated Security Helper",
    "OCSF_PRODUCT_NAME": "Automated Security Helper",
    "AGGREGATED_REPORT_NAME": "Automated Security Helper - Aggregated Report",
    "AGGREGATED_REPORT_POST_PROCESSOR_DESCRIPTION": (
        "Automated Security Helper Aggregated Report Post-processor"
    ),
    "WORKSPACE_REPORT_METADATA_DESCRIPTION": (
        "Automated Security Helper workspace-mode aggregated report"
    ),
    "WORKSPACE_REPORT_DESCRIPTION_LEAD": (
        "Automated Security Helper - aggregated workspace report. One "
    ),
}

# Module (relative to the package) -> constants it must import from report_identity.
SITES: Dict[str, List[str]] = {
    "models/asharp_model.py": [
        "AGGREGATED_REPORT_NAME",
        "AGGREGATED_REPORT_POST_PROCESSOR_DESCRIPTION",
        "SARIF_DRIVER_NAME",
    ],
    "models/flat_vulnerability.py": ["SARIF_DRIVER_NAME"],
    "utils/occurrence_context.py": ["SARIF_DRIVER_NAME"],
    "plugin_modules/ash_builtin/reporters/sarif_reporter.py": ["SARIF_DRIVER_NAME"],
    "plugin_modules/ash_builtin/reporters/github_ghas_reporter.py": [
        "GHAS_DRIVER_NAME"
    ],
    "plugin_modules/ash_builtin/reporters/gitlab_sast_reporter.py": [
        "GITLAB_ANALYZER_NAME",
        "GITLAB_SCANNER_NAME",
    ],
    "plugin_modules/ash_builtin/reporters/ocsf_reporter.py": ["OCSF_PRODUCT_NAME"],
    "plugin_modules/ash_builtin/reporters/asff_formatter.py": ["ASFF_PRODUCT_NAME"],
    "workspace/aggregation.py": [
        "WORKSPACE_REPORT_DESCRIPTION_LEAD",
        "WORKSPACE_REPORT_METADATA_DESCRIPTION",
    ],
}


def _literal_copies(source: str, values: List[str]) -> List[str]:
    """Identity values that appear as a whole string literal in ``source``."""
    found = []
    for node in ast.walk(ast.parse(source)):
        if (
            isinstance(node, ast.Constant)
            and isinstance(node.value, str)
            and node.value in values
        ):
            found.append(node.value)
    return found


def _imported_names(source: str) -> set:
    names = set()
    for node in ast.walk(ast.parse(source)):
        if (
            isinstance(node, ast.ImportFrom)
            and node.module == "automated_security_helper.base.report_identity"
        ):
            names.update(alias.name for alias in node.names)
    return names


def test_values_are_the_ones_reports_carry_today():
    for name, expected in EXPECTED_VALUES.items():
        assert getattr(report_identity, name) == expected, name


def test_the_module_defines_nothing_the_test_does_not_pin():
    defined = {
        name
        for name, value in vars(report_identity).items()
        if name.isupper() and isinstance(value, str)
    }
    assert defined == set(EXPECTED_VALUES)


@pytest.mark.parametrize("relative_path", sorted(SITES))
def test_site_imports_its_constants_and_holds_no_literal_copy(relative_path):
    source = (PACKAGE_ROOT / relative_path).read_text(encoding="utf-8")
    imported = _imported_names(source)
    for name in SITES[relative_path]:
        assert name in imported, f"{relative_path} does not import {name}"
    copies = _literal_copies(source, list(EXPECTED_VALUES.values()))
    assert copies == [], f"{relative_path} holds literal copies of {copies}"


def test_sites_read_the_shared_objects():
    from automated_security_helper.models import flat_vulnerability
    from automated_security_helper.plugin_modules.ash_builtin.reporters import (
        asff_formatter,
    )
    from automated_security_helper.utils import occurrence_context

    assert (
        flat_vulnerability._GENERIC_ASH_TOOL_NAME is report_identity.SARIF_DRIVER_NAME
    )
    assert (
        occurrence_context._GENERIC_ASH_TOOL_NAME is report_identity.SARIF_DRIVER_NAME
    )
    assert asff_formatter.PRODUCT_NAME is report_identity.ASFF_PRODUCT_NAME


def test_literal_copy_detector_flags_a_planted_copy_and_passes_a_clean_module():
    values = list(EXPECTED_VALUES.values())
    planted = 'driver = {"name": "AWS Labs - Automated Security Helper"}\n'
    clean = (
        "from automated_security_helper.base.report_identity import SARIF_DRIVER_NAME\n"
        'driver = {"name": SARIF_DRIVER_NAME}\n'
    )
    assert _literal_copies(planted, values) == ["AWS Labs - Automated Security Helper"]
    assert _literal_copies(clean, values) == []
    assert _imported_names(clean) == {"SARIF_DRIVER_NAME"}
    assert _imported_names(planted) == set()
