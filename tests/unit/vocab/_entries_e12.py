# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Unit E12's registrations in the vocabulary drift gate: the scanner-module sweep.

Two vocabularies are distinctive enough inside the scanner modules for the NEGATIVE
mode (an ``ast`` walk flagging any non-docstring string constant equal to a member
value):

* ``Severity``: the ladder words (``CRITICAL`` ... ``INFO``) in a scanner's grade
  tables. A scanner's own severity words stay its own (semgrep's ``INFO`` /
  ``WARNING`` / ``ERROR``, trivy's ``UNKNOWN``, npm's ``moderate``); only the
  ASH-grade side of each table spells members.
* ``ScannerToolType``: the tool-type fallback spellings in the scanners that wrote
  ``or "UNKNOWN"``.

The two ambiguous vocabularies of the sweep do not fit the negative mode and have
their own context-aware scans: ``TargetType`` (``test_target_type_drift.py``, whose
``SCANNER_SCOPE`` scan reads comparisons and ``Literal`` subscripts) and the SARIF
``Level`` words (``test_scanner_sweep_e12.py``).
"""

from __future__ import annotations

from automated_security_helper.core.enums import ScannerToolType
from automated_security_helper.models.vocab import Severity

from ._drift_gate import VocabEntry, register

_SCANNERS = "plugin_modules/ash_builtin/scanners/"

#: Scanner modules whose grade tables are re-keyed from ``Severity``.
E12_GRADE_SCOPE = (
    _SCANNERS + "_grep_scanner_base.py",
    _SCANNERS + "_trivy_scanner_base.py",
    _SCANNERS + "actionlint_scanner.py",
    _SCANNERS + "bandit_scanner.py",
    _SCANNERS + "cfn_guard_scanner.py",
    _SCANNERS + "cfn_lint_scanner.py",
    _SCANNERS + "gitleaks_scanner.py",
    _SCANNERS + "grype_scanner.py",
    _SCANNERS + "npm_audit_scanner.py",
    _SCANNERS + "opengrep_scanner.py",
    _SCANNERS + "zizmor_scanner.py",
    "plugin_modules/ash_betterleaks_plugins/betterleaks_scanner.py",
    "plugin_modules/ash_guarddog_plugins/guarddog_scanner.py",
    "plugin_modules/ash_hadolint_plugins/hadolint_scanner.py",
)

#: Scanner modules whose ``tool_type`` fallback is the enum member.
E12_TOOL_TYPE_SCOPE = (
    _SCANNERS + "cdk_nag_scanner.py",
    _SCANNERS + "detect_secrets_scanner.py",
    _SCANNERS + "npm_audit_scanner.py",
)

SEVERITY_IN_SCANNERS = register(
    VocabEntry(
        name="Severity (scanner grade tables)",
        enum=Severity,
        scope=E12_GRADE_SCOPE,
        mode="negative",
        allowlist={
            _SCANNERS + "_grep_scanner_base.py": (
                "GrepSeverityWord spells semgrep's and opengrep's own --severity "
                "words (INFO, WARNING, ERROR); INFO is the tools' word, not the ladder's"
            ),
        },
    )
)

TOOL_TYPE_IN_SCANNERS = register(
    VocabEntry(
        name="ScannerToolType (scanner fallbacks)",
        enum=ScannerToolType,
        scope=E12_TOOL_TYPE_SCOPE,
        mode="negative",
    )
)
