# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Unit E1's registrations in the vocabulary drift gate: Severity and SeverityThreshold.

Both are ambiguous short words ("LOW", "ALL", "info"), so both run in POSITIVE
mode: a collection scan over the files this unit cured (a copied ladder is a
tuple, set or rank table of three or more of the values), the inventoried copy
sites pinned as forbidden fragments, and the derived constants pinned to the enum.

Scope notes, kept with the entries because they are the unit boundary:

* ``utils/severity_ladder.py``, ``models/flat_vulnerability.py`` and
  ``models/asharp_model.py`` are not in scope: their tables are re-keyed from the
  enum by the severity-ladder unit (they ride the polars frame files), and the
  gate grows to cover them when that unit lands.
* The reporters and the scanner modules keep their own grade tables until the
  emitter and scanner-sweep units; they join the scope then.
"""

from __future__ import annotations

from automated_security_helper.models import vocab
from automated_security_helper.models.vocab import (
    SEVERITY_BUCKETS,
    SEVERITY_COUNT_FIELDS,
    SEVERITY_THRESHOLD_VALUES,
    SEVERITY_VALUES,
    Severity,
    SeverityThreshold,
)

from ._drift_gate import VocabEntry, register

#: The files unit E1 cured. A file is added here the moment a unit cures it.
E1_SCOPE = (
    "base/options.py",
    "cli/inspect/inspect_findings_app.py",
    "cli/mcp/workspace.py",
    "cli/mcp_tools.py",
    "config/ash_config.py",
    "config/ash_workspace_config.py",
    "core/constants.py",
    "core/metrics_table.py",
    "core/orchestrator.py",
    "core/phases/scanner_executor.py",
    "core/resource_management/error_handling.py",
    "core/resource_management/result_filters.py",
    "core/resource_management/scan_registry.py",
    "core/resource_management/scan_tracking.py",
    "core/scanner_statistics_calculator.py",
    "interactions/run_ash_scan.py",
    "models/scan_results_container.py",
    "plugin_modules/ash_builtin/reporters/junitxml_reporter.py",
    "utils/sarif_utils.py",
    "utils/ui_theme.py",
)


def _is(actual: object, expected: object, what: str) -> None:
    assert actual is expected, f"{what} is not derived from the vocab module"


def _eq(actual: object, expected: object, what: str) -> None:
    assert actual == expected, f"{what}: {actual!r} != {expected!r}"


def _derived_constants() -> None:
    from automated_security_helper.core import constants
    from automated_security_helper.core.phases import scanner_executor
    from automated_security_helper.core.resource_management import (
        error_handling,
        result_filters,
        scan_tracking,
    )
    from automated_security_helper.utils import sarif_utils, ui_theme

    _eq(
        constants.VALID_SEVERITY_VALUES,
        frozenset(m.value for m in Severity),
        "VALID_SEVERITY_VALUES",
    )
    _eq(constants.SHIPPED_SEVERITY_LEVEL, SeverityThreshold.MEDIUM.value, "shipped")
    _is(
        error_handling.VALID_SEVERITY_THRESHOLDS,
        SEVERITY_THRESHOLD_VALUES,
        "VALID_SEVERITY_THRESHOLDS",
    )
    _is(sarif_utils._CANONICAL_SEVERITIES, SEVERITY_VALUES, "_CANONICAL_SEVERITIES")
    _is(ui_theme.SEVERITY_LEVELS, SEVERITY_BUCKETS, "SEVERITY_LEVELS")
    _eq(
        scan_tracking.SEVERITY_BUCKETS,
        SEVERITY_BUCKETS + ("suppressed",),
        "scan_tracking.SEVERITY_BUCKETS",
    )
    _eq(
        result_filters._SEVERITY_KEYS,
        SEVERITY_BUCKETS + ("suppressed",),
        "result_filters._SEVERITY_KEYS",
    )
    _is(
        result_filters._COUNTED_SEVERITY_KEYS,
        SEVERITY_BUCKETS,
        "result_filters._COUNTED_SEVERITY_KEYS",
    )
    _is(
        scanner_executor._SEVERITY_COUNT_FIELDS,
        SEVERITY_COUNT_FIELDS,
        "scanner_executor._SEVERITY_COUNT_FIELDS",
    )


def _derivation_matches_the_count_model() -> None:
    """The derived bucket names are the model's own field names, in its order."""
    from automated_security_helper.models.asharp_model import ScannerSeverityCount

    fields = tuple(ScannerSeverityCount.model_fields)
    _eq(fields[: len(SEVERITY_COUNT_FIELDS)], SEVERITY_COUNT_FIELDS, "count fields")


def _typed_fields_are_the_enum() -> None:
    from automated_security_helper.base.options import ScannerOptionsBase
    from automated_security_helper.config.ash_config import (
        AshConfigGlobalSettingsSection,
    )
    from automated_security_helper.config.ash_workspace_config import (
        WorkspacePolicyConfig,
    )
    from automated_security_helper.models.scan_results_container import (
        ScanResultsContainer,
    )

    import typing

    from automated_security_helper.models.vocab import SeverityThresholdText

    # The static Literal mirrors the enum, member for member and in order.
    _eq(
        typing.get_args(SeverityThresholdText),
        SEVERITY_THRESHOLD_VALUES,
        "SeverityThresholdText",
    )
    for model, field_name in (
        (AshConfigGlobalSettingsSection, "severity_threshold"),
        (WorkspacePolicyConfig, "max_severity_threshold"),
        (ScanResultsContainer, "scanner_severity_threshold"),
        (ScannerOptionsBase, "severity_threshold"),
    ):
        annotation = model.model_fields[field_name].annotation
        spelled = set(typing.get_args(annotation)) - {type(None)}
        assert spelled == {SeverityThresholdText} or spelled == set(
            SEVERITY_THRESHOLD_VALUES
        ), (
            f"{model.__name__}.{field_name} is typed {annotation}, not the shared Literal"
        )


def _vocab_module_imports_nothing_from_the_package() -> None:
    import ast
    import inspect

    tree = ast.parse(inspect.getsource(vocab))
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            assert not (node.module or "").startswith("automated_security_helper")
        if isinstance(node, ast.Import):
            assert not any(
                a.name.startswith("automated_security_helper") for a in node.names
            )


SEVERITY = register(
    VocabEntry(
        name="Severity",
        enum=Severity,
        scope=E1_SCOPE,
        mode="positive",
        min_hits=3,
        forbidden_fragments=(
            ("core/constants.py", '{"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}'),
            ("utils/sarif_utils.py", 'return "CRITICAL"'),
            ("utils/sarif_utils.py", 'severity="MEDIUM"'),
            ("models/scan_results_container.py", '("CRITICAL", counts.critical)'),
            ("interactions/run_ash_scan.py", '("CRITICAL", "HIGH", "MEDIUM"'),
            ("core/phases/scanner_executor.py", '("suppressed", "critical"'),
            ("core/scanner_statistics_calculator.py", '("suppressed", "critical"'),
            ("core/resource_management/result_filters.py", '("critical", "high"'),
            ("utils/ui_theme.py", '("critical", "high"'),
            ("cli/inspect/inspect_findings_app.py", '("critical", "high"'),
            ("cli/inspect/inspect_findings_app.py", '"critical": 0, "high": 1'),
        ),
        derivations={
            "derived constants": _derived_constants,
            "count model fields": _derivation_matches_the_count_model,
            "vocab imports nothing": _vocab_module_imports_nothing_from_the_package,
        },
    )
)

#: The same ladder, spelled the way count buckets and field names spell it.
SEVERITY_BUCKET_NAMES = register(
    VocabEntry(
        name="Severity (lowercase buckets)",
        enum=Severity,
        scope=E1_SCOPE,
        mode="positive",
        min_hits=4,
        values=tuple(SEVERITY_BUCKETS),
        allowlist={
            "interactions/run_ash_scan.py": (
                "the MinSeverity rank table (critical/high/medium/low/none) is the "
                "min-severity family's, keyed by core.enums.MinSeverity in the "
                "status-family unit, and is deliberately not the ladder"
            ),
            "utils/ui_theme.py": (
                "COLORS is the palette dict; its severity keys are color names the "
                "theme looks up through SEVERITY_LEVELS, the derived tuple"
            ),
        },
    )
)

SEVERITY_THRESHOLD = register(
    VocabEntry(
        name="SeverityThreshold",
        enum=SeverityThreshold,
        scope=E1_SCOPE,
        mode="positive",
        min_hits=3,
        forbidden_fragments=(
            ("config/ash_config.py", 'Literal["ALL", "LOW"'),
            ("config/ash_workspace_config.py", 'Literal["ALL", "LOW"'),
            ("base/options.py", 'Literal["ALL", "LOW"'),
            ("models/scan_results_container.py", 'Literal["ALL", "LOW"'),
            ("core/orchestrator.py", 'Literal["ALL", "LOW"'),
            ("core/phases/scanner_executor.py", 'Literal["ALL", "LOW"'),
            (
                "core/resource_management/error_handling.py",
                '("ALL", "LOW", "MEDIUM", "HIGH", "CRITICAL")',
            ),
        ),
        derivations={"typed fields": _typed_fields_are_the_enum},
    )
)
