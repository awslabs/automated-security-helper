# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The scanner-module sweep: grade tables, SARIF levels and shared option types.

What the sweep changed, and what each test pins:

* The ASH-grade side of every scanner's grade table is spelled from ``Severity``
  members, and the SARIF-level side from ``Level`` members. The wire spellings do
  not move, so each table is pinned to its literal wire form here (a test file may
  spell the words; the scanner modules may not).
* The tool-native side of a table stays tool-native: zizmor's ``informational``,
  npm's ``moderate``, hadolint's ``style``, trivy's ``UNKNOWN``, semgrep's
  ``WARNING``. Nothing here asserts those are ladder words.
* The "one band lower" map in zizmor is derived from the member order.
* bandit's confidence option is a ``Literal`` of bandit's own choices, and the
  semgrep and opengrep option types that were spelled twice are one alias each.
* A SARIF-level spelling scan reads context, because ``"error"`` and ``"none"`` are
  ordinary words in a scanner module (a response's ``error`` key, a stdout
  preference).

The ``Severity`` and ``ScannerToolType`` spellings are gated by the shared drift
gate (``_entries_e12``); ``TargetType`` by ``test_target_type_drift``.
"""

from __future__ import annotations

import ast
import json
from pathlib import Path
from typing import get_args

import pytest
from pydantic import ValidationError

from automated_security_helper.core.enums import ScannerToolType
from automated_security_helper.models.vocab import (
    SEVERITY_VALUES,
    Severity,
    SeverityThresholdText,
)
from automated_security_helper.schemas.sarif_schema_model import Level

pytestmark = pytest.mark.unit

PKG = Path(__file__).resolve().parents[3] / "automated_security_helper"
LEVEL_WORDS = frozenset(m.value for m in Level)

_SCANNERS = "plugin_modules/ash_builtin/scanners/"

#: Scanner modules whose SARIF-level words are spelled from ``Level``.
LEVEL_SCOPE = (
    _SCANNERS + "_trivy_scanner_base.py",
    _SCANNERS + "actionlint_scanner.py",
    _SCANNERS + "cfn_guard_scanner.py",
    _SCANNERS + "cfn_lint_scanner.py",
    _SCANNERS + "npm_audit_scanner.py",
    _SCANNERS + "zizmor_scanner.py",
    "plugin_modules/ash_guarddog_plugins/guarddog_scanner.py",
    "plugin_modules/ash_hadolint_plugins/hadolint_scanner.py",
)

#: ``path -> reason`` for files that may spell a level word.
LEVEL_ALLOWLIST: dict[str, str] = {
    "plugin_modules/ash_hadolint_plugins/hadolint_scanner.py": (
        "hadolint's own level words (error, warning, info, style) are the tool's "
        "side of its map and two of them read like SARIF's; the SARIF side of "
        "each table is pinned below instead"
    ),
}


def level_spellings(source: str) -> list[int]:
    """Lines where a SARIF level word is spelled as text in a level context.

    A level context is a dict value, the default of a two-argument ``.get``, the
    value assigned to a name that says LEVEL, an ``x or "<level>"`` fallback or a
    comparison against an expression that mentions ``level``. Other constants equal
    to a level word (a response's ``"error"`` key, a stdout preference) are not
    levels and are not read.
    """
    tree = ast.parse(source)
    lines: set[int] = set()

    def is_level_text(node: ast.AST) -> bool:
        return (
            isinstance(node, ast.Constant)
            and isinstance(node.value, str)
            and node.value in LEVEL_WORDS
        )

    for node in ast.walk(tree):
        if isinstance(node, ast.Dict):
            for value in node.values:
                members = value.elts if isinstance(value, ast.Tuple) else [value]
                lines.update(m.lineno for m in members if is_level_text(m))
        elif isinstance(node, ast.Call):
            func = node.func
            if (
                isinstance(func, ast.Attribute)
                and func.attr == "get"
                and len(node.args) == 2
                and is_level_text(node.args[1])
            ):
                lines.add(node.args[1].lineno)
        elif isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            names = " ".join(ast.unparse(t) for t in targets).lower()
            if (
                "level" in names
                and node.value is not None
                and is_level_text(node.value)
            ):
                lines.add(node.value.lineno)
        elif isinstance(node, ast.BoolOp) and isinstance(node.op, ast.Or):
            texts = [v for v in node.values if is_level_text(v)]
            others = [v for v in node.values if not is_level_text(v)]
            if texts and any("level" in ast.unparse(o).lower() for o in others):
                lines.update(t.lineno for t in texts)
        elif isinstance(node, ast.Compare):
            operands = [node.left, *node.comparators]
            texts = [o for o in operands if is_level_text(o)]
            others = [o for o in operands if not is_level_text(o)]
            if texts and any("level" in ast.unparse(o).lower() for o in others):
                lines.update(t.lineno for t in texts)
    return sorted(lines)


@pytest.mark.parametrize("rel", LEVEL_SCOPE)
def test_no_scanner_table_spells_a_sarif_level_as_text(rel):
    if rel in LEVEL_ALLOWLIST:
        pytest.skip(LEVEL_ALLOWLIST[rel])
    assert (PKG / rel).is_file()
    lines = level_spellings((PKG / rel).read_text(encoding="utf-8"))
    assert lines == [], f"{rel} spells a SARIF level at lines {lines}"


def test_the_level_scan_flags_each_planted_shape_and_ignores_other_words():
    planted = (
        'TABLE = {"HIGH": "error"}\n'  # 1: a dict value
        'PAIR = {"E": ("MEDIUM", "warning")}\n'  # 2: a tuple in a dict value
        'lvl = LEVELS.get(sev, "warning")\n'  # 3: .get default
        'VIOLATION_LEVEL = "error"\n'  # 4: a LEVEL name
        'shown = result.level or "error"\n'  # 5: an or fallback
        'same = sarif_level == "note"\n'  # 6: a comparison with a level
    )
    assert level_spellings(planted) == [1, 2, 3, 4, 5, 6]
    clean = (
        'ok = response.get("error")\n'
        'bad = "error" in response\n'
        'stdout_preference = "none"\n'
        'message = f"could not be run: {response.get(' + "'error'" + ')}"\n'
        "TABLE = {Severity.HIGH.value: Level.error.value}\n"
        "same = sarif_level == Level.note.value\n"
    )
    assert level_spellings(clean) == []


# --- the grade tables keep their wire form ----------------------------------------


def test_every_ash_grade_a_scanner_table_hands_out_is_on_the_ladder():
    from automated_security_helper.plugin_modules.ash_builtin.scanners import (
        _trivy_scanner_base as trivy,
        actionlint_scanner as actionlint,
        npm_audit_scanner as npm,
        zizmor_scanner as zizmor,
    )
    from automated_security_helper.plugin_modules.ash_guarddog_plugins import (
        guarddog_scanner as guarddog,
    )
    from automated_security_helper.plugin_modules.ash_hadolint_plugins import (
        hadolint_scanner as hadolint,
    )

    ladder = set(SEVERITY_VALUES)
    grades = {
        "zizmor base": set(zizmor._BASE_SEVERITY.values()),
        "zizmor one band": set(zizmor._ONE_BAND_LOWER)
        | set(zizmor._ONE_BAND_LOWER.values()),
        "zizmor level": set(zizmor._LEVEL_TO_SEVERITY.values()),
        "zizmor to level": set(zizmor._SEVERITY_TO_LEVEL),
        "actionlint kinds": set(actionlint.KIND_SEVERITY.values())
        | {actionlint.UNKNOWN_KIND_SEVERITY},
        "actionlint to level": set(actionlint._SEVERITY_TO_LEVEL),
        "npm grade": set(npm._SEVERITY_GRADE.values()),
        "hadolint": {grade for grade, _ in hadolint.HADOLINT_LEVEL_MAP.values()},
        "guarddog": set(guarddog._SEVERITY_LEVELS),
        "trivy": set(trivy.TRIVY_SEVERITIES) | set(trivy._SARIF_LEVEL),
    }
    for name, values in grades.items():
        assert values <= ladder, (
            f"{name}: {sorted(values - ladder)} are not ladder words"
        )
        assert all(type(v) is str for v in values), f"{name} holds a non-text member"


def test_zizmor_tables_keep_their_wire_pairs():
    from automated_security_helper.plugin_modules.ash_builtin.scanners import (
        zizmor_scanner as zizmor,
    )

    assert zizmor._BASE_SEVERITY == {
        "high": "HIGH",
        "medium": "MEDIUM",
        "low": "LOW",
        "informational": "INFO",
    }
    assert zizmor._ONE_BAND_LOWER == {
        "CRITICAL": "HIGH",
        "HIGH": "MEDIUM",
        "MEDIUM": "LOW",
        "LOW": "INFO",
        "INFO": "INFO",
    }
    assert zizmor._LEVEL_TO_SEVERITY == {
        "error": "HIGH",
        "warning": "MEDIUM",
        "note": "LOW",
        "none": "INFO",
    }
    assert zizmor._SEVERITY_TO_LEVEL == {
        "CRITICAL": Level.error,
        "HIGH": Level.error,
        "MEDIUM": Level.warning,
        "LOW": Level.note,
        "INFO": Level.none,
    }


def test_zizmor_one_band_lower_follows_the_ladder_order():
    from automated_security_helper.plugin_modules.ash_builtin.scanners import (
        zizmor_scanner as zizmor,
    )

    members = list(Severity)
    for position, member in enumerate(members):
        below = members[min(position + 1, len(members) - 1)]
        assert zizmor._ONE_BAND_LOWER[member.value] == below.value


def test_actionlint_keeps_its_severities_and_levels():
    from automated_security_helper.plugin_modules.ash_builtin.scanners import (
        actionlint_scanner as actionlint,
    )

    assert actionlint._SEVERITY_TO_LEVEL == {
        "HIGH": "error",
        "MEDIUM": "warning",
        "LOW": "note",
    }
    assert actionlint.UNKNOWN_KIND_SEVERITY == "LOW"
    assert actionlint.KIND_SEVERITY["credentials"] == "HIGH"
    assert actionlint.KIND_SEVERITY["permissions"] == "MEDIUM"
    assert actionlint.KIND_SEVERITY["if-cond"] == "MEDIUM"
    assert {
        v
        for k, v in actionlint.KIND_SEVERITY.items()
        if k not in {"credentials", "permissions", "if-cond"}
    } == {"LOW"}
    assert actionlint.severity_for("shellcheck", "x") == "LOW"
    assert actionlint.severity_for("unlisted-kind", "x") == "LOW"
    assert (
        actionlint.severity_for(
            "deprecated-commands", 'workflow command "set-env" was deprecated'
        )
        == "MEDIUM"
    )


def test_cfn_scanners_keep_their_severity_and_level_pairs():
    from automated_security_helper.plugin_modules.ash_builtin.scanners import (
        cfn_guard_scanner as guard,
        cfn_lint_scanner as lint,
    )

    assert (guard.VIOLATION_SEVERITY, guard.VIOLATION_LEVEL) == ("HIGH", "error")
    assert lint.SEVERITY_BY_RULE_LETTER == {
        "E": ("MEDIUM", "warning"),
        "W": ("LOW", "note"),
        "I": ("INFO", "none"),
    }
    assert Level(guard.VIOLATION_LEVEL) is Level.error
    assert all(Level(level) for _, level in lint.SEVERITY_BY_RULE_LETTER.values())


def test_npm_audit_keeps_its_two_tables():
    from automated_security_helper.plugin_modules.ash_builtin.scanners import (
        npm_audit_scanner as npm,
    )

    assert npm._SEVERITY_LEVEL == {
        "critical": "error",
        "high": "error",
        "moderate": "warning",
        "low": "note",
        "info": "note",
    }
    assert npm._SEVERITY_GRADE == {
        "critical": "CRITICAL",
        "high": "HIGH",
        "moderate": "MEDIUM",
        "low": "LOW",
        "info": "INFO",
    }


def test_hadolint_keeps_its_map_and_the_sarif_side_is_level_members():
    from automated_security_helper.plugin_modules.ash_hadolint_plugins import (
        hadolint_scanner as hadolint,
    )

    assert hadolint.HADOLINT_LEVEL_MAP == {
        "error": ("HIGH", Level.error),
        "warning": ("MEDIUM", Level.warning),
        "info": ("LOW", Level.note),
        "style": ("INFO", Level.none),
    }
    assert hadolint._SARIF_LEVEL_TO_HADOLINT == {
        "error": "error",
        "warning": "warning",
        "note": "info",
        "none": "style",
    }
    assert set(hadolint._SARIF_LEVEL_TO_HADOLINT) == LEVEL_WORDS


def test_guarddog_keeps_its_tables():
    from automated_security_helper.plugin_modules.ash_guarddog_plugins import (
        guarddog_scanner as guarddog,
    )

    assert guarddog._SEVERITY_LEVELS == {
        "HIGH": "error",
        "MEDIUM": "warning",
        "LOW": "note",
        "INFO": "none",
    }
    assert guarddog._risk_severity("high") == "HIGH"
    assert guarddog._risk_severity("low") == "LOW"
    assert guarddog._risk_severity("surprising") == "MEDIUM"
    assert guarddog._risk_severity(None) == "MEDIUM"


def test_trivy_base_keeps_its_severity_words_and_levels():
    from automated_security_helper.plugin_modules.ash_builtin.scanners import (
        _trivy_scanner_base as trivy,
    )

    assert trivy.TRIVY_SEVERITIES == ("CRITICAL", "HIGH", "MEDIUM", "LOW")
    assert trivy._SARIF_LEVEL == {
        "CRITICAL": "error",
        "HIGH": "error",
        "MEDIUM": "warning",
        "LOW": "note",
    }
    # trivy's own fifth rating stays trivy's: it is not a ladder word.
    assert trivy._MESSAGE_LEVEL == {**trivy._SARIF_LEVEL, "UNKNOWN": "note"}
    assert trivy._SEVERITY_ORDER == ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")
    assert "UNKNOWN" not in SEVERITY_VALUES


# --- options and fallbacks ---------------------------------------------------------


def test_bandit_confidence_option_is_the_set_bandit_documents():
    from automated_security_helper.plugin_modules.ash_builtin.scanners import (
        bandit_scanner as bandit,
    )

    assert get_args(bandit.BanditConfidenceLevel) == ("all", "low", "medium", "high")
    for word in get_args(bandit.BanditConfidenceLevel):
        assert bandit.BanditScannerConfigOptions(confidence_level=word)
    assert bandit.BanditScannerConfigOptions().confidence_level == "all"
    with pytest.raises(ValidationError):
        bandit.BanditScannerConfigOptions(confidence_level="extreme")
    property_schema = bandit.BanditScannerConfigOptions.model_json_schema()[
        "properties"
    ]["confidence_level"]
    text = json.dumps(property_schema)
    assert "pattern" not in text
    assert json.loads(text).get("enum") == ["all", "low", "medium", "high"]


def test_opengrep_takes_the_shared_grep_option_types():
    # The semgrep scanner that shared these types was removed in v4 (opengrep
    # serves its name), so opengrep is the one grep-family scanner left to check.
    from automated_security_helper.plugin_modules.ash_builtin.scanners import (
        _grep_scanner_base as base,
        opengrep_scanner as opengrep,
    )

    assert get_args(base.GrepSeverityWord) == ("INFO", "WARNING", "ERROR")
    assert get_args(base.GrepMetricsMode) == ("auto", "on", "off")
    fields = opengrep.OpengrepScannerConfigOptions.model_fields
    severity = fields["severity"].annotation
    assert get_args(severity) == (base.GrepSeverityWord,)
    assert fields["metrics"].annotation == base.GrepMetricsMode


def test_grype_threshold_option_is_the_pinned_text_alias():
    from automated_security_helper.plugin_modules.ash_builtin.scanners import (
        grype_scanner as grype,
    )

    annotation = grype.GrypeScannerConfigOptions.model_fields[
        "severity_threshold"
    ].annotation
    assert SeverityThresholdText in get_args(annotation)


def test_detect_secrets_result_defaults_to_the_secrets_type_tag():
    from automated_security_helper.plugin_modules.ash_builtin.scanners.detect_secrets_scanner import (
        DetectSecretsScanner,
    )

    result = DetectSecretsScanner.build_secret_result(
        finding_type="AWS Access Key", uri="a.py", line_number=3
    )
    assert f"tool_type::{ScannerToolType.SECRETS.value}" in result.properties.tags
    assert ScannerToolType.UNKNOWN.value == "UNKNOWN"
