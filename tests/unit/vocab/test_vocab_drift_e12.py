# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Drift gate for the scanner-module sweep (enum unit E12) and the identity rider (E10).

What the sweep cured, and how this module keeps it cured:

* ``TargetType``: the 36 inline ``Literal["source", "converted"]`` copies in the
  scanner modules, their compares and default-tree call sites, and
  ``finding_identity``'s ``CONVERTED_TREE`` constant. Distinctive enough for the
  NEGATIVE mode (any string constant equal to a member value in a scope file). The
  few legitimate spellings (npm's own advisory key ``"source"``, the work
  directory's name) are allowed by exact source line, not by whole file, so the rest
  of that file stays gated.
* ``Severity``: the scanner grade tables. Their uppercase ladder words must be
  members; NEGATIVE mode over the cured files, plus POSITIVE (collection) mode for
  a table that spells the SARIF level words three or more at a time.
* The shared option aliases in the grep base and the bandit confidence option.

Scanner and converter NAMES are an open set and are never an enum here (the
genericity rule); nothing in this module registers one.

Each mode carries a planted-positive control, so a scan that stopped looking cannot
read as clean. Behavior pins show the tables still hand plain text across the
boundaries they always did (``.value`` at the edge).
"""

from __future__ import annotations

from pathlib import Path
from typing import List, Tuple, get_args

import pytest
from pydantic import ValidationError

from automated_security_helper.models.vocab import (
    Severity,
    SeverityThresholdText,
    TargetType,
)
from automated_security_helper.schemas.sarif_schema_model import Level
from tests.unit.vocab._drift_gate import (
    PACKAGE_ROOT,
    Hit,
    VocabEntry,
    planted_control,
    scan_entry,
)

pytestmark = pytest.mark.unit

PM = "plugin_modules/"

#: The 21 scanner files that carried the Literal, plus the identity module.
TARGET_TYPE_SCOPE: Tuple[str, ...] = (
    PM + "ash_betterleaks_plugins/betterleaks_scanner.py",
    PM + "ash_builtin/scanners/_grep_scanner_base.py",
    PM + "ash_builtin/scanners/actionlint_scanner.py",
    PM + "ash_builtin/scanners/bandit_scanner.py",
    PM + "ash_builtin/scanners/cdk_nag_scanner.py",
    PM + "ash_builtin/scanners/cfn_guard_scanner.py",
    PM + "ash_builtin/scanners/cfn_lint_scanner.py",
    PM + "ash_builtin/scanners/cfn_nag_scanner.py",
    PM + "ash_builtin/scanners/checkov_scanner.py",
    PM + "ash_builtin/scanners/detect_secrets_scanner.py",
    PM + "ash_builtin/scanners/gitleaks_scanner.py",
    PM + "ash_builtin/scanners/grype_scanner.py",
    PM + "ash_builtin/scanners/npm_audit_scanner.py",
    PM + "ash_builtin/scanners/syft_scanner.py",
    PM + "ash_builtin/scanners/trivy_scanner.py",
    PM + "ash_builtin/scanners/zizmor_scanner.py",
    PM + "ash_ferret_plugins/ferret_scanner.py",
    PM + "ash_guarddog_plugins/guarddog_scanner.py",
    PM + "ash_hadolint_plugins/hadolint_scanner.py",
    PM + "ash_snyk_plugins/snyk_code_scanner.py",
    PM + "ash_trivy_plugins/trivy_repo_scanner.py",
    "utils/finding_identity.py",
)

#: ``(file, exact source line, reason)``: a spelling of a member value that is not
#: the vocabulary. Matched by the line's stripped text, so a second spelling in the
#: same file is still a hit.
TARGET_TYPE_LINE_ALLOWLIST: Tuple[Tuple[str, str, str], ...] = (
    (
        PM + "ash_builtin/scanners/npm_audit_scanner.py",
        'source = via.get("source")',
        "npm's advisory JSON key, not a tree label",
    ),
    (
        PM + "ash_builtin/scanners/npm_audit_scanner.py",
        '"source": record.get("id"),',
        "npm's advisory JSON key, not a tree label",
    ),
    (
        PM + "ash_builtin/scanners/detect_secrets_scanner.py",
        'work_dir=output_dir.joinpath("converted"),',
        "the work directory's on-disk name (ASH_WORK_DIR_NAME), not a tree label",
    ),
)

TARGET_TYPE = VocabEntry(
    name="TargetType (scanner sweep)", enum=TargetType, scope=TARGET_TYPE_SCOPE
)

#: The scanner files whose grade tables were re-keyed to ``Severity`` members.
GRADE_SCOPE: Tuple[str, ...] = (
    PM + "ash_betterleaks_plugins/betterleaks_scanner.py",
    PM + "ash_builtin/scanners/actionlint_scanner.py",
    PM + "ash_builtin/scanners/cfn_guard_scanner.py",
    PM + "ash_builtin/scanners/cfn_lint_scanner.py",
    PM + "ash_builtin/scanners/gitleaks_scanner.py",
    PM + "ash_builtin/scanners/grype_scanner.py",
    PM + "ash_builtin/scanners/npm_audit_scanner.py",
    PM + "ash_builtin/scanners/zizmor_scanner.py",
    PM + "ash_guarddog_plugins/guarddog_scanner.py",
    PM + "ash_hadolint_plugins/hadolint_scanner.py",
)

SEVERITY_GRADES = VocabEntry(
    name="Severity (scanner grade tables)", enum=Severity, scope=GRADE_SCOPE
)

#: Files that map a tool's severity onto a SARIF level. ``trivy`` keys its table by
#: trivy's own severity words, which stay tool-native; only the SARIF side is a member.
LEVEL_SCOPE: Tuple[str, ...] = (
    PM + "ash_builtin/scanners/_trivy_scanner_base.py",
    PM + "ash_builtin/scanners/actionlint_scanner.py",
    PM + "ash_builtin/scanners/cfn_guard_scanner.py",
    PM + "ash_builtin/scanners/cfn_lint_scanner.py",
    PM + "ash_builtin/scanners/npm_audit_scanner.py",
    PM + "ash_builtin/scanners/zizmor_scanner.py",
    PM + "ash_guarddog_plugins/guarddog_scanner.py",
    PM + "ash_hadolint_plugins/hadolint_scanner.py",
)

SARIF_LEVELS = VocabEntry(
    name="SARIF Level (scanner tables)",
    enum=Level,
    scope=LEVEL_SCOPE,
    mode="positive",
    min_hits=3,
)


def _line_of(rel: str, hit: Hit) -> str:
    return (
        (PACKAGE_ROOT / rel)
        .read_text(encoding="utf-8")
        .splitlines()[hit.line - 1]
        .strip()
    )


def _unallowed(hits: List[Hit]) -> List[Hit]:
    allowed = {(rel, line) for rel, line, _ in TARGET_TYPE_LINE_ALLOWLIST}
    return [h for h in hits if (h.path, _line_of(h.path, h)) not in allowed]


def test_the_scope_files_exist():
    for rel in {*TARGET_TYPE_SCOPE, *GRADE_SCOPE, *LEVEL_SCOPE}:
        assert (PACKAGE_ROOT / rel).is_file(), rel


def test_every_allowlist_entry_has_a_reason_and_still_matches():
    for rel, line, reason in TARGET_TYPE_LINE_ALLOWLIST:
        assert reason.strip()
        text = (PACKAGE_ROOT / rel).read_text(encoding="utf-8")
        assert any(row.strip() == line for row in text.splitlines()), (rel, line)


def test_the_scanner_modules_spell_no_target_type_value():
    hits = _unallowed(scan_entry(TARGET_TYPE))
    assert not hits, "TargetType was re-spelled:\n" + "\n".join(
        f"  {h.path}:{h.line}: {h.text}" for h in hits
    )


def test_the_scanner_grade_tables_spell_no_severity_word():
    hits = scan_entry(SEVERITY_GRADES)
    assert not hits, "a scanner re-spelled the severity ladder:\n" + "\n".join(
        f"  {h.path}:{h.line}: {h.text}" for h in hits
    )


def test_no_scanner_table_spells_the_sarif_level_words_together():
    hits = scan_entry(SARIF_LEVELS)
    assert not hits, "a scanner table re-spelled the SARIF levels:\n" + "\n".join(
        f"  {h.path}:{h.line}: {h.text}" for h in hits
    )


@pytest.mark.parametrize(
    "entry", [TARGET_TYPE, SEVERITY_GRADES, SARIF_LEVELS], ids=lambda e: e.name
)
def test_the_planted_stray_spelling_is_flagged(entry, tmp_path):
    assert planted_control(entry, tmp_path), (
        f"the scan did not flag a planted {entry.name}"
    )


def test_the_line_allowlist_does_not_hide_a_second_spelling(tmp_path):
    """A planted stray spelling beside an allowlisted line is still a hit."""
    planted = tmp_path / "planted.py"
    planted.write_text('x = via.get("source")\ny = "converted"\n', encoding="utf-8")
    hits = scan_entry(
        VocabEntry(name="p", enum=TargetType, scope=("planted.py",)), root=tmp_path
    )
    assert sorted(h.line for h in hits) == [1, 2]
    # The allowlist is keyed by real package paths and exact lines: a planted file is
    # never in it, and the real file's allowed lines stay the only ones skipped.
    assert len(_unallowed(scan_entry(TARGET_TYPE))) == 0


# --- the shared option aliases and the closed options ----------------------------


def test_the_grep_scanners_share_the_option_aliases():
    from automated_security_helper.plugin_modules.ash_builtin.scanners._grep_scanner_base import (
        GrepMetricsText,
        GrepRuleSeverityText,
    )

    assert get_args(GrepRuleSeverityText) == ("INFO", "WARNING", "ERROR")
    assert get_args(GrepMetricsText) == ("auto", "on", "off")
    for rel in (
        PM + "ash_builtin/scanners/semgrep_scanner.py",
        PM + "ash_builtin/scanners/opengrep_scanner.py",
    ):
        text = (PACKAGE_ROOT / rel).read_text(encoding="utf-8")
        assert 'Literal["INFO", "WARNING", "ERROR"]' not in text, rel
        assert 'Literal["auto", "on", "off"]' not in text, rel


def test_the_grep_options_still_validate_the_same_words():
    from automated_security_helper.plugin_modules.ash_builtin.scanners.opengrep_scanner import (
        OpengrepScannerConfigOptions,
    )
    from automated_security_helper.plugin_modules.ash_builtin.scanners.semgrep_scanner import (
        SemgrepScannerConfigOptions,
    )

    for options in (SemgrepScannerConfigOptions, OpengrepScannerConfigOptions):
        assert options(severity=["WARNING"], metrics="off").metrics == "off"
        with pytest.raises(ValidationError):
            options(metrics="maybe")
        with pytest.raises(ValidationError):
            options(severity=["SEVERE"])


def test_bandit_confidence_is_a_closed_literal():
    from automated_security_helper.plugin_modules.ash_builtin.scanners.bandit_scanner import (
        BanditScannerConfigOptions,
    )

    for word in ("all", "low", "medium", "high"):
        assert (
            BanditScannerConfigOptions(confidence_level=word).confidence_level == word
        )
    for bad in ("ALL", "none", "", "highest"):
        with pytest.raises(ValidationError):
            BanditScannerConfigOptions(confidence_level=bad)
    assert BanditScannerConfigOptions().confidence_level == "all"


def test_grype_threshold_uses_the_vocab_alias():
    from automated_security_helper.plugin_modules.ash_builtin.scanners.grype_scanner import (
        GrypeScannerConfigOptions,
    )

    annotation = GrypeScannerConfigOptions.model_fields["severity_threshold"].annotation
    assert SeverityThresholdText in get_args(annotation)
    assert (
        GrypeScannerConfigOptions(severity_threshold="HIGH").severity_threshold
        == "HIGH"
    )
    with pytest.raises(ValidationError):
        GrypeScannerConfigOptions(severity_threshold="SEVERE")


# --- the tables hand plain text across the boundaries they always did -------------


def test_zizmor_severity_stays_plain_text():
    from automated_security_helper.plugin_modules.ash_builtin.scanners.zizmor_scanner import (
        map_zizmor_severity,
    )

    for args, expected in (
        (("high", "High", None), "HIGH"),
        (("high", "Low", None), "MEDIUM"),
        (("informational", None, None), "INFO"),
        (("bogus", None, "warning"), "MEDIUM"),
        (("bogus", None, None), "MEDIUM"),
    ):
        got = map_zizmor_severity(*args)
        assert got == expected and type(got) is str


def test_cfn_lint_rule_letters_grade_with_members_and_hand_out_text():
    from automated_security_helper.plugin_modules.ash_builtin.scanners.cfn_lint_scanner import (
        SEVERITY_BY_RULE_LETTER,
        severity_for_rule,
    )

    assert {s for s, _ in SEVERITY_BY_RULE_LETTER.values()} <= set(Severity)
    assert {lv for _, lv in SEVERITY_BY_RULE_LETTER.values()} <= set(Level)
    severity, level = severity_for_rule("W1234")
    assert (severity, level) == ("LOW", "note")
    assert type(severity) is str


def test_npm_audit_grades_hand_out_plain_text():
    from automated_security_helper.plugin_modules.ash_builtin.scanners.npm_audit_scanner import (
        _SEVERITY_GRADE,
        _SEVERITY_LEVEL,
        _grade_properties,
    )

    assert set(_SEVERITY_GRADE.values()) == set(Severity)
    assert set(_SEVERITY_LEVEL.values()) <= set(Level)
    props = _grade_properties("moderate")
    assert props == {"issue_severity": "MEDIUM"}
    assert type(props["issue_severity"]) is str
    assert _grade_properties("nonsense") == {}


def test_actionlint_kinds_grade_with_members():
    from automated_security_helper.plugin_modules.ash_builtin.scanners import (
        actionlint_scanner as al,
    )

    assert set(al.KIND_SEVERITY.values()) <= set(Severity)
    assert al.UNKNOWN_KIND_SEVERITY is Severity.LOW
    assert al.severity_for("credentials", "x") is Severity.HIGH
    assert al.severity_for("never-heard-of-it", "x") is Severity.LOW
    assert set(al._SEVERITY_TO_LEVEL) <= set(Severity)


def test_the_identity_key_for_a_converted_file_still_spells_the_wire_word():
    from automated_security_helper.utils.finding_identity import finding_identity

    identity = finding_identity(
        scanner="s",
        rule_id="r",
        file_path="a.py",
        line_start=1,
        line_end=1,
        converted=True,
    )
    tree = identity.base["tree"]
    assert tree == "converted" and type(tree) is str
    plain = finding_identity(
        scanner="s", rule_id="r", file_path="a.py", line_start=1, line_end=1
    )
    assert "tree" not in plain.base


def test_the_converted_tree_constant_is_gone():
    from automated_security_helper.utils import finding_identity

    assert not hasattr(finding_identity, "CONVERTED_TREE")


def test_scan_default_tree_is_a_member_where_the_grep_base_keeps_it():
    from automated_security_helper.plugin_modules.ash_builtin.scanners._grep_scanner_base import (
        GrepScannerBase,
    )

    private = GrepScannerBase.__private_attributes__["_scan_target_type"]
    assert private.default is TargetType.SOURCE


def test_the_gate_reads_real_files():
    # A control that the scan sees real scope files: the vocab module spells both.
    assert Path(PACKAGE_ROOT / "models/vocab.py").is_file()
