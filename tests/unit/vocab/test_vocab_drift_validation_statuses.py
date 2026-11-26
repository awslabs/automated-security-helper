# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Drift gate for the scanner-validation status vocabularies (unit E6).

Four closed vocabularies live in ``models/scanner_validation.py``:
``RegistrationStatus``, ``EnablementStatus``, ``ValidationOutcome`` and
``CheckpointName``. This gate keeps the spelled sites from coming back, in the
two modes the enum program uses:

* NEGATIVE mode, for the distinctive spellings: an ``ast`` scan of the scope's
  Python files flags any string constant (docstrings skipped) equal to a member
  value. ``registered_scanners``, ``scanner_enablement``, ``execution_completion``,
  ``result_completeness``, ``task_queue_validation``, ``missing_deps``,
  ``registered`` and ``untracked`` are distinctive enough for a flat scan.
* POSITIVE mode, for the short ambiguous words (``unknown``, ``enabled``,
  ``disabled``, ``excluded``, ``completed``, ``failed``, ``missing``, which are
  also dict keys and prose in the same files): an explicit list of
  ``(path, forbidden source fragment)`` pairs naming the exact assignment and
  comparison shapes the cure removed, plus a runtime pin that the summary
  buckets are derived from the enum.

A planted-positive control proves each mode can fail.
"""

import ast
import io
import tokenize
from pathlib import Path
from typing import Iterable, List, Set, Tuple

import pytest

from automated_security_helper.models.scanner_validation import (
    CheckpointName,
    EnablementStatus,
    RegistrationStatus,
    ScannerStateTracker,
    ScannerValidationState,
    ValidationCheckpoint,
    ValidationOutcome,
)

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[3]
PACKAGE = REPO_ROOT / "automated_security_helper"

#: The files the unit cured. The scope grows as later units land.
SCOPE = [
    PACKAGE / "models" / "scanner_validation.py",
    PACKAGE / "core" / "phases" / "scan_phase.py",
]
#: The enum module itself spells every value once, by construction.
ENUM_MODULE = PACKAGE / "models" / "scanner_validation.py"

#: Distinctive spellings scanned flat across the scope.
DISTINCTIVE_VALUES = {
    "registered_scanners",
    "scanner_enablement",
    "execution_completion",
    "result_completeness",
    "task_queue_validation",
    "missing_deps",
    "registered",
    "untracked",
}

#: ``(path, reason)`` allowlist for the negative scan, keyed by path then value.
#: scan_phase.py spells ``"registered"`` in unrelated prose-like constants only if
#: listed here with a reason; the cured scope has none today.
NEGATIVE_ALLOWLIST: dict = {}

#: Ambiguous words: the exact source fragments the cure removed.
FORBIDDEN_FRAGMENTS: List[Tuple[Path, str]] = [
    (ENUM_MODULE, 'registration_status="'),
    (ENUM_MODULE, 'enablement_status="'),
    (ENUM_MODULE, 'enablement_status == "'),
    (ENUM_MODULE, 'enablement_status != "'),
    (ENUM_MODULE, 'checkpoint_name="'),
    (ENUM_MODULE, 'checkpoint_name == "'),
    (ENUM_MODULE, '["status"] == "'),
    (ENUM_MODULE, '"status": "'),
    (ENUM_MODULE, '"registration_status", "'),
    (ENUM_MODULE, '"enablement_status", "'),
    (PACKAGE / "core" / "phases" / "scan_phase.py", 'registration_status="'),
    (PACKAGE / "core" / "phases" / "scan_phase.py", 'enablement_status="'),
]


def _source_without_comments(path: Path) -> str:
    """The file's source with every comment token blanked (prose may quote a value)."""
    source = path.read_text(encoding="utf-8")
    lines = source.splitlines(keepends=True)
    for token in tokenize.generate_tokens(io.StringIO(source).readline):
        if token.type == tokenize.COMMENT:
            row, col = token.start
            lines[row - 1] = lines[row - 1][:col] + "\n"
    return "".join(lines)


def _docstring_nodes(tree: ast.AST) -> Set[int]:
    skipped: Set[int] = set()
    for node in ast.walk(tree):
        if isinstance(
            node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)
        ):
            body = getattr(node, "body", [])
            if (
                body
                and isinstance(body[0], ast.Expr)
                and isinstance(body[0].value, ast.Constant)
                and isinstance(body[0].value.value, str)
            ):
                skipped.add(id(body[0].value))
    return skipped


def stray_spellings(path: Path, values: Iterable[str]) -> List[Tuple[int, str]]:
    """Return ``(line, value)`` for each non-docstring constant equal to a value."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    skipped = _docstring_nodes(tree)
    wanted = set(values)
    hits = []
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Constant)
            and isinstance(node.value, str)
            and id(node) not in skipped
            and node.value in wanted
        ):
            hits.append((node.lineno, node.value))
    return sorted(hits)


def _enum_body_lines(path: Path) -> Set[int]:
    """Lines inside the vocabulary classes, where each value is spelled once."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    enum_names = {
        "RegistrationStatus",
        "EnablementStatus",
        "ValidationOutcome",
        "CheckpointName",
    }
    lines: Set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and node.name in enum_names:
            lines.update(range(node.lineno, node.end_lineno + 1))
    return lines


@pytest.mark.parametrize("path", SCOPE, ids=lambda p: p.name)
def test_no_stray_distinctive_spellings(path: Path):
    allowed = NEGATIVE_ALLOWLIST.get(path, set())
    inside_enums = _enum_body_lines(path) if path == ENUM_MODULE else set()
    stray = [
        (line, value)
        for line, value in stray_spellings(path, DISTINCTIVE_VALUES)
        if line not in inside_enums and value not in allowed
    ]
    assert stray == [], (
        f"{path.name} spells a vocabulary value outside its enum: {stray}"
    )


@pytest.mark.parametrize(
    "path,fragment", FORBIDDEN_FRAGMENTS, ids=lambda v: str(v)[-40:]
)
def test_removed_copy_sites_stay_gone(path: Path, fragment: str):
    assert fragment not in _source_without_comments(path)


def test_planted_positive_control_negative_mode(tmp_path):
    planted = tmp_path / "planted.py"
    planted.write_text(
        '"""docstring mentioning registered is skipped."""\n'
        "state = 'registered'\n"
        "name = 'task_queue_validation'\n",
        encoding="utf-8",
    )
    assert stray_spellings(planted, DISTINCTIVE_VALUES) == [
        (2, "registered"),
        (3, "task_queue_validation"),
    ]


def test_planted_positive_control_positive_mode():
    planted = 'x.update(enablement_status="excluded")'
    assert any(fragment in planted for _, fragment in FORBIDDEN_FRAGMENTS)


def test_summary_buckets_are_derived_from_the_outcome_enum():
    tracker = ScannerStateTracker()
    assert list(tracker.get_scanner_state_summary()) == [
        member.value for member in ValidationOutcome
    ]
    assert {member.value for member in ValidationOutcome} == {
        "completed",
        "excluded",
        "missing_deps",
        "failed",
        "missing",
    }


def test_member_values_keep_their_wire_spellings():
    assert {m.value for m in RegistrationStatus} == {
        "unknown",
        "registered",
        "untracked",
    }
    assert {m.value for m in EnablementStatus} == {
        "unknown",
        "enabled",
        "disabled",
        "excluded",
        "missing_deps",
    }
    assert {m.value for m in CheckpointName} == {
        "registered_scanners",
        "scanner_enablement",
        "execution_completion",
        "result_completeness",
        "task_queue_validation",
    }


def test_members_compare_and_format_as_their_wire_strings():
    for member in (
        *RegistrationStatus,
        *EnablementStatus,
        *ValidationOutcome,
        *CheckpointName,
    ):
        assert member == member.value
        assert str(member) == member.value
        assert f"{member}" == member.value


def test_defaults_are_members_and_state_serializes_as_plain_strings():
    import json

    state = ScannerValidationState(name="bandit")
    assert state.registration_status is RegistrationStatus.UNKNOWN
    assert state.enablement_status is EnablementStatus.UNKNOWN
    assert (
        json.dumps({"r": state.registration_status, "e": state.enablement_status})
        == '{"r": "unknown", "e": "unknown"}'
    )


def test_checkpoint_name_accepts_member_and_unlisted_plain_string():
    member = ValidationCheckpoint(checkpoint_name=CheckpointName.SCANNER_ENABLEMENT)
    plain = ValidationCheckpoint(checkpoint_name="scanner_tasks")
    assert member.checkpoint_name == "scanner_enablement"
    assert plain.checkpoint_name == "scanner_tasks"
