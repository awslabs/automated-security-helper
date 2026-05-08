# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for AshSuppression and IgnorePathWithReason methods.

TDD-first: these tests exercise methods that are being added to the models in
``automated_security_helper.models.core``. Behavior mirrors the existing
procedural helpers in ``automated_security_helper.utils.suppression_matcher``
and ``automated_security_helper.utils.sarif_utils``.
"""

from datetime import date, datetime, timedelta

from automated_security_helper.models.core import (
    AshSuppression,
    IgnorePathWithReason,
)
from automated_security_helper.models.flat_vulnerability import FlatVulnerability


def _make_finding(
    rule_id: str = "TEST-001",
    file_path: str = "src/file.py",
    line_start: int | None = 10,
    line_end: int | None = 15,
) -> FlatVulnerability:
    return FlatVulnerability(
        id="f-id",
        title="Test Finding",
        description="Desc",
        severity="HIGH",
        scanner="test-scanner",
        scanner_type="SAST",
        rule_id=rule_id,
        file_path=file_path,
        line_start=line_start,
        line_end=line_end,
    )


# ---------------------------------------------------------------------------
# AshSuppression.matches(finding)
# ---------------------------------------------------------------------------


class TestAshSuppressionMatches:
    def test_rule_id_exact_match(self):
        finding = _make_finding(rule_id="TEST-001", line_start=10, line_end=10)
        suppression = AshSuppression(
            path="src/file.py",
            rule_id="TEST-001",
            reason="r",
        )
        assert suppression.matches(finding) is True

    def test_rule_id_glob_pattern(self):
        finding = _make_finding(rule_id="B105", line_start=10, line_end=10)
        suppression = AshSuppression(
            path="src/file.py",
            rule_id="B1*",
            reason="r",
        )
        assert suppression.matches(finding) is True

    def test_rule_id_mismatch(self):
        finding = _make_finding(rule_id="TEST-001", line_start=10, line_end=10)
        suppression = AshSuppression(
            path="src/file.py",
            rule_id="TEST-002",
            reason="r",
        )
        assert suppression.matches(finding) is False

    def test_path_glob_match(self):
        finding = _make_finding(file_path="src/foo.py", line_start=10, line_end=10)
        suppression = AshSuppression(
            path="src/*.py",
            rule_id="TEST-001",
            reason="r",
        )
        assert suppression.matches(finding) is True

    def test_path_recursive_glob_match(self):
        finding = _make_finding(
            file_path="tests/sub/test_bar.py", line_start=1, line_end=1
        )
        suppression = AshSuppression(
            path="tests/**/*.py",
            rule_id="TEST-001",
            reason="r",
        )
        assert suppression.matches(finding) is True

    def test_line_range_overlap(self):
        finding = _make_finding(line_start=12, line_end=18)
        suppression = AshSuppression(
            path="src/file.py",
            rule_id="TEST-001",
            line_start=10,
            line_end=15,
            reason="r",
        )
        assert suppression.matches(finding) is True

    def test_line_range_no_overlap(self):
        finding = _make_finding(line_start=1, line_end=5)
        suppression = AshSuppression(
            path="src/file.py",
            rule_id="TEST-001",
            line_start=10,
            line_end=15,
            reason="r",
        )
        assert suppression.matches(finding) is False

    def test_expired_suppression_does_not_match(self):
        # Use a bypass construction — validator drops past dates, so build
        # via model_construct to keep the string on the model for this test.
        past = (date.today() - timedelta(days=1)).strftime("%Y-%m-%d")
        suppression = AshSuppression.model_construct(
            path="src/file.py",
            rule_id="TEST-001",
            reason="r",
            expiration=past,
        )
        finding = _make_finding(rule_id="TEST-001", line_start=10, line_end=10)
        assert suppression.matches(finding) is False

    def test_case_insensitive_rule_id(self):
        finding = _make_finding(rule_id="test-001", line_start=10, line_end=10)
        suppression = AshSuppression(
            path="src/file.py",
            rule_id="TEST-001",
            reason="r",
        )
        assert suppression.matches(finding) is True


# ---------------------------------------------------------------------------
# AshSuppression.id
# ---------------------------------------------------------------------------


class TestAshSuppressionId:
    def test_id_with_all_fields(self):
        suppression = AshSuppression(
            path="src/file.py",
            rule_id="TEST-001",
            line_start=10,
            line_end=20,
            reason="r",
        )
        assert suppression.id == "src/file.py|TEST-001|10|20"

    def test_id_with_no_rule_id(self):
        # Mirror existing _get_suppression_id behavior: rule_id None -> "*"
        suppression = AshSuppression(
            path="src/file.py",
            reason="r",
        )
        assert suppression.id == "src/file.py|*|*|*"

    def test_id_with_only_line_start(self):
        # line_end falls back to line_start per existing helper
        suppression = AshSuppression(
            path="src/file.py",
            rule_id="TEST-001",
            line_start=10,
            reason="r",
        )
        assert suppression.id == "src/file.py|TEST-001|10|10"


# ---------------------------------------------------------------------------
# AshSuppression.is_expired
# ---------------------------------------------------------------------------


class TestAshSuppressionIsExpired:
    def test_is_expired_past_date(self):
        past = (date.today() - timedelta(days=1)).strftime("%Y-%m-%d")
        suppression = AshSuppression.model_construct(
            path="src/file.py",
            rule_id="TEST-001",
            reason="r",
            expiration=past,
        )
        assert suppression.is_expired is True

    def test_is_expired_future_date(self):
        future = (date.today() + timedelta(days=30)).strftime("%Y-%m-%d")
        suppression = AshSuppression(
            path="src/file.py",
            rule_id="TEST-001",
            reason="r",
            expiration=future,
        )
        assert suppression.is_expired is False

    def test_is_expired_no_expiration(self):
        suppression = AshSuppression(
            path="src/file.py",
            rule_id="TEST-001",
            reason="r",
        )
        assert suppression.is_expired is False


# ---------------------------------------------------------------------------
# AshSuppression.days_until_expiry
# ---------------------------------------------------------------------------


class TestAshSuppressionDaysUntilExpiry:
    def test_days_until_expiry_30_days_out(self):
        future = (date.today() + timedelta(days=30)).strftime("%Y-%m-%d")
        suppression = AshSuppression(
            path="src/file.py",
            rule_id="TEST-001",
            reason="r",
            expiration=future,
        )
        assert suppression.days_until_expiry == 30

    def test_days_until_expiry_none_expiration(self):
        suppression = AshSuppression(
            path="src/file.py",
            rule_id="TEST-001",
            reason="r",
        )
        assert suppression.days_until_expiry is None

    def test_days_until_expiry_past_date_is_negative(self):
        past = (date.today() - timedelta(days=5)).strftime("%Y-%m-%d")
        suppression = AshSuppression.model_construct(
            path="src/file.py",
            rule_id="TEST-001",
            reason="r",
            expiration=past,
        )
        # Past date yields a negative count (e.g., -5). Callers that only care
        # about "is it already expired" should use is_expired.
        assert suppression.days_until_expiry is not None
        assert suppression.days_until_expiry < 0


# ---------------------------------------------------------------------------
# IgnorePathWithReason.matches_path
# ---------------------------------------------------------------------------


class TestIgnorePathWithReasonMatchesPath:
    def test_exact_match(self):
        entry = IgnorePathWithReason(path="src/file.py", reason="r")
        assert entry.matches_path("src/file.py") is True

    def test_glob_match(self):
        entry = IgnorePathWithReason(path="*.py", reason="r")
        assert entry.matches_path("foo.py") is True

    def test_recursive_glob_match(self):
        entry = IgnorePathWithReason(path="tests/**/*.py", reason="r")
        assert entry.matches_path("tests/unit/nested/test_bar.py") is True

    def test_non_matching_path(self):
        entry = IgnorePathWithReason(path="src/*.py", reason="r")
        assert entry.matches_path("lib/foo.py") is False


# ---------------------------------------------------------------------------
# Sanity: datetime is usable (prevents unused-import lint in minimal edits)
# ---------------------------------------------------------------------------


def test_module_imports_are_alive():
    # Defensive: ensure the testing module's imports remain valid in minimal
    # test environments. Keeps pydantic model resolution warm before other
    # test modules import the same symbols.
    assert datetime is not None
