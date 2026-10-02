# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The severity threshold is normalized once, at the environment boundary.

``ASH_DEFAULT_SEVERITY_LEVEL`` is read straight out of ``os.environ`` and used as
the default for ``global_settings.severity_threshold``, a ``Literal`` of the five
ladder values. ``pydantic`` does not validate a default that no caller supplied,
so before this module's fixes an off-table environment value reached the field --
``AshConfig().global_settings.severity_threshold == "INFO"`` -- while passing the
identical value explicitly raised ``ValidationError``.

Two things then went wrong downstream, and these tests pin both:

* ``ScannerStatisticsCalculator.calculate_actionable_count`` answered 0 for an
  unrecognized threshold, so every scanner reported zero actionable findings at
  every severity and the summary table read PASSED over real findings.
* Nothing rejected the off-table default, so the premise ``utils.severity_ladder``
  documents -- that the field cannot hold a value outside the ladder -- was false.

The tests are grouped by which half of the boundary they hold.
"""

from __future__ import annotations

import importlib
import logging

import pytest
from pydantic import ValidationError, create_model

from automated_security_helper.config.ash_config import (
    AshConfigGlobalSettingsSection,
)
from automated_security_helper.core import constants as ash_constants
from automated_security_helper.core.scanner_statistics_calculator import (
    ScannerStatisticsCalculator,
)
from automated_security_helper.utils.severity_ladder import (
    SEVERITY_THRESHOLDS,
    normalize_threshold,
)


class TestTheEnvironmentValueIsNormalized:
    """``ASH_DEFAULT_SEVERITY_LEVEL`` is validated before it becomes a default."""

    @pytest.mark.parametrize(
        "raw,expected",
        [
            ("HIGH", "HIGH"),
            ("high", "HIGH"),
            ("  high  ", "HIGH"),
            ("CRITICAL", "CRITICAL"),
            ("ALL", "ALL"),
            # Off-table: INFO is a severity, not a threshold, and it is the
            # plausible mistake -- an operator means "report everything" and the
            # ladder reads an unrecognized threshold as CRITICAL.
            ("INFO", "MEDIUM"),
            ("NONE", "MEDIUM"),
            ("MEDUIM", "MEDIUM"),
            ("", "MEDIUM"),
            ("   ", "MEDIUM"),
            (None, "MEDIUM"),
        ],
    )
    def test_the_resolved_level_is_always_on_the_ladder(self, raw, expected):
        assert ash_constants._resolve_default_severity_level(raw) == expected

    def test_an_unrecognized_value_names_itself_and_the_valid_set(self, caplog):
        """The fallback is silent-proof: a typo has to be visible to be fixable."""
        with caplog.at_level(logging.WARNING):
            ash_constants._resolve_default_severity_level("INFO")

        assert "INFO" in caplog.text
        assert "ASH_DEFAULT_SEVERITY_LEVEL" in caplog.text
        for threshold in SEVERITY_THRESHOLDS:
            assert threshold in caplog.text

    def test_a_recognized_value_warns_about_nothing(self, caplog):
        with caplog.at_level(logging.WARNING):
            ash_constants._resolve_default_severity_level("high")

        assert caplog.text == ""

    def test_the_module_constant_is_a_ladder_value(self):
        """The invariant ``validate_default=True`` depends on, in whatever
        environment this suite happens to run in."""
        assert ash_constants.ASH_DEFAULT_SEVERITY_LEVEL in SEVERITY_THRESHOLDS

    def test_an_off_table_environment_value_does_not_reach_the_constant(
        self, monkeypatch
    ):
        """The wiring, end to end: environment in, ladder value out.

        Reloaded rather than called directly because the defect was in the
        module-level read, not in any function -- a test of the helper alone would
        pass against the original ``os.environ.get(..., "MEDIUM")`` line. The
        module is reloaded again afterwards so the rest of the session sees the
        constant this environment really produces.
        """
        monkeypatch.setenv("ASH_DEFAULT_SEVERITY_LEVEL", "INFO")
        try:
            reloaded = importlib.reload(ash_constants)
            assert reloaded.ASH_DEFAULT_SEVERITY_LEVEL == "MEDIUM"
        finally:
            monkeypatch.undo()
            importlib.reload(ash_constants)

    def test_normalize_threshold_reports_the_unrecognized_case_as_none(self):
        """The shared predicate keeps "unrecognized" distinguishable from a value.

        ``constants`` needs to warn about the difference, so the helper cannot
        substitute a fallback of its own.
        """
        assert normalize_threshold("high") == "HIGH"
        assert normalize_threshold("INFO") is None
        assert normalize_threshold("") is None
        assert normalize_threshold(None) is None


class TestTheFieldDefaultIsValidated:
    """``validate_default=True`` makes the ladder's stated premise enforceable."""

    def test_the_shipped_default_constructs(self):
        """The happy path, because ``validate_default=True`` gates it too."""
        assert (
            AshConfigGlobalSettingsSection().severity_threshold in SEVERITY_THRESHOLDS
        )

    def test_an_off_table_default_is_rejected_at_construction(self):
        """A future default outside the ``Literal`` fails where it is written.

        Built as a subclass rather than by mutating the shipped field, so the
        assertion is about the inherited ``model_config`` -- which is the thing
        the fix adds -- and not about any state this test leaves behind.
        """
        off_table = create_model(
            "_OffTableDefaultGlobalSettings",
            __base__=AshConfigGlobalSettingsSection,
            severity_threshold=(
                AshConfigGlobalSettingsSection.model_fields[
                    "severity_threshold"
                ].annotation,
                "INFO",
            ),
        )

        with pytest.raises(ValidationError):
            off_table()

    def test_an_explicit_off_table_value_is_still_rejected(self):
        """Unchanged, and stated so the pair above is not read as the whole rule."""
        with pytest.raises(ValidationError):
            AshConfigGlobalSettingsSection(severity_threshold="INFO")


class TestAnUnrecognizedThresholdCountsFindings:
    """The fail-open zero, and the arm it is replaced by."""

    def test_an_off_table_threshold_counts_critical_rather_than_nothing(self):
        """Was 0 for every scanner at every severity; now the ladder's own arm.

        CRITICAL-only rather than count-everything because that is what
        ``utils.severity_ladder`` already does with an unrecognized threshold, and
        one encoding that is arguably conservative beats two that disagree. The
        load-bearing property is that it is not zero: zero is the one answer that
        makes a findings-bearing scan report clean.
        """
        assert (
            ScannerStatisticsCalculator.calculate_actionable_count(
                1, 2, 3, 4, 5, "INVALID"
            )
            == 1
        )

    def test_a_lowercase_threshold_is_not_read_as_its_upper_case_twin(self):
        """Threshold matching stays case-sensitive, as the ladder documents.

        Upper-casing here instead of at the boundary would make this one consumer
        read ``"medium"`` as MEDIUM while ``determine_status`` and the junitxml
        reporter read it as CRITICAL -- which is the divergence the whole phase is
        closing. Normalization belongs where the value enters, in ``constants``.
        """
        assert (
            ScannerStatisticsCalculator.calculate_actionable_count(
                1, 2, 3, 4, 5, "medium"
            )
            == 1
        )

    @pytest.mark.parametrize("threshold", ["", None])
    def test_a_falsy_threshold_gates_nothing(self, threshold):
        """A falsy threshold is how an operator turns the gate off, and it is
        deliberately *not* a synonym for an unrecognized one."""
        assert (
            ScannerStatisticsCalculator.calculate_actionable_count(
                1, 2, 3, 4, 5, threshold
            )
            == 0
        )

    @pytest.mark.parametrize(
        "threshold,expected",
        [
            ("ALL", 15),
            ("LOW", 10),
            ("MEDIUM", 6),
            ("HIGH", 3),
            ("CRITICAL", 1),
        ],
    )
    def test_every_ladder_value_still_counts_what_it_did(self, threshold, expected):
        """Delegating to the shared ladder must not move any of the five."""
        assert (
            ScannerStatisticsCalculator.calculate_actionable_count(
                1, 2, 3, 4, 5, threshold
            )
            == expected
        )
