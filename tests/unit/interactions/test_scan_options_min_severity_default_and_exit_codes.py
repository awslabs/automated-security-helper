# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Follow-ups to the enum adoption in ``run_ash_scan``.

* A default-built ``ScanOptions`` holds the same plain string for ``min_severity``
  that an explicit value holds: the field's before-validator turns a member into
  its text, but a default skips validation, so the default is spelled as text.
* The exits that name an ``AshExitCode`` in their docstrings carry that code's
  value, as the plain integer they always did.
"""

from __future__ import annotations

import inspect
from unittest.mock import MagicMock

import pytest

from automated_security_helper.core.enums import AshExitCode, MinSeverity
from automated_security_helper.interactions import run_ash_scan
from automated_security_helper.interactions.run_ash_scan import (
    OUTPUT_DIR_REFUSED_EXIT_CODE,
    OutputDirRefusedExit,
    ReportPathRefusedExit,
    ScanIncompleteExit,
    ScanOptions,
)

pytestmark = pytest.mark.unit


class TestMinSeverityDefaultIsPlainText:
    def test_a_default_built_option_holds_a_plain_str(self):
        opts = ScanOptions(source_dir=".", output_dir=".")

        assert type(opts.min_severity) is str
        assert opts.min_severity == "low"

    def test_a_default_equals_the_explicit_value_in_type_and_text(self):
        default = ScanOptions(source_dir=".", output_dir=".")
        explicit = ScanOptions(source_dir=".", output_dir=".", min_severity="low")

        assert type(default.min_severity) is type(explicit.min_severity)
        assert str(default.min_severity) == str(explicit.min_severity) == "low"
        assert f"{default.min_severity}" == "low"

    def test_the_run_function_default_is_plain_text_too(self):
        default = (
            inspect.signature(run_ash_scan.run_ash_scan)
            .parameters["min_severity"]
            .default
        )

        assert type(default) is str
        assert default == MinSeverity.LOW.value


class TestExitCodesStayTheirIntegers:
    def test_a_scan_incomplete_exit_is_the_scan_errors_code(self):
        exit_ = ScanIncompleteExit(MagicMock(), MagicMock())

        assert type(exit_.code) is int
        assert exit_.code == AshExitCode.SCAN_ERRORS.value == 1

    def test_a_report_path_refused_exit_is_the_scan_errors_code(self):
        exit_ = ReportPathRefusedExit("a reason")

        assert type(exit_.code) is int
        assert exit_.code == AshExitCode.SCAN_ERRORS.value == 1

    def test_an_output_dir_refused_exit_is_the_invalid_config_code(self):
        exit_ = OutputDirRefusedExit("found", "reason")

        assert type(OUTPUT_DIR_REFUSED_EXIT_CODE) is int
        assert OUTPUT_DIR_REFUSED_EXIT_CODE == AshExitCode.INVALID_CONFIG.value == 3
        assert exit_.code == 3
