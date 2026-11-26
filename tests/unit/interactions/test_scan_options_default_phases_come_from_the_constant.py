# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``ScanOptions.phases`` has one default: ``DEFAULT_EXECUTION_PHASES``.

The field's default factory and the validator that turns ``None`` into the default
each spelled the convert, scan and report triple by hand while the run itself read
the constant, so a phase added to the constant reached the run but not the options.
"""

from __future__ import annotations

import pytest

from automated_security_helper.core.enums import DEFAULT_EXECUTION_PHASES
from automated_security_helper.interactions.run_ash_scan import ScanOptions

pytestmark = pytest.mark.unit


def test_the_default_and_the_none_default_are_the_constant(tmp_path):
    expected = list(DEFAULT_EXECUTION_PHASES)

    assert ScanOptions(source_dir=tmp_path, output_dir=tmp_path).phases == expected
    assert (
        ScanOptions(source_dir=tmp_path, output_dir=tmp_path, phases=None).phases
        == expected
    )


def test_each_default_is_its_own_list(tmp_path):
    first = ScanOptions(source_dir=tmp_path, output_dir=tmp_path)
    second = ScanOptions(source_dir=tmp_path, output_dir=tmp_path)

    first.phases.append("inspect")  # type: ignore[union-attr]

    assert second.phases == list(DEFAULT_EXECUTION_PHASES)
