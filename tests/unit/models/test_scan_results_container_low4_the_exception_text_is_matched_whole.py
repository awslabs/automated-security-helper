# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``for_failure`` lists an exception's text unless an error already says it.

An error said it when the text was anywhere inside it, so ``timed out`` was
"already listed" by ``Scanner x timed out after 300s``, and the exception's own
text was left out of the errors the reports render.
"""

from __future__ import annotations

import pytest

from automated_security_helper.models.scan_results_container import (
    ScanResultsContainer,
)

pytestmark = pytest.mark.unit


def test_a_text_only_inside_an_error_is_still_listed():
    container = ScanResultsContainer.for_failure(
        "scripted",
        errors=["Scanner x timed out after 300s"],
        exception=RuntimeError("timed out"),
    )

    assert container.errors == ["Scanner x timed out after 300s", "timed out"]
    assert container.exception == "timed out"


def test_a_text_that_starts_an_error_is_still_listed():
    container = ScanResultsContainer.for_failure(
        "scripted",
        errors=["timed out after 300s"],
        exception=RuntimeError("timed out"),
    )

    assert container.errors == ["timed out after 300s", "timed out"]


def test_an_error_that_is_the_text_lists_it_once():
    container = ScanResultsContainer.for_failure(
        "scripted", errors=["timed out"], exception=RuntimeError("timed out")
    )

    assert container.errors == ["timed out"]


def test_an_error_that_ends_in_a_label_and_the_text_lists_it_once():
    container = ScanResultsContainer.for_failure(
        "scripted",
        errors=["Scanner scripted failed: timed out"],
        exception=RuntimeError("timed out"),
    )

    assert container.errors == ["Scanner scripted failed: timed out"]


def test_an_error_ending_in_the_text_without_a_label_does_not_count():
    container = ScanResultsContainer.for_failure(
        "scripted",
        errors=["Scanner scripted never timed out"],
        exception=RuntimeError("timed out"),
    )

    assert container.errors == ["Scanner scripted never timed out", "timed out"]
