# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A malformed results file under ``--use-existing`` is refused as results that
did not load.

Why these tests exist
---------------------
``_build_engine`` reads the existing results file and wraps a read that fails
(``OSError``, ``UnicodeDecodeError``) as ``ASHValidationError("Failed to load
existing results: ...")``. The validation of what was read was not wrapped: a
file cut off by a crash or a full disk raised a bare pydantic ``ValidationError``,
which no entry point reads as a results file that failed to load. The wrap
covers it, with the description pydantic gives, redacted of the values the
configuration read from the environment.

Each test states the assertion that fails at the base.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.exceptions import ASHValidationError
from automated_security_helper.core.orchestrator import ASHScanOrchestrator
from automated_security_helper.models.asharp_model import AshAggregatedResults

pytestmark = pytest.mark.unit


def _orchestrator(tmp_path, results_text: str) -> ASHScanOrchestrator:
    source = tmp_path / "proj"
    source.mkdir()
    output = tmp_path / "out"
    output.mkdir()
    existing = tmp_path / "existing.json"
    existing.write_text(results_text, encoding="utf-8")
    return ASHScanOrchestrator(
        source_dir=source, output_dir=output, existing_results_path=existing
    )


def test_a_truncated_results_file_is_refused_as_failed_to_load(tmp_path):
    whole = AshAggregatedResults().model_dump_json()
    orchestrator = _orchestrator(tmp_path, whole[: len(whole) // 2])

    with pytest.raises(ASHValidationError) as raised:
        orchestrator._build_engine(AshConfig())

    # Red at the base: a bare pydantic ValidationError escaped.
    assert "Failed to load existing results" in str(raised.value)
    assert not isinstance(raised.value, ValidationError)


def test_a_results_file_that_is_not_json_is_refused_the_same_way(tmp_path):
    orchestrator = _orchestrator(tmp_path, "this is not json")

    with pytest.raises(ASHValidationError, match="Failed to load existing results"):
        orchestrator._build_engine(AshConfig())
