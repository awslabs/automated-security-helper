# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A project name that holds a value the config read from the environment is not applied.

Why these tests exist
---------------------
``ASHScanOrchestrator._apply_metadata`` copies the workspace's project label onto
the results' metadata, which every report prints as text. It dropped the label
when it was exactly a value the configuration read from the environment, and
applied it otherwise, so a label that quoted such a value inside a longer name
(``team-<value>-api``) reached the reports. The test is now the redaction the rest
of the run uses: a label the redaction changes holds a value, and the name the
engine recorded stands.

Each test states the assertion that fails at the base.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.orchestrator import ASHScanOrchestrator

pytestmark = pytest.mark.unit

SECRET = "envproj-secret-5e19"


def _applied(tmp_path, label: str, value: str = SECRET) -> str:
    source = tmp_path / "proj"
    source.mkdir()
    output = tmp_path / "out"
    output.mkdir()
    orchestrator = ASHScanOrchestrator(source_dir=source, output_dir=output)
    config = AshConfig()
    config._environment_values = [value]
    orchestrator.config = config
    engine = MagicMock()
    engine._asharp_model.metadata.project_name = "recorded"
    orchestrator.execution_engine = engine
    orchestrator.metadata = {"project_name": label}

    orchestrator._apply_metadata()

    return engine._asharp_model.metadata.project_name


def test_a_label_that_is_the_value_is_not_applied(tmp_path):
    assert _applied(tmp_path, SECRET) == "recorded"


def test_a_label_that_quotes_the_value_inside_a_longer_name_is_not_applied(tmp_path):
    # Red at the base: only a label equal to the value was dropped.
    assert _applied(tmp_path, f"team-{SECRET}-api") == "recorded"


def test_a_label_with_surrounding_space_that_is_the_value_is_not_applied(tmp_path):
    assert _applied(tmp_path, f"  {SECRET}  ") == "recorded"


@pytest.mark.parametrize("short", ["a", "ab", "api"])
def test_a_label_that_is_a_short_value_is_not_applied(tmp_path, short):
    # Red without the equality arm: the redaction leaves a value under four
    # characters alone unless the text quotes it, so the text is unchanged and
    # the label was applied, where an exact match was dropped before.
    assert _applied(tmp_path, short, value=short) == "recorded"


@pytest.mark.parametrize("short", ["a", "ab", "api"])
def test_a_label_with_surrounding_space_that_is_a_short_value_is_not_applied(
    tmp_path, short
):
    # Red without the equality arm, for the same reason as the unpadded form
    # above. Its own test, because the helper makes its directories under
    # tmp_path and a second call in one test would find them already there.
    assert _applied(tmp_path, f"  {short}  ", value=short) == "recorded"


def test_a_label_that_only_contains_a_short_value_is_applied(tmp_path):
    """The control for the short band: only an exact match is dropped there."""
    assert _applied(tmp_path, "payments-api", value="api") == "payments-api"


def test_a_plain_label_is_applied(tmp_path):
    """The control: a name that holds no value still names the project."""
    assert _applied(tmp_path, "payments-api") == "payments-api"
