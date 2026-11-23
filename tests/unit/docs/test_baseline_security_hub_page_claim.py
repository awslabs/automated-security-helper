# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The GitHub Actions page says Security Hub archives nothing after a baseline scan.

how-to/ci/github-actions.md#baseline warns that "Security Hub does not archive absent
findings from a baseline-filtered run". A baseline removes findings from the results the
reporter compares with what Security Hub stores, so an archive pass over them would mark
every baselined finding resolved. This test pins the sentence and runs the reporter over
results a baseline filtered. It is separate from test_baseline_page_claims.py because the
Security Hub doubles carry autouse fixtures that fake AWS credentials, which nothing else
in that module needs.
"""

from __future__ import annotations

import pytest

from tests.unit.docs.test_page_claims import assert_on_page
from tests.unit.plugin_modules.ash_aws_plugins.security_hub_reporter_doubles import (
    archive_run,
    built_finding,
    isolated_aws_environment as isolated_aws_environment,
    make_model,
    make_reporter,
    make_result,
    no_retry_sleep as no_retry_sleep,
    stored_finding,
)

pytestmark = pytest.mark.unit

GITHUB_ACTIONS = "how-to/ci/github-actions.md"


def test_the_actions_page_says_security_hub_does_not_archive_after_a_baseline(tmp_path):
    assert_on_page(
        GITHUB_ACTIONS,
        "Security Hub does not archive absent findings from a baseline-filtered run.",
    )
    model = make_model([make_result()], completed=("bandit",))
    model.metadata.baseline = {
        "sha256": "abc",
        "matched": 1,
        "matched_without_lines": 0,
    }
    stale = stored_finding(
        built_finding(make_reporter(tmp_path), make_result(rule_id="B105", line=5))
    )
    document, _, _ = archive_run(tmp_path, model, [stale], expected_sent=1)
    assert document["archived"] == 0
    assert (
        document["archive_skipped"]
        == "the results leave out findings already in a baseline"
    )
