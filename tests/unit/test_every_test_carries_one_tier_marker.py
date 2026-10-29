# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Collection refuses a session in which a test has no tier marker, or two.

Every test carries exactly one of the ``unit``, ``integration`` and ``e2e`` markers,
because the CI jobs select tests by tier (see "Test tiers" in
tests/NAMING_CONVENTIONS.md). The check is the first thing
``pytest_collection_modifyitems`` in tests/conftest.py does. It is a usage error
rather than a skip or a warning: a test with no tier would otherwise run green by
default, or be left out of every tier job without anyone noticing.

The check is only worth anything if the real hook refuses what it should and admits
what it should, so this file runs a child pytest under the suite's own root conftest
(``run_a_child_pytest_under_this_suite``) over a planted module, once for each case:

* a module with one test that has no tier and one that has two: the child exits with
  the usage-error code, and its output holds the rule and both node ids with the
  tiers each carries;
* a control module whose tests take their tier from a module-level ``pytestmark``:
  the child exits 0 and collects them;
* the same control with the ``e2e`` tier, which also shows that ``e2e`` is registered
  under ``--strict-markers``.

This file starts a child pytest, so by its own rule it is an integration test.
"""

import pytest

from tests.utils.helpers import run_a_child_pytest_under_this_suite

pytestmark = pytest.mark.integration

RULE = "every test needs exactly one of the unit, integration or e2e markers"

NO_TIER_AND_TWO_TIERS = """\
import pytest


def test_with_no_tier():
    pass


@pytest.mark.unit
@pytest.mark.integration
def test_with_two_tiers():
    pass
"""

ONE_TIER_FROM_PYTESTMARK = """\
import pytest

pytestmark = pytest.mark.{tier}


def test_takes_its_tier_from_the_module():
    pass
"""


def _collect(source: str, tmp_path):
    """Collect *source* in a child pytest that has the suite's own root conftest.

    ``-o addopts=`` is the helper's, so the repository's ``--strict-markers`` is
    given again here: the check has to hold under the same flag CI uses.
    """
    return run_a_child_pytest_under_this_suite(
        source,
        tmp_path,
        prefix="tier-",
        options=("--collect-only", "-q", "-n", "0", "--strict-markers"),
    )


def test_a_test_with_no_tier_or_two_tiers_makes_collection_a_usage_error(tmp_path):
    result = _collect(NO_TIER_AND_TWO_TIERS, tmp_path)
    output = result.stdout + result.stderr

    assert result.returncode == pytest.ExitCode.USAGE_ERROR, output
    assert RULE in output, output
    assert "2 collected test(s)" in output, output
    assert "::test_with_no_tier -> none" in output, output
    assert "::test_with_two_tiers -> integration, unit" in output, output


@pytest.mark.parametrize("tier", ["unit", "integration", "e2e"])
def test_a_test_with_one_tier_from_a_module_pytestmark_is_collected(tmp_path, tier):
    result = _collect(ONE_TIER_FROM_PYTESTMARK.format(tier=tier), tmp_path)
    output = result.stdout + result.stderr

    assert result.returncode == pytest.ExitCode.OK, output
    assert "::test_takes_its_tier_from_the_module" in result.stdout, output
    assert RULE not in output, output
