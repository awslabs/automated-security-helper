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

The hook has a second refusal, for a test marked both ``unit`` and ``slow``: the unit
CI job runs without ``--run-slow``, so such a test would be skipped there and run in no
job. A module marked ``unit`` and ``slow`` gets the usage error, and the same module
marked ``integration`` and ``slow`` is collected.

The CI jobs run under pytest-xdist, where the hook runs in the workers and a usage error
raised there never reaches the output: the controller failed with "Unexpectedly no
active workers available" or ``assert not crashitem`` and named no test. So each refusal
is also run with two workers (not ``--collect-only``, under which pytest-xdist does not
start any): the run must stop with the rule and the offending node ids in its output,
run no test and show no internal error, and the control module with one tier must run
its test and pass.

This file starts a child pytest, so by its own rule it is an integration test.
"""

import re

import pytest

from tests.utils.helpers import run_a_child_pytest_under_this_suite

pytestmark = pytest.mark.integration

RULE = "every test needs exactly one of the unit, integration or e2e markers"

UNIT_SLOW_RULE = "also carry the slow marker"

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


def _run_with_two_workers(source: str, tmp_path):
    """Run *source* in a child pytest with two xdist workers, as the CI jobs run.

    Not ``--collect-only``: pytest-xdist does not start workers for a collection-only
    run, so the child would collect in one process and never take the worker path.
    """
    return run_a_child_pytest_under_this_suite(
        source,
        tmp_path,
        prefix="tier-xdist-",
        options=("-q", "-n", "2", "--strict-markers"),
    )


#: A summary count of tests that ran ("1 passed"), which a refused run never prints.
RAN = re.compile(r"\b\d+ (passed|failed)\b")


def _marked(tiers_and_slow: str) -> str:
    """A planted module whose one test takes its markers from a module ``pytestmark``."""
    return (
        "import pytest\n"
        "\n"
        f"pytestmark = [{tiers_and_slow}]\n"
        "\n"
        "\n"
        "def test_carries_the_module_markers():\n"
        "    pass\n"
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


def test_a_unit_test_that_is_also_marked_slow_makes_collection_a_usage_error(tmp_path):
    result = _collect(_marked("pytest.mark.unit, pytest.mark.slow"), tmp_path)
    output = result.stdout + result.stderr

    assert result.returncode == pytest.ExitCode.USAGE_ERROR, output
    assert UNIT_SLOW_RULE in output, output
    assert "1 unit test(s) also carry the slow marker" in output, output
    assert "::test_carries_the_module_markers" in output, output
    # The tier count is right (one tier), so the first refusal is not what fired.
    assert RULE not in output, output


def test_an_integration_test_that_is_also_marked_slow_is_collected(tmp_path):
    result = _collect(_marked("pytest.mark.integration, pytest.mark.slow"), tmp_path)
    output = result.stdout + result.stderr

    assert result.returncode == pytest.ExitCode.OK, output
    assert "::test_carries_the_module_markers" in result.stdout, output
    assert UNIT_SLOW_RULE not in output, output
    assert RULE not in output, output


# The control for the unit-and-slow refusal, a test with no tier marker at all, is
# test_a_test_with_no_tier_or_two_tiers_makes_collection_a_usage_error above: it is
# still refused with "do not carry exactly one tier marker", and that refusal is
# checked first, so a test with no tier never reaches the slow check.


def test_with_workers_a_test_with_no_tier_stops_the_run_and_names_it(tmp_path):
    result = _run_with_two_workers(NO_TIER_AND_TWO_TIERS, tmp_path)
    output = result.stdout + result.stderr

    assert result.returncode == pytest.ExitCode.INTERRUPTED, output
    assert RULE in output, output
    assert "2 collected test(s)" in output, output
    assert "::test_with_no_tier -> none" in output, output
    assert "::test_with_two_tiers -> integration, unit" in output, output
    assert "INTERNALERROR" not in output, output
    assert not RAN.search(output), output


def test_with_workers_a_unit_test_also_marked_slow_stops_the_run_and_names_it(
    tmp_path,
):
    result = _run_with_two_workers(
        _marked("pytest.mark.unit, pytest.mark.slow"), tmp_path
    )
    output = result.stdout + result.stderr

    assert result.returncode == pytest.ExitCode.INTERRUPTED, output
    assert "1 unit test(s) also carry the slow marker" in output, output
    assert "::test_carries_the_module_markers" in output, output
    assert RULE not in output, output
    assert "INTERNALERROR" not in output, output
    assert not RAN.search(output), output


def test_with_workers_a_module_whose_test_has_one_tier_runs_it(tmp_path):
    result = _run_with_two_workers(
        ONE_TIER_FROM_PYTESTMARK.format(tier="unit"), tmp_path
    )
    output = result.stdout + result.stderr

    assert result.returncode == pytest.ExitCode.OK, output
    assert "1 passed" in output, output
    assert RULE not in output, output
    assert "INTERNALERROR" not in output, output
