# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""scripts/verify_moto_server_suite.py: the report evaluation.

* the floor counts tests from the moto-server modules only, so the rest of
  tests/unit/deploy cannot keep it satisfied while those modules shrink;
* each required module has its own floor;
* the two S3 helper parametrizations are looked for in the S3 module alone,
  so an unrelated module's "terraform" cannot stand in for the lost copy.
"""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.unit


@pytest.fixture
def moto(script_loader):
    return script_loader("verify_moto_server_suite")


def _clean_totals(tests: int) -> dict:
    return {"tests": tests, "failures": 0, "errors": 0, "skipped": 0}


def _names(module: str, count: int, suffix: str = "") -> list[str]:
    return [f"tests.unit.deploy.{module}.TestX::test_{i}{suffix}" for i in range(count)]


def _healthy_names(moto) -> list[str]:
    """One report comfortably above every floor the script declares.

    Built from the script's own constants, so a floor that moves does not
    silently turn this fixture into a shrunken suite.
    """
    names: list[str] = []
    for module, floor in moto.REQUIRED_MODULES.items():
        if module == moto.PARAMETRIZED_MODULE:
            per_param = floor // len(moto.REQUIRED_PARAMS) + 5
            for param in moto.REQUIRED_PARAMS:
                names += _names(module, per_param, f"[{param}]")
        else:
            names += _names(module, floor + 3)
    assert len(names) >= moto.MIN_TESTS, "the fixture must clear the overall floor"
    return names


def test_a_healthy_report_is_clean(moto):
    names = _healthy_names(moto)
    assert moto.evaluate_report(_clean_totals(len(names)), names) == []


def test_other_modules_do_not_keep_the_floor_satisfied(moto):
    """At the base, 150 unrelated tests cleared the floor with one moto test per module."""
    names = _names("test_deploy_gate_claims", 150)
    for module in moto.REQUIRED_MODULES:
        names += _names(module, 1, "[terraform]")
    problems = moto.evaluate_report(_clean_totals(len(names)), names)
    assert any(
        "below the floor of" in p and "moto-server modules" in p for p in problems
    )


def test_a_module_that_shrank_below_its_own_floor_is_reported(moto):
    names = _healthy_names(moto)
    names = [n for n in names if "mcp_entrypoint_secrets" not in n]
    names += _names("test_deploy_mcp_entrypoint_secrets_moto_server", 2)
    problems = moto.evaluate_report(_clean_totals(len(names)), names)
    assert any(
        "test_deploy_mcp_entrypoint_secrets_moto_server, below its floor" in p
        for p in problems
    )


def test_the_terraform_copy_must_be_exercised_by_the_s3_module(moto):
    """At the base, any name containing -terraform anywhere in the suite satisfied the check."""
    s3 = "test_deploy_s3_sync_moto_server"
    names = _names(s3, 30, "[cdk-template]")
    names += _names("test_deploy_buildspec_ssm_moto_server", 11)
    names += _names("test_deploy_mcp_entrypoint_secrets_moto_server", 8)
    names += _names("test_terraform_merge_exit_codes", 3, "[terraform]")
    problems = moto.evaluate_report(_clean_totals(len(names)), names)
    assert any("'terraform' copy of the S3 helper" in p for p in problems)
    assert not any("'cdk-template' copy" in p for p in problems)


def test_failures_are_reported(moto):
    names = _healthy_names(moto)
    totals = _clean_totals(len(names))
    totals["failures"] = 2
    assert any("2 failure(s)" in p for p in moto.evaluate_report(totals, names))


def test_a_module_is_matched_as_a_whole_name_not_a_prefix(moto):
    """At the base, `module in name` let test_..._moto_server_v2 satisfy the S3 floor."""
    names = _healthy_names(moto)
    s3 = "test_deploy_s3_sync_moto_server"
    renamed = [n.replace(f".{s3}.", f".{s3}_v2.") for n in names if f".{s3}." in n]
    others = [n for n in names if f".{s3}." not in n]
    problems = moto.evaluate_report(_clean_totals(len(names)), others + renamed)
    assert any(f"no test ran from {s3}." in p for p in problems)


def test_a_skip_in_a_moto_module_is_a_problem(moto):
    names = _healthy_names(moto)
    totals = _clean_totals(len(names))
    totals["skipped"] = 1
    problems = moto.evaluate_report(totals, names, skipped=[names[0]])
    assert any("skipped in the moto-server modules" in p for p in problems)
    assert any(names[0] in p for p in problems)


def test_a_skip_in_an_unrelated_deploy_module_is_not_a_problem(moto):
    """At the base, main counted every skip in tests/unit/deploy against the gate."""
    names = _healthy_names(moto)
    unrelated = _names("test_deploy_gate_claims", 1)
    totals = _clean_totals(len(names) + 1)
    totals["skipped"] = 1
    assert moto.evaluate_report(totals, names + unrelated, skipped=unrelated) == []
