# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A checkov result says which resource it is about.

checkov's SARIF result names the rule, the file and the lines, and not the
resource. Two instances of one module, or two resources of a terraform plan
(every plan result is at line 1 of the plan file), gave results that differ in
nothing, and a suppression scoped to a resource (``scope.resource_id``) never
matched a checkov finding, because the finding carried no resource.

checkov's JSON report names the resource of every record. The scanner asks for
that report on every run and copies each record's resource to its SARIF result
under ``ash_resource_id``, the resource-identity contract of
``utils/package_identity.py``. An id that one file's records give at two line
ranges names two resources, so it is copied to neither. The records of the checks
that passed count as places, so a finding keeps or loses its id whichever of the
other checks fail.
"""

import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path
from urllib.parse import quote

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.models.core import AshSuppression
from automated_security_helper.models.flat_vulnerability import FlatVulnerability
from automated_security_helper.plugin_modules.ash_builtin.scanners.checkov_scanner import (
    CheckovScanner,
    CheckovScannerConfig,
    CheckovScannerConfigOptions,
    _NO_RESOURCE_FRAMEWORKS,
    _RESOURCE_FRAMEWORKS,
    attach_checkov_resources,
    checkov_resources,
)
from automated_security_helper.schemas.sarif_schema_model import SarifReport
from automated_security_helper.utils.package_identity import (
    ASH_RESOURCE_ID_KEY,
    extract_resource_identity,
)
from automated_security_helper.utils.scanner_names import SCANNER_TOOL_TYPES

pytestmark = pytest.mark.unit

PluginContext.model_rebuild()

CAPTURED = (
    Path(__file__).parents[3] / "test_data" / "scanners" / "checkov" / "resources"
)


def _record(check_id, path, lines, resource):
    return {
        "check_id": check_id,
        "repo_file_path": path,
        "file_line_range": list(lines),
        "resource": resource,
    }


def _report(check_type, failed=(), skipped=(), passed=()):
    return {
        "check_type": check_type,
        "results": {
            "failed_checks": list(failed),
            "skipped_checks": list(skipped),
            "passed_checks": list(passed),
        },
    }


def _result(rule_id, uri, start, end, **fields):
    return {
        "ruleId": rule_id,
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": uri},
                    "region": {"startLine": start, "endLine": end},
                }
            }
        ],
        **fields,
    }


def _sarif(*results):
    return {"version": "2.1.0", "runs": [{"results": list(results)}]}


def _resource(result):
    return (result.get("properties") or {}).get(ASH_RESOURCE_ID_KEY)


def _attach(sarif, *reports):
    return attach_checkov_resources(sarif, checkov_resources(list(reports)))


class TestAResultTakesTheResourceOfItsRecord:
    def test_two_resources_in_one_file_are_told_apart_by_their_lines(self):
        sarif = _sarif(
            _result("CKV_AWS_17", "tf/main.tf", 1, 7),
            _result("CKV_AWS_17", "tf/main.tf", 9, 16),
        )

        attached = _attach(
            sarif,
            _report(
                "terraform",
                failed=[
                    _record("CKV_AWS_17", "/tf/main.tf", (1, 7), "aws_db_instance.a"),
                    _record("CKV_AWS_17", "/tf/main.tf", (9, 16), "aws_db_instance.b"),
                ],
            ),
        )

        assert attached == 2
        assert [_resource(r) for r in sarif["runs"][0]["results"]] == [
            "aws_db_instance.a",
            "aws_db_instance.b",
        ]

    def test_two_plan_resources_at_the_same_place_are_told_apart_by_their_order(self):
        # A plan record has no lines: checkov writes 0 in the JSON report and 1
        # in the SARIF result, for every resource of the plan.
        sarif = _sarif(
            _result("CKV_AWS_17", "tfplan.json", 1, 1),
            _result("CKV_AWS_16", "tfplan.json", 1, 1),
            _result("CKV_AWS_17", "tfplan.json", 1, 1),
        )

        _attach(
            sarif,
            _report(
                "terraform_plan",
                failed=[
                    _record("CKV_AWS_17", "/tfplan.json", (0, 0), "module.db.x.this"),
                    _record("CKV_AWS_16", "/tfplan.json", (0, 0), "module.db.x.this"),
                    _record("CKV_AWS_17", "/tfplan.json", (0, 0), "module.db2.x.this"),
                ],
            ),
        )

        assert [_resource(r) for r in sarif["runs"][0]["results"]] == [
            "module.db.x.this",
            "module.db.x.this",
            "module.db2.x.this",
        ]

    def test_a_skipped_record_follows_the_failed_ones_as_in_the_sarif_report(self):
        sarif = _sarif(
            _result("CKV_X", "main.tf", 1, 1),
            _result("CKV_X", "main.tf", 1, 1, suppressions=[{"kind": "inSource"}]),
        )

        _attach(
            sarif,
            _report(
                "terraform",
                failed=[_record("CKV_X", "/main.tf", (1, 1), "failed.one")],
                skipped=[_record("CKV_X", "/main.tf", (1, 1), "skipped.one")],
            ),
        )

        assert [_resource(r) for r in sarif["runs"][0]["results"]] == [
            "failed.one",
            "skipped.one",
        ]

    def test_the_uri_is_matched_as_checkov_quotes_it(self):
        sarif = _sarif(_result("CKV_X", quote("my dir/main.tf"), 1, 2))

        _attach(
            sarif,
            _report(
                "terraform", failed=[_record("CKV_X", "/my dir/main.tf", (1, 2), "a.b")]
            ),
        )

        assert _resource(sarif["runs"][0]["results"][0]) == "a.b"

    def test_the_results_other_properties_are_kept(self):
        sarif = _sarif(_result("CKV_X", "main.tf", 1, 2, properties={"tags": ["x"]}))

        _attach(
            sarif,
            _report("terraform", failed=[_record("CKV_X", "/main.tf", (1, 2), "a.b")]),
        )

        assert sarif["runs"][0]["results"][0]["properties"] == {
            "tags": ["x"],
            ASH_RESOURCE_ID_KEY: "a.b",
        }

    def test_the_flat_finding_reads_it_as_its_resource_id(self):
        sarif = _sarif(_result("CKV_X", "main.tf", 1, 2))
        _attach(
            sarif,
            _report("terraform", failed=[_record("CKV_X", "/main.tf", (1, 2), "a.b")]),
        )

        resource_id, _ = extract_resource_identity(
            sarif["runs"][0]["results"][0]["properties"]
        )

        assert resource_id == "a.b"


class TestOnlyFrameworksThatNameAResource:
    @pytest.mark.parametrize("check_type", sorted(_RESOURCE_FRAMEWORKS))
    def test_a_resource_framework_gives_its_resource(self, check_type):
        sarif = _sarif(_result("CKV_X", "file", 3, 4))

        _attach(
            sarif, _report(check_type, failed=[_record("CKV_X", "/file", (3, 4), "R")])
        )

        assert _resource(sarif["runs"][0]["results"][0]) == "R"

    @pytest.mark.parametrize(
        "check_type, written",
        [
            # the dockerfile framework writes the path and the instruction
            ("dockerfile", "/Dockerfile.RUN"),
            # the secrets framework writes a 40-digit hash of the secret
            ("secrets", "0f" * 20),
            ("github_actions", "jobs(build)"),
            ("serverless", "complete"),
        ],
    )
    def test_another_framework_gives_none(self, check_type, written):
        sarif = _sarif(_result("CKV_X", "file", 3, 4))

        attached = _attach(
            sarif,
            _report(check_type, failed=[_record("CKV_X", "/file", (3, 4), written)]),
        )

        assert attached == 0
        assert "properties" not in sarif["runs"][0]["results"][0]

    @pytest.mark.parametrize("check_type", sorted(_NO_RESOURCE_FRAMEWORKS))
    def test_no_classified_framework_without_a_resource_gives_one(self, check_type):
        sarif = _sarif(_result("CKV_X", "file", 3, 4))

        attached = _attach(
            sarif,
            _report(check_type, failed=[_record("CKV_X", "/file", (3, 4), "R")]),
        )

        assert attached == 0
        assert "properties" not in sarif["runs"][0]["results"][0]

    def test_an_unclassified_framework_gives_none(self):
        # Fail closed: a runner checkov adds later is not trusted until it is
        # classified (the drift test below says so).
        sarif = _sarif(_result("CKV_X", "file", 3, 4))

        attached = _attach(
            sarif,
            _report("a_new_runner", failed=[_record("CKV_X", "/file", (3, 4), "R")]),
        )

        assert attached == 0


class TestEveryCheckovFrameworkIsClassified:
    def test_the_frameworks_that_name_a_resource_are_pinned(self):
        # A framework is listed only after its ids were shown to name one
        # resource in a file, so a change to the list is a reviewed change.
        assert _RESOURCE_FRAMEWORKS == frozenset(
            {"terraform", "terraform_plan", "cloudformation", "kubernetes", "bicep"}
        )

    @pytest.mark.parametrize("check_type", ["arm", "terraform_json"])
    def test_arm_and_terraform_json_are_classified_as_naming_none(self, check_type):
        assert check_type in _NO_RESOURCE_FRAMEWORKS
        assert check_type not in _RESOURCE_FRAMEWORKS

    def test_the_two_sets_do_not_overlap(self):
        assert _RESOURCE_FRAMEWORKS.isdisjoint(_NO_RESOURCE_FRAMEWORKS)

    def test_every_denied_framework_says_why(self):
        assert all(reason.strip() for reason in _NO_RESOURCE_FRAMEWORKS.values())

    def test_checkovs_runners_are_all_in_one_of_the_sets(self, tmp_path):
        # Needs checkov in the environment: ASH installs it on first scan, so a
        # development environment may not have it. It is read in a child with its
        # own HOME, because importing checkov writes its update-check cache there.
        if importlib.util.find_spec("checkov") is None:
            pytest.skip("checkov is not installed")
        child = subprocess.run(
            [
                sys.executable,
                "-I",
                "-c",
                (
                    "import checkov.main as m, json;"
                    "print(json.dumps([r.check_type for r in m.DEFAULT_RUNNERS]))"
                ),
            ],
            env={**os.environ, "HOME": str(tmp_path), "XDG_CACHE_HOME": str(tmp_path)},
            capture_output=True,
            text=True,
            timeout=120,
            check=True,
        )
        runners = set(json.loads(child.stdout.strip().splitlines()[-1]))

        unclassified = runners - _RESOURCE_FRAMEWORKS - set(_NO_RESOURCE_FRAMEWORKS)
        gone = (_RESOURCE_FRAMEWORKS | set(_NO_RESOURCE_FRAMEWORKS)) - runners

        assert not unclassified, (
            f"checkov has runners {sorted(unclassified)} that checkov_scanner.py "
            "does not classify: read a record of each and add it to "
            "_RESOURCE_FRAMEWORKS (its resource names an infrastructure "
            "resource) or _NO_RESOURCE_FRAMEWORKS (with the reason)"
        )
        assert not gone, f"classified but no longer a checkov runner: {sorted(gone)}"


class TestAKeyTheReportsDisagreeOnGetsNoResource:
    """A wrong resource would bind a suppression to a finding it was not written
    for. A missing one only leaves a resource-scoped suppression unmatched."""

    def test_more_results_than_records(self):
        sarif = _sarif(
            _result("CKV_X", "tfplan.json", 1, 1),
            _result("CKV_X", "tfplan.json", 1, 1),
        )

        attached = _attach(
            sarif,
            _report(
                "terraform_plan",
                failed=[_record("CKV_X", "/tfplan.json", (0, 0), "a.b")],
            ),
        )

        assert attached == 0
        assert [_resource(r) for r in sarif["runs"][0]["results"]] == [None, None]

    def test_more_records_than_results(self):
        sarif = _sarif(_result("CKV_X", "tfplan.json", 1, 1))

        attached = _attach(
            sarif,
            _report(
                "terraform_plan",
                failed=[
                    _record("CKV_X", "/tfplan.json", (0, 0), "a.b"),
                    _record("CKV_X", "/tfplan.json", (0, 0), "c.d"),
                ],
            ),
        )

        assert attached == 0

    def test_a_record_of_another_framework_with_the_key_counts(self):
        # Two frameworks report one rule at one place: the n-th result is still
        # the n-th record, and only the resource framework's one is named.
        sarif = _sarif(_result("CKV_X", "file", 1, 1), _result("CKV_X", "file", 1, 1))

        _attach(
            sarif,
            _report(
                "dockerfile", failed=[_record("CKV_X", "/file", (1, 1), "/file.RUN")]
            ),
            _report("terraform", failed=[_record("CKV_X", "/file", (1, 1), "a.b")]),
        )

        assert [_resource(r) for r in sarif["runs"][0]["results"]] == [None, "a.b"]

    def test_the_other_keys_are_still_named(self):
        sarif = _sarif(
            _result("CKV_X", "tfplan.json", 1, 1),
            _result("CKV_X", "tfplan.json", 1, 1),
            _result("CKV_Y", "main.tf", 5, 9),
        )

        attached = _attach(
            sarif,
            _report(
                "terraform_plan",
                failed=[_record("CKV_X", "/tfplan.json", (0, 0), "a.b")],
            ),
            _report("terraform", failed=[_record("CKV_Y", "/main.tf", (5, 9), "c.d")]),
        )

        assert attached == 1
        assert _resource(sarif["runs"][0]["results"][2]) == "c.d"


#: The id checkov gives a resource named by a template parameter that has no
#: default: the name stays the expression, so it is the same for every resource
#: of the type that the expression names.
SHARED_ID = "Microsoft.Storage/storageAccounts.[parameters('n')]"


class TestAnIdTwoResourcesOfAFileShareNamesNeither:
    """Every check on one resource gives that resource's lines, so one id at two
    line ranges of one file is two resources that share it. A suppression scoped
    to it would cover the findings of both, so neither is given it."""

    @pytest.mark.parametrize("check_type", sorted(_RESOURCE_FRAMEWORKS))
    def test_one_id_at_two_line_ranges_names_neither(self, check_type):
        sarif = _sarif(
            _result("CKV_AZURE_33", "main.json", 5, 20),
            _result("CKV_AZURE_33", "main.json", 21, 36),
        )

        attached = _attach(
            sarif,
            _report(
                check_type,
                failed=[
                    _record("CKV_AZURE_33", "/main.json", (5, 20), SHARED_ID),
                    _record("CKV_AZURE_33", "/main.json", (21, 36), SHARED_ID),
                ],
            ),
        )

        assert attached == 0
        assert [_resource(r) for r in sarif["runs"][0]["results"]] == [None, None]

    @pytest.mark.parametrize("check_type", sorted(_RESOURCE_FRAMEWORKS))
    def test_control_two_ids_at_two_line_ranges_are_both_named(self, check_type):
        first = "Microsoft.Storage/storageAccounts.[parameters('a')]"
        second = "Microsoft.Storage/storageAccounts.[parameters('b')]"
        sarif = _sarif(
            _result("CKV_AZURE_33", "main.json", 5, 20),
            _result("CKV_AZURE_33", "main.json", 21, 36),
        )

        attached = _attach(
            sarif,
            _report(
                check_type,
                failed=[
                    _record("CKV_AZURE_33", "/main.json", (5, 20), first),
                    _record("CKV_AZURE_33", "/main.json", (21, 36), second),
                ],
            ),
        )

        assert attached == 2
        assert [_resource(r) for r in sarif["runs"][0]["results"]] == [first, second]

    def test_the_two_resources_need_not_fail_the_same_check(self):
        # No key repeats: each check fails on one resource only. The line
        # ranges are what show that the id names two resources.
        sarif = _sarif(
            _result("CKV_AZURE_33", "main.json", 5, 20),
            _result("CKV_AZURE_35", "main.json", 21, 36),
        )

        attached = _attach(
            sarif,
            _report(
                "bicep",
                failed=[
                    _record("CKV_AZURE_33", "/main.json", (5, 20), SHARED_ID),
                    _record("CKV_AZURE_35", "/main.json", (21, 36), SHARED_ID),
                ],
            ),
        )

        assert attached == 0

    def test_a_skipped_record_is_one_of_the_places(self):
        sarif = _sarif(
            _result("CKV_AZURE_33", "main.json", 5, 20),
            _result(
                "CKV_AZURE_33",
                "main.json",
                21,
                36,
                suppressions=[{"kind": "inSource"}],
            ),
        )

        attached = _attach(
            sarif,
            _report(
                "bicep",
                failed=[_record("CKV_AZURE_33", "/main.json", (5, 20), SHARED_ID)],
                skipped=[_record("CKV_AZURE_33", "/main.json", (21, 36), SHARED_ID)],
            ),
        )

        assert attached == 0

    def test_control_one_resource_that_several_checks_flag_keeps_its_id(self):
        sarif = _sarif(
            _result("CKV_AZURE_33", "main.json", 5, 20),
            _result("CKV_AZURE_35", "main.json", 5, 20),
        )

        attached = _attach(
            sarif,
            _report(
                "bicep",
                failed=[
                    _record("CKV_AZURE_33", "/main.json", (5, 20), SHARED_ID),
                    _record("CKV_AZURE_35", "/main.json", (5, 20), SHARED_ID),
                ],
            ),
        )

        assert attached == 2
        assert {_resource(r) for r in sarif["runs"][0]["results"]} == {SHARED_ID}

    def test_control_one_id_in_two_files_is_named_in_each(self):
        # A suppression names its path, so the same id in another file is
        # another suppression's.
        sarif = _sarif(
            _result("CKV_AZURE_33", "a.json", 5, 20),
            _result("CKV_AZURE_33", "b.json", 21, 36),
        )

        attached = _attach(
            sarif,
            _report(
                "bicep",
                failed=[
                    _record("CKV_AZURE_33", "/a.json", (5, 20), SHARED_ID),
                    _record("CKV_AZURE_33", "/b.json", (21, 36), SHARED_ID),
                ],
            ),
        )

        assert attached == 2

    def test_the_other_resources_of_the_file_are_still_named(self):
        sarif = _sarif(
            _result("CKV_AZURE_33", "main.json", 5, 20),
            _result("CKV_AZURE_33", "main.json", 21, 36),
            _result("CKV_AZURE_33", "main.json", 40, 52),
        )

        attached = _attach(
            sarif,
            _report(
                "bicep",
                failed=[
                    _record("CKV_AZURE_33", "/main.json", (5, 20), SHARED_ID),
                    _record("CKV_AZURE_33", "/main.json", (21, 36), SHARED_ID),
                    _record(
                        "CKV_AZURE_33",
                        "/main.json",
                        (40, 52),
                        "Microsoft.Storage/storageAccounts.st",
                    ),
                ],
            ),
        )

        assert attached == 1
        assert [_resource(r) for r in sarif["runs"][0]["results"]] == [
            None,
            None,
            "Microsoft.Storage/storageAccounts.st",
        ]


class TestWhetherAnIdIsSharedDoesNotDependOnWhichChecksFail:
    """checkov's JSON report lists the checks that passed as well as the ones that
    failed or were skipped, and a check gives the lines of the resource it ran on
    whichever way it went. So the places of a resource are read from every record
    of a file. Read from the failed and skipped records alone, a finding kept its
    id while the check at the resource's other place passed and lost it when that
    check started to fail: the id of a finding depended on which other checks
    failed. A check that passed has no result in the SARIF report, so it counts as
    a place and is not an entry of any key."""

    @pytest.mark.parametrize("check_type", sorted(_RESOURCE_FRAMEWORKS))
    def test_a_check_that_passed_at_another_place_is_one_of_the_places(
        self, check_type
    ):
        """One id at two line ranges is two resources that share it, also when the
        check at the second range passed: the finding at the first range does not
        carry the id, as it does not when that check failed."""
        sarif = _sarif(_result("CKV_AZURE_33", "main.json", 5, 20))

        attached = _attach(
            sarif,
            _report(
                check_type,
                failed=[_record("CKV_AZURE_33", "/main.json", (5, 20), SHARED_ID)],
                passed=[_record("CKV_AZURE_35", "/main.json", (21, 36), SHARED_ID)],
            ),
        )

        assert attached == 0
        assert [_resource(r) for r in sarif["runs"][0]["results"]] == [None]

    def test_the_check_that_passed_may_be_at_the_first_place(self):
        """The order of the two places does not matter: the finding at the second
        range loses the id when the check at the first range passed."""
        sarif = _sarif(_result("CKV_AZURE_33", "main.json", 21, 36))

        attached = _attach(
            sarif,
            _report(
                "bicep",
                failed=[_record("CKV_AZURE_33", "/main.json", (21, 36), SHARED_ID)],
                passed=[_record("CKV_AZURE_35", "/main.json", (5, 20), SHARED_ID)],
            ),
        )

        assert attached == 0
        assert [_resource(r) for r in sarif["runs"][0]["results"]] == [None]

    def test_a_skipped_finding_loses_its_id_to_a_check_that_passed_elsewhere(self):
        """A skipped record is a finding too, and is dropped the same way."""
        sarif = _sarif(
            _result(
                "CKV_AZURE_33", "main.json", 5, 20, suppressions=[{"kind": "inSource"}]
            )
        )

        attached = _attach(
            sarif,
            _report(
                "bicep",
                skipped=[_record("CKV_AZURE_33", "/main.json", (5, 20), SHARED_ID)],
                passed=[_record("CKV_AZURE_35", "/main.json", (21, 36), SHARED_ID)],
            ),
        )

        assert attached == 0
        assert [_resource(r) for r in sarif["runs"][0]["results"]] == [None]

    def test_the_check_that_passed_is_not_an_entry_of_any_key(self):
        """The SARIF report has no result for a check that passed, so its record is
        read for its place and given no entry: the failed record keeps its one
        entry, now None, and no key is made for the passed one."""
        report = _report(
            "bicep",
            failed=[_record("CKV_AZURE_33", "/main.json", (5, 20), SHARED_ID)],
            passed=[_record("CKV_AZURE_35", "/main.json", (21, 36), SHARED_ID)],
        )

        assert checkov_resources([report]) == {
            ("CKV_AZURE_33", "main.json", 5, 20): [None]
        }

    def test_control_two_failed_places_still_name_neither(self):
        """The case that was already handled: the check at each place failed."""
        sarif = _sarif(
            _result("CKV_AZURE_33", "main.json", 5, 20),
            _result("CKV_AZURE_35", "main.json", 21, 36),
        )

        attached = _attach(
            sarif,
            _report(
                "bicep",
                failed=[
                    _record("CKV_AZURE_33", "/main.json", (5, 20), SHARED_ID),
                    _record("CKV_AZURE_35", "/main.json", (21, 36), SHARED_ID),
                ],
            ),
        )

        assert attached == 0
        assert [_resource(r) for r in sarif["runs"][0]["results"]] == [None, None]

    def test_control_one_place_keeps_its_id_whatever_else_passes_or_fails(self):
        """A resource at one line range keeps its id whichever way its own checks
        went, and whichever way the checks of the file's other resources went."""
        mine = "Microsoft.Storage/storageAccounts.mine"
        sibling = "Microsoft.Storage/storageAccounts.sibling"
        quiet = "Microsoft.Storage/storageAccounts.quiet"
        clean = "Microsoft.Storage/storageAccounts.clean"
        sarif = _sarif(
            _result("CKV_AZURE_33", "main.json", 5, 20),
            _result("CKV_AZURE_33", "main.json", 40, 52),
            _result(
                "CKV_AZURE_35", "main.json", 60, 70, suppressions=[{"kind": "inSource"}]
            ),
        )

        attached = _attach(
            sarif,
            _report(
                "bicep",
                failed=[
                    _record("CKV_AZURE_33", "/main.json", (5, 20), mine),
                    _record("CKV_AZURE_33", "/main.json", (40, 52), sibling),
                ],
                skipped=[_record("CKV_AZURE_35", "/main.json", (60, 70), quiet)],
                passed=[
                    # another check on the same resource, at its own lines
                    _record("CKV_AZURE_35", "/main.json", (5, 20), mine),
                    # a resource of the file that no check failed on
                    _record("CKV_AZURE_33", "/main.json", (21, 36), clean),
                    _record("CKV_AZURE_35", "/main.json", (21, 36), clean),
                ],
            ),
        )

        assert attached == 3
        assert [_resource(r) for r in sarif["runs"][0]["results"]] == [
            mine,
            sibling,
            quiet,
        ]

    def test_control_a_check_that_passed_in_another_file_is_not_a_place(self):
        """The same id in another file is another suppression's, as for a check
        that failed there."""
        sarif = _sarif(_result("CKV_AZURE_33", "a.json", 5, 20))

        attached = _attach(
            sarif,
            _report(
                "bicep",
                failed=[_record("CKV_AZURE_33", "/a.json", (5, 20), SHARED_ID)],
                passed=[_record("CKV_AZURE_35", "/b.json", (21, 36), SHARED_ID)],
            ),
        )

        assert attached == 1
        assert [_resource(r) for r in sarif["runs"][0]["results"]] == [SHARED_ID]

    def test_control_a_check_of_a_framework_naming_no_resource_is_not_a_place(self):
        """A record of a framework that names no resource gives no id, so it gives
        no place either, whatever its resource field holds."""
        sarif = _sarif(_result("CKV_AWS_17", "main.tf", 1, 7))
        db = "aws_db_instance.a"

        attached = _attach(
            sarif,
            _report(
                "terraform",
                failed=[_record("CKV_AWS_17", "/main.tf", (1, 7), db)],
            ),
            _report(
                "secrets",
                passed=[_record("CKV_SECRET_1", "/main.tf", (9, 16), db)],
            ),
        )

        assert attached == 1
        assert [_resource(r) for r in sarif["runs"][0]["results"]] == [db]

    def test_control_a_passed_check_takes_no_place_in_the_order_of_a_key(self):
        """In a plan every record is at line 1, so one rule's records of several
        resources share a key. Only the failed one has a result in the SARIF
        report, and the result takes the entry of the record at its position: an
        entry made for the passed record would hand it another resource's id."""
        passed_on, failed_on = "module.db.x.this", "module.db2.x.this"
        sarif = _sarif(_result("CKV_AWS_17", "tfplan.json", 1, 1))
        report = _report(
            "terraform_plan",
            failed=[_record("CKV_AWS_17", "/tfplan.json", (0, 0), failed_on)],
            passed=[_record("CKV_AWS_17", "/tfplan.json", (0, 0), passed_on)],
        )

        assert checkov_resources([report]) == {
            ("CKV_AWS_17", "tfplan.json", 1, 1): [failed_on]
        }
        assert attach_checkov_resources(sarif, checkov_resources([report])) == 1
        assert [_resource(r) for r in sarif["runs"][0]["results"]] == [failed_on]

    @pytest.mark.parametrize(
        "passed",
        [
            "text",
            None,
            7,
            {"a": 1},
            [None, "x", 3],
            [{"check_id": "C", "resource": "r"}],
            [_record("C", "/a.json", (5, 6), None)],
            [_record("C", "/a.json", (5, 6), 7)],
        ],
    )
    def test_control_a_passed_list_of_another_shape_is_read_for_what_it_holds(
        self, passed
    ):
        """A passed list that is not a list of records, a record without its key
        and a record with no resource text add no place, and no error."""
        report = _report("bicep", failed=[_record("C", "/a.json", (1, 2), "r")])
        report["results"]["passed_checks"] = passed

        assert checkov_resources([report]) == {("C", "a.json", 1, 2): ["r"]}


def _scanned(first_id, second_id):
    """The flat findings of two records of one rule in one file, with these ids."""
    sarif = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "Checkov"}},
                "results": [
                    _result("CKV_AZURE_33", "main.json", 5, 20, message={"text": "m"}),
                    _result("CKV_AZURE_33", "main.json", 21, 36, message={"text": "m"}),
                ],
            }
        ],
    }
    _attach(
        sarif,
        _report(
            "bicep",
            failed=[
                _record("CKV_AZURE_33", "/main.json", (5, 20), first_id),
                _record("CKV_AZURE_33", "/main.json", (21, 36), second_id),
            ],
        ),
    )
    report = SarifReport.model_validate(json.loads(json.dumps(sarif)))
    return [
        FlatVulnerability.from_sarif_result(
            result, "checkov", SCANNER_TOOL_TYPES["checkov"], report.runs[0]
        )
        for result in report.runs[0].results
    ]


def _suppression(**fields):
    return AshSuppression.model_validate(
        {"path": "main.json", "reason": "test", **fields}
    )


class TestAResourceScopedSuppressionCoversOnlyItsResource:
    def test_a_suppression_for_a_shared_id_cannot_cover_the_second_record(self):
        first, second = _scanned(SHARED_ID, SHARED_ID)
        entry = _suppression(scope={"resource_id": SHARED_ID})

        assert not entry.matches(second)
        assert not entry.matches(first)

    def test_path_and_lines_still_cover_the_first_record_alone(self):
        first, second = _scanned(SHARED_ID, SHARED_ID)
        entry = _suppression(line_start=5, line_end=20)

        assert entry.matches(first)
        assert not entry.matches(second)

    def test_control_a_unique_id_binds_the_suppression_to_its_record(self):
        first, second = _scanned(
            SHARED_ID, "Microsoft.Storage/storageAccounts.[parameters('other')]"
        )
        entry = _suppression(scope={"resource_id": SHARED_ID})

        assert first.resource_id == SHARED_ID
        assert entry.matches(first)
        assert not entry.matches(second)


class TestAReportThatIsNotAsExpectedIsReadForWhatItHolds:
    @pytest.mark.parametrize(
        "report",
        [
            None,
            "text",
            [],
            {},
            {"check_type": "terraform"},
            {"check_type": "terraform", "results": []},
            {"check_type": "terraform", "results": {"failed_checks": "text"}},
            {"check_type": "terraform", "results": {"failed_checks": [None, "x", 3]}},
        ],
    )
    def test_a_json_report_of_another_shape_names_nothing(self, report):
        assert checkov_resources(report) == {}

    @pytest.mark.parametrize(
        "record",
        [
            {"repo_file_path": "/a.tf", "file_line_range": [1, 2], "resource": "r"},
            {"check_id": "C", "file_line_range": [1, 2], "resource": "r"},
            {"check_id": "C", "repo_file_path": "/a.tf", "resource": "r"},
            {"check_id": "C", "repo_file_path": "/a.tf", "file_line_range": [1]},
            {"check_id": "C", "repo_file_path": "/a.tf", "file_line_range": ["x", 2]},
            {"check_id": 7, "repo_file_path": "/a.tf", "file_line_range": [1, 2]},
        ],
    )
    def test_a_record_without_a_key_is_left_out(self, record):
        assert checkov_resources([_report("terraform", failed=[record])]) == {}

    @pytest.mark.parametrize("resource", [None, "", 7, ["a"]])
    def test_a_record_with_no_resource_text_names_none_and_still_counts(self, resource):
        found = checkov_resources(
            [_report("terraform", failed=[_record("C", "/a.tf", (1, 2), resource)])]
        )

        assert found == {("C", "a.tf", 1, 2): [None]}

    @pytest.mark.parametrize(
        "sarif",
        [None, "text", [], {}, {"runs": None}, {"runs": [None, {"results": None}]}],
    )
    def test_a_sarif_of_another_shape_is_left_as_it_is(self, sarif):
        resources = {("C", "a.tf", 1, 2): ["r"]}

        assert attach_checkov_resources(sarif, resources) == 0

    @pytest.mark.parametrize(
        "result",
        [
            None,
            {"ruleId": "C"},
            {"ruleId": "C", "locations": []},
            {"ruleId": "C", "locations": [{}]},
            {"ruleId": "C", "locations": ["text"]},
            {"ruleId": "C", "locations": [{"physicalLocation": "text"}]},
            {
                "ruleId": "C",
                "locations": [
                    {"physicalLocation": {"artifactLocation": "a.tf", "region": {}}}
                ],
            },
            {
                "ruleId": "C",
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": "a.tf"},
                            "region": "1-2",
                        }
                    }
                ],
            },
            {
                "locations": [
                    {"physicalLocation": {"artifactLocation": {"uri": "a.tf"}}}
                ]
            },
            _result("C", "a.tf", "1", 2),
            _result("C", "a.tf", True, 2),
        ],
    )
    def test_a_result_without_a_key_is_left_as_it_is(self, result):
        sarif = {"runs": [{"results": [result]}]}
        before = json.dumps(sarif)

        assert attach_checkov_resources(sarif, {("C", "a.tf", 1, 2): ["r"]}) == 0
        assert json.dumps(sarif) == before

    def test_no_json_report_leaves_the_sarif_as_it_is(self):
        sarif = _sarif(_result("C", "a.tf", 1, 2))
        before = json.dumps(sarif)

        assert attach_checkov_resources(sarif, {}) == 0
        assert json.dumps(sarif) == before


class TestTheReportsCheckovWrote:
    """``tests/test_data/scanners/checkov/resources``: what checkov 3.4.6 wrote
    for a tree with terraform, a plan, cloudformation, kubernetes and a
    Dockerfile. Its README has the command."""

    @pytest.fixture
    def named(self):
        sarif = json.loads((CAPTURED / "results_sarif.sarif").read_text("utf-8"))
        report = json.loads((CAPTURED / "results_json.json").read_text("utf-8"))
        attached = attach_checkov_resources(sarif, checkov_resources(report))
        return sarif["runs"][0]["results"], report, attached

    def test_the_sarif_report_names_no_resource_itself(self):
        text = (CAPTURED / "results_sarif.sarif").read_text("utf-8")

        assert "aws_db_instance" not in text
        assert "module.db2" not in text

    def test_every_result_of_a_resource_framework_is_named(self, named):
        results, report, attached = named
        expected = sum(
            len(r["results"]["failed_checks"]) + len(r["results"]["skipped_checks"])
            for r in report
            if r["check_type"] != "dockerfile"
        )

        assert attached == expected == 76
        assert sum(1 for r in results if _resource(r)) == 76

    def test_the_two_reports_agree_result_by_result(self, named):
        results, report, _ = named
        in_order = [
            None if r["check_type"] == "dockerfile" else record["resource"]
            for r in report
            for kind in ("failed_checks", "skipped_checks")
            for record in r["results"][kind]
        ]

        assert [_resource(r) for r in results] == in_order

    def test_the_two_instances_of_the_module_in_the_plan_are_told_apart(self, named):
        results, _, _ = named
        on_the_plan = {
            _resource(r)
            for r in results
            if r["ruleId"] == "CKV_AWS_17"
            and r["locations"][0]["physicalLocation"]["artifactLocation"][
                "uri"
            ].endswith("tfplan.json")
        }

        assert on_the_plan == {
            "module.db.aws_db_instance.this",
            "module.db2.aws_db_instance.this",
        }

    def test_the_skipped_result_is_named_too(self, named):
        results, _, _ = named
        (skipped,) = [r for r in results if r.get("suppressions")]

        assert _resource(skipped) == "aws_db_instance.b"

    def test_each_framework_names_its_resource_in_its_own_form(self, named):
        results, _, _ = named
        resources = {_resource(r) for r in results}

        assert "aws_db_instance.a" in resources
        assert "AWS::S3::Bucket.Bucket" in resources
        assert "Deployment.shop.web" in resources

    def test_the_dockerfile_results_are_not_named(self, named):
        results, _, _ = named
        on_the_dockerfile = [
            r
            for r in results
            if r["locations"][0]["physicalLocation"]["artifactLocation"][
                "uri"
            ].endswith("Dockerfile")
        ]

        assert len(on_the_dockerfile) == 4
        assert not any(_resource(r) for r in on_the_dockerfile)


def _scanner(source: Path, output: Path, **opts) -> CheckovScanner:
    context = PluginContext(
        source_dir=source,
        output_dir=output,
        work_dir=output / "converted",
        config=AshConfig(),
    )
    return CheckovScanner(
        context=context,
        config=CheckovScannerConfig(options=CheckovScannerConfigOptions(**opts)),
    )


def _output_formats(scanner: CheckovScanner) -> list[str]:
    return [arg.value for arg in scanner.args.extra_args if arg.key == "--output"]


class TestTheScannerAsksForTheJsonReport:
    def test_on_every_run(self, tmp_path):
        scanner = _scanner(tmp_path, tmp_path / "out")

        assert _output_formats(scanner) == ["cyclonedx_json", "json"]

    def test_once_when_the_options_ask_for_it_as_well(self, tmp_path):
        scanner = _scanner(
            tmp_path, tmp_path / "out", additional_formats=["json", "csv"]
        )

        assert _output_formats(scanner) == ["json", "csv"]

    def test_when_the_options_ask_for_no_other_format(self, tmp_path):
        scanner = _scanner(tmp_path, tmp_path / "out", additional_formats=[])

        assert _output_formats(scanner) == ["json"]


@pytest.mark.skipif(os.name == "nt", reason="POSIX paths")
class TestTheScannerReadsBothReports:
    """checkov runs from the filesystem root, so it writes each path as the
    absolute path without its leading ``/``. The resources are matched on those
    paths and the paths are then rewritten relative to the source directory."""

    def _reports(self, tmp_path, **opts):
        source = tmp_path / "src"
        source.mkdir()
        (source / "tfplan.json").write_text("{}", encoding="utf-8")
        scanner = _scanner(source, tmp_path / "out", **opts)
        results_dir = Path(scanner.results_dir) / "source"
        results_dir.mkdir(parents=True, exist_ok=True)
        written = (source / "tfplan.json").as_posix()
        results_file = results_dir / "results_sarif.sarif"
        results_file.write_text(
            json.dumps(
                _sarif(
                    _result("CKV_AWS_17", quote(written.lstrip("/")), 1, 1),
                    _result("CKV_AWS_17", quote(written.lstrip("/")), 1, 1),
                )
            ),
            encoding="utf-8",
        )
        records = [
            {
                **_record("CKV_AWS_17", written, (0, 0), resource),
                "file_abs_path": written,
            }
            for resource in ("module.db.x.this", "module.db2.x.this")
        ]
        return scanner, results_file, records

    def test_each_result_is_named_and_its_path_is_rewritten(self, tmp_path):
        scanner, results_file, records = self._reports(tmp_path)
        (results_file.parent / "results_json.json").write_text(
            json.dumps([_report("terraform_plan", failed=records)]), encoding="utf-8"
        )
        scanner._checkov_cwd = Path("/")
        scanner._checkov_target = tmp_path / "src"

        raw = scanner._read_results_file(results_file)

        results = raw["runs"][0]["results"]
        assert [_resource(r) for r in results] == [
            "module.db.x.this",
            "module.db2.x.this",
        ]
        assert {
            r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
            for r in results
        } == {"tfplan.json"}

    def test_a_default_run_rewrites_the_json_report_checkov_always_writes(
        self, tmp_path
    ):
        # additional_formats is left at its default (CycloneDX JSON only), yet
        # checkov writes results_json.json on every run. Left as checkov wrote
        # it, its paths would be the host's root-relative ones, which match
        # neither the SARIF nor a suppression.
        scanner, results_file, records = self._reports(tmp_path)
        assert "json" not in scanner.config.options.additional_formats
        json_report = results_file.parent / "results_json.json"
        json_report.write_text(
            json.dumps([_report("terraform_plan", failed=records)]), encoding="utf-8"
        )
        scanner._checkov_cwd = Path("/")
        scanner._checkov_target = tmp_path / "src"

        raw = scanner._read_results_file(results_file)

        assert [_resource(r) for r in raw["runs"][0]["results"]] == [
            "module.db.x.this",
            "module.db2.x.this",
        ]
        rewritten = json.loads(json_report.read_text(encoding="utf-8"))
        assert {
            r["repo_file_path"] for r in rewritten[0]["results"]["failed_checks"]
        } == {"/tfplan.json"}

    def test_a_json_report_the_operator_asked_for_is_rewritten(self, tmp_path):
        scanner, results_file, records = self._reports(
            tmp_path, additional_formats=["json"]
        )
        json_report = results_file.parent / "results_json.json"
        json_report.write_text(
            json.dumps([_report("terraform_plan", failed=records)]), encoding="utf-8"
        )
        scanner._checkov_cwd = Path("/")
        scanner._checkov_target = tmp_path / "src"

        scanner._read_results_file(results_file)

        rewritten = json.loads(json_report.read_text(encoding="utf-8"))
        assert {
            r["repo_file_path"] for r in rewritten[0]["results"]["failed_checks"]
        } == {"/tfplan.json"}

    def test_without_a_json_report_the_results_are_read_as_before(self, tmp_path):
        scanner, results_file, _ = self._reports(tmp_path)
        scanner._checkov_cwd = Path("/")
        scanner._checkov_target = tmp_path / "src"

        raw = scanner._read_results_file(results_file)

        results = raw["runs"][0]["results"]
        assert [_resource(r) for r in results] == [None, None]
        assert {
            r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
            for r in results
        } == {"tfplan.json"}

    def test_a_json_report_that_cannot_be_read_costs_only_the_resources(
        self, tmp_path, caplog
    ):
        scanner, results_file, _ = self._reports(tmp_path)
        (results_file.parent / "results_json.json").write_text("{", encoding="utf-8")
        scanner._checkov_cwd = Path("/")
        scanner._checkov_target = tmp_path / "src"

        raw = scanner._read_results_file(results_file)

        assert [_resource(r) for r in raw["runs"][0]["results"]] == [None, None]


class TestTheScannerReadsTheChecksThatPassed:
    """checkov writes the checks that passed into its JSON report, and nothing in
    the command line the scanner builds asks it to leave them out, so the report
    the scanner reads holds the places those checks give."""

    @pytest.mark.parametrize("flag", ["--quiet", "-q", "--compact"])
    def test_control_the_command_line_asks_for_no_flag_that_drops_them(
        self, tmp_path, flag
    ):
        scanner = _scanner(tmp_path, tmp_path / "out")

        assert flag not in {arg.key for arg in scanner.args.extra_args}

    @pytest.mark.skipif(os.name == "nt", reason="POSIX paths")
    def test_a_finding_loses_its_id_to_a_check_that_passed_at_another_place(
        self, tmp_path
    ):
        source = tmp_path / "src"
        source.mkdir()
        scanner = _scanner(source, tmp_path / "out", additional_formats=["json"])
        results_dir = Path(scanner.results_dir) / "source"
        results_dir.mkdir(parents=True, exist_ok=True)
        written = (source / "main.json").as_posix()
        results_file = results_dir / "results_sarif.sarif"
        results_file.write_text(
            json.dumps(
                _sarif(_result("CKV_AZURE_33", quote(written.lstrip("/")), 5, 20))
            ),
            encoding="utf-8",
        )
        failed = {
            **_record("CKV_AZURE_33", written, (5, 20), SHARED_ID),
            "file_abs_path": written,
        }
        passed = {
            **_record("CKV_AZURE_35", written, (21, 36), SHARED_ID),
            "file_abs_path": written,
        }
        (results_dir / "results_json.json").write_text(
            json.dumps([_report("bicep", failed=[failed], passed=[passed])]),
            encoding="utf-8",
        )
        scanner._checkov_cwd = Path("/")
        scanner._checkov_target = source

        raw = scanner._read_results_file(results_file)

        assert [_resource(r) for r in raw["runs"][0]["results"]] == [None]


class TestANameThatIsNotUtf8CostsNothing:
    """json.load turns the ``\\udcXX`` escape of a non-UTF-8 file name into a lone
    surrogate. The key of its record is built as checkov builds the SARIF URI, the
    bytes percent-encoded, as the path rewrite already reads them."""

    def test_the_key_percent_encodes_the_bytes_of_the_name(self):
        found = checkov_resources(
            [
                _report(
                    "terraform", failed=[_record("C", "/d/bad\udcff.tf", (1, 2), "r.x")]
                )
            ]
        )

        assert found == {("C", "d/bad%FF.tf", 1, 2): ["r.x"]}

    @pytest.mark.parametrize("check_type", [["terraform"], {"a": 1}, 7, None])
    def test_a_check_type_that_is_not_text_names_none_and_still_counts(
        self, check_type
    ):
        found = checkov_resources(
            [_report(check_type, failed=[_record("C", "/a.tf", (1, 2), "r.x")])]
        )

        assert found == {("C", "a.tf", 1, 2): [None]}

    @pytest.mark.skipif(os.name == "nt", reason="POSIX paths")
    def test_the_scanner_keeps_the_rewrite_and_the_resource(self, tmp_path):
        source = tmp_path / "src"
        source.mkdir()
        scanner = _scanner(source, tmp_path / "out", additional_formats=["json"])
        results_dir = Path(scanner.results_dir) / "source"
        results_dir.mkdir(parents=True, exist_ok=True)
        written = (source / "bad\udcff.tf").as_posix()
        results_file = results_dir / "results_sarif.sarif"
        results_file.write_text(
            json.dumps(
                _sarif(
                    _result(
                        "CKV_AWS_17",
                        quote(written.lstrip("/"), errors="surrogateescape"),
                        1,
                        2,
                    )
                )
            ),
            encoding="utf-8",
        )
        record = {
            **_record("CKV_AWS_17", written, (1, 2), "aws_db_instance.this"),
            "file_abs_path": written,
        }
        json_report = results_file.parent / "results_json.json"
        json_report.write_text(
            json.dumps([_report("terraform", failed=[record])]), encoding="utf-8"
        )
        scanner._checkov_cwd = Path("/")
        scanner._checkov_target = source

        raw = scanner._read_results_file(results_file)

        assert [_resource(r) for r in raw["runs"][0]["results"]] == [
            "aws_db_instance.this"
        ]
        rewritten = json.loads(json_report.read_text(encoding="utf-8"))
        assert rewritten[0]["results"]["failed_checks"][0]["repo_file_path"] == (
            "/bad\udcff.tf"
        )

    @pytest.mark.skipif(os.name == "nt", reason="POSIX paths")
    def test_a_failure_reading_the_resources_leaves_the_path_rewrite(
        self, tmp_path, monkeypatch
    ):
        scanner, results_file, records = TestTheScannerReadsBothReports()._reports(
            tmp_path, additional_formats=["json"]
        )
        json_report = results_file.parent / "results_json.json"
        json_report.write_text(
            json.dumps([_report("terraform_plan", failed=records)]), encoding="utf-8"
        )
        scanner._checkov_cwd = Path("/")
        scanner._checkov_target = tmp_path / "src"

        def fails(document):
            raise UnicodeEncodeError("utf-8", "x", 0, 1, "planted")

        monkeypatch.setattr(
            "automated_security_helper.plugin_modules.ash_builtin.scanners."
            "checkov_scanner.checkov_resources",
            fails,
        )

        raw = scanner._read_results_file(results_file)

        assert [_resource(r) for r in raw["runs"][0]["results"]] == [None, None]
        rewritten = json.loads(json_report.read_text(encoding="utf-8"))
        assert {
            r["repo_file_path"] for r in rewritten[0]["results"]["failed_checks"]
        } == {"/tfplan.json"}
