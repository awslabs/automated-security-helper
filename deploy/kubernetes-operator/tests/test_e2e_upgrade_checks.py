"""Unit tests for the checks the lifecycle e2e relies on, without a cluster.

The e2e runs these checks once per job, against one real pair of inputs, so a check
that stopped detecting anything would still pass there. Planted inputs here require
each rule to fire, and a real pair to come back clean.
"""

from __future__ import annotations

import copy
from pathlib import Path

import pytest
import yaml

from tests.e2e.crd_compat import upgrade_problems
from tests.e2e.lifecycle import previous_ref
from tests.e2e.shared_contract import (
    CASES_FILE,
    ENV_EQUIVALENTS,
    case_spec,
    env_as_arguments,
    load_cases,
)

OPERATOR_DIR = Path(__file__).resolve().parents[1]
HEAD_CRDS = {
    plural: yaml.safe_load((OPERATOR_DIR / "generated" / f"crd-{plural}.yaml").read_text())
    for plural in ("ashscans", "ashmcpservers")
}


def _schema(crd: dict) -> dict:
    return crd["spec"]["versions"][0]["schema"]["openAPIV3Schema"]


class TestCrdCompatibility:
    @pytest.mark.parametrize("plural", sorted(HEAD_CRDS))
    def test_a_crd_is_compatible_with_itself(self, plural):
        assert upgrade_problems(HEAD_CRDS[plural], HEAD_CRDS[plural]) == []

    def test_a_removed_spec_field_is_reported(self):
        new = copy.deepcopy(HEAD_CRDS["ashscans"])
        del _schema(new)["properties"]["spec"]["properties"]["extraScanArguments"]
        problems = upgrade_problems(HEAD_CRDS["ashscans"], new)
        assert any("spec.extraScanArguments is removed" in p for p in problems), problems

    def test_a_removed_field_under_preserve_unknown_fields_is_not_pruned(self):
        # status carries x-kubernetes-preserve-unknown-fields, so a property dropped
        # from it is kept on stored objects and is not a loss.
        old = HEAD_CRDS["ashscans"]
        assert _schema(old)["properties"]["status"].get("x-kubernetes-preserve-unknown-fields")
        new = copy.deepcopy(old)
        del _schema(new)["properties"]["status"]["properties"]["phase"]
        assert upgrade_problems(old, new) == []

    def test_a_newly_required_field_is_reported(self):
        new = copy.deepcopy(HEAD_CRDS["ashscans"])
        _schema(new)["properties"]["spec"]["required"].append("scanners")
        problems = upgrade_problems(HEAD_CRDS["ashscans"], new)
        assert any("spec.scanners becomes required" in p for p in problems), problems

    def test_a_type_change_is_reported(self):
        new = copy.deepcopy(HEAD_CRDS["ashscans"])
        _schema(new)["properties"]["spec"]["properties"]["shardCount"]["type"] = "string"
        problems = upgrade_problems(HEAD_CRDS["ashscans"], new)
        assert any("spec.shardCount changes type" in p for p in problems), problems

    def test_dropping_the_stored_version_is_reported(self):
        old = copy.deepcopy(HEAD_CRDS["ashscans"])
        old["status"] = {"storedVersions": ["v1alpha1"]}
        new = copy.deepcopy(HEAD_CRDS["ashscans"])
        new["spec"]["versions"][0]["name"] = "v1alpha2"
        problems = upgrade_problems(old, new)
        assert any("v1alpha1 holds stored objects" in p for p in problems), problems

    def test_dropping_the_status_subresource_is_reported(self):
        new = copy.deepcopy(HEAD_CRDS["ashscans"])
        new["spec"]["versions"][0]["subresources"] = {}
        problems = upgrade_problems(HEAD_CRDS["ashscans"], new)
        assert any("drops the status subresource" in p for p in problems), problems

    def test_a_second_storage_version_is_reported(self):
        new = copy.deepcopy(HEAD_CRDS["ashscans"])
        extra = copy.deepcopy(new["spec"]["versions"][0])
        extra["name"] = "v1alpha2"
        new["spec"]["versions"].append(extra)
        problems = upgrade_problems(HEAD_CRDS["ashscans"], new)
        assert any("2 storage versions" in p for p in problems), problems


class TestSharedCaseTranslation:
    def test_every_case_translates(self):
        for name, case in load_cases().items():
            spec = case_spec(case)
            assert spec["scanners"] == case["scanners"], name
            assert spec["extraScanArguments"][: len(case["args"])] == case["args"], name

    def test_the_incomplete_case_runs_offline(self):
        spec = case_spec(load_cases()["incomplete"])
        assert "--offline" in spec["extraScanArguments"]
        assert spec["extraScanArguments"][:2] == [
            "--config-overrides",
            "scanners.opengrep.enabled=true",
        ]

    @pytest.mark.parametrize(
        "env",
        [{"ASH_OFFLINE": "NO"}, {"SOMETHING_NEW": "1"}, {"OPENGREP_RULES_CACHE_DIR": "/rules"}],
    )
    def test_an_unknown_variable_or_value_is_refused(self, env):
        with pytest.raises(AssertionError, match="ENV_EQUIVALENTS"):
            env_as_arguments(env)

    def test_the_cases_file_is_the_shared_one(self):
        assert CASES_FILE.parts[-4:] == ("tests", "e2e", "fixtures", "cases.json")
        assert set(ENV_EQUIVALENTS) >= {
            key for case in load_cases().values() for key in (case.get("env") or {})
        }


class TestPreviousRef:
    # The default N-1 needs full history and is exercised by the lifecycle e2e, whose
    # job fetches it. The refusal works in any clone.
    def test_an_n_minus_one_with_heads_code_is_refused(self, monkeypatch):
        monkeypatch.setenv("ASH_OPERATOR_E2E_PREV_REF", "HEAD")
        with pytest.raises(AssertionError, match="crosses no change"):
            previous_ref()
