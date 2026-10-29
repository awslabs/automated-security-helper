# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""scripts/verify_docs_freshness.py: the comparison helpers.

* an inventory row covers a code name only when the whole normalized name
  matches, so a row containing another name as a substring hides nothing;
* a config-discovery list that places an ashrc name or pyproject.toml under
  ``.ash/`` is reported;
* an options block that uses the ``!ENV`` tag is parsed, not skipped;
* a plugin documented under its underscore spelling finds the dashed model.
"""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.unit


@pytest.fixture
def freshness(script_loader):
    return script_loader("verify_docs_freshness")


TABLE = """\
| Reporter | Output |
|---|---|
| gitlab-cyclonedx | ash.gl-dependency-scanning-report.cdx.json |
| cfn-nag (CloudFormation) | ash.summary.txt |
"""


class TestCompareInventories:
    def test_a_row_containing_the_name_as_a_substring_does_not_cover_it(
        self, freshness
    ):
        code = {"cyclonedx": "CycloneDXReporter", "gitlab-cyclonedx": "GitLabReporter"}
        failures = freshness.compare_inventories(
            "reporters", code, TABLE, "Reporter", "reporters.md"
        )
        assert any(
            "'cyclonedx'" in f and "is in the code but no row" in f for f in failures
        )

    def test_a_leftover_row_is_not_covered_by_a_longer_name(self, freshness):
        code = {"gitlab-cyclonedx": "GitLabReporter", "cfn-nag": "CfnNagScanner"}
        table = TABLE + "| cyclonedx | ash.cdx.json |\n"
        failures = freshness.compare_inventories(
            "reporters", code, table, "Reporter", "reporters.md"
        )
        assert any(
            "row 'cyclonedx'" in f and "names nothing in the code" in f
            for f in failures
        )

    def test_a_trailing_parenthetical_is_not_part_of_the_name(self, freshness):
        code = {"gitlab-cyclonedx": "GitLabReporter", "cfn_nag": "CfnNagScanner"}
        failures = freshness.compare_inventories(
            "reporters", code, TABLE, "Reporter", "reporters.md"
        )
        assert failures == []


class TestConfigDiscoveryLists:
    SUPPORTED = {".ash.yaml", ".ash.yml", "ash.yaml"}
    NEWER = {".ashrc.yaml", "pyproject.toml"}

    def test_a_newer_name_under_dot_ash_is_reported(self, freshness):
        lines = [
            "1. `.ash/.ash.yaml`",
            "2. `.ash/.ash.yml`",
            "3. `.ash/ash.yaml`",
            "4. `.ash/.ashrc.yaml`",
            "5. `.ash/pyproject.toml`",
        ]
        failures, lists = freshness._config_list_problems(
            "docs/x.md", lines, self.SUPPORTED, self.NEWER
        )
        assert lists == 1
        assert any("under .ash/" in f and ".ashrc.yaml" in f for f in failures)

    def test_a_complete_list_at_the_right_places_is_clean(self, freshness):
        lines = [
            "1. `.ash/.ash.yaml`",
            "2. `.ash/.ash.yml`",
            "3. `.ash/ash.yaml`",
            "4. `.ashrc.yaml`",
            "5. `pyproject.toml`",
        ]
        failures, lists = freshness._config_list_problems(
            "docs/x.md", lines, self.SUPPORTED, self.NEWER
        )
        assert (failures, lists) == ([], 1)

    def test_a_single_example_is_not_an_inventory(self, freshness):
        failures, lists = freshness._config_list_problems(
            "docs/x.md", ["- `.ash/.ash.yaml`", "prose"], self.SUPPORTED, self.NEWER
        )
        assert (failures, lists) == ([], 0)


class TestOptionsYaml:
    def test_an_env_tag_parses_as_its_text(self, freshness):
        parsed = freshness._load_options_yaml(
            "scanners:\n  bandit:\n    options:\n      config_file: !ENV ${BANDIT_CONFIG}\n"
        )
        assert (
            parsed["scanners"]["bandit"]["options"]["config_file"] == "${BANDIT_CONFIG}"
        )

    def test_invalid_yaml_still_returns_none(self, freshness):
        assert freshness._load_options_yaml("scanners: [unclosed") is None


class TestModelLookup:
    def test_the_underscore_spelling_finds_the_dashed_model(self, freshness):
        class CdkNagOptions:
            pass

        models = {"cdk-nag": CdkNagOptions}
        assert freshness._model_for(models, "cdk_nag") is CdkNagOptions
        assert freshness._model_for(models, "cdk-nag") is CdkNagOptions

    def test_an_unknown_plugin_finds_nothing(self, freshness):
        assert freshness._model_for({"cdk-nag": object}, "third-party") is None
