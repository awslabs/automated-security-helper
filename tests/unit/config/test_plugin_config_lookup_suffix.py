# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A plugin whose config key ends in -reporter must still be findable.

Why this file exists
--------------------
`--config-overrides 'reporters.bedrock-summary-reporter.options.model_id=...'`
was silently ignored, and the reporter kept its hardcoded default model.

The issue attributes this to `ReporterConfigSegment` being a closed model with no
field for external plugins. It is not: that model already sets `extra="allow"`
with a typed `__pydantic_extra__`, and the override really does land in it --

    reporters.__pydantic_extra__["bedrock-summary-reporter"]
        == {"options": {"model_id": "..."}}

so nothing is lost at the config layer. The value is simply never read.

The actual defect
-----------------
`AshConfig.get_plugin_config` strips a `Converter|Scanner|Reporter` suffix from
the *query*::

    BedrockSummaryReporter -> bedrocksummaryreporter -> bedrocksummary

but builds its candidate `key_map` from the config keys **without** stripping the
same suffix::

    bedrock-summary-reporter -> bedrocksummaryreporter

so the two forms can never meet. `report_phase` looks plugins up by lowercased
class name, so any plugin whose config key contains the plugin-type word is
unreachable and silently falls back to its defaults.

`csv` works for one reason only: its key does not contain "reporter". That is why
this looked like an external-plugin problem -- every built-in happens to be named
in a way that dodges it.

Verified before fixing, since the same key with the suffix removed resolves fine:

    key=bedrock-summary-reporter  query=bedrocksummaryreporter  -> not found
    key=bedrock-summary           query=bedrocksummaryreporter  -> FOUND

Scope
-----
The same regex covers scanners and converters, so the asymmetry is not
reporter-specific and neither is the fix.
"""

import pytest

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.resolve_config import apply_config_overrides


def _config_with(override: str) -> AshConfig:
    return apply_config_overrides(AshConfig(project_name="probe"), [override])


class TestSuffixedConfigKeyIsReachable:
    def test_external_reporter_with_reporter_suffix_is_found(self):
        """The reported case, looked up the way report_phase looks it up."""
        config = _config_with(
            "reporters.bedrock-summary-reporter.options.model_id=MY-MODEL"
        )

        found = config.get_plugin_config(
            plugin_type="reporter",
            # report_phase passes plugin_class.__name__.lower()
            plugin_name="bedrocksummaryreporter",
        )

        assert found is not None, (
            "The override is present in reporters.__pydantic_extra__ but "
            "get_plugin_config cannot find it, so the reporter falls back to its "
            "hardcoded defaults."
        )
        assert found["options"]["model_id"] == "MY-MODEL"

    @pytest.mark.parametrize(
        "plugin_type,key,query",
        [
            ("reporter", "my-thing-reporter", "mythingreporter"),
            ("scanner", "my-thing-scanner", "mythingscanner"),
            ("converter", "my-thing-converter", "mythingconverter"),
        ],
    )
    def test_the_asymmetry_is_fixed_for_every_plugin_type(
        self, plugin_type, key, query
    ):
        """One regex covers all three, so all three had the bug."""
        config = _config_with(f"{plugin_type}s.{key}.options.x=1")

        assert (
            config.get_plugin_config(plugin_type=plugin_type, plugin_name=query)
            is not None
        )

    def test_a_key_without_the_suffix_still_resolves(self):
        """This already worked; it must keep working."""
        config = _config_with("reporters.bedrock-summary.options.model_id=M")

        found = config.get_plugin_config(
            plugin_type="reporter", plugin_name="bedrocksummaryreporter"
        )

        assert found is not None
        assert found["options"]["model_id"] == "M"


class TestExistingLookupsAreUnchanged:
    @pytest.mark.parametrize("query", ["csv", "csvreporter", "CSVReporter"])
    def test_builtin_reporter_still_resolves_by_every_spelling(self, query):
        config = _config_with("reporters.csv.enabled=false")

        found = config.get_plugin_config(
            plugin_type="reporter", plugin_name=query.lower()
        )

        assert found is not None
        assert found["enabled"] is False

    def test_builtin_scanner_still_resolves(self):
        config = _config_with("scanners.bandit.enabled=false")

        found = config.get_plugin_config(
            plugin_type="scanner", plugin_name="banditscanner"
        )

        assert found is not None
        assert found["enabled"] is False

    def test_an_exact_key_wins_over_another_keys_stripped_form(self):
        """Guard against the new candidate shadowing a real key.

        If `bedrock-summary` and `bedrock-summary-reporter` both exist, the
        stripped form of the second collides with the first. The exact key has to
        keep priority, or adding a plugin would silently repoint another
        plugin's config.
        """
        config = apply_config_overrides(
            AshConfig(project_name="probe"),
            [
                "reporters.bedrock-summary.options.which=exact",
                "reporters.bedrock-summary-reporter.options.which=suffixed",
            ],
        )

        found = config.get_plugin_config(
            plugin_type="reporter", plugin_name="bedrock-summary"
        )

        assert found is not None
        assert found["options"]["which"] == "exact"

    def test_an_unknown_plugin_still_returns_none(self):
        """The fix must not start inventing matches."""
        config = AshConfig(project_name="probe")

        assert (
            config.get_plugin_config(
                plugin_type="reporter", plugin_name="nosuchthingreporter"
            )
            is None
        )
