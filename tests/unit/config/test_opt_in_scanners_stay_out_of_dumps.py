# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""An opt-in scanner nobody touched leaves no trace in a serialized config.

The scan phase already drops an unenabled opt-in scanner from a run, but its default
config entry still reached ``ash_aggregated_results.json`` (which embeds the resolved
config), the YAML reporter, the S3 and CloudWatch payloads (one embeds the config's
repr), and the loader's "Loaded N scanners" line. Measured with the snapshot suite:
adding cfn-lint and cfn-guard changed 13 default-output snapshots that way.
"""

from __future__ import annotations

import logging

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.default_config import get_default_config

OPT_IN = ("cfn-guard", "cfn-lint")


def test_default_config_dump_omits_untouched_opt_in_scanners():
    dumped = get_default_config().model_dump(by_alias=True)["scanners"]
    assert not set(OPT_IN) & set(dumped), sorted(dumped)
    assert "cfn-nag" in dumped  # the omission is for opt-in scanners only


def test_the_repr_omits_them_too():
    text = repr(get_default_config().scanners)
    assert "cfn_lint" not in text and "cfn_guard" not in text
    assert "cfn_nag" in text


def test_an_enabled_or_configured_opt_in_scanner_is_kept():
    config = AshConfig.model_validate(
        {
            "project_name": "p",
            "scanners": {
                "cfn-lint": {"enabled": True},
                "cfn-guard": {"options": {"rule_sets": ["cis-aws-benchmark-level-1"]}},
            },
        }
    )
    dumped = config.model_dump(by_alias=True)["scanners"]
    assert dumped["cfn-lint"]["enabled"] is True
    assert dumped["cfn-guard"]["options"]["rule_sets"] == ["cis-aws-benchmark-level-1"]
    # And it round-trips to the same configuration.
    again = AshConfig.model_validate({"project_name": "p", "scanners": dumped})
    assert again.scanners.cfn_guard.options.rule_sets == ["cis-aws-benchmark-level-1"]


def test_the_runtime_lookup_still_finds_an_untouched_entry():
    config = get_default_config()
    found = config.get_plugin_config("scanner", "cfn-lint")
    assert found is not None and found["enabled"] is False


def test_the_loader_count_leaves_opt_in_scanners_out(caplog, test_plugin_context):
    from automated_security_helper.plugins.loader import load_plugins

    with caplog.at_level(logging.INFO, logger="ash"):
        plugins = load_plugins(test_plugin_context)
    names = {cls.__name__ for cls in plugins["scanners"]}
    assert {"CfnLintScanner", "CfnGuardScanner"} <= names
    from automated_security_helper.core.scanner_opt_in import is_opt_in

    expected = sum(1 for cls in plugins["scanners"] if not is_opt_in(cls))
    lines = [
        r.getMessage() for r in caplog.records if r.getMessage().startswith("Loaded ")
    ]
    assert lines and f", {expected} scanners," in lines[-1], lines


def test_the_workspace_plan_leaves_untouched_opt_in_scanners_out():
    """Neither listed as a scanner nor contributing a pin until enabled."""
    from automated_security_helper.workspace.resolver import _scanner_state

    names, pins = _scanner_state(get_default_config())
    assert not set(OPT_IN) & set(names)
    assert not set(OPT_IN) & set(pins), pins

    enabled = AshConfig.model_validate(
        {"project_name": "p", "scanners": {"cfn-lint": {"enabled": True}}}
    )
    names, pins = _scanner_state(enabled)
    assert "cfn-lint" in names
    assert pins["cfn-lint"] == ">=1.43.3,<2.0.0"
