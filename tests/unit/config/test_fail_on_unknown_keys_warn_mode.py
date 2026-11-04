# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Warn-then-refuse rollout for unknown suppression keys (fail_on_unknown_keys).

The 3.x default is warn: a config whose suppression or ignore-path entry holds
a key the model does not declare loads, a resolution warning names the key with
the did-you-mean, and the entry applies to nothing until it is fixed. Setting
``fail_on_unknown_keys: true`` restores today's refusal, verbatim, which v4
makes the default again.

Fail-closed by construction: the entry that kept an unknown key is marked
``has_unknown_keys`` and never matches a finding, so a typo can only narrow
what is suppressed (the #324 class: a silently ignored ``resource_id`` in
v3.7.x suppressed MORE than the author intended).
"""

import pytest
from pydantic import ValidationError

from automated_security_helper.config.resolve_config import build_config
from automated_security_helper.models.core import AshSuppression
from automated_security_helper.models.flat_vulnerability import FlatVulnerability
from automated_security_helper.utils.suppression_matcher import (
    should_suppress_finding,
)
from automated_security_helper.utils.unknown_keys import (
    TOLERATE_STORED_CONFIG,
    WARN_UNKNOWN_KEYS,
)

pytestmark = pytest.mark.unit


def _config_data(suppression: dict, **top_level) -> dict:
    data = {
        "project_name": "warn-mode-test",
        "global_settings": {"suppressions": [suppression]},
    }
    data.update(top_level)
    return data


def _finding(rule_id="RULE-1", path="src/app.py"):
    return FlatVulnerability(
        id="f1",
        title="t",
        description="d",
        severity="HIGH",
        scanner="bandit",
        scanner_type="SAST",
        rule_id=rule_id,
        file_path=path,
    )


class TestWarnModeDefault:
    def test_unknown_key_warns_and_loads(self):
        config = build_config(
            _config_data(
                {
                    "rule_id": "RULE-1",
                    "path": "src/app.py",
                    "reason": "test",
                    "expiraton": "2099-12-31",
                }
            )
        )
        warnings = [
            w for w in config._resolution_warnings if "Unknown key 'expiraton'" in w
        ]
        assert len(warnings) == 1
        # The suggestion steers to the canonical spelling, never the deprecated
        # "expiration" alias (utils/unknown_keys.DEPRECATED_KEYS).
        assert "did you mean 'expires'?" in warnings[0]
        assert "fail_on_unknown_keys" in warnings[0]

    def test_the_kept_entry_never_applies(self):
        config = build_config(
            _config_data(
                {
                    "rule_id": "RULE-1",
                    "path": "src/app.py",
                    "reason": "test",
                    "resorce_id": "whatever",
                }
            )
        )
        entry = config.global_settings.suppressions[0]
        assert entry.has_unknown_keys
        suppressed, matched = should_suppress_finding(_finding(), [entry])
        assert suppressed is False
        assert matched is None

    def test_control_entry_without_the_typo_applies(self):
        config = build_config(
            _config_data({"rule_id": "RULE-1", "path": "src/app.py", "reason": "test"})
        )
        entry = config.global_settings.suppressions[0]
        suppressed, matched = should_suppress_finding(_finding(), [entry])
        assert suppressed is True
        assert matched is entry

    def test_flag_defaults_to_false(self):
        config = build_config(_config_data({"path": "a.py", "reason": "r"}))
        assert config.fail_on_unknown_keys is False


class TestOptInRefusal:
    def test_flag_true_reproduces_the_refusal(self):
        with pytest.raises(ValidationError) as excinfo:
            build_config(
                _config_data(
                    {
                        "rule_id": "RULE-1",
                        "path": "src/app.py",
                        "reason": "test",
                        "resource": "Stack/Role/Resource",
                    },
                    fail_on_unknown_keys=True,
                )
            )
        message = str(excinfo.value)
        assert "Unknown key 'resource'" in message
        assert "in a suppression" in message

    def test_override_opts_into_the_refusal(self):
        with pytest.raises(ValidationError):
            build_config(
                _config_data(
                    {
                        "rule_id": "RULE-1",
                        "path": "src/app.py",
                        "reason": "test",
                        "resource": "x",
                    }
                ),
                config_overrides=["fail_on_unknown_keys=true"],
            )

    def test_non_bool_flag_is_refused_by_pydantic(self):
        with pytest.raises(ValidationError):
            build_config(
                _config_data(
                    {"path": "a.py", "reason": "r"}, fail_on_unknown_keys="yes"
                )
            )


class TestOverrideAddedEntries:
    def test_an_override_added_bad_entry_warns(self):
        config = build_config(
            _config_data({"path": "clean.py", "reason": "r"}),
            config_overrides=[
                (
                    "global_settings.suppressions+="
                    '[{"rule_id":"X","path":"a.py","reason":"r","expiraton":"2099-01-01"}]'
                )
            ],
        )
        warnings = [
            w for w in config._resolution_warnings if "Unknown key 'expiraton'" in w
        ]
        assert len(warnings) == 1
        added = config.global_settings.suppressions[1]
        assert added.has_unknown_keys

    def test_an_override_entry_with_the_files_typo_still_warns(self):
        """The warning text carries no entry location, so an override-added
        entry with the SAME typo as a file entry re-produces the file's exact
        text; the carry subtracts by count, so both entries' warnings surface
        (a membership dedup dropped the override's, the silent inert entry
        this warn mode exists to surface)."""
        config = build_config(
            _config_data(
                {
                    "rule_id": "X",
                    "path": "a.py",
                    "reason": "r",
                    "expiraton": "2099-01-01",
                }
            ),
            config_overrides=[
                (
                    "global_settings.suppressions+="
                    '[{"rule_id":"X","path":"a.py","reason":"r",'
                    '"expiraton":"2099-01-01"}]'
                )
            ],
        )
        warnings = [
            w for w in config._resolution_warnings if "Unknown key 'expiraton'" in w
        ]
        assert len(warnings) == 2, config._resolution_warnings
        assert all(s.has_unknown_keys for s in config.global_settings.suppressions)

    def test_a_file_entrys_warning_is_not_duplicated_by_the_rebuild(self):
        config = build_config(
            _config_data({"path": "a.py", "reason": "r", "expiraton": "2099-01-01"}),
            config_overrides=["fail_on_findings=false"],
        )
        warnings = [w for w in config._resolution_warnings if "expiraton" in w]
        assert len(warnings) == 1


class TestOtherModesUntouched:
    def test_stored_results_tolerance_still_records_notes(self):
        notes: list = []
        entry = AshSuppression.model_validate(
            {"path": "a.py", "reason": "r", "bogus_key": 1},
            context={TOLERATE_STORED_CONFIG: notes},
        )
        assert entry.has_unknown_keys
        assert notes  # the tolerance recorded, warn mode did not take over

    def test_plugin_options_still_refuse_under_warn_context(self):
        # Warn mode covers entry models only: a plugin option model cannot
        # mark itself inert, so a kept key there would be silently unread.
        from automated_security_helper.plugin_modules.ash_builtin.scanners.bandit_scanner import (
            BanditScannerConfigOptions,
        )

        with pytest.raises(ValidationError):
            BanditScannerConfigOptions.model_validate(
                {"severity_level": "HIGH"}, context={WARN_UNKNOWN_KEYS: []}
            )
