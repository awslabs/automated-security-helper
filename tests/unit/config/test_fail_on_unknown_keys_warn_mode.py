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


class TestV4DeprecationSentence:
    """The warning names the key, the did-you-mean, and the v4 flip.

    The refusal (fail_on_unknown_keys: true, and the v4 default) keeps its
    original form: the deprecation sentence belongs to the warning only, since
    an error needs no notice that it becomes an error.
    """

    def test_warning_names_the_key_the_suggestion_and_v4(self):
        config = build_config(
            _config_data(
                {
                    "rule_id": "RULE-1",
                    "path": "src/app.py",
                    "reason": "test",
                    "expirey": "2099-12-31",
                }
            )
        )
        warnings = [
            w for w in config._resolution_warnings if "Unknown key 'expirey'" in w
        ]
        assert len(warnings) == 1, config._resolution_warnings
        assert "did you mean 'expires'?" in warnings[0]
        assert "This will become an error in ASH v4." in warnings[0]

    def test_demo_shaped_unknown_keys_warn_and_are_counted(self):
        # The one-observability-demo shape with each demo key misspelled: 25
        # entries with a resource_id-shaped unknown key and one with an
        # expires-shaped unknown key load with exactly one warning per entry,
        # and every such entry is inert.
        suppressions = [
            {
                "rule_id": "AwsSolutions-IAM5",
                "path": "cdk.out/*.template.json",
                "reason": f"demo suppression {index}",
                "resorce_id": f"Stack/Construct{index}/Resource",
            }
            for index in range(25)
        ]
        suppressions.append(
            {
                "rule_id": "GHSA-demo-advisory",
                "path": "package-lock.json",
                "reason": "accepted dependency advisory",
                "expirey": "2099-12-31",
            }
        )
        config = build_config(
            {
                "project_name": "warn-mode-test",
                "global_settings": {"suppressions": suppressions},
            }
        )
        warnings = [w for w in config._resolution_warnings if "Unknown key" in w]
        assert len(warnings) == 26, config._resolution_warnings
        assert all("ASH v4" in w for w in warnings)
        assert all(s.has_unknown_keys for s in config.global_settings.suppressions)

    def test_the_demo_keys_themselves_load_with_no_warning(self):
        # The control for the pair above: the demo keys spelled right are
        # declared fields, so the config loads with no unknown-key warning and
        # the entry applies.
        config = build_config(
            _config_data(
                {
                    "rule_id": "AwsSolutions-IAM5",
                    "path": "cdk.out/*.template.json",
                    "reason": "demo",
                    "resource_id": "Stack/Construct/Resource",
                    "expires": "2099-12-31",
                }
            )
        )
        assert not [w for w in config._resolution_warnings if "Unknown key" in w]
        entry = config.global_settings.suppressions[0]
        assert entry.has_unknown_keys is False
        assert entry.scope is not None and entry.scope.resource_id is not None

    def test_known_key_value_errors_still_refuse_in_warn_mode(self):
        # Warn mode covers unknown KEYS only: a declared key's bad VALUE is
        # refused exactly as before.
        with pytest.raises(ValidationError):
            build_config(
                _config_data({"path": "a.py", "reason": "r", "expires": "31-12-2099"})
            )
        with pytest.raises(ValidationError):
            build_config(_config_data({"rule_id": "  ", "path": "a.py", "reason": "r"}))

    def test_planted_control_opt_in_refusal_keeps_its_original_form(self):
        # fail_on_unknown_keys: true still refuses a typo'd key verbatim: the
        # error names the key and the did-you-mean and carries neither the
        # inert-entry sentence nor the v4 deprecation sentence.
        with pytest.raises(ValidationError) as excinfo:
            build_config(
                _config_data(
                    {
                        "rule_id": "RULE-1",
                        "path": "src/app.py",
                        "reason": "test",
                        "expiraton": "2099-12-31",
                    },
                    fail_on_unknown_keys=True,
                )
            )
        message = str(excinfo.value)
        assert "Unknown key 'expiraton'" in message
        assert "did you mean 'expires'?" in message
        assert "applies to nothing" not in message
        assert "ASH v4" not in message


class TestV4GateConstant:
    """The v4 flip is one module-level constant, read everywhere it matters."""

    def test_the_gate_is_false_on_the_3x_line(self):
        from automated_security_helper.utils.unknown_keys import (
            UNKNOWN_ENTRY_KEYS_ARE_FATAL_BY_DEFAULT,
        )

        assert UNKNOWN_ENTRY_KEYS_ARE_FATAL_BY_DEFAULT is False

    def test_the_field_default_reads_the_gate(self):
        # Today both sides are the False singleton, so this cannot tell the
        # constant from a literal; its job is the v4 bump, where a field left
        # at a literal False would no longer match the flipped constant.
        from automated_security_helper.config.ash_config import AshConfig
        from automated_security_helper.utils.unknown_keys import (
            UNKNOWN_ENTRY_KEYS_ARE_FATAL_BY_DEFAULT,
        )

        assert (
            AshConfig.model_fields["fail_on_unknown_keys"].default
            is UNKNOWN_ENTRY_KEYS_ARE_FATAL_BY_DEFAULT
        )

    def test_flipping_the_gate_makes_the_refusal_the_default(self, monkeypatch):
        # The v4 bump flips the constant; a document that never mentions the
        # flag then refuses an unknown entry key outright. (The field default
        # is bound at import, so this exercises the raw-document read, which
        # runs first and decides the validation context.)
        from automated_security_helper.utils import unknown_keys

        monkeypatch.setattr(
            unknown_keys, "UNKNOWN_ENTRY_KEYS_ARE_FATAL_BY_DEFAULT", True
        )
        with pytest.raises(ValidationError) as excinfo:
            build_config(
                _config_data(
                    {
                        "rule_id": "RULE-1",
                        "path": "src/app.py",
                        "reason": "test",
                        "expirey": "2099-12-31",
                    }
                )
            )
        assert "Unknown key 'expirey'" in str(excinfo.value)

    def test_the_flag_stays_the_escape_hatch_after_the_flip(self, monkeypatch):
        # fail_on_unknown_keys: false keeps warn mode even once the default is
        # the refusal, so v4 operators can opt back out per config.
        from automated_security_helper.utils import unknown_keys

        monkeypatch.setattr(
            unknown_keys, "UNKNOWN_ENTRY_KEYS_ARE_FATAL_BY_DEFAULT", True
        )
        config = build_config(
            _config_data(
                {
                    "rule_id": "RULE-1",
                    "path": "src/app.py",
                    "reason": "test",
                    "expirey": "2099-12-31",
                },
                fail_on_unknown_keys=False,
            )
        )
        warnings = [
            w for w in config._resolution_warnings if "Unknown key 'expirey'" in w
        ]
        assert len(warnings) == 1, config._resolution_warnings
