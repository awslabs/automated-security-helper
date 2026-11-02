# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tier-0 placement suggestions for misplaced suppression keys.

A known misplacement gets a shaped suggestion naming where the key belongs
(``move it under scope.engines.cdk-nag``), not merely the nearest spelling.
The engine-specific spellings are seeded in the static table beside core's
own (unknown-key warnings are produced at config load, which precedes plugin
imports, so no import here and no plugin load is needed for them). The
suggestion surfaces in both modes: inside the refusal under
fail_on_unknown_keys, inside the warning otherwise. A key with no map entry
falls through to closest_key unchanged.
"""

import pytest
from pydantic import ValidationError

from automated_security_helper.models.core import AshSuppression
from automated_security_helper.utils.unknown_keys import (
    WARN_UNKNOWN_KEYS,
    unknown_keys_message,
)

pytestmark = pytest.mark.unit


class TestPlacementSuggestions:
    def test_entry_level_applies_to_points_at_the_engine_block(self):
        with pytest.raises(ValidationError) as excinfo:
            AshSuppression.model_validate(
                {"path": "a", "reason": "r", "applies_to": "Action::logs:*"}
            )
        message = str(excinfo.value)
        assert "Unknown key 'applies_to'" in message
        assert "move it under scope.engines.cdk-nag" in message

    def test_entry_level_resource_path_points_at_the_engine_block(self):
        with pytest.raises(ValidationError) as excinfo:
            AshSuppression.model_validate(
                {"path": "a", "reason": "r", "resource_path": "Stack/*"}
            )
        assert "move it under scope.engines.cdk-nag" in str(excinfo.value)

    def test_resource_suggests_resource_id(self):
        with pytest.raises(ValidationError) as excinfo:
            AshSuppression.model_validate(
                {"path": "a", "reason": "r", "resource": "Stack/Thing"}
            )
        assert "did you mean 'resource_id'?" in str(excinfo.value)

    def test_the_suggestion_appears_in_warn_mode_too(self):
        warnings: list = []
        AshSuppression.model_validate(
            {"path": "a", "reason": "r", "applies_to": "Action::logs:*"},
            context={WARN_UNKNOWN_KEYS: warnings},
        )
        assert len(warnings) == 1
        assert "move it under scope.engines.cdk-nag" in warnings[0]

    def test_an_unmapped_key_falls_through_to_closest_key(self):
        message = unknown_keys_message(
            ["expiraton"], ["expiration", "path", "reason"], "a suppression"
        )
        assert "did you mean 'expiration'?" in message

    def test_hints_do_not_fire_outside_entry_kinds(self):
        message = unknown_keys_message(
            ["applies_to"], ["severity_threshold"], "these plugin options"
        )
        assert "move it under scope.engines.cdk-nag" not in message

    def test_hints_do_not_fire_for_ignore_paths(self):
        """An ignore path has no resource_id and no scope, so a suppression
        placement hint there would send the author to another unknown key;
        the ordinary did-you-mean applies instead."""
        message = unknown_keys_message(
            ["resource", "applies_to"],
            ["path", "reason", "expiration"],
            "an ignore path",
        )
        assert "did you mean 'resource_id'?" not in message
        assert "scope.engines" not in message

    def test_a_registered_hint_is_isolated_and_scoped_to_its_kinds(self, monkeypatch):
        """register_placement_hint stays the plugin API; a test exercising it
        isolates the session-wide table (monkeypatch.setitem restores it), and
        the registered hint fires only for its own entry kinds."""
        from automated_security_helper.utils import unknown_keys

        monkeypatch.setitem(
            unknown_keys._PLACEMENT_HINTS,
            "fake_block_key",
            ("move it under scope.engines.fake", ("suppression",)),
        )
        hit = unknown_keys_message(["fake_block_key"], ["path"], "a suppression")
        miss = unknown_keys_message(["fake_block_key"], ["path"], "an ignore path")
        assert "move it under scope.engines.fake" in hit
        assert "move it under scope.engines.fake" not in miss

    def test_an_ignore_path_entry_with_resource_gets_no_placement_advice(self):
        from automated_security_helper.models.core import IgnorePathWithReason

        with pytest.raises(ValidationError) as excinfo:
            IgnorePathWithReason.model_validate(
                {"path": "a", "reason": "r", "resource": "Stack/Thing"}
            )
        message = str(excinfo.value)
        assert "Unknown key 'resource'" in message
        assert "did you mean 'resource_id'?" not in message
        assert "scope.engines" not in message
