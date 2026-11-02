# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tier-0 placement suggestions for misplaced suppression keys.

A known misplacement gets a shaped suggestion naming where the key belongs
(``move it under scope.engines.cdk-nag``), not merely the nearest spelling.
Core seeds the spellings it owns; a plugin registers its own at load (cdk-nag
registers ``applies_to`` and ``resource_path``). The suggestion surfaces in
both modes: inside the refusal under fail_on_unknown_keys, inside the warning
otherwise. A key with no map entry falls through to closest_key unchanged.
"""

import pytest
from pydantic import ValidationError

# Importing the cdk-nag scanner module is what registers its placement hints,
# as a plugin load would.
import automated_security_helper.plugin_modules.ash_builtin.scanners.cdk_nag_scanner  # noqa: F401
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
