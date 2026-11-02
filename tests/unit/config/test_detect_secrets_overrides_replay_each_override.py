# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""How the detect-secrets confinement replays ``--config-overrides``.

``confine_detect_secrets_settings`` keeps a verification filter, a ``file://`` entry
or a baseline when the trusted base with the operator's overrides replayed names it.
The overrides applied to the resolved config already, so one that does not apply to
the trusted base turns nothing on and drops only itself: the others still count as
the operator's. A respelled section is the one refusal that is raised, as the
reporters overrides' replay raises it.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from automated_security_helper.config import resolve_config as resolve_module
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.secret_verification_trust import (
    confine_detect_secrets_settings,
    names_verification,
)
from automated_security_helper.core.exceptions import (
    ASHConfigValidationError,
    ASHRespelledOverrideError,
)

pytestmark = pytest.mark.unit

VERIFICATION_FILTER = (
    "detect_secrets.filters.common.is_ignored_due_to_verification_policies"
)
VERIFICATION_OVERRIDE = (
    "scanners.detect-secrets.options.scan_settings.filters_used+="
    + json.dumps([{"path": VERIFICATION_FILTER, "min_level": 2}])
)
OTHER_OVERRIDE = "scanners.detect-secrets.options.scan_timeout=60"
IN_TREE = [Path("repo") / ".ash" / ".ash.yaml"]
REASON = "the file is the repository's"


def _confine(config: AshConfig, overrides: list[str]) -> None:
    confine_detect_secrets_settings(config, AshConfig(), overrides, IN_TREE, REASON)


def _resolved_with_verification() -> AshConfig:
    """A resolved config whose settings name the verification filter, as the
    repository's file would have written them, before the confinement."""
    config = resolve_module.apply_config_overrides(AshConfig(), [VERIFICATION_OVERRIDE])
    assert names_verification(config)
    return config


def test_one_override_that_does_not_apply_keeps_the_others(monkeypatch):
    real = resolve_module.apply_config_overrides
    config = _resolved_with_verification()

    def fake_apply(base, overrides):
        if OTHER_OVERRIDE in overrides:
            raise ASHConfigValidationError("does not apply to this base")
        return real(base, overrides)

    monkeypatch.setattr(resolve_module, "apply_config_overrides", fake_apply)

    _confine(config, [VERIFICATION_OVERRIDE, OTHER_OVERRIDE])

    assert config._untrusted_detect_secrets_settings.operator_verifies is True
    assert names_verification(config)


def test_overrides_valid_only_together_still_land_together(monkeypatch):
    real = resolve_module.apply_config_overrides
    config = _resolved_with_verification()
    calls: list[list[str]] = []

    def needs_both(base, overrides):
        calls.append(list(overrides))
        if len(overrides) == 1:
            raise ASHConfigValidationError("valid only with the other entry")
        return real(base, overrides)

    monkeypatch.setattr(resolve_module, "apply_config_overrides", needs_both)

    _confine(config, [VERIFICATION_OVERRIDE, OTHER_OVERRIDE])

    assert calls == [[VERIFICATION_OVERRIDE, OTHER_OVERRIDE]], calls
    assert config._untrusted_detect_secrets_settings.operator_verifies is True


def test_a_respelled_section_is_refused_and_not_dropped(monkeypatch):
    def refuse(base, overrides):
        raise ASHRespelledOverrideError("names a spelling of an existing section")

    monkeypatch.setattr(resolve_module, "apply_config_overrides", refuse)

    with pytest.raises(ASHRespelledOverrideError):
        _confine(AshConfig(), [OTHER_OVERRIDE])


def test_a_respelled_section_among_several_is_refused_too(monkeypatch):
    real = resolve_module.apply_config_overrides

    def refuse_one(base, overrides):
        if OTHER_OVERRIDE in overrides:
            raise ASHRespelledOverrideError("names a spelling of an existing section")
        return real(base, overrides)

    monkeypatch.setattr(resolve_module, "apply_config_overrides", refuse_one)

    with pytest.raises(ASHRespelledOverrideError):
        _confine(_resolved_with_verification(), [VERIFICATION_OVERRIDE, OTHER_OVERRIDE])
