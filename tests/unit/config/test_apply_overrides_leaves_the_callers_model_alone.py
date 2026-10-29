# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""apply_config_overrides answers a rebuilt model and leaves its input alone.

The record of the reporters sections as the file spelled them (what the
trusted replay's fold reads) was stamped on the CALLER's model before the
rebuild, so applying overrides mutated its input: the scan's resolved model,
or the trusted replay's operator configuration, gained a private attribute as
a side effect, and kept it even when the overridden document failed
validation. The record is computed from the input and set on the rebuilt
model, which already carries the input's private state by copy; a model that
already holds a record (a rebuilt one sent through a second application)
keeps its first application's, so a key an override itself created never
counts as a spelling the repository forced.
"""

from __future__ import annotations

import pytest

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.resolve_config import apply_config_overrides
from automated_security_helper.core.exceptions import ASHConfigValidationError


def _a_config() -> AshConfig:
    return AshConfig.model_validate(
        {
            "project_name": "t",
            "reporters": {"markdown": {"enabled": True}},
        }
    )


def test_applying_overrides_leaves_the_callers_model_alone():
    config = _a_config()
    before = config.model_dump()
    its_sections = tuple(before["reporters"])

    rebuilt = apply_config_overrides(config, ["reporters.markdown.enabled=false"])

    assert config._reporters_before_overrides is None
    assert config.model_dump() == before
    assert rebuilt is not config
    assert rebuilt._reporters_before_overrides == its_sections
    assert rebuilt.reporters.markdown.enabled is False


def test_a_failing_application_leaves_the_callers_model_alone():
    config = _a_config()

    with pytest.raises(ASHConfigValidationError):
        apply_config_overrides(config, ["reporters.markdown.enabled=maybe-so"])

    assert config._reporters_before_overrides is None


def test_a_second_application_keeps_the_first_applications_record():
    """A key an override itself created is not a section the input's document
    held: the rebuilt model's record is its input's sections, and a further
    application on that model keeps it rather than reading the overridden
    document's."""
    config = _a_config()
    its_sections = tuple(config.model_dump()["reporters"])

    first = apply_config_overrides(config, ["reporters.custom-thing.enabled=true"])
    second = apply_config_overrides(first, ["reporters.markdown.enabled=false"])

    assert "custom-thing" in first.model_dump()["reporters"], (
        "control: the override made its own section"
    )
    assert first._reporters_before_overrides == its_sections
    assert "custom-thing" not in (first._reporters_before_overrides or ())
    assert second._reporters_before_overrides == its_sections
