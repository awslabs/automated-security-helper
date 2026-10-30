# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""load_config_with_references validates a document as a scan does.

``build_config`` and ``validate_config_document`` validate a resolved document
with the ``strict_file_load`` context, which selects the named refusal of a
typed field's environment reference. ``load_config_with_references`` validated
the same document strictly but without the context, so a caller that loads a
config through it (to write the config out again) read pydantic's message about
the resolved text where a scan reads the refusal that names the variable.

Red at the base: the validation call carried no ``context``.
"""

from __future__ import annotations

import pytest

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.config_sources import (
    load_config_with_references,
)

pytestmark = pytest.mark.unit


def test_the_file_load_context_is_passed(monkeypatch, tmp_path):
    seen = {}
    original = AshConfig.model_validate

    def spy(data, **kwargs):
        seen.update(kwargs)
        return original(data, **kwargs)

    monkeypatch.setattr(AshConfig, "model_validate", spy)
    config_file = tmp_path / "ash.yaml"
    config_file.write_text("project_name: p\n", encoding="utf-8")

    config = load_config_with_references(config_file)

    assert config.project_name == "p"
    assert seen.get("strict") is True
    assert seen.get("context") == {"strict_file_load": True}
