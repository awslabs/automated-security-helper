# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A non-empty ``build.custom_scanners`` entry is refused by name.

Nothing loads the field after validation: the package declares it and reads
it nowhere else. Before this change a non-empty entry died inside pydantic
with an unnamed ``TypeError`` from instantiating the plugin base, so an
operator who wrote entries got a stack trace instead of being told the key is
not supported. The entries are config that silently does nothing even when
they validate, which is the dead-config shape the named refusal exists for.

The empty default and an absent key stay accepted: both are what every config
without custom scanners already has.

An entry that holds an environment reference draws the same refusal, whichever
slot the reference sits in (a ``str | None`` option, a nested name, or a
mapping key). The refusal names the variable when a list item or mapping value
holds the reference (a mapping key is not searched, so that shape names none),
and gives no advice to write the value in the file, which the field would
refuse as well.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from automated_security_helper.utils.redacted_model import env_resolved_scalar

pytestmark = pytest.mark.unit

ENTRY_CANARY = "zz-custom-scanner-entry-canary-77143"
VARIABLE = "ASH_ZZ_CUSTOM_SCANNER_ENTRY"


def _validate(build_section: dict):
    from automated_security_helper.config.ash_config import AshConfig

    return AshConfig.model_validate({"project_name": "zz-cs", "build": build_section})


def _refusal_text(build_section: dict) -> str:
    """The refusal as the product's describe layer reads it: loc and msg per
    error. pydantic's raw rendering also appends ``input_value=...``, which
    echoes the input (cut at about 50 characters) on every refusal route, so
    the shown surfaces build from the message and this helper does too."""
    with pytest.raises(ValidationError) as refused:
        _validate(build_section)
    return " ".join(
        f"{error['loc']}: {error['msg']}" for error in refused.value.errors()
    )


def test_a_non_empty_entry_is_refused_naming_the_key():
    text = _refusal_text({"custom_scanners": [{"config": {"name": ENTRY_CANARY}}]})
    assert "custom_scanners" in text, text
    assert "not supported" in text, text


def test_the_refusal_does_not_echo_the_entry():
    text = _refusal_text({"custom_scanners": [{"config": {"name": ENTRY_CANARY}}]})
    assert "custom_scanners" in text, text
    assert ENTRY_CANARY not in text, text


def test_an_entry_in_a_file_is_refused_without_echoing_it(tmp_path: Path):
    from automated_security_helper.config.resolve_config import (
        ConfigFileRefused,
        load_config_file_for_run,
    )

    path = tmp_path / "entry.ash.yaml"
    path.write_text(
        "project_name: zz-cs\n"
        "build:\n"
        "  custom_scanners:\n"
        "    - config:\n"
        f"        name: {ENTRY_CANARY}\n",
        encoding="utf-8",
    )

    with pytest.raises(ConfigFileRefused) as refused:
        load_config_file_for_run(path)

    text = str(refused.value)
    assert "custom_scanners" in text, text
    assert "not supported" in text, text
    assert ENTRY_CANARY not in text, text


@pytest.mark.parametrize(
    "entry",
    [
        lambda marker: {"command": marker},
        lambda marker: {"config": {"name": marker}},
        lambda marker: {marker: "value"},
    ],
    ids=["str-or-null-command-slot", "config-name", "reference-as-a-key"],
)
def test_an_entry_holding_a_reference_at_a_text_slot_draws_the_named_refusal(entry):
    """Each shape keeps the reference's text as a plain str, so the reference
    walk has nothing to refuse and the entry used to reach the plugin base,
    which raised a bare TypeError that pydantic does not wrap."""
    marker = env_resolved_scalar(ENTRY_CANARY, VARIABLE)

    text = _refusal_text({"custom_scanners": [entry(marker)]})

    assert "custom_scanners" in text, text
    assert "not supported" in text, text
    assert ENTRY_CANARY not in text, text


def test_a_reference_at_a_converting_slot_is_refused_naming_the_variable():
    marker = env_resolved_scalar(ENTRY_CANARY, VARIABLE)

    text = _refusal_text({"custom_scanners": [{"dependencies_satisfied": marker}]})

    assert "not supported" in text, text
    assert "Input should be a valid" not in text, text
    assert "Write the value in the file" not in text, text
    assert VARIABLE in text, text
    assert ENTRY_CANARY not in text, text


def test_the_schema_says_the_list_must_stay_empty():
    """The loader refuses every entry, so the schema an editor validates
    against says so too instead of advertising a list of scanner models."""
    from automated_security_helper.config.ash_config import AshConfig

    schema = AshConfig.model_json_schema()
    field = schema["$defs"]["BuildConfig"]["properties"]["custom_scanners"]
    assert field["maxItems"] == 0, field


def test_an_absent_key_still_validates():
    config = _validate({})
    assert config.build.custom_scanners == []


def test_an_empty_list_still_validates():
    config = _validate({"custom_scanners": []})
    assert config.build.custom_scanners == []
