# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The option check of a loaded plugin checks what the plugin reads, and all of it.

``AshConfig.get_plugin_config`` gives a plugin one section: the key spelled as its
name, else the first key that claims its reduced name. A second respelling of the
name is never read and is warned about where the lookup runs. The check of a
loaded plugin (``refuse_unknown_plugin_options``) used to validate every
respelling, so the run was refused over a section the plugin does not read. It now
checks the section the lookup returns.

A section the check does read is checked the way a built-in plugin's is at load:
an ``options`` value that is not a mapping and an ``enabled`` value of the wrong
type are refused too, rather than failing later when the plugin is built.
"""

from __future__ import annotations

from typing import Any, Dict

import pytest

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.plugin_option_check import (
    refuse_unknown_plugin_options,
)
from automated_security_helper.core.exceptions import ASHConfigValidationError
from automated_security_helper.plugin_modules.ash_snyk_plugins.snyk_code_scanner import (
    SnykCodeScanner,
)
from automated_security_helper.utils.redacted_model import env_resolved_scalar

pytestmark = pytest.mark.unit

AshConfig.model_rebuild()

PLUGINS = {"scanner": [SnykCodeScanner]}
GOOD: Dict[str, Any] = {"options": {}}
BAD: Dict[str, Any] = {"options": {"no_such_option": True}}


def _config(scanners: Dict[str, Any]) -> AshConfig:
    return AshConfig.model_validate({"project_name": "t", "scanners": scanners})


def _refusal(config: AshConfig) -> str | None:
    try:
        refuse_unknown_plugin_options(config, PLUGINS)
    except ASHConfigValidationError as error:
        return str(error)
    return None


def test_control_the_lookup_reads_the_section_spelled_as_the_plugins_name():
    config = _config({"Snyk_Code": BAD, "snyk-code": GOOD})

    assert config.get_plugin_config("scanner", "snyk-code") == GOOD


@pytest.mark.parametrize("first", ["Snyk_Code", "snykcode", "SNYK-CODE"])
def test_a_respelled_section_the_lookup_never_reads_is_not_checked(first):
    config = _config({first: BAD, "snyk-code": GOOD})

    assert _refusal(config) is None


@pytest.mark.parametrize("first", ["Snyk_Code", "snykcode"])
def test_the_section_the_lookup_reads_is_still_checked(first):
    config = _config({first: GOOD, "snyk-code": BAD})

    assert "scanners.snyk-code.options" in (_refusal(config) or "")


def test_a_respelled_section_alone_is_the_one_read_and_is_checked():
    config = _config({"Snyk_Code": BAD})

    assert config.get_plugin_config("scanner", "snyk-code") == BAD
    assert "scanners.Snyk_Code.options" in (_refusal(config) or "")


@pytest.mark.parametrize("options", ["all", ["a"], 3])
def test_options_that_are_not_a_mapping_are_refused(options):
    config = _config({"snyk-code": {"options": options}})

    assert "scanners.snyk-code.options" in (_refusal(config) or "")


def test_a_section_with_no_options_or_null_options_is_accepted():
    assert _refusal(_config({"snyk-code": {"enabled": True}})) is None
    assert _refusal(_config({"snyk-code": {"options": None}})) is None


def test_an_enabled_value_of_the_wrong_type_is_refused():
    config = _config({"snyk-code": {"enabled": "maybe"}})

    assert "scanners.snyk-code.enabled" in (_refusal(config) or "")


@pytest.mark.parametrize("enabled", [True, False, "true"])
def test_control_an_enabled_value_the_model_accepts_is_not_refused(enabled):
    config = _config({"snyk-code": {"enabled": enabled}})

    assert _refusal(config) is None


def test_enabled_is_checked_through_the_plugins_config_class():
    """``enabled`` goes through the config class as the plugin is built: a
    validator on the field runs, so a value it turns into a boolean is not
    refused; another required field the section does not carry is not this
    check's to report; a wrong type is refused and located at ``enabled``."""
    from pydantic import BaseModel, field_validator

    from automated_security_helper.config.plugin_option_check import (
        _enabled_problems,
    )

    class _Lenient(BaseModel):
        enabled: bool = True
        name: str

        @field_validator("enabled", mode="before")
        @classmethod
        def _on_demand(cls, value):
            return True if value == "on-demand" else value

    assert _enabled_problems(_Lenient, {"enabled": "on-demand"}, "s.x", "p 'x'") == []
    refused = _enabled_problems(_Lenient, {"enabled": "maybe"}, "s.x", "p 'x'")
    assert len(refused) == 1, refused
    assert refused[0].startswith("s.x.enabled (p 'x'): "), refused


def test_an_enabled_type_with_no_schema_is_not_a_crash():
    """A field type pydantic builds no schema for on its own (a plain class the
    model allows as an arbitrary type) used to raise out of the check, from the
    bare annotation's adapter. It is checked through the class now."""
    from pydantic import BaseModel, ConfigDict

    from automated_security_helper.config.plugin_option_check import (
        _enabled_problems,
    )

    class _Marker:
        pass

    class _Arbitrary(BaseModel):
        model_config = ConfigDict(arbitrary_types_allowed=True)
        enabled: _Marker = _Marker()

    assert _enabled_problems(_Arbitrary, {"enabled": _Marker()}, "s.x", "p 'x'") == []
    problems = _enabled_problems(_Arbitrary, {"enabled": "text"}, "s.x", "p 'x'")
    assert all(item.startswith("s.x.enabled (p 'x'): ") for item in problems)


def test_a_model_validator_reading_another_key_is_not_a_crash_of_the_check():
    """A plugin's config class may hold a model-level validator that reads a key
    beside ``enabled``. Run over a mapping holding ``enabled`` alone it raised a
    ``KeyError`` that ended the run with a traceback. It runs over the section
    as the plugin is built from it now, so a bad ``enabled`` is reported there,
    and a validator that still raises something else is left to the plugin's
    own build."""
    from pydantic import BaseModel, model_validator

    from automated_security_helper.config.plugin_option_check import (
        _enabled_problems,
    )

    class _ReadsOptions(BaseModel):
        enabled: bool = True
        options: Dict[str, Any] = {}

        @model_validator(mode="before")
        @classmethod
        def _reads_options(cls, data):
            _ = data["options"]
            return data

    section = {"enabled": "maybe", "options": {}}
    refused = _enabled_problems(_ReadsOptions, section, "s.x", "p 'x'")
    assert len(refused) == 1, refused
    assert refused[0].startswith("s.x.enabled (p 'x'): "), refused
    assert (
        _enabled_problems(
            _ReadsOptions, {"enabled": True, "options": {}}, "s.x", "p 'x'"
        )
        == []
    )
    # The validator raises past ``ValueError`` here, as the plugin's own build
    # would: not a refusal of ``enabled``, and not a crash.
    assert _enabled_problems(_ReadsOptions, {"enabled": "maybe"}, "s.x", "p 'x'") == []
    assert section == {"enabled": "maybe", "options": {}}


def test_a_validator_refusing_a_missing_key_does_not_hide_a_bad_enabled():
    """A model-level validator that refuses a mapping without ``options`` raises
    an error located at no field, which the ``enabled`` filter dropped, so
    ``enabled: maybe`` went unreported. Over the real section it is reported."""
    from pydantic import BaseModel, model_validator

    from automated_security_helper.config.plugin_option_check import (
        _enabled_problems,
    )

    class _NeedsOptions(BaseModel):
        enabled: bool = True
        options: Dict[str, Any] = {}

        @model_validator(mode="before")
        @classmethod
        def _needs_options(cls, data):
            if "options" not in data:
                raise ValueError("options are required")
            return data

    refused = _enabled_problems(
        _NeedsOptions, {"enabled": "maybe", "options": {}}, "s.x", "p 'x'"
    )
    assert len(refused) == 1, refused
    assert refused[0].startswith("s.x.enabled (p 'x'): "), refused
    assert (
        _enabled_problems(
            _NeedsOptions, {"enabled": True, "options": {}}, "s.x", "p 'x'"
        )
        == []
    )


def test_an_enabled_value_read_from_the_environment_is_left_to_the_plugin():
    """The loader's marker for text read from the environment, holding text
    the model would refuse: not this check's to refuse. The plugin that reads
    the section names the variable when it is built, and an off-host reporter
    is warned of by the type and not run, as before the check read enabled."""
    value = env_resolved_scalar("maybe", "ASH_SNYK_ENABLED", "${ASH_SNYK_ENABLED}")
    config = _config({"snyk-code": {"enabled": value}})

    assert _refusal(config) is None


def test_an_enabled_reference_left_as_written_is_left_to_the_plugin():
    """A reference the loader left as written (a name a config file may not
    read): the same path, not a refusal of the run."""
    config = _config({"snyk-code": {"enabled": "${SNYK_ENABLED}"}})

    assert _refusal(config) is None
