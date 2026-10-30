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
