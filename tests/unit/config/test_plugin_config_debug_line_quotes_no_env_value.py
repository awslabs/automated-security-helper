# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The debug line for a plugin's config section names no value read from the
environment.

``AshConfig.get_plugin_config`` logs the section it found for a plugin at
DEBUG, whole: with ``--debug`` on the console, and in ash.log when the file
handler records DEBUG. A value the config file reads from the environment,
``${VAR}`` under a reporter's options here, is the variable's value by then,
and the line names no such value.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from automated_security_helper.config.resolve_config import resolve_config

CANARY = "ash-canary-7f3e-0123456789"
CONFIG = (
    "project_name: demo\n"
    "reporters:\n"
    "  gitlab-cyclonedx:\n"
    "    options:\n"
    "      language_override: ${ASH_PROBE_VALUE}\n"
)


def test_the_section_is_logged_without_the_value(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("ASH_PROBE_VALUE", CANARY)
    config_file = tmp_path / ".ash.yaml"
    config_file.write_text(CONFIG, encoding="utf-8")
    config = resolve_config(config_file)

    with patch("automated_security_helper.config.ash_config.ASH_LOGGER") as log:
        section = config.get_plugin_config(
            plugin_type="reporter", plugin_name="gitlab-cyclonedx"
        )

    # The control: the plugin gets the value, and the section was logged.
    assert section["options"]["language_override"] == CANARY, section
    logged = " ".join(str(call) for call in log.mock_calls)
    assert "Found config for reporter plugin gitlab-cyclonedx" in logged, logged
    assert CANARY not in logged, logged


@pytest.mark.parametrize("extends", [False, True], ids=["one-file", "extends"])
def test_the_values_are_known_without_parsing_a_file_twice(
    tmp_path: Path, monkeypatch, extends
):
    """resolve_config keeps the values the chain read for those lines, from what
    the load read: each parse resolves every !ENV reference again and logs its
    warning again. With ``extends`` the value is in the base file."""
    import automated_security_helper.config.config_sources as config_sources

    monkeypatch.setenv("ASH_PROBE_VALUE", CANARY)
    parses = []
    real_loader = config_sources.load_yaml_config

    def counting_loader(stream):
        parses.append(stream)
        return real_loader(stream)

    monkeypatch.setattr(config_sources, "load_yaml_config", counting_loader)
    config_file = tmp_path / ".ash.yaml"
    if extends:
        (tmp_path / "base.yaml").write_text(CONFIG, encoding="utf-8")
        config_file.write_text("extends: base.yaml\n", encoding="utf-8")
    else:
        config_file.write_text(CONFIG, encoding="utf-8")

    config = resolve_config(config_file)

    assert len(parses) == (2 if extends else 1), parses
    assert CANARY in config._environment_values, config._environment_values


def test_the_ash_config_file_s_refusal_names_no_env_read_key(
    tmp_path: Path, monkeypatch
):
    """The MCP server's scan of a directory with no configuration: resolve_config
    is given no file, so the run's configuration is get_default_config()'s, the
    ASH_CONFIG file's. (ash scan reads ASH_CONFIG as its --config instead.) An
    option key that file reads from the environment, of a plugin it loads, is
    refused at the option check, and the refusal names no such key."""
    from automated_security_helper.config.plugin_option_check import (
        refuse_unknown_plugin_options,
    )
    from automated_security_helper.core.exceptions import ASHConfigValidationError
    from automated_security_helper.plugin_modules.ash_trivy_plugins import (
        ASH_SCANNERS,
    )

    monkeypatch.setenv("ASH_PROBE_VALUE", CANARY)
    config_file = tmp_path / "ash-config.yaml"
    config_file.write_text(
        "project_name: operator\n"
        "scanners:\n"
        "  trivy-repo:\n"
        "    options:\n"
        "      ${ASH_PROBE_VALUE}: true\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("ASH_CONFIG", str(config_file))
    scanned = tmp_path / "scanned"
    scanned.mkdir()

    config = resolve_config(source_dir=scanned)
    with pytest.raises(ASHConfigValidationError) as refused:
        refuse_unknown_plugin_options(config, {"scanner": ASH_SCANNERS})

    # The control: the refusal is the option check's, at trivy-repo's options,
    # for a key read from the environment (the marker is where the value
    # would be).
    assert "scanners.trivy-repo.options" in str(refused.value), refused.value
    assert "Unknown key '<value>'" in str(refused.value), refused.value
    assert CANARY not in str(refused.value), refused.value


@pytest.mark.parametrize("extends", [False, True], ids=["one-file", "extends"])
def test_the_ash_config_file_s_values_are_known(tmp_path: Path, monkeypatch, extends):
    """get_default_config, the configuration a scan starts from when nothing
    else names one, knows the values its chain read too, from one parse."""
    import automated_security_helper.config.config_sources as config_sources
    from automated_security_helper.config.default_config import get_default_config

    monkeypatch.setenv("ASH_PROBE_VALUE", CANARY)
    parses = []
    real_loader = config_sources.load_yaml_config

    def counting_loader(stream):
        parses.append(stream)
        return real_loader(stream)

    monkeypatch.setattr(config_sources, "load_yaml_config", counting_loader)
    config_file = tmp_path / "ash-config.yaml"
    if extends:
        (tmp_path / "base.yaml").write_text(CONFIG, encoding="utf-8")
        config_file.write_text("extends: base.yaml\n", encoding="utf-8")
    else:
        config_file.write_text(CONFIG, encoding="utf-8")
    monkeypatch.setenv("ASH_CONFIG", str(config_file))

    config = get_default_config()

    # The control: the file was loaded.
    assert (
        config.reporters.model_dump(by_alias=True)["gitlab-cyclonedx"]["options"][
            "language_override"
        ]
        == CANARY
    )
    assert len(parses) == (2 if extends else 1), parses
    assert CANARY in config._environment_values, config._environment_values
