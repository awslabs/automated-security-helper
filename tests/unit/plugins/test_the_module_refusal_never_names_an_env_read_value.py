# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The plugin-module refusal names an entry the config read from the environment
by its reference, never by the variable's value.

``refuse_plugin_modules_outside_namespace`` takes a ``shown`` mapping for
exactly this, and its callers pass one, so a refusal names an env-read
``ash_plugin_modules`` entry by its reference. Both spellings resolve to the
value and record a
reference (measured: ``resolve_config`` gives each one entry holding the value
and one ``_environment_references`` entry): the ``!ENV ${VAR}`` tag and a plain
``${VAR}``. The engine and ``load_plugins`` pass the mapping
(``plugin_module_trust.config_module_names``), which names such an entry
``<value>``; a literal entry is still named as written.
"""

from __future__ import annotations

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.resolve_config import resolve_config
from automated_security_helper.plugins.loader import (
    PluginModuleNamespaceError,
    load_plugins,
)

#: The variable's value: outside the namespace, so the refusal fires on it, and
#: a name nothing else in the message would contain, so finding it is the leak.
VALUE = "env_named_module"
MASKED = "<value>"


@pytest.fixture(params=["!ENV ${ASH_T_PLUGIN}", "${ASH_T_PLUGIN}"])
def env_read_config(request, tmp_path, monkeypatch):
    """A resolved config whose first entry reads from the environment, in both
    spellings that do: the ``!ENV`` tag and a plain ``${VAR}``."""
    monkeypatch.setenv("ASH_T_PLUGIN", VALUE)
    # The config file sits outside the scanned tree (the cwd), so its
    # ash_plugin_modules entries are the operator's and are kept as given;
    # a file inside the tree keeps only installed modules.
    source = tmp_path / "src"
    source.mkdir()
    monkeypatch.chdir(source)
    config_file = tmp_path / "cfg" / ".ash.yaml"
    config_file.parent.mkdir()
    config_file.write_text(
        "project_name: probe\n"
        "ash_plugin_modules:\n"
        f"  - {request.param}\n"
        "  - literal_module\n"
    )
    return resolve_config(config_path=str(config_file))


def _context(tmp_path, config) -> PluginContext:
    return PluginContext(
        source_dir=tmp_path,
        output_dir=tmp_path / "out",
        work_dir=tmp_path / "out" / "work",
        config=config,
    )


def test_load_plugins_shows_the_entry_masked(tmp_path, env_read_config):
    with pytest.raises(PluginModuleNamespaceError) as refused:
        load_plugins(plugin_context=_context(tmp_path, env_read_config))

    message = str(refused.value)
    assert VALUE not in message, message
    assert MASKED in message, message
    # A literal entry is still named as written.
    assert "literal_module" in message, message


def test_the_engine_log_names_the_entry_masked(tmp_path, env_read_config):
    """The INFO line naming the modules about to load is masked like the
    refusal. It is logged before the check, so the resolved value would
    otherwise reach the console and ash.log in the same run whose refusal
    hides it."""
    import logging
    from unittest.mock import patch

    from automated_security_helper.core.execution_engine import ScanExecutionEngine
    from automated_security_helper.utils.log import ASH_LOGGER

    class Sink(logging.Handler):
        def __init__(self):
            super().__init__(level=1)
            self.messages: list = []

        def emit(self, record):
            self.messages.append(record.getMessage())

    sink = Sink()
    level = ASH_LOGGER.level
    ASH_LOGGER.addHandler(sink)
    # The logger's own level gates records before any handler sees them.
    ASH_LOGGER.setLevel(1)
    try:
        with (
            patch("automated_security_helper.plugins.loader.load_internal_plugins"),
            pytest.raises(PluginModuleNamespaceError),
        ):
            ScanExecutionEngine(
                context=_context(tmp_path, env_read_config), show_progress=False
            )
    finally:
        ASH_LOGGER.removeHandler(sink)
        ASH_LOGGER.setLevel(level)

    joined = " ".join(sink.messages)
    assert VALUE not in joined, joined
    assert any(
        "Loading plugin modules" in message and MASKED in message
        for message in sink.messages
    ), sink.messages


def test_the_engine_shows_the_entry_masked(tmp_path, env_read_config):
    from unittest.mock import patch

    from automated_security_helper.core.execution_engine import ScanExecutionEngine

    with (
        patch("automated_security_helper.plugins.loader.load_internal_plugins"),
        pytest.raises(PluginModuleNamespaceError) as refused,
    ):
        ScanExecutionEngine(
            context=_context(tmp_path, env_read_config), show_progress=False
        )

    message = str(refused.value)
    assert VALUE not in message, message
    assert MASKED in message, message
    assert "literal_module" in message, message
