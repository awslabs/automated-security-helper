# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""repr and str of a configuration show no value it read from the environment.

AshConfig's repr prints its resolved fields, so a value a file read through
``${VAR}`` sat in it as written, wherever the field is: at the top
(ash_plugin_modules) or inside a nested section (an ignore path's reason).
Reprs reach users through tracebacks with locals (show_debug_locals), DEBUG
logs of objects, and the text around a validation error, and a model that
embeds a config (PluginContext) prints it through the same path. Every
env-read value shows <value> there, and a literal value stays readable.
"""

from io import StringIO

import pytest
from rich.console import Console
from rich.traceback import Traceback

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config import resolve_config as resolve_config_module
from automated_security_helper.utils.error_text import config_environment_values

pytestmark = pytest.mark.unit

#: The values the config's file reads from the environment: one for a top-level
#: list field, one for a field inside a nested section. Nothing else in the
#: config prints them.
MODULE_CANARY = "zzreprmod_ash_plugins"
REASON_CANARY = "zzreprvalue-7421"
#: A value written literally in the same file, which redaction must not touch.
LITERAL = "readable-project-name"

WRITTEN = (
    f"project_name: {LITERAL}\n"
    "global_settings:\n"
    "  ignore_paths:\n"
    "    - path: vendor/**\n"
    "      reason: !ENV ${ASH_ZR_REASON}\n"
    "ash_plugin_modules:\n"
    "  - !ENV ${ASH_ZR_MOD}\n"
)


@pytest.fixture
def config(tmp_path, monkeypatch):
    """The config loaded the way a run loads it, its environment reads known."""
    monkeypatch.setenv("ASH_ZR_MOD", MODULE_CANARY)
    monkeypatch.setenv("ASH_ZR_REASON", REASON_CANARY)
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    path = tmp_path / ".ash.yaml"
    path.write_text(WRITTEN, encoding="utf-8")
    _, loaded = resolve_config_module.load_config_file_for_run(path)
    known = set(config_environment_values(loaded)) >= {MODULE_CANARY, REASON_CANARY}
    assert known, "control: the config does not know the values it read"
    # Controls: the values really sit in the resolved fields.
    assert MODULE_CANARY in loaded.ash_plugin_modules
    reasons = [entry.reason for entry in loaded.global_settings.ignore_paths]
    assert REASON_CANARY in reasons
    return loaded


def _shows_no_value(text: str) -> None:
    assert MODULE_CANARY not in text, "the top-level env value prints as written"
    assert REASON_CANARY not in text, "the nested env value prints as written"


def test_the_configs_repr_shows_no_environment_value(config):
    text = repr(config)
    _shows_no_value(text)
    assert "<value>" in text, "the env-read fields are not shown as <value>"
    assert LITERAL in text, "a literal value went unreadable"


def test_the_configs_str_shows_no_environment_value(config):
    _shows_no_value(str(config))


def test_a_model_embedding_the_config_prints_it_redacted(config, tmp_path):
    context = PluginContext(
        source_dir=tmp_path / "src",
        output_dir=tmp_path / "out",
        config=config,
    )
    _shows_no_value(repr(context))


def test_a_rich_traceback_with_locals_shows_no_environment_value(config):
    """The traceback renderer prints each frame local through its repr: the
    frame holding the config is the one show_debug_locals surfaces."""

    def failing(loaded_config):
        raise ValueError("the error whose traceback shows the frame's locals")

    try:
        failing(config)
    except ValueError:
        rendered = Traceback(show_locals=True, width=200)
    console = Console(file=StringIO(), width=200, force_terminal=False)
    console.print(rendered)
    _shows_no_value(console.file.getvalue())
