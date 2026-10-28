# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The configs and examples this repository ships load the way a scan loads them.

A plugin section refuses a key beside ``enabled`` that it does not declare, and a
plugin's options refuse one they do not declare. Built-in sections are checked
when the config loads; a plugin from ``ash_plugin_modules`` once the plugins are
loaded (``ScanExecutionEngine.__init__``). Were the repository's own
``.ash/.ash_community_plugins.yaml`` to keep ``snyk-code.severity_threshold`` beside
``enabled``, every community-plugin CI leg would stop at engine init while
``ash config validate`` on the same file passed; a doc or a plugin README showing
options that way hands a user who copies them exit 3.

Each check here runs both stages: the config model, then the loaded-plugin check
with every plugin this distribution ships.
"""

import importlib
import pkgutil
import re
from pathlib import Path

import pytest
import yaml
from pydantic import ValidationError

import automated_security_helper.plugin_modules as plugin_packages
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.plugin_option_check import (
    refuse_unknown_plugin_options,
)
from automated_security_helper.core.exceptions import ASHConfigValidationError
from automated_security_helper.plugins import ash_plugin_manager

REPO = Path(__file__).resolve().parents[3]
SEGMENTS = ("scanners", "reporters", "converters")

for _module in pkgutil.iter_modules(plugin_packages.__path__):
    importlib.import_module(f"{plugin_packages.__name__}.{_module.name}")

PLUGINS = {
    kind: ash_plugin_manager.plugin_modules(kind)
    for kind in ("converter", "scanner", "reporter")
}


def _problems(document: dict) -> list:
    """Why a scan would refuse ``document``'s plugin sections, or nothing."""
    sections = {key: document[key] for key in SEGMENTS if key in document}
    try:
        config = AshConfig.model_validate({"project_name": "docs", **sections})
    except ValidationError as error:
        return [e["msg"] for e in error.errors()]
    try:
        refuse_unknown_plugin_options(config, PLUGINS)
    except ASHConfigValidationError as error:
        return [str(error)]
    return []


@pytest.mark.parametrize(
    "relative",
    sorted(
        p.relative_to(REPO).as_posix()
        for p in (REPO / ".ash").glob("*.y*ml")
        if not p.name.startswith(".ash-workspace")
    ),
)
def test_a_shipped_config_loads_with_its_plugins(relative):
    document = yaml.safe_load((REPO / relative).read_text(encoding="utf-8"))
    assert _problems(document) == []


_FENCE = re.compile(r"^```ya?ml[^\n]*\n(.*?)^```", re.MULTILINE | re.DOTALL)


def _yaml_blocks():
    files = sorted(
        list((REPO / "docs" / "content").rglob("*.md"))
        + list((REPO / "automated_security_helper" / "plugin_modules").rglob("*.md"))
        + [REPO / "README.md"]
    )
    for path in files:
        text = path.read_text(encoding="utf-8")
        for match in _FENCE.finditer(text):
            try:
                document = yaml.safe_load(match.group(1))
            except yaml.YAMLError:
                continue
            if not isinstance(document, dict):
                continue
            if not any(isinstance(document.get(key), dict) for key in SEGMENTS):
                continue
            line = text[: match.start()].count("\n") + 1
            yield pytest.param(
                document, id=f"{path.relative_to(REPO).as_posix()}:{line}"
            )


BLOCKS = list(_yaml_blocks())


def test_the_docs_have_plugin_examples_to_check():
    """Guards the walk: no block found would make the test below vacuous."""
    assert len(BLOCKS) > 20, len(BLOCKS)


@pytest.mark.parametrize("document", BLOCKS)
def test_a_documented_plugin_example_loads(document):
    assert _problems(document) == []
