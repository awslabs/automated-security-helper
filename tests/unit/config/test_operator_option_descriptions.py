# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A scanner option only the operator sets says who that is, in one shared sentence.

``config/tool_config_trust.py`` takes a scanner's own config file, and the options
that choose part of it, from the trusted base when the config that set them is
repository-written: inside any git checkout or the scanned directory
(``sandbox_grants.repository_written``), or delivered by an MCP client. The
descriptions of those options said "a config file outside the scanned tree",
which a config file in another git checkout, such as an operator's ops
repository, also is, and that file does not choose them. Each description now
ends its rule with ``confinement_remedy.SET_BY_THE_OPERATOR``, the rule as
resolution applies it, and the JSON schemas and reference pages built from the
descriptions say the same.
"""

from __future__ import annotations

import importlib
import pkgutil
from typing import Dict, Iterator, Tuple

import pytest

import automated_security_helper.plugin_modules as plugin_modules
from automated_security_helper.base.scanner_plugin import ScannerPluginConfigBase
from automated_security_helper.config.confinement_remedy import SET_BY_THE_OPERATOR

#: The options whose descriptions state who sets them, by scanner.
STATED: Dict[str, Tuple[str, ...]] = {
    "bandit": ("config_file",),
    "grype": ("config_file",),
    "syft": ("config_file",),
    "ferret-scan": ("profile", "use_default_config"),
    "snyk-code": ("honor_tree_exclusions",),
    "trivy-repo": ("ignore_file", "secret_config_file"),
}

#: The wording the rule used before, which a file in another checkout also meets.
OUTDATED = "config file outside the scanned tree"


def _scanner_options() -> Dict[str, type]:
    """Each scanner's options model, by scanner name, from every bundled plugin module."""
    for module in pkgutil.walk_packages(
        plugin_modules.__path__, plugin_modules.__name__ + "."
    ):
        importlib.import_module(module.name)
    found: Dict[str, type] = {}
    pending = list(ScannerPluginConfigBase.__subclasses__())
    while pending:
        cls = pending.pop()
        pending.extend(cls.__subclasses__())
        name = cls.model_fields.get("name")
        options = cls.model_fields.get("options")
        if name is None or options is None or not isinstance(name.default, str):
            continue
        if isinstance(options.annotation, type):
            found[name.default] = options.annotation
    return found


def _descriptions() -> Iterator[Tuple[str, str, str]]:
    for scanner, model in sorted(_scanner_options().items()):
        for option, field in model.model_fields.items():
            yield scanner, option, field.description or ""


@pytest.mark.parametrize(
    ("scanner", "option"),
    [(scanner, option) for scanner, options in STATED.items() for option in options],
)
def test_the_option_states_who_sets_it_with_the_shared_sentence(scanner, option):
    description = _scanner_options()[scanner].model_fields[option].description or ""

    assert SET_BY_THE_OPERATOR in description, description


def test_no_scanner_option_states_the_outdated_rule():
    stale = [
        f"{scanner}.{option}"
        for scanner, option, description in _descriptions()
        if OUTDATED in description
    ]

    assert stale == []


def test_control_the_options_are_found():
    """The walk reaches every scanner named above, so the checks are not vacuous."""
    options = _scanner_options()

    for scanner, names in STATED.items():
        assert scanner in options, sorted(options)
        for name in names:
            assert name in options[scanner].model_fields, (scanner, name)
