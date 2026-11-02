# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A bool extra arg reaches ferret-scan spelled as a config file spells it.

``ToolExtraArg.value`` admits a bool and a number, and a spawn takes text
only. ``ScannerPluginBase._resolve_arguments`` spells a bool ``true`` or
``false`` and a number as its digits. :class:`FerretScanScanner` overrides
``_resolve_arguments`` with its own loop over ``self.args.extra_args``, which
spelled every value with ``str()``, so a bool landed on the command line as
``True`` or ``False``, a spelling no tool's flag parser reads as a bool.

The override keeps the base rule: ``True`` -> ``true``, ``False`` -> ``false``,
``7`` -> ``7``, and a value-less key stands alone.
"""

from unittest.mock import patch

import pytest

from automated_security_helper.models.core import ToolExtraArg
from automated_security_helper.plugin_modules.ash_ferret_plugins.ferret_scanner import (
    FerretScanScanner,
)

pytestmark = pytest.mark.unit


def _seeded(scanner, extra_args):
    """Stand in for ``_process_config_options``, which rebuilds the list.

    ferret-scan's own options never carry a bool value, so the extra args are
    seeded here, as a plugin configuration carrying them would, after the
    method that clears the list has run.
    """

    def seed():
        scanner.args.extra_args = list(extra_args)

    return patch.object(scanner, "_process_config_options", side_effect=seed)


def test_a_bool_value_is_spelled_lowercase(mock_plugin_context, tmp_path):
    scanner = FerretScanScanner(context=mock_plugin_context)
    extra_args = [
        ToolExtraArg(key="--validate", value=True),
        ToolExtraArg(key="--parallel", value=False),
    ]

    with _seeded(scanner, extra_args):
        args = scanner._resolve_arguments(target=tmp_path)

    assert args[args.index("--validate") + 1] == "true", args
    assert args[args.index("--parallel") + 1] == "false", args
    assert "True" not in args and "False" not in args, args


def test_a_number_is_spelled_as_its_digits(mock_plugin_context, tmp_path):
    scanner = FerretScanScanner(context=mock_plugin_context)

    with _seeded(scanner, [ToolExtraArg(key="--limit", value=7)]):
        args = scanner._resolve_arguments(target=tmp_path)

    assert args[args.index("--limit") + 1] == "7", args


def test_a_value_less_key_stands_alone(mock_plugin_context, tmp_path):
    scanner = FerretScanScanner(context=mock_plugin_context)
    extra_args = [
        ToolExtraArg(key="--recursive", value=None),
        ToolExtraArg(key="--checks", value="SECRETS"),
    ]

    with _seeded(scanner, extra_args):
        args = scanner._resolve_arguments(target=tmp_path)

    recursive = args.index("--recursive")
    assert args[recursive + 1] == "--checks", args
    assert args[recursive + 2] == "SECRETS", args
