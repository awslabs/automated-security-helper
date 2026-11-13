# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A bool extra arg reaches snyk spelled as a config file spells it.

``ToolExtraArg.value`` admits a bool and a number, and a spawn takes text
only. ``ScannerPluginBase._resolve_arguments`` spells a bool ``true`` or
``false`` and a number as its digits. :class:`SnykCodeScanner` overrides
``_resolve_arguments`` with its own loop over ``self.args.extra_args``, which
spelled every value with ``str()``, so a bool landed on the command line as
``True`` or ``False``, a spelling no tool's flag parser reads as a bool.

The override keeps the base rule: ``True`` -> ``true``, ``False`` -> ``false``,
``7`` -> ``7``, and a value-less key stands alone.
"""

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.models.core import ToolExtraArg
from automated_security_helper.plugin_modules.ash_snyk_plugins.snyk_code_scanner import (
    SnykCodeScanner,
    SnykCodeScannerConfig,
)

pytestmark = pytest.mark.unit


@pytest.fixture
def scanner(tmp_path):
    context = PluginContext(
        source_dir=tmp_path / "src",
        output_dir=tmp_path / "out",
        work_dir=tmp_path / "work",
        config=get_default_config(),
    )
    context.source_dir.mkdir(parents=True)
    context.output_dir.mkdir(parents=True)
    context.work_dir.mkdir(parents=True)
    return SnykCodeScanner(context=context, config=SnykCodeScannerConfig())


def _argv(scanner, extra_args):
    scanner.args.extra_args = list(extra_args)
    target = scanner.context.source_dir
    return scanner._resolve_arguments(target, scanner.context.work_dir / "r.sarif")


def test_a_bool_value_is_spelled_lowercase(scanner):
    args = _argv(
        scanner,
        [
            ToolExtraArg(key="--report", value=True),
            ToolExtraArg(key="--all-projects", value=False),
        ],
    )

    assert args[args.index("--report") + 1] == "true", args
    assert args[args.index("--all-projects") + 1] == "false", args
    assert "True" not in args and "False" not in args, args


def test_a_number_is_spelled_as_its_digits(scanner):
    args = _argv(scanner, [ToolExtraArg(key="--max-depth", value=7)])

    assert args[args.index("--max-depth") + 1] == "7", args


def test_a_value_less_key_stands_alone(scanner):
    args = _argv(
        scanner,
        [
            ToolExtraArg(key="--debug", value=None),
            ToolExtraArg(key="--org", value="example"),
        ],
    )

    debug = args.index("--debug")
    assert args[debug + 1] == "--org", args
    assert args[debug + 2] == "example", args
    assert args[-1].startswith("--sarif-file-output="), args
