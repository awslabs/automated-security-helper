# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``discover_plugins`` redacts a fresh import failure with the run's env-read values.

The loader records a module's import failure with the values the configuration
read from the environment redacted and carried on the error object. The import
``discover_plugins`` makes raises a NEW exception object, which carries none of
them, and its warning line went through ``error_text`` with no values: a value the
loader had redacted from the same failure printed unredacted here. The engine now
hands the discovery the run's values, and the warning is redacted with them.
"""

from __future__ import annotations

import importlib
from unittest.mock import patch

import pytest

from automated_security_helper.plugins.discovery import discover_plugins

pytestmark = pytest.mark.unit

_SECRET = "quoted-env-value-7f"


def _package_whose_import_quotes_the_value(tmp_path, monkeypatch) -> str:
    name = "quoting_ash_plugins"
    package = tmp_path / name
    package.mkdir()
    (package / "__init__.py").write_text(
        f'raise ImportError("cannot reach {_SECRET} while loading")\n'
    )
    monkeypatch.syspath_prepend(str(tmp_path))
    importlib.invalidate_caches()
    return name


def test_the_import_warning_is_redacted_with_the_runs_values(tmp_path, monkeypatch):
    """Red before the fix: discover_plugins took no values, so the warning
    quoted the value as the exception did."""
    name = _package_whose_import_quotes_the_value(tmp_path, monkeypatch)

    with patch("automated_security_helper.plugins.discovery.ASH_LOGGER") as logger:
        discover_plugins(plugin_modules=[name], values=(_SECRET,))

    warnings = " ".join(str(c.args[0]) for c in logger.warning.call_args_list)
    assert "Failed to import plugin" in warnings
    assert _SECRET not in warnings


def test_without_values_the_warning_still_names_the_failure(tmp_path, monkeypatch):
    """Control: no values given, the error's own text is shown as before."""
    name = _package_whose_import_quotes_the_value(tmp_path, monkeypatch)

    with patch("automated_security_helper.plugins.discovery.ASH_LOGGER") as logger:
        discover_plugins(plugin_modules=[name])

    warnings = " ".join(str(c.args[0]) for c in logger.warning.call_args_list)
    assert "cannot reach" in warnings
