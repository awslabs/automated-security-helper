# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Every refusal ``refuse_failed_plugin_imports`` raises carries its entries.

``ConfigValidator.with_environment_remedy`` reads ``error.entries`` to decide
whether a closing offers "unset it in ASH_PLUGIN_MODULES". The function raised
its three refusals (import only, registration only, both) with ``entries``
left empty, so a failed module that only the environment contributed never
received that remedy, while the populated raisers (the namespace refusal and
the unfindable-import refusal) did. One cell per raise site. The records are
planted by hand (``zz_`` names, nothing is imported), and the environment-only
subtraction is set on the error the way
``plugin_module_trust.refuse_plugin_modules_a_scan_refuses`` sets it.
"""

from __future__ import annotations

import pytest

from automated_security_helper.config.plugin_module_trust import (
    plugin_module_refusal_message,
)
from automated_security_helper.plugins.loader import (
    PluginLoadFailure,
    PluginModuleImportError,
    refuse_failed_plugin_imports,
)

IMPORTS = "zz_entries_import_fake_mod"
REGISTERS = "zz_entries_register_fake_mod"
REMEDY = "or unset it in ASH_PLUGIN_MODULES."


def _refusal(modules: list, record: dict) -> PluginModuleImportError:
    with pytest.raises(PluginModuleImportError) as raised:
        refuse_failed_plugin_imports(modules, record)
    return raised.value


def _rendered(error: PluginModuleImportError, environment_only: set) -> str:
    error.environment_only_entries = frozenset(environment_only)
    return plugin_module_refusal_message(error)


def test_the_import_only_refusal_carries_its_entry_and_the_remedy():
    record = {IMPORTS: PluginLoadFailure("ImportError: boom", "ImportError", "import")}

    error = _refusal([IMPORTS], record)

    assert error.entries == (IMPORTS,), error.entries
    assert _rendered(error, {IMPORTS}).endswith(REMEDY)


def test_the_registration_only_refusal_carries_its_entry_and_the_remedy():
    record = {REGISTERS: PluginLoadFailure("TypeError: boom", "TypeError", "register")}

    error = _refusal([REGISTERS], record)

    assert error.entries == (REGISTERS,), error.entries
    assert _rendered(error, {REGISTERS}).endswith(REMEDY)


def test_the_mixed_refusal_carries_both_entries_and_the_remedy():
    record = {
        IMPORTS: PluginLoadFailure("ImportError: boom", "ImportError", "import"),
        REGISTERS: PluginLoadFailure("TypeError: boom", "TypeError", "register"),
    }

    error = _refusal([IMPORTS, REGISTERS], record)

    assert set(error.entries) == {IMPORTS, REGISTERS}, error.entries
    # Only the registration module came from the environment: one environment
    # entry among the refused is enough for the remedy, as for the other raisers.
    assert _rendered(error, {REGISTERS}).endswith(REMEDY)
    # And no environment entry among them, no remedy.
    assert not _rendered(error, set()).endswith(REMEDY)
