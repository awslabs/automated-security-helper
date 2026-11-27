# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``selection_key`` is the one key scanner names are compared on.

The scan phase, the selection helpers and the MCP result filters each used to
carry their own copy of this composition (strip, resolve a retired name, lower).
"""

import pytest

from automated_security_helper.core.resource_management import result_filters
from automated_security_helper.core.scanner_selection import selection_after_exclusions
from automated_security_helper.utils.scanner_names import selection_key

pytestmark = pytest.mark.unit


@pytest.mark.parametrize(
    "typed, key",
    [
        ("Bandit", "bandit"),
        (" bandit ", "bandit"),
        ("semgrep", "opengrep"),
        (" Semgrep ", "opengrep"),
        ("OpenGrep", "opengrep"),
        ("cfn-nag", "cfn-nag"),
    ],
)
def test_the_key_strips_lowers_and_resolves_a_retired_name(typed, key):
    assert selection_key(typed) == key


def test_a_retired_name_and_its_replacement_share_a_key():
    assert selection_key("semgrep") == selection_key("opengrep")


def test_no_module_restates_the_key_under_a_private_name():
    from automated_security_helper.core import scanner_selection

    assert not hasattr(scanner_selection, "_selection_key")
    assert not hasattr(result_filters, "_scanner_key")


def test_the_selection_helpers_compare_through_the_key():
    assert selection_after_exclusions(["opengrep", "bandit"], ["Semgrep"]) == ["bandit"]
