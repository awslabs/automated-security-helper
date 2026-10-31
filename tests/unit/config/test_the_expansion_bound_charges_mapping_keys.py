# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``refuse_past_expansion_bound`` charges a mapping's keys as well as its values.

Writing a document out costs each key's characters as it costs each value's,
but the budget charged values only, so an aliased long key repeated across
many aliased mappings passed the text budget on its values alone.

Red at the base: the mapping below, whose keys alone hold more characters than
the byte budget, passed.
"""

from __future__ import annotations

import pytest

from automated_security_helper.config import config_sources
from automated_security_helper.config.config_sources import (
    refuse_past_expansion_bound,
)
from automated_security_helper.core.exceptions import ASHConfigSourceError

pytestmark = pytest.mark.unit


def test_keys_past_the_byte_budget_are_refused() -> None:
    key_length = config_sources._UNALIASED_BYTE_BOUND // 4 + 1
    document = {("k" * key_length) + str(index): 1 for index in range(5)}

    with pytest.raises(ASHConfigSourceError, match="expands to more than"):
        refuse_past_expansion_bound(document, "the document")


def test_keys_under_the_budget_pass() -> None:
    """The control: the same shape with keys that fit the budget."""
    key_length = config_sources._UNALIASED_BYTE_BOUND // 8
    document = {("k" * key_length) + str(index): 1 for index in range(5)}

    assert refuse_past_expansion_bound(document, "the document") is None
