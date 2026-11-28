"""The invalidation scope enum is defined in ``utils``, and ``core`` re-exports it.

``utils/ash_lock.py`` needs the enum and the layer order does not let ``utils``
import ``core``, so the enum is defined where ``utils`` can reach it. The name
``core.enums.InvalidationScope`` keeps working and is the same class, so a
member from either path compares and serializes alike.
"""

from __future__ import annotations

import pytest

from automated_security_helper.core import enums
from automated_security_helper.utils import invalidation_scope

pytestmark = pytest.mark.unit


def test_core_re_exports_the_same_class():
    assert enums.InvalidationScope is invalidation_scope.InvalidationScope


def test_the_members_are_the_two_kinds_a_lock_records():
    kinds = invalidation_scope.InvalidationScope
    assert [member.value for member in kinds] == ["file", "symbol"]
    assert str(kinds.FILE) == "file"
    assert kinds("symbol") is enums.InvalidationScope.SYMBOL
