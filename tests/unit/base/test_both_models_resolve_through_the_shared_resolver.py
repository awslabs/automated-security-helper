# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Both models resolve their AshConfig forward reference through one resolver.

``base.plugin_context`` and ``models.asharp_model`` each carried a byte-equivalent
copy of a once-only resolver: a lock, a resolved flag set after the rebuild, a
double-checked import and bind. The copies drift (one gained the import-outside-
the-lock fix before the other). Both now call ``base.forward_refs.OnceOnlyResolver``,
and this file pins the shared shape and the resolver's own behavior.
"""

from __future__ import annotations

import pytest

from automated_security_helper.base import plugin_context as plugin_context_module
from automated_security_helper.base.forward_refs import OnceOnlyResolver
from automated_security_helper.models import asharp_model

pytestmark = pytest.mark.unit


def test_both_modules_resolve_through_the_shared_resolver():
    assert isinstance(plugin_context_module._forward_refs, OnceOnlyResolver)
    assert isinstance(asharp_model._forward_refs, OnceOnlyResolver)
    # Each module keeps its own instance (its own lock and flag): two models,
    # two rebuilds, one implementation.
    assert plugin_context_module._forward_refs is not asharp_model._forward_refs
    plugin_context_module._resolve_forward_refs()
    asharp_model._resolve_forward_refs()
    assert plugin_context_module._forward_refs.resolved is True
    assert asharp_model._forward_refs.resolved is True
    # The bind put the class on the module, where the model's annotation names it.
    assert getattr(asharp_model, "AshConfig", None) is not None


def test_the_resolver_binds_once_and_sets_the_flag_after_the_bind():
    resolver: OnceOnlyResolver[str] = OnceOnlyResolver()
    bound = []

    def bind(target: str) -> None:
        # The flag is still down while the bind runs: a caller that saw it early
        # would skip the rebuild and run against the still-mocked validator.
        assert resolver.resolved is False
        bound.append(target)

    resolver.resolve(lambda: "the class", bind)
    resolver.resolve(lambda: "the class again", bind)

    assert bound == ["the class"]
    assert resolver.resolved is True


def test_an_unimportable_target_leaves_the_resolver_unresolved():
    resolver: OnceOnlyResolver[str] = OnceOnlyResolver()

    def not_yet() -> str:
        raise ImportError("mid-cycle")

    resolver.resolve(not_yet, lambda _target: None)

    assert resolver.resolved is False
    resolver.resolve(lambda: "now", lambda _target: None)
    assert resolver.resolved is True
