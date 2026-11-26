# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""An exclusion that names its scanner and option is matched by that option's builder.

``bandit_would_skip`` took the first bandit-kind glob builder in manifest order
whenever the named option's own declaration was missing, of another kind, or had
no builder. Another tool's exclude semantics then decided which findings were
hidden, and the answer could be "hidden" for a finding the named scanner would
have reported. With both ``scanner`` and ``option`` named the option's own
bandit builder is required and a ``ScannerError`` names what is missing. A
caller that names no option keeps the manifest-order fallback.
"""

from __future__ import annotations

import pytest

from automated_security_helper.base.plugin_manifest import ExclusionOption
from automated_security_helper.config import client_scanner_exclusions
from automated_security_helper.config.client_scanner_exclusions import (
    bandit_would_skip,
)
from automated_security_helper.core.exceptions import ScannerError

pytestmark = pytest.mark.unit

WHERE = {"relative": "v/x.py", "absolute": "/s/v/x.py"}

# The other tool's builder hides everything; if it is ever consulted the answer
# is True, which is the hide-findings direction.
BUILDERS = {
    "pkg.other:build": lambda root, pattern: ["*"],
    "pkg.own:build": lambda root, pattern: [],
}


def _install(monkeypatch, declared):
    monkeypatch.setattr(
        client_scanner_exclusions, "exclusion_options", lambda: declared
    )
    monkeypatch.setattr(client_scanner_exclusions, "resolve_ref", BUILDERS.__getitem__)


OTHER = (
    "other-tool",
    ExclusionOption(option="o", kind="bandit", glob_builder="pkg.other:build"),
)


def test_control_the_options_own_builder_decides(monkeypatch):
    own = (
        "mine",
        ExclusionOption(option="x", kind="bandit", glob_builder="pkg.own:build"),
    )
    _install(monkeypatch, [OTHER, own])

    assert bandit_would_skip("v", scanner="mine", option="x", **WHERE) is False


def test_a_missing_declaration_is_refused_not_matched_by_another_tools_builder(
    monkeypatch,
):
    """Red at the base: answered True from the other tool's builder."""
    _install(monkeypatch, [OTHER])

    with pytest.raises(ScannerError, match="mine.*x|glob_builder"):
        bandit_would_skip("v", scanner="mine", option="x", **WHERE)


def test_a_declaration_of_another_kind_is_refused(monkeypatch):
    """Red at the base: answered True from the other tool's builder."""
    wrong = ("mine", ExclusionOption(option="x", kind="glob"))
    _install(monkeypatch, [OTHER, wrong])

    with pytest.raises(ScannerError, match="glob_builder"):
        bandit_would_skip("v", scanner="mine", option="x", **WHERE)


def test_a_bandit_declaration_with_no_builder_is_refused(monkeypatch):
    """Red at the base: answered True from the other tool's builder."""
    # The model refuses this shape at validation; built unvalidated it is what a
    # manifest set that bypassed validation would hand the matcher.
    builderless = (
        "mine",
        ExclusionOption.model_construct(
            option="x",
            kind="bandit",
            default=(),
            split_commas=False,
            glob_builder=None,
        ),
    )
    _install(monkeypatch, [OTHER, builderless])

    with pytest.raises(ScannerError, match="glob_builder"):
        bandit_would_skip("v", scanner="mine", option="x", **WHERE)


def test_a_caller_that_names_no_option_keeps_the_manifest_order_fallback(
    monkeypatch,
):
    _install(monkeypatch, [OTHER])

    assert bandit_would_skip("v", **WHERE) is True
    assert bandit_would_skip("v", scanner="mine", **WHERE) is True
