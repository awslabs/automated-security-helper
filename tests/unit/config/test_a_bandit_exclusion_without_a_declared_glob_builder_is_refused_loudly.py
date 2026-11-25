# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A bandit exclusion with no declared glob builder fails as an error, not as StopIteration.

``bandit_would_skip`` reads the builder of bandit's ``--exclude`` globs from the
manifests (``ExclusionOption.glob_builder`` on an option of kind ``bandit``). The
lookup was ``next(...)`` with no default, so a manifest set that declared no such
builder ended the call as a bare ``StopIteration``. Inside a generator that is
turned into ``RuntimeError: generator raised StopIteration`` by PEP 479; inside a
``map`` callback or a custom ``__next__`` it ends the iteration with no error at
all, and the findings that were still to be checked are dropped. The call now
raises a ``ScannerError`` that names the missing ``glob_builder``.
"""

from __future__ import annotations

import pytest

from automated_security_helper.config import client_scanner_exclusions
from automated_security_helper.config.client_scanner_exclusions import (
    bandit_would_skip,
)
from automated_security_helper.core.exceptions import ScannerError

pytestmark = pytest.mark.unit


def _call():
    return bandit_would_skip(
        "vendor", relative="vendor/x.py", absolute="/s/vendor/x.py"
    )


def test_control_the_real_manifests_declare_the_builder():
    """Control: with the manifests as shipped the call answers, so the refusal
    below comes from the missing declaration and not from the arguments."""
    assert _call() is True


def test_no_declared_builder_raises_a_scanner_error_naming_it(monkeypatch):
    monkeypatch.setattr(client_scanner_exclusions, "exclusion_options", list)

    with pytest.raises(ScannerError, match="glob_builder"):
        _call()


def test_no_declared_builder_is_not_a_stop_iteration_inside_a_generator(monkeypatch):
    """Red at the base: the call raised ``StopIteration``, which a generator
    caller saw as ``RuntimeError`` and a ``map`` callback as a silent end."""
    monkeypatch.setattr(client_scanner_exclusions, "exclusion_options", list)

    def hidden_findings():
        for _ in range(3):
            yield _call()

    with pytest.raises(ScannerError):
        list(hidden_findings())


def test_each_scanner_is_matched_by_the_builder_its_own_option_declares(monkeypatch):
    """Two manifests may share the kind with different builders. The matcher took
    the first bandit-kind builder in manifest order whichever scanner the entry
    came from, so the second scanner's entries were matched by the first's globs."""
    from automated_security_helper.base.plugin_manifest import ExclusionOption

    declared = [
        (
            "scanner-a",
            ExclusionOption(option="x", kind="bandit", glob_builder="pkg.one:build"),
        ),
        (
            "scanner-b",
            ExclusionOption(option="y", kind="bandit", glob_builder="pkg.two:build"),
        ),
    ]
    builders = {
        "pkg.one:build": lambda root, pattern: [],
        "pkg.two:build": lambda root, pattern: ["*"],
    }
    monkeypatch.setattr(
        client_scanner_exclusions, "exclusion_options", lambda: declared
    )
    monkeypatch.setattr(client_scanner_exclusions, "resolve_ref", builders.__getitem__)
    where = {"relative": "v/x.py", "absolute": "/s/v/x.py"}

    assert bandit_would_skip("v", scanner="scanner-a", option="x", **where) is False
    assert bandit_would_skip("v", scanner="scanner-b", option="y", **where) is True


def test_a_map_callback_does_not_end_its_iteration_silently(monkeypatch):
    monkeypatch.setattr(client_scanner_exclusions, "exclusion_options", list)

    def call_for(_item):
        return _call()

    with pytest.raises(ScannerError):
        list(map(call_for, range(3)))
