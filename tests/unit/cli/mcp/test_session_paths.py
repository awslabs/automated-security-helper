#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The two layers that turn a caller-supplied id into one path component.

Each layer is tested on its own. They are deliberately redundant -- the allowlist
is the barrier and the containment check backs it up -- and two guards in series
are the classic way to end up with neither one actually tested, because whichever
runs first hides the other from every input a test can supply through the front
door. So :class:`TestTheAllowlist` drives ``validated_path_component`` directly and
:class:`TestTheContainmentCheck` drives ``joined_inside`` directly with values the
allowlist would never have passed through.
"""

from __future__ import annotations

import pytest

from automated_security_helper.cli.mcp.session_paths import (
    joined_inside,
    session_directory,
    validated_path_component,
)

#: Forms the allowlist has to refuse. Each is a distinct reason rather than a
#: variation on one: a drive-letter prefix, a bare drive, both relative
#: components, separators in both directions, a NUL and other control characters,
#: a space, a glob character, a colon that is not a drive, and empty.
REFUSED = [
    "D:x",
    "C:x",
    "C:",
    "..",
    ".",
    "",
    "a/b",
    "a\\b",
    "a\x00b",
    "a\nb",
    "a b",
    "a?b",
    "a*b",
    "a:b",
    "a|b",
    'a"b',
    "a<b",
]

#: Forms it has to keep accepting. A server-assigned session id is UUID-shaped, so
#: the hyphenated and bare-hex cases are what production actually supplies; the
#: others pin the remaining characters the class allows so a future tightening has
#: to be deliberate.
ACCEPTED = [
    "session-a",
    "6f1d2c3b4a5e6f70",
    "b7f3e1c2-4d5a-6b7c-8d9e-0f1a2b3c4d5e",
    "under_score",
    "dotted.name",
    "MiXedCase99",
    "__default__",
]


class TestTheAllowlist:
    """``validated_path_component`` decides what may become a path component."""

    @pytest.mark.parametrize("value", REFUSED)
    def test_a_value_outside_the_allowlist_is_rejected(self, value):
        with pytest.raises(ValueError):
            validated_path_component(value)

    @pytest.mark.parametrize("value", ACCEPTED)
    def test_a_value_inside_the_allowlist_is_returned_unchanged(self, value):
        """Returned, not rewritten.

        Positive control, and it has to be here: a validator that rejected
        everything would satisfy every case above while breaking every session.
        Returning the value unchanged also pins that nothing is sanitized --
        mapping two ids onto one component would merge two callers' directories.
        """
        assert validated_path_component(value) == value

    def test_the_message_names_the_field(self):
        """A refusal that does not say which input was wrong is not actionable."""
        with pytest.raises(ValueError, match="upload_id"):
            validated_path_component("a/b", "upload_id")


class TestTheContainmentCheck:
    """``joined_inside`` is the second layer, and it is reachable on its own.

    Every value here would have been stopped by the allowlist. They are passed
    straight to ``joined_inside`` on purpose: the point of a backstop is that it
    works for a caller who did not run the first check, and a backstop that cannot
    be made to fire is decoration rather than defense.
    """

    def test_a_component_that_climbs_out_is_rejected(self, tmp_path):
        parent = tmp_path / "workspaces"
        parent.mkdir()

        with pytest.raises(ValueError):
            joined_inside(parent, "..")

    def test_a_component_that_climbs_further_out_is_rejected(self, tmp_path):
        parent = tmp_path / "workspaces"
        parent.mkdir()

        with pytest.raises(ValueError):
            joined_inside(parent, "../../elsewhere")

    def test_an_absolute_component_is_rejected(self, tmp_path):
        """An absolute segment replaces the parent rather than extending it."""
        parent = tmp_path / "workspaces"
        parent.mkdir()
        outside = tmp_path / "elsewhere"

        with pytest.raises(ValueError):
            joined_inside(parent, str(outside))

    def test_landing_on_the_parent_itself_is_rejected(self, tmp_path):
        """Equality is a failure, not a pass.

        ``"."`` resolves back to the parent, and every caller goes on to create or
        remove what it is handed, so returning the parent would hand a caller the
        directory that holds every other session's.
        """
        parent = tmp_path / "workspaces"
        parent.mkdir()

        with pytest.raises(ValueError):
            joined_inside(parent, ".")

    def test_an_ordinary_component_passes_and_is_returned_unresolved(self, tmp_path):
        """Positive control, plus the return-shape contract.

        The unresolved join is what callers get, so one that compares the result
        against its own spelling still matches. Asserting the exact value here is
        what would catch a change to ``resolve()``-and-return.
        """
        parent = tmp_path / "workspaces"
        parent.mkdir()

        assert joined_inside(parent, "session-a") == parent / "session-a"

    def test_it_holds_when_the_parent_is_reached_through_a_symlink(self, tmp_path):
        """Both sides are resolved, so a symlinked parent still contains its child.

        Without resolving the parent, the comparison would be made between a
        resolved child and an unresolved parent and would fail for a legitimate
        component -- refusing every session on a host whose workspace root is a
        symlink, which is the ordinary arrangement on macOS under /var.
        """
        real = tmp_path / "real-workspaces"
        real.mkdir()
        link = tmp_path / "workspaces"
        link.symlink_to(real, target_is_directory=True)

        assert joined_inside(link, "session-a") == link / "session-a"


class TestBothLayersTogether:
    """``session_directory`` is the form every caller should use."""

    def test_it_rejects_what_the_allowlist_rejects(self, tmp_path):
        """The parent is never examined, because validation runs first.

        ``validated_path_component`` is evaluated before ``joined_inside`` is
        entered, so any real directory serves as the parent here. The ``tmp_path``
        fixture is used rather than a literal path, matching the sibling test
        below, so this file carries no hardcoded temporary-directory string.
        """
        with pytest.raises(ValueError):
            session_directory(tmp_path, "D:x")

    def test_it_returns_the_child_for_an_ordinary_id(self, tmp_path):
        assert session_directory(tmp_path, "session-a") == tmp_path / "session-a"
