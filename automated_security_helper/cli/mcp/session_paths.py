#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Turning a caller-supplied id into one path component, in one place.

Several MCP surfaces take an id from the client -- a session id from a header, an
upload id from a tool argument -- and use it to build a path the server then
creates, writes into, or removes. Each of those sites had its own inline check, or
none, and the checks had drifted: four of them denied ``/``, ``\\``, ``.`` and
``..``; two of them checked nothing at all.

Why an allowlist rather than a longer denylist
----------------------------------------------
A denylist has to enumerate every spelling that means something to a path parser,
and the set is larger than it looks and differs per platform. The values being
validated are machine-generated -- server-assigned session ids and upload ids are
UUID-shaped -- so ``[A-Za-z0-9._-]+`` costs nothing in practice and settles the
question by construction instead of one character at a time.

``.`` and ``..`` are rejected explicitly. Both satisfy the character class, so the
allowlist alone admits them, and both mean something to a path parser.

Two layers, and why the second one earns its place
--------------------------------------------------
:func:`validated_path_component` is the real barrier. :func:`joined_inside` is a
containment assertion applied after the join, and with the allowlist in front of
it no caller-supplied value can reach it and fail. It is here for the caller that
a later change adds without the allowlist, or that loosens the character class --
the failure mode where a path-building site is introduced beside the validated
ones and nobody notices it skipped the check, which is exactly how this module's
predecessors came to disagree.

Keeping it useful means keeping it reachable, so it is a separate public function
rather than an inline assertion: a test can hand it a value the allowlist would
have refused and watch it fire. A guard that cannot be made to fire on its own is
decoration, and this one is tested on its own for that reason.

Known limitation
----------------
The containment comparison is ``is_relative_to`` over resolved paths, and that is
not a universal path-equivalence test -- it compares parsed components, so two
spellings of one location do not always compare equal. The allowlist is what keeps
alternative spellings from arriving here at all; do not read the containment layer
as a general normalizer.
"""

from __future__ import annotations

import re
from pathlib import Path

#: A validated id may hold ASCII letters, digits, dot, underscore and hyphen, and
#: nothing else. Anchored with ``fullmatch`` at the call site rather than with
#: ``^``/``$`` here, so the pattern cannot be reused unanchored by accident.
_ALLOWED_COMPONENT = re.compile(r"[A-Za-z0-9._-]+")

#: Rejected although the character class admits them: both name a directory
#: relative to another one rather than a directory of their own.
_RELATIVE_COMPONENTS = (".", "..")


def validated_path_component(value: str, what: str = "session_id") -> str:
    """Return ``value`` if it is usable as a single path component, else raise.

    Args:
        value: The caller-supplied id.
        what: Name of the field, used in the error message so a refusal says
            which input was wrong.

    Returns:
        ``value`` unchanged.

    Raises:
        ValueError: if ``value`` is empty, holds a character outside the
            allowlist, or is ``.`` or ``..``.

    Refused rather than sanitized. Sanitizing maps two distinct ids onto one
    component, which silently merges two callers' directories -- a quieter and
    worse outcome than rejecting the second caller's id.
    """

    if not value:
        raise ValueError(f"{what} must be a non-empty string")
    if value in _RELATIVE_COMPONENTS:
        raise ValueError(f"{what} must not be a relative-path component: {value!r}")
    if not _ALLOWED_COMPONENT.fullmatch(value):
        raise ValueError(
            f"{what} may contain only letters, digits, '.', '_' and '-': {value!r}"
        )
    return value


def joined_inside(parent: Path, component: str, what: str = "session_id") -> Path:
    """Join ``component`` onto ``parent`` and confirm the result stays inside it.

    Args:
        parent: Directory the result must fall within.
        component: Single path component to append. Not re-validated here; see
            the module docstring on why this is the second layer and not the
            first.
        what: Name of the field, for the error message.

    Returns:
        ``parent / component``, unresolved, so a caller that compares the return
        value against its own unresolved spelling still matches.

    Raises:
        ValueError: if the join does not land strictly inside ``parent``.

    The comparison is made on resolved paths because ``parent`` may itself be
    reached through a symlink, in which case the two sides have to be resolved to
    agree. The value returned is the unresolved join, because resolving it would
    change what existing callers get back.

    Equality with ``parent`` is a failure, not a pass: a component that lands on
    the parent itself has not named a directory of its own, and every caller here
    goes on to create or remove what it is handed.
    """

    joined = parent / component
    resolved_parent = parent.resolve()
    resolved_joined = joined.resolve()
    if resolved_joined == resolved_parent or not resolved_joined.is_relative_to(
        resolved_parent
    ):
        raise ValueError(
            f"{what} does not resolve to a directory inside {parent}: {component!r}"
        )
    return joined


def session_directory(parent: Path, session_id: str, what: str = "session_id") -> Path:
    """Return ``parent``'s subdirectory for ``session_id``, both layers applied.

    The form every caller that needs a per-session directory should use, so that
    the validation and the containment check cannot be applied at one site and
    forgotten at the next.
    """

    return joined_inside(parent, validated_path_component(session_id, what), what)


__all__ = [
    "joined_inside",
    "session_directory",
    "validated_path_component",
]
