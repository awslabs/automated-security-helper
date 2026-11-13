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
allowlist alone admits them, and both mean something to a path parser. The same
holds for two Windows forms, refused for the same reason: a name ending in ``.``
(Windows drops the period, so ``abc.`` opens the directory of ``abc``) and the
reserved device names ``CON``, ``PRN``, ``AUX``, ``NUL``, ``COM1``-``COM9`` and
``LPT1``-``LPT9``, with or without an extension (``NUL.txt`` is ``NUL``). No id a
client is issued takes either shape, so refusing them costs nothing.

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

import contextlib
import errno
import os
import re
import stat
import uuid
from pathlib import Path
from typing import List, Set

#: The characters a validated id may hold: ASCII letters, digits, and
#: ``. _ ~ + = -``. Anchored with ``fullmatch`` at the call site rather than with
#: ``^``/``$`` here, so the pattern cannot be reused unanchored by accident.
#:
#: This is the ONE rule for every caller-supplied id that becomes a path
#: component: the ``Mcp-Session-Id`` header (``session_identity``), the
#: ``sessions`` registry, and ``source_delivery``'s session and upload ids. Two
#: rules used to exist and disagreed; this is the wider character set of the two
#: (URL-unreserved plus ``+`` and ``=``: the alphabet of UUIDs, hex tokens,
#: JWTs and padded or unpadded base64url) with the 128-character cap of the
#: other. The alphabet and the cap are separate rules: a UUID or a hex token is
#: well inside the cap, while a JWT, whose three base64url parts carry claims,
#: is usually longer than 128 characters and is refused by the cap, not by the
#: character class. The cap is the filename budget below, not a judgment about
#: token formats.
#:
#: KNOWN RISK, ACCEPTED BY THE OPERATOR, UNTESTED: two ids this rule admits as
#: distinct can name one directory on a volume that folds names. A
#: case-insensitive volume (the macOS and Windows defaults) folds letter case,
#: so ``Abc`` and ``abc`` open one directory; and with ``~`` allowed, an id
#: shaped like a Windows 8.3 short name (``SESSIO~1``) might alias a sibling
#: session's directory on a volume where 8.3 name generation is enabled. The
#: registry (``sessions``) keys on the id as given, so two such ids are two
#: sessions with two locks over one directory. Neither fold is guarded here, on
#: purpose: refusing upper-case letters or ``~`` would refuse the UUID, JWT and
#: base64url ids the rule exists to admit, and folding case before the lookup
#: would be the sanitizing :func:`validated_path_component` refuses (two ids that
#: ARE distinct on a case-sensitive volume would be merged into one session).
#: What is defended is the one directory whose aliasing matters whatever the
#: caller: the reserved names are compared casefolded and without trailing
#: periods (``session_identity.is_reserved_session_id``), and a new session
#: directory is checked against the default session's by ``os.path.samefile``
#: (``source_delivery._created_session_dir``). Isolation between two sessions
#: that an upstream platform issued is the platform's (``session_identity``, the
#: ``--trust-upstream-session-id`` paragraph). Do not add a partial guard for
#: either fold here without revisiting that decision. The two Windows forms
#: refused below (a trailing period, a device name) are not that: no id format
#: uses them, so refusing them loses no caller.
_ALLOWED_COMPONENT = re.compile(r"[A-Za-z0-9._~+=-]+")

#: Individual filenames cap at 255 bytes on ext4/APFS/NTFS; 128 leaves room for
#: the ``.zip.part`` suffixes ``source_delivery`` appends to an upload id.
MAX_COMPONENT_LEN = 128

#: Rejected although the character class admits them: both name a directory
#: relative to another one rather than a directory of their own.
_RELATIVE_COMPONENTS = (".", "..")

#: Rejected although the character class admits them: on Windows these name a
#: device in every directory, whatever follows the first period (``NUL.txt`` is
#: ``NUL``), so a directory cannot be made under them. The list is the one in
#: Microsoft's "Naming Files, Paths, and Namespaces"; the ``COM`` and ``LPT``
#: forms with a superscript digit it also names are outside the character class.
#: Refused on every platform: an id a client is issued never takes this shape,
#: and a workspace root shared between hosts (a network filesystem) must mean
#: one thing on each.
_WINDOWS_DEVICE_NAMES = frozenset(
    {"CON", "PRN", "AUX", "NUL"}
    | {f"COM{digit}" for digit in range(1, 10)}
    | {f"LPT{digit}" for digit in range(1, 10)}
)


def _is_a_windows_device_name(value: str) -> bool:
    """True if Windows would open ``value`` as a device rather than a file.

    The base name, before the first period, is compared case-insensitively. The
    value has already passed the character class, so it holds no space to strip.
    """

    return value.partition(".")[0].upper() in _WINDOWS_DEVICE_NAMES


def validated_path_component(value: str, what: str = "session_id") -> str:
    """Return ``value`` if it is usable as a single path component, else raise.

    Args:
        value: The caller-supplied id.
        what: Name of the field, used in the error message so a refusal says
            which input was wrong.

    Returns:
        ``value`` unchanged.

    Raises:
        ValueError: if ``value`` is empty, longer than ``MAX_COMPONENT_LEN``,
            holds a character outside the allowlist, is ``.`` or ``..``, ends in
            a period or names a Windows device (``_WINDOWS_DEVICE_NAMES``, with
            or without an extension), or has exactly the shape of a hidden delete
            name (``.<name>.deleting-<uuid4>``, :func:`hidden_deleting_name`).

    Refused rather than sanitized. Sanitizing maps two distinct ids onto one
    component, which silently merges two callers' directories -- a quieter and
    worse outcome than rejecting the second caller's id. The same reasoning
    keeps a trailing period a refusal rather than a strip: Windows drops it when
    it opens the name, so ``abc.`` and ``abc`` would be two registry entries over
    one directory.
    """

    # The specific rules run before the character class so the common mistakes
    # keep their own messages; the class is the closing net.
    if not value:
        raise ValueError(f"{what} must be a non-empty string")
    if len(value) > MAX_COMPONENT_LEN:
        raise ValueError(
            f"{what} is {len(value)} characters; the maximum is {MAX_COMPONENT_LEN}"
        )
    if "/" in value or "\\" in value:
        raise ValueError(f"{what} must not contain path separators: {value!r}")
    if value in _RELATIVE_COMPONENTS:
        raise ValueError(f"{what} must not be a relative-path component: {value!r}")
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in value):
        raise ValueError(f"{what} must not contain control characters: {value!r}")
    if not _ALLOWED_COMPONENT.fullmatch(value):
        raise ValueError(
            f"{what} may contain only letters, digits and the characters "
            f"'.', '_', '-', '~', '+', '=': {value!r}"
        )
    # Two names Windows reads otherwise than written, both inside the character
    # class. A space is the third such ending Windows drops, and it is already
    # outside the class.
    if value.endswith("."):
        raise ValueError(
            f"{what} must not end with '.': Windows drops a trailing period, so "
            f"{value!r} would name the directory of {value.rstrip('.')!r}"
        )
    if _is_a_windows_device_name(value):
        raise ValueError(
            f"{what} must not be a Windows device name (CON, PRN, AUX, NUL, "
            f"COM1-COM9, LPT1-LPT9, with or without an extension): {value!r}"
        )
    if is_a_deleting_name(value):
        # The name a workspace is renamed to for its delete. The TTL sweep clears
        # such a directory as the leftover of an ended session, so an id of this
        # shape would name a live tree the sweep takes for one.
        raise ValueError(
            f"{what} must not have the shape of a hidden delete name "
            f"('.<name>{DELETING_INFIX}<uuid>'): {value!r}"
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


#: File ASH writes into every session workspace it creates. The TTL sweep removes
#: only directories that carry it, so anything else under the workspace root is
#: never touched.
SESSION_MARKER = ".ash-mcp-session"


#: Existing directories already warned about as listable by other accounts, so
#: an operator reads one line per directory, not one per session created in it.
_listable_parents_warned: Set[Path] = set()


def make_private_dir(directory: Path) -> List[Path]:
    """Create ``directory`` and its missing ancestors, each private from the start.

    Every level is made with ``os.mkdir(path, 0o700)``: the mode is the creating
    call's own, so there is no moment between a ``mkdir`` and a later ``chmod``
    in which another account can open the new directory and keep a handle whose
    listing outlives the ``chmod``. A umask that drops owner bits leaves a
    directory tighter than ``0o700``, which is then set once. A directory that
    already exists keeps the mode it has, and the one a new directory is made
    under is warned about, once per path, when other accounts can list it
    (POSIX only): under the workspace root that listing is the live session
    ids. Returns the directories made, deepest last.

    Raises:
        FileExistsError: ``errno.EEXIST`` naming the level at which something
            that is not a directory sits where ``directory`` or an ancestor
            goes, as ``Path.mkdir(parents=True, exist_ok=True)`` raises for it.
            Without this the file was taken for an existing level, and the
            caller's next open under it failed as ``ENOTDIR`` on its own path,
            naming the file it tried to open rather than the directory that
            could not be made.
    """
    missing: List[Path] = []
    for ancestor in (directory, *directory.parents):
        if ancestor.exists():
            if not ancestor.is_dir():
                raise FileExistsError(
                    errno.EEXIST, os.strerror(errno.EEXIST), str(ancestor)
                )
            break
        missing.append(ancestor)
    if missing:
        _warn_once_about_a_listable_parent(missing[-1].parent)
    made: List[Path] = []
    for path in reversed(missing):
        try:
            os.mkdir(path, 0o700)
        except FileExistsError:
            # Made meanwhile by another server sharing the root; its mode is its
            # maker's, as an existing directory's is.
            continue
        if stat.S_IMODE(os.stat(path).st_mode) != 0o700:
            with contextlib.suppress(OSError):
                os.chmod(path, 0o700)
        made.append(path)
    return made


def _warn_once_about_a_listable_parent(parent: Path) -> None:
    if os.name != "posix":
        return
    try:
        mode = stat.S_IMODE(os.stat(parent).st_mode)
    except OSError:
        return
    if not mode & 0o077 or parent in _listable_parents_warned:
        return
    _listable_parents_warned.add(parent)
    from automated_security_helper.utils.log import ASH_LOGGER

    ASH_LOGGER.warning(
        "Other accounts on this host can list %s (mode %s): under the MCP "
        "workspace root that listing is the live session ids. Only directories "
        "ASH creates are made private; set this one to 0700 if other accounts "
        "should not read it.",
        parent,
        oct(mode),
    )


def mark_session_workspace(directory: Path) -> Path:
    """Create ``directory`` as a session workspace, with its marker, and return it.

    The directory, and every ancestor this call creates (the workspace root among
    them), is readable and searchable by its owner alone (``0o700``) from the
    moment it exists, whatever the process umask (:func:`make_private_dir`): a
    session's directory holds a client's delivered source, and the root's
    listing is the set of live session ids. A directory that already exists
    keeps the mode it has, with one warning when other accounts can list it.
    """

    make_private_dir(directory)
    (directory / SESSION_MARKER).touch(exist_ok=True)
    return directory


#: Where the uuid of a hidden delete name starts: ``.<session id>.deleting-<uuid4>``.
DELETING_INFIX = ".deleting-"

_UUID4_TEXT = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
_DELETING_NAME = re.compile(
    r"\.[A-Za-z0-9._~+=-]+" + re.escape(DELETING_INFIX) + _UUID4_TEXT
)


def hidden_deleting_name(session_id: str) -> str:
    """The name a session workspace is renamed to before it is deleted.

    A hidden sibling of the workspace, ``.<session id>.deleting-<uuid4>``: the
    rename is instant, so the session's own path is free for the whole delete,
    and a second end of the same session gets a name of its own.
    """

    return f".{session_id}{DELETING_INFIX}{uuid.uuid4()}"


def is_a_deleting_name(name: str) -> bool:
    """True if ``name`` has the shape :func:`hidden_deleting_name` gives."""

    return _DELETING_NAME.fullmatch(name) is not None


def session_directory(parent: Path, session_id: str, what: str = "session_id") -> Path:
    """Return ``parent``'s subdirectory for ``session_id``, both layers applied.

    The form every caller that needs a per-session directory should use, so that
    the validation and the containment check cannot be applied at one site and
    forgotten at the next.
    """

    return joined_inside(parent, validated_path_component(session_id, what), what)


__all__ = [
    "DELETING_INFIX",
    "MAX_COMPONENT_LEN",
    "SESSION_MARKER",
    "hidden_deleting_name",
    "is_a_deleting_name",
    "mark_session_workspace",
    "joined_inside",
    "session_directory",
    "validated_path_component",
]
