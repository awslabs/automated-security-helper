# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""One reading of a Windows path's links before anything resolves it.

Resolving a path on Windows opens what it names: a UNC spelling, or a link whose
target is one, makes the OS connect to the host the path names before any gate
has judged it. Two callers refused such paths unresolved and each carried its own
copy of the reading: the MCP sandbox gates (``cli/mcp/sandbox.py``, every
client-named scan target and config input) and the config loader
(``config/config_sources.py``, a config source or ``.ash`` directory under an
operator grant). The copies drifted in two ways: one read only the last component
of the path, so a link in a PARENT component was followed by ``os.lstat`` on the
whole path and opened the share at the very check meant to prevent it; and their
link tests differed, one counting every reparse point and the other only those
that name another path. This module is the one reading both callers use.

What it judges, from text and from ``os.lstat`` / ``os.readlink`` alone, which
open a link's own entry and never what it names:

- :func:`names_a_windows_share`: whether a spelling names something other than a
  directory on a local volume (a UNC path; a device-prefixed path whose device is
  not a drive letter; a device-prefixed drive path with a ``..`` step, which Win32
  normalizes before the object manager sees it).
- :func:`is_link_stat`: the link test. The stricter of the two copies: a symbolic
  link, or on Windows ANY reparse point. A reparse point that names no path (a
  deduplicated or cloud-placeholder entry) is then read as a link whose target
  cannot be read, and refused, where the other copy followed it as a plain entry.
- :func:`link_chain_names_a_windows_share`: whether a link, or a link it leads to,
  names a share, one hop at a time, at most :data:`LINK_HOPS` hops.
- :func:`first_unsafe_link`: the walk. Every component of the path from its anchor
  down, on the lexically collapsed spelling (``os.path.normpath``), since Win32
  collapses ``..`` before any file access: a component that is stepped back over
  is never examined, as the OS never examines it, and a link under the step is
  found. The first link met is judged by the chain reading; a local link is
  followed, since what it names is local and resolving reads through it; a link
  that leads to a share, or whose target cannot be read, is the answer. A
  component that is not there ends the walk with nothing judged: nothing below it
  is there either, and the gates judge the path as they do on every other
  platform. A component that IS there but cannot be examined (``os.lstat``
  refuses it, or its spelling cannot be given to the filesystem) is the answer
  too, marked unexaminable: it may be a link resolving would follow, and the
  doubt is refused, never passed on as a local name.

Both readings walk a path the way resolving does, so that ``os.lstat`` is only ever
asked about an entry whose parent directories have all been examined and hold no
link. The walk keeps a prefix it has reached, which holds no link, and looks one
name up under it. A link met on the way is read with ``os.readlink`` and its
target's names are walked next: from the directory the link is in, which is the
one reached (``a\\l3`` with ``a`` a link to ``b\\c`` has ``l3`` in ``b\\c``, and a
target ``..\\x`` of ``l3`` is ``b\\x``, not ``x`` beside ``a``), or from the
target's own anchor when it has one. A link in a parent of a hop's target is
therefore examined before anything under it is, and a relative target is taken
from where the link is, not from where the caller spelled it.

A target is collapsed by text before its names are walked, as the caller's own
spelling is: a ``..`` steps back over the name in front of it and never opens
it, so ``sub\\lnk\\..\\z`` names ``sub\\z`` and ``lnk`` is not examined, which is
how Win32 reads such a spelling. Only a ``..`` left at the front of a relative
target goes up from the directory the link is in, and that directory holds no
link, so the step there is the same by text and on disk.

Nothing here decides a refusal's wording or its platform gate; the callers do
(``_running_on_windows`` in the sandbox, ``_on_windows`` in the loader).
"""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Tuple

#: Links followed before a chain is given up on as unjudgeable: the bound
#: ``os.path.realpath`` applies to a chain of links before it stops following.
LINK_HOPS = 40

_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)


def is_link_stat(info: os.stat_result) -> bool:
    """A symbolic link, or on Windows any reparse point.

    Every reparse point counts, not only one that names another path (a symbolic
    link, a junction, a mount point): a reparse point of another kind has no
    target ``os.readlink`` can return, so the chain reading answers None for it
    and the caller refuses it as a link whose target cannot be read. That is the
    stricter of the two readings the callers used to carry, and the one both
    carry now.
    """
    if stat.S_ISLNK(info.st_mode):
        return True
    return bool(getattr(info, "st_file_attributes", 0) & _REPARSE_POINT)


def names_a_windows_share(path: object) -> bool:
    """Whether the text of ``path`` names something other than a local volume path.

    True for a UNC path, ``\\\\server\\share`` or ``//server/share``, and for any
    path in the extended form, ``\\\\?\\...``, ``\\\\.\\...`` or the native ``\\??\\...``,
    whose device is not a drive letter: ``\\\\?\\UNC\\server\\share`` (a share),
    ``\\\\?\\GLOBALROOT\\...`` (the object namespace, through which a redirector or a
    mounted share is reached by another name) and ``\\\\.\\pipe\\...`` (a device, not
    a directory) are all refused by the callers, which open only directories on a
    local volume. Only ``\\\\?\\C:\\repo`` and ``\\\\.\\C:\\repo``, a drive letter and a
    separator after the prefix, are local; a drive-relative ``\\\\?\\C:repo`` is not,
    and neither is ``\\\\.\\C:`` with nothing after the colon, which names the
    volume's device rather than a directory. Forward slashes are read as
    separators first, so a mixed spelling is judged by what it names.
    ``os.readlink`` returns a junction's target in the extended form (its
    substitute name, since Python 3.8), so the form is read here rather than taken
    for a share by its two leading separators, and a junction to a local volume
    stays local.

    Behind a device prefix a ``..`` component is not a step up a local tree: Win32
    normalizes a ``\\\\.\\`` path before the object manager sees it, so
    ``\\\\.\\C:\\..\\UNC\\server\\share`` is the share and ``\\\\.\\C:\\..\\pipe\\x`` the
    pipe, each spelled with a drive letter in front. Such a spelling is judged by
    what it reaches, whatever it reaches: a caller that means a local directory
    names it without the step.
    """
    text = os.fspath(path) if isinstance(path, (str, os.PathLike)) else str(path)
    text = text.replace("/", "\\")
    if text.startswith(("\\\\?\\", "\\\\.\\", "\\??\\")):
        rest = text[4:]
        if not is_a_drive_spelling(rest):
            return True
        return any(part == ".." for part in rest.split("\\"))
    return text.startswith("\\\\")


def is_a_drive_spelling(text: str) -> bool:
    """Whether ``text`` is a drive letter, a colon and a separator: ``C:\\`` or ``C:\\repo``.

    A directory on a volume always has the separator (the volume's root is
    ``C:\\``), and so does the substitute name ``os.readlink`` gives for a
    junction. ``C:`` alone, behind the prefix, names the volume's device object
    (``\\\\.\\C:`` is how a raw volume is opened), not a directory on it, and the
    drive-relative ``C:repo`` names nothing the extended form resolves against a
    current directory; neither is a drive spelling here.
    """
    return (
        len(text) >= 3
        and text[0].isascii()
        and text[0].isalpha()
        and text[1] == ":"
        and text[2] == "\\"
    )


class _Hops:
    """The one budget of ``os.readlink`` calls a judgment may spend.

    Shared between the chain reading and the component walk when one calls the
    other (a hop's target has parent components, and a parent component can be
    a link with its own chain), so a crafted tree of links costs at most
    ``LINK_HOPS`` reads in all, never a product of nested bounds.
    """

    def __init__(self, left: int) -> None:
        self.left = left

    def take(self) -> bool:
        if self.left <= 0:
            return False
        self.left -= 1
        return True


def link_chain_names_a_windows_share(
    text: str, *, hops: int = LINK_HOPS
) -> Optional[bool]:
    """Whether the link at ``text``, or a link it leads to, names a network share.

    Read with ``os.readlink`` one hop at a time: reading a reparse point's
    substitute name opens the link's own entry, never what it names, so a chain
    is judged without a connection to anything it leads to. A relative name is
    taken from the link's directory, as resolving would take it. The walk ends
    at the first name that is not a link, or that is not there: a local name is
    then all that resolving would open, and the answer is False.

    A hop's target is walked name by name from the directory the link is in
    (``text`` is that link's own location, so the directory holds no link the
    caller has not judged: the component walk, :func:`first_unsafe_link`, calls
    this with the directory it has reached), so ``os.lstat``, which does not
    follow the entry it is given but DOES follow a link in any of its parents,
    is only asked about an entry under parents already examined. A parent of
    the target that is a link to a share, or whose target cannot be read, or
    that cannot be examined at all, is the chain's answer. A config file linked
    as ``.ash/ash.yaml -> ..\\vendor\\cfg.yaml`` with ``vendor`` a junction to a
    share is judged at ``vendor`` and the share is never opened.

    None when the chain cannot be judged: a reparse point whose name cannot be
    read (one that is no symbolic link or junction), a hop that cannot be
    examined (its directory cannot be searched: it may be a link to a share that
    nobody here can see), or more than ``hops`` reads in all, the parent walks
    included. The caller refuses then, as it refused every link before, since
    what resolving would open cannot be told. Only a hop that is not there (no
    such file, or a path component that is not a directory) ends the walk as a
    local name: nothing is there to follow, so resolving opens nothing.
    """
    return _chain_names_a_windows_share(text, _Hops(hops))


@dataclass(frozen=True)
class _Finding:
    """Why a walk stopped on a link.

    ``reaches_a_share`` is True when the chain names a share or a device, and
    None when it cannot be judged. ``unexaminable`` is True when the entry the
    caller named could not be examined at all (``os.lstat`` refused it), as
    opposed to something its target leads through.
    """

    reaches_a_share: Optional[bool]
    unexaminable: bool = False


def _parent(reached: str) -> str:
    """The directory above ``reached``, which holds no link, so this is its parent."""
    if not reached or os.path.basename(reached) == "..":
        # A relative prefix that has not left its start (or is already above
        # it) goes up by a step that is kept, not collapsed.
        return os.path.join(reached, "..")
    parent = os.path.dirname(reached)
    if not parent and os.path.splitdrive(reached)[0]:
        return reached
    return parent


def _split_target(directory: str, target: str) -> Tuple[str, List[str]]:
    """Where a link's target starts, and the names still to walk under it.

    A relative target starts at ``directory``, the one the link is in. A target
    with an anchor starts there: a drive and a root, a root alone (on the
    volume the link is on, as the OS takes it), or a drive alone.

    The target is collapsed by text first (``os.path.normpath``), so a ``..``
    after a name is a step back over that name, never a step up from wherever
    walking the name would have led. What is left of ``..`` is at the front of a
    relative target, or nowhere.
    """
    parsed = Path(os.path.normpath(target))
    parts = list(parsed.parts)
    if not parsed.anchor:
        return directory, parts
    if parsed.root and not parsed.drive:
        start = os.path.splitdrive(directory)[0] + parsed.root
    else:
        start = parsed.anchor
    return start, (parts[1:] if parts and parts[0] == parsed.anchor else parts)


def _walk_names(
    reached: str, names: List[str], budget: _Hops, *, spliced: bool
) -> Tuple[Optional[str], Optional[_Finding]]:
    """Walk ``names`` down from ``reached``, a directory known to hold no link.

    Each name is looked up with ``os.lstat`` under the prefix reached so far,
    never under a spelling that passes through a link. A name that is a link is
    read, its target is judged by its text, and the target's own names are
    walked next, in place of the link, from the directory the link is in (or
    from the target's anchor): so a relative target is taken from where the
    link is, and a link in a parent of the target is examined before anything
    under it is. A target arrives collapsed by text (:func:`_split_target`), so
    a ``..`` met here is one left at the front of a relative target, and it
    goes up from the prefix reached, which is a real directory.

    Returns the prefix reached when every name was walked and none was unsafe;
    ``(None, None)`` when a name is not there (nothing below it is there
    either, so resolving opens nothing); and ``(None, finding)`` for the first
    link whose chain leads to a share (``True``) or cannot be judged
    (``None``): its target cannot be read, it is past the shared hop budget, or
    an entry on the way cannot be examined. That last case is marked
    ``unexaminable`` only for a name the caller itself gave (``spliced`` False
    until a link has been followed): inside a target it is the chain that
    cannot be told.
    """
    pending = list(reversed(names))
    while pending:
        name = pending.pop()
        if name in ("", "."):
            continue
        if name == "..":
            reached = _parent(reached)
            continue
        candidate = os.path.join(reached, name)
        try:
            info = os.lstat(candidate)
        except (FileNotFoundError, NotADirectoryError):
            # Not there: a local name that resolving would open nothing for.
            return None, None
        except (OSError, ValueError):
            # Cannot be examined (a directory the process cannot search, an
            # entry it may not read, or a spelling the filesystem refuses, such
            # as an embedded NUL that ``os.lstat`` raises ValueError for): the
            # entry may itself be a link to a share, so the doubt is the answer.
            return None, _Finding(None, unexaminable=not spliced)
        if not is_link_stat(info):
            reached = candidate
            continue
        if not budget.take():
            return None, _Finding(None)
        try:
            target = os.readlink(candidate)
        except (OSError, ValueError):
            # OSError: the entry went away or cannot be opened. ValueError: on
            # Windows CPython raises "not a symbolic link" for a reparse point
            # that names a path but is neither a symbolic link nor a junction
            # (a WSL link), and for one that names no path at all, which
            # ``is_link_stat`` reads as a link.
            return None, _Finding(None)
        if names_a_windows_share(target):
            return None, _Finding(True)
        reached, target_names = _split_target(reached, target)
        pending.extend(reversed(target_names))
        spliced = True
    return reached, None


def _chain_names_a_windows_share(text: str, budget: _Hops) -> Optional[bool]:
    if not budget.take():
        return None
    try:
        target = os.readlink(text)
    except (OSError, ValueError):
        # As in _walk_names: the entry went away, or it is a reparse point
        # that is no symbolic link or junction.
        return None
    if names_a_windows_share(target):
        return True
    start, names = _split_target(os.path.dirname(text), target)
    _, finding = _walk_names(start, names, budget, spliced=True)
    if finding is None:
        return False
    return True if finding.reaches_a_share else None


def components_down_to(text: str) -> List[str]:
    """``text``'s ancestors from its anchor down, then ``text`` itself.

    ``C:\\a\\b`` gives ``C:\\a`` and ``C:\\a\\b``; the anchor alone (a drive root
    or a share root) is not a component to judge. A relative path starts at its
    first component. The spelling is kept as given: nothing here resolves, and
    nothing here collapses (:func:`first_unsafe_link` collapses before it asks).
    """
    parsed = Path(text)
    parts = list(parsed.parts)
    if parsed.anchor and parts and parts[0] == parsed.anchor:
        current = parts[0]
        rest = parts[1:]
    else:
        current = ""
        rest = parts
    components: List[str] = []
    for part in rest:
        current = os.path.join(current, part) if current else part
        components.append(current)
    return components or [text]


@dataclass(frozen=True)
class UnsafeLink:
    """The first link on a path that resolving must not follow.

    ``component`` is the collapsed spelling of the component that is the link
    (the path itself when ``is_last``); ``reaches_a_share`` is True when the
    chain from it names a share or a device, and None when its target cannot be
    read, so what resolving would open cannot be told. ``unexaminable`` is True
    when the component could not be read at all (``os.lstat`` refused it), so
    whether it is a link, let alone where it leads, cannot be told; such a
    component is reported with ``reaches_a_share`` None and refused the same way.
    """

    component: str
    is_last: bool
    reaches_a_share: Optional[bool]
    unexaminable: bool = False


def first_unsafe_link(text: str, *, hops: int = LINK_HOPS) -> Optional[UnsafeLink]:
    """The first link on ``text``, from its anchor down, that is not a local link.

    Judges the lexically collapsed spelling, the one Win32 examines: ``..`` is
    collapsed before any file access, so ``C:\\granted\\missing\\..\\lnk`` examines
    ``C:\\granted\\lnk`` and never asks whether ``missing`` is there, and
    ``C:\\granted\\lnk\\..\\other`` never opens ``lnk``. Every component is read with
    ``os.lstat``, which does not follow the component it is given, and under a
    prefix that holds no link, so a link in a parent is found before anything
    under it is touched. A local link is followed: the components under it are
    judged in the directory it leads to, which is where resolving would read
    them, and a relative link met there is taken from that directory, not from
    the spelling the caller gave. A component that is not there ends the walk
    with None:
    nothing below it is there either, and the caller's gates judge the path as
    they do on every other platform. A component that IS there but cannot be
    examined (its entry refuses the read, or the spelling cannot be given to the
    filesystem) is the answer, marked ``unexaminable``: it may be a link that
    resolving would follow, and the doubt is refused, as the chain reading
    refuses a hop it cannot read, never passed on as a local name.

    The caller judges the TEXT of ``text`` with :func:`names_a_windows_share`
    first, with its own wording; this walk assumes a spelling that names a local
    volume. ``hops`` bounds the ``os.readlink`` calls of the whole judgment, the
    chains of every link met and of every parent of a hop's target included.
    """
    return _first_unsafe_link(text, _Hops(hops))


def _first_unsafe_link(text: str, budget: _Hops) -> Optional[UnsafeLink]:
    collapsed = os.path.normpath(text)
    parsed = Path(collapsed)
    parts = list(parsed.parts)
    if parsed.anchor and parts and parts[0] == parsed.anchor:
        reached, names = parts[0], parts[1:]
    else:
        reached, names = "", parts
    # The components are the collapsed spellings the answer names; the walk
    # itself goes by the prefix it has reached, which differs from the spelling
    # once a local link has been followed.
    components = components_down_to(collapsed)
    for index, name in enumerate(names):
        walked, finding = _walk_names(reached, [name], budget, spliced=False)
        if finding is not None:
            return UnsafeLink(
                component=components[index],
                is_last=index == len(names) - 1,
                reaches_a_share=finding.reaches_a_share,
                unexaminable=finding.unexaminable,
            )
        if walked is None:
            # Not there: nothing below it is there either, so resolving opens
            # nothing; the caller's gates judge the path.
            return None
        reached = walked
    return None
