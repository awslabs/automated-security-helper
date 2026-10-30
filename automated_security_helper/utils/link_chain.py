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
  component that is not there, or cannot be examined, ends the walk with nothing
  judged: nothing below it is there either, and the gates judge the path as they
  do on every other platform.

Nothing here decides a refusal's wording or its platform gate; the callers do
(``_running_on_windows`` in the sandbox, ``_on_windows`` in the loader).
"""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

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

    A hop's target is examined with ``os.lstat``, which does not follow the
    target itself but DOES follow a link in any of the target's parent
    components; so before that lstat the target's parent components are judged
    by the component walk (:func:`first_unsafe_link`), and a parent that is a
    link to a share, or whose target cannot be read, or that cannot be examined
    at all, is the chain's answer. A
    config file linked as ``.ash/ash.yaml -> ..\\vendor\\cfg.yaml`` with
    ``vendor`` a junction to a share is judged at ``vendor`` and the share is
    never opened.

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


def _chain_names_a_windows_share(text: str, budget: _Hops) -> Optional[bool]:
    current = text
    while budget.take():
        try:
            target = os.readlink(current)
        except (OSError, ValueError):
            # OSError: the entry went away or cannot be opened. ValueError: on
            # Windows CPython raises "not a symbolic link" for a reparse point
            # that names a path but is neither a symbolic link nor a junction
            # (a WSL link), and for one that names no path at all, which
            # ``is_link_stat`` reads as a link.
            return None
        if names_a_windows_share(target):
            return True
        if not os.path.isabs(target):
            target = os.path.join(os.path.dirname(current), target)
        target = os.path.normpath(target)
        parent = os.path.dirname(target)
        if parent and parent != target:
            # The lstat below follows a link in a PARENT component of the
            # target; judge those components first, as the caller's own path
            # was judged, so a junction to a share on the way is found before
            # anything under it is touched.
            unsafe_parent = _first_unsafe_link(parent, budget)
            if unsafe_parent is not None:
                return True if unsafe_parent.reaches_a_share else None
        try:
            is_link = is_link_stat(os.lstat(target))
        except (FileNotFoundError, NotADirectoryError):
            # Not there: a local name that resolving would open nothing for.
            return False
        except OSError:
            # Cannot be examined (a directory the process cannot search): the
            # entry may itself be a link to a share, so the chain is unjudged.
            return None
        if not is_link:
            return False
        current = target
    return None


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
    ``os.lstat``, which does not follow the component it is given; a link in a
    parent is therefore found before anything under it is touched. A local link
    is followed (the components under it are judged through it, as resolving
    would read them). A component that is not there ends the walk with None:
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
    components = components_down_to(os.path.normpath(text))
    for index, component in enumerate(components):
        try:
            is_link = is_link_stat(os.lstat(component))
        except (FileNotFoundError, NotADirectoryError):
            # Not there: nothing below it is there either, so resolving opens
            # nothing; the caller's gates judge the path.
            return None
        except (OSError, ValueError):
            # Cannot be examined: an entry the process may not read, or a
            # spelling the filesystem refuses (an embedded NUL). It may be a
            # link that resolving would follow, so the doubt is the answer and
            # the caller refuses it, as it refuses a chain it cannot read.
            return UnsafeLink(
                component=component,
                is_last=index == len(components) - 1,
                reaches_a_share=None,
                unexaminable=True,
            )
        if not is_link:
            continue
        reaches_a_share = _chain_names_a_windows_share(component, budget)
        if reaches_a_share is False:
            continue
        return UnsafeLink(
            component=component,
            is_last=index == len(components) - 1,
            reaches_a_share=reaches_a_share,
        )
    return None
