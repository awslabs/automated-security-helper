# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Parse and discover a VS Code ``.code-workspace`` definition.

Why this module exists
----------------------
Workspace mode takes its project list from the file editors already keep for
exactly that purpose, so an operator does not maintain a second list that can
drift from the first. That file belongs to another tool, though, which makes the
boundary worth stating precisely and in one place: this module reads the
``folders`` array and nothing else, and hands back the raw text of each entry
for the resolver to validate. It performs no filesystem checks on the entries
themselves -- see :mod:`automated_security_helper.utils.path_containment` for
those.

The shape read
--------------
::

    { "folders": [ { "path": "kiro-bootstrap" }, { "path": "shared-infra" } ],
      "settings": {} }

Folder paths are interpreted relative to the directory holding the workspace
file, which is the workspace root. Absolute paths are accepted here and passed
through; whether they are permissible is a containment question the resolver
answers.

What this module deliberately ignores, and why
----------------------------------------------
* ``settings`` -- entirely. It is tempting to let a workspace set an ASH
  severity threshold or suppression list there, and it would work. It would also
  put ASH policy in a file owned by another tool, whose schema ASH does not
  control and whose keys VS Code may repurpose. ASH policy lives in ASH's own
  config file, where ``ash config lint`` can see it.
* A folder entry's ``name`` -- also entirely. VS Code uses it as a display name
  in the sidebar, and reading it would make ASH's per-project attribution label
  depend on an editor preference. The resolver derives labels from
  ``AshConfig.project_name`` or the project key instead, both of which are ASH's
  own.
* Any other top-level key (``extensions``, ``launch``, ``tasks``, ...). Ignored
  rather than rejected, because a real workspace file will carry them and
  rejecting an unknown key would make ASH refuse ordinary files.

Every rejection here is exit code 4
-----------------------------------
The file is either usable or it is not; there is nothing to partially accept, so
every problem below raises ``WorkspaceDefinitionError`` and nothing is scanned:
the file is absent, is a directory, is unreadable, is not valid JSON, is not a
JSON object, has no ``folders`` key, has a ``folders`` value that is not a list,
has an empty ``folders`` list, or has an entry that is not an object with a
non-blank string ``path``. A file whose canonical path, or its directory's, is
not UTF-8 is refused before it is read (``WorkspacePathNotUtf8Error``): the plan
holds both paths, and the plan is UTF-8 only.

An empty ``folders`` list is a refusal rather than a no-op scan for the reason
that runs through all of workspace mode: a scan of zero projects exits 0, which
in CI is indistinguishable from a scan that found nothing wrong.

A null character is judged on the raw text, not by pathlib
----------------------------------------------------------
An entry containing ``\\x00`` is rejected here, by inspecting the string, rather
than being left for the filesystem to refuse. Two reasons, and the second is the
one that matters:

1. ``os.lstat`` raises ``ValueError`` rather than ``OSError`` for a null byte,
   and ``ValueError`` is not part of this package's contract. It escaped
   ``resolve_workspace`` uncaught, so a malformed workspace file produced a
   traceback and exit 1 -- an internal error -- instead of the exit 4 that says
   "your workspace file is wrong".
2. The wording is version-dependent: Python 3.10 says ``embedded null byte``
   and 3.13 says ``lstat: embedded null character in path``. Anything asserting
   on it passes on one supported interpreter and fails on another. This project
   supports 3.10 through 3.14, so no behaviour may rest on pathlib's handling of
   an unusual input; such inputs are decided from the raw string, where the
   answer is the same everywhere.

Failure modes and known limitations
-----------------------------------
* JSON only, not JSONC. VS Code tolerates ``//`` comments and trailing commas in
  ``.code-workspace`` files; :mod:`json` does not, so a commented file is
  rejected. The error message says so on every parse failure, because
  "Expecting value: line 2 column 3" sends the reader looking for the wrong
  problem. It says what VS Code accepts and ASH does not, and claims nothing
  about this file: a trailing comma alone leaves no comment marker to detect,
  and a ``//`` inside a URL string is data, so a hint keyed on the text pointed
  at the wrong problem both ways. Stripping comments was considered and rejected:
  doing it correctly requires a real tokeniser, since ``//`` inside a string
  literal is data, and a naive stripper silently corrupts paths like
  ``https://...``. Rejecting with an actionable message is the honest failure.
* A leading byte order mark is dropped (``utf-8-sig``), as ASH's own JSON config
  reader drops it: Windows PowerShell 5 writes one, and the file was refused as
  invalid JSON for it.
* A parse failure that is not ``JSONDecodeError`` is refused the same way:
  ``RecursionError`` for a document nested past the interpreter's limit, and the
  ``ValueError`` Python 3.11 and later raise for an integer literal past the
  digit limit. Both escaped as tracebacks, exit 1.
* A workspace file that is a symlink is read where the operator named it: the
  workspace root is the directory holding the link, made canonical, and not the
  directory holding the link's target. Folder entries are relative to the file
  the operator opened, as they are in VS Code, and a link into another tree
  would otherwise move every project to that tree.
* Existence is read with ``os.stat`` and the error kept: ``Path.exists()`` and
  ``Path.is_file()`` raised a bare ``PermissionError`` for a file under an
  unsearchable directory on Python 3.10-3.13 (exit 1) and read it as absent on
  3.14, where the module promises exit 4 for every unusable input. Discovery
  lists the directory the same way: an unlistable directory is a refusal, not
  "no workspace file found".
* Duplicate ``folders`` entries are not detected here. Two entries naming the
  same directory -- textually, or via a symlink -- are caught by the resolver's
  overlap detection, which compares canonicalised real paths and therefore
  catches aliases a textual check would miss.
* Parsing is a point-in-time read. The file can change between this call and the
  scan; this module cannot close that window.
* The whole file is read into memory. Workspace definitions are a few hundred
  bytes, so this is not worth streaming.
"""

from __future__ import annotations

import json
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any, List, Tuple, Union

from automated_security_helper.config.config_sources import parse_error_kind
from automated_security_helper.core.exceptions import (
    WorkspaceDefinitionError,
    WorkspacePathNotUtf8Error,
)

PathLike = Union[str, Path]

#: The suffix that identifies a workspace definition, as VS Code writes it.
WORKSPACE_FILE_SUFFIX = ".code-workspace"

#: The value of ``--workspace`` that means "find the definition yourself".
WORKSPACE_AUTO = "auto"

_FOLDERS_KEY = "folders"
_PATH_KEY = "path"

# Rejected from the raw text, before any pathlib call. See the module docstring.
_NULL_CHARACTER = "\x00"

# What every parse refusal adds. It names what VS Code accepts and ASH does not
# and claims nothing about this file: see "JSON only, not JSONC" above.
_STRICT_JSON_HINT = (
    " VS Code accepts comments and trailing commas in this file; ASH reads "
    "strict JSON, so remove any '//' or '/* */' comments and trailing commas."
)


@dataclass(frozen=True)
class WorkspaceFolder:
    """One ``folders`` entry, carrying only what ASH acts on.

    ``path`` is the raw text exactly as written in the file. It is kept
    unnormalised so error messages can echo back what the operator typed, and so
    the resolver -- not this module -- decides what it resolves to.

    There is deliberately no ``name`` field; see the module docstring.
    """

    path: str


@dataclass(frozen=True)
class WorkspaceDefinition:
    """A parsed workspace definition.

    Attributes:
        path: Absolute path of the ``.code-workspace`` file where the operator
            named it, its directory made canonical: for a link, the link's own
            location, not its target's.
        root: Canonical absolute directory holding it. This is the workspace
            root: folder entries resolve against it, containment is judged
            against it, and in container mode it is what gets mounted at
            ``/src``.
        folders: The ``folders`` entries in file order. Order is preserved
            because it is the operator's stated order and shows up in
            ``--dry-run`` output; nothing depends on it semantically.
    """

    path: Path
    root: Path
    folders: Tuple[WorkspaceFolder, ...]


def _reject(message: str) -> WorkspaceDefinitionError:
    return WorkspaceDefinitionError(message)


def _read_json(workspace_file: Path) -> Any:
    """Read and parse the workspace file, or raise with an actionable message."""
    undecoded = ""
    try:
        # utf-8-sig: a leading byte order mark is dropped, as the JSON config
        # reader drops it (config_sources._read_config_file).
        raw = workspace_file.read_text(encoding="utf-8-sig")
    except OSError as exc:
        raise _reject(
            f"workspace file '{workspace_file.as_posix()}' could not be read: {exc}"
        ) from exc
    except UnicodeDecodeError as exc:
        # The decoder's message prints the byte's value; parse_error_kind gives
        # its offset and nothing from the file (as workspace/policy.py).
        undecoded = parse_error_kind(exc)
    if undecoded:
        # Outside the handler, so the decoder's error is not its context.
        raise _reject(
            f"workspace file '{workspace_file.as_posix()}' could not be parsed "
            f"{undecoded}"
        )

    try:
        return json.loads(raw)
    except (ValueError, RecursionError) as exc:
        # json.JSONDecodeError is a ValueError; so is the integer-digit-limit
        # refusal of Python 3.11 and later. RecursionError is a document nested
        # past the interpreter's limit. Every one is "this file is not usable".
        reason = (
            parse_error_kind(exc)
            if isinstance(exc, json.JSONDecodeError)
            else (f"({type(exc).__name__})")
        )
        raise _reject(
            f"workspace file '{workspace_file.as_posix()}' is not valid JSON "
            f"{reason}.{_STRICT_JSON_HINT}"
        ) from exc


def _parse_folders(document: Any, workspace_file: Path) -> Tuple[WorkspaceFolder, ...]:
    """Extract the ``folders`` array, rejecting every unusable shape."""
    location = workspace_file.as_posix()

    if not isinstance(document, dict):
        raise _reject(
            f"workspace file '{location}' must contain a JSON object at the top "
            f"level, found {type(document).__name__}"
        )

    if _FOLDERS_KEY not in document:
        raise _reject(
            f"workspace file '{location}' has no '{_FOLDERS_KEY}' key; a "
            f"workspace must list at least one folder to scan"
        )

    raw_folders = document[_FOLDERS_KEY]
    if not isinstance(raw_folders, list):
        raise _reject(
            f"workspace file '{location}' has a '{_FOLDERS_KEY}' value that is "
            f"not a list, found {type(raw_folders).__name__}"
        )

    if not raw_folders:
        # A zero-project scan would exit 0 having examined nothing, which in CI
        # is indistinguishable from a clean scan.
        raise _reject(
            f"workspace file '{location}' lists no folders; a workspace must "
            f"name at least one folder to scan"
        )

    folders: List[WorkspaceFolder] = []
    problems: List[str] = []
    for index, entry in enumerate(raw_folders):
        if not isinstance(entry, dict):
            problems.append(
                f"entry {index} is not a JSON object, found {type(entry).__name__}"
            )
            continue
        value = entry.get(_PATH_KEY)
        if not isinstance(value, str) or not value.strip():
            problems.append(
                f"entry {index} has no usable '{_PATH_KEY}'; it must be a "
                f"non-empty string, found {value!r}"
            )
            continue
        if _NULL_CHARACTER in value:
            # Decided on the raw text so the verdict cannot depend on the
            # interpreter's pathlib. See the module docstring.
            problems.append(
                f"entry {index} contains a null character in its "
                f"'{_PATH_KEY}'; no filesystem accepts one"
            )
            continue
        folders.append(WorkspaceFolder(path=value))

    if problems:
        # Report every bad entry: an operator with three malformed entries
        # should not have to run ASH three times to find them.
        raise WorkspaceDefinitionError.listing(
            f"workspace file '{location}' has unusable folder entries:", problems
        )

    return tuple(folders)


def is_utf8_path(path: Path) -> bool:
    """Whether *path* is UTF-8: a name that is not arrives as surrogate escapes."""
    try:
        str(path).encode("utf-8")
    except UnicodeEncodeError:
        return False
    return True


#: The end of every refusal of a path that is not UTF-8.
NOT_UTF8_ON_THE_HOST = (
    "Container mode does not get around this: the workspace is planned on the host."
)


def _refuse_a_file_path_that_is_not_utf8(resolved: Path) -> None:
    """Refuse a workspace file whose canonical path is not UTF-8, before reading it.

    The plan and the results file hold the file's path and its root's, and both
    are UTF-8. The root is named first, since renaming it is what clears both.
    The message holds the path as it is, on one line; each sink shows it once
    (see WorkspacePathNotUtf8Error).
    """
    if not is_utf8_path(resolved.parent):
        raise WorkspacePathNotUtf8Error(
            f"The workspace root '{resolved.parent.as_posix()}' has a path that is "
            "not UTF-8. The workspace plan and its results hold the root's path and "
            "every project's, and they are UTF-8 only, so the workspace cannot be "
            "planned. Rename the directory whose name is not UTF-8. "
            f"{NOT_UTF8_ON_THE_HOST}"
        )
    if not is_utf8_path(resolved):
        raise WorkspacePathNotUtf8Error(
            f"The workspace file '{resolved.as_posix()}' has a name that is not "
            "UTF-8. The workspace plan holds its path, and it is UTF-8 only, so the "
            f"workspace cannot be planned. Rename the file. {NOT_UTF8_ON_THE_HOST}"
        )


def load_workspace_file(workspace_file: PathLike) -> WorkspaceDefinition:
    """Parse *workspace_file* into a :class:`WorkspaceDefinition`.

    Args:
        workspace_file: Path to a ``.code-workspace`` file. The suffix is not
            enforced -- an operator who passes ``--workspace ./my.json`` gets
            their file read -- because the content, not the name, decides
            whether it is usable.

    Returns:
        The parsed definition, with the workspace root resolved.

    Raises:
        WorkspaceDefinitionError: For every unusable input. See "Every rejection
            here is exit code 4" in the module docstring for the full list.
    """
    candidate = Path(workspace_file)
    _refuse_unless_a_regular_file(candidate)

    # The file where the operator named it, its directory canonical: a link's
    # own location, so the workspace root is the directory holding the link and
    # folder entries resolve against the tree the operator opened. resolve() of
    # the file itself would move the root to the link target's directory.
    located = _resolved_directory(candidate.parent) / candidate.name
    _refuse_a_file_path_that_is_not_utf8(located)
    document = _read_json(located)
    folders = _parse_folders(document, located)

    return WorkspaceDefinition(
        path=located,
        root=located.parent,
        folders=folders,
    )


def _refuse_unless_a_regular_file(candidate: Path) -> None:
    """Refuse *candidate* unless a regular file is at it, with the error kept.

    ``os.stat``, not ``Path.exists()``/``is_file()``: those raised a bare
    ``PermissionError`` for a file under an unsearchable directory on Python
    3.10-3.13 (a traceback, exit 1) and read it as absent on 3.14, where every
    unusable input here is exit 4.
    """
    label = f"workspace file '{candidate.as_posix()}'"
    try:
        mode = os.stat(candidate).st_mode
    except FileNotFoundError as exc:
        raise _reject(f"{label} does not exist") from exc
    except OSError as exc:
        raise _reject(
            f"{label} could not be examined ({exc.strerror or type(exc).__name__})"
        ) from exc
    if not stat.S_ISREG(mode):
        raise _reject(f"{label} is not a file")


def _resolved_directory(directory: Path) -> Path:
    """*directory* made canonical, or the refusal for one that cannot be.

    ``Path.resolve`` raises ``RuntimeError`` for a symlink loop on CPython 3.10
    to 3.12 and ``OSError`` for a few unreadable shapes.
    """
    try:
        return directory.resolve()
    except (RuntimeError, OSError) as exc:
        raise _reject(
            f"workspace directory '{directory.as_posix()}' cannot be resolved: a "
            f"component on the way to it is a symlink loop or cannot be read "
            f"({type(exc).__name__})"
        ) from exc


def discover_workspace_file(search_dir: PathLike) -> Path:
    """Find the single ``*.code-workspace`` file in *search_dir*.

    Non-recursive by design. Recursing would let ASH pick up a definition from a
    vendored dependency or a nested checkout, and the operator would have no
    obvious way to tell which file was chosen.

    Args:
        search_dir: The directory to look in -- the process working directory,
            when reached via ``--workspace auto``.

    Returns:
        The canonical absolute path of the one candidate found.

    Raises:
        WorkspaceDefinitionError: When there is no candidate, or more than one,
            or the directory cannot be listed. Ambiguity is refused rather than
            resolved by sort order or mtime, both of which would silently pick a
            different file as the directory changes. The message lists every
            candidate so the operator can name one explicitly.
    """
    directory = Path(search_dir)
    # os.listdir with its error kept, not Path.glob, which swallows a
    # PermissionError and reads an unlistable directory as holding nothing.
    try:
        names = os.listdir(directory)
    except OSError as exc:
        raise _reject(
            f"'{directory.as_posix()}' could not be listed for a "
            f"'*{WORKSPACE_FILE_SUFFIX}' file ({exc.strerror or type(exc).__name__})"
        ) from exc
    candidates = sorted(
        directory / name
        for name in names
        # A directory can carry the suffix; it is not a definition.
        if name.endswith(WORKSPACE_FILE_SUFFIX) and _is_a_regular_file(directory / name)
    )

    if not candidates:
        raise _reject(
            f"No '*{WORKSPACE_FILE_SUFFIX}' file found in "
            f"'{directory.as_posix()}'. Pass '--workspace <file>' to name one "
            f"explicitly, or drop '--workspace' to scan a single directory."
        )

    if len(candidates) > 1:
        raise WorkspaceDefinitionError.listing(
            f"Found {len(candidates)} '*{WORKSPACE_FILE_SUFFIX}' files in "
            f"'{directory.as_posix()}'; '--workspace auto' needs exactly one. "
            f"Pass '--workspace <file>' to choose:",
            [candidate.as_posix() for candidate in candidates],
        )

    # The directory canonical, the file as named: a linked definition is read
    # where it was found (see load_workspace_file).
    return _resolved_directory(directory) / candidates[0].name


def _is_a_regular_file(path: Path) -> bool:
    """Whether a regular file is at *path*; one that cannot be examined is not.

    For discovery's candidate filter, where a candidate that cannot be examined
    is not a definition to pick. ``Path.is_file()`` raised instead on 3.10-3.13.
    """
    try:
        return stat.S_ISREG(os.stat(path).st_mode)
    except OSError:
        return False
