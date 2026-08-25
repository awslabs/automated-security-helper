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

Every rejection here is exit code 2
-----------------------------------
The file is either usable or it is not; there is nothing to partially accept, so
every problem below raises ``WorkspaceDefinitionError`` and nothing is scanned:
the file is absent, is a directory, is unreadable, is not valid JSON, is not a
JSON object, has no ``folders`` key, has a ``folders`` value that is not a list,
has an empty ``folders`` list, or has an entry that is not an object with a
non-blank string ``path``.

An empty ``folders`` list is a refusal rather than a no-op scan for the reason
that runs through all of workspace mode: a scan of zero projects exits 0, which
in CI is indistinguishable from a scan that found nothing wrong.

Failure modes and known limitations
-----------------------------------
* JSON only, not JSONC. VS Code tolerates ``//`` comments and trailing commas in
  ``.code-workspace`` files; :mod:`json` does not, so a commented file is
  rejected. The error message says so explicitly, because "Expecting value:
  line 2 column 3" sends the reader looking for the wrong problem. Stripping
  comments was considered and rejected: doing it correctly requires a real
  tokeniser, since ``//`` inside a string literal is data, and a naive stripper
  silently corrupts paths like ``https://...``. Rejecting with an actionable
  message is the honest failure.
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
from dataclasses import dataclass
from pathlib import Path
from typing import Any, List, Tuple, Union

from automated_security_helper.core.exceptions import WorkspaceDefinitionError

PathLike = Union[str, Path]

#: The suffix that identifies a workspace definition, as VS Code writes it.
WORKSPACE_FILE_SUFFIX = ".code-workspace"

#: The value of ``--workspace`` that means "find the definition yourself".
WORKSPACE_AUTO = "auto"

_FOLDERS_KEY = "folders"
_PATH_KEY = "path"

# Substrings that mean "this is probably JSONC, not JSON". Used only to improve
# the error message after json has already refused the content, never to decide
# whether the content is valid.
_COMMENT_MARKERS = ("//", "/*")


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
        path: Canonical absolute path of the ``.code-workspace`` file.
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
    try:
        raw = workspace_file.read_text(encoding="utf-8")
    except OSError as exc:
        raise _reject(
            f"workspace file '{workspace_file.as_posix()}' could not be read: {exc}"
        ) from exc
    except UnicodeDecodeError as exc:
        raise _reject(
            f"workspace file '{workspace_file.as_posix()}' is not valid UTF-8: {exc}"
        ) from exc

    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        hint = ""
        if any(marker in raw for marker in _COMMENT_MARKERS):
            hint = (
                " It appears to contain comments; ASH reads strict JSON, so "
                "remove any '//' or '/* */' comments and trailing commas."
            )
        raise _reject(
            f"workspace file '{workspace_file.as_posix()}' is not valid JSON: "
            f"{exc}.{hint}"
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
        folders.append(WorkspaceFolder(path=value))

    if problems:
        # Report every bad entry: an operator with three malformed entries
        # should not have to run ASH three times to find them.
        joined = "\n  - ".join(problems)
        raise _reject(
            f"workspace file '{location}' has unusable folder entries:\n  - {joined}"
        )

    return tuple(folders)


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
            here is exit code 2" in the module docstring for the full list.
    """
    candidate = Path(workspace_file)

    if not candidate.exists():
        raise _reject(f"workspace file '{candidate.as_posix()}' does not exist")
    if not candidate.is_file():
        raise _reject(f"workspace file '{candidate.as_posix()}' is not a file")

    resolved = candidate.resolve()
    document = _read_json(resolved)
    folders = _parse_folders(document, resolved)

    return WorkspaceDefinition(
        path=resolved,
        root=resolved.parent,
        folders=folders,
    )


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
        WorkspaceDefinitionError: When there is no candidate, or more than one.
            Ambiguity is refused rather than resolved by sort order or mtime,
            both of which would silently pick a different file as the directory
            changes. The message lists every candidate so the operator can name
            one explicitly.
    """
    directory = Path(search_dir)
    candidates = sorted(
        entry
        for entry in directory.glob(f"*{WORKSPACE_FILE_SUFFIX}")
        # A directory can carry the suffix; it is not a definition.
        if entry.is_file()
    )

    if not candidates:
        raise _reject(
            f"No '*{WORKSPACE_FILE_SUFFIX}' file found in "
            f"'{directory.as_posix()}'. Pass '--workspace <file>' to name one "
            f"explicitly, or drop '--workspace' to scan a single directory."
        )

    if len(candidates) > 1:
        listed = "\n  - ".join(candidate.as_posix() for candidate in candidates)
        raise _reject(
            f"Found {len(candidates)} '*{WORKSPACE_FILE_SUFFIX}' files in "
            f"'{directory.as_posix()}'; '--workspace auto' needs exactly one. "
            f"Pass '--workspace <file>' to choose:\n  - {listed}"
        )

    return candidates[0].resolve()
