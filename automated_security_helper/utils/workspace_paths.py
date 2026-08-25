# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Move glob patterns between the project path space and the workspace space.

Why this module exists
----------------------
In workspace mode a scan has two coordinate systems. Each project's own config
writes patterns against that project's root (``src/x.py``), while aggregated
output, workspace-level policy and per-project attribution all live in
workspace-relative coordinates (``project-a/src/x.py``). Every place that
crosses between the two has to prefix or unprefix a pattern, and doing it with
string concatenation produces ``project-a//src/x.py`` the first time someone
writes a project-rooted pattern. Both directions live here, both go through
``PurePosixPath``, and neither concatenates.

Patterns are a POSIX-shaped namespace, not filesystem paths
-----------------------------------------------------------
ASH compares patterns against SARIF URIs and suppression paths, which are
always forward-slash separated regardless of host OS. So this module works in
``PurePosixPath`` throughout and normalises backslashes on input. That is what
makes the behaviour identical on Windows: the pattern space does not change
shape underfoot. ``PurePosixPath`` also leaves glob metacharacters alone --
``*``, ``**`` and ``[0-9]`` are ordinary components to it -- so joining cannot
corrupt a pattern.

Up-conversion: project-relative to workspace-relative
-----------------------------------------------------
* relative (``src/x.py``, ``tests/**/*.py``) -- prefixed with the project path.
* project-rooted (``/src/x.py``) -- the leading separator is stripped BEFORE
  the join. This ordering is load-bearing, and not for cosmetic reasons:
  ``PurePosixPath("project-a") / "/src/x.py"`` silently DISCARDS the prefix and
  evaluates to ``/src/x.py``. Getting it wrong does not produce a doubled
  separator, it produces a pattern that has escaped the project entirely.
* ``**``-anchored (``**/test_*.py``) -- prefixed, with ``**`` intact.
* containing ``..`` -- rejected.
* drive- or UNC-anchored (``C:/Windows``, ``//server/share``) -- rejected.

The one case the table above cannot decide
------------------------------------------
``/src/x.py`` (project-rooted, must be prefixed) and ``/etc/passwd``
(a filesystem path, nominally rejected) are textually identical in shape on
POSIX. No pure function can tell them apart, and resolving against the
filesystem is not an option: patterns routinely name files that do not exist,
and a pattern's meaning must not depend on the state of the disk.

So a leading separator is always read as project-rooted. ``/etc/passwd``
up-converts to ``project-a/etc/passwd`` rather than being rejected. The
security property the rejection was protecting -- a project cannot reach
outside itself -- is preserved by a stronger mechanism than rejection: after
prefixing, no up-converted pattern can address anything outside its project, so
escape is structurally impossible rather than merely refused. Drive and UNC
anchors are still rejected, because those are unambiguous and prefixing them
would yield nonsense like ``project-a/C:/Windows``.

One consequence of keeping the UNC rejection is worth knowing before someone
files it as a bug: a DOUBLED leading separator is rejected too.
``PureWindowsPath("//src/x.py").drive`` is ``\\\\src\\x.py``, so the Windows
flavour cannot tell ``//src/x.py`` -- most likely a project-rooted pattern with
a stray extra slash -- from a real ``//server/share``. Rejecting it with an
error the operator can act on beats silently choosing one reading. A single
leading separator is unaffected and is prefixed as described above.

Down-conversion: workspace-relative to project-relative
-------------------------------------------------------
Used to push a workspace-level policy into one project. The contract is
behavioural, not textual -- for every project-relative path ``p``::

    matches(to_project_pattern(P, R), p)  ==  matches(P, R + "/" + p)

A down-converted pattern must reach exactly the files the workspace-level
pattern reached inside that project. ``None`` means the pattern cannot match
anything in the project, so the caller applies nothing.

Getting this wrong is not symmetric, and the asymmetry runs the opposite way to
intuition. These patterns are suppressions. A pattern that matches TOO MUCH
suppresses findings that should have been reported, and a suppressed finding
leaves no trace in the output -- nobody sees what is missing. A pattern that
matches too little, or is dropped entirely, produces extra findings, which are
visible and merely noisy. So the safe failure is to under-suppress: return
``None``, or refuse, rather than widen a pattern.

The code follows that. Nothing is passed through on the hope that it might
apply. Every rewrite below was derived by sweeping candidate rewrites against
ASH's own ``file_path_matches`` and keeping only those satisfying the contract:

* Anchored to this project (``api/src/x.py`` over ``api``) -- strip the prefix.
* Anchored elsewhere (``api/src/x.py`` over ``api-v2``) -- ``None``.
* Naming only the project directory (``api`` over ``api``) -- ``None``.
  ``file_path_matches("api/src/x.py", "api")`` is False, so this pattern covers
  no file in the project. Returning ``**`` here would have suppressed a whole
  project the operator never named.
* Unbounded leading glob (``*/src/x.py``, ``project-*/src/x.py``) -- becomes
  ``**/src/x.py``. ``*`` crosses ``/`` in this matcher, so it absorbed the
  prefix and can absorb further directories; ``**`` is what that means
  project-side. Returning the pattern unchanged retargeted it: ``*/src/x.py``
  over project ``api`` stopped matching ``src/x.py``, the file the operator
  named, while still matching ``sub/src/x.py``.
* Bounded leading glob (``?roject-a/src/x.py``, ``[pq]roject-a/src/x.py``) --
  becomes ``src/x.py``, NOT ``**/src/x.py``. ``?`` and ``[...]`` match a fixed
  number of characters, so the component consumed exactly the prefix and no
  extra directories. ``**`` would over-suppress ``sub/src/x.py``.
* Leading glob that cannot absorb the prefix (``api*/src/x.py`` over
  ``services/api``) -- ``None``.
* Trailing ``**`` inside the prefix span (``api/**`` over ``api/sub``) -- ``**``.

Fail-closed classes
-------------------
Three shapes have no correct single-pattern rewrite, and are rejected with an
error naming the pattern and the remedy rather than guessed at:

1. A literal component after the leading wildcard that also matches part of the
   project path (``*/api/src/x.py`` over ``services/api``). The workspace-level
   match can begin INSIDE the prefix -- ``*`` absorbs ``services`` and ``api``
   aligns with the prefix's own second component -- which no project-relative
   pattern expresses.
2. A wildcard falling inside the project path itself (``api/*/x.py`` over
   ``api/sub``), where how much of the path it consumes is ambiguous.
3. A lone fixed-length wildcard (``?????????``). It matches ``api/x.txt`` --
   nine characters -- while matching neither ``api`` nor ``x.txt``, so the
   constraint lives in the length of the joined path and cannot survive
   stripping the prefix.

Failure modes and known limitations
-----------------------------------
* The fail-closed test is deliberately coarser than strictly necessary, because
  it is syntactic. ``*/api/src/x.py`` over project ``api`` does have a valid
  rewrite, but is refused along with the genuinely ambiguous
  ``services/api`` case. Refusing a representable pattern costs the operator an
  error message; accepting an unrepresentable one silently changes which
  findings are suppressed.
* Prefix comparison is case-insensitive, matching how ``file_path_matches`` and
  ``_path_pattern_matches`` compare paths elsewhere in ASH. Two projects
  differing only in case would therefore both match; ASH has no such case
  elsewhere, and diverging from the rest of the codebase's comparison rule
  would be worse.
* The contract is stated against ``file_path_matches``. If that matcher's glob
  semantics change -- particularly whether ``*`` crosses ``/`` -- these rewrites
  must be re-derived. The property test in
  ``tests/unit/utils/test_workspace_paths.py`` calls the real matcher on both
  sides for exactly that reason, so such a change fails the suite here.
* Up-conversion is purely textual. It does not check that the project prefix
  exists; that is :mod:`automated_security_helper.utils.path_containment`'s job.
"""

from __future__ import annotations

import fnmatch
from pathlib import PurePosixPath, PureWindowsPath
from typing import Optional, Union

from automated_security_helper.core.exceptions import WorkspacePatternError

PathLike = Union[str, PurePosixPath]

_PARENT = ".."

# A pattern component containing any of these is a glob, not a literal name.
_GLOB_METACHARACTERS = frozenset("*?[]")

# What a down-converted pattern becomes when it names exactly the project root.
_WHOLE_PROJECT = "**"


def _normalise(value: PathLike, *, label: str) -> PurePosixPath:
    """Normalise separators and validate, returning a PurePosixPath.

    Rejects the empty value, any ``..`` component, and any drive or UNC anchor.
    Backslashes become forward slashes first, so a Windows-style pattern is
    validated on POSIX rather than being read as one long filename.
    """
    raw = str(value)
    if not raw.strip():
        raise WorkspacePatternError(f"{label} must not be empty")

    # Detect a drive or UNC anchor before normalising, using the Windows
    # flavour: PurePosixPath has no concept of a drive, so it would read
    # "C:/Windows" as an ordinary relative pattern with a component named "C:".
    windows_view = PureWindowsPath(raw)
    if windows_view.drive:
        raise WorkspacePatternError(
            f"{label} '{raw}' is an absolute filesystem path "
            f"(drive or UNC anchor '{windows_view.drive}'); "
            "patterns must be relative to a project or workspace root"
        )

    normalised = PurePosixPath(raw.replace("\\", "/"))
    if _PARENT in normalised.parts:
        raise WorkspacePatternError(
            f"{label} '{raw}' contains a '..' component; "
            "patterns must not traverse upward out of their root"
        )
    return normalised


def _relative_parts(path: PurePosixPath) -> tuple:
    """Return path components with any root anchor dropped.

    This is where a project-rooted pattern loses its leading separator, and it
    happens before any join for the reason in the module docstring: joining a
    root-anchored pattern onto a prefix discards the prefix.
    """
    parts = path.parts
    if parts and parts[0] in ("/", "//"):
        return parts[1:]
    return parts


def _is_glob_component(component: str) -> bool:
    return any(char in _GLOB_METACHARACTERS for char in component)


def _absorbs(prefix_parts: tuple, component: str) -> bool:
    """True when a leading glob *component* can swallow the whole project prefix.

    ``*`` crosses ``/`` in ASH's matcher, so one component can absorb several
    path components. Tested against the joined prefix rather than its first
    component for exactly that reason: ``api*`` absorbs ``api/sub``.
    """
    joined = PurePosixPath(*prefix_parts).as_posix()
    return fnmatch.fnmatch(joined.lower(), component.lower())


def _collides_with_prefix(prefix_parts: tuple, component: str) -> bool:
    """True when *component* could align with a component of the project prefix.

    This is the fail-closed trigger. If the pattern component that follows the
    leading glob can also match part of the prefix, the workspace-level match
    may begin INSIDE the prefix, and no project-relative pattern reproduces
    that -- see the module docstring.
    """
    return any(
        fnmatch.fnmatch(part.lower(), component.lower()) for part in prefix_parts
    )


def _down_convert_unanchored(
    pattern_parts: tuple, prefix_parts: tuple
) -> Optional[str]:
    """Down-convert a pattern whose first component is a glob.

    Returns the project-relative pattern, or None when the pattern cannot match
    inside this project. Raises when the rewrite would be unsound.

    Every branch below was derived by sweeping candidate rewrites against
    ASH's own ``file_path_matches`` and keeping only those that satisfy the
    contract in the module docstring, rather than by reasoning about globs.
    """
    leading, rest = pattern_parts[0], pattern_parts[1:]

    # Whether the leading component can stretch. Only `*` is unbounded; `?` and
    # `[...]` match a FIXED number of characters, so they consume exactly the
    # prefix and never the extra directories that `**` would allow. Rewriting a
    # bounded component to `**` over-matches -- the sweep caught it on
    # "?roject-a/src/x.py", which must not suppress "sub/src/x.py".
    unbounded = "*" in leading

    if not rest:
        # A single-component pattern constrains the whole path, not a directory.
        if leading.startswith("*"):
            # A leading `.*` absorbs the "<prefix>/" itself, so it carries over.
            return leading
        if unbounded:
            # Anchored at the workspace root but stretchy, e.g. "api*" over
            # project "api": every path inside the project matches. When it
            # cannot absorb the prefix it can never match inside the project.
            return _WHOLE_PROJECT if _absorbs(prefix_parts, leading) else None
        # Bounded and alone, e.g. "?????????". Whether it matches depends on the
        # TOTAL length of "<prefix>/<path>", so stripping the prefix changes the
        # answer: it matches "api/x.txt" (nine characters) while matching
        # neither "api" nor "x.txt". A project-relative pattern cannot carry a
        # constraint that depends on the prefix's length, so fail closed.
        raise WorkspacePatternError(
            f"pattern '{leading}' cannot be rewritten for project "
            f"'{PurePosixPath(*prefix_parts).as_posix()}': it is a single "
            f"fixed-length wildcard with no '*', so whether it matches depends "
            f"on the length of the full workspace-relative path and no "
            f"project-relative pattern reproduces it. Use '*' or name a path."
        )

    if not _absorbs(prefix_parts, leading):
        return None

    if _collides_with_prefix(prefix_parts, rest[0]):
        pattern = PurePosixPath(*pattern_parts).as_posix()
        prefix = PurePosixPath(*prefix_parts).as_posix()
        raise WorkspacePatternError(
            f"pattern '{pattern}' cannot be rewritten for project '{prefix}': "
            f"the component '{rest[0]}' after the leading wildcard can also "
            f"match part of the project path, so the pattern may match across "
            f"the project boundary and no single project-relative pattern "
            f"reproduces it. Anchor the pattern with '**/' or name the "
            f"project explicitly."
        )

    if unbounded:
        # The leading glob absorbed the prefix and can absorb an arbitrary
        # number of leading path components with it, which is what `**` means
        # project-side.
        return PurePosixPath(_WHOLE_PROJECT, *rest).as_posix()

    # Bounded: the leading component consumed exactly the prefix and nothing
    # more, so what remains is the pattern as written from the project root.
    return PurePosixPath(*rest).as_posix()


def to_workspace_pattern(pattern: PathLike, project_prefix: PathLike) -> str:
    """Rebase a project-relative *pattern* onto the workspace root.

    Args:
        pattern: A pattern written against the project root. May be relative,
            project-rooted (a leading separator), or ``**``-anchored.
        project_prefix: The project's workspace-relative path, e.g.
            ``project-a`` or ``apps/web``.

    Returns:
        The workspace-relative pattern, forward-slash separated.

    Raises:
        WorkspacePatternError: If either argument is empty, contains a ``..``
            component, or is anchored to a drive or UNC share.
    """
    prefix_parts = _relative_parts(_normalise(project_prefix, label="project prefix"))
    if not prefix_parts:
        raise WorkspacePatternError("project prefix must name at least one component")

    pattern_parts = _relative_parts(_normalise(pattern, label="pattern"))
    if not pattern_parts:
        raise WorkspacePatternError("pattern must name at least one component")

    return PurePosixPath(*prefix_parts, *pattern_parts).as_posix()


def to_project_pattern(pattern: PathLike, project_prefix: PathLike) -> Optional[str]:
    """Rebase a workspace-relative *pattern* onto one project's root.

    The inverse of :func:`to_workspace_pattern`, for pushing a workspace-level
    policy down into a single project.

    Args:
        pattern: A workspace-relative pattern.
        project_prefix: The project's workspace-relative path.

    Satisfies, for every project-relative path ``p``::

        matches(to_project_pattern(P, R), p) == matches(P, R + "/" + p)

    where ``matches`` is ``suppression_matcher.file_path_matches``. See the
    module docstring for the per-shape rewrites and why over-suppression is the
    dangerous direction.

    Returns:
        The project-relative pattern, or ``None`` when the pattern cannot match
        anything inside this project -- including when it names only the project
        directory, which covers no file within it.

    Raises:
        WorkspacePatternError: On the same malformed inputs as
            :func:`to_workspace_pattern`, and on the three shapes that have no
            correct single-pattern rewrite (see "Fail-closed classes" in the
            module docstring). The message names the pattern and the remedy.
    """
    prefix_parts = _relative_parts(_normalise(project_prefix, label="project prefix"))
    if not prefix_parts:
        raise WorkspacePatternError("project prefix must name at least one component")

    pattern_parts = _relative_parts(_normalise(pattern, label="pattern"))
    if not pattern_parts:
        raise WorkspacePatternError("pattern must name at least one component")

    if _is_glob_component(pattern_parts[0]):
        return _down_convert_unanchored(pattern_parts, prefix_parts)

    # Walk the span the project prefix occupies, component by component and
    # case-insensitively, to match how the rest of ASH compares paths. A string
    # prefix test would wrongly accept "project-abc" as inside "project-a".
    for index, prefix_part in enumerate(prefix_parts):
        if index >= len(pattern_parts):
            # The pattern runs out inside the prefix span, so it names an
            # ancestor of the project rather than anything within it.
            return None

        pattern_part = pattern_parts[index]
        if not _is_glob_component(pattern_part):
            if pattern_part.lower() != prefix_part.lower():
                return None
            continue

        # A glob inside the prefix span. The one shape that is both common and
        # soundly rewritable is a trailing `**`, which covers everything below
        # this point and therefore the whole project: "api/**" over project
        # "api/sub". Anything else would need glob algebra to align a stretchy
        # component against the remaining prefix, so fail closed.
        if pattern_parts[index:] == (_WHOLE_PROJECT,):
            return _WHOLE_PROJECT
        raise WorkspacePatternError(
            f"pattern '{PurePosixPath(*pattern_parts).as_posix()}' cannot be "
            f"rewritten for project "
            f"'{PurePosixPath(*prefix_parts).as_posix()}': the wildcard "
            f"'{pattern_part}' falls inside the project path itself, so how "
            f"much of that path it consumes is ambiguous. Anchor the pattern "
            f"with '**/' or name the project path explicitly."
        )

    remainder = pattern_parts[len(prefix_parts) :]
    if not remainder:
        # The pattern names the project directory and nothing below it. In
        # ASH's matcher "api" matches the path "api", not "api/src/x.py", so no
        # file inside the project is covered and the pattern does not apply.
        # Returning `**` here would suppress the entire project -- the
        # contract sweep caught exactly that.
        return None
    return PurePosixPath(*remainder).as_posix()
