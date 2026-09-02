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

The matcher has two glob semantics, and they are not interconvertible
--------------------------------------------------------------------
This is the fact that makes down-conversion hard, and it will surprise the next
reader. ``file_path_matches`` dispatches on whether the pattern contains ``**``:

* No ``**`` -- the pattern goes to ``fnmatch`` (suppression_matcher.py:100),
  where ``*`` is ``.*`` and CROSSES ``/``. So ``*/sub/*.py`` behaves like the
  regex ``.*/sub/.*\\.py``, and its trailing ``*.py`` spans directories: it
  matches ``api/sub/src/x.py``.
* Contains ``**`` -- the pattern goes to ``_recursive_glob_match``
  (suppression_matcher.py:98), which anchors each segment to whole path
  COMPONENTS. In ``**/sub/*.py`` the trailing ``*.py`` is now pinned to one
  component and no longer matches ``src/x.py``.

So introducing ``**`` to express "at any depth" silently re-interprets every
OTHER glob in the same pattern. The two semantics cannot be converted into one
another in general, which is why down-conversion is sound only for a proven
subset of shapes rather than for a tidy rule. This is the same inconsistency
recorded in the corrected comment at suppression_matcher.py:92.

Every rewrite below was therefore derived by sweeping candidate rewrites against
the real ``file_path_matches`` over an adversarial corpus -- component names
chosen to collide with pattern literals -- and keeping only those that satisfied
the contract for every path. Nothing is passed through on the hope that it might
apply, and nothing is justified by reasoning about glob semantics alone:

* Anchored to this project (``api/src/x.py`` over ``api``) -- strip the prefix.
* Anchored elsewhere (``api/src/x.py`` over ``api-v2``) -- ``None``.
* Naming only the project directory (``api`` over ``api``) -- ``None``.
  ``file_path_matches("api/src/x.py", "api")`` is False, so this pattern covers
  no file in the project. Returning ``**`` here would have suppressed a whole
  project the operator never named.
* All-stars leading (``*``, ``**``) with an all-literal or single-component
  remainder (``*/src/x.py``, ``*/*.py``) -- becomes ``**/src/x.py``,
  ``**/*.py``. The leading absorbed the prefix and can absorb further
  directories, which is what ``**`` means project-side. Returning the pattern
  unchanged retargeted it: ``*/src/x.py`` over project ``api`` stopped matching
  ``src/x.py``, the file the operator named.
* Literal-then-star leading (``api*``, ``project-*``) -- same treatment, plus
  ``None`` when it cannot absorb the prefix. Sound because the literal is pinned
  to position 0 of the joined path, so the prefix alone decides whether it can
  match at all.
* Star-then-literal leading as the WHOLE pattern (``*.py``, ``*v2``) -- carries
  over unchanged. Its constraint is "the joined path ends with the literal",
  which the part inside the project decides on its own.
* Fixed-length leading spanning the prefix exactly
  (``?roject-a/src/x.py`` over ``project-a``) -- becomes ``src/x.py``, NOT
  ``**/src/x.py``. ``?`` and ``[...]`` match a fixed number of characters, so
  the component consumed exactly the prefix; ``**`` would over-suppress
  ``sub/src/x.py``.
* Trailing ``**`` inside the prefix span (``api/**`` over ``api/sub``) -- ``**``.

Fail-closed classes
-------------------
Everything not in the list above is rejected with an error naming the pattern,
the project and the remedy. The families, each with the counter-example that
put it here:

1. A remainder that is multi-component AND contains a glob, under a leading that
   needs ``**`` (``*/sub/*.py``). This is the two-semantics problem above:
   ``*/sub/*.py`` covers ``api/sub/src/x.py`` because the trailing ``*.py``
   crosses ``/`` under fnmatch, but ``**/sub/*.py`` pins it to one component and
   does not.
2. A star before a literal with a remainder (``*v2/src``). The literal has to
   land immediately before a separator, and nothing makes that a directory
   boundary -- ``*v2/src`` matches ``apiv2/xv2/src`` with the ``v2`` inside
   ``xv2``, so the bare remainder ``src`` would miss files the pattern covers.
3. A wildcard mixed between or among literals (``a*b``, ``*b*``), where the
   component's span is pinned to neither end. ``*b*`` over project ``a/b`` is
   satisfied by the prefix supplying the ``b``, so no project-relative pattern
   reproduces it.
4. A fixed-length leading that does not span the prefix exactly (``?`` over
   ``a/b``, ``?????????`` alone). The pattern's separator can land INSIDE the
   prefix, or the verdict rests on the joined path's total length --
   ``?????????`` matches ``api/x.txt`` (nine characters) while matching neither
   ``api`` nor ``x.txt``.
5. A literal component after the leading wildcard that also matches part of the
   project path (``*/api/src/x.py`` over ``services/api``), where the match can
   begin inside the prefix.
6. A wildcard falling inside the project path itself (``api/*/x.py`` over
   ``api/sub``), where how much of the path it consumes is ambiguous.

Failure modes and known limitations
-----------------------------------
* The fail-closed tests are syntactic and therefore coarser than strictly
  necessary. ``*/api/src/x.py`` over project ``api`` does have a valid rewrite
  but is refused along with the genuinely ambiguous ``services/api`` case, and
  family 1 refuses some remainders that would happen to survive. Refusing a
  representable pattern costs the operator an error message; accepting an
  unrepresentable one silently changes which findings are suppressed. Given the
  asymmetry above, that trade is the right way round.
* The safe region is small, and deliberately so. Of 2,880 pattern/prefix pairs
  in the verification sweep, 371 convert, 656 return ``None`` and 1,853 fail
  closed. Anyone widening it must extend that sweep first and show it still
  reports zero contract violations.
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


def _leading_separator_count(normalised_raw: str) -> int:
    """Count the leading separators of an already backslash-normalised string.

    Decided from the raw text rather than from ``PureWindowsPath.drive``, because
    that attribute is version-dependent and would make this a portability bug.
    See :func:`_normalise` for the table.
    """
    return len(normalised_raw) - len(normalised_raw.lstrip("/"))


def _normalise(value: PathLike, *, label: str) -> PurePosixPath:
    """Normalise separators and validate, returning a PurePosixPath.

    Rejects the empty value, any ``..`` component, two-or-more leading
    separators, and any drive anchor. Backslashes become forward slashes first,
    so a Windows-style pattern is validated on POSIX rather than being read as
    one long filename.

    The leading-separator rule is decided by counting characters, NOT by
    ``PureWindowsPath(raw).drive``, because that value changed between 3.11 and
    3.12 and this project supports 3.10 through 3.13::

        input            3.10/3.11 .drive     3.12/3.13 .drive
        /src/x.py        ''       falsy       ''         falsy
        //src/x.py       '\\\\\\\\src\\\\x.py'  truthy      same       truthy
        ///src/x.py      ''       FALSY       '\\\\\\\\\\\\src'  TRUTHY
        ////src/x.py     ''       FALSY       '\\\\\\\\\\\\'     TRUTHY

    So three-or-more leading separators read as an ordinary rooted path on
    3.10/3.11 and as a drive anchor on 3.12+. Relying on ``.drive`` for this
    made ``///src/x.py`` accepted on the older interpreters and rejected on the
    newer ones -- the module docstring claimed the latter, and CI's py3.10 and
    py3.11 rows disagreed. Counting characters is identical on every version.
    ``PurePosixPath.parts`` is NOT the culprit: it is identical across all four
    versions, collapsing three-or-more leading separators to a single ``/``,
    which is precisely why the anchor cannot be recovered after parsing.
    """
    raw = str(value)
    if not raw.strip():
        raise WorkspacePatternError(f"{label} must not be empty")

    normalised_raw = raw.replace("\\", "/")

    # Explicit, version-independent decision about the leading separators. This
    # runs BEFORE the drive check so that it, rather than the pathlib version,
    # decides every all-separator anchor -- including the real UNC "//server/share".
    leading = _leading_separator_count(normalised_raw)
    if leading >= 2:
        raise WorkspacePatternError(
            f"{label} '{raw}' starts with {leading} separators; "
            "that is either a UNC share or a malformed project-rooted path, and "
            "the two cannot be told apart. Use a single leading separator for a "
            "project-rooted pattern, or none for a relative one"
        )

    # A genuine drive letter ("C:/Windows") has no leading separator at all, so
    # it survives the check above and still needs the Windows flavour to spot
    # it: PurePosixPath has no concept of a drive and would read "C:" as an
    # ordinary component name. This use of `.drive` is version-stable because it
    # only ever sees zero-or-one-leading-separator input by this point.
    windows_view = PureWindowsPath(normalised_raw)
    if windows_view.drive:
        raise WorkspacePatternError(
            f"{label} '{raw}' is an absolute filesystem path "
            f"(drive anchor '{windows_view.drive}'); "
            "patterns must be relative to a project or workspace root"
        )

    normalised = PurePosixPath(normalised_raw)
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


def _is_all_stars(component: str) -> bool:
    """``*`` or ``**`` -- matches any run of characters, including separators."""
    return bool(component) and set(component) == {"*"}


def _is_literal_then_star(component: str) -> bool:
    """``api*`` -- a literal anchored at position 0, then one trailing ``*``.

    Soundly convertible because the literal must match the very start of the
    joined path, so whether it matches is decided by the prefix alone, and the
    trailing ``*`` is free to absorb further directories.
    """
    return (
        component.endswith("*")
        and component.count("*") == 1
        and not any(char in "?[]" for char in component)
        and not _is_all_stars(component)
    )


def _is_star_then_literal(component: str) -> bool:
    """``*.py``, ``*v2`` -- one leading ``*`` then a literal, and nothing else.

    Convertible only when it is the entire pattern. Then its constraint is
    "the joined path ends with <literal>", which the project-relative part alone
    decides, so the pattern carries over unchanged. With a remainder it is NOT
    convertible: the literal must land immediately before a separator, and
    nothing pins that to a directory boundary -- ``*v2/src`` matches
    ``apiv2/xv2/src`` with the ``v2`` inside ``xv2``.
    """
    return (
        component.startswith("*")
        and component.count("*") == 1
        and not any(char in "?[]" for char in component[1:])
        and not _is_all_stars(component)
    )


def _is_fixed_length(component: str) -> bool:
    """``?roject-a``, ``[pq]roject-a`` -- no ``*``, so a fixed character count."""
    return "*" not in component


def _survives_double_star(rest: tuple) -> bool:
    """True when prefixing *rest* with ``**`` does not change what it matches.

    Introducing ``**`` moves the whole pattern from ``fnmatch`` to
    ``_recursive_glob_match`` (see the module docstring), which re-anchors every
    OTHER glob in the pattern to a single path component. Two remainder shapes
    are unaffected, both established by exhaustive sweep rather than by
    reasoning about glob semantics:

    * every component literal -- a literal suffix means the same thing matched
      character-wise or component-wise.
    * exactly one component -- re-anchoring has nothing to re-anchor.

    Anything else changes meaning. ``sub/*.py`` is the counter-example: under
    ``fnmatch`` the trailing ``*.py`` crosses ``/`` and matches ``src/x.py``,
    but under ``**/sub/*.py`` it is pinned to the final component and does not.
    """
    return len(rest) == 1 or not any(_is_glob_component(part) for part in rest)


def _unconvertible(
    pattern_parts: tuple, prefix_parts: tuple, reason: str
) -> WorkspacePatternError:
    """Build the fail-closed error, naming the pattern, the project and the fix."""
    return WorkspacePatternError(
        f"pattern '{PurePosixPath(*pattern_parts).as_posix()}' cannot be "
        f"rewritten for project '{PurePosixPath(*prefix_parts).as_posix()}': "
        f"{reason}. Write the pattern with explicit '**' components, which mean "
        f"the same thing in both path spaces, or name the project explicitly."
    )


def _down_convert_unanchored(
    pattern_parts: tuple, prefix_parts: tuple
) -> Optional[str]:
    """Down-convert a pattern whose first component is a glob.

    Returns the project-relative pattern, ``None`` when the pattern cannot match
    inside this project, or raises for any shape not proven convertible.

    Only four leading shapes are converted, each established by sweeping
    candidate rewrites against ASH's own ``file_path_matches`` over an
    adversarial corpus rather than by reasoning about glob semantics. Everything
    else fails closed. See "Fail-closed classes" in the module docstring for why
    the safe region is this narrow.
    """
    leading, rest = pattern_parts[0], pattern_parts[1:]

    # A leading made only of stars, or a literal followed by one trailing star,
    # both anchor cleanly: the former matches anything, the latter is decided by
    # the prefix's opening characters. Both can absorb further directories, so
    # expressing them project-side needs `**`.
    if _is_all_stars(leading) or _is_literal_then_star(leading):
        if _is_literal_then_star(leading) and not _absorbs(prefix_parts, leading):
            # The literal is pinned to position 0 of the joined path, so failing
            # to match the prefix means it can never match inside the project.
            return None
        if not rest:
            return _WHOLE_PROJECT
        if _collides_with_prefix(prefix_parts, rest[0]):
            raise _unconvertible(
                pattern_parts,
                prefix_parts,
                f"the component '{rest[0]}' after the leading wildcard can also "
                f"match part of the project path, so the match may begin inside "
                f"the project path rather than after it",
            )
        if not _survives_double_star(rest):
            raise _unconvertible(
                pattern_parts,
                prefix_parts,
                f"expressing the leading '{leading}' project-side requires "
                f"'**', which switches the matcher from fnmatch to "
                f"component-anchored matching and re-interprets the glob in "
                f"'{PurePosixPath(*rest).as_posix()}' -- under fnmatch a '*' "
                f"crosses '/', under '**' it is pinned to one path component",
            )
        return PurePosixPath(_WHOLE_PROJECT, *rest).as_posix()

    # One leading star then a literal. Convertible only as the whole pattern,
    # where the constraint is "the joined path ends with <literal>" and the part
    # inside the project decides it on its own.
    if _is_star_then_literal(leading):
        if not rest:
            return leading
        raise _unconvertible(
            pattern_parts,
            prefix_parts,
            f"the leading '{leading}' puts a wildcard before a literal, so the "
            f"literal need not land on a directory boundary -- '{leading}/…' "
            f"also matches paths where it falls inside a component name",
        )

    # Fixed-length leading. Sound only when it spans the prefix exactly: then the
    # separator after it in the pattern must be the one after the prefix, so the
    # remainder applies verbatim and no `**` is introduced.
    if _is_fixed_length(leading):
        if rest and _absorbs(prefix_parts, leading):
            return PurePosixPath(*rest).as_posix()
        raise _unconvertible(
            pattern_parts,
            prefix_parts,
            f"the leading '{leading}' matches a fixed number of characters that "
            f"does not span the project path exactly, so whether it matches "
            f"depends on the length of the joined path rather than on the part "
            f"inside the project",
        )

    # Everything else: several stars mixed with literals ("a*b", "*b*"), or a
    # star mixed with "?"/"[...]". How much of the joined path the component
    # consumes is not pinned to any boundary.
    raise _unconvertible(
        pattern_parts,
        prefix_parts,
        f"the leading '{leading}' mixes wildcards and literals in a way that is "
        f"not pinned to a directory boundary, so how much of the project path it "
        f"consumes is ambiguous",
    )


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
