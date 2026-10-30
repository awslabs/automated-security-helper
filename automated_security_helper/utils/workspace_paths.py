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
* drive- or UNC-anchored (``C:/Windows``, ``//server/share``) -- rejected. A
  drive anchor is one ASCII letter, a colon and then a separator or the end of
  the text, decided from the text (:func:`_drive_anchor`): ``c:notes.py`` and
  ``*:Zone.Identifier`` are component names, as they are on POSIX.
* A pattern is text. ``PurePosixPath`` has no trailing separator, so a
  directory-form ignore path given as a path object would arrive as ``vendor``
  rather than ``vendor/``; both converters take the pattern as a ``str``.

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

    matches(to_project_pattern(P, R, kind=k), p)  ==  matches(P, R + "/" + p)

A down-converted pattern must reach exactly the files the workspace-level
pattern reached inside that project. ``None`` means the pattern cannot match
anything in the project, so the caller applies nothing. ``matches`` is the
matcher of the entry's kind: ``ignore_path_matches`` for an ignore path, where a
trailing ``/`` names a directory (``vendor/`` covers what is inside ``vendor``),
and ``file_path_matches`` for a suppression, where it is literal and matches no
file. So an ignore path keeps its directory form (``api/vendor/`` over ``api``
becomes ``vendor/``) and a suppression keeps its slash.

A ``.`` or empty component (``./api/x.py``, ``api/./x.py``, ``api//x.py``) is
refused. The top-level matchers read it literally, so it matches no file there,
while ``PurePosixPath`` folds it away. A leading separator (``/api/x.py``) is
refused for the same reason: the matcher reads it literally too (it absorbs one
only before a leading ``**``, so ``/**/x.py`` is ``**/x.py``), and no
workspace-relative path starts with one. A non-UTF-8 name's record-form escape
(``\\udcNN``) is read as its one character before the separators are, as the
matcher reads it, so such a name stays one component.

Getting this wrong is not symmetric, and the asymmetry runs the opposite way to
intuition. A suppression that matches TOO MUCH suppresses findings that should
have been reported, and a suppressed finding leaves no trace in the output --
nobody sees what is missing. An ignore path that matches too much drops files
from the scan, with the same result. A pattern that matches too little, or is
dropped entirely, produces extra findings, which are visible and merely noisy.
So the safe failure is to match less: return ``None``, or refuse, rather than
widen a pattern.

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

A pattern that already holds ``**`` is read component by component on both
sides of the contract, so it converts exactly (``_down_convert_components``):
the project prefix is walked through the pattern's components as
``_recursive_glob_match`` walks a path, and what is left of the pattern is the
project-side pattern. ``**`` over the whole project is the answer when what is
left covers every path, ``None`` when nothing is left, and the pattern is
refused when the walk leaves two positions neither of which covers the other
(``**/api/src/x.py`` over ``services/api``). An ignore path's directory form
(``vendor/``, read as ``vendor/*/**``) is always of this kind.

Every rewrite below, for a pattern WITHOUT ``**``, was therefore derived by
sweeping candidate rewrites against the real ``file_path_matches`` over an
adversarial corpus -- component names chosen to collide with pattern literals --
and keeping only those that satisfied the contract for every path. Nothing is
passed through on the hope that it might apply, and nothing is justified by
reasoning about glob semantics alone:

* Anchored to this project (``api/src/x.py`` over ``api``) -- strip the prefix.
  A project directory whose name holds a bracket (``app[v2]``) is anchored by
  the matcher's equality reading alone: ``fnmatch`` reads ``[v2]`` as a class
  that never matches the text ``[v2]``, so the glob reading matches nothing in
  the project, and a path equal to the pattern's text is a match before any
  glob. The remainder is then the rewrite when it is literal (``x.py``), and
  refused when it holds a glob, which project-side would match more than the
  one file the equality covered.
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
  ``src/x.py``, the file the operator named. A single remainder that is itself
  ``*`` or ``*<literal>`` (``*/*``, ``*/*.py``) converts whatever the project
  path holds: its constraint is on the end of the joined path, which the part
  inside the project decides, so a prefix component that ``*.py`` happens to
  match (a project directory ``lib.py``) does not make the match begin inside
  the prefix.
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
  ``sub/src/x.py``. With ``**`` in the pattern this rule does not apply: there a
  ``?`` stays inside one component, so ``???/**`` covers nothing in ``a/b``. One
  that cannot span the prefix (``?pi/src/x.py`` over ``services``: the pattern's
  separator would have to land on the ``v``), whose separator lands inside the
  prefix but whose remainder opens with a plain name other than the prefix's next
  component (``?/src/x.py`` over ``a/b``: the ``src`` would have to be ``b``), or
  that alone would match only the bare prefix, is ``None``, like a literal
  anchored elsewhere. One whose remainder
  is a glob that does not match its own text (``?pi/[x].py``) is refused: the
  matcher reads a path equal to a pattern's text as a match before any glob, so
  project-side ``[x].py`` would also cover the file ``[x].py``.
* Trailing ``**`` inside the prefix span (``api/**`` over ``api/sub``) -- ``**``,
  from the component walk.

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
4. A fixed-length leading that does not span the prefix exactly and is not
   shown to match nothing (``?/*/x.py`` or ``?/b/src/x.py`` over ``a/b``,
   ``?????????`` alone). The pattern's separator can land INSIDE the prefix and
   the remainder can absorb the rest of it, or the match rests on the
   joined path's total length --
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
* The safe region for patterns without ``**`` is small, and deliberately so.
  Anyone widening it must extend the contract sweeps first (both kinds, in
  ``tests/unit/utils/test_workspace_paths.py``) and show they still report zero
  contract violations.
* Prefix comparison is case-sensitive, as ``file_path_matches`` and
  ``_path_pattern_matches`` compare paths: on a case-sensitive filesystem
  ``Project-A`` is another directory, so a workspace pattern naming it does not
  apply to the project ``project-a``. Diverging from the matcher would break the
  contract below.
* The contract is stated against ``file_path_matches`` and
  ``ignore_path_matches``. If their glob semantics change -- particularly
  whether ``*`` crosses ``/``, or how ``ignore_path_pattern`` reads a trailing
  ``/`` -- these rewrites must be re-derived. The property tests in
  ``tests/unit/utils/test_workspace_paths.py`` call the real matchers on both
  sides for exactly that reason, so such a change fails the suite here.
* Up-conversion is purely textual. It does not check that the project prefix
  exists; that is :mod:`automated_security_helper.utils.path_containment`'s job.
* Up-conversion folds a ``.`` or empty component away, as ``PurePosixPath``
  does, while down-conversion refuses one. Its one caller rebases a finding's
  URI (``workspace/aggregation.to_workspace_uri``), where ``./src/x.py`` is the
  path ``src/x.py``; for a pattern the matcher reads the component literally,
  so a project-side pattern holding one matches no file, and the folded
  workspace-side pattern would match one. A refusal here would make such a URI
  unconvertible, so the URI caller has to fold its own text first.
"""

from __future__ import annotations

import fnmatch
from pathlib import PurePosixPath
from typing import Final, FrozenSet, Literal, Optional, Tuple, Union

from automated_security_helper.core.exceptions import WorkspacePatternError
from automated_security_helper.utils.path_matching import (
    _pattern_components,
    ignore_path_pattern,
)
from automated_security_helper.utils.undecodable_text import (
    text_of_undecodable,
    undecodable_of_text,
)

PathLike = Union[str, PurePosixPath]

#: The two kinds of workspace policy entry a pattern can be. Each is read at the
#: top level by its own matcher, and a down-converted pattern has to keep that
#: matcher's answer: an ignore path by ``suppression_matcher.ignore_path_matches``,
#: where a trailing ``/`` names a directory and covers what is inside it, and a
#: suppression by ``suppression_matcher.file_path_matches``, where a trailing
#: ``/`` is literal and so matches no file.
IGNORE_PATH: Final = "ignore_path"
SUPPRESSION: Final = "suppression"
PatternKind = Literal["ignore_path", "suppression"]
_KINDS: FrozenSet[str] = frozenset({IGNORE_PATH, SUPPRESSION})

_PARENT = ".."

# A pattern component containing any of these is a glob, not a literal name.
_GLOB_METACHARACTERS = frozenset("*?[]")

# What a down-converted pattern becomes when it names exactly the project root.
_WHOLE_PROJECT = "**"

# What ``ignore_path_pattern`` appends to a directory: one component, then any.
_INSIDE_DIRECTORY = "/*/**"


def _leading_separator_count(normalised_raw: str) -> int:
    """Count the leading separators of an already backslash-normalised string.

    Decided from the raw text rather than from ``PureWindowsPath.drive``, because
    that attribute is version-dependent and would make this a portability bug.
    See :func:`_normalise` for the table.
    """
    return len(normalised_raw) - len(normalised_raw.lstrip("/"))


def _drive_anchor(normalised_raw: str) -> str:
    """The drive anchor an already backslash-normalised string starts with, or ``""``.

    One ASCII letter and a colon, followed by a separator or by nothing
    (``C:/Windows``, ``C:``). Decided from the text, as the leading separators
    are, and not by ``PureWindowsPath(raw).drive``: that attribute read
    ``c:notes.py`` as the drive ``c:`` on every interpreter, and on 3.12 and
    later it reads any first character followed by a colon (``*:Zone.Identifier``,
    ``1:x.py``) as a drive, where 3.10 and 3.11 read a component name. Those are
    legal POSIX names, and a pattern that names one is a pattern, not a
    filesystem path; the Windows reading of ``c:notes.py`` as a drive-relative
    path has no meaning in a POSIX-shaped pattern space.
    """
    if (
        len(normalised_raw) >= 2
        and normalised_raw[0].isascii()
        and normalised_raw[0].isalpha()
        and normalised_raw[1] == ":"
        and (len(normalised_raw) == 2 or normalised_raw[2] == "/")
    ):
        return normalised_raw[:2]
    return ""


def drive_anchor(text: str) -> str:
    """The drive anchor *text* starts with, ``"C:"`` for ``C:/x``, ``C:\\x`` or
    ``C:``, and ``""`` for anything else, ``c:notes.py`` and ``x:legacy`` included.

    The one rule for "is this a Windows drive" the pattern converters read,
    exported so the aggregator's URI reading can take it too and a letter-colon
    NAME is a name on both sides. ``aggregation._posix_text`` strips the leading
    separator of any ``/x:...`` URI on the colon alone, so the POSIX URI
    ``/x:legacy/src/x.py`` reads as the unrooted ``x:legacy/src/x.py`` and is
    rebased under its project, a path naming nothing, where :func:`_drive_anchor`
    reads ``x:legacy`` as a name and the converters keep it one. The aggregator's
    adoption of this function is its own change; until it lands the two readings
    differ, and this function is the one the aggregator is to take.
    """
    return _drive_anchor(text.replace("\\", "/"))


def _normalise(value: PathLike, *, label: str) -> PurePosixPath:
    """Normalise separators and validate, returning a PurePosixPath.

    Rejects the empty value, any ``..`` component, two-or-more leading
    separators, and any drive anchor. Backslashes become forward slashes first,
    so a Windows-style pattern is validated on POSIX rather than being read as
    one long filename.

    The leading-separator rule is decided by counting characters, NOT by
    ``PureWindowsPath(raw).drive``, because that value changed between 3.11 and
    3.12 and this project supports 3.10 through 3.14::

        input            3.10/3.11 .drive     3.12-3.14 .drive
        /src/x.py        ''       falsy       ''         falsy
        //src/x.py       '\\\\\\\\src\\\\x.py'  truthy      same       truthy
        ///src/x.py      ''       FALSY       '\\\\\\\\\\\\src'  TRUTHY
        ////src/x.py     ''       FALSY       '\\\\\\\\\\\\'     TRUTHY

    So three-or-more leading separators read as an ordinary rooted path on
    3.10/3.11 and as a drive anchor on 3.12+. Relying on ``.drive`` for this
    made ``///src/x.py`` accepted on the older interpreters and rejected on the
    newer ones -- the module docstring claimed the latter, and CI's py3.10 and
    py3.11 rows disagreed. Counting characters is identical on every version.
    ``PurePosixPath.parts`` is NOT the culprit: it is identical across all five
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
            f"{label} '{_shown(raw)}' starts with {leading} separators; "
            "that is either a UNC share or a malformed project-rooted path, and "
            "the two cannot be told apart. Use a single leading separator for a "
            "project-rooted pattern, or none for a relative one"
        )

    # A genuine drive letter ("C:/Windows") has no leading separator at all, so
    # it survives the check above and still needs spotting: PurePosixPath has no
    # concept of a drive and would read "C:" as an ordinary component name.
    # Decided from the text (_drive_anchor), the same way as the separators, so
    # a POSIX name such as "c:notes.py" stays a name on every interpreter.
    drive = _drive_anchor(normalised_raw)
    if drive:
        raise WorkspacePatternError(
            f"{label} '{_shown(raw)}' is an absolute filesystem path "
            f"(drive anchor '{drive}'); "
            "patterns must be relative to a project or workspace root"
        )

    normalised = PurePosixPath(normalised_raw)
    if _PARENT in normalised.parts:
        raise WorkspacePatternError(
            f"{label} '{_shown(raw)}' contains a '..' component; "
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
    return fnmatch.fnmatchcase(joined, component)


def _collides_with_prefix(prefix_parts: tuple, component: str) -> bool:
    """True when *component* could align with a component of the project prefix.

    This is the fail-closed trigger. If the pattern component that follows the
    leading glob can also match part of the prefix, the workspace-level match
    may begin INSIDE the prefix, and no project-relative pattern reproduces
    that -- see the module docstring.
    """
    return any(fnmatch.fnmatchcase(part, component) for part in prefix_parts)


def _names_by_equality(pattern_part: str, prefix_part: str) -> bool:
    """True when a glob *pattern_part* matches *prefix_part* only by being its text.

    The matcher reads a path equal to a pattern's text as a match before any glob
    (``path_matching._path_pattern_matches``), so ``app[v2]/x.py`` covers the
    file ``x.py`` of the project ``app[v2]`` though ``fnmatch`` reads ``[v2]`` as
    a class that never matches the text ``[v2]``. A component with no ``*`` is
    fixed-width and anchored, so when its glob reading does not match the prefix
    component the glob reading matches no path under the prefix at all, and the
    equality reading is the only one left: the pattern covers exactly the paths
    spelled as its remainder.
    """
    return (
        pattern_part == prefix_part
        and "*" not in pattern_part
        and not fnmatch.fnmatchcase(prefix_part, pattern_part)
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


def _fixed_width(component: str) -> int:
    """How many characters a component without ``*`` matches.

    One per literal character, one per ``?`` and one per ``[...]`` class, read as
    ``fnmatch.translate`` reads them: a ``[`` that no ``]`` closes is a literal
    ``[``, a ``]`` right after the ``[`` (or after a leading ``!``) is part of the
    class. So the width is exact for every component ``fnmatchcase`` accepts.
    """
    width = 0
    index, end = 0, len(component)
    while index < end:
        char = component[index]
        index += 1
        if char == "[":
            closing = index
            if closing < end and component[closing] == "!":
                closing += 1
            if closing < end and component[closing] == "]":
                closing += 1
            while closing < end and component[closing] != "]":
                closing += 1
            if closing < end:
                index = closing + 1
        width += 1
    return width


def _survives_double_star(rest: tuple) -> bool:
    """True when prefixing *rest* with ``**`` does not change what it matches.

    Introducing ``**`` moves the whole pattern from ``fnmatch`` to
    ``_recursive_glob_match`` (see the module docstring), which re-anchors every
    OTHER glob in the pattern to a single path component. Two remainder shapes
    are unaffected, both established by exhaustive sweep rather than by
    reasoning about glob semantics:

    * every component literal -- a literal suffix means the same thing matched
      character-wise or component-wise.
    * exactly one component that is ``*``, or ``*`` then a literal (``*.py``) --
      "the path ends with the literal" is decided inside the last component.

    Anything else changes meaning. ``sub/*.py`` is the counter-example: under
    ``fnmatch`` the trailing ``*.py`` crosses ``/`` and matches ``src/x.py``,
    but under ``**/sub/*.py`` it is pinned to the final component and does not.
    One component is not enough on its own: ``*/a*`` over project ``x`` covers
    ``api/sub``, because ``a*`` takes ``api/sub`` under fnmatch, while ``**/a*``
    needs the last component to start with ``a``.
    """
    if len(rest) == 1:
        only = rest[0]
        return (
            not _is_glob_component(only)
            or _is_all_stars(only)
            or _is_star_then_literal(only)
        )
    return not any(_is_glob_component(part) for part in rest)


def _unconvertible(
    pattern_parts: tuple, prefix_parts: tuple, reason: str
) -> WorkspacePatternError:
    """Build the fail-closed error, naming the pattern, the project and the fix.

    The whole message goes through :func:`_shown`, the reason included: a reason
    quotes components of the pattern, and a lone surrogate in any of them is as
    unprintable as one in the pattern text.
    """
    message = (
        f"pattern '{PurePosixPath(*pattern_parts).as_posix()}' cannot be "
        f"rewritten for project '{PurePosixPath(*prefix_parts).as_posix()}': "
        f"{reason}. Write the pattern with explicit '**' components, which mean "
        f"the same thing in both path spaces, or name the project explicitly."
    )
    return WorkspacePatternError(_shown(message))


def _shown(text: str) -> str:
    """*text* as a message shows it: each lone surrogate as its record-form escape.

    Down-conversion works on the name a non-UTF-8 file has (each undecodable byte
    a lone surrogate, as the matcher reads the pattern), and a lone surrogate in
    an error message cannot be printed by every sink.
    """
    return text_of_undecodable(text)


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
        # A lone remainder of "*" or "*<literal>" constrains only the end of the
        # joined path, which the part inside the project decides by itself, so
        # it cannot begin inside the prefix: "*/*" is "**/*" over any project,
        # and "*/*.py" is "**/*.py" over a project directory named "lib.py" too.
        ends_only = len(rest) == 1 and (
            _is_all_stars(rest[0]) or _is_star_then_literal(rest[0])
        )
        if not ends_only and _collides_with_prefix(prefix_parts, rest[0]):
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
        width = _fixed_width(leading)
        joined = PurePosixPath(*prefix_parts).as_posix()
        if width < len(joined) and (
            joined[width] != "/" or not fnmatch.fnmatchcase(joined[:width], leading)
        ):
            # The leading ends inside the prefix. The pattern's separator after
            # it has to land on the prefix's character at that position, and
            # the leading has to match the text before it; when either fails,
            # no path under the prefix matches. (When both hold, the pattern's
            # separator sits inside the project path, and that is refused below:
            # the remainder would have to absorb the rest of the prefix.)
            return None
        if width < len(joined) and rest and not _is_glob_component(rest[0]):
            # Both hold: the pattern's separator is the one inside the prefix, so
            # what follows it starts at the next component of the prefix. A
            # remainder that opens with a plain name matches there only when the
            # name is that component, whatever comes after it and whether the
            # entry is a suppression or an ignore path. Another name matches
            # nothing under this prefix: a pattern about another project, as the
            # arms above read one. A glob there could absorb the rest of the
            # prefix, and an equal name leaves the remainder to be rewritten
            # past it; both are refused below.
            if rest[0] != joined[width + 1 :].split("/", 1)[0]:
                return None
        if width == len(joined):
            if not rest or not fnmatch.fnmatchcase(joined, leading):
                # The leading alone matches only the bare prefix, which names no
                # file; a leading that does not match the prefix matches nothing
                # under it either.
                return None
            rewritten = PurePosixPath(*rest).as_posix()
            if not fnmatch.fnmatchcase(rewritten, rewritten):
                # The matcher reads a path that equals the pattern's text as a
                # match before any glob (path_matching._path_pattern_matches),
                # so project-side the remainder also covers the file spelled
                # exactly as the remainder ("[x].py"), which the workspace
                # pattern, whose leading is a glob, never equals. Nothing
                # subtracts that one file from a glob, so fail closed.
                raise _unconvertible(
                    pattern_parts,
                    prefix_parts,
                    f"what is left after the leading, '{rewritten}', also "
                    f"names a file spelled exactly like it project-side, which "
                    f"the workspace pattern does not match",
                )
            return rewritten
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


def to_workspace_pattern(pattern: str, project_prefix: PathLike) -> str:
    """Rebase a project-relative *pattern* onto the workspace root.

    Args:
        pattern: A pattern written against the project root, as text. May be
            relative, project-rooted (a leading separator), or ``**``-anchored.
            Text, not a path object: ``PurePosixPath("vendor/")`` is ``vendor``,
            so a directory-form ignore path given as one would lose its form
            before this call could read it.
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

    rebased = PurePosixPath(*prefix_parts, *pattern_parts).as_posix()
    # PurePosixPath drops a trailing slash, which the matcher reads as "the
    # directory's files" (utils/path_matching.py): put it back.
    return rebased + "/" if _names_a_directory(pattern) else rebased


def _names_a_directory(pattern: str) -> bool:
    """Whether ``pattern`` ends in a separator, ``vendor/`` rather than ``vendor``."""
    raw = str(pattern).replace("\\", "/")
    return raw.endswith("/") and bool(raw.strip("/"))


def _refuse_dot_components(raw: str, text: str) -> None:
    """Refuse a pattern with a ``.`` or an empty component.

    The top-level readers compare a pattern as it is written
    (``path_matching._path_pattern_matches``), so ``./api/x.py``, ``api/./x.py``
    and ``api//x.py`` match no file there, and neither does ``./*``.
    ``PurePosixPath`` folds those components away, so read through it they would
    be ``api/x.py`` and ``*``, and a pushed-down ignore path would drop files from
    the scan that the same pattern at the top level keeps. Refusing names the
    pattern instead of guessing what it meant.

    ``text`` is ``raw`` with backslashes as separators and without its one leading
    separator. Trailing separators are not components: they are an ignore path's
    directory form or a suppression's literal slash.
    """
    for component in text.rstrip("/").split("/"):
        if component in ("", "."):
            raise WorkspacePatternError(
                f"pattern '{_shown(raw)}' has a '.' or empty component, "
                "which ASH's matcher reads literally, so it matches no file; "
                "remove the extra '.' or '/'"
            )


def _down_convert_components(
    text: str, components: Tuple[str, ...], prefix_parts: tuple
) -> Optional[str]:
    """Down-convert a pattern the matcher reads component by component.

    A pattern holding ``**`` anywhere goes to ``_recursive_glob_match`` on both
    sides of the contract, where every other component matches exactly one path
    component. So the conversion is exact: walk the project prefix through the
    pattern's components as that matcher does, ``**`` taking any number of them,
    and keep what is left of the pattern. ``components`` are the pattern's as the
    matcher splits them (``path_matching._pattern_components``).

    The fnmatch-derived rules of :func:`_down_convert_unanchored` do not hold
    here: there a ``?`` or a ``*`` crosses ``/``, here it does not, so ``???/**``
    covers nothing in project ``a/b`` though ``???`` matches the text ``a/b``.

    Returns ``None`` when no position of the pattern survives the prefix, ``**``
    when one that does matches every path, and raises when two positions survive
    and neither covers the other, because no single pattern is their union.
    """
    end = len(components)

    def closure(states: set) -> set:
        # A "**" also matches no component, so the position after it is reached too.
        pending = list(states)
        while pending:
            index = pending.pop()
            if index < end and components[index] == _WHOLE_PROJECT:
                if index + 1 not in states:
                    states.add(index + 1)
                    pending.append(index + 1)
        return states

    # The positions reached after the last prefix component are kept without the
    # closure: what is left from a "**" already covers what is left after it.
    states: set = {0}
    for prefix_part in prefix_parts:
        advanced = set()
        for index in closure(set(states)):
            if index == end:
                continue
            if components[index] == _WHOLE_PROJECT:
                advanced.add(index)
            elif fnmatch.fnmatchcase(prefix_part, components[index]):
                advanced.add(index + 1)
        states = advanced

    # A position at the end matches only the empty path, which names no file.
    states.discard(end)
    if not states:
        return None
    remainders = [components[index:] for index in sorted(states)]
    if any(_matches_every_path(remainder) for remainder in remainders):
        return _WHOLE_PROJECT
    # The remainders are suffixes of one component list, so a longer one is some
    # components followed by a shorter one. A shorter remainder that starts with
    # "**" therefore covers every longer one: its "**" takes those components. So
    # the shortest such remainder stands for all the longer ones, and only the
    # remainders shorter than it are left to disagree with it.
    covering = [
        len(remainder) for remainder in remainders if remainder[0] == _WHOLE_PROJECT
    ]
    if covering:
        shortest = min(covering)
        remainders = [
            remainder for remainder in remainders if len(remainder) <= shortest
        ]
    if len(remainders) > 1:
        raise _unconvertible(
            tuple(text.split("/")),
            prefix_parts,
            "the match can continue from more than one point of the project path, "
            "so no single pattern covers what the workspace pattern covers there",
        )
    rewritten = "/".join(remainders[0])
    if _WHOLE_PROJECT not in rewritten and any(
        _is_glob_component(part) for part in remainders[0]
    ):
        # Without a "**" the project side would be read by fnmatch, whose "*"
        # crosses "/". The workspace side's "**" was inside a component ("x**.py").
        raise _unconvertible(
            tuple(text.split("/")),
            prefix_parts,
            "what is left after the project path has no '**' component, so the "
            "project side would read its wildcards across '/'",
        )
    return rewritten


def _matches_every_path(remainder: Tuple[str, ...]) -> bool:
    """Whether a component-matched pattern covers every path of one or more components.

    ``**`` takes any number of components and ``*`` exactly one, so the remainder
    covers every path when it holds a ``**`` and at most one ``*``, and nothing
    else.
    """
    stars = [part for part in remainder if part != _WHOLE_PROJECT]
    return (
        _WHOLE_PROJECT in remainder
        and all(part == "*" for part in stars)
        and len(stars) <= 1
    )


def _down_convert(text: str, prefix_parts: tuple) -> Optional[str]:
    """Down-convert ``text``: no leading or trailing separator, no ``.`` component."""
    if _WHOLE_PROJECT in text:
        # The matcher reads any pattern holding "**" component by component.
        return _down_convert_components(
            text, tuple(_pattern_components(text)), prefix_parts
        )

    pattern_parts = PurePosixPath(text).parts
    if _is_glob_component(pattern_parts[0]) and not _names_by_equality(
        pattern_parts[0], prefix_parts[0]
    ):
        return _down_convert_unanchored(pattern_parts, prefix_parts)

    # Walk the span the project prefix occupies, component by component and
    # case-sensitively, as file_path_matches compares paths. A string prefix
    # test would wrongly accept "project-abc" as inside "project-a".
    by_equality = False
    for index, prefix_part in enumerate(prefix_parts):
        if index >= len(pattern_parts):
            # The pattern runs out inside the prefix span, so it names an
            # ancestor of the project rather than anything within it.
            return None

        pattern_part = pattern_parts[index]
        if not _is_glob_component(pattern_part):
            if pattern_part != prefix_part:
                return None
            continue
        if by_equality:
            # An earlier component matched only by its exact spelling, so the
            # glob reading of the whole pattern matches nothing under the
            # prefix and only the exact text can still match: a later glob
            # component is its own text here, or nothing. "app[v2]/s?b/x.py"
            # over "app[v2]/s?b" is "x.py"; over "app[v2]/sub" it is nothing.
            if pattern_part != prefix_part:
                return None
            continue
        if _names_by_equality(pattern_part, prefix_part):
            # The matcher's equality reading anchors this component to the
            # project directory spelled exactly so; its glob reading matches
            # nothing under the prefix (_names_by_equality).
            by_equality = True
            continue

        # A glob inside the prefix span. Under fnmatch it could align with the
        # rest of the prefix in more than one way, so fail closed. ("api/**" over
        # "api/sub" holds "**" and is converted by _down_convert_components.)
        raise WorkspacePatternError(
            _shown(
                f"pattern '{PurePosixPath(*pattern_parts).as_posix()}' cannot be "
                f"rewritten for project "
                f"'{PurePosixPath(*prefix_parts).as_posix()}': the wildcard "
                f"'{pattern_part}' falls inside the project path itself, so how "
                f"much of that path it consumes is ambiguous. Anchor the pattern "
                f"with '**/' or name the project path explicitly."
            )
        )

    remainder = pattern_parts[len(prefix_parts) :]
    if not remainder:
        # The pattern names the project directory and nothing below it. In
        # ASH's matcher "api" matches the path "api", not "api/src/x.py", so no
        # file inside the project is covered and the pattern does not apply.
        # Returning `**` here would suppress the entire project -- the
        # contract sweep caught exactly that.
        return None
    if by_equality and any(_is_glob_component(part) for part in remainder):
        # Workspace-side only the path spelled exactly as the pattern matched
        # (the equality reading); project-side the remainder's glob would also
        # match every file it covers as a glob. Nothing subtracts those.
        raise _unconvertible(
            pattern_parts,
            prefix_parts,
            "the project path is matched only by the pattern's exact spelling, "
            "so the pattern covers one file, while what is left after it, "
            f"'{_shown(PurePosixPath(*remainder).as_posix())}', is a glob that "
            "would cover more project-side",
        )
    return PurePosixPath(*remainder).as_posix()


def _as_directory_form(converted: Optional[str]) -> Optional[str]:
    """An ignore path's down-converted ``<dir>/*/**`` written back as ``<dir>/``.

    ``ignore_path_pattern`` reads ``<dir>/`` as ``<dir>/*/**``, so the two are one
    ignore path, and the directory form is the one the operator wrote. ``**`` (the
    whole project) and ``None`` are returned as they are.
    """
    if converted is not None and converted.endswith(_INSIDE_DIRECTORY):
        directory = converted[: -len(_INSIDE_DIRECTORY)]
        if directory:
            return f"{directory}/"
    return converted


def _down_convert_literal_slash(text: str, prefix_parts: tuple) -> Optional[str]:
    """Down-convert a suppression ending in ``/``, whose slash is literal.

    A file's path never ends in ``/``, so such a suppression matches no file at
    the top level, and the one pushed down must match none either. It keeps its
    slash (``api/vendor/`` becomes ``vendor/``), so the project's warning about a
    suppression that names a directory still names it. When no rewrite keeps the
    slash meaningful, which includes the project root itself (``api/`` over
    ``api``) and a rewrite whose slash ``**`` would absorb (``*/`` would become
    ``**/``, which is ``**``), it is dropped for the project, never widened.

    ``api/**/`` is not literal: the matcher absorbs a slash after a trailing
    ``**``, so it is ``api/**`` and converts as that.
    """
    directory = text.rstrip("/")
    if _pattern_components(text)[-1] != "":
        return _down_convert(directory, prefix_parts)
    try:
        converted = _down_convert(directory, prefix_parts)
    except WorkspacePatternError:
        # Matching no file either way, there is nothing to refuse.
        return None
    if converted is None or converted == _WHOLE_PROJECT:
        return None
    candidate = f"{converted}/"
    return candidate if _pattern_components(candidate)[-1] == "" else None


def to_project_pattern(
    pattern: str, project_prefix: PathLike, *, kind: PatternKind
) -> Optional[str]:
    """Rebase a workspace-relative *pattern* onto one project's root.

    The inverse of :func:`to_workspace_pattern`, for pushing a workspace-level
    policy down into a single project.

    Args:
        pattern: A workspace-relative pattern, as text (see
            :func:`to_workspace_pattern` on why not a path object).
        project_prefix: The project's workspace-relative path.
        kind: :data:`IGNORE_PATH` or :data:`SUPPRESSION`, the kind of policy entry
            the pattern belongs to, which decides the matcher it is read by.

    Satisfies, for every project-relative path ``p``::

        matches(to_project_pattern(P, R, kind=k), p) == matches(P, R + "/" + p)

    where ``matches`` is ``suppression_matcher.ignore_path_matches`` for an ignore
    path and ``suppression_matcher.file_path_matches`` for a suppression. See the
    module docstring for the per-shape rewrites and why widening a pattern is the
    dangerous direction.

    An ignore path keeps its directory form: ``api/vendor/`` over ``api`` becomes
    ``vendor/``, and one naming the project directory or an ancestor of it
    (``api/`` over ``api`` or ``api/sub``) covers the whole project, ``**``. A
    suppression keeps its literal ``/`` (:func:`_down_convert_literal_slash`).

    Returns:
        The project-relative pattern, or ``None`` when the pattern cannot match
        anything inside this project -- including when it names only the project
        directory, which covers no file within it.

    Raises:
        WorkspacePatternError: On the same malformed inputs as
            :func:`to_workspace_pattern`, on a ``.`` or empty component
            (:func:`_refuse_dot_components`), on a leading ``/`` (the matcher
            reads it literally, so the pattern matches no workspace-relative
            path and has no rewrite that matches the same files; a leading
            ``/`` in a PROJECT config is read as project-rooted by
            :func:`to_workspace_pattern`, which this function does not invert
            for that one shape), and on the shapes that have no correct
            single-pattern rewrite (see "Fail-closed classes" in the module
            docstring). The message names the pattern and the remedy.
        ValueError: ``kind`` is neither kind.
    """
    if kind not in _KINDS:
        raise ValueError(f"unknown workspace pattern kind {kind!r}")
    prefix_parts = _relative_parts(_normalise(project_prefix, label="project prefix"))
    if not prefix_parts:
        raise WorkspacePatternError("project prefix must name at least one component")

    raw = str(pattern)
    # In the matcher's reading order (path_matching._match_form): a non-UTF-8
    # name's record-form escape ("\udcNN") is read as its one character before
    # the separators are, so its backslash is part of the name, not a separator,
    # and such a name stays one component here, for the validation too: read on
    # the raw text, the escape's backslash was a separator, so "api/..\udce9.py"
    # was refused as a ".." traversal and "c:\udce9x.py" as a drive. The result
    # is written back in the record form, the form the operator wrote and a
    # report shows; the messages quote the raw text through _shown.
    name = undecodable_of_text(raw)
    if not _relative_parts(_normalise(name, label="pattern")):
        raise WorkspacePatternError("pattern must name at least one component")

    form = name.replace("\\", "/")
    if form.startswith("/") and _pattern_components(form)[0] == "":
        # The matcher reads the separator literally (it absorbs one only before
        # a leading "**"), and no workspace-relative path starts with one, so the
        # pattern matches no file at the top level. Converted, it would match
        # files project-side that it never matched workspace-side.
        raise WorkspacePatternError(
            f"pattern '{_shown(raw)}' starts with '/', which ASH's matcher reads "
            "literally, so it matches no workspace-relative path; remove the "
            "leading '/'"
        )
    # One leading separator at most (_normalise refuses more).
    text = form.removeprefix("/")
    _refuse_dot_components(raw, text)

    if text.endswith("/"):
        if kind == IGNORE_PATH:
            converted = _as_directory_form(
                _down_convert(ignore_path_pattern(text), prefix_parts)
            )
        else:
            converted = _down_convert_literal_slash(text, prefix_parts)
    else:
        converted = _down_convert(text, prefix_parts)
    return text_of_undecodable(converted) if converted is not None else None
