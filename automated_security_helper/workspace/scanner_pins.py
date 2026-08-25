# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Decide whether two scanner version pins can both be satisfied.

Why this module exists
----------------------
A project pins the version of a scanner tool through
``scanners.<name>.options.tool_version``, a PEP 440 specifier set such as
``">=1.125.0,<2.0.0"``. One ASH run installs one version of each tool, and
per-project tool isolation is out of scope, so a workspace whose projects demand
disjoint version ranges cannot be honoured for both. The only two honest
responses are to refuse the workspace or to scan a project with a tool version it
explicitly excluded -- and for a security scanner the second is not acceptable,
because the operator's stated reason for the exclusion (a false-negative in that
version, say) is silently overridden and nothing in the output says so.

So this module answers exactly one question -- "does any version satisfy both
pins?" -- and answers it in three values rather than two, because "I cannot
tell" is a real outcome that must not be collapsed into either verdict.

Why not use ``packaging``
-------------------------
``packaging.specifiers.SpecifierSet`` would parse these strings correctly, and it
is present in the environment as a transitive dependency. It is not a declared
dependency of ASH and nothing in ASH imports it today, so depending on it here
would make ASH's behaviour hostage to another package's dependency tree. It also
would not finish the job: ``SpecifierSet`` can test whether a *given* version
satisfies a set, but exposes no intersection-emptiness operation, which is the
question actually being asked. The subset modelled below is small enough to
implement against the standard library and to test exhaustively.

The modelled subset, and what falls outside it
----------------------------------------------
Modelled: the operators ``==``, ``!=``, ``>=``, ``<=``, ``>``, ``<``, ``~=`` and
``===``, over versions consisting only of a release segment (``1``, ``1.4``,
``1.125.0``), plus ``.*`` prefix matching on ``==`` and ``!=``.

Outside it, and therefore UNDECIDABLE: pre-releases (``1.0rc1``), post-releases
(``1.0.post1``), dev releases (``1.0.dev0``), local versions (``1.0+abc``),
explicit epochs (``1!1.0``), any operator not in the list, and any text that is
not a specifier at all. ``===X`` is modelled only when ``X`` is itself a plain
release version; PEP 440 defines it as arbitrary string equality, so
``===some-build`` names a version this module cannot order.

UNDECIDABLE is refused by the caller, not assumed compatible. The asymmetry is
the same one that runs through workspace mode: refusing a workspace that would
have been fine costs the operator an error message they can act on, while
accepting one that is not fine produces a scan whose result is quietly wrong.

How emptiness is decided
------------------------
Both pins are converted to constraint lists and a witness is searched for: a
version satisfying every constraint on both sides. The search is over candidates
derived from the boundary versions mentioned by either pin -- each boundary
itself, one step above and below it, and the same boundary with a deeper release
segment appended. This is sufficient because every constraint's boundary lies in
that set, so a non-empty feasible region must contain either a boundary or a
point in an open interval between two consecutive ones, and an appended segment
lands inside such an interval.

Two candidates cover the unbounded ends: ``0`` for a region open below, and one
past the largest major seen for a region open above.

Failure modes and known limitations
-----------------------------------
* The witness search is not complete for boundaries nested more than two release
  segments deep. Pins of the form ``>1.0, <1.0.0.1`` have a feasible region
  (``1.0.0.0.1`` satisfies both) that the candidate set does not reach, and the
  verdict comes back INCOMPATIBLE. That errs toward refusal, which is the safe
  direction, and no real scanner pin has that shape.
* Ordering ignores everything but the release segment, which is exactly why
  anything carrying a pre/post/dev/local marker is rejected as UNDECIDABLE
  rather than compared on its release segment alone -- ``1.0rc1`` and ``1.0``
  have the same release segment and are different versions.
* Two textually identical pins are COMPATIBLE without being parsed at all. That
  is not just an optimisation: it means a project using an exotic pin is not
  refused merely because every project in the workspace inherited the same
  exotic pin from the same default.
* A verdict says nothing about whether the version exists on any index. A pin of
  ``==99.0.0`` is compatible with ``<100`` and will still fail to install.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from typing import List, Optional, Set, Tuple

#: A version reduced to its release segment, as a tuple of integers.
ReleaseTuple = Tuple[int, ...]

# Operators are matched longest-first so "==" is not read as "=" and ">=" is not
# read as ">".
_OPERATORS = ("===", "==", "!=", "~=", ">=", "<=", ">", "<")

_SPECIFIER_RE = re.compile(
    r"^\s*(===|==|!=|~=|>=|<=|>|<)\s*(\S.*?)\s*$",
)

# A version this module can order: release segment only, no epoch, no pre/post/
# dev release, no local version.
_RELEASE_RE = re.compile(r"^\d+(?:\.\d+)*$")

_PREFIX_SUFFIX = ".*"


class PinVerdict(str, Enum):
    """Whether two pins can both be satisfied.

    Three values rather than two: UNDECIDABLE means the pins fall outside the
    modelled subset, which the caller must treat as a refusal rather than
    resolve in either direction.
    """

    COMPATIBLE = "compatible"
    INCOMPATIBLE = "incompatible"
    UNDECIDABLE = "undecidable"


class _Op(str, Enum):
    """The modelled comparison kinds, after ``~=`` and ``===`` are expanded."""

    EQUAL = "=="
    NOT_EQUAL = "!="
    PREFIX_EQUAL = "==prefix"
    PREFIX_NOT_EQUAL = "!=prefix"
    GREATER_EQUAL = ">="
    GREATER = ">"
    LESS_EQUAL = "<="
    LESS = "<"


@dataclass(frozen=True)
class _Constraint:
    """One modelled constraint: a comparison kind and a release tuple."""

    op: _Op
    version: ReleaseTuple


def _pad(value: ReleaseTuple, length: int) -> ReleaseTuple:
    """Zero-extend *value* to *length* components.

    PEP 440 compares versions as if the shorter were zero-padded, so ``1.4`` and
    ``1.4.0`` are the same version. Every comparison here pads first.
    """
    return value + (0,) * (length - len(value))


def _compare(left: ReleaseTuple, right: ReleaseTuple) -> int:
    """Three-way comparison of two release tuples, zero-padded to equal length."""
    length = max(len(left), len(right))
    padded_left = _pad(left, length)
    padded_right = _pad(right, length)
    if padded_left < padded_right:
        return -1
    if padded_left > padded_right:
        return 1
    return 0


def _parse_release(text: str) -> Optional[ReleaseTuple]:
    """Parse a plain release version, or return None if it is outside the subset."""
    if not _RELEASE_RE.match(text):
        return None
    return tuple(int(part) for part in text.split("."))


def _expand_compatible_release(version: ReleaseTuple) -> Optional[List[_Constraint]]:
    """Expand ``~=X.Y[.Z]`` into ``>=X.Y[.Z]`` plus a prefix match.

    ``~=1.4.5`` means ``>=1.4.5, ==1.4.*``: the last component is free to move
    and everything above it is pinned. It needs at least two components, since
    ``~=1`` has no component to free and PEP 440 rejects it.
    """
    if len(version) < 2:
        return None
    return [
        _Constraint(_Op.GREATER_EQUAL, version),
        _Constraint(_Op.PREFIX_EQUAL, version[:-1]),
    ]


def _parse_specifier(specifier: str) -> Optional[List[_Constraint]]:
    """Parse one specifier into constraints, or None if outside the subset."""
    match = _SPECIFIER_RE.match(specifier)
    if match is None:
        return None
    operator, version_text = match.group(1), match.group(2)

    is_prefix = version_text.endswith(_PREFIX_SUFFIX)
    if is_prefix:
        if operator not in ("==", "!="):
            # ".*" is only meaningful for equality; anywhere else PEP 440
            # rejects it and so does this module.
            return None
        version_text = version_text[: -len(_PREFIX_SUFFIX)]

    version = _parse_release(version_text)
    if version is None:
        return None

    if operator == "==":
        return [_Constraint(_Op.PREFIX_EQUAL if is_prefix else _Op.EQUAL, version)]
    if operator == "!=":
        return [
            _Constraint(_Op.PREFIX_NOT_EQUAL if is_prefix else _Op.NOT_EQUAL, version)
        ]
    if operator == "===":
        # Arbitrary equality. Modelled only because the version text happened to
        # be an orderable release version; see the module docstring.
        return [_Constraint(_Op.EQUAL, version)]
    if operator == "~=":
        return _expand_compatible_release(version)
    if operator == ">=":
        return [_Constraint(_Op.GREATER_EQUAL, version)]
    if operator == ">":
        return [_Constraint(_Op.GREATER, version)]
    if operator == "<=":
        return [_Constraint(_Op.LESS_EQUAL, version)]
    if operator == "<":
        return [_Constraint(_Op.LESS, version)]
    return None  # pragma: no cover - _OPERATORS and the branches above agree


def _parse_pin(pin: str) -> Optional[List[_Constraint]]:
    """Parse a whole specifier set, or None if any part is outside the subset.

    An empty pin parses to an empty constraint list, which every version
    satisfies. That is the right reading: a project that sets ``tool_version``
    to an empty string has expressed no constraint.
    """
    constraints: List[_Constraint] = []
    for part in pin.split(","):
        if not part.strip():
            continue
        parsed = _parse_specifier(part)
        if parsed is None:
            return None
        constraints.extend(parsed)
    return constraints


def _matches_prefix(candidate: ReleaseTuple, prefix: ReleaseTuple) -> bool:
    """True when *candidate* starts with *prefix* once zero-padded.

    ``==1.4.*`` matches ``1.4`` as well as ``1.4.0`` and ``1.4.9``, because the
    shorter version is padded before the comparison.
    """
    padded = _pad(candidate, max(len(candidate), len(prefix)))
    return padded[: len(prefix)] == prefix


def _satisfies(candidate: ReleaseTuple, constraint: _Constraint) -> bool:
    """True when *candidate* satisfies one constraint."""
    if constraint.op is _Op.PREFIX_EQUAL:
        return _matches_prefix(candidate, constraint.version)
    if constraint.op is _Op.PREFIX_NOT_EQUAL:
        return not _matches_prefix(candidate, constraint.version)

    order = _compare(candidate, constraint.version)
    if constraint.op is _Op.EQUAL:
        return order == 0
    if constraint.op is _Op.NOT_EQUAL:
        return order != 0
    if constraint.op is _Op.GREATER_EQUAL:
        return order >= 0
    if constraint.op is _Op.GREATER:
        return order > 0
    if constraint.op is _Op.LESS_EQUAL:
        return order <= 0
    return order < 0  # _Op.LESS


def _candidates(constraints: List[_Constraint]) -> Set[ReleaseTuple]:
    """Build the witness search space from the boundaries the pins mention.

    For each boundary: the boundary itself, one step above and below it in its
    last component, and the boundary with a deeper release segment appended --
    the last of these is what reaches inside an open interval between two
    consecutive boundaries. A prefix boundary also contributes the start of the
    next prefix, which is where its range ends.

    ``0`` and one past the largest major cover regions open below and above.
    """
    # Seeded so a pair of unconstrained pins still has something to test.
    candidates: Set[ReleaseTuple] = {(0,), (1,)}

    boundaries = [constraint.version for constraint in constraints]
    for boundary in boundaries:
        candidates.add(boundary)
        candidates.add(boundary + (1,))
        candidates.add(boundary + (0, 1))
        candidates.add(boundary[:-1] + (boundary[-1] + 1,))
        if boundary[-1] > 0:
            candidates.add(boundary[:-1] + (boundary[-1] - 1,))

    largest_major = max((boundary[0] for boundary in boundaries), default=0)
    candidates.add((largest_major + 1,))
    return candidates


def _normalise(pin: str) -> Tuple[str, ...]:
    """Reduce a pin to a comparable form, ignoring whitespace and ordering.

    A specifier set is a conjunction, so the order of its parts carries no
    meaning: ``"<2.0.0,>=1.7.0"`` and ``">=1.7.0, <2.0.0"`` are the same pin and
    must not reach the solver as different ones.
    """
    return tuple(sorted(part.strip() for part in pin.split(",") if part.strip()))


def compare_pins(first: str, second: str) -> PinVerdict:
    """Decide whether *first* and *second* can both be satisfied.

    Args:
        first: A PEP 440 specifier set, e.g. ``">=1.125.0,<2.0.0"``. An empty
            string means no constraint.
        second: The other specifier set.

    Returns:
        ``COMPATIBLE`` when some version satisfies both, ``INCOMPATIBLE`` when
        the modelled search proves none does, and ``UNDECIDABLE`` when either pin
        falls outside the modelled subset. Callers must treat ``UNDECIDABLE`` as
        a refusal; see the module docstring for why it is not COMPATIBLE.

    The result does not depend on argument order.
    """
    if _normalise(first) == _normalise(second):
        # Also the path that keeps a shared exotic default from being refused.
        return PinVerdict.COMPATIBLE

    first_constraints = _parse_pin(first)
    second_constraints = _parse_pin(second)
    if first_constraints is None or second_constraints is None:
        return PinVerdict.UNDECIDABLE

    combined = first_constraints + second_constraints
    for candidate in _candidates(combined):
        if all(_satisfies(candidate, constraint) for constraint in combined):
            return PinVerdict.COMPATIBLE
    return PinVerdict.INCOMPATIBLE
