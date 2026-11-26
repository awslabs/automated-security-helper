# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Version-range filters for the runtime-compatibility facet: one interface,
the range grammar native to each runtime underneath.

``base/scanner_operational_facets.py`` declares rows that say "this range of a
tool's versions needs that range of its language runtime's versions". Both
sides are ranges, and the right way to write a range depends on the runtime:
Python tooling speaks PEP 440 specifier sets, Node tooling speaks node-semver
comparator ranges. A row is therefore written in the runtime's own grammar and
read through :func:`parse_range`, which hands back one :class:`RangePredicate`
whatever the grammar, so the installer and the gate never branch on runtime.

Grammars:

- ``python``: PEP 440, through ``packaging.specifiers.SpecifierSet``, the
  library this tree already uses for exactly this (``uv_tool_runner``,
  ``pre_installed_tool``, ``workspace/scanner_pins``).
- ``node``: node-semver comparator ranges. Declared in :data:`RANGE_GRAMMARS`
  and refused by :func:`parse_range` until a validator lands with its first
  consumer: no node-runtime tool declares a compatibility row today, the tree
  vendors no node-semver library, and ``npm_audit_scanner`` documents why
  ``packaging`` must not be handed semver bounds.

This module imports ``packaging`` and the standard library only. It is
imported by ``base``, so it must never import ``base``.
"""

from __future__ import annotations

import re
from typing import Callable, Dict, Protocol, Tuple

from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version


class RangeError(ValueError):
    """A range that the runtime's grammar does not accept, or has no grammar."""


class RangePredicate(Protocol):
    """A parsed version range, whatever grammar it was written in."""

    def contains(self, version: str) -> bool:
        """Whether *version* is inside the range."""
        ...

    def combined(self, other: "RangePredicate") -> "RangePredicate":
        """The range both this and *other* accept (a PIN merge)."""
        ...

    def as_request(self) -> str:
        """The range as one whitespace-free argv element for ``uv --python``."""
        ...


#: The grammar each runtime names, for error messages and the facets reference.
RANGE_GRAMMARS: Dict[str, str] = {
    "python": "PEP 440 specifier set (packaging.specifiers.SpecifierSet)",
    "node": "node-semver comparator ranges (validator not yet landed)",
}


class _Pep440Range:
    """A PEP 440 specifier set that remembers the order it was written in.

    ``str(SpecifierSet)`` sorts its clauses, which would change the argv a
    scanner has always passed to ``uv --python`` (``>=3.10,<3.14`` would print
    ``<3.14,>=3.10``). The clauses are kept as written and joined in order.
    """

    def __init__(self, clauses: Tuple[str, ...]) -> None:
        self._clauses = clauses
        self._specifiers = SpecifierSet(",".join(clauses))

    def contains(self, version: str) -> bool:
        try:
            parsed = Version(version.strip())
        except InvalidVersion as exc:
            raise RangeError(f"{version!r} is not a PEP 440 version") from exc
        # Prereleases count: a row that constrains 3.15 must constrain 3.15.0rc1.
        return self._specifiers.contains(parsed, prereleases=True)

    def combined(self, other: RangePredicate) -> RangePredicate:
        if not isinstance(other, _Pep440Range):
            raise RangeError("a PEP 440 range combines only with a PEP 440 range")
        merged = self._clauses + tuple(
            clause for clause in other._clauses if clause not in self._clauses
        )
        return _Pep440Range(merged)

    def as_request(self) -> str:
        return ",".join(self._clauses)


def _pep440_range(text: str) -> RangePredicate:
    clauses = tuple(part.strip() for part in text.split(",") if part.strip())
    # An empty text has no clauses, which ``SpecifierSet`` reads as the
    # universal range; every other clause must parse as written.
    try:
        return _Pep440Range(clauses)
    except InvalidSpecifier as exc:
        raise RangeError(f"{text!r} is not a PEP 440 specifier set: {exc}") from exc


_IMPLEMENTED_GRAMMARS: Dict[str, Callable[[str], RangePredicate]] = {
    "python": _pep440_range,
}


def parse_range(runtime: str, text: str) -> RangePredicate:
    """*text* as a range in *runtime*'s own grammar.

    ``""`` is the universal range ("every version"), stated by the declaration
    and never defaulted by the reader. A runtime with no implemented grammar,
    or one this module has never heard of, refuses with the registry's words.
    """
    if runtime not in RANGE_GRAMMARS:
        raise RangeError(
            f"no range grammar is declared for runtime {runtime!r}; declared: "
            + ", ".join(
                f"{name} ({grammar})" for name, grammar in RANGE_GRAMMARS.items()
            )
        )
    parser = _IMPLEMENTED_GRAMMARS.get(runtime)
    if parser is None:
        raise RangeError(
            f"the {runtime} range grammar is {RANGE_GRAMMARS[runtime]}; no "
            f"{runtime}-runtime tool declares a compatibility row today, so land "
            "its validator with the first consumer"
        )
    return parser(text)


_EXACT_PIN = re.compile(r"^\s*(?:===?\s*)?(?P<version>[0-9][^\s,*]*)\s*$")


def exact_version(constraint: str | None) -> str | None:
    """The one version *constraint* names, or None when it names a range.

    ``==3.4.11``, ``===3.4.11`` and a bare ``3.4.11`` name one version. A range
    (``>=3.2.0,<4.0.0``), a wildcard (``==3.4.*``) or None do not.
    """
    if not constraint:
        return None
    match = _EXACT_PIN.match(constraint)
    if match is None:
        return None
    version = match.group("version")
    try:
        Version(version)
    except InvalidVersion:
        return None
    return version
