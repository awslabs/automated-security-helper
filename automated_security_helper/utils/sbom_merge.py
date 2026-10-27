# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Combine two CycloneDX SBOMs of one scan into the one the scan reports.

A scan can produce more than one SBOM. syft runs on the source tree and, when a
converter wrote files, on the converted tree, and each run gives a report. The
scan result holds one, so :func:`merge_cyclonedx_reports` is what a second report
is handed to: it returns the SBOM the scan keeps.

The rules, which a reader of ``ash.cdx.json`` can rely on:

* The header (``version``, ``specVersion`` and ``metadata``) is the first SBOM's.
  In a scan that is the source tree's, the subject the user named.
  ``metadata.component`` describes a single subject
  (``reporters/cyclonedx_reporter.py``), so the second document's does not replace
  it.
* The ``serialNumber`` is the first SBOM's only when the merge adds nothing. A
  merge that adds a component, a dependency or a ref to a dependency entry makes a
  document that is no longer the first one, so it gets a new ``urn:uuid`` serial
  number. ``version`` stays as it is: a new serial number starts a new document,
  and the first document's version is the only one the merge has.
* ``components`` hold every component of both. A component the second SBOM
  repeats is listed once, and the first copy is kept whole. That holds whether the
  first copy is a top-level component of the first SBOM, nested inside one of its
  components, or an earlier component of the second SBOM. Its key is its
  ``bom-ref`` or, when it has none, its ``purl``. A ``bom-ref`` is unique within
  one BOM and promises nothing across two, so a shared ``bom-ref`` is a repeat only
  when the two are the same package. With a ``purl`` on both, that is the same
  ``purl``. When either has no ``purl`` (generators that number their refs write
  none for files, operating systems and vendored code), it is the same ``type``,
  ``group``, ``name`` and ``version``. Otherwise the two are different packages:
  both stay, and the second one is given a new ``bom-ref`` (its old one, a hyphen
  and a short hash of its ``purl``, or of its type, group, name and version when it
  has no ``purl``) that no component or dependency entry of either SBOM uses. Every
  reference to the old ``bom-ref`` in the second SBOM's ``dependencies``
  (``dependsOn`` and ``provides``) follows it. One merge logs one warning however
  many components it re-references: the count and the first few shared
  ``bom-ref`` values. Each re-referenced component has a debug line of its own.
  A component with neither key is never matched, so both copies stay.
* A component nested inside a second-SBOM component gets the same check as a
  top-level one. A nested component that repeats a package is left out of the
  copy of its parent, one that only shares a ``bom-ref`` gets a new one, and a new
  one is kept. A second-SBOM component dropped as a repeat is not copied, but the
  components nested in it are checked in its place: the ones the first SBOM does
  not hold are added to the list the dropped component was in, so a package is not
  lost with the component that held it.
* ``dependencies`` are united by ``ref``. When a ref is in both, its ``dependsOn``
  and its ``provides`` are each the union of the two lists, first-seen order.
* A report with no header and no components is the empty default
  (``AshAggregatedResults.cyclonedx`` starts as one). It never wins over a report
  that holds something, and it is replaced by the first report that arrives.

Limits:

* One package that two runs name with different ``bom-ref`` values is listed
  twice. Matching ``purl`` across different ``bom-ref`` values would also mean
  rewriting every reference to the dropped one (``dependencies``,
  ``vulnerabilities``, ``annotations`` and ``compositions``), and nothing here
  shows that a package keeps its ``bom-ref`` from one run to the next. Listing a
  package twice is visible and harmless; merging two packages is not. That
  includes a package that the second SBOM lists under a ``bom-ref`` the first
  gives to a different package: the first SBOM holds it under one ref, the merge
  adds the second copy under a new ref, and each further SBOM that does the same
  adds another copy.
* Only ``components`` and ``dependencies`` are combined. Every other list
  (``services``, ``externalReferences``, ``compositions``, ``vulnerabilities``,
  ``annotations``, ``formulation``, ``declarations``, ``definitions``,
  ``properties`` and ``signature``) comes from the first SBOM, and the second
  one's is not carried. syft writes only a header, components and dependencies,
  so nothing it produces is lost. A scanner that writes more is where this needs
  to grow.
* When a ``bom-ref`` is re-assigned, only references from the second SBOM's
  ``dependencies`` follow it, because no other list of the second SBOM is carried.

The result is a new report that shares no object with either argument. The scan
hands this function the scanner's own report object (``utils/undecodable_text.py``
returns a model itself when nothing in it needs a change), which the scan goes on
reading, and stores the result in its results, which later steps read and change.
So neither argument is changed, and every part of the result that comes from an
argument is a deep copy of it: the header, the lists that are not combined, the
components, the dependency entries and their refs. When one side is missing or
empty, the result is a deep copy of the other.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from collections.abc import Iterable, Iterator
from typing import Any

from automated_security_helper.schemas.cyclonedx_bom_1_6_schema import (
    Component,
    CycloneDXReport,
    Dependency,
    RefLinkType,
)
from automated_security_helper.utils.log import ASH_LOGGER

__all__ = ["component_key", "merge_cyclonedx_reports", "sbom_is_empty"]

#: The two lists of refs a dependency holds, united field by field.
_REF_LISTS = ("dependsOn", "provides")

#: What the merge does with a component of the second SBOM.
_NEW = "new"  # no held component has its key: it is added
_REPEAT = "repeat"  # the held SBOM already lists this package: it is dropped
_SHARED_REF = "shared-ref"  # a held component has its bom-ref and is another package

#: How many re-referenced bom-refs the summary warning of a merge names.
_REFS_NAMED = 3


def sbom_is_empty(report: CycloneDXReport) -> bool:
    """Whether *report* holds nothing: no header, no serial number, no component.

    The test the CycloneDX reporter makes to tell the default report from an SBOM
    a scanner produced (``reporters/cyclonedx_reporter.py``): every SBOM a scanner
    writes has metadata or a serial number.
    """
    return (
        report.metadata is None
        and report.serialNumber is None
        and not report.components
    )


def component_key(component: Component) -> str | None:
    """The key two components share when they are one: ``bom-ref``, else ``purl``."""
    if component.bom_ref is not None:
        return component.bom_ref.root
    return component.purl or None


def _walk(components: Iterable[Component] | None) -> Iterator[Component]:
    """Every component of *components*, the ones nested inside a component included."""
    for component in components or []:
        yield component
        yield from _walk(component.components)


def _identity(component: Component) -> tuple[str, str | None, str, str | None]:
    """What names a package that has no ``purl``: type, group, name and version."""
    return (
        component.type.value,
        component.group or None,
        component.name,
        component.version.root if component.version is not None else None,
    )


def _fingerprint(component: Component) -> str:
    """What a new ``bom-ref`` is made from: the ``purl``, else the identity."""
    return component.purl or json.dumps(_identity(component))


def _describe(component: Component) -> str:
    """*component* for a log line: its ``purl``, else its name and version."""
    if component.purl:
        return component.purl
    version = component.version.root if component.version is not None else None
    return f"{component.name} {version}" if version else component.name


def _same_package(held: Component, incoming: Component) -> bool:
    """Whether two components that share a ``bom-ref`` are one package.

    Two components with a ``purl`` are one package when the ``purl`` is the same.
    When either has none, they are one when their type, group, name and version
    are all the same.
    """
    if held.purl and incoming.purl:
        return held.purl == incoming.purl
    return _identity(held) == _identity(incoming)


def _note(
    component: Component, keys: set[str], held_by_ref: dict[str, list[Component]]
) -> None:
    """Note the key of *component*, not the ones nested in it, as taken.

    *keys* gets the component's key, and *held_by_ref* its ``bom-ref`` with the
    components that hold it.
    """
    key = component_key(component)
    if key is not None:
        keys.add(key)
    if component.bom_ref is not None:
        held_by_ref.setdefault(component.bom_ref.root, []).append(component)


def _record(
    components: Iterable[Component],
    keys: set[str],
    held_by_ref: dict[str, list[Component]],
) -> None:
    """Note the keys of *components*, and of those nested in them, as taken."""
    for component in _walk(components):
        _note(component, keys, held_by_ref)


def _verdict(
    component: Component, keys: set[str], held_by_ref: dict[str, list[Component]]
) -> str:
    """What the merge does with *component*, given the keys already taken."""
    key = component_key(component)
    if key is None or key not in keys:
        return _NEW
    if component.bom_ref is None:
        return _REPEAT
    holders = held_by_ref.get(component.bom_ref.root, [])
    if not holders or any(_same_package(held, component) for held in holders):
        return _REPEAT
    return _SHARED_REF


def _every_ref(*reports: CycloneDXReport) -> set[str]:
    """Each ``bom-ref`` and each dependency ref the reports use, nested ones included."""
    used: set[str] = set()
    for report in reports:
        for component in _walk(report.components):
            if component.bom_ref is not None:
                used.add(component.bom_ref.root)
        for dependency in report.dependencies or []:
            used.add(dependency.ref.root.root)
            for field in _REF_LISTS:
                used.update(ref.root.root for ref in getattr(dependency, field) or [])
    return used


def _new_ref(old: str, fingerprint: str, used: set[str]) -> str:
    """A ref made from *old* and *fingerprint* that is not in *used*."""
    base = f"{old}-{hashlib.sha256(fingerprint.encode()).hexdigest()[:8]}"
    candidate, count = base, 1
    while candidate in used:
        count += 1
        candidate = f"{base}-{count}"
    return candidate


def _rename(ref: RefLinkType, renames: dict[str, str]) -> None:
    new = renames.get(ref.root.root)
    if new is not None:
        ref.root.root = new


def _renamed_dependencies(
    dependencies: list[Dependency] | None, renames: dict[str, str]
) -> list[Dependency] | None:
    """Copies of *dependencies* with every ref in *renames* replaced by its new one."""
    if dependencies is None or not renames:
        return dependencies
    renamed: list[Dependency] = []
    for dependency in dependencies:
        copy = dependency.model_copy(deep=True)
        _rename(copy.ref, renames)
        for field in _REF_LISTS:
            for ref in getattr(copy, field) or []:
                _rename(ref, renames)
        renamed.append(copy)
    return renamed


def _dumped(dependencies: list[Dependency] | None) -> list[dict[str, Any]]:
    """*dependencies* as plain data, for telling whether the merge changed them."""
    return [
        dependency.model_dump(mode="json", by_alias=True)
        for dependency in dependencies or []
    ]


def _united_refs(
    first: list[RefLinkType] | None, second: list[RefLinkType] | None
) -> list[RefLinkType] | None:
    """Copies of the refs of both lists, each once, first-seen order; None if unset."""
    if first is None and second is None:
        return None
    united: list[RefLinkType] = []
    seen: set[str] = set()
    for ref in [*(first or []), *(second or [])]:
        if ref.root.root not in seen:
            seen.add(ref.root.root)
            united.append(ref.model_copy(deep=True))
    return united


def _united_dependencies(
    first: list[Dependency] | None, second: list[Dependency] | None
) -> list[Dependency] | None:
    """Copies of the dependencies of both, one per ref; None when neither is set."""
    if first is None and second is None:
        return None
    united: dict[str, Dependency] = {}
    for dependency in [*(first or []), *(second or [])]:
        known = united.get(dependency.ref.root.root)
        if known is None:
            united[dependency.ref.root.root] = dependency.model_copy(deep=True)
            continue
        update: dict[str, Any] = {}
        for field in _REF_LISTS:
            refs = _united_refs(getattr(known, field), getattr(dependency, field))
            if refs is not None:
                update[field] = refs
        united[dependency.ref.root.root] = known.model_copy(update=update)
    return list(united.values())


def _warn_re_referenced(refs: list[str]) -> None:
    """One warning for a merge: how many components got a new ``bom-ref``, and which.

    *refs* holds the old ``bom-ref`` of each. A generator that numbers its refs
    makes most components of two SBOMs share one, so a warning for each would
    flood the scan log; each has a debug line of its own.
    """
    if not refs:
        return
    shown = list(dict.fromkeys(refs))[:_REFS_NAMED]
    more = len(set(refs)) - len(shown)
    named = ", ".join(repr(ref) for ref in shown) + (
        f" and {more} more" if more > 0 else ""
    )
    subject = "component shares" if len(refs) == 1 else "components share"
    ASH_LOGGER.warning(
        f"SBOM merge: {len(refs)} {subject} a bom-ref with a different package "
        f"(bom-ref {named}); keeping both, the first under its own bom-ref and "
        f"the second under a new one. Each is listed at debug level."
    )


class _Walk:
    """What one merge knows while it goes through the second report's components."""

    def __init__(
        self,
        keys: set[str],
        held_by_ref: dict[str, list[Component]],
        used_refs: set[str],
    ) -> None:
        #: The keys already taken, and each ``bom-ref`` with the components holding it.
        self.keys = keys
        self.held_by_ref = held_by_ref
        #: Every ref either SBOM uses, so a new one never collides.
        self.used_refs = used_refs
        #: The old ``bom-ref`` of each re-referenced component, and its new one.
        self.renames: dict[str, str] = {}
        #: The refs of second-SBOM components kept under the ref they came with.
        self.kept_as_is: set[str] = set()
        #: The old ``bom-ref`` of each component given a new one, in order.
        self.re_referenced: list[str] = []

    def take(
        self, components: Iterable[Component] | None, kept: list[Component]
    ) -> None:
        """Add to *kept* a copy of each of *components* that the merge keeps.

        A component nested in a kept one gets the same check and is kept in the
        copy's own list. A component dropped as a repeat is not copied, but the
        components nested in it are checked in its place, so *kept* gets the ones
        the held SBOM lacks.
        """
        for component in components or []:
            verdict = _verdict(component, self.keys, self.held_by_ref)
            if verdict == _REPEAT:
                self.take(component.components, kept)
                continue
            copy = component.model_copy(deep=True)
            if verdict == _NEW and component.bom_ref is not None:
                self.kept_as_is.add(component.bom_ref.root)
            # Only a component that has a bom-ref can share one, and the copy has the
            # same one; the checks let the type checker see that.
            if (
                verdict == _SHARED_REF
                and component.bom_ref is not None
                and copy.bom_ref is not None
            ):
                old = component.bom_ref.root
                new = _new_ref(old, _fingerprint(component), self.used_refs)
                self.used_refs.add(new)
                copy.bom_ref.root = new
                if old not in self.kept_as_is:
                    self.renames.setdefault(old, new)
                self.re_referenced.append(old)
                ASH_LOGGER.debug(
                    f"SBOM merge: bom-ref {old!r} names more than one package "
                    f"({_describe(component)!r} and "
                    f"{sorted(_describe(h) for h in self.held_by_ref[old])!r}); "
                    f"keeping both, the first under {old!r} and the second under "
                    f"{new!r}"
                )
            # Under the key it came with, so a later copy of it here is a repeat.
            _note(component, self.keys, self.held_by_ref)
            if component.components is not None:
                nested: list[Component] = []
                self.take(component.components, nested)
                copy.components = nested
            kept.append(copy)


def merge_cyclonedx_reports(
    held: CycloneDXReport | None, incoming: CycloneDXReport | None
) -> CycloneDXReport | None:
    """The SBOM a scan keeps once *incoming* arrives while it holds *held*.

    *held* is what the scan has so far, the empty default included. The rules are
    in the module docstring. The result is never an argument and holds no object
    an argument holds: when one side adds nothing it is a deep copy of the other,
    and otherwise it is built from deep copies.
    """
    if incoming is None:
        return None if held is None else held.model_copy(deep=True)
    if held is None or sbom_is_empty(held):
        return incoming.model_copy(deep=True)
    if sbom_is_empty(incoming):
        return held.model_copy(deep=True)

    keys: set[str] = set()
    held_by_ref: dict[str, list[Component]] = {}
    _record(held.components or [], keys, held_by_ref)
    walk = _Walk(keys, held_by_ref, _every_ref(held, incoming))
    added: list[Component] = []
    walk.take(incoming.components, added)
    _warn_re_referenced(walk.re_referenced)
    result = held.model_copy(deep=True)
    if held.components is not None or incoming.components is not None:
        result.components = [*(result.components or []), *added]
    dependencies = _united_dependencies(
        held.dependencies, _renamed_dependencies(incoming.dependencies, walk.renames)
    )
    if dependencies is not None:
        result.dependencies = dependencies
    if added or _dumped(held.dependencies) != _dumped(dependencies):
        result.serialNumber = f"urn:uuid:{uuid.uuid4()}"
    return result
