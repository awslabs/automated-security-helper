# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Characterization of the SBOM component union against its sequential original.

What counts as "the same component" is decided by one pass over the second SBOM's
components in document order, each checked against the keys of the held SBOM and
of the earlier ones it kept. The union core runs as a join of two frames, with the
order-dependent remainder replayed in order; this module pins that the two give the
same verdict for every component, the same held packages in the log line for a
shared ``bom-ref``, and the same merged SBOM.

``_legacy_*`` below is the pass as it was before the move to frames, kept whole as
the reference. A red here means the union is not behavior-identical. The existing
tests in this directory state intent; this one states observed output, including
for text no polars string can hold (a lone surrogate in a ``bom-ref``, ``purl`` or
name) and for ``bom-ref`` values that equal a ``purl``.
"""

from __future__ import annotations

import random
from typing import Any

import pytest

from automated_security_helper.schemas.cyclonedx_bom_1_6_schema import (
    Component,
    CycloneDXReport,
)
from automated_security_helper.utils import sbom_merge
from automated_security_helper.utils.sbom_merge import (
    _NEW,
    _REPEAT,
    _SHARED_REF,
    _describe,
    _every_ref,
    _fingerprint,
    _new_ref,
    _note,
    _record,
    _renamed_dependencies,
    _united_dependencies,
    _verdict,
    _verdicts,
    _walk,
    merge_cyclonedx_reports,
)

pytestmark = pytest.mark.unit


def _legacy_verdicts(
    held: Any, incoming: Any
) -> tuple[list[str], dict[int, list[str]]]:
    """The verdict of each incoming component, one pass in document order."""
    keys: set[str] = set()
    held_by_ref: dict[str, list[Component]] = {}
    _record(list(_walk(held)), keys, held_by_ref)
    out: list[str] = []
    shared: dict[int, list[str]] = {}
    for n, component in enumerate(_walk(incoming)):
        verdict = _verdict(component, keys, held_by_ref)
        out.append(verdict)
        if verdict == _SHARED_REF and component.bom_ref is not None:
            shared[n] = sorted(
                _describe(h) for h in held_by_ref[component.bom_ref.root]
            )
        if verdict != _REPEAT:
            _note(component, keys, held_by_ref)
    return out, shared


def _legacy_merge(held: CycloneDXReport, incoming: CycloneDXReport) -> dict[str, Any]:
    """The merge with the pass above in the loop, as the module had it."""
    keys: set[str] = set()
    held_by_ref: dict[str, list[Component]] = {}
    _record(held.components or [], keys, held_by_ref)
    used = _every_ref(held, incoming)
    renames: dict[str, str] = {}
    kept_as_is: set[str] = set()

    def take(components: Any, kept: list[Component]) -> None:
        for component in components or []:
            verdict = _verdict(component, keys, held_by_ref)
            if verdict == _REPEAT:
                take(component.components, kept)
                continue
            copy = component.model_copy(deep=True)
            if verdict == _NEW and component.bom_ref is not None:
                kept_as_is.add(component.bom_ref.root)
            if (
                verdict == _SHARED_REF
                and component.bom_ref is not None
                and copy.bom_ref is not None
            ):
                old = component.bom_ref.root
                new = _new_ref(old, _fingerprint(component), used)
                used.add(new)
                copy.bom_ref.root = new
                if old not in kept_as_is:
                    renames.setdefault(old, new)
            _note(component, keys, held_by_ref)
            if component.components is not None:
                nested: list[Component] = []
                take(component.components, nested)
                copy.components = nested
            kept.append(copy)

    added: list[Component] = []
    take(incoming.components, added)
    result = held.model_copy(deep=True)
    if held.components is not None or incoming.components is not None:
        result.components = [*(result.components or []), *added]
    dependencies = _united_dependencies(
        held.dependencies, _renamed_dependencies(incoming.dependencies, renames)
    )
    if dependencies is not None:
        result.dependencies = dependencies
    dumped = result.model_dump(mode="python", by_alias=True)
    dumped.pop("serialNumber", None)
    return dumped


# "§" and "¤" stand for lone surrogates, which pydantic refuses to validate; the
# report is built with them and then given the surrogates (see ``_taint``).
_REFS = ["1", "2", "3", "pkg:a@1", "pkg:b@1", "pkg:c@1", "x§y", "é", "x¤y"]
_PURLS = [None, "", "pkg:a@1", "pkg:b@1", "pkg:c@1", "pkg:d@1", "pkg:s§@1"]
_NAMES = ["a", "b", "c", "n§"]
_VERSIONS = [None, "", "1", "2"]
_GROUPS = [None, "", "g"]
_TYPES = ["library", "file", "application"]


def _component(rng: random.Random, depth: int = 0) -> dict[str, Any]:
    component: dict[str, Any] = {
        "type": rng.choice(_TYPES),
        "name": rng.choice(_NAMES),
    }
    if rng.random() < 0.8:
        component["bom-ref"] = rng.choice(_REFS)
    purl = rng.choice(_PURLS)
    if purl is not None:
        component["purl"] = purl
    version = rng.choice(_VERSIONS)
    if version is not None:
        component["version"] = version
    group = rng.choice(_GROUPS)
    if group is not None:
        component["group"] = group
    if depth < 2 and rng.random() < 0.3:
        component["components"] = [
            _component(rng, depth + 1) for _ in range(rng.randint(0, 3))
        ]
    return component


def _surrogates(text: str) -> str:
    return text.replace("§", "\ud800").replace("¤", "\udfff")


def _taint(report: CycloneDXReport) -> CycloneDXReport:
    """Give the marked texts of *report* the lone surrogates they stand for."""
    for component in _walk(report.components):
        if component.bom_ref is not None:
            component.bom_ref.root = _surrogates(component.bom_ref.root)
        if component.purl:
            component.purl = _surrogates(component.purl)
        component.name = _surrogates(component.name)
    for dependency in report.dependencies or []:
        dependency.ref.root.root = _surrogates(dependency.ref.root.root)
        for ref in dependency.dependsOn or []:
            ref.root.root = _surrogates(ref.root.root)
    return report


def _report(rng: random.Random) -> CycloneDXReport:
    refs = [c for c in _REFS if c]
    return _taint(_build(rng, refs))


def _build(rng: random.Random, refs: list[str]) -> CycloneDXReport:
    return CycloneDXReport.model_validate(
        {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
            "version": 1,
            "components": [_component(rng) for _ in range(rng.randint(0, 8))],
            "dependencies": [
                {
                    "ref": rng.choice(refs),
                    "dependsOn": rng.sample(refs, rng.randint(0, 3)),
                }
                for _ in range(rng.randint(0, 3))
            ],
        }
    )


@pytest.mark.parametrize("seed", range(400))
def test_the_union_core_gives_each_component_the_verdict_the_pass_gave(seed: int):
    rng = random.Random(seed)
    held, incoming = _report(rng), _report(rng)
    assert _verdicts(held.components, incoming.components) == _legacy_verdicts(
        held.components, incoming.components
    )


@pytest.mark.parametrize("seed", range(400))
def test_the_merged_sbom_is_the_one_the_pass_made(seed: int):
    rng = random.Random(10_000 + seed)
    held, incoming = _report(rng), _report(rng)
    held_before = held.model_dump(mode="python", by_alias=True)
    # A new bom-ref is hashed from the purl or identity, which raises for a lone
    # surrogate; that is how the sequential original behaved too, and is kept.
    try:
        expected: Any = _legacy_merge(held, incoming)
    except UnicodeEncodeError:
        expected = UnicodeEncodeError
    try:
        merged = merge_cyclonedx_reports(held, incoming)
        assert merged is not None
        actual: Any = merged.model_dump(mode="python", by_alias=True)
        actual.pop("serialNumber", None)
    except UnicodeEncodeError:
        actual = UnicodeEncodeError
    assert actual == expected
    assert held.model_dump(mode="python", by_alias=True) == held_before


def test_a_shared_ref_is_told_apart_from_a_repeat_and_a_new_package():
    held = CycloneDXReport.model_validate(
        {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "version": 1,
            "components": [
                {"type": "library", "name": "a", "bom-ref": "1", "purl": "pkg:a@1"},
                {"type": "library", "name": "b", "bom-ref": "2"},
            ],
        }
    )
    incoming = CycloneDXReport.model_validate(
        {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "version": 1,
            "components": [
                {"type": "library", "name": "a", "bom-ref": "1", "purl": "pkg:a@1"},
                {"type": "library", "name": "z", "bom-ref": "1", "purl": "pkg:z@1"},
                {"type": "library", "name": "q", "bom-ref": "9"},
                {"type": "library", "name": "q2"},
            ],
        }
    )
    verdicts, shared = _verdicts(held.components, incoming.components)
    assert verdicts == [_REPEAT, _SHARED_REF, _NEW, _NEW]
    assert shared == {1: ["pkg:a@1"]}


def test_a_lone_surrogate_in_a_key_is_a_repeat_of_itself():
    ref = "pkg:s§@1"
    body = {"type": "library", "name": "s§", "bom-ref": ref, "purl": ref}
    held = _taint(
        CycloneDXReport.model_validate(
            {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": [body]}
        )
    )
    incoming = _taint(
        CycloneDXReport.model_validate(
            {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": [body]}
        )
    )
    assert _verdicts(held.components, incoming.components)[0] == [_REPEAT]


def test_the_module_still_exports_what_it_did():
    assert set(sbom_merge.__all__) == {
        "component_key",
        "merge_cyclonedx_reports",
        "sbom_is_empty",
    }
