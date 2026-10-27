# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``ash merge`` unites the SBOMs of every shard instead of keeping the first one's.

Why this exists
---------------
A sharded scan splits the scanners across shards, and each shard's report holds the
CycloneDX SBOM of the SBOM-producing scanners it owned. ``merge_shard_results``
adopted a shard's SBOM only while the merged report listed no component, so once one
shard had contributed components every later shard's SBOM was dropped. Two SBOM
scanners on two shards left ``ash.cdx.json`` (and the SPDX and GitLab reports built
from it) with one scanner's packages only.

What the cells pin
------------------
The shards' SBOMs are united in shard order by the rule a single scan uses for its
own (``utils/sbom_merge.py``). Every component of every shard is listed, and a
component a later shard repeats is listed once. A component's key is its
``bom-ref`` or, without one, its ``purl``; the first copy is kept, a component with
neither is never matched, and one package under two different ``bom-ref`` values is
listed twice. ``dependencies`` are united by ``ref``. The ``version``, the
``metadata`` and every other top-level list are the lowest-indexed SBOM's, whatever
order ``--results`` lists the shards in. The ``serialNumber`` is that SBOM's only
while the merge adds nothing: a merge that adds a component or a dependency is a new
document and carries its own ``urn:uuid`` serial number. A shard with no SBOM (the
empty default, or null), or whose SBOM lists nothing, hides nothing. The
SBOM of the only shard that has one is kept as it was, and the merged SBOM shares no
object with a shard's report.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest

from automated_security_helper.cli.merge import merge_shard_results
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.schemas.cyclonedx_bom_1_6_schema import (
    CycloneDXReport,
)
from tests.unit.cli.test_merge import as_loaded, build_shards

REQUESTS = {"name": "requests", "version": "2.19.1", "purl": "pkg:pypi/requests@2.19.1"}
FLASK = {"name": "flask", "version": "3.0.0", "purl": "pkg:pypi/flask@3.0.0"}
DJANGO = {"name": "django", "version": "5.0.0", "purl": "pkg:pypi/django@5.0.0"}

FIRST_SERIAL = f"urn:uuid:{uuid.UUID(int=1)}"
SECOND_SERIAL = f"urn:uuid:{uuid.UUID(int=2)}"
FIRST_VERSION = 7
SECOND_VERSION = 9

#: The order ``--results`` lists the shards in. The merge sorts by shard index, so
#: both must give one report.
ORDERS = ["forward", "reversed"]
IDENTITIES = [True, False]
IDENTITY_IDS = ["bom-ref", "purl-only"]


def _component(spec: dict[str, str], *, bom_ref: bool) -> dict[str, Any]:
    component: dict[str, Any] = {"type": "library", **spec}
    if bom_ref:
        component["bom-ref"] = spec["purl"]
    return component


def _dependency(ref: str, *depends_on: str) -> dict[str, Any]:
    entry: dict[str, Any] = {"ref": ref}
    if depends_on:
        entry["dependsOn"] = list(depends_on)
    return entry


def _sbom(
    *components: dict[str, Any],
    serial: str | None = None,
    version: int | None = None,
    subject: str | None = None,
    dependencies: list[dict[str, Any]] | None = None,
    properties: list[dict[str, str]] | None = None,
) -> CycloneDXReport:
    document: dict[str, Any] = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "components": list(components),
    }
    if serial is not None:
        document["serialNumber"] = serial
    if version is not None:
        document["version"] = version
    if subject is not None:
        document["metadata"] = {"component": {"type": "file", "name": subject}}
    if dependencies is not None:
        document["dependencies"] = dependencies
    if properties is not None:
        document["properties"] = properties
    return CycloneDXReport.model_validate(document)


def _shards(
    count: int, sboms: dict[int, CycloneDXReport]
) -> list[AshAggregatedResults]:
    """*count* shards of one scan; the shards named in *sboms* carry that SBOM.

    The others keep the empty default report, which is what a shard that owned no
    SBOM scanner writes.
    """
    shards = build_shards(count)
    for index, report in sboms.items():
        shards[index].cyclonedx = report
    return shards


def _merge(
    shards: list[AshAggregatedResults], order: str = "forward"
) -> CycloneDXReport:
    listed = shards if order == "forward" else list(reversed(shards))
    return merge_shard_results(as_loaded(listed)).cyclonedx


def _names(report: CycloneDXReport) -> list[str]:
    return sorted(component.name for component in report.components or [])


def _edges(report: CycloneDXReport) -> dict[str, list[str]]:
    return {
        dependency.ref.root.root: sorted(
            ref.root.root for ref in dependency.dependsOn or []
        )
        for dependency in report.dependencies or []
    }


def _dump(report: CycloneDXReport) -> dict[str, Any]:
    return report.model_dump(by_alias=True, exclude_unset=True, mode="json")


def _objects(report: CycloneDXReport) -> set[int]:
    """The identity of every component and dependency the report holds."""
    return {
        id(item) for item in [*(report.components or []), *(report.dependencies or [])]
    }


@pytest.mark.parametrize("bom_ref", IDENTITIES, ids=IDENTITY_IDS)
def test_every_shards_components_are_listed(bom_ref):
    shards = _shards(
        2,
        {
            0: _sbom(
                _component(REQUESTS, bom_ref=bom_ref),
                _component(FLASK, bom_ref=bom_ref),
            ),
            1: _sbom(_component(DJANGO, bom_ref=bom_ref)),
        },
    )

    assert _names(_merge(shards)) == ["django", "flask", "requests"]


@pytest.mark.parametrize("bom_ref", IDENTITIES, ids=IDENTITY_IDS)
def test_a_component_two_shards_carry_is_listed_once(bom_ref):
    shards = _shards(
        2,
        {
            0: _sbom(
                _component(REQUESTS, bom_ref=bom_ref),
                _component(FLASK, bom_ref=bom_ref),
            ),
            1: _sbom(
                _component(REQUESTS, bom_ref=bom_ref),
                _component(DJANGO, bom_ref=bom_ref),
            ),
        },
    )

    assert _names(_merge(shards)) == ["django", "flask", "requests"]


def test_a_shard_with_no_sbom_between_two_that_have_one_hides_neither():
    shards = _shards(
        3,
        {
            0: _sbom(_component(REQUESTS, bom_ref=True)),
            2: _sbom(_component(DJANGO, bom_ref=True)),
        },
    )

    assert _names(_merge(shards)) == ["django", "requests"]


def _shards_with_a_null_sbom(null_at: int) -> list[AshAggregatedResults]:
    """Three shards; two hold an SBOM, and the one at *null_at* holds None.

    ``AshAggregatedResults.cyclonedx`` is ``CycloneDXReport | None``
    (models/asharp_model.py), and both reporters that read it test for None, so a
    results file written with ``"cyclonedx": null`` is a shape the code accepts. A
    file that leaves the key out reads back as the empty default instead, which
    the cell above covers.
    """
    first, second = [index for index in range(3) if index != null_at]
    shards = _shards(
        3,
        {
            first: _sbom(_component(REQUESTS, bom_ref=True)),
            second: _sbom(_component(DJANGO, bom_ref=True)),
        },
    )
    shards[null_at].cyclonedx = None
    return shards


@pytest.mark.parametrize(
    "null_at", [0, 1, 2], ids=["null-first", "null-middle", "null-last"]
)
def test_a_shard_with_a_null_sbom_hides_no_other_shards_components(null_at):
    shards = _shards_with_a_null_sbom(null_at)

    assert _names(_merge(shards)) == ["django", "requests"]


@pytest.mark.parametrize(
    "holder", [0, 1], ids=["null-last-of-two", "null-first-of-two"]
)
def test_the_only_sbom_beside_a_null_one_is_kept_as_it_was(holder):
    report = _sbom(
        _component(REQUESTS, bom_ref=True),
        serial=FIRST_SERIAL,
        subject="the only SBOM",
    )
    expected = _dump(report)
    shards = _shards(2, {holder: report})
    shards[1 - holder].cyclonedx = None

    assert _dump(_merge(shards)) == expected


def test_shards_that_all_hold_a_null_sbom_merge_to_none():
    shards = _shards(2, {})
    for shard in shards:
        shard.cyclonedx = None

    assert _merge(shards) is None


def test_components_with_neither_bom_ref_nor_purl_are_never_matched():
    keyless = {"type": "library", "name": "vendored", "version": "1.0"}
    shards = _shards(2, {0: _sbom(dict(keyless)), 1: _sbom(dict(keyless))})

    assert _names(_merge(shards)) == ["vendored", "vendored"]


def test_one_package_under_two_bom_refs_is_listed_twice():
    first = {**_component(REQUESTS, bom_ref=False), "bom-ref": "first-shard-ref"}
    second = {**_component(REQUESTS, bom_ref=False), "bom-ref": "second-shard-ref"}
    shards = _shards(2, {0: _sbom(first), 1: _sbom(second)})

    assert _names(_merge(shards)) == ["requests", "requests"]


@pytest.mark.parametrize("order", ORDERS)
def test_dependencies_are_united_by_ref(order):
    shards = _shards(
        2,
        {
            0: _sbom(
                _component(REQUESTS, bom_ref=True),
                _component(FLASK, bom_ref=True),
                dependencies=[
                    _dependency(REQUESTS["purl"], FLASK["purl"]),
                    _dependency(FLASK["purl"]),
                ],
            ),
            1: _sbom(
                _component(REQUESTS, bom_ref=True),
                _component(DJANGO, bom_ref=True),
                dependencies=[
                    _dependency(REQUESTS["purl"], DJANGO["purl"]),
                    _dependency(DJANGO["purl"]),
                ],
            ),
        },
    )

    assert _edges(_merge(shards, order)) == {
        REQUESTS["purl"]: sorted([FLASK["purl"], DJANGO["purl"]]),
        FLASK["purl"]: [],
        DJANGO["purl"]: [],
    }


@pytest.mark.parametrize("order", ORDERS)
def test_the_version_and_metadata_are_the_lowest_indexed_shards(order):
    shards = _shards(
        2,
        {
            0: _sbom(
                _component(REQUESTS, bom_ref=True),
                serial=FIRST_SERIAL,
                version=FIRST_VERSION,
                subject="first shard",
            ),
            1: _sbom(
                _component(DJANGO, bom_ref=True),
                serial=SECOND_SERIAL,
                version=SECOND_VERSION,
                subject="second shard",
            ),
        },
    )

    merged = _merge(shards, order)

    assert merged.version == FIRST_VERSION
    assert merged.metadata.component.name == "first shard"


@pytest.mark.parametrize("order", ORDERS)
def test_a_merge_that_adds_a_component_carries_its_own_serial_number(order):
    shards = _shards(
        2,
        {
            0: _sbom(
                _component(REQUESTS, bom_ref=True),
                serial=FIRST_SERIAL,
                version=FIRST_VERSION,
            ),
            1: _sbom(
                _component(DJANGO, bom_ref=True),
                serial=SECOND_SERIAL,
                version=SECOND_VERSION,
            ),
        },
    )

    serial = _merge(shards, order).serialNumber

    assert serial not in (FIRST_SERIAL, SECOND_SERIAL)
    assert serial.startswith("urn:uuid:")
    assert serial == f"urn:uuid:{uuid.UUID(serial.removeprefix('urn:uuid:'))}"


@pytest.mark.parametrize("order", ORDERS)
def test_a_merge_that_adds_nothing_keeps_the_lowest_indexed_serial_number(order):
    shards = _shards(
        2,
        {
            0: _sbom(
                _component(REQUESTS, bom_ref=True),
                serial=FIRST_SERIAL,
                version=FIRST_VERSION,
            ),
            1: _sbom(
                _component(REQUESTS, bom_ref=True),
                serial=SECOND_SERIAL,
                version=SECOND_VERSION,
            ),
        },
    )

    merged = _merge(shards, order)

    assert _names(merged) == ["requests"]
    assert merged.serialNumber == FIRST_SERIAL
    assert merged.version == FIRST_VERSION


def test_the_other_top_level_lists_come_from_the_lowest_indexed_shard():
    shards = _shards(
        2,
        {
            0: _sbom(_component(REQUESTS, bom_ref=True)),
            1: _sbom(
                _component(DJANGO, bom_ref=True),
                properties=[{"name": "second-shard-only", "value": "1"}],
            ),
        },
    )

    assert _merge(shards).properties is None


@pytest.mark.parametrize("holder", [0, 1, 2], ids=["first", "middle", "last"])
def test_the_only_shards_sbom_is_kept_as_it_was(holder):
    report = _sbom(
        _component(REQUESTS, bom_ref=True),
        _component(FLASK, bom_ref=False),
        serial=FIRST_SERIAL,
        subject="the only SBOM",
        dependencies=[_dependency(REQUESTS["purl"], FLASK["purl"])],
    )
    expected = _dump(report)
    shards = _shards(3, {holder: report})

    assert _dump(_merge(shards)) == expected


@pytest.mark.parametrize(
    "empty_first", [True, False], ids=["header-first", "header-last"]
)
def test_an_sbom_that_lists_nothing_hides_no_shards_components(empty_first):
    empty = _sbom(serial=FIRST_SERIAL, subject="nothing to catalog")
    listing = _sbom(_component(DJANGO, bom_ref=True))
    shards = _shards(
        2, {0: empty, 1: listing} if empty_first else {0: listing, 1: empty}
    )

    assert _names(_merge(shards)) == ["django"]


@pytest.mark.parametrize("order", ORDERS)
def test_the_merge_changes_no_shard(order):
    shards = _shards(
        2,
        {
            0: _sbom(
                _component(REQUESTS, bom_ref=True),
                serial=FIRST_SERIAL,
                dependencies=[_dependency(REQUESTS["purl"], FLASK["purl"])],
            ),
            1: _sbom(
                _component(REQUESTS, bom_ref=True),
                _component(DJANGO, bom_ref=True),
                serial=SECOND_SERIAL,
                dependencies=[_dependency(REQUESTS["purl"], DJANGO["purl"])],
            ),
        },
    )
    before = [shard.model_dump_json() for shard in shards]

    _merge(shards, order)

    assert [shard.model_dump_json() for shard in shards] == before


@pytest.mark.parametrize(
    ("sboms", "expected"),
    [
        pytest.param(
            {
                1: _sbom(
                    _component(REQUESTS, bom_ref=True),
                    _component(DJANGO, bom_ref=True),
                    dependencies=[_dependency(REQUESTS["purl"], DJANGO["purl"])],
                )
            },
            ["django", "requests"],
            id="adopted-whole",
        ),
        pytest.param(
            {
                0: _sbom(
                    _component(REQUESTS, bom_ref=True),
                    _component(FLASK, bom_ref=True),
                    dependencies=[_dependency(REQUESTS["purl"], FLASK["purl"])],
                ),
                1: _sbom(
                    _component(REQUESTS, bom_ref=True),
                    _component(DJANGO, bom_ref=True),
                    dependencies=[_dependency(REQUESTS["purl"], DJANGO["purl"])],
                ),
            },
            ["django", "flask", "requests"],
            id="united",
        ),
    ],
)
def test_the_merged_sbom_shares_no_object_with_a_shard(sboms, expected):
    shards = _shards(2, sboms)
    # Read off the shards themselves, so the check holds whatever assignment does
    # with the report it is given.
    held_by_shards = set().union(*(_objects(shard.cyclonedx) for shard in shards))

    merged = _merge(shards)

    assert _names(merged) == expected
    assert not _objects(merged) & held_by_shards
