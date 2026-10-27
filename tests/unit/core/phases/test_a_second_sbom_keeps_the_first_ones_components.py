# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A second CycloneDX result in one run adds to the SBOM instead of replacing it.

Why this exists
---------------
A scan reads the source tree and, when a converter wrote files, the converted tree
too. syft runs on both, so one run hands ``ScanResultProcessor.process_container``
two ``CycloneDXReport`` results. It assigned each one to
``aggregated_results.cyclonedx``, so the later result replaced the earlier: the
SBOM listed only the components of whichever target arrived last, and a converted
tree with nothing to catalog left it empty.

What the cells pin
------------------
Every component of either result is listed, whichever target arrives first, and a
component both results carry is listed once. A component's key is its ``bom-ref``
or, without one, its ``purl``. The first copy is kept, a component with neither is
never matched, and one package under two different ``bom-ref`` values is listed
twice. The header (``version`` and ``metadata``) is the first result's, a merge
that adds gives the SBOM a serial number of its own (the cells for it are in
``tests/unit/utils/test_sbom_merge_a_merged_sbom_carries_its_own_serial.py``),
``dependencies`` are united by ``ref``, and the other top-level lists come from
the first result only. A single result is stored as the scanner made it,
and the merge changes neither input.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.phases.scan_result_processor import (
    ScanResultProcessor,
)
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.models.scan_results_container import (
    ScanResultsContainer,
)
from automated_security_helper.schemas.cyclonedx_bom_1_6_schema import (
    CycloneDXReport,
)

AshConfig.model_rebuild()

REQUESTS = {"name": "requests", "version": "2.19.1", "purl": "pkg:pypi/requests@2.19.1"}
FLASK = {"name": "flask", "version": "3.0.0", "purl": "pkg:pypi/flask@3.0.0"}
DJANGO = {"name": "django", "version": "5.0.0", "purl": "pkg:pypi/django@5.0.0"}

SOURCE_SERIAL = "urn:uuid:11111111-1111-4111-8111-111111111111"
CONVERTED_SERIAL = "urn:uuid:22222222-2222-4222-8222-222222222222"

#: Different on purpose: ``version`` defaults to 1, so two SBOMs that set none agree
#: and a merge that took the wrong one would pass.
VERSIONS = {"source": 3, "converted": 5}

#: The order the scan phase hands a scanner's targets over, and the reverse.
ARRIVALS = [("source", "converted"), ("converted", "source")]
ARRIVAL_IDS = ["source-first", "converted-first"]
IDENTITIES = [True, False]
IDENTITY_IDS = ["bom-ref", "purl-only"]


def _component(
    spec: dict[str, str], *, bom_ref: bool, copy: str | None = None
) -> dict[str, Any]:
    """A component; *copy* labels which SBOM's copy of it this is, in a property."""
    component: dict[str, Any] = {"type": "library", **spec}
    if bom_ref:
        component["bom-ref"] = spec["purl"]
    if copy is not None:
        component["properties"] = [{"name": "copy-of", "value": copy}]
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


def _aggregate(
    tmp_path: Path, *results: tuple[str, CycloneDXReport]
) -> AshAggregatedResults:
    """Run each (target type, SBOM) through the processor in order, as a scan does."""
    source_dir = tmp_path / "source"
    source_dir.mkdir(exist_ok=True)
    context = PluginContext(
        source_dir=source_dir, output_dir=tmp_path / "out", config=AshConfig()
    )
    processor = ScanResultProcessor(plugin_context=context)
    aggregated = AshAggregatedResults()
    for target_type, report in results:
        processor.process_container(
            ScanResultsContainer(
                scanner_name="syft", target_type=target_type, raw_results=report
            ),
            aggregated,
        )
    return aggregated


def _names(aggregated: AshAggregatedResults) -> list[str]:
    return sorted(c.name for c in aggregated.cyclonedx.components or [])


def _edges(aggregated: AshAggregatedResults) -> dict[str, list[str]]:
    return {
        dependency.ref.root.root: sorted(
            ref.root.root for ref in dependency.dependsOn or []
        )
        for dependency in aggregated.cyclonedx.dependencies or []
    }


def _dump(report: CycloneDXReport) -> dict[str, Any]:
    return report.model_dump(by_alias=True, exclude_unset=True, mode="json")


@pytest.mark.parametrize("bom_ref", IDENTITIES, ids=IDENTITY_IDS)
@pytest.mark.parametrize("order", ARRIVALS, ids=ARRIVAL_IDS)
def test_every_component_of_both_targets_is_listed(tmp_path, order, bom_ref):
    by_target = {
        "source": _sbom(
            _component(REQUESTS, bom_ref=bom_ref), _component(FLASK, bom_ref=bom_ref)
        ),
        "converted": _sbom(_component(DJANGO, bom_ref=bom_ref)),
    }

    aggregated = _aggregate(tmp_path, *((t, by_target[t]) for t in order))

    assert _names(aggregated) == ["django", "flask", "requests"]


@pytest.mark.parametrize("bom_ref", IDENTITIES, ids=IDENTITY_IDS)
@pytest.mark.parametrize("order", ARRIVALS, ids=ARRIVAL_IDS)
def test_a_component_both_targets_carry_is_listed_once(tmp_path, order, bom_ref):
    by_target = {
        "source": _sbom(
            _component(REQUESTS, bom_ref=bom_ref, copy="source"),
            _component(FLASK, bom_ref=bom_ref),
        ),
        "converted": _sbom(
            _component(REQUESTS, bom_ref=bom_ref, copy="converted"),
            _component(DJANGO, bom_ref=bom_ref),
        ),
    }

    aggregated = _aggregate(tmp_path, *((t, by_target[t]) for t in order))

    assert _names(aggregated) == ["django", "flask", "requests"]
    # The copy that arrived first is the one kept, whole.
    (requests,) = (c for c in aggregated.cyclonedx.components if c.name == "requests")
    assert [(p.name, p.value) for p in requests.properties] == [("copy-of", order[0])]


@pytest.mark.parametrize("header", [False, True], ids=["bare", "with-header"])
@pytest.mark.parametrize("order", ARRIVALS, ids=ARRIVAL_IDS)
def test_a_target_with_no_components_leaves_the_inventory_alone(
    tmp_path, order, header
):
    if header:
        empty = _sbom(serial=CONVERTED_SERIAL, subject="converted tree")
    else:
        empty = _sbom()
    by_target = {
        "source": _sbom(
            _component(REQUESTS, bom_ref=True), _component(FLASK, bom_ref=True)
        ),
        "converted": empty,
    }

    aggregated = _aggregate(tmp_path, *((t, by_target[t]) for t in order))

    assert _names(aggregated) == ["flask", "requests"]


def test_components_with_neither_bom_ref_nor_purl_are_never_matched(tmp_path):
    keyless = {"type": "library", "name": "vendored", "version": "1.0"}

    aggregated = _aggregate(
        tmp_path,
        ("source", _sbom(dict(keyless))),
        ("converted", _sbom(dict(keyless))),
    )

    assert _names(aggregated) == ["vendored", "vendored"]


def test_one_package_under_two_bom_refs_is_listed_twice(tmp_path):
    source = {**_component(REQUESTS, bom_ref=False), "bom-ref": "source-ref"}
    converted = {**_component(REQUESTS, bom_ref=False), "bom-ref": "converted-ref"}

    aggregated = _aggregate(
        tmp_path, ("source", _sbom(source)), ("converted", _sbom(converted))
    )

    assert _names(aggregated) == ["requests", "requests"]


@pytest.mark.parametrize("order", ARRIVALS, ids=ARRIVAL_IDS)
def test_the_first_sbom_keeps_its_header(tmp_path, order):
    by_target = {
        "source": _sbom(
            _component(REQUESTS, bom_ref=True),
            serial=SOURCE_SERIAL,
            version=VERSIONS["source"],
            subject="source tree",
        ),
        "converted": _sbom(
            _component(DJANGO, bom_ref=True),
            serial=CONVERTED_SERIAL,
            version=VERSIONS["converted"],
            subject="converted tree",
        ),
    }
    first = by_target[order[0]]

    aggregated = _aggregate(tmp_path, *((t, by_target[t]) for t in order))

    assert aggregated.cyclonedx.version == VERSIONS[order[0]]
    assert aggregated.cyclonedx.version != VERSIONS[order[1]]
    assert aggregated.cyclonedx.serialNumber not in (SOURCE_SERIAL, CONVERTED_SERIAL)
    assert aggregated.cyclonedx.metadata.component.name == (
        first.metadata.component.name
    )


@pytest.mark.parametrize("order", ARRIVALS, ids=ARRIVAL_IDS)
def test_dependencies_are_united_by_ref(tmp_path, order):
    by_target = {
        "source": _sbom(
            _component(REQUESTS, bom_ref=True),
            _component(FLASK, bom_ref=True),
            dependencies=[
                _dependency(REQUESTS["purl"], FLASK["purl"]),
                _dependency(FLASK["purl"]),
            ],
        ),
        "converted": _sbom(
            _component(REQUESTS, bom_ref=True),
            _component(DJANGO, bom_ref=True),
            dependencies=[
                _dependency(REQUESTS["purl"], DJANGO["purl"]),
                _dependency(DJANGO["purl"]),
            ],
        ),
    }

    aggregated = _aggregate(tmp_path, *((t, by_target[t]) for t in order))

    assert _edges(aggregated) == {
        REQUESTS["purl"]: sorted([FLASK["purl"], DJANGO["purl"]]),
        FLASK["purl"]: [],
        DJANGO["purl"]: [],
    }


@pytest.mark.parametrize("order", ARRIVALS, ids=ARRIVAL_IDS)
def test_provides_are_united_by_ref(tmp_path, order):
    provided = {"source": FLASK["purl"], "converted": DJANGO["purl"]}
    by_target = {
        target: _sbom(
            _component(REQUESTS, bom_ref=True),
            dependencies=[{"ref": REQUESTS["purl"], "provides": [provided[target]]}],
        )
        for target in provided
    }

    aggregated = _aggregate(tmp_path, *((t, by_target[t]) for t in order))

    (entry,) = aggregated.cyclonedx.dependencies
    assert entry.ref.root.root == REQUESTS["purl"]
    assert [ref.root.root for ref in entry.provides] == [provided[t] for t in order]
    assert entry.dependsOn is None


def test_the_other_top_level_lists_come_from_the_first_sbom(tmp_path):
    source = _sbom(_component(REQUESTS, bom_ref=True))
    converted = _sbom(
        _component(DJANGO, bom_ref=True),
        properties=[{"name": "converted-only", "value": "1"}],
    )

    aggregated = _aggregate(tmp_path, ("source", source), ("converted", converted))

    assert aggregated.cyclonedx.properties is None


@pytest.mark.parametrize("order", ARRIVALS, ids=ARRIVAL_IDS)
def test_the_merge_changes_neither_input(tmp_path, order):
    by_target = {
        "source": _sbom(
            _component(REQUESTS, bom_ref=True),
            serial=SOURCE_SERIAL,
            dependencies=[_dependency(REQUESTS["purl"], FLASK["purl"])],
        ),
        "converted": _sbom(
            _component(REQUESTS, bom_ref=True),
            _component(DJANGO, bom_ref=True),
            serial=CONVERTED_SERIAL,
            dependencies=[_dependency(REQUESTS["purl"], DJANGO["purl"])],
        ),
    }
    before = {target: _dump(report) for target, report in by_target.items()}

    _aggregate(tmp_path, *((t, by_target[t]) for t in order))

    assert {target: _dump(report) for target, report in by_target.items()} == before


@pytest.mark.parametrize("target_type", ["source", "converted"])
def test_one_sbom_is_stored_as_the_scanner_made_it(tmp_path, target_type):
    report = _sbom(_component(REQUESTS, bom_ref=True), _component(FLASK, bom_ref=False))
    expected = _dump(report)

    aggregated = _aggregate(tmp_path, (target_type, report))

    assert _dump(aggregated.cyclonedx) == expected
